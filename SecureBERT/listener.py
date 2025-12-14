import sys
import os
import json
import re
import time
import requests
import logging
import base64
from datetime import datetime
from telethon import TelegramClient, events
from telethon.tl.types import Channel, Chat

# ================= CONFIGURAZIONE =================

# 1. TELEGRAM API (Prendile da my.telegram.org)
API_ID = API_ID          # <--- INSERISCI QUI
API_HASH = 'API_HASH'  # <--- INSERISCI QUI
SESSION_NAME = 'sentinel_session'

# 2. VIRUSTOTAL
VT_API_KEY = "VT_APY_KEY"
VT_THRESHOLD = 1  # Consideriamo malevolo se almeno X engine lo rilevano

# 3. WAZUH LOG FILE (Dove scriviamo i risultati)
# Assicurati che l'utente che lancia lo script abbia i permessi di scrittura qui
OUTPUT_LOG_FILE = r"C:\Logs\virustotal_results.json"

# 4. TARGETS
# Puoi mettere i nomi dei canali o gli ID interi.
# Se lasci vuoto [], ascolterà tutte le chat dove l'account è presente (SCONSIGLIATO per il rumore)
TARGET_CHATS = ['Project_DPA'] 

# ================= LOGGING SETUP =================
logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("Sentinel")

# ================= CACHE (Per non sprecare API) =================
# Struttura: { "1.1.1.1": {"malicious": 0, "time": 1715000000} }
vt_cache = {}
CACHE_DURATION = 3600 * 24  # 24 ore di memoria

# ================= FUNZIONI PIPELINE =================

def extract_iocs(text):
    """
    Step 1: Estrazione. Trova IP e URL nel testo.
    """
    iocs = []
    
    # Regex IP v4
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    # Filtro base per IP locali/fake (es. 127.0.0.1)
    valid_ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("192.168.")]
    
    # Regex URL (Semplificata ma efficace)
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    
    # Uniamo e rimuoviamo duplicati
    for item in valid_ips + urls:
        if item not in iocs:
            iocs.append(item)
            
    return iocs

def check_virustotal(ioc):
    """
    Step 2: Enrichment. Controlla su VT se l'IoC è pericoloso.
    Gestisce Cache e Rate Limit.
    """
    # 1. Controllo Cache
    current_time = time.time()
    if ioc in vt_cache:
        cached_data = vt_cache[ioc]
        # Se il dato è fresco (meno di 24h), usalo
        if (current_time - cached_data['time']) < CACHE_DURATION:
            logger.info(f"♻️ Cache Hit per {ioc}")
            return cached_data['data']

    # 2. Preparazione Request
    ioc_type = "ip_addresses"
    endpoint = ioc
    
    # Se è un URL, va codificato in base64
    if ioc.startswith("http"):
        ioc_type = "urls"
        endpoint = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
    
    url = f"https://www.virustotal.com/api/v3/{ioc_type}/{endpoint}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            result = {
                "malicious": stats['malicious'],
                "total": sum(stats.values()),
                "link": response.json()['data']['links']['self']
            }
            
            # Salva in Cache
            vt_cache[ioc] = {"data": result, "time": current_time}
            return result
            
        elif response.status_code == 429:
            logger.warning("⏳ Quota VT superata. Salto questo IoC.")
            return None
        elif response.status_code == 404:
            # Non trovato = Probabilmente pulito o nuovo
            return {"malicious": 0, "total": 0, "link": "N/A"}
        else:
            logger.error(f"Errore VT {response.status_code}")
            return None

    except Exception as e:
        logger.error(f"Eccezione VT: {e}")
        return None

def save_to_wazuh(event_data):
    """
    Step 3: Output. Scrive il JSON su una singola riga (NDJSON).
    """
    try:
        with open(OUTPUT_LOG_FILE, 'a') as f:
            f.write(json.dumps(event_data) + "\n")
        logger.info(f"✅ Evento scritto su {OUTPUT_LOG_FILE}")
    except Exception as e:
        logger.error(f"❌ Impossibile scrivere su file log: {e}")

# ================= MAIN LISTENER =================

client = TelegramClient(SESSION_NAME, API_ID, API_HASH)

@client.on(events.NewMessage(chats=TARGET_CHATS if TARGET_CHATS else None))
async def handler(event):
    """
    Questa funzione viene eseguita per OGNI nuovo messaggio ricevuto.
    """
    sender = await event.get_sender()
    chat = await event.get_chat()
    
    sender_id = sender.id if sender else 0

    raw_chat_id = chat.id if chat else 0
    chat_title = chat.title if hasattr(chat, 'title') else "Private"
    
    # --- CORREZIONE ID PER BOT API ---
    # Telethon restituisce ID positivi per i canali/supergruppi.
    # L'API Bot vuole il prefisso -100.
    chat_id_for_bot = raw_chat_id
    
    # Se è un Canale o un Supergruppo (Megagroup)
    if isinstance(chat, Channel):
        # Concateniamo -100 davanti all'ID
        chat_id_for_bot = int(f"-100{raw_chat_id}")
        logger.info(f"🔧 ID Convertito per Bot API: {raw_chat_id} -> {chat_id_for_bot}")
        
    # Se è un Gruppo legacy (raro ormai, ma possibile)
    elif isinstance(chat, Chat):
        # I gruppi legacy hanno ID negativo
        chat_id_for_bot = -raw_chat_id
        
    # Se è una chat privata, l'ID resta positivo (nessuna modifica)
    # -----------------------------------

    text = event.raw_text

    logger.info(f"📩 Nuovo messaggio da {chat_title} (ID: {sender_id})")

    # --- FASE 1: PIPELINE ESTRAZIONE ---
    iocs = extract_iocs(text)
    
    if not iocs:
        return 

    logger.info(f"🔎 Trovati {len(iocs)} IoC. Avvio scansione...")

    # --- FASE 2: ENRICHMENT (VirusTotal) ---
    for ioc in iocs:
        vt_result = check_virustotal(ioc)
        
        if not vt_result:
            continue 
            
        is_malicious = vt_result['malicious'] >= VT_THRESHOLD
        
        if is_malicious:
            logger.warning(f"🚨 RILEVATO MALEVOLO: {ioc} ({vt_result['malicious']}/{vt_result['total']})")
        else:
            logger.info(f"clean: {ioc}")

        # --- FASE 3: SCRITTURA JSON PER WAZUH ---
        log_payload = {
            "timestamp": datetime.now().isoformat(),
            "integration_source": "telegram_sentinel", 
            "source_chat": chat_title,
            "chat_id": chat_id_for_bot,  # <--- QUI USIAMO L'ID CORRETTO
            "author_id": sender_id,
            "message_snippet": text[:50], 
            "ioc": ioc,
            "ioc_type": "url" if ioc.startswith("http") else "ip",
            "virustotal": {
                "malicious": vt_result['malicious'],
                "total_engines": vt_result['total'],
                "permalink": vt_result['link']
            }
        }
        
        save_to_wazuh(log_payload)
        time.sleep(1)

# ================= AVVIO =================
if __name__ == '__main__':
    print(f"""
    🤖 SENTINEL BOT AVVIATO
    -----------------------
    📂 Log Output: {OUTPUT_LOG_FILE}
    🎯 Target Chats: {TARGET_CHATS if TARGET_CHATS else "TUTTE"}
    🔑 VT Api Key: {'CARICATA' if VT_API_KEY else 'MANCANTE'}
    -----------------------
    In attesa di messaggi... (Premi Ctrl+C per fermare)
    """)
    
    # Assicuriamoci che il file di log esista e sia scrivibile
    if not os.path.exists(OUTPUT_LOG_FILE):
        open(OUTPUT_LOG_FILE, 'a').close()
        os.chmod(OUTPUT_LOG_FILE, 0o666) # Permessi rw per tutti (per evitare problemi con wazuh-agent)

    client.start()
    client.run_until_disconnected()