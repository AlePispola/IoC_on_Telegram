import sys
import os
import json
import re
import time
import requests
import logging
import base64
import emoji
import torch
from datetime import datetime
from telethon import TelegramClient, events
from telethon.tl.types import Channel, Chat
from transformers import RobertaTokenizer, RobertaForSequenceClassification

# ================= CONFIGURAZIONE =================

# 1. TELEGRAM API
API_ID = API_ID          # <--- INSERISCI QUI
API_HASH = 'API_HASH'    # <--- INSERISCI QUI
SESSION_NAME = 'sentinel_ai_session'

# 2. VIRUSTOTAL
VT_API_KEY = "VT_APY_KEY"
VT_THRESHOLD = 1 

# 3. AI MODEL CONFIGURATION
PERCORSO_MODELLO = "./modello_finale"  # La cartella dove hai salvato il modello addestrato
SOGLIA_CYBER = 0.60                    # Utile per flaggare nel JSON se è rilevante

# 4. WAZUH LOG FILE
OUTPUT_LOG_FILE = r"C:\Logs\virustotal_results.json"

# 5. TARGETS
TARGET_CHATS = ['Project_DPA'] 

# ================= LOGGING SETUP =================
logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("Sentinel_AI")

# ================= SETUP MODELLO AI (Caricamento all'avvio) =================
device = "cuda" if torch.cuda.is_available() else "cpu"
logger.info(f"⚙️  AI Device: {device.upper()}")

try:
    logger.info(f"🧠 Caricamento modello da {PERCORSO_MODELLO}...")
    tokenizer = RobertaTokenizer.from_pretrained(PERCORSO_MODELLO)
    model = RobertaForSequenceClassification.from_pretrained(PERCORSO_MODELLO).to(device)
    model.eval() # Imposta in modalità valutazione (no training)
    logger.info("✅ Modello AI caricato con successo.")
except Exception as e:
    logger.error(f"❌ Errore critico caricamento modello: {e}")
    logger.error("Assicurati che la cartella 'modello_finale' esista e contenga config.json e model.safetensors/bin")
    sys.exit(1)

# ================= CACHE =================
vt_cache = {}
CACHE_DURATION = 3600 * 24 

# ================= FUNZIONI AI & CLEANING =================

def clean_and_mask(text):
    """
    Stessa funzione usata nel training per garantire coerenza al modello.
    """
    if not isinstance(text, str): return ""
    text = emoji.replace_emoji(text, replace='')
    
    # Mascheramento entità (Regex identiche al training)
    text = re.sub(r'CVE-\d{4}-\d+', '[CVE]', text, flags=re.IGNORECASE)
    text = re.sub(r'(?:https?://)?(?:www\.)?(?:t\.me|telegram\.me)/[a-zA-Z0-9_]+', '[TG_LINK]', text)
    text = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', '[URL]', text)
    text = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP]', text)
    text = re.sub(r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|ru|cn|it|uk|gov)\b', '[DOMAIN]', text)
    
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_cyber_score(text):
    """
    Restituisce la probabilità (0.0 - 1.0) che il messaggio sia Cyber Security related.
    """
    if not text or len(text) < 4:
        return 0.0
        
    cleaned_text = clean_and_mask(text)
    
    try:
        inputs = tokenizer(cleaned_text, return_tensors="pt", padding=True, truncation=True, max_length=128).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
            # Applichiamo Softmax per ottenere probabilità tra 0 e 1
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        # Assumiamo che la classe '1' sia quella "Cyber/Relevant"
        # Se nel tuo training le classi erano invertite, cambia index in 0
        score = probs[0][1].item() 
        return score
    except Exception as e:
        logger.error(f"Errore inferenza AI: {e}")
        return 0.0

# ================= FUNZIONI IOC PIPELINE =================

def extract_iocs(text):
    iocs = []
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    valid_ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("192.168.")]
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    for item in valid_ips + urls:
        if item not in iocs:
            iocs.append(item)
    return iocs

def check_virustotal(ioc):
    # Check Cache
    current_time = time.time()
    if ioc in vt_cache:
        cached_data = vt_cache[ioc]
        if (current_time - cached_data['time']) < CACHE_DURATION:
            logger.info(f"♻️ Cache Hit per {ioc}")
            return cached_data['data']

    # Prepare Request
    ioc_type = "ip_addresses"
    endpoint = ioc
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
            vt_cache[ioc] = {"data": result, "time": current_time}
            return result
        elif response.status_code == 429:
            logger.warning("⏳ Quota VT superata.")
            return None
        elif response.status_code == 404:
            return {"malicious": 0, "total": 0, "link": "N/A"}
        else:
            return None
    except Exception as e:
        logger.error(f"Eccezione VT: {e}")
        return None

def save_to_wazuh(event_data):
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
    sender = await event.get_sender()
    chat = await event.get_chat()
    
    sender_id = sender.id if sender else 0
    raw_chat_id = chat.id if chat else 0
    chat_title = chat.title if hasattr(chat, 'title') else "Private"
    
    # ID Logic per Bot API
    chat_id_for_bot = raw_chat_id
    if isinstance(chat, Channel):
        chat_id_for_bot = int(f"-100{raw_chat_id}")
    elif isinstance(chat, Chat):
        chat_id_for_bot = -raw_chat_id

    text = event.raw_text
    
    # ---------------------------------------------------------
    # STEP 1: AI GATEKEEPER (Il Filtro)
    # ---------------------------------------------------------
    # Calcoliamo lo score PRIMA di fare qualsiasi altra cosa costosa
    cyber_score = get_cyber_score(text)
    
    # LOGICA DI BLOCCO:
    # Se lo score è sotto la soglia, il messaggio è "rumore".
    # Lo ignoriamo completamente.
    if cyber_score < SOGLIA_CYBER:
        # (Opzionale) Log di debug per vedere cosa scartiamo
        # logger.info(f"🗑️ Scartato (Score: {cyber_score:.2f}): {text[:30]}...")
        return 

    # Se siamo qui, il messaggio è INTERESSANTE (Cyber Relevant)
    logger.info(f"🧠 AI PASS: Score {cyber_score:.4f} | Analisi IoC avviata per: {chat_title}")

    # ---------------------------------------------------------
    # STEP 2: ESTENSIONE IOC (Eseguita solo sui messaggi rilevanti)
    # ---------------------------------------------------------
    iocs = extract_iocs(text)
    
    if not iocs:
        logger.info(f"Message relevant ({cyber_score:.2f}) but no IoC found.")
        return 

    logger.info(f"🔎 Trovati {len(iocs)} IoC. Controllo VT...")

    # ---------------------------------------------------------
    # STEP 3: ENRICHMENT & WAZUH LOGGING
    # ---------------------------------------------------------
    for ioc in iocs:
        vt_result = check_virustotal(ioc)
        
        if not vt_result:
            continue 
            
        is_malicious = vt_result['malicious'] >= VT_THRESHOLD
        
        if is_malicious:
            logger.warning(f"🚨 RILEVATO MALEVOLO: {ioc}")

        log_payload = {
            "timestamp": datetime.now().isoformat(),
            "integration_source": "telegram_sentinel",
            "source_chat": chat_title,
            "chat_id": chat_id_for_bot,
            "author_id": sender_id,
            "ai_classification": {
                "cyber_score": round(cyber_score, 4),
                "is_relevant": True # È true per definizione se siamo arrivati qui
            },
            "ioc": ioc,
            "ioc_type": "url" if ioc.startswith("http") else "ip",
            "virustotal": {
                "malicious": vt_result['malicious'],
                "total_engines": vt_result['total'],
                "permalink": vt_result['link']
            }
        }
        
        save_to_wazuh(log_payload)
        
        # Pausa per VT Rate Limit
        time.sleep(1)

# ================= AVVIO =================
if __name__ == '__main__':
    print(f"""
    🤖 SENTINEL BOT + AI CLASSIFIER AVVIATO
    ---------------------------------------
    📂 Log Output: {OUTPUT_LOG_FILE}
    🧠 Modello AI: {PERCORSO_MODELLO} (Device: {device})
    🎯 Target Chats: {TARGET_CHATS if TARGET_CHATS else "TUTTE"}
    ---------------------------------------
    In attesa...
    """)
    
    if not os.path.exists(OUTPUT_LOG_FILE):
        open(OUTPUT_LOG_FILE, 'a').close()
        os.chmod(OUTPUT_LOG_FILE, 0o666)

    client.start()
    client.run_until_disconnected()