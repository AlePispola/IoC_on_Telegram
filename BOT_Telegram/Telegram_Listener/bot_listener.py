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

# ================= ENVIRONMENT CONFIGURATION =================
# Reading configurations from Docker Environment Variables
API_ID = int(os.getenv('TG_API_ID', '00000'))
API_HASH = os.getenv('TG_API_HASH', '')
SESSION_NAME = '/app/session/sentinel_session' # Persistent path

VT_API_KEY = os.getenv('VT_API_KEY', '')
VT_THRESHOLD = int(os.getenv('VT_THRESHOLD', '1'))

# Internal container path for log forwarding
OUTPUT_LOG_FILE = "/app/logs/virustotal_results.json"

TARGET_CHATS = os.getenv('TARGET_CHATS', 'Project_DPA').split(',')

# ================= LOGGING SETUP =================
logging.basicConfig(format='[%(levelname)s] %(asctime)s - %(message)s', level=logging.INFO)
logger = logging.getLogger("Sentinel")

# ================= CACHE (API Quota Optimization) =================
# Structure: { "1.1.1.1": {"data": {...}, "time": 1715000000} }
vt_cache = {}
CACHE_DURATION = 3600 * 24  # 24-hour retention

# ================= PIPELINE FUNCTIONS =================

def extract_iocs(text):
    """
    Step 1: Extraction. Identifies IP addresses and URLs within the text.
    """
    iocs = []
    
    # IPv4 Pattern
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = re.findall(ip_pattern, text)
    
    # Basic filtering for local/internal IPs (e.g., 127.0.0.1)
    valid_ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("192.168.")]
    
    # URL Pattern (Simplified but effective)
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)
    
    # Merge and deduplicate
    for item in valid_ips + urls:
        if item not in iocs:
            iocs.append(item)
            
    return iocs

def check_virustotal(ioc):
    """
    Step 2: Enrichment. Consults VirusTotal API for threat reputation.
    Handles caching and rate limiting.
    """
    # 1. Cache Check
    current_time = time.time()
    if ioc in vt_cache:
        cached_data = vt_cache[ioc]
        if (current_time - cached_data['time']) < CACHE_DURATION:
            logger.info(f"♻️ Cache Hit for {ioc}")
            return cached_data['data']

    # 2. Request Preparation
    ioc_type = "ip_addresses"
    endpoint = ioc
    
    # URLs must be base64 encoded for the VT v3 API
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
            
            # Store in Cache
            vt_cache[ioc] = {"data": result, "time": current_time}
            return result
            
        elif response.status_code == 429:
            logger.warning("⏳ VT Quota exceeded. Skipping this IoC.")
            return None
        elif response.status_code == 404:
            # Not found usually implies clean or unknown/new
            return {"malicious": 0, "total": 0, "link": "N/A"}
        else:
            logger.error(f"VT API Error {response.status_code}")
            return None

    except Exception as e:
        logger.error(f"VT Exception: {e}")
        return None

def save_to_wazuh(event_data):
    """
    Step 3: Output. Writes the event as a single-line JSON (NDJSON) for Wazuh monitoring.
    """
    try:
        with open(OUTPUT_LOG_FILE, 'a') as f:
            f.write(json.dumps(event_data) + "\n")
        logger.info(f"✅ Event logged to {OUTPUT_LOG_FILE}")
    except Exception as e:
        logger.error(f"❌ Failed to write to log file: {e}")

# ================= MAIN LISTENER =================

client = TelegramClient(SESSION_NAME, API_ID, API_HASH)

@client.on(events.NewMessage(chats=TARGET_CHATS if TARGET_CHATS else None))
async def handler(event):
    """
    Triggers on every new message received in monitored chats.
    """
    sender = await event.get_sender()
    chat = await event.get_chat()
    
    sender_id = sender.id if sender else 0
    raw_chat_id = chat.id if chat else 0
    chat_title = chat.title if hasattr(chat, 'title') else "Private"
    
    # --- CHAT ID CONVERSION FOR BOT API COMPATIBILITY ---
    # Telethon returns positive IDs for channels/supergroups.
    # The Bot API requires the -100 prefix for these entities.
    chat_id_for_bot = raw_chat_id
    
    if isinstance(chat, Channel):
        chat_id_for_bot = int(f"-100{raw_chat_id}")
        logger.info(f"🔧 ID Converted for Bot API: {raw_chat_id} -> {chat_id_for_bot}")
        
    elif isinstance(chat, Chat):
        # Legacy groups already use negative IDs
        chat_id_for_bot = -raw_chat_id
    # ----------------------------------------------------

    text = event.raw_text
    logger.info(f"📩 New message from {chat_title} (Sender ID: {sender_id})")

    # --- PHASE 1: EXTRACTION ---
    iocs = extract_iocs(text)
    
    if not iocs:
        return 

    logger.info(f"🔎 Found {len(iocs)} IoCs. Starting scan...")

    # --- PHASE 2: ENRICHMENT (VirusTotal) ---
    for ioc in iocs:
        vt_result = check_virustotal(ioc)
        
        if not vt_result:
            continue 
            
        is_malicious = vt_result['malicious'] >= VT_THRESHOLD
        
        if is_malicious:
            logger.warning(f"🚨 MALICIOUS DETECTED: {ioc} ({vt_result['malicious']}/{vt_result['total']})")
        else:
            logger.info(f"Clean: {ioc}")

        # --- PHASE 3: LOG GENERATION FOR WAZUH ---
        log_payload = {
            "timestamp": datetime.now().isoformat(),
            "integration_source": "telegram_sentinel", 
            "source_chat": chat_title,
            "chat_id": chat_id_for_bot,
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

# ================= EXECUTION START =================
if __name__ == '__main__':
    print(f"""
    🤖 SENTINEL BOT STARTED
    -----------------------
    📂 Log Output: {OUTPUT_LOG_FILE}
    🎯 Target Chats: {TARGET_CHATS if TARGET_CHATS else "ALL"}
    🔑 VT Api Key: {'LOADED' if VT_API_KEY else 'MISSING'}
    -----------------------
    Listening for messages... (Press Ctrl+C to stop)
    """)
    
    # Ensure log file exists and is writable for the Wazuh agent
    if not os.path.exists(OUTPUT_LOG_FILE):
        open(OUTPUT_LOG_FILE, 'a').close()
        os.chmod(OUTPUT_LOG_FILE, 0o666)

    client.start()
    client.run_until_disconnected()