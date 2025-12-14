#!/usr/bin/env python3
import sys
import json
import requests

# --- CONFIGURAZIONE ---
BOT_TOKEN = "IL_TUO_BOT_TOKEN_QUI"
# ----------------------

def send_telegram_msg(chat_id, text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    requests.post(url, data=data)

def ban_user(chat_id, user_id):
    # L'API 'kickChatMember' banna l'utente (e opzionalmente lo sbanna subito per permettergli di rientrare dopo tot tempo)
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/kickChatMember"
    data = {"chat_id": chat_id, "user_id": user_id}
    response = requests.post(url, data=data)
    return response.json()

# --- LETTURA INPUT DA WAZUH ---
# Wazuh passa l'alert tramite STDIN (Standard Input)
try:
    input_data = sys.stdin.read()
    json_data = json.loads(input_data)
    
    # Navighiamo nel JSON per trovare i dati del log originale
    # Struttura tipica: {"parameters": {"alert": {"data": {...}}}}
    alert = json_data.get("parameters", {}).get("alert", {})
    log_data = alert.get("data", {})

    # Estraiamo i campi che il tuo script Python 'Listener' ha scritto nel JSON
    target_user_id = log_data.get("author_id")
    target_chat_id = log_data.get("chat_id")
    ioc_detected = log_data.get("ioc")

    if target_user_id and target_chat_id:
        # 1. Esegui il Ban
        result = ban_user(target_chat_id, target_user_id)
        
        # 2. Scrivi nel log di Active Response (utile per debug)
        with open("/var/ossec/logs/active-responses.log", "a") as log:
            log.write(f"Telegram Ban: Tentativo su User {target_user_id} in Chat {target_chat_id}. Esito: {result}\n")

        # 3. Manda messaggio di avviso nel gruppo (Opzionale)
        if result.get("ok"):
            send_telegram_msg(target_chat_id, f"🚫 **UTENTE BANNATO**\nIl sistema di difesa ha rimosso l'utente per aver condiviso IoC malevolo: `{ioc_detected}`")
            
    else:
        with open("/var/ossec/logs/active-responses.log", "a") as log:
            log.write("Telegram Ban Error: user_id o chat_id mancanti nell'alert.\n")

except Exception as e:
    with open("/var/ossec/logs/active-responses.log", "a") as log:
        log.write(f"Telegram Ban Exception: {str(e)}\n")