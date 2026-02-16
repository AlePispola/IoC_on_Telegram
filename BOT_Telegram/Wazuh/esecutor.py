#!/usr/bin/env python3
import sys
import json
import requests

# --- CONFIGURATION ---
# Replace with your actual Telegram Bot Token
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
# ----------------------

def send_telegram_msg(chat_id, text):
    """
    Sends a notification message to the Telegram group regarding the enforcement action.
    """
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    try:
        requests.post(url, data=data)
    except Exception as e:
        pass # Silent fail for notification to avoid blocking the main logic

def ban_user(chat_id, user_id):
    """
    Triggers the 'kickChatMember' API to ban the user from the group.
    """
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/kickChatMember"
    data = {"chat_id": chat_id, "user_id": user_id}
    response = requests.post(url, data=data)
    return response.json()

# --- WAZUH INPUT PROCESSING ---
# Wazuh passes the alert details via STDIN (Standard Input)
try:
    input_data = sys.stdin.read()
    json_data = json.loads(input_data)
    
    # Navigate the JSON structure to find the original log data
    # Standard Wazuh structure: {"parameters": {"alert": {"data": {...}}}}
    alert = json_data.get("parameters", {}).get("alert", {})
    log_data = alert.get("data", {})

    # Extract fields written by the Sentinel Python Listener
    target_user_id = log_data.get("author_id")
    target_chat_id = log_data.get("chat_id")
    ioc_detected = log_data.get("ioc")

    if target_user_id and target_chat_id:
        # 1. Execute Ban
        result = ban_user(target_chat_id, target_user_id)
        
        # 2. Log to Active Response history for auditing and debugging
        with open("/var/ossec/logs/active-responses.log", "a") as log:
            log.write(f"Telegram Active Response: Attempting Ban on User {target_user_id} in Chat {target_chat_id}. Result: {result}\n")

        # 3. Send warning message to the group (Optional)
        if result.get("ok"):
            warning_text = (
                f"🚫 **USER BANNED**\n"
                f"The defense system has removed the user for sharing a malicious IoC: `{ioc_detected}`"
            )
            send_telegram_msg(target_chat_id, warning_text)
            
    else:
        with open("/var/ossec/logs/active-responses.log", "a") as log:
            log.write("Telegram Active Response Error: user_id or chat_id missing in the alert data.\n")

except Exception as e:
    with open("/var/ossec/logs/active-responses.log", "a") as log:
        log.write(f"Telegram Active Response Exception: {str(e)}\n")