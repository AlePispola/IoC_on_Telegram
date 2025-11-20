import os
import torch
import pandas as pd
from pymongo import MongoClient
from iocsearcher.searcher import Searcher
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification
from tqdm.notebook import tqdm

# ============================================================
# CONFIGURAZIONE
# ============================================================
MODEL_PATH = "./cyber_classifier_model" 
MONGO_URI = "mongodb://DPA_Project_ReadOnly:DPA_sd_2025@130.192.238.49:27015/?authSource=admin"
DB_NAME = "GroupMonitoringRelease"
BATCH_SIZE = 64
LIMIT_MESSAGES = 5000  # Metti None per processare tutto, oppure un numero (es. 5000) per test

# ============================================================
# 1. CARICAMENTO MODELLO (GPU)
# ============================================================
print(">>> Caricamento Modello e Tokenizer...")
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Using device: {device}")

try:
    tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_PATH)
    model = DistilBertForSequenceClassification.from_pretrained(MODEL_PATH)
    model.to(device)
    model.eval()
    print(">>> Modello caricato con successo!")
except Exception as e:
    print(f"ERRORE: Non trovo il modello in '{MODEL_PATH}'. Scaricalo dall'output del training.")
    raise e

searcher = Searcher()

# ============================================================
# 2. CONNESSIONE DB E MAPPA GRUPPI (CON LINGUA)
# ============================================================
print(">>> Connessione a MongoDB...")
client = MongoClient(MONGO_URI)
db = client[DB_NAME]

print(">>> Indicizzazione gruppi e verifica lingua...")
groups_collection = db["groups"]
group_info_map = {}

# Estraiamo anche il campo "language"
for group_doc in groups_collection.find({}, {"collection_name": 1, "chat_name": 1, "topic": 1, "language": 1}):
    col_name = group_doc.get("collection_name")
    if col_name:
        group_info_map[col_name] = {
            "name": group_doc.get("chat_name", "Unknown"),
            "topic": group_doc.get("topic", "Unknown"),
            "language": group_doc.get("language", "Unknown") # <--- CAMPO NUOVO
        }

all_collections = [n for n in db.list_collection_names() if n.startswith("messages_")]
print(f">>> Trovate {len(all_collections)} collection totali.")

# ============================================================
# 3. CLASSIFICAZIONE BATCH
# ============================================================
def predict_batch(texts):
    inputs = tokenizer(texts, return_tensors="pt", padding=True, truncation=True, max_length=128).to(device)
    with torch.no_grad():
        logits = model(**inputs).logits
    return torch.argmax(logits, dim=-1).cpu().numpy()

# ============================================================
# 4. LOOP DI ANALISI CON FILTRO LINGUA
# ============================================================
extracted_data = []
total_analyzed = 0
total_cyber = 0
skipped_groups = 0

print(f">>> Inizio analisi...")

for collection_name in tqdm(all_collections, desc="Collections"):
    
    if LIMIT_MESSAGES and total_analyzed >= LIMIT_MESSAGES:
        break

    # Recuperiamo i metadati
    g_meta = group_info_map.get(collection_name, {"name": "Unknown", "topic": "Unknown", "language": "Unknown"})
    
    # --- FILTRO LINGUA ---
    # Se la lingua è esplicitata e NON è English, saltiamo.
    # Se è "Unknown" o "not_specified", decidiamo se rischiare o no. 
    # Qui sotto teniamo SOLO quelli esplicitamente "English".
    current_lang = str(g_meta["language"])
    
    if "English" not in current_lang: 
        # Nota: uso 'in' perché a volte potrebbe essere "English (US)" o liste
        # Se vuoi essere più permissivo e includere anche i "not_specified", cambia la condizione.
        skipped_groups += 1
        continue 

    # Se siamo qui, il gruppo è in inglese. Procediamo.
    cursor = db[collection_name].find({}, {"message": 1, "date": 1, "id": 1})
    
    batch_texts = []
    batch_docs = []
    
    for doc in cursor:
        msg_text = doc.get("message")
        
        if not msg_text or len(str(msg_text)) < 5:
            continue
            
        batch_texts.append(str(msg_text))
        batch_docs.append(doc)
        
        if len(batch_texts) >= BATCH_SIZE:
            total_analyzed += len(batch_texts)
            
            preds = predict_batch(batch_texts)
            
            for i, is_cyber in enumerate(preds):
                if is_cyber == 1:
                    total_cyber += 1
                    text = batch_texts[i]
                    original_doc = batch_docs[i]
                    
                    try:
                        iocs_list = searcher.search_raw(text)
                        if iocs_list:
                            for ioc_tuple in iocs_list:
                                # TUA LOGICA: index 0=type, index 1=value
                                ioc_type = ioc_tuple[0]
                                ioc_value = ioc_tuple[1]
                                
                                extracted_data.append({
                                    "group": g_meta["name"],
                                    "topic": g_meta["topic"],
                                    "language": current_lang, # Salviamo anche la lingua per debug
                                    "date": original_doc.get("date"),
                                    "msg_id": original_doc.get("id"),
                                    "ioc_type": ioc_type,
                                    "ioc_value": ioc_value,
                                    "message_text": text 
                                })
                    except Exception:
                        continue

            batch_texts = []
            batch_docs = []
            
            if LIMIT_MESSAGES and total_analyzed >= LIMIT_MESSAGES:
                break

# Ultimo batch residuo (per correttezza formale lo aggiungiamo qui)
if batch_texts and (not LIMIT_MESSAGES or total_analyzed < LIMIT_MESSAGES):
    preds = predict_batch(batch_texts)
    for i, is_cyber in enumerate(preds):
        if is_cyber == 1:
            try:
                iocs_list = searcher.search_raw(batch_texts[i])
                if iocs_list:
                    for ioc_tuple in iocs_list:
                        extracted_data.append({
                            "group": g_meta["name"],
                            "topic": g_meta["topic"],
                            "language": current_lang,
                            "date": batch_docs[i].get("date"),
                            "msg_id": batch_docs[i].get("id"),
                            "ioc_type": ioc_tuple[0],
                            "ioc_value": ioc_tuple[1],
                            "message_text": batch_texts[i]
                        })
            except: pass

# ============================================================
# 5. SALVATAGGIO OUTPUT
# ============================================================
print("\n" + "="*30)
print(f"STATISTICHE FINALI:")
print(f"- Gruppi Saltati (Non-English): {skipped_groups}")
print(f"- Messaggi Analizzati (English): {total_analyzed}")
print(f"- Messaggi 'Cyber' Rilevati: {total_cyber}")
print(f"- IoC Estratti: {len(extracted_data)}")
print("="*30)

if extracted_data:
    df = pd.DataFrame(extracted_data)
    df = df.drop_duplicates(subset=['ioc_value', 'msg_id'])
    filename = "ioc_db_filtered_english.csv"
    df.to_csv(filename, index=False)
    print(f">>> Salvato CSV: {filename}")
    print(df.head())
else:
    print(">>> Nessun IoC trovato.")