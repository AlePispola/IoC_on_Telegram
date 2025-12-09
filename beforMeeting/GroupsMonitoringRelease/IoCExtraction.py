# ====================================================================
# Script V7: Analisi Approfondita con Salvataggio su CSV
# ====================================================================

# 1. SETUP
# Esegui nel terminale: pip install pymongo iocsearcher pandas
from pymongo import MongoClient
from iocsearcher.searcher import Searcher
import pandas as pd # Usiamo Pandas per gestire facilmente il CSV
import os

# ============================================================
# FASE 0: CONNESSIONE AL DATABASE E CONFIGURAZIONE
# ============================================================
uri = "mongodb://DPA_Project_ReadOnly:DPA_sd_2025@130.192.238.49:27015/?authSource=admin"
client = MongoClient(uri)
db = client["GroupMonitoringRelease"]

# Nome del file dove salvare i risultati
output_csv_file = "iocs_trovati.csv"

# ============================================================
# FASE 1: RACCOLTA INFORMAZIONI SUI GRUPPI
# ============================================================
print("Raccolgo informazioni su tutti i gruppi nel database...")

groups_collection = db["groups"]
group_info_map = {} # Un dizionario per mappare collection_name -> info del gruppo

for group_doc in groups_collection.find({}):
    collection_name = group_doc.get("collection_name")
    if collection_name:
        group_info_map[collection_name] = {
            "group_id": group_doc.get("id"),
            "group_name": group_doc.get("chat_name"),
            "group_username": group_doc.get("username"),
            "group_topic": group_doc.get("topic"),
            "group_language": group_doc.get("language")
        }
print(f"Trovate informazioni per {len(group_info_map)} gruppi.")

# ============================================================
# FASE 2: SETUP di iocsearcher e CICLO DI ESTRAZIONE
# ============================================================
searcher = Searcher()
all_found_iocs = [] # Una lista per raccogliere tutti gli IoC trovati

# Prendiamo solo le collection di messaggi per cui abbiamo informazioni
collections_da_analizzare = list(group_info_map.keys())

for collection_name in collections_da_analizzare:
    
    # Se vuoi analizzare solo alcuni gruppi, puoi filtrare qui
    # Esempio: if group_info_map[collection_name]['group_name'] not in ["ToreSays®️ + Chat"]: continue

    print(f"\n--- Analizzando la collection: {collection_name} ({group_info_map[collection_name]['group_name']}) ---")
    current_collection = db[collection_name]
    
    # Rimuovi .limit() per analizzare tutti i messaggi
    cursor = current_collection.find({}).limit(1000) # Mettiamo un limite basso per i test iniziali

    for message_doc in cursor:
        message_text = message_doc.get("message", "")

        if not message_text:
            continue

        iocs_list = searcher.search_raw(message_text)

        if iocs_list:
            # Per ogni IoC trovato, aggiungiamo una riga alla nostra lista di risultati
            for ioc_tuple in iocs_list:
                ioc_type = ioc_tuple[0]
                ioc_value = ioc_tuple[1]
                
                # Estraiamo l'ID dell'utente
                sender_id = None
                if message_doc.get("from_id") and isinstance(message_doc["from_id"], dict):
                    sender_id = message_doc["from_id"].get("user_id")

                # Aggiungiamo un dizionario con tutte le info utili
                all_found_iocs.append({
                    "timestamp": message_doc.get("date"),
                    "group_id": group_info_map[collection_name].get("group_id"),
                    "group_name": group_info_map[collection_name].get("group_name"),
                    "group_topic": group_info_map[collection_name].get("group_topic"),
                    "message_id": message_doc.get("id"),
                    "sender_id": sender_id,
                    "message_text": message_text,
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                })

print(f"\n\nAnalisi completata. Trovati in totale {len(all_found_iocs)} IoC candidati.")

# ============================================================
# FASE 3: SALVATAGGIO DEI RISULTATI SU CSV
# ============================================================
if all_found_iocs:
    # Creiamo un DataFrame Pandas dalla nostra lista di dizionari
    df = pd.DataFrame(all_found_iocs)
    
    # Salviamo il DataFrame in un file CSV
    df.to_csv(output_csv_file, index=False, encoding='utf-8')
    
    print(f"Risultati salvati con successo nel file: {output_csv_file}")
    print("\nPrime 5 righe del file CSV:")
    print(df.head())
else:
    print("Nessun IoC trovato, nessun file CSV è stato creato.")

client.close()