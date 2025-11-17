# ====================================================================
# Script V8: Analisi Adattata alla Nuova Struttura DB
# ====================================================================

# 1. SETUP
# Esegui nel terminale: pip install pymongo iocsearcher pandas
from pymongo import MongoClient
from iocsearcher.searcher import Searcher
import pandas as pd
import os

# ============================================================
# FASE 0: CONNESSIONE AL DATABASE E CONFIGURAZIONE
# ============================================================
# <<< MODIFICA: Assicurati che l'URI e il nome del DB siano corretti per il tuo nuovo database
uri = "mongodb://DPA_Project_ReadOnly:DPA_sd_2025@130.192.238.49:27015/?authSource=admin"
client = MongoClient(uri)
db = client["USelection2024"] 

# Nome del file dove salvare i risultati
output_csv_file = "iocs_trovati_nuova_struttura.csv"

# ============================================================
# FASE 1: RACCOLTA INFORMAZIONI SUI GRUPPI (ADATTATA)
# ============================================================
print("Raccolgo informazioni su tutti i gruppi nel database (nuova struttura)...")

groups_collection = db["entities"]
group_info_map = {} # Un dizionario per mappare collection_name -> info del gruppo

for group_doc in groups_collection.find({}):
    collection_name = group_doc.get("collection_name")
    if collection_name:
        # <<< MODIFICA: Estrazione dei dati adattata alla nuova struttura del documento 'entities'
        
        # Estrae il nome del gruppo/canale dal percorso annidato
        group_name = None
        if group_doc.get("full_entity") and group_doc["full_entity"].get("chats"):
            # Il nome è nel primo elemento della lista 'chats'
            group_name = group_doc["full_entity"]["chats"][0].get("title")

        # Estrae la descrizione (topic) dal percorso annidato
        group_topic = None
        if group_doc.get("full_entity") and group_doc["full_entity"].get("full_chat"):
            group_topic = group_doc["full_entity"]["full_chat"].get("about")
            
        # Estrae la lingua principale dall'analisi dei messaggi (opzionale ma utile)
        group_language = None
        if group_doc.get("message_analysis") and group_doc["message_analysis"][0].get("language_count"):
            lang_dict = group_doc["message_analysis"][0]["language_count"]
            if lang_dict: # Controlla che il dizionario non sia vuoto
                # Prende la lingua con la percentuale più alta
                group_language = max(lang_dict, key=lang_dict.get)

        group_info_map[collection_name] = {
            "group_id": group_doc.get("id"), # Campo 'id' al posto di 'group_doc.get("id")' del vecchio script
            "group_name": group_name, # Estratto da 'full_entity.chats[0].title'
            "group_username": group_doc.get("username"), # Campo 'username' è diretto
            "group_topic": group_topic, # Estratto da 'full_entity.full_chat.about'
            "group_language": group_language # Estratto da 'message_analysis'
        }

print(f"Trovate informazioni per {len(group_info_map)} gruppi.")

# ============================================================
# FASE 2: SETUP di iocsearcher e CICLO DI ESTRAZIONE
# ============================================================
searcher = Searcher()
all_found_iocs = [] # Una lista per raccogliere tutti gli IoC trovati

collections_da_analizzare = list(group_info_map.keys())

for collection_name in collections_da_analizzare:
    
    group_display_name = group_info_map[collection_name].get('group_name', 'Nome non trovato')
    print(f"\n--- Analizzando la collection: {collection_name} ({group_display_name}) ---")
    
    current_collection = db[collection_name]
    
    # Rimuovi .limit() per analizzare tutti i messaggi
    cursor = current_collection.find({}).limit(1000)

    for message_doc in cursor:
        message_text = message_doc.get("message", "")

        if not message_text:
            continue

        iocs_list = searcher.search_raw(message_text)

        if iocs_list:
            for ioc_tuple in iocs_list:
                ioc_type = ioc_tuple[0]
                ioc_value = ioc_tuple[1]
                
                # <<< MODIFICA: L'estrazione del sender_id rimane la stessa,
                # ma è importante notare che 'from_id' è spesso 'null' nei canali.
                # Il codice originale gestiva già questo caso correttamente.
                sender_id = None
                if message_doc.get("from_id") and isinstance(message_doc["from_id"], dict):
                    sender_id = message_doc["from_id"].get("user_id")

                all_found_iocs.append({
                    "timestamp": message_doc.get("date"), # Campo 'date' è corretto
                    "group_id": group_info_map[collection_name].get("group_id"),
                    "group_name": group_info_map[collection_name].get("group_name"),
                    "group_topic": group_info_map[collection_name].get("group_topic"),
                    "message_id": message_doc.get("id"), # Campo 'id' è corretto
                    "sender_id": sender_id,
                    "message_text": message_text,
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                })

print(f"\n\nAnalisi completata. Trovati in totale {len(all_found_iocs)} IoC candidati.")

# ============================================================
# FASE 3: SALVATAGGIO DEI RISULTATI SU CSV
# ============================================================
# <<< NESSUNA MODIFICA NECESSARIA IN QUESTA FASE
if all_found_iocs:
    df = pd.DataFrame(all_found_iocs)
    df.to_csv(output_csv_file, index=False, encoding='utf-8')
    
    print(f"Risultati salvati con successo nel file: {output_csv_file}")
    print("\nPrime 5 righe del file CSV:")
    print(df.head())
else:
    print("Nessun IoC trovato, nessun file CSV è stato creato.")

client.close()