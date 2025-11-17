# ====================================================================
# Script V6: Utilizza search_raw per un output robusto e prevedibile
# ====================================================================

# 1. SETUP
from pymongo import MongoClient
from iocsearcher.searcher import Searcher

# ============================================================
# FASE 0: CONNESSIONE AL DATABASE E CONFIGURAZIONE
# ============================================================
uri = "mongodb://DPA_Project_ReadOnly:DPA_sd_2025@130.192.238.49:27015/?authSource=admin"
GRUPPI_DA_ANALIZZARE = ["ToreSays®️ + Chat", "Herbalism and natural cures"]

client = MongoClient(uri)
db = client["GroupMonitoringRelease"]
groups_collection = db["groups"]

# ============================================================
# FASE 1: TROVARE LE COLLECTION DI MESSAGGI PER I GRUPPI SCELTI
# ============================================================
print("Cerco le informazioni dei gruppi selezionati...")

target_groups_docs = groups_collection.find({"chat_name": {"$in": GRUPPI_DA_ANALIZZARE}})

collections_da_analizzare = []
for group_doc in target_groups_docs:
    collection_name = group_doc.get("collection_name")
    if collection_name:
        collections_da_analizzare.append(collection_name)
        print(f"  -> Trovato gruppo '{group_doc.get('chat_name')}'. Collection messaggi: {collection_name}")

# ============================================================
# FASE 2: SETUP di iocsearcher e CICLO DI ESTRAZIONE
# ============================================================
searcher = Searcher()
total_iocs_found = 0

for collection_name in collections_da_analizzare:
    print(f"\n--- Analizzando la collection: {collection_name} ---")
    current_collection = db[collection_name]
    
    # Analizziamo un buon numero di messaggi per trovare qualcosa
    cursor = current_collection.find({}).limit(20000)

    for message_doc in cursor:
        message_text = message_doc.get("message", "")

        if not message_text:
            continue

        # USA SEARCH_RAW, che restituisce una LISTA di TUPLE
        iocs_list = searcher.search_raw(message_text)

        if iocs_list:
            print("-" * 20)
            print(f"  Messaggio con potenziale IoC (ID: {message_doc.get('id')})")
            print(f"  Testo: {message_text[:200]}...")
            print("  IoC Estratti:")
            
            total_iocs_found += len(iocs_list)
            
            # Ora iteriamo sulla lista di tuple, che è un'operazione sicura
            # Ogni tupla è (tipo, valore, pos, testo_originale)
            for ioc_tuple in iocs_list:
                ioc_type = ioc_tuple[0]
                ioc_value = ioc_tuple[1]
                print(f"    - Tipo: {ioc_type}, Valore: {ioc_value}")

print(f"\n\nAnalisi completata. Trovati in totale {total_iocs_found} IoC nei gruppi selezionati.")
client.close()

