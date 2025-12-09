# ====================================================================
# Script V4: Corretto per usare iocsearcher nel modo giusto
# ====================================================================

# 1. SETUP
# Esegui nel terminale una sola volta: pip install pymongo iocsearcher
from pymongo import MongoClient
# Importiamo la CLASSE 'Searcher' dalla libreria
from iocsearcher.searcher import Searcher

# ============================================================
# FASE 0: CONNESSIONE AL DATABASE E CONFIGURAZIONE
# ============================================================
uri = "mongodb://DPA_Project_ReadOnly:DPA_sd_2025@130.192.238.49:27015/?authSource=admin"
# Inserisci qui i nomi ESATTI dei gruppi che vuoi analizzare
GRUPPI_DA_ANALIZZARE = [
    "ToreSays®️ + Chat",
    "Herbalism and natural cures", # Ho aggiunto il secondo gruppo che hai trovato
]

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
    else:
        print(f"  -> ATTENZIONE: Il gruppo '{group_doc.get('chat_name')}' non ha un campo 'collection_name'.")

# ============================================================
# FASE 2: SETUP di iocsearcher e CICLO DI ESTRAZIONE
# ============================================================
# Creiamo l'oggetto Searcher UNA SOLA VOLTA prima del ciclo, per efficienza
searcher = Searcher()
total_iocs_found = 0

# Itera solo sulle collection che abbiamo selezionato
for collection_name in collections_da_analizzare:
    print(f"\n--- Analizzando la collection: {collection_name} ---")
    current_collection = db[collection_name]
    
    # Rimuovi .limit() per analizzare TUTTI i messaggi
    cursor = current_collection.find({}).limit(5000) # Limite aumentato per trovare più roba

    for message_doc in cursor:
        message_text = message_doc.get("message", "")

        if not message_text:
            continue

        # Usa il metodo search_data() dell'oggetto searcher
        iocs_found = searcher.search_data(message_text)

        # iocs_found è un SET di TUPLE, es: {('email', 'a@b.com'), ('url', 'http://c.de')}
        if iocs_found:
            print("-" * 20)
            print(f"  Messaggio con potenziale IoC (ID: {message_doc.get('id')})")
            print(f"  Testo: {message_text[:200]}...")
            print("  IoC Estratti:")
            
            total_iocs_found += len(iocs_found)
            # Iteriamo direttamente sul set di tuple
            for ioc_type, ioc_value in iocs_found:
                print(f"    - Tipo: {ioc_type}, Valore: {ioc_value}")

#print(f"\n\nAnalisi completata. Trovati in totale {total_iocs_found} IoC nei gruppi selezionati.")
client.close()