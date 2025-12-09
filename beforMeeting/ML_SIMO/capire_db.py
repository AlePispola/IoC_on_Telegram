from datasets import load_dataset
import pandas as pd

# Lista dei dataset da ispezionare
datasets_to_check = [
    {"name": "sms_spam", "trust": False},
    {"name": "thehamkercat/telegram-spam-ham", "trust": False},
    {"name": "ag_news", "trust": False},
    {"name": "ealvaradob/phishing-dataset", "trust": True}, # Nota il True qui
    {"name": "mrmoor/cyber-threat-intelligence", "trust": False}
]

print("--- ANALISI STRUTTURA DATASET ---")

for ds_info in datasets_to_check:
    name = ds_info["name"]
    print(f"\n🔍 Ispeziono: {name}")
    try:
        # Carica solo le prime 10 righe (streaming=True) per fare veloce
        dataset = load_dataset(name, split="train", streaming=True, trust_remote_code=ds_info["trust"])
        
        # Prendi il primo elemento
        first_row = next(iter(dataset))
        
        print(f"   ✅ Colonne trovate: {list(first_row.keys())}")
        print(f"   📝 Esempio riga: {first_row}")
        
    except Exception as e:
        print(f"   ❌ Errore caricamento: {e}")


