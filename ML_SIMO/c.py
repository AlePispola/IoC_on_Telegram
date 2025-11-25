import pandas as pd
import requests
import io

print("--- ISPEZIONE STRUTTURA JSON EALVARADOB ---")

# URL diretto al file JSON del dataset "combined_reduced"
json_url = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/combined_reduced.json"

try:
    print(f"Scaricamento anteprima da: {json_url}...")
    response = requests.get(json_url)
    
    if response.status_code == 200:
        # Leggiamo il JSON direttamente in un DataFrame
        df_preview = pd.read_json(io.StringIO(response.text))
        
        print("\n✅ DATI SCARICATI CON SUCCESSO!")
        print(f"Dimensioni: {df_preview.shape}")
        
        print("\n1. NOMI COLONNE:")
        print(list(df_preview.columns))
        
        print("\n2. ANTEPRIMA RIGHE:")
        pd.set_option('display.max_colwidth', 100) # Per vedere bene il testo
        print(df_preview.head(5))
        
        print("\n3. ANALISI LABEL (Distribuzione):")
        print(df_preview['label'].value_counts())
        
        print("\n4. CONTROLLO VISIVO RAPIDO (Per capire cos'è 1 e cos'è 0):")
        # Prendiamo un esempio di label 1
        example_1 = df_preview[df_preview['label'] == 1].iloc[0]['text']
        print(f"\n---> ESEMPIO LABEL 1:\n{example_1[:300]}...")
        
        # Prendiamo un esempio di label 0
        example_0 = df_preview[df_preview['label'] == 0].iloc[0]['text']
        print(f"\n---> ESEMPIO LABEL 0:\n{example_0[:300]}...")
        
    else:
        print(f"❌ Errore HTTP: {response.status_code}")

except Exception as e:
    print(f"❌ Errore esecuzione: {e}")