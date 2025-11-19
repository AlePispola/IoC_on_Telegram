# ====================================================================
# Script V16: Interazione Diretta con l'API di URLScan usando 'requests'
# ====================================================================

# 1. SETUP
# Esegui nel terminale: pip install pandas requests
import pandas as pd
import requests # La libreria standard per le richieste HTTP
import time
import os

# ============================================================
# FASE 0: CONFIGURAZIONE
# ============================================================
URLSCAN_API_KEY = "019a9266-cab8-72ec-a24e-d0f27b10075d"
input_csv_file = "iocs_found_Uselection2024.csv"
output_csv_file = "iocs_url_arricchiti_urlscan.csv"

URL_SAMPLE_SIZE = 100 

if not os.path.exists(input_csv_file):
    print(f"ERRORE: Il file '{input_csv_file}' non è stato trovato.")
    exit()

# ============================================================
# FASE 1: FILTRAGGIO E CAMPIONAMENTO DEGLI URL (invariato)
# ============================================================
print(f"Leggo gli IoC da '{input_csv_file}'...")
df_full = pd.read_csv(input_csv_file)
print(f"Trovati {len(df_full)} IoC totali.")

df_urls = df_full[df_full['ioc_type'] == 'url'].copy()
print(f"Isolati {len(df_urls)} IoC di tipo URL.")

if len(df_urls) > URL_SAMPLE_SIZE:
    df_sample = df_urls.sample(n=URL_SAMPLE_SIZE, random_state=42)
    print(f"Creato un campione casuale di {URL_SAMPLE_SIZE} URL da analizzare.")
else:
    df_sample = df_urls
    print(f"Il numero di URL ({len(df_urls)}) è inferiore a {URL_SAMPLE_SIZE}. Li analizzerò tutti.")

df_sample['urlscan_verdict'] = 'N/A'
df_sample['urlscan_is_malicious'] = False
df_sample['urlscan_report_url'] = ''

# ============================================================
# FASE 2: CICLO DI ANALISI CON URLSCAN.IO (USANDO REQUESTS)
# ============================================================
# Definiamo gli header per l'autenticazione, come da documentazione
headers = {
    'Content-Type': 'application/json',
    'API-Key': URLSCAN_API_KEY
}

for index, row in df_sample.iterrows():
    ioc_value = str(row['ioc_value'])
    
    progress_counter = list(df_sample.index).index(index) + 1
    print(f"\nAnalizzo {progress_counter}/{len(df_sample)} -> URL: {ioc_value}")

    try:
        # --- FASE 2.1: SUBMIT DELLA SCANSIONE (con requests.post) ---
        submit_url = "https://urlscan.io/api/v1/scan/"
        payload = {"url": ioc_value, "visibility": "public"}
        
        response = requests.post(submit_url, headers=headers, json=payload)
        response.raise_for_status() # Lancia un errore se la richiesta non è andata a buon fine (es. 401, 429)

        scan_uuid = response.json()['uuid']
        print(f"  -> URL inviato per la scansione. UUID: {scan_uuid}")
        
        # --- FASE 2.2: ATTESA ---
        print("  -> Attendo 20 secondi per il completamento della scansione...")
        time.sleep(30)
        
        # --- FASE 2.3: RECUPERO DEL RISULTATO (con requests.get) ---
        result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
        
        result_response = requests.get(result_url)
        # Non lanciamo un errore per 404, lo gestiamo
        if result_response.status_code == 404:
            print("  -> Risultato non ancora pronto o UUID non valido. Salto.")
            df_sample.loc[index, 'urlscan_verdict'] = "Result Not Ready / Not Found"
            continue # Passa al prossimo URL

        result_response.raise_for_status() # Lancia un errore per altri problemi
        
        scan_result = result_response.json()
        
        # Il resto della logica per analizzare il risultato è identico
        verdicts = scan_result.get('verdicts', {})
        overall_verdict = verdicts.get('overall', {})
        
        is_malicious = overall_verdict.get('malicious', False)
        score = overall_verdict.get('score', 0)
        verdict_str = f"Malicious: {is_malicious}, Score: {score}"
        report_url = scan_result.get('task', {}).get('reportURL', '')
        
        print(f"  -> Risultato URLScan: {verdict_str}")
        
        df_sample.loc[index, 'urlscan_verdict'] = verdict_str
        df_sample.loc[index, 'urlscan_is_malicious'] = is_malicious
        df_sample.loc[index, 'urlscan_report_url'] = report_url

    except requests.exceptions.RequestException as e:
        print(f"  -> ERRORE DI RETE durante la scansione: {e}")
        df_sample.loc[index, 'urlscan_verdict'] = f"Network Error: {e}"
    except Exception as e:
        print(f"  -> ERRORE GENERICO durante la scansione: {e}")
        df_sample.loc[index, 'urlscan_verdict'] = f"Error: {e}"

# ============================================================
# FASE 3: SALVATAGGIO DEL CSV FINALE
# ============================================================
print("\nAnalisi del campione di URL completata.")
df_sample.to_csv(output_csv_file, index=False, encoding='utf-8')
print(f"Risultati salvati con successo nel file: {output_csv_file}")