# ====================================================================
# Script V11: Analisi Esclusiva MD5 su un Campione con AlienVault OTX
# ====================================================================

# 1. SETUP
import pandas as pd
from OTXv2 import OTXv2, IndicatorTypes
import time
import os

# ============================================================
# FASE 0: CONFIGURAZIONE
# ============================================================
OTX_API_KEY = "aff5d671b0d7718718715f7e95d9cff12412bb01e5b730cb1b86d6ca7c33ee22"  
input_csv_file = "iocs_trovati.csv"
output_csv_file = "iocs_arricchiti_otx_sample_md5_only.csv"

# === Definiamo la dimensione del campione da analizzare ===
SAMPLE_SIZE = 10

if not os.path.exists(input_csv_file):
    print(f"ERRORE: Il file '{input_csv_file}' non è stato trovato.")
    exit()

# === La Mappa di Traduzione da iocsearcher a OTX ===
# Per questa versione, ci concentriamo solo sull'MD5
IOC_TYPE_MAP = {
    'url': IndicatorTypes.URL,
    # Altri tipi vengono ignorati dal filtro che applichiamo sotto
}

# ============================================================
# FASE 1: LETTURA, FILTRAGGIO E CAMPIONAMENTO DEL CSV
# ============================================================
print(f"Leggo gli IoC candidati da '{input_csv_file}'...")
df_full = pd.read_csv(input_csv_file)

# <<< MODIFICA: Filtriamo il DataFrame per mantenere solo le righe dove 'ioc_type' è 'md5'
df_full = df_full[df_full['ioc_type'] == 'url'].copy()
print(f"Trovati {len(df_full)} IoC di tipo 'md5'.")


# Creiamo un campione casuale dal DataFrame filtrato
if len(df_full) == 0:
    print("Nessun IoC di tipo 'md5' trovato nel file. Lo script termina.")
    exit()
elif len(df_full) > SAMPLE_SIZE:
    df = df_full.sample(n=SAMPLE_SIZE, random_state=42) # random_state per la riproducibilità
    print(f"Creato un campione casuale di {SAMPLE_SIZE} IoC MD5.")
else:
    df = df_full
    print(f"Il dataset ha {len(df_full)} IoC MD5, li analizzerò tutti.")

df['otx_pulse_count'] = 0
df['is_malicious'] = False

# ============================================================
# FASE 2: CICLO DI ANALISI CON OTX
# ============================================================
otx = OTXv2(OTX_API_KEY)

# <<< MODIFICA: Il ciclo ora processerà solo IoC di tipo MD5
for index, row in df.iterrows():
    ioc_value = str(row['ioc_value'])
    ioc_type_str = row['ioc_type']
    
    # Usiamo la nostra mappa per "tradurre" il tipo di IoC
    otx_indicator_type = IOC_TYPE_MAP.get(ioc_type_str)

    # Questo controllo è ora quasi ridondante, ma lo teniamo per sicurezza
    if not otx_indicator_type:
        continue # Passa alla prossima riga
    
    print(f"\nAnalizzo {index + 1}/{len(df)} -> Tipo: {ioc_type_str}, Valore: {ioc_value}")

    try:
        # Usiamo direttamente il tipo mappato
        result = otx.get_indicator_details_full(otx_indicator_type, ioc_value)
        pulse_count = result.get('pulse_info', {}).get('count', 0)
        
        print(f"  -> Risultato OTX: Trovato in {pulse_count} report (Pulses).")
        
        # Aggiorniamo il DataFrame
        df.loc[index, 'otx_pulse_count'] = pulse_count
        if pulse_count > 0:
            df.loc[index, 'is_malicious'] = True

    except Exception as e:
        print(f"  -> IoC non trovato su OTX o errore API.")
        df.loc[index, 'otx_pulse_count'] = 0

    time.sleep(1)

# ============================================================
# FASE 3: SALVATAGGIO DEL CSV ARRICCHITO
# ============================================================
print("\nAnalisi del campione MD5 completata.")
df.to_csv(output_csv_file, index=False, encoding='utf-8')
print(f"Risultati del campione salvati con successo nel file: {output_csv_file}")