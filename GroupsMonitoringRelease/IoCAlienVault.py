# ====================================================================
# Script V10: Analisi Multi-Tipo su un Campione con AlienVault OTX
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
input_csv_file = "GroupsMonitoringRelease/iocs_trovati.csv"
output_csv_file = "iocs_arricchiti_otx_sample.csv"

# === NUOVO: Definiamo la dimensione del campione da analizzare ===
SAMPLE_SIZE = 1000

if not os.path.exists(input_csv_file):
    print(f"ERRORE: Il file '{input_csv_file}' non è stato trovato.")
    exit()

# === NUOVO: La Mappa di Traduzione da iocsearcher a OTX ===
# Abbiamo analizzato i tuoi 29 tipi e li abbiamo mappati a quelli di OTX
IOC_TYPE_MAP = {
    'url': IndicatorTypes.URL,
    'ip4': IndicatorTypes.IPv4,
    'ip6': IndicatorTypes.IPv6,
    'fqdn': IndicatorTypes.DOMAIN,
    'md5': IndicatorTypes.FILE_HASH_MD5,
    'sha1': IndicatorTypes.FILE_HASH_SHA1,
    'sha256': IndicatorTypes.FILE_HASH_SHA256,
    'cve': IndicatorTypes.CVE,
    'ip4Net': IndicatorTypes.CIDR,
    'email': IndicatorTypes.EMAIL
    # Tipi che iocsearcher trova ma OTX non ha un endpoint specifico. 
    # Vengono ignorati da questo script.
    # 'telegramHandle', 'twitterHandle', 'instagramHandle', 'youtubeHandle', 
    # 'uuid', 'trademark', 'youtubeChannel', 'githubHandle', 'facebookHandle', 
    # 'email', 'copyright', 'packageName', 'tron', 'solana', 'linkedinHandle', 
    # 'phoneNumber', 'tox', 'iban'
}

# ============================================================
# FASE 1: LETTURA E CAMPIONAMENTO DEL CSV
# ============================================================
print(f"Leggo gli IoC candidati da '{input_csv_file}'...")
df_full = pd.read_csv(input_csv_file)
print(f"Trovati {len(df_full)} IoC totali nel file.")

# === NUOVA SEZIONE DI FILTRAGGIO ===
# Filtro #1: Seleziona solo le righe con il topic "Darknet"
print("Applico filtro per topic 'Darknet'...")
df_filtered_topic = df_full[df_full["group_topic"] == "Darknet"]

# Filtro #2: Dalle righe filtrate, escludi quelle dove l'ioc_value è 't.me'
print("Applico filtro per escludere IoC 't.me'...")
df_filtered = df_filtered_topic[df_filtered_topic["ioc_value"] != "t.me"]

num_filtered_iocs = len(df_filtered)
print(f"Trovati {num_filtered_iocs} IoC candidati dopo i filtri.")


if len(df_full) > SAMPLE_SIZE:
    df = df_filtered.sample(n=SAMPLE_SIZE, random_state=42) # random_state per la riproducibilità
    print(f"Creato un campione casuale di {SAMPLE_SIZE} IoC su {len(df_full)} totali.")
else:
    df = df_filtered
    print("Il dataset ha meno di 10k righe, li analizzerò tutti.")

df['otx_pulse_count'] = 0
df['is_malicious'] = False

# ============================================================
# FASE 2: CICLO DI ANALISI CON OTX
# ============================================================
otx = OTXv2(OTX_API_KEY)
count = 0
for index, row in df.iterrows():
    ioc_value = str(row['ioc_value'])
    ioc_type_str = row['ioc_type']
    
    # Usiamo la nostra mappa per "tradurre" il tipo di IoC
    otx_indicator_type = IOC_TYPE_MAP.get(ioc_type_str)

    # Se il tipo non è nella nostra mappa, lo saltiamo in modo pulito
    if not otx_indicator_type:
        continue # Passa alla prossima riga del CSV
    
    print(f"\nAnalizzo {count}/{len(df)} -> Tipo: {ioc_type_str}, Valore: {ioc_value}")
    count = count +1
    try:
        result = otx.get_indicator_details_full(otx_indicator_type, ioc_value)
        pulse_count = result.get('pulse_info', {}).get('count', 0)
        
        print(f"  -> Risultato OTX: Trovato in {pulse_count} report (Pulses).")
        
        # Aggiorniamo il DataFrame originale nei punti giusti
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
print("\nAnalisi del campione completata.")
df.to_csv(output_csv_file, index=False, encoding='utf-8')
print(f"Risultati del campione salvati con successo nel file: {output_csv_file}")