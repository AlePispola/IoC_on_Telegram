import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ================= CONFIGURAZIONE =================
INPUT_CSV = "IOC_DATASET.csv"
VT_RESULTS_JSON = "virustotal_full_results.json"
pd.set_option('display.max_rows', None)
pd.set_option('display.width', 1000)

def print_header(title):
    print(f"\n{'='*60}\n📊 {title}\n{'='*60}")

# 1. Caricamento e Merge
try:
    df_csv = pd.read_csv(INPUT_CSV)
    df_vt = pd.read_json(VT_RESULTS_JSON, lines=True)
except ValueError:
    print("⚠️ Errore: Assicurati di aver generato il file JSON con lo script di scansione!")
    exit()

# Uniamo i dati originali con i risultati VT usando l'IoC come chiave
# Inner join: analizziamo solo quelli che hanno un risultato VT
merged = df_csv.merge(df_vt, left_on='ioc_value', right_on='ioc', how='inner')

# Creiamo un subset solo per i MALEVOLI 
malicious_df = merged[merged['malicious'] >= 0].copy()

sns.set_theme(style="whitegrid")

# =========================================================
# METRICA 1: Chi condivide più roba infetta? (Per Gruppo)
# =========================================================
print_header("CLASSIFICA GRUPPI: Numero di IoC Malevoli inviati")
group_mal_counts = malicious_df['chat_name'].value_counts().head(10)
print(group_mal_counts.reset_index(name='IoC Malevoli'))

plt.figure(figsize=(10, 6))
sns.barplot(x=group_mal_counts.values, y=group_mal_counts.index, palette="Reds_r")
plt.title("Top 10 Gruppi per invio di IoC Malevoli (VT > 1)")
plt.xlabel("Numero di IoC Malevoli unici")
plt.tight_layout()
plt.show()

# =========================================================
# METRICA 2: Qual è il Topic più pericoloso?
# =========================================================
print_header("PERICOLOSITÀ PER TOPIC")
topic_stats = merged.groupby('topic').apply(
    lambda x: pd.Series({
        'Totale Scansionati': len(x),
        'Malevoli': len(x[x['malicious'] >= 0]),
        '% Infetti': (len(x[x['malicious'] >= 0]) / len(x) * 100) if len(x)>0 else 0
    })
).sort_values('% Infetti', ascending=False)

print(topic_stats)

# Grafico della % di infezione
plt.figure(figsize=(8, 5))
sns.barplot(x=topic_stats.index, y=topic_stats['% Infetti'], palette="Oranges_r")
plt.title("Percentuale di IoC Malevoli per Topic")
plt.ylabel("% di IoC risultati infetti")
plt.tight_layout()
plt.show()

# =========================================================
# METRICA 3: I "King of Malware" (I 10 IoC più rilevati)
# =========================================================
print_header("TOP 10 IOC PIÙ MALEVOLI TROVATI")
# Prendiamo gli IoC unici ordinati per numero di engine antivirus che li rilevano
top_bad_iocs = df_vt.sort_values('malicious', ascending=False).head(10)
top_bad_iocs_display = top_bad_iocs[['ioc', 'vt_type', 'malicious', 'total_engines']]

print(top_bad_iocs_display.to_string(index=False))

# =========================================================
# METRICA 4: Distribuzione Temporale (Se hai le date)
# =========================================================
# Se nel CSV originale c'è una colonna data, vediamo quando sono stati mandati i malware
if 'date' in malicious_df.columns:
    malicious_df['date'] = pd.to_datetime(malicious_df['date'], errors='coerce')
    malicious_df = malicious_df.dropna(subset=['date'])
    daily_malware = malicious_df.groupby(malicious_df['date'].dt.date).size()
    
    if not daily_malware.empty:
        print_header("Trend Temporale Attacchi")
        print(daily_malware.tail(10)) # Ultimi 10 giorni attivi

        plt.figure(figsize=(10, 5))
        daily_malware.plot(kind='line', marker='o', color='red')
        plt.title("Timeline rilevamento IoC Malevoli nelle chat")
        plt.ylabel("N. Malware")
        plt.grid(True)
        plt.tight_layout()
        plt.show()