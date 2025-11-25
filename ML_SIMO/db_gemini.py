import pandas as pd
from datasets import load_dataset
import random
import requests
import io
import urllib3

# Disabilita i warning se il certificato SSL fa i capricci
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("--- GENERAZIONE DATASET THESIS V8 (SSL FIX + BOOSTER) ---")

# ==============================================================================
# CONFIGURAZIONE
# ==============================================================================
SAFE_URLS = [
    "https://www.google.com", "http://www.youtube.com", "https://facebook.com",
    "www.amazon.com", "https://en.wikipedia.org", "https://t.me", "https://github.com",
    "https://stackoverflow.com", "https://repubblica.it", "https://netflix.com"
]

def inject_link_smart(text):
    if pd.isna(text): return text
    url = random.choice(SAFE_URLS)
    dice = random.random()
    if dice < 0.2: return url  # 20% Solo Link (Simula link nudi)
    elif dice < 0.6: return f"{text} {url}"
    else: return f"Check {url}: {text}"

# Liste accumulo
df_class_0_parts = []
df_class_1_parts = []

# ==============================================================================
# 1. CLASSE 0 (BENIGN): Target ~4000+ righe
# ==============================================================================
print("\n1. Costruzione Classe 0 (Benign)...")

# --- A. Telegram Ham ---
try:
    print("   -> Caricamento Telegram Ham...")
    ds_tele = load_dataset("thehamkercat/telegram-spam-ham", split="train")
    df_tele = pd.DataFrame(ds_tele)
    
    # Filtro 'ham'
    df_tele_ham = df_tele[df_tele['text_type'] == 'ham'].copy()
    df_tele_ham = df_tele_ham.rename(columns={'text': 'message'})
    
    # Prendiamo FINO A 3000 messaggi (se ce ne sono meno, prende tutti)
    count_tele = min(len(df_tele_ham), 3000)
    sample_tele = df_tele_ham.sample(n=count_tele, random_state=42)
    
    # Hard Negatives Injection
    sample_tele['message'] = sample_tele['message'].apply(lambda x: inject_link_smart(x) if random.random() > 0.4 else x)
    
    df_class_0_parts.append(sample_tele[['message']])
    print(f"      OK: Aggiunti {len(sample_tele)} messaggi Telegram.")
except Exception as e:
    print(f"      ERRORE Telegram: {e}")

# --- B. News Tech (AG News) ---
try:
    print("   -> Caricamento AG News (Tech)...")
    ds_news = load_dataset("ag_news", split="train")
    df_news = pd.DataFrame(ds_news)
    # Label 3 = Tech
    df_tech = df_news[df_news['label'] == 3].sample(n=2500, random_state=42)
    df_tech = df_tech.rename(columns={'text': 'message'})
    df_class_0_parts.append(df_tech[['message']])
    print(f"      OK: Aggiunti {len(df_tech)} articoli Tech.")
except Exception as e:
    print(f"      ERRORE News: {e}")

# ==============================================================================
# 2. CLASSE 1 (CYBER): Target ~4000+ righe
# ==============================================================================
print("\n2. Costruzione Classe 1 (Cyber Threats)...")

# --- A. Phishing Dataset (TESI) - METODO ROBUSTO (REQUESTS) ---
print("   -> Caricamento Phishing Dataset (ealvaradob) con requests...")
json_url = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/combined_reduced.json"

try:
    # USIAMO REQUESTS INVECE DI PANDAS DIRETTO PER EVITARE ERRORE SSL MAC
    # verify=False forza il download anche se il certificato non piace al Mac
    response = requests.get(json_url, verify=False)
    
    if response.status_code == 200:
        # Leggiamo dal contenuto scaricato in memoria
        df_phish_thesis = pd.read_json(io.BytesIO(response.content))
        
        # Filtro label=1
        df_phish_mal = df_phish_thesis[df_phish_thesis['label'] == 1].copy()
        
        # Prendiamo 3500 righe per fare volume
        count_phish = min(len(df_phish_mal), 3500)
        sample = df_phish_mal.sample(n=count_phish, random_state=42)
        
        df_class_1_parts.append(sample[['text']].rename(columns={'text': 'message'}))
        print(f"      OK: Aggiunti {len(sample)} messaggi Phishing Tesi.")
    else:
        print(f"      ERRORE HTTP: {response.status_code}")

except Exception as e:
    print(f"      ERRORE DOWNLOAD REQUESTS: {e}")

# --- B. SMS Spam ---
try:
    print("   -> Caricamento SMS Spam...")
    ds_sms = load_dataset("sms_spam", split="train")
    df_sms = pd.DataFrame(ds_sms)
    df_spam = df_sms[df_sms['label'] == 1].copy()
    
    df_class_1_parts.append(df_spam[['sms']].rename(columns={'sms': 'message'}))
    print(f"      OK: Aggiunti {len(df_spam)} SMS Spam.")
except Exception as e:
    print(f"      ERRORE SMS: {e}")

# ==============================================================================
# 3. CONSOLIDAMENTO FINALE & BILANCIAMENTO
# ==============================================================================
print("\n3. Elaborazione Finale...")

# Unione provvisoria
df_0_final = pd.concat(df_class_0_parts)
df_0_final['label'] = 0

if not df_class_1_parts:
    print("ERRORE CRITICO: Classe 1 vuota. Controlla la connessione internet.")
    exit()

df_1_final = pd.concat(df_class_1_parts)
df_1_final['label'] = 1

df_final = pd.concat([df_0_final, df_1_final])

# Pulizia
df_final = df_final.dropna(subset=['message'])
df_final['message'] = df_final['message'].astype(str)
df_final = df_final[df_final['message'].str.strip() != ""]
df_final = df_final.drop_duplicates(subset=['message'])

# Bilanciamento
count_0 = len(df_final[df_final['label']==0])
count_1 = len(df_final[df_final['label']==1])
min_count = min(count_0, count_1)

print(f"   -> Totali Disponibili: Classe 0 = {count_0} | Classe 1 = {count_1}")
print(f"   -> Bilanciamento a {min_count} per classe.")

df_0_bal = df_final[df_final['label']==0].sample(n=min_count, random_state=42)
df_1_bal = df_final[df_final['label']==1].sample(n=min_count, random_state=42)

df_final_balanced = pd.concat([df_0_bal, df_1_bal]).sample(frac=1, random_state=42).reset_index(drop=True)

filename = "dataset_thesis_v8.csv"
df_final_balanced.to_csv(filename, index=False)

print("\n" + "="*40)
print(f"DATASET PRONTO: {filename}")
print(f"Totale righe finali: {len(df_final_balanced)}")
print("Distribuzione:")
print(df_final_balanced['label'].value_counts())
print("="*40)