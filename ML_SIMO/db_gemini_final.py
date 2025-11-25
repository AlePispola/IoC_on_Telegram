import pandas as pd
from datasets import load_dataset
import random
import requests
import io
import urllib3

# Disabilita i warning SSL (necessario per Mac/alcune reti)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("--- GENERAZIONE DATASET THESIS V10 (FINAL HYBRID) ---")

# ==============================================================================
# CONFIGURAZIONE & UTILS
# ==============================================================================
SAFE_URLS = [
    "https://www.google.com", "http://www.youtube.com", "https://facebook.com",
    "www.amazon.com", "https://en.wikipedia.org", "https://t.me", "https://github.com",
    "https://stackoverflow.com", "https://repubblica.it"
]

# 1. Per Classe 0: Inietta link sicuri in chat normali
def inject_link_safe(text):
    if pd.isna(text): return text
    url = random.choice(SAFE_URLS)
    if random.random() < 0.2: return url # Solo link
    return f"{text} {url}"

# 2. Per Classe 1: Maschera una minaccia da messaggio chat (Adversarial)
def make_threat_chatty(text):
    if pd.isna(text): return text
    # Prendiamo solo i primi 60 caratteri della minaccia (es. l'URL o l'oggetto mail)
    snippet = text[:60]
    prefixes = [
        "Bro check this scam", "Is this real?", "Look at this", 
        "WTF is this??", "Check this out", "Verify this link",
        "Hey, is this you?", "I found this suspicious site",
        "Be careful with this"
    ]
    return f"{random.choice(prefixes)} {snippet}"

df_class_0_parts = []
df_class_1_parts = []

# ==============================================================================
# 1. CLASSE 0 (BENIGN): Chat Reali + POCHE News Tech
# ==============================================================================
print("\n1. Costruzione Classe 0 (Benign)...")

# --- A. Telegram Ham (Chat) ---
try:
    print("   -> Caricamento Telegram Ham...")
    ds_tele = load_dataset("thehamkercat/telegram-spam-ham", split="train")
    df_tele = pd.DataFrame(ds_tele)
    df_tele_ham = df_tele[df_tele['text_type'] == 'ham'].copy()
    df_tele_ham = df_tele_ham.rename(columns={'text': 'message'})
    
    # Prendiamo 3500 messaggi (Volume alto per imparare lo stile chat)
    sample_tele = df_tele_ham.sample(n=min(len(df_tele_ham), 3500), random_state=42)
    
    # Hard Negatives: Mettiamo link sicuri nel 50% dei casi
    sample_tele['message'] = sample_tele['message'].apply(lambda x: inject_link_safe(x) if random.random() > 0.5 else x)
    
    df_class_0_parts.append(sample_tele[['message']])
    print(f"      OK: Aggiunti {len(sample_tele)} messaggi Telegram.")
except Exception as e:
    print(f"      ERRORE Telegram: {e}")

# --- B. News Tech (AG News) - RIDOTTO ---
# Ne mettiamo poche (500) solo per il vocabolario base, non per dominare
try:
    print("   -> Caricamento AG News (Ridotto)...")
    ds_news = load_dataset("ag_news", split="train")
    df_news = pd.DataFrame(ds_news)
    # Label 3 = Tech
    df_tech = df_news[df_news['label'] == 3].sample(n=500, random_state=42)
    df_tech = df_tech.rename(columns={'text': 'message'})
    df_class_0_parts.append(df_tech[['message']])
    print(f"      OK: Aggiunti {len(df_tech)} articoli Tech (Limitati).")
except Exception as e:
    print(f"      ERRORE News: {e}")


# ==============================================================================
# 2. CLASSE 1 (CYBER): Phishing + CTI + Chatty Threats
# ==============================================================================
print("\n2. Costruzione Classe 1 (Cyber Threats)...")

# --- A. Phishing Dataset (Tesi) - BASE ---
print("   -> Caricamento Phishing Dataset (ealvaradob)...")
json_url = "https://huggingface.co/datasets/ealvaradob/phishing-dataset/resolve/main/combined_reduced.json"

try:
    # Usiamo requests con verify=False per il fix SSL
    response = requests.get(json_url, verify=False)
    df_phish_thesis = pd.read_json(io.BytesIO(response.content))
    df_phish_mal = df_phish_thesis[df_phish_thesis['label'] == 1].copy()
    
    # 1. Phishing Standard (2000 righe)
    sample_std = df_phish_mal.sample(n=min(len(df_phish_mal), 2000), random_state=42)
    df_class_1_parts.append(sample_std[['text']].rename(columns={'text': 'message'}))
    print(f"      OK: Aggiunti {len(sample_std)} Phishing Standard.")
    
    # 2. Chatty Threats (1000 righe) - CRITICO PER IL TUO PROBLEMA
    # Prendiamo altri 1000 esempi e li rendiamo "Chatty"
    if len(df_phish_mal) > 3000:
        sample_chatty = df_phish_mal.sample(n=1000, random_state=99)
        sample_chatty['text'] = sample_chatty['text'].apply(make_threat_chatty)
        df_class_1_parts.append(sample_chatty[['text']].rename(columns={'text': 'message'}))
        print(f"      OK: Aggiunti {len(sample_chatty)} Chatty Threats (Adversarial).")
        
except Exception as e:
    print(f"      ERRORE Download Phishing: {e}")

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

# --- C. CTI Reports (CRITICO PER 'WINDOWS SERVER') ---
# Questo insegna al modello che il linguaggio tecnico PUÒ essere malevolo
try:
    print("   -> Caricamento CTI Reports (mrmoor)...")
    ds_cti = load_dataset("mrmoor/cyber-threat-intelligence", split="train")
    df_cti = pd.DataFrame(ds_cti)
    # Prendiamo 1500 report
    sample_cti = df_cti.sample(n=min(len(df_cti), 1500), random_state=42)
    df_class_1_parts.append(sample_cti[['text']].rename(columns={'text': 'message'}))
    print(f"      OK: Aggiunti {len(sample_cti)} Report Tecnici CTI.")
except Exception as e:
    print(f"      ERRORE CTI: {e}")


# ==============================================================================
# 3. SALVATAGGIO & BILANCIAMENTO
# ==============================================================================
print("\n3. Elaborazione Finale...")

df_final = pd.concat([pd.concat(df_class_0_parts).assign(label=0), 
                      pd.concat(df_class_1_parts).assign(label=1)])

# Pulizia
df_final = df_final.dropna(subset=['message'])
df_final['message'] = df_final['message'].astype(str)
df_final = df_final[df_final['message'].str.strip() != ""]
df_final = df_final.drop_duplicates(subset=['message'])

# Bilanciamento Esatto
count_0 = len(df_final[df_final['label']==0])
count_1 = len(df_final[df_final['label']==1])
min_count = min(count_0, count_1)

print(f"   -> Disponibili: Classe 0 = {count_0} | Classe 1 = {count_1}")
print(f"   -> Bilanciamento a {min_count} righe per classe.")

df_0_bal = df_final[df_final['label']==0].sample(n=min_count, random_state=42)
df_1_bal = df_final[df_final['label']==1].sample(n=min_count, random_state=42)

df_final_v10 = pd.concat([df_0_bal, df_1_bal]).sample(frac=1, random_state=42).reset_index(drop=True)

filename = "dataset_final.csv"
df_final_v10.to_csv(filename, index=False)

print("\n" + "="*40)
print(f"DATASET PRONTO: {filename}")
print(f"Totale righe: {len(df_final_v10)}")
print("Distribuzione:")
print(df_final_v10['label'].value_counts())
print("="*40)