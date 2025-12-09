# ============================================================
# Script di Generazione Dataset V2: Basato su Dataset Multi-Sorgente
# ============================================================
import pandas as pd
from datasets import load_dataset
import random

print("--- GENERAZIONE DATASET BILANCIATO V2 ---")

# ... (La parte della Classe 0 rimane quasi identica, è già ottima) ...
print("1. Costruzione Classe 0 (Hard Negatives)...")
# ... (codice per caricare telegram-spam-ham e ag_news) ...

# ==============================================================================
# 2. CLASSE 1 (CYBER): OBIETTIVO 5000+ RIGHE (DA MOLTEPLICI FONTI)
# ==============================================================================
print("\n2. Costruzione Classe 1 (Cyber Threats da fonti diverse)...")
df_class_1_parts = []
TARGET_SIZE_PER_SOURCE = 1500 # Prendiamo N esempi da ogni fonte per diversificare

# --- Fonte 1: Cyber Threat Intelligence Tweets (la migliore!) ---
try:
    ds_tweets = load_dataset("g-ronimo/cyber-threat-intelligence-tweets", split="train")
    df_tweets = pd.DataFrame(ds_tweets).rename(columns={'text': 'message'})
    df_tweets = df_tweets.sample(n=min(len(df_tweets), TARGET_SIZE_PER_SOURCE), random_state=42)
    df_class_1_parts.append(df_tweets[['message']])
    print(f"   -> Aggiunti {len(df_tweets)} esempi da Cyber-Threat Tweets.")
except Exception as e:
    print(f"Errore caricamento Cyber Tweets: {e}")

# --- Fonte 2: Phishing/Spam SMS ---
try:
    ds_sms = load_dataset("sms_spam", split="train")
    df_sms = pd.DataFrame(ds_sms).rename(columns={'sms': 'message'})
    df_sms_spam = df_sms[df_sms['label'] == 1].copy() # 1 è l'etichetta per 'spam'
    df_sms_spam = df_sms_spam.sample(n=min(len(df_sms_spam), TARGET_SIZE_PER_SOURCE), random_state=42)
    df_class_1_parts.append(df_sms_spam[['message']])
    print(f"   -> Aggiunti {len(df_sms_spam)} esempi da SMS Spam.")
except Exception as e:
    print(f"Errore caricamento SMS Spam: {e}")

# --- Fonte 3: Phishing Emails (se riusciamo a trovarne una buona su HF) ---
# Esempio con un dataset che potrebbe esistere, da verificare
try:
    # NOTA: Il nome del dataset qui è inventato, va cercato quello giusto!
    ds_phish = load_dataset("phishing-email-dataset-name", split="train")
    df_phish = pd.DataFrame(ds_phish).rename(columns={'text': 'message'})
    df_phish = df_phish.sample(n=min(len(df_phish), TARGET_SIZE_PER_SOURCE), random_state=42)
    df_class_1_parts.append(df_phish[['message']])
    print(f"   -> Aggiunti {len(df_phish)} esempi da Phishing Emails.")
except Exception as e:
    print(f"   -> Nota: Dataset di phishing email non trovato/caricato (da cercare).")

# --- Fonte 4: La base originale, per non perdere il contesto tecnico ---
try:
    ds_cyber_orig = load_dataset("mrmoor/cyber-threat-intelligence", split="train")
    df_cyber_orig = pd.DataFrame(ds_cyber_orig).rename(columns={'text': 'message'})
    df_cyber_orig = df_cyber_orig.sample(n=min(len(df_cyber_orig), 1000), random_state=42) # Ne teniamo un po'
    df_class_1_parts.append(df_cyber_orig[['message']])
    print(f"   -> Aggiunti {len(df_cyber_orig)} esempi dal dataset tecnico originale.")
except Exception as e:
    print(f"Errore caricamento Cyber Threat Intelligence: {e}")


# Unione di tutte le fonti per la Classe 1
if df_class_1_parts:
    df_class_1 = pd.concat(df_class_1_parts)
    df_class_1['label'] = 1
    print(f"==> TOTALE CLASSE 1: {len(df_class_1)} righe da fonti multiple.")
else:
    df_class_1 = pd.DataFrame()


# ==============================================================================
# 3. SALVATAGGIO FINALE (invariato)
# ==============================================================================
# ... (il resto del tuo script di pulizia, shuffle e salvataggio) ...