import pandas as pd
from datasets import load_dataset
import random

print("--- GENERAZIONE DATASET BILANCIATO CON AUGMENTATION ---")

# Lista di domini sicuri/comuni per "sporcare" i messaggi normali
SAFE_URLS = [
    "https://www.google.com", "http://www.youtube.com", "https://facebook.com",
    "www.amazon.com", "https://en.wikipedia.org", "http://reddit.com",
    "https://www.nytimes.com", "www.instagram.com", "https://twitter.com",
    "http://weather.com", "www.netflix.com", "https://github.com"
]

def inject_link(text):
    """Prende un testo normale e ci appende un link a caso"""
    url = random.choice(SAFE_URLS)
    # A volte lo mette alla fine, a volte in mezzo (semplificato alla fine per ora)
    return f"{text} {url}"

# ==============================================================================
# 1. CLASSE 0 (NON-CYBER): Obiettivo 5000 righe (TUTTE CON LINK O TERMINI TECH)
# ==============================================================================
print("1. Costruzione Classe 0 (Super Hard Negatives)...")
df_class_0_parts = []

# A. Telegram Reali CON Link (Quelli originali)
try:
    dataset_tele = load_dataset("thehamkercat/telegram-spam-ham", split="train")
    df_tele = pd.DataFrame(dataset_tele)
    
    df_tele_links = df_tele[df_tele['text'].str.contains(r'http|www\.', case=False, regex=True, na=False)].copy()
    print(f"   -> Trovati {len(df_tele_links)} messaggi Telegram originali CON Link.")
    df_class_0_parts.append(df_tele_links)
    
    # B. Telegram "Augmented" (Chat normali + Link iniettato)
    # Calcoliamo quanti ne servono per arrivare a 2500 messaggi stile "Chat con link"
    missing = 2500 - len(df_tele_links)
    
    # Prendiamo messaggi SENZA link
    df_tele_clean = df_tele[~df_tele['text'].str.contains(r'http|www\.', case=False, regex=True, na=False)].copy()
    
    # Ne prendiamo un campione
    df_aug = df_tele_clean.sample(n=missing, random_state=42).copy()
    
    # APPLICHIAMO L'INIEZIONE
    df_aug['text'] = df_aug['text'].apply(inject_link)
    
    print(f"   -> Generati {len(df_aug)} messaggi sintetici (Chat + Link Sicuro).")
    df_class_0_parts.append(df_aug)

except Exception as e:
    print(f"Errore Telegram: {e}")

# C. AG News (Tech context - Hard Negatives semantici)
try:
    dataset_news = load_dataset("ag_news", split="train")
    df_news = pd.DataFrame(dataset_news)
    
    # 2500 News di tecnologia (contengono parole come system, server, code, ma sono news)
    df_tech = df_news[df_news['label'] == 3].sample(n=2500, random_state=42).copy()
    print(f"   -> Aggiunti {len(df_tech)} articoli Tech News.")
    df_class_0_parts.append(df_tech)
    
except Exception as e:
    print(f"Errore News: {e}")

# Unione Classe 0
df_class_0 = pd.concat(df_class_0_parts)
df_class_0['label'] = 0
if 'text' in df_class_0.columns:
    df_class_0 = df_class_0.rename(columns={'text': 'message'})
df_class_0 = df_class_0[['message', 'label']]

print(f"==> TOTALE CLASSE 0: {len(df_class_0)} righe (Tutte 'difficili').")


# ==============================================================================
# 2. CLASSE 1 (CYBER): Obiettivo 5000 righe
# ==============================================================================
print("\n2. Costruzione Classe 1 (Cyber Threats)...")
try:
    dataset_cyber = load_dataset("mrmoor/cyber-threat-intelligence", split="train")
    df_cyber = pd.DataFrame(dataset_cyber)
    
    # Rimuoviamo duplicati
    col = 'text' if 'text' in df_cyber.columns else df_cyber.columns[0]
    df_cyber = df_cyber.drop_duplicates(subset=[col])
    
    n_cyber = min(len(df_cyber), 5000)
    df_class_1 = df_cyber.sample(n=n_cyber, random_state=42).copy()
    
    df_class_1['label'] = 1
    df_class_1 = df_class_1.rename(columns={col: 'message'})
    df_class_1 = df_class_1[['message', 'label']]
    
    print(f"==> TOTALE CLASSE 1: {len(df_class_1)} righe.")

except Exception as e:
    print(f"Errore Cyber: {e}")
    df_class_1 = pd.DataFrame()

# ==============================================================================
# 3. SALVATAGGIO E PULIZIA FINALE
# ==============================================================================
if not df_class_0.empty and not df_class_1.empty:
    df_final = pd.concat([df_class_0, df_class_1])
    
    # 1. Pulizia righe vuote
    df_final = df_final.dropna(subset=['message'])
    df_final = df_final[df_final['message'].str.strip() != ""]
    
    print(f"Totale grezzo: {len(df_final)}")
    
    # 2. RIMOZIONE DUPLICATI (La tua modifica)
    # Teniamo 'first' (il primo che trova)
    df_final = df_final.drop_duplicates(subset=['message'], keep='first')
    
    # 3. Shuffle (Mescoliamo)
    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)
    
    filename = "dataset_training_augmented.csv"
    df_final.to_csv(filename, index=False)
    
    print("\n" + "="*30)
    print(f"DATASET GENERATO E PULITO: {filename}")
    print(f"Totale righe finali uniche: {len(df_final)}")
    print("Distribuzione Classi:")
    print(df_final['label'].value_counts())
    print("="*30)
    
    # Check rapido: siamo ancora bilanciati?
    counts = df_final['label'].value_counts()
    if abs(counts[0] - counts[1]) > 1000:
        print("⚠️ ATTENZIONE: La rimozione duplicati ha sbilanciato un po' le classi.")
        print("Va bene lo stesso per DistilBERT, ma tienilo a mente.")
    else:
        print("✅ Il dataset è ancora ben bilanciato.")

else:
    print("Errore generazione.")