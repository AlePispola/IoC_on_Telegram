import pandas as pd
from datasets import load_dataset

print("--- 1. CARICAMENTO DATASET 'IRRILEVANTE' (Telegram Spam/Ham) ---")
# Fonte: Chat reali di Telegram (sia spam che normali)
# Obiettivo: Insegnare al modello cosa NON è una minaccia cyber specifica (es. "Ciao", "Crypto scam", "Politica")
try:
    dataset_tele = load_dataset("thehamkercat/telegram-spam-ham", split="train")
    df_tele = pd.DataFrame(dataset_tele)
    
    # Prendiamo un campione bilanciato di Ham (chat normale) e Spam (pubblicità generica)
    # Questo rende il modello robusto contro il rumore tipico di Telegram
    df_ham = df_tele[df_tele['text_type'] == 'ham'].sample(n=3000)
    df_spam = df_tele[df_tele['text_type'] == 'spam'].sample(n=2000)
    
    # Uniamo e assegniamo LABEL 0 (Irrilevante per la CTI)
    df_class_0 = pd.concat([df_ham, df_spam])
    df_class_0['label'] = 0 
    df_class_0 = df_class_0.rename(columns={'text': 'message'})
    df_class_0 = df_class_0[['message', 'label']] # Teniamo solo le colonne utili
    
    print(f"--> Caricati {len(df_class_0)} messaggi generici (Classe 0).")
    
except Exception as e:
    print(f"Errore nel caricamento dataset Telegram: {e}")
    df_class_0 = pd.DataFrame()

print("\n--- 2. CARICAMENTO DATASET 'RILEVANTE' (Cyber Threat Intelligence) ---")
# Fonte: Report reali di cybersecurity (APT, Malware, CVE)
# Obiettivo: Insegnare al modello il linguaggio tecnico delle minacce.
# Sostituiamo il dataset inesistente con 'mrmoor/cyber-threat-intelligence'
try:
    # Nota: 'split="train"' è necessario per caricare subito i dati
    dataset_cyber = load_dataset("mrmoor/cyber-threat-intelligence", split="train")
    df_cyber = pd.DataFrame(dataset_cyber)
    
    # Questo dataset ha una colonna 'text' che contiene il report completo.
    # Assegniamo LABEL 1 (Rilevante / Minaccia)
    df_class_1 = df_cyber[['text']].copy()
    df_class_1['label'] = 1
    df_class_1 = df_class_1.rename(columns={'text': 'message'})
    
    # Prendiamo un campione di 5000 righe per bilanciare esattamente con la classe 0
    if len(df_class_1) > 5000:
        df_class_1 = df_class_1.sample(n=5000)
        
    print(f"--> Caricati {len(df_class_1)} report di cybersecurity (Classe 1).")

except Exception as e:
    print(f"Errore nel caricamento dataset Cyber: {e}")
    df_class_1 = pd.DataFrame()

print("\n--- 3. UNIONE E SALVATAGGIO ---")
if not df_class_0.empty and not df_class_1.empty:
    # Uniamo i due dataframe
    df_final = pd.concat([df_class_0, df_class_1])
    
    # Mescoliamo i dati (shuffle) così il modello non impara l'ordine
    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)
    
    print("Statistiche Dataset Finale:")
    print(df_final['label'].value_counts())
    
    # Pulizia base: Rimuoviamo righe vuote o NaN
    len_pre = len(df_final)
    df_final = df_final.dropna(subset=['message'])
    df_final = df_final[df_final['message'].str.strip() != ""]
    df_final = df_final.drop_duplicates(subset=['message'])
    print(f"Rimosse {len_pre - len(df_final)} righe vuote.")
    
    # Salvataggio
    filename = "dataset_training_context.csv"
    df_final.to_csv(filename, index=False)
    print(f"\n[SUCCESSO] Dataset salvato come '{filename}' con {len(df_final)} righe.")
    print("Ora puoi usare questo file per il fine-tuning di DistilBERT.")
else:
    print("\n[ERRORE] Uno dei due dataset non è stato caricato. Controlla la connessione o i nomi dei dataset.")