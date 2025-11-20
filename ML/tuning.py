import pandas as pd
import torch
from sklearn.model_selection import train_test_split
from transformers import DistilBertTokenizerFast, DistilBertForSequenceClassification, Trainer, TrainingArguments
import os

# --- CONFIGURAZIONE ---
MODEL_NAME = 'distilbert-base-uncased' 
DATASET_FILE = '/kaggle/input/tuningdistilbert/dataset_training_context.csv'
OUTPUT_DIR = './cyber_classifier_model'
NUM_EPOCHS = 3 

# Dataset Class CORRETTA (con i dunder methods __)
class CyberDataset(torch.utils.data.Dataset):
    def __init__(self, encodings, labels):
        self.encodings = encodings
        self.labels = labels

    def __getitem__(self, idx):
        # Il trainer si aspetta tensori, non liste
        item = {key: torch.tensor(val[idx]) for key, val in self.encodings.items()}
        item['labels'] = torch.tensor(self.labels[idx])
        return item

    def __len__(self):
        return len(self.labels)

def main():
    print("--- 1. PREPARAZIONE DATI ---")
    try:
        df = pd.read_csv(DATASET_FILE)
        print(f"Dataset caricato: {len(df)} righe.")
    except FileNotFoundError:
        print("ERRORE: File csv non trovato. Assicurati di aver eseguito lo script precedente.")
        return

    # Pulizia e conversione
    df['message'] = df['message'].astype(str)
    
    # Split Train / Validation
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        df['message'].tolist(), 
        df['label'].tolist(), 
        test_size=0.2, 
        random_state=42
    )

    print(f"Training set: {len(train_texts)} esempi")
    print(f"Validation set: {len(val_texts)} esempi")

    # --- 2. TOKENIZZAZIONE ---
    print(f"Caricamento tokenizer ({MODEL_NAME})...")
    try:
        tokenizer = DistilBertTokenizerFast.from_pretrained(MODEL_NAME)
    except Exception as e:
        print(f"\nERRORE DI RETE: Non riesco a scaricare il tokenizer.\n{e}")
        print("Soluzione: Verifica la connessione internet o usa un proxy.")
        return

    train_encodings = tokenizer(train_texts, truncation=True, padding=True, max_length=128)
    val_encodings = tokenizer(val_texts, truncation=True, padding=True, max_length=128)

    train_dataset = CyberDataset(train_encodings, train_labels)
    val_dataset = CyberDataset(val_encodings, val_labels)

    # --- 3. CONFIGURAZIONE MODELLO ---
    print("Caricamento modello pre-addestrato...")
    model = DistilBertForSequenceClassification.from_pretrained(MODEL_NAME, num_labels=2)

    # Uso GPU se disponibile
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    print(f"Training su device: {device}")

    training_args = TrainingArguments(
        output_dir=OUTPUT_DIR,
        num_train_epochs=NUM_EPOCHS,
        per_device_train_batch_size=16,  
        per_device_eval_batch_size=64,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir='./logs',
        logging_steps=10,
        eval_strategy="epoch", # Aggiornato per versioni recenti di transformers
        save_strategy="epoch",
        load_best_model_at_end=True,
        save_total_limit=2, # Salva solo gli ultimi 2 checkpoint per risparmiare spazio
        report_to="none" 
    )

    # --- 4. ADDESTRAMENTO ---
    print("Avvio training...")
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset
    )

    trainer.train()

    # --- 5. SALVATAGGIO FINALE ---
    print(f"Salvataggio modello finale in {OUTPUT_DIR}...")
    model.save_pretrained(OUTPUT_DIR)
    tokenizer.save_pretrained(OUTPUT_DIR)
    
    # Test rapido
    print("\n--- TEST DI VERIFICA RAPIDO ---")
    test_phrases = ["Hello guys how are you", "New malware detected on IP 192.168.1.5"]
    inputs = tokenizer(test_phrases, padding=True, truncation=True, return_tensors="pt").to(device)
    outputs = model(**inputs)
    predictions = torch.argmax(outputs.logits, dim=-1)
    print(f"Frasi: {test_phrases}")
    print(f"Predizioni (0=Ham, 1=Cyber): {predictions.tolist()}")

if __name__ == "__main__":
    main()