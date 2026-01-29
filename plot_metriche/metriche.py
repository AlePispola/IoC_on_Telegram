import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter
import re

### GRAFICI E TABELLE

# ================= CONFIGURAZIONE =================
# Impostazioni per visualizzare tutte le colonne/righe nelle tabelle in console
pd.set_option('display.max_rows', None)
pd.set_option('display.max_columns', None)
pd.set_option('display.width', 1000)
pd.set_option('display.colheader_justify', 'left')

# Funzione helper per stampare titoli delle tabelle
def print_table_header(title):
    print("\n" + "="*60)
    print(f"📊 TABELLA DATI: {title}")
    print("="*60)

# 1. Caricamento Dati
df = pd.read_csv('DistilBERT/IOC_DATASET.csv')
sns.set_theme(style="whitegrid") 

# =========================================================
# METRICA 1: Volume per Gruppo
# =========================================================
top_groups = df['chat_name'].value_counts().head(10)

# -- STAMPA TABELLA --
print_table_header("Volume di IoC estratti per Gruppo (Top 10)")
# Convertiamo in DataFrame per una stampa pulita
table_1 = top_groups.reset_index()
table_1.columns = ['Nome Gruppo', 'Numero IoC']
print(table_1)

# -- GRAFICO --
plt.figure(figsize=(10, 6))
sns.barplot(x=top_groups.values, y=top_groups.index, palette="viridis")
plt.title("Volume di IoC estratti per Gruppo")
plt.xlabel("Numero di IoC")
plt.tight_layout()
plt.show()

# =========================================================
# METRICA 2: Heatmap (Chi scambia cosa)
# =========================================================
top_groups_list = df['chat_name'].value_counts().head(5).index
top_types_list = df['ioc_type'].value_counts().head(5).index
filtered_df = df[df['chat_name'].isin(top_groups_list) & df['ioc_type'].isin(top_types_list)]

# Creiamo la tabella pivot
crosstab = pd.crosstab(filtered_df['chat_name'], filtered_df['ioc_type'])

# -- STAMPA TABELLA --
print_table_header("Specializzazione Gruppi vs Tipo IoC (Valori Assoluti)")
print(crosstab)

# -- GRAFICO --
plt.figure(figsize=(12, 8))
sns.heatmap(crosstab, annot=True, fmt='d', cmap="YlGnBu", linewidths=.5)
plt.title("Specializzazione dei Gruppi: Quali IoC scambiano?")
plt.tight_layout()
plt.show()

# =========================================================
# METRICA 3: Analisi del Contesto
# =========================================================
def analyze_context(ioc_type):
    texts = df[df['ioc_type'] == ioc_type]['text'].dropna().tolist()
    text_blob = " ".join(texts).lower()
    words = re.findall(r'\b\w{4,}\b', text_blob)
    stopwords = {'http', 'https', 'with', 'this', 'that', 'from', 'code', 'data', 'sono', 'come', 'delle'}
    clean_words = [w for w in words if w not in stopwords]
    return Counter(clean_words).most_common(5)

# Prepariamo i dati per la tabella
words_ip = analyze_context('ip4')
words_url = analyze_context('url')

# -- STAMPA TABELLA --
print_table_header("Parole più frequenti nel contesto (NLP)")
df_context = pd.DataFrame({
    'Rank': [1, 2, 3, 4, 5],
    'IP Context': [f"{w} ({c})" for w, c in words_ip],
    'URL Context': [f"{w} ({c})" for w, c in words_url]
})
print(df_context.to_string(index=False))

# (Nessun grafico qui, solo print come da tuo script originale)

# =========================================================
# METRICA 4A: Volume totale per Topic
# =========================================================
topic_counts = df['topic'].value_counts()

# -- STAMPA TABELLA --
print_table_header("Volume Totale per Topic")
table_4a = topic_counts.reset_index()
table_4a.columns = ['Topic', 'Totale IoC']
print(table_4a)

# -- GRAFICO --
plt.figure(figsize=(8, 5))
sns.barplot(x=topic_counts.index, y=topic_counts.values, palette="rocket")
plt.title("Volume totale di IoC per Topic")
plt.ylabel("Numero di IoC")
plt.xlabel("Topic")
plt.tight_layout()
plt.savefig('metric_topic_volume.png')
plt.show()

# =========================================================
# METRICA 4B: Topic vs Tipo IoC (Percentuali)
# =========================================================
crosstab_topic = pd.crosstab(df['topic'], df['ioc_type'], normalize='index')
relevant_types = ['url', 'ip4', 'fqdn', 'email', 'phoneNumber', 'bitcoin', 'md5']
# Filtriamo solo le colonne che esistono davvero nel dataset
existing_cols = [c for c in relevant_types if c in crosstab_topic.columns]
crosstab_topic_filtered = crosstab_topic[existing_cols]

# -- STAMPA TABELLA --
print_table_header("Distribuzione % dei Tipi di IoC per Topic")
# Moltiplichiamo per 100 e arrotondiamo per leggere meglio
print(crosstab_topic_filtered.mul(100).round(2).astype(str) + '%')

# -- GRAFICO --
plt.figure(figsize=(10, 6))
sns.heatmap(crosstab_topic_filtered, annot=True, fmt=".1%", cmap="Purples", linewidths=.5)
plt.title("Composizione percentuale degli IoC per Topic")
plt.ylabel("Topic")
plt.xlabel("Tipo di IoC")
plt.tight_layout()
plt.savefig('metric_topic_heatmap.png')
plt.show()

print("\n--- GENERAZIONE GRAFICO 1: Rilevanti + Altro ---")

# Creiamo una copia per non modificare il dataset originale
df_grouped = df.copy()

# Logica: Se il tipo è nella lista rilevante lo teniamo, altrimenti lo chiamiamo 'Other'
df_grouped['ioc_category'] = df_grouped['ioc_type'].apply(lambda x: x if x in relevant_types else 'Other')

# Creiamo la crosstab normalizzata
crosstab_grouped = pd.crosstab(df_grouped['topic'], df_grouped['ioc_category'], normalize='index')

# Riordiniamo le colonne per mettere "Other" alla fine per pulizia visiva
# Prendiamo le colonne rilevanti che esistono effettivamente + 'Other' (se esiste)
cols_order = [c for c in relevant_types if c in crosstab_grouped.columns]
if 'Other' in crosstab_grouped.columns:
    cols_order.append('Other')
    
crosstab_grouped = crosstab_grouped[cols_order]

# -- PLOT GRAFICO 1 --
plt.figure(figsize=(12, 6))
sns.heatmap(crosstab_grouped, annot=True, fmt=".1%", cmap="Purples", linewidths=.5)
plt.title("Composizione % IoC per Topic (Con categoria 'Altro' per arrivare al 100%)")
plt.ylabel("Topic")
plt.xlabel("Categoria IoC")
plt.tight_layout()
plt.savefig('metric_topic_heatmap_100percent.png') # Salva con nome diverso
plt.show()

# =========================================================
# GRAFICO 2: TUTTI I TIPI DI IOC (Visione Completa)
# =========================================================
print("\n--- GENERAZIONE GRAFICO 2: Visione Completa ---")

# Qui facciamo la crosstab su TUTTI i tipi originali, senza filtri
crosstab_full = pd.crosstab(df['topic'], df['ioc_type'], normalize='index')

# -- PLOT GRAFICO 2 --
# Aumentiamo la larghezza perché ci saranno molte più colonne
plt.figure(figsize=(16, 8)) 
sns.heatmap(crosstab_full, annot=True, fmt=".1%", cmap="Blues", linewidths=.5)
plt.title("Composizione % Completa di TUTTI i tipi di IoC (Senza filtri)")
plt.ylabel("Topic")
plt.xlabel("Tutti i Tipi di IoC")

# Ruotiamo le etichette dell'asse X se sono tante, per leggerle meglio
plt.xticks(rotation=45, ha='right') 

plt.tight_layout()
plt.savefig('metric_topic_heatmap_full.png') # Salva con nome diverso
plt.show()

# =========================================================
# METRICA 4C: Top 3 IoC per Topic
# =========================================================
top_ioc_by_topic = df.groupby(['topic', 'ioc_value']).size().reset_index(name='count')
top_ioc_by_topic = top_ioc_by_topic.sort_values(['topic', 'count'], ascending=[True, False])
top3 = top_ioc_by_topic.groupby('topic').head(3)

# -- STAMPA TABELLA --
print_table_header("Top 3 IoC specifici per Topic")
# Puliamo un po' la tabella finale per la stampa
final_table = top3.rename(columns={'topic': 'Topic', 'ioc_value': 'IoC', 'count': 'Frequenza'})
print(final_table.to_string(index=False))

print("\n" + "="*60)
print("✅ Finito. Tutte le tabelle sono state stampate sopra i grafici.")

# =========================================================
# METRICA EXTRA: WORD CLOUD (Nuvola di Parole)
# =========================================================
from wordcloud import WordCloud # Assicurati di aver fatto: pip install wordcloud

print("\n--- GENERAZIONE WORD CLOUD ---")

# 1. Calcoliamo la frequenza di ogni Tipo di IoC
# (Crea un dizionario tipo: {'url': 500, 'ip4': 200, 'phoneNumber': 50...})
freq_dict = df['ioc_type'].value_counts().to_dict()

# 2. Configuriamo la Word Cloud
# - width/height: risoluzione
# - background_color: colore di sfondo (white è meglio per le slide)
# - colormap: schema colori (es. 'viridis', 'magma', 'inferno', 'plasma')
# 2. Configuriamo la Word Cloud (Versione Compatta)
wordcloud = WordCloud(
    width=1600, 
    height=800, 
    background_color='white', 
    colormap='viridis',
    prefer_horizontal=0.9, # Mantiene quasi tutto orizzontale
    relative_scaling=0.5,  # <--- FONDAMENTALE: 0.5 rende tutto più compatto (default è 1 auto)
    max_font_size=250,     # <--- Limita la grandezza massima per non far esplodere la prima parola
    margin=2,              # <--- Riduce il margine tra le parole
    random_state=42        # <--- Blocca il layout (così se lo rifai esce uguale)
).generate_from_frequencies(freq_dict)

# 3. Disegniamo il grafico
plt.figure(figsize=(15, 8))
plt.imshow(wordcloud, interpolation='bilinear')
plt.axis("off") # Nascondiamo gli assi X e Y che qui non servono
plt.title("IoC Word Cloud: I tipi di minaccia più frequenti", fontsize=20, pad=20)
plt.tight_layout()
plt.savefig('metric_wordcloud.png') # Salva l'immagine
plt.show()

print("✅ Word Cloud generata con successo!")