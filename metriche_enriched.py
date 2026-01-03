import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

# ================= CONFIGURATION =================
pd.set_option('display.max_rows', None)
pd.set_option('display.width', 1000)
sns.set_theme(style="whitegrid") # Clean theme for professional slides

# Threshold to consider an IoC "Confirmed Malicious"
VT_THRESHOLD = 1  # As requested: vt_malicious > 0

def print_header(title):
    print("\n" + "█"*80)
    print(f"👉 {title}")
    print("█"*80)

# ================= 1. DATA LOADING & PREPARATION =================
try:
    # Load Datasets
    df_distil = pd.read_csv('csv_final/ENRICHED_IOC_DATASET.csv')
    df_distil['Model'] = 'DistilBERT'
    
    df_secure = pd.read_csv('csv_final/SECUREBERT_ENRICHED_IOC_DATASET.csv')
    df_secure['Model'] = 'SecureBERT'
    
    # --- DATASET 1: FULL COMBINED (For Comparative Metrics) ---
    # We keep duplicates here to compare how each model performed on the same data
    df_combined = pd.concat([df_distil, df_secure], ignore_index=True)
    df_combined['vt_malicious'] = pd.to_numeric(df_combined['vt_malicious'], errors='coerce').fillna(0).astype(int)
    
    # Categorize Threat Level
    def categorize_threat(score):
        if score == 0: return 'Clean/Unknown'
        if score < 3: return 'Suspicious (1-2 Engines)'
        return 'Malicious (3+ Engines)'
    df_combined['Threat_Level'] = df_combined['vt_malicious'].apply(categorize_threat)

    # --- DATASET 2: UNIQUE MALICIOUS FINDINGS (For System Metrics) ---
    # 1. Filter only confirmed malicious (vt_malicious > 0)
    df_malicious = df_combined[df_combined['vt_malicious'] > 0].copy()
    
    # 2. Remove duplicates (if both models found the same IoC in the same message, count it once)
    df_malicious_unique = df_malicious.drop_duplicates(subset=['msg_id', 'ioc_value'])

    print(f"✅ Data Loaded successfully.")
    print(f"   - Total Findings (Comparative): {len(df_combined)}")
    print(f"   - Unique Confirmed Malicious Findings (System View): {len(df_malicious_unique)}")

except FileNotFoundError:
    print("❌ Error: CSV files not found. Please upload 'ENRICHED_IOC_DATASET.csv' and 'SECUREBERT_ENRICHED_IOC_DATASET.csv'.")
    exit()

# ==============================================================================
# PART 1: COMPARATIVE METRICS (DistilBERT vs SecureBERT) - ENGLISH
# ==============================================================================

# --- METRIC 1: Detection Rate Comparison ---
print_header("1. Validation Rate Comparison (Detection Rate)")

# Calculate % of IoCs confirmed malicious per model
stats = df_combined.groupby('Model')['vt_malicious'].apply(lambda x: (x > 0).mean() * 100).reset_index()
stats.columns = ['Model', 'Confirmed_Malicious_Rate (%)']
print(stats)

plt.figure(figsize=(10, 6))
sns.countplot(data=df_combined, x='Model', hue='Threat_Level', palette='viridis')
plt.title("IoC Quality Extraction: DistilBERT vs SecureBERT")
plt.ylabel("Number of IoCs Sent to VirusTotal")
plt.xlabel("NLP Model")
plt.legend(title='VirusTotal Status')
plt.tight_layout()
plt.show()

# --- METRIC 2: Score Density (Violin Plot) ---
print_header("2. VirusTotal Score Density")
df_positives = df_combined[df_combined['vt_malicious'] > 0] # Only show positives for scale

plt.figure(figsize=(10, 6))
sns.violinplot(data=df_positives, x='Model', y='vt_malicious', palette='muted', inner='quartile')
plt.title("Density of VT Scores (Positive IoCs Only)")
plt.ylabel("Malicious Engines Count (vt_malicious)")
plt.grid(True, axis='y', linestyle='--', alpha=0.7)
plt.tight_layout()
plt.show()

# --- METRIC 3: Risk Analysis by Topic (Heatmap) ---
print_header("3. Risk Intensity by Topic (Heatmap)")
# Pivot: Mean VT score per Topic & IoC Type
heatmap_data = df_combined.pivot_table(index='topic', columns='ioc_type', values='vt_malicious', aggfunc='mean')

plt.figure(figsize=(12, 8))
sns.heatmap(heatmap_data, annot=True, fmt=".2f", cmap="Reds", linewidths=.5)
plt.title("Threat Intensity (Mean VT Score) by Topic & IoC Type")
plt.tight_layout()
plt.show()

# --- METRIC 4: Correlation NLP vs VT ---
print_header("4. Correlation: Model Confidence vs Reality")
df_sample = df_combined.sample(min(2000, len(df_combined)), random_state=42) # Sample for speed

g = sns.FacetGrid(df_sample, col="Model", height=6, aspect=1.2)
g.map(sns.scatterplot, "cyber_score", "vt_malicious", alpha=0.6)
g.set_axis_labels("NLP Cyber Score (Model Confidence)", "VT Malicious Count (Reality)")
g.fig.suptitle("Correlation: NLP Prediction vs External Validation", y=1.02)
plt.show()

# --- METRIC 5: Top Offenders (Groups) ---
print_header("5. Top 10 Telegram Groups for Confirmed Malware")
# Filter confirmed threats from combined dataset
confirmed_threats = df_combined[df_combined['vt_malicious'] >= 2] # Use >=2 for "High Confidence" threats here
top_groups = confirmed_threats['chat_name'].value_counts().head(10).reset_index()
top_groups.columns = ['Chat Name', 'Confirmed Malware Count']

plt.figure(figsize=(10, 6))
sns.barplot(data=top_groups, y='Chat Name', x='Confirmed Malware Count', palette='magma')
plt.title("Top 10 Groups by Confirmed Threat Volume (VT >= 2)")
plt.xlabel("Number of Malicious IoCs")
plt.tight_layout()
plt.show()

# ==============================================================================
# PART 2: SYSTEM METRICS (Merged & Filtered only Malicious > 0)
# ==============================================================================
print_header("PART 2: SYSTEM-WIDE METRICS (Only Confirmed Malicious IoCs)")

# --- SYSTEM METRIC A: Group Specialization (Heatmap) ---
# Filter: Only top groups and top IoC types from the VALIDATED MALICIOUS dataset
top_groups_list = df_malicious_unique['chat_name'].value_counts().head(5).index
top_types_list = df_malicious_unique['ioc_type'].value_counts().head(5).index

filtered_df = df_malicious_unique[
    df_malicious_unique['chat_name'].isin(top_groups_list) & 
    df_malicious_unique['ioc_type'].isin(top_types_list)
]

crosstab = pd.crosstab(filtered_df['chat_name'], filtered_df['ioc_type'])

print("Data for Heatmap (Absolute Counts of Malicious IoCs):")
print(crosstab)

plt.figure(figsize=(12, 8))
sns.heatmap(crosstab, annot=True, fmt='d', cmap="YlGnBu", linewidths=.5)
plt.title("Group Specialization: Verified Malicious IoCs Exchange")
plt.ylabel("Telegram Group")
plt.xlabel("IoC Type")
plt.tight_layout()
plt.show()

# --- SYSTEM METRIC B: Total Volume by Topic ---
topic_counts = df_malicious_unique['topic'].value_counts()

print("\nTotal Confirmed Malicious IoCs by Topic:")
print(topic_counts)

plt.figure(figsize=(10, 6))
sns.barplot(x=topic_counts.index, y=topic_counts.values, palette="rocket")
plt.title("Total Volume of CONFIRMED Malicious IoCs by Topic (VT > 0)")
plt.ylabel("Number of Unique Malicious IoCs")
plt.xlabel("Topic")

# Add value labels on top of bars
for i, v in enumerate(topic_counts.values):
    plt.text(i, v + (v*0.01), str(v), color='black', ha='center', fontweight='bold')

plt.tight_layout()
plt.show()

print("\n✅ All charts generated successfully.")