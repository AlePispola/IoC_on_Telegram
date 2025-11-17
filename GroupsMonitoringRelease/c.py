import pandas as pd

df = pd.read_csv(r'/Users/simonecapriolo/Desktop/Project Jha/IoCTelegram/GroupsMonitoringRelease/iocs_trovati.csv')

# Conteggi per ogni tipo di IOC
counts = df['group_topic'].value_counts()

# Percentuali per ogni tipo di IOC
percentages = df['group_topic'].value_counts(normalize=True) * 100

# Combinare tutto in un unico DataFrame
summary = pd.DataFrame({
    'count': counts,
    'percentage': percentages.round(2)
})

print(summary)



