import pandas as pd

db = pd.read_csv("ioc_db_filtered_english.csv")
messaggi = db["message_text"]
with open("dhn.txt", "w") as file:
    for m in messaggi:
        file.write(m)