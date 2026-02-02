FROM python:3.9-slim

# Impostiamo la directory di lavoro
WORKDIR /app

# Copiamo i requisiti e installiamo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Creiamo le cartelle per log e sessioni
RUN mkdir -p /app/logs /app/session

# Copiamo lo script
COPY bot_listener.py .

# Comando di avvio
CMD ["python", "bot_listener.py"]