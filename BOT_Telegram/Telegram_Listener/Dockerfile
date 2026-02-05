FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy dependency requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories for logs and Telegram sessions
RUN mkdir -p /app/logs /app/session

# Copy the bot script into the container
COPY bot_listener.py .

# Define the command to start the bot
CMD ["python", "bot_listener.py"]