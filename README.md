# IoC Detection on Telegram: Research & Operational Pipeline

This project investigates the presence of **Indicators of Compromise (IoCs)** in Telegram messages. It combines an offline analysis pipeline based on Natural Language Processing (NLP) with an operational monitoring system using **Wazuh (SIEM/SOAR)** for real-time threat response.

## 🚀 Project Overview

The repository is divided into two main components:

1. **Offline Analysis (Research):** * Comparison between **DistilBERT** and **SecureBERT** models to filter security-relevant messages.
* IoC extraction using `iocsearcher` and custom Regex.
* Threat validation through the **VirusTotal API**.


2. **Real-Time Monitoring (Operational):**
* A **Telegram Listener** bot that monitors groups in real-time.
* Integration with **Wazuh** to generate alerts and trigger **Active Responses** (automated user banning for malicious content).



## 📂 Repository Structure

Based on the project organization, here is the directory map:

* **`DistilBERT/`** & **`SecureBERT/`**: Contain the Jupyter Notebooks for model fine-tuning, IoC identification, and VirusTotal validation.
* **`metrics/`**: Visualizations and figures generated during the research phase (Heatmaps, Overlap counts).
* **`BOT_Telegram/Telegram_Listener/`**: The core bot logic (`bot_listener.py`) and Docker configuration for deployment.
* **`BOT_Telegram/Wazuh/`**: Scripts for Wazuh integration, including the automated executor for banning users.


## 🛠️ Technical Workflow

### 1. Research Pipeline

* **Preprocessing**: Messages are cleaned and masked (e.g., replacing URLs/IPs with placeholders) to help models focus on the semantic context.
* **Filtering**: SecureBERT is used to identify technical discussions with higher sensitivity than general-purpose models.
* **Validation**: Extracted IoCs are checked against VirusTotal. Our research found a high concentration of malicious IPs in "Software & Applications" groups and malicious domains in "Darknet" groups.

### 2. Operational System (SIEM/SOAR)

* **Detection**: The Sentinel Bot listens to configured chats and forwards suspicious IoCs to a log file (`virustotal_results.json`).
* **Alerting**: Wazuh monitors this JSON file. If an IoC exceeds the malicious threshold, a Wazuh rule triggers.
* **Response**: An Active Response script automatically kicks/bans the sender from the Telegram group via the Bot API.

## ⚙️ Installation & Setup

1. **Clone the Repo**:
```bash
git clone https://github.com/Simolaaaab/IoC_on_Telegram.git

```


2. **Configuration**:
* Set your `TG_API_ID`, `TG_API_HASH`, and `VT_API_KEY` in the environment variables or `.env` file.


3. **Deployment**:
* Use the provided **Dockerfile** and `docker-compose.yml` to run the Sentinel Bot.
* Configure the Wazuh Agent to monitor the `/app/logs/` directory.



---

*This is a University Project developed at **Politecnico di Torino**.*

---