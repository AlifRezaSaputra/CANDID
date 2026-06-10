
# CANDID — Configuration Anti-Drift & Incident Detector

CANDID is a lightweight, event-driven File Integrity Monitoring (FIM) and automated remediation system designed to prevent configuration drift in Linux server infrastructures.

Unlike traditional polling-based configuration management tools, CANDID reacts **only when a real file system event occurs**, ensuring minimal resource usage, fast response time, and a reduced attack window.

---

## 🚀 Key Features

- **Pure Event-Driven Architecture**  
  Zero idle CPU usage by leveraging the Linux kernel `inotify` subsystem.  
  No periodic scans, no unnecessary polling.

- **Strict State Verification**  
  File integrity is validated using:
  - Cryptographic hash verification (SHA-256)
  - File permission enforcement (`stat`)

- **Automated Micro-Remediation**  
  Detected drifts are instantly healed via:
  - Secure SSH orchestration (Paramiko)
  - Two-stage remediation (content + attributes)
  - Zero-downtime service reloads (e.g., Nginx hot reload)

- **Real-Time Incident Telemetry**  
  Every incident and remediation cycle is reported instantly via Telegram Bot API for operational visibility.

---

## 🏗️ System Architecture

CANDID operates using a **Master–Agent distributed architecture**:

1. **Agent Node**  
   A lightweight Bash-based daemon running on each server:
   - Monitors critical configuration files using `inotifywait`
   - Emits events only when changes occur
   - Sends telemetry payloads to the Master controller

2. **Master Node**  
   A centralized Python 3 controller responsible for:
   - Receiving event signals over HTTP
   - Verifying file state against a secure baseline
   - Performing SSH-based remediation
   - Reloading affected services safely
---

## How It Works!

[ Agent Node ]
-> (ernel Event → HTTP Signal)
[ Master Controller ]
->(SSH / SFTP Remediation)
[ Agent Node (Healed State) ]
---

## ❓ Why CANDID?

Most configuration management and FIM tools rely on **polling-based mechanisms**, scanning the system every few seconds or minutes.  
This approach introduces:

- Continuous CPU usage
- Delayed detection windows
- Unnecessary system overhead

CANDID was built to address these problems by:

- Eliminating polling entirely
- Reacting only to kernel-level file system events
- Executing remediation only when a **real configuration drift is proven**

This makes CANDID suitable for systems where **performance efficiency, security, and reaction speed** are critical.

---

## 🛠️ Installation & Setup

### 1. Agent Node Setup

Install dependencies and run the monitoring daemon:

```bash
sudo apt update && sudo apt install inotify-tools
chmod +x servant/slaveMonitor.sh
./servant/slaveMonitor.sh
```
The agent will start monitoring the configured file(s) and emit events automatically.

### 2. Master Node Setup

Install Python dependencies and start the controller:
```bash
pip install paramiko
python3 master/masterController.py
```
Ensure the Master node is reachable from the Agent node (LAN, VPN, or Tailscale).


## 🔐 Telegram Configuration

CANDID uses Telegram Bot API for real-time incident notifications.

## Setup Steps
Copy the example configuration file:
```bash
cp telegramConfig.example.py telegramConfig.py
```
## Edit the file and insert your credentials:
```bash
TELEGRAM_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"
```
⚠️ Never commit telegramConfig.py to a public repository.

## 📊 Incident Report Example

When a configuration drift occurs (e.g., unauthorized chmod 777), CANDID automatically heals the system and broadcasts the following incident report:
```bash
✅ CANDID — Incident Remediation
━━━━━━━━━━━━━━━━━━━━
🕐 Timestamp       : 2026-06-09 14:56:31
🖥️ Agent IP        : 192.168.1.13
📄 Target File     : /etc/nginx/sites-available/default
⚡ Trigger Event   : ATTRIB
🔑 Permission     : 777 ➔ 644
🔑 Hash Status    : UNCHANGED
⏱️ Execution Time : 245ms
📊 Result          : SUCCESS
━━━━━━━━━━━━━━━━━━━━
```
## ⚠️ Current Limitations

The current version of CANDID intentionally keeps the design minimal and focused.
Known limitations include:

- No event buffering if the Master node is unavailable
- HTTP payloads are not yet authenticated (planned: HMAC signing)
- Single-file monitoring per agent instance
- No dry-run or audit-only mode

These limitations are planned for future development and security hardening.

## 🧠 Design Philosophy

CANDID follows these principles:

- React, don’t poll
- Verify before remediate
- Minimal moving parts
- Kernel-assisted detection
- Security over convenience

## 📌 Future Roadmap
- Authenticated event payloads (HMAC)
- Event buffering and replay
- Multi-file and directory monitoring
- Policy-based remediation
- Audit-only and dry-run modes
- Native VPN-aware deployments (e.g., Tailscale-first)

## 📜 License

This project is provided for educational and research purposes.
Use at your own risk in production environments.