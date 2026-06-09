#!/usr/bin/env python3

import os
import json
import logging
import paramiko
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
import urllib.request

from telegramConfig import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID

# --- Configuration ---
MASTER_PORT        = 7777
SERVANT_USER       = "slave"
SSH_KEY_PATH       = os.path.expanduser("~/.ssh/candid_key")
BASELINE_DIR       = os.path.expanduser("~/CANDID/baseline")
BASELINE_HASH_FILE = os.path.join(BASELINE_DIR, "baseline_hashes.json")
LOG_FILE           = os.path.expanduser("~/CANDID/logs/candid_security.log")

# --- Logging Setup ---
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("CANDID")

# --- Helper Functions ---
def send_telegram(message: str):
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        data = json.dumps({
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "Markdown"
        }).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"}
        )
        urllib.request.urlopen(req, timeout=10)
        log.info("Telegram notification sent successfully")
    except Exception as e:
        log.error(f"Failed to send Telegram notification: {e}")

def get_remote_hash(ssh: paramiko.SSHClient, filepath: str) -> str:
    _, stdout, _ = ssh.exec_command(f"sha256sum {filepath} 2>/dev/null")
    result = stdout.read().decode().strip()
    return result.split()[0] if result else "FILE_NOT_FOUND"

def get_remote_perm(ssh: paramiko.SSHClient, filepath: str) -> str:
    _, stdout, _ = ssh.exec_command(f"stat -c '%a' {filepath} 2>/dev/null")
    result = stdout.read().decode().strip()
    return result if result else "000"

# --- Core Remediation Engine ---
def remediate(servant_ip: str, target_file: str, event: str, timestamp: str):
    start_time = time.time()
    log.warning(f"SIGNAL RECEIVED | IP: {servant_ip} | File: {target_file} | Event: {event}")

    if not os.path.exists(BASELINE_HASH_FILE):
        log.error(f"Baseline hash file not found at: {BASELINE_HASH_FILE}")
        return

    with open(BASELINE_HASH_FILE, "r") as f:
        baselines = json.load(f)

    baseline_key = None
    baseline_data = None
    for key, data in baselines.items():
        if data["path"] == target_file:
            baseline_key = key
            baseline_data = data
            break

    if not baseline_data:
        log.error(f"Target path unrecognized in baseline dictionary: {target_file}")
        return

    baseline_file = os.path.join(BASELINE_DIR, f"{baseline_key}.conf")
    expected_hash = baseline_data["hash"]
    safe_perm     = baseline_data["permission"]

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=servant_ip,
            username=SERVANT_USER,
            key_filename=SSH_KEY_PATH,
            timeout=10
        )

        current_hash = get_remote_hash(ssh, target_file)
        current_perm = get_remote_perm(ssh, target_file)
        
        log.info(f"Current State -> Hash: {current_hash} | Perm: {current_perm}")
        log.info(f"Expected State -> Hash: {expected_hash} | Perm: {safe_perm}")

        # Infinite loop protection
        if current_hash == expected_hash and current_perm == safe_perm:
            log.info("State matches baseline. Terminating cycle to prevent alert loop.")
            ssh.close()
            return

        log.warning(f"Drift detected! Initiating remediation on {target_file}...")
        is_content_restored = False

        # Content Restoration
        if current_hash != expected_hash:
            log.info("Hash mismatch. Synchronizing content via SCP...")
            temp_remote_path = f"/tmp/{baseline_key}.tmp"
            
            sftp = ssh.open_sftp()
            sftp.put(baseline_file, temp_remote_path)
            sftp.close()

            _, _, stderr = ssh.exec_command(f"sudo mv {temp_remote_path} {target_file}")
            mv_err = stderr.read().decode().strip()
            if mv_err:
                log.error(f"Failed to move file via sudo mv: {mv_err}")
            else:
                is_content_restored = True
                log.info("File content successfully overwritten with secure baseline.")
                time.sleep(0.2)

        # Attribute / Permission Restoration
        if current_perm != safe_perm or is_content_restored:
            log.info(f"Enforcing file permission back to {safe_perm} via sudo chmod...")
            _, _, stderr = ssh.exec_command(f"sudo chmod {safe_perm} {target_file}")
            chmod_err = stderr.read().decode().strip()
            
            ssh.exec_command(f"sudo chown root:root {target_file}")
            
            if chmod_err:
                log.error(f"Failed to execute sudo chmod: {chmod_err}")
            else:
                log.info("File permissions and ownership successfully restored.")
                time.sleep(0.2)

        # Reload Service
        log.info("Triggering hot-reload for Nginx daemon on Servant...")
        ssh.exec_command("sudo systemctl reload nginx")

        # Post-Remediation Verification
        final_hash = get_remote_hash(ssh, target_file)
        final_perm = get_remote_perm(ssh, target_file)
        ssh.close()

        remediated = (final_hash == expected_hash) and (final_perm == safe_perm)
        duration_ms = round((time.time() - start_time) * 1000)
        status = "SUCCESS" if remediated else "FAILED"

        log.info(f"Remediation Cycle Finished | Status: {status} | Duration: {duration_ms}ms")

        # Send Telemetry Alert
        emoji = "✅" if remediated else "❌"
        message = (
            f"{emoji} *CANDID — Incident Remediation*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f" Tian *Timestamp* : `{timestamp}`\n"
            f"🖥️ *Servant IP*: `{servant_ip}`\n"
            f"📄 *Target File* : `{target_file}`\n"
            f"⚡ *Trigger Event* : `{event}`\n"
            f"🔑 *Permission*: `{current_perm}` ➔ `{final_perm}`\n"
            f"🔑 *Hash Status*: `{'RESTORED' if is_content_restored else 'UNCHANGED'}`\n"
            f"⏱️ *Execution Time*: `{duration_ms}ms`\n"
            f"📊 *Remediation Result* : `{status}`\n"
            f"━━━━━━━━━━━━━━━━━━━━"
        )
        send_telegram(message)

    except Exception as e:
        duration_ms = round((time.time() - start_time) * 1000)
        log.error(f"Critical error within remediation handler: {e}")
        send_telegram(f"❌ *CANDID — Remediation System Error*\nTarget: `{target_file}`\nDetail: `{str(e)}`")

# --- HTTP Traffic Listener ---
class AlertHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/alert":
            length = int(self.headers.get("Content-Length", 0))
            body   = self.rfile.read(length).decode()
            params = parse_qs(body)

            servant_ip  = params.get("servant_ip",  ["unknown"])[0]
            target_file = params.get("target_file", ["unknown"])[0]
            event       = params.get("event",       ["unknown"])[0]
            timestamp   = params.get("timestamp",   ["unknown"])[0]

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")

            remediate(servant_ip, target_file, event, timestamp)

    def log_message(self, format, *args):
        pass

# --- Entrypoint ---
if __name__ == "__main__":
    log.info("=" * 50)
    log.info("CANDID Master Controller - Engine v2 Active")
    log.info(f"Listening for infrastructure updates on port {MASTER_PORT}...")
    log.info("=" * 50)
    server = HTTPServer(("0.0.0.0", MASTER_PORT), AlertHandler)
    server.serve_forever()