#!/bin/bash

# ============================================================
# CANDID — Servant Node Monitor
# Monitor nginx configuration file changes in real-time
# using inotifywait and sending signal to Master
# ============================================================

# Configuration
TARGET_FILE="/etc/nginx/sites-available/default" #other crucial files can be added
MASTER_IP="192.168.1.19" #depend on your master server
MASTER_PORT="7777" #can be adjusted to your own preference
SERVANT_IP=$(hostname -I | awk '{print $1}')
LOG_PREFIX="[CANDID-SERVANT]"

echo "$LOG_PREFIX Start monitoring on: $TARGET_FILE"
echo "$LOG_PREFIX The signal will be sent to the Master: $MASTER_IP:$MASTER_PORT"
echo "$LOG_PREFIX Servant IP: $SERVANT_IP"
echo "---------------------------------------------------"

# Main loop
while true; do
    # Event Listener
    EVENT=$(inotifywait -e modify,attrib --format '%e' "$TARGET_FILE" 2>/dev/null)

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    echo "$LOG_PREFIX [$TIMESTAMP] Event detected: $EVENT on $TARGET_FILE"

    # HTTP Payload
    PAYLOAD="servant_ip=$SERVANT_IP&target_file=$TARGET_FILE&event=$EVENT&timestamp=$TIMESTAMP"

    echo "$LOG_PREFIX Sending to Master..."

    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 5 \
        --data "$PAYLOAD" \
        "http://$MASTER_IP:$MASTER_PORT/alert")

    if [ "$RESPONSE" == "200" ]; then
        echo "$LOG_PREFIX Signal successfully received by Master"
    else
        echo "$LOG_PREFIX Signal failed to send, response code: $RESPONSE"
    fi

    echo "---------------------------------------------------"
done