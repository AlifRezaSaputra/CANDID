# CANDID — Configuration Anti-Drift & Incident Detector

Sistem monitoring keamanan real-time berbasis event-driven untuk mendeteksi 
dan meremedasi Configuration Drift secara otomatis.

## Arsitektur
- **Master Node**: Pusat orkestrasi (Python 3 + Paramiko)
- **Servant Node**: Target server yang dimonitor (Bash + inotify-tools)
- **Output Gateway**: Notifikasi instan via Telegram API

## Status
🚧 In Development — MVP Target: 10 Juni 2026
