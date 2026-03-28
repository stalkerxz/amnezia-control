#!/usr/bin/env bash
set -euo pipefail
STAMP=$(date +%F-%H%M%S)
BACKUP_DIR="/root/amnezia-backup-$STAMP"
sudo mkdir -p "$BACKUP_DIR"
sudo cp -a /etc/amnezia "$BACKUP_DIR" || true
sudo cp -a /opt/amnezia "$BACKUP_DIR" || true
sudo tar -czf "$BACKUP_DIR.tar.gz" -C /root "$(basename "$BACKUP_DIR")"
echo "Backup created: $BACKUP_DIR.tar.gz"
