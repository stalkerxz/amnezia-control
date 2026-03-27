#!/usr/bin/env bash
set -euo pipefail
USER_NAME=${1:-amnezia}
sudo useradd -m -s /bin/bash "$USER_NAME" || true
sudo mkdir -p /home/$USER_NAME/.ssh
sudo chmod 700 /home/$USER_NAME/.ssh
sudo touch /home/$USER_NAME/.ssh/authorized_keys
sudo chmod 600 /home/$USER_NAME/.ssh/authorized_keys
sudo chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh
echo "User $USER_NAME prepared for SSH key login"
