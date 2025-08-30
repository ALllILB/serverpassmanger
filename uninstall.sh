#!/bin/bash

# ServerPass Uninstaller
echo "Uninstalling ServerPass..."

# Stop and disable service
sudo systemctl stop serverpass 2>/dev/null || true
sudo systemctl disable serverpass 2>/dev/null || true

# Remove service file
sudo rm -f /etc/systemd/system/serverpass.service

# Remove application directory
sudo rm -rf /opt/serverpass

# Reload systemd
sudo systemctl daemon-reload

echo "ServerPass uninstalled successfully!"