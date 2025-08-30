#!/bin/bash
set -e

# ServerPass Auto Installer for Ubuntu
echo "Installing ServerPass..."

# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv

# Create application directory
sudo mkdir -p /opt/serverpass
sudo chown $USER:$USER /opt/serverpass

# Copy files to /opt/serverpass
cp -r * /opt/serverpass/
cd /opt/serverpass

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install Flask==3.1.2 cryptography==41.0.7 pandas==2.1.4 openpyxl==3.1.2 Werkzeug==3.1.3

# Generate keys
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Create environment file
cat > /opt/serverpass/.env << EOF
FLASK_SECRET_KEY=$SECRET_KEY
FERNET_KEY=$FERNET_KEY
EOF

# Initialize database
python3 -c "
import sqlite3
from werkzeug.security import generate_password_hash

# Create/recreate database
conn = sqlite3.connect('database.db')
with open('schema.sql', 'r') as f:
    conn.executescript(f.read())

# Create admin user
hashed_password = generate_password_hash('admin')
conn.execute('DELETE FROM users WHERE username = ?', ('admin',))
conn.execute('INSERT INTO users (username, password_hash, role, access_levels) VALUES (?, ?, ?, ?)',
             ('admin', hashed_password, 'admin', 'level1,level2,level3'))
conn.commit()
conn.close()
print('Database and admin user created')
"

# Create systemd service
sudo tee /etc/systemd/system/serverpass.service << EOF
[Unit]
Description=ServerPass Application
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/opt/serverpass
EnvironmentFile=/opt/serverpass/.env
ExecStart=/opt/serverpass/venv/bin/python /opt/serverpass/app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable serverpass
sudo systemctl start serverpass

# Open firewall
sudo ufw allow 5000 2>/dev/null || true

echo "Installation complete!"
echo "Service status:"
sudo systemctl status serverpass --no-pager
echo ""
echo "Access at: http://$(hostname -I | awk '{print $1}'):5000"
echo "Default login: admin/admin"
echo ""
echo "Commands:"
echo "  sudo systemctl status serverpass   # Check status"
echo "  sudo systemctl restart serverpass  # Restart service"
echo "  sudo systemctl logs serverpass     # View logs"