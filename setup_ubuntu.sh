#!/bin/bash

# Quick setup script for Ubuntu
set -e

echo "Setting up ServerPass on Ubuntu..."

# Generate keys
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
FERNET_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install Flask==3.1.2 cryptography==41.0.7 pandas==2.1.4 openpyxl==3.1.2 Werkzeug==3.1.3

# Set environment variables
export FLASK_SECRET_KEY="$SECRET_KEY"
export FERNET_KEY="$FERNET_KEY"

# Initialize database
python3 -c "
import sqlite3
with open('schema.sql', 'r') as f:
    conn = sqlite3.connect('database.db')
    conn.executescript(f.read())
    conn.close()
print('Database initialized')
"

echo "Setup complete!"
echo "Run: source venv/bin/activate && FLASK_SECRET_KEY='$SECRET_KEY' FERNET_KEY='$FERNET_KEY' python3 app.py"