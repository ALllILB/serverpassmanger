# ServerPass - Server Credential Manager

## Quick Installation

```bash
chmod +x install.sh
sudo ./install.sh
```

## Access
- URL: `http://SERVER_IP:5000`
- Default login: `admin/admin`

## Service Management
```bash
sudo systemctl status serverpass    # Check status
sudo systemctl restart serverpass   # Restart
sudo systemctl stop serverpass      # Stop
sudo systemctl start serverpass     # Start
sudo journalctl -u serverpass -f    # View logs
```

## Uninstall
```bash
chmod +x uninstall.sh
sudo ./uninstall.sh
```

## Features
- Encrypted password storage
- Role-based access control
- Server organization by sections
- Excel export functionality
- Persian/Farsi interface support