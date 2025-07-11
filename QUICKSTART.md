# Quick Setup Guide

## 🚀 Fast Track Installation

### 1. Download and Setup
```bash
git clone https://github.com/Tavo22/wireguard-server.git
cd wireguard-server
chmod +x *.sh
```

### 2. Install WireGuard Server
```bash
sudo ./install-wireguard.sh
```

### 3. Add Your First Client
```bash
sudo ./wireguard-manager.sh add myclient
```

### 4. Get Client Configuration
The script will display:
- Client configuration file content
- QR code for mobile devices
- Configuration file location

## 📱 Mobile Setup
1. Install WireGuard app from your app store
2. Scan the QR code displayed after adding a client
3. Enable the VPN connection

## 💻 Desktop Setup
1. Install WireGuard client from wireguard.com
2. Copy the client configuration content to a .conf file
3. Import the configuration into WireGuard client
4. Activate the tunnel

## 🔧 Common Commands

### Management
```bash
sudo ./wireguard-manager.sh list          # List all clients
sudo ./wireguard-manager.sh status        # Show server status
sudo ./wireguard-manager.sh remove client # Remove a client
sudo ./wireguard-manager.sh help          # Show all commands
```

### Diagnostics
```bash
sudo ./diagnostics.sh                     # Run system diagnostics
sudo ./validate-config.sh                # Validate all configurations
sudo ./test-installation.sh              # Test complete installation
```

### Backup
```bash
sudo ./wireguard-manager.sh backup        # Backup configurations
```

## 🛠️ Troubleshooting

### Check if WireGuard is running
```bash
sudo systemctl status wg-quick@wg0
```

### View logs
```bash
sudo journalctl -u wg-quick@wg0 -f
```

### Test connectivity
```bash
sudo wg show
```

### Run diagnostics
```bash
sudo ./diagnostics.sh
```

## 🔐 Security Notes

- All clients get unique keys
- Server uses preshared keys for additional security
- Configuration files have restricted permissions
- Regular updates recommended

## 📋 Prerequisites

- Linux server (Ubuntu/Debian/CentOS/RHEL/Fedora)
- Root access
- Public IP address
- Open UDP port 51820 (or custom port)

## 🗑️ Uninstall

```bash
sudo ./uninstall.sh
```

This will:
- Stop WireGuard service
- Remove all configurations
- Uninstall packages
- Create backup before removal

---

For detailed information, see the main README.md file.
