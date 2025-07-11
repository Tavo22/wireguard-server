#!/bin/bash

# WireGuard Server Installation and Setup Script
# This script sets up a WireGuard VPN server from scratch on a fresh Linux system
# Supports Ubuntu/Debian and CentOS/RHEL/Fedora

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
WG_DIR="/etc/wireguard"
WG_CONFIG_FILE="$WG_DIR/wg0.conf"
WG_INTERFACE="wg0"
WG_PORT="51820"
WG_NETWORK="10.8.0.0/24"
SERVER_IP="10.8.0.1"
SERVER_PUBLIC_IP=""
CLIENTS_DIR="$WG_DIR/clients"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Function to detect the operating system
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [ -f /etc/lsb-release ]; then
        . /etc/lsb-release
        OS=$DISTRIB_ID
        VER=$DISTRIB_RELEASE
    elif [ -f /etc/debian_version ]; then
        OS=Debian
        VER=$(cat /etc/debian_version)
    elif [ -f /etc/SuSe-release ]; then
        OS=openSUSE
    elif [ -f /etc/redhat-release ]; then
        OS=CentOS
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Function to check system requirements
check_requirements() {
    print_header "Checking System Requirements"
    
    # Check if WireGuard is already installed
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        print_warning "WireGuard appears to be already running"
        read -p "Do you want to continue and potentially overwrite the existing installation? (y/N): " confirm
        if [[ ! $confirm =~ ^[Yy]$ ]]; then
            print_status "Installation cancelled"
            exit 0
        fi
    fi
    
    # Check for required commands
    required_commands=("curl" "awk" "grep" "ip" "systemctl")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            print_error "Required command '$cmd' not found"
            exit 1
        fi
    done
    
    # Check available disk space (minimum 100MB)
    available_space=$(df / | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 102400 ]; then
        print_error "Insufficient disk space. At least 100MB required."
        exit 1
    fi
    
    # Check if port 51820 is already in use
    if ss -lun | grep -q ":51820"; then
        print_warning "Port 51820 appears to be in use"
        read -p "Do you want to continue? (y/N): " confirm
        if [[ ! $confirm =~ ^[Yy]$ ]]; then
            print_status "Installation cancelled"
            exit 0
        fi
    fi
    
    print_status "System requirements check passed"
}

# Function to install WireGuard based on the OS
install_wireguard() {
    print_header "Installing WireGuard"
    
    case $OS in
        "Ubuntu"|"Debian"*)
            print_status "Updating package lists..."
            if ! apt update; then
                print_error "Failed to update package lists"
                exit 1
            fi
            
            print_status "Installing packages..."
            if ! apt install -y wireguard wireguard-tools iptables iptables-persistent resolvconf qrencode fail2ban; then
                print_error "Failed to install required packages"
                exit 1
            fi
            ;;
        "CentOS"*|"Red Hat"*|"Fedora"*)
            if command -v dnf &> /dev/null; then
                print_status "Installing EPEL repository..."
                if ! dnf install -y epel-release; then
                    print_error "Failed to install EPEL repository"
                    exit 1
                fi
                
                print_status "Installing packages..."
                if ! dnf install -y wireguard-tools iptables qrencode fail2ban; then
                    print_error "Failed to install required packages"
                    exit 1
                fi
            else
                print_status "Installing EPEL repository..."
                if ! yum install -y epel-release; then
                    print_error "Failed to install EPEL repository"
                    exit 1
                fi
                
                print_status "Installing packages..."
                if ! yum install -y wireguard-tools iptables qrencode fail2ban; then
                    print_error "Failed to install required packages"
                    exit 1
                fi
            fi
            ;;
        *)
            print_error "Unsupported operating system: $OS"
            exit 1
            ;;
    esac
    
    print_status "WireGuard and security tools installed successfully"
}

# Function to get the server's public IP
get_public_ip() {
    print_status "Detecting server public IP..."
    
    # Try multiple methods to get public IP with timeout
    SERVER_PUBLIC_IP=""
    
    # Array of IP detection services
    services=(
        "ipv4.icanhazip.com"
        "ifconfig.me"
        "ipecho.net/plain"
        "checkip.amazonaws.com"
        "ip.sb"
    )
    
    for service in "${services[@]}"; do
        print_status "Trying $service..."
        if SERVER_PUBLIC_IP=$(curl -s --connect-timeout 10 --max-time 15 "$service" 2>/dev/null); then
            # Validate IP format
            if [[ $SERVER_PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                print_status "Detected public IP: $SERVER_PUBLIC_IP"
                break
            else
                SERVER_PUBLIC_IP=""
            fi
        fi
    done
    
    # Try dig as fallback
    if [ -z "$SERVER_PUBLIC_IP" ] && command -v dig >/dev/null 2>&1; then
        print_status "Trying DNS lookup method..."
        SERVER_PUBLIC_IP=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null | head -n1)
        if [[ ! $SERVER_PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            SERVER_PUBLIC_IP=""
        fi
    fi
    
    if [ -z "$SERVER_PUBLIC_IP" ]; then
        print_warning "Could not automatically detect public IP"
        while true; do
            read -p "Please enter your server's public IP address: " SERVER_PUBLIC_IP
            if [[ $SERVER_PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                break
            else
                print_error "Invalid IP address format. Please try again."
            fi
        done
    else
        while true; do
            read -p "Is this IP correct? (y/n): " confirm
            case $confirm in
                [Yy]* ) break;;
                [Nn]* ) 
                    while true; do
                        read -p "Please enter your server's public IP address: " SERVER_PUBLIC_IP
                        if [[ $SERVER_PUBLIC_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                            break 2
                        else
                            print_error "Invalid IP address format. Please try again."
                        fi
                    done
                    ;;
                * ) print_error "Please answer yes (y) or no (n).";;
            esac
        done
    fi
    
    print_status "Using public IP: $SERVER_PUBLIC_IP"
}

# Function to configure network interface
configure_network() {
    print_header "Configuring Network Interface"
    
    # Get the default network interface
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [ -z "$DEFAULT_INTERFACE" ]; then
        print_error "Could not detect default network interface"
        print_status "Available interfaces:"
        ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/:$//' | sed 's/^/  /'
        exit 1
    fi
    
    print_status "Default network interface: $DEFAULT_INTERFACE"
    
    # Backup existing sysctl.conf
    if [ -f /etc/sysctl.conf ]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.backup-$(date +%Y%m%d-%H%M%S)
    fi
    
    # Enable IP forwarding (check if already enabled to avoid duplicates)
    if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
    fi
    
    if ! grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf 2>/dev/null; then
        echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.conf
    fi
    
    # Apply sysctl changes
    if ! sysctl -p; then
        print_error "Failed to apply network configuration"
        exit 1
    fi
    
    # Verify IP forwarding is enabled
    ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward)
    if [ "$ipv4_forward" != "1" ]; then
        print_error "IPv4 forwarding could not be enabled"
        exit 1
    fi
    
    print_status "IP forwarding enabled and verified"
}

# Function to generate server keys
generate_server_keys() {
    print_header "Generating Server Keys"
    
    # Create WireGuard directory
    mkdir -p $WG_DIR
    chmod 700 $WG_DIR
    
    # Verify wg command is available
    if ! command -v wg >/dev/null 2>&1; then
        print_error "WireGuard tools not found. Installation may have failed."
        exit 1
    fi
    
    # Generate server private and public keys
    print_status "Generating server private key..."
    if ! SERVER_PRIVATE_KEY=$(wg genkey); then
        print_error "Failed to generate server private key"
        exit 1
    fi
    
    print_status "Generating server public key..."
    if ! SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey); then
        print_error "Failed to generate server public key"
        exit 1
    fi
    
    # Validate key format (WireGuard keys are 44 characters base64)
    if [ ${#SERVER_PRIVATE_KEY} -ne 44 ] || [ ${#SERVER_PUBLIC_KEY} -ne 44 ]; then
        print_error "Generated keys have invalid format"
        exit 1
    fi
    
    print_status "Server keys generated successfully"
    print_status "Public key: $SERVER_PUBLIC_KEY"
}

# Function to create server configuration
create_server_config() {
    print_header "Creating Server Configuration"
    
    # Get the default interface for iptables rules
    DEFAULT_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [ -z "$DEFAULT_INTERFACE" ]; then
        print_error "Could not determine default network interface"
        exit 1
    fi
    
    print_status "Using network interface: $DEFAULT_INTERFACE"
    
    # Create server configuration
    cat > "$WG_CONFIG_FILE" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_IP/24
ListenPort = $WG_PORT
SaveConfig = true

# iptables rules for NAT
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $DEFAULT_INTERFACE -j MASQUERADE

EOF
    
    # Set secure permissions
    chmod 600 "$WG_CONFIG_FILE"
    chown root:root "$WG_CONFIG_FILE"
    
    # Validate configuration syntax
    if ! wg-quick strip wg0 >/dev/null 2>&1; then
        print_error "Generated WireGuard configuration is invalid"
        exit 1
    fi
    
    print_status "Server configuration created and validated"
}

# Function to configure firewall
configure_firewall() {
    print_header "Configuring Firewall"
    
    # Configure UFW if it exists
    if command -v ufw &> /dev/null; then
        # Ensure SSH is allowed before configuring other rules
        ufw allow ssh
        ufw allow $WG_PORT/udp
        print_status "UFW rules added for SSH and port $WG_PORT"
    fi
    
    # Configure firewalld if it exists
    if command -v firewall-cmd &> /dev/null; then
        # Ensure SSH is allowed
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --permanent --add-port=$WG_PORT/udp
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
        print_status "Firewalld configured with SSH and WireGuard access"
    fi
    
    # Configure iptables directly as fallback
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || true
    iptables -A INPUT -p udp --dport $WG_PORT -j ACCEPT
    
    # Save iptables rules
    if command -v iptables-save &> /dev/null; then
        case $OS in
            "Ubuntu"|"Debian"*)
                # Create iptables directory if it doesn't exist
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4
                # Also save to netfilter-persistent location
                if [ -d "/etc/iptables" ]; then
                    iptables-save > /etc/iptables/rules.v4
                fi
                ;;
            "CentOS"*|"Red Hat"*|"Fedora"*)
                iptables-save > /etc/sysconfig/iptables
                # Enable iptables service for persistence
                if command -v systemctl &> /dev/null; then
                    systemctl enable iptables 2>/dev/null || true
                fi
                ;;
        esac
    fi
    
    print_status "Firewall configured"
}

# Function to configure fail2ban
configure_fail2ban() {
    print_header "Configuring Fail2ban"
    
    # Create fail2ban configuration directory if it doesn't exist
    mkdir -p /etc/fail2ban
    
    # Create custom jail configuration for SSH and WireGuard
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban IP for 1 hour (3600 seconds) after 5 failed attempts within 10 minutes
bantime = 3600
findtime = 600
maxretry = 5
backend = auto

# Email notifications (optional - configure if needed)
# destemail = admin@yourdomain.com
# sender = fail2ban@yourdomain.com
# mta = sendmail

# Default action is to ban IP using iptables
banaction = iptables-multiport
banaction_allports = iptables-allports

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

# Additional protection for Ubuntu/Debian systems
[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 3600

# Protect against port scanning
[portscan]
enabled = true
filter = portscan
logpath = /var/log/syslog
maxretry = 1
bantime = 86400

# Custom WireGuard protection (optional)
[wireguard]
enabled = false
port = 51820
protocol = udp
filter = wireguard
logpath = /var/log/syslog
maxretry = 10
bantime = 3600
EOF

    # Create custom WireGuard filter (basic protection)
    cat > /etc/fail2ban/filter.d/wireguard.conf << 'EOF'
[Definition]
failregex = ^.*wireguard.*: Invalid handshake initiation from <HOST>.*$
            ^.*wireguard.*: Packet has unallowed src IP <HOST>.*$
ignoreregex =
EOF

    # Create portscan filter if it doesn't exist
    if [ ! -f /etc/fail2ban/filter.d/portscan.conf ]; then
        cat > /etc/fail2ban/filter.d/portscan.conf << 'EOF'
[Definition]
failregex = ^.*kernel:.*IN=.*SRC=<HOST>.*DST=.*PROTO=(TCP|UDP).*DPT=(?!22|80|443|51820).*$
ignoreregex =
EOF
    fi
    
    # Adjust log path for CentOS/RHEL systems
    if [[ "$OS" == "CentOS"* || "$OS" == "Red Hat"* || "$OS" == "Fedora"* ]]; then
        sed -i 's|/var/log/auth.log|/var/log/secure|g' /etc/fail2ban/jail.local
    fi
    
    # Enable and start fail2ban service
    systemctl enable fail2ban
    systemctl start fail2ban
    
    # Wait a moment for fail2ban to start
    sleep 2
    
    # Check if fail2ban is running
    if systemctl is-active --quiet fail2ban; then
        print_status "Fail2ban installed and configured successfully"
        print_status "SSH protection enabled with 3 attempts before 1-hour ban"
        print_status "Port scan protection enabled with 1-day ban"
    else
        print_warning "Fail2ban service may not be running properly"
    fi
}

# Function to start and enable WireGuard service
start_wireguard() {
    print_header "Starting WireGuard Service"
    
    # Enable the WireGuard service
    if ! systemctl enable wg-quick@wg0; then
        print_error "Failed to enable WireGuard service"
        exit 1
    fi
    
    # Start the WireGuard service
    print_status "Starting WireGuard interface..."
    if ! systemctl start wg-quick@wg0; then
        print_error "Failed to start WireGuard service"
        print_status "Checking for errors..."
        journalctl -u wg-quick@wg0 --no-pager -n 10
        exit 1
    fi
    
    # Wait for service to fully start
    sleep 3
    
    # Verify service is running
    if ! systemctl is-active --quiet wg-quick@wg0; then
        print_error "WireGuard service is not running"
        print_status "Service status:"
        systemctl status wg-quick@wg0 --no-pager
        exit 1
    fi
    
    # Verify interface is up
    if ! ip link show wg0 >/dev/null 2>&1; then
        print_error "WireGuard interface was not created"
        exit 1
    fi
    
    # Show interface status
    print_status "WireGuard interface status:"
    ip addr show wg0 | sed 's/^/  /'
    
    print_status "WireGuard service started and enabled successfully"
}

# Function to create clients directory and management scripts
setup_management() {
    print_header "Setting up Management Tools"
    
    # Create clients directory
    mkdir -p $CLIENTS_DIR
    chmod 700 $CLIENTS_DIR
    
    # Create server info file
    cat > $WG_DIR/server.conf << EOF
SERVER_PUBLIC_KEY=$SERVER_PUBLIC_KEY
SERVER_PRIVATE_KEY=$SERVER_PRIVATE_KEY
SERVER_PUBLIC_IP=$SERVER_PUBLIC_IP
SERVER_PORT=$WG_PORT
SERVER_NETWORK=$WG_NETWORK
SERVER_IP=$SERVER_IP
CLIENTS_DIR=$CLIENTS_DIR
EOF
    
    chmod 600 $WG_DIR/server.conf
    
    print_status "Management tools configured"
}

# Function to create the management script
create_management_script() {
    print_status "Creating management script..."
    
    # The management script will be created separately
    # This just creates a symlink for easy access
    if [ -f "./wireguard-manager.sh" ]; then
        cp ./wireguard-manager.sh /usr/local/bin/wg-manager
        chmod +x /usr/local/bin/wg-manager
        print_status "Management script installed as 'wg-manager'"
    fi
}

# Main installation function
main() {
    print_header "WireGuard Server Installation"
    
    # Preliminary checks
    check_root
    check_requirements
    detect_os
    print_status "Detected OS: $OS $VER"
    
    # Get configuration
    get_public_ip
    
    # Installation steps
    install_wireguard
    configure_network
    generate_server_keys
    create_server_config
    configure_firewall
    configure_fail2ban
    start_wireguard
    setup_management
    create_management_script
    
    print_header "Installation Complete!"
    print_status "WireGuard server is now running on port $WG_PORT"
    print_status "Fail2ban is protecting SSH and scanning attempts"
    print_status "Server public key: $SERVER_PUBLIC_KEY"
    print_status "Server IP: $SERVER_IP"
    print_status "Network: $WG_NETWORK"
    echo ""
    print_status "Use './wireguard-manager.sh' or 'wg-manager' to manage clients"
    print_status "Server configuration: $WG_CONFIG_FILE"
    print_status "Client configurations will be stored in: $CLIENTS_DIR"
    echo ""
    print_warning "Make sure port $WG_PORT/UDP is open in your firewall and router"
    print_status "Check fail2ban status with: fail2ban-client status"
}

# Run the main function
main "$@"
