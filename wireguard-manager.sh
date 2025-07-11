#!/bin/bash

# WireGuard Server Management Script
# This script allows you to manage WireGuard server clients and view server status

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
WG_DIR="/etc/wireguard"
WG_CONFIG_FILE="$WG_DIR/wg0.conf"
WG_INTERFACE="wg0"
SERVER_CONFIG="$WG_DIR/server.conf"
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

print_client_info() {
    echo -e "${CYAN}$1${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to load server configuration
load_server_config() {
    if [ ! -f "$SERVER_CONFIG" ]; then
        print_error "Server configuration not found. Please run the installation script first."
        exit 1
    fi
    
    source "$SERVER_CONFIG"
}

# Function to get next available IP
get_next_ip() {
    # Extract network base from SERVER_NETWORK (e.g., 10.8.0 from 10.8.0.0/24)
    NETWORK_BASE=$(echo $SERVER_NETWORK | cut -d'.' -f1-3)
    
    # Start checking from .2 (server is .1)
    for i in {2..254}; do
        IP="$NETWORK_BASE.$i"
        if ! grep -q "$IP" "$WG_CONFIG_FILE" 2>/dev/null; then
            echo "$IP"
            return
        fi
    done
    
    print_error "No available IP addresses in the network"
    exit 1
}

# Function to generate client configuration
generate_client_config() {
    local CLIENT_NAME="$1"
    local CLIENT_IP="$2"
    
    # Validate inputs
    if [ -z "$CLIENT_NAME" ] || [ -z "$CLIENT_IP" ]; then
        print_error "Client name and IP are required"
        return 1
    fi
    
    # Generate client keys with error checking
    if ! CLIENT_PRIVATE_KEY=$(wg genkey); then
        print_error "Failed to generate client private key"
        return 1
    fi
    
    if ! CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey); then
        print_error "Failed to generate client public key"
        return 1
    fi
    
    if ! CLIENT_PRESHARED_KEY=$(wg genpsk); then
        print_error "Failed to generate preshared key"
        return 1
    fi
    
    # Create client directory
    CLIENT_DIR="$CLIENTS_DIR/$CLIENT_NAME"
    if ! mkdir -p "$CLIENT_DIR"; then
        print_error "Failed to create client directory"
        return 1
    fi
    
    chmod 700 "$CLIENT_DIR"
    
    # Create client configuration file
    cat > "$CLIENT_DIR/$CLIENT_NAME.conf" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/32
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $CLIENT_PRESHARED_KEY
Endpoint = $SERVER_PUBLIC_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

    # Save client info
    cat > "$CLIENT_DIR/client.info" << EOF
CLIENT_NAME=$CLIENT_NAME
CLIENT_IP=$CLIENT_IP
CLIENT_PRIVATE_KEY=$CLIENT_PRIVATE_KEY
CLIENT_PUBLIC_KEY=$CLIENT_PUBLIC_KEY
CLIENT_PRESHARED_KEY=$CLIENT_PRESHARED_KEY
CREATED_DATE=$(date)
EOF

    # Add client to server configuration
    cat >> "$WG_CONFIG_FILE" << EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $CLIENT_PRESHARED_KEY
AllowedIPs = $CLIENT_IP/32
EOF

    # Restart WireGuard to apply changes
    print_status "Restarting WireGuard service..."
    if ! systemctl restart wg-quick@wg0; then
        print_error "Failed to restart WireGuard service"
        return 1
    fi
    
    # Verify service is still running
    sleep 2
    if ! systemctl is-active --quiet wg-quick@wg0; then
        print_error "WireGuard service failed to start after adding client"
        return 1
    fi
    
    echo "$CLIENT_PUBLIC_KEY"
}

# Function to add a new client
add_client() {
    print_header "Adding New Client"
    
    # Get client name
    if [ -z "$1" ]; then
        while true; do
            read -p "Enter client name: " CLIENT_NAME
            if [ -n "$CLIENT_NAME" ]; then
                break
            else
                print_error "Client name cannot be empty"
            fi
        done
    else
        CLIENT_NAME="$1"
    fi
    
    # Validate client name (more strict validation)
    if [[ ! "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]{1,32}$ ]]; then
        print_error "Client name must be 1-32 characters and contain only letters, numbers, underscore, and dash"
        exit 1
    fi
    
    # Check if client already exists
    if [ -d "$CLIENTS_DIR/$CLIENT_NAME" ]; then
        print_error "Client '$CLIENT_NAME' already exists"
        exit 1
    fi
    
    # Verify WireGuard is running
    if ! systemctl is-active --quiet wg-quick@wg0; then
        print_error "WireGuard service is not running"
        exit 1
    fi
    
    # Get next available IP
    CLIENT_IP=$(get_next_ip)
    print_status "Assigning IP: $CLIENT_IP to client: $CLIENT_NAME"
    
    # Generate client configuration
    CLIENT_PUBLIC_KEY=$(generate_client_config "$CLIENT_NAME" "$CLIENT_IP")
    
    print_status "Client '$CLIENT_NAME' added successfully"
    print_status "Configuration file: $CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.conf"
    
    # Generate QR code if qrencode is available
    if command -v qrencode &> /dev/null; then
        print_status "Generating QR code..."
        qrencode -t ansiutf8 < "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.conf"
        echo ""
        print_status "QR code saved to: $CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.png"
        qrencode -o "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.png" < "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.conf"
    fi
    
    echo ""
    print_client_info "Client configuration:"
    echo "======================================"
    cat "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.conf"
    echo "======================================"
}

# Function to remove a client
remove_client() {
    print_header "Removing Client"
    
    # Get client name
    if [ -z "$1" ]; then
        list_clients
        echo ""
        read -p "Enter client name to remove: " CLIENT_NAME
    else
        CLIENT_NAME="$1"
    fi
    
    # Check if client exists
    if [ ! -d "$CLIENTS_DIR/$CLIENT_NAME" ]; then
        print_error "Client '$CLIENT_NAME' not found"
        exit 1
    fi
    
    # Get client public key
    source "$CLIENTS_DIR/$CLIENT_NAME/client.info"
    
    # Remove client from server configuration
    # Create a temporary file without the client section
    awk -v client="$CLIENT_NAME" -v pubkey="$CLIENT_PUBLIC_KEY" '
        BEGIN { skip = 0 }
        /^# Client:/ && $3 == client { skip = 1; next }
        /^\[Peer\]/ && skip == 1 { skip = 2; next }
        /^PublicKey =/ && skip == 2 && $3 == pubkey { skip = 3; next }
        /^PresharedKey =/ && skip == 3 { skip = 4; next }
        /^AllowedIPs =/ && skip == 4 { skip = 0; next }
        /^$/ && skip > 0 && skip < 4 { skip = 0 }
        skip == 0 { print }
    ' "$WG_CONFIG_FILE" > "$WG_CONFIG_FILE.tmp"
    
    # Verify the temp file was created successfully
    if [ ! -f "$WG_CONFIG_FILE.tmp" ]; then
        print_error "Failed to create temporary configuration file"
        exit 1
    fi
    
    # Replace the original config file
    if ! mv "$WG_CONFIG_FILE.tmp" "$WG_CONFIG_FILE"; then
        print_error "Failed to update WireGuard configuration"
        exit 1
    fi
    
    # Remove client directory
    if ! rm -rf "$CLIENTS_DIR/$CLIENT_NAME"; then
        print_warning "Failed to remove client directory"
    fi
    
    # Restart WireGuard to apply changes
    print_status "Restarting WireGuard service..."
    if ! systemctl restart wg-quick@wg0; then
        print_error "Failed to restart WireGuard service"
        exit 1
    fi
    
    # Verify service is still running
    sleep 2
    if ! systemctl is-active --quiet wg-quick@wg0; then
        print_error "WireGuard service failed to start after removing client"
        exit 1
    fi
    
    print_status "Client '$CLIENT_NAME' removed successfully"
}

# Function to list all clients
list_clients() {
    print_header "Active Clients"
    
    if [ ! -d "$CLIENTS_DIR" ] || [ -z "$(ls -A "$CLIENTS_DIR" 2>/dev/null)" ]; then
        print_warning "No clients found"
        return
    fi
    
    printf "%-20s %-15s %-20s %-10s\n" "CLIENT NAME" "IP ADDRESS" "CREATED DATE" "STATUS"
    echo "-------------------------------------------------------------------"
    
    for client_dir in "$CLIENTS_DIR"/*; do
        if [ -d "$client_dir" ]; then
            client_name=$(basename "$client_dir")
            if [ -f "$client_dir/client.info" ]; then
                source "$client_dir/client.info"
                
                # Check if client is connected
                if wg show wg0 | grep -q "$CLIENT_PUBLIC_KEY"; then
                    status="Connected"
                else
                    status="Offline"
                fi
                
                printf "%-20s %-15s %-20s %-10s\n" "$CLIENT_NAME" "$CLIENT_IP" "${CREATED_DATE:0:19}" "$status"
            fi
        fi
    done
}

# Function to show detailed client information
show_client() {
    if [ -z "$1" ]; then
        list_clients
        echo ""
        read -p "Enter client name: " CLIENT_NAME
    else
        CLIENT_NAME="$1"
    fi
    
    if [ ! -d "$CLIENTS_DIR/$CLIENT_NAME" ]; then
        print_error "Client '$CLIENT_NAME' not found"
        exit 1
    fi
    
    print_header "Client Details: $CLIENT_NAME"
    
    source "$CLIENTS_DIR/$CLIENT_NAME/client.info"
    
    echo "Client Name: $CLIENT_NAME"
    echo "IP Address: $CLIENT_IP"
    echo "Created Date: $CREATED_DATE"
    echo "Public Key: $CLIENT_PUBLIC_KEY"
    echo ""
    
    # Show connection status
    if wg show wg0 | grep -q "$CLIENT_PUBLIC_KEY"; then
        print_status "Status: Connected"
        
        # Show transfer statistics
        wg_output=$(wg show wg0 | grep -A 4 "$CLIENT_PUBLIC_KEY")
        if echo "$wg_output" | grep -q "transfer:"; then
            transfer_line=$(echo "$wg_output" | grep "transfer:")
            echo "Transfer: $transfer_line"
        fi
        
        if echo "$wg_output" | grep -q "latest handshake:"; then
            handshake_line=$(echo "$wg_output" | grep "latest handshake:")
            echo "Latest Handshake: $handshake_line"
        fi
    else
        print_warning "Status: Offline"
    fi
    
    echo ""
    print_client_info "Configuration file location:"
    echo "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.conf"
    
    if [ -f "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.png" ]; then
        echo ""
        print_client_info "QR code location:"
        echo "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.png"
    fi
}

# Function to show server status
show_status() {
    print_header "WireGuard Server Status"
    
    # Check if WireGuard is running
    if systemctl is-active --quiet wg-quick@wg0; then
        print_status "Service Status: Active"
    else
        print_error "Service Status: Inactive"
    fi
    
    echo ""
    echo "Server Information:"
    echo "  Public IP: $SERVER_PUBLIC_IP"
    echo "  Port: $SERVER_PORT"
    echo "  Interface: $WG_INTERFACE"
    echo "  Network: $SERVER_NETWORK"
    echo ""
    
    # Show interface information
    if ip link show $WG_INTERFACE &>/dev/null; then
        print_status "Interface Status: Up"
        echo ""
        echo "Interface Details:"
        wg show $WG_INTERFACE
    else
        print_error "Interface Status: Down"
    fi
    
    echo ""
    echo "Connected Clients:"
    if wg show $WG_INTERFACE | grep -q "peer:"; then
        wg show $WG_INTERFACE | grep -E "(peer:|latest handshake:|transfer:)"
    else
        print_warning "No clients connected"
    fi
}

# Function to restart WireGuard service
restart_service() {
    print_header "Restarting WireGuard Service"
    
    systemctl restart wg-quick@wg0
    
    if systemctl is-active --quiet wg-quick@wg0; then
        print_status "WireGuard service restarted successfully"
    else
        print_error "Failed to restart WireGuard service"
        exit 1
    fi
}

# Function to show QR code for a client
show_qr() {
    if [ -z "$1" ]; then
        list_clients
        echo ""
        read -p "Enter client name: " CLIENT_NAME
    else
        CLIENT_NAME="$1"
    fi
    
    if [ ! -d "$CLIENTS_DIR/$CLIENT_NAME" ]; then
        print_error "Client '$CLIENT_NAME' not found"
        exit 1
    fi
    
    if ! command -v qrencode &> /dev/null; then
        print_error "qrencode is not installed. Please install it first."
        exit 1
    fi
    
    print_header "QR Code for Client: $CLIENT_NAME"
    qrencode -t ansiutf8 < "$CLIENTS_DIR/$CLIENT_NAME/$CLIENT_NAME.conf"
}

# Function to backup configurations
backup_configs() {
    print_header "Backing up Configurations"
    
    BACKUP_DIR="/root/wireguard-backup-$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Copy server configuration
    cp -r "$WG_DIR" "$BACKUP_DIR/"
    
    # Create archive
    tar -czf "$BACKUP_DIR.tar.gz" -C "$(dirname "$BACKUP_DIR")" "$(basename "$BACKUP_DIR")"
    rm -rf "$BACKUP_DIR"
    
    print_status "Backup created: $BACKUP_DIR.tar.gz"
}

# Function to show fail2ban status
show_fail2ban_status() {
    print_header "Fail2ban Security Status"
    
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        print_error "Fail2ban is not installed"
        return 1
    fi
    
    if ! systemctl is-active --quiet fail2ban; then
        print_error "Fail2ban service is not running"
        return 1
    fi
    
    # General status
    echo "Service Status: Running"
    echo ""
    
    # Show active jails
    echo "Active Jails:"
    fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list://' | tr ',' '\n' | sed 's/^[ \t]*/  - /'
    echo ""
    
    # Show SSH jail details
    if fail2ban-client status | grep -q "sshd"; then
        echo "SSH Protection Details:"
        fail2ban-client status sshd 2>/dev/null | grep -E "(Filter|Actions|Currently failed|Total failed|Currently banned|Total banned)" | sed 's/^/  /'
        echo ""
    fi
    
    # Show recently banned IPs
    echo "Recent Fail2ban Activity:"
    if [ -f /var/log/fail2ban.log ]; then
        tail -n 20 /var/log/fail2ban.log | grep "Ban\|Unban" | tail -5 | sed 's/^/  /' || echo "  No recent ban activity"
    else
        echo "  Log file not found"
    fi
}

# Function to unban an IP address
unban_ip() {
    if [ -z "$1" ]; then
        while true; do
            read -p "Enter IP address to unban: " ip_address
            if [[ $ip_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                break
            else
                print_error "Invalid IP address format. Please try again."
            fi
        done
    else
        ip_address="$1"
        # Validate IP format
        if [[ ! $ip_address =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            print_error "Invalid IP address format: $ip_address"
            return 1
        fi
    fi
    
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        print_error "Fail2ban is not installed"
        return 1
    fi
    
    if ! systemctl is-active --quiet fail2ban; then
        print_error "Fail2ban service is not running"
        return 1
    fi
    
    # Unban from all jails
    jails=$(fail2ban-client status | grep "Jail list:" | sed 's/.*://' | tr ',' ' ')
    unbanned=false
    
    for jail in $jails; do
        jail=$(echo $jail | tr -d ' \t')
        if fail2ban-client status "$jail" 2>/dev/null | grep -q "$ip_address"; then
            fail2ban-client set "$jail" unbanip "$ip_address" 2>/dev/null
            print_status "Unbanned $ip_address from jail: $jail"
            unbanned=true
        fi
    done
    
    if [ "$unbanned" = false ]; then
        print_warning "IP $ip_address was not found in any jail"
    fi
}

# Function to show help
show_help() {
    echo "WireGuard Server Management Script"
    echo ""
    echo "Usage: $0 [COMMAND] [ARGUMENTS]"
    echo ""
    echo "Commands:"
    echo "  add [client_name]     Add a new client"
    echo "  remove [client_name]  Remove a client"
    echo "  list                  List all clients"
    echo "  show [client_name]    Show detailed client information"
    echo "  qr [client_name]      Show QR code for client configuration"
    echo "  status                Show server status"
    echo "  restart               Restart WireGuard service"
    echo "  backup                Backup all configurations"
    echo "  security              Show fail2ban security status"
    echo "  unban [ip_address]    Unban an IP address from fail2ban"
    echo "  help                  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 add john"
    echo "  $0 remove john"
    echo "  $0 show john"
    echo "  $0 qr john"
    echo "  $0 status"
    echo "  $0 security"
    echo "  $0 unban 192.168.1.100"
}

# Main function
main() {
    # Check if running as root
    check_root
    
    # Load server configuration
    load_server_config
    
    # Parse command line arguments
    case "${1:-help}" in
        "add")
            add_client "$2"
            ;;
        "remove"|"delete")
            remove_client "$2"
            ;;
        "list"|"ls")
            list_clients
            ;;
        "show"|"info")
            show_client "$2"
            ;;
        "qr"|"qrcode")
            show_qr "$2"
            ;;
        "status"|"stat")
            show_status
            ;;
        "restart")
            restart_service
            ;;
        "backup")
            backup_configs
            ;;
        "security"|"fail2ban")
            show_fail2ban_status
            ;;
        "unban")
            unban_ip "$2"
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run the main function
main "$@"
