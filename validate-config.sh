#!/bin/bash

# WireGuard Configuration Validator
# This script validates WireGuard server and client configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[ℹ]${NC} $1"
}

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

# Configuration paths
WG_CONFIG="/etc/wireguard/wg0.conf"
SERVER_CONFIG="/etc/wireguard/server.conf"
CLIENTS_DIR="/etc/wireguard/clients"

# Validation counters
issues_found=0
warnings_found=0

# Function to add issue
add_issue() {
    print_error "$1"
    ((issues_found++))
}

# Function to add warning
add_warning() {
    print_warning "$1"
    ((warnings_found++))
}

# Function to validate file permissions
validate_permissions() {
    local file="$1"
    local expected_perms="$2"
    local description="$3"
    
    if [ ! -f "$file" ]; then
        add_issue "$description: File does not exist: $file"
        return 1
    fi
    
    actual_perms=$(stat -c '%a' "$file" 2>/dev/null)
    if [ "$actual_perms" != "$expected_perms" ]; then
        add_warning "$description: Permissions are $actual_perms, should be $expected_perms"
    else
        print_status "$description: Correct permissions ($expected_perms)"
    fi
}

# Function to validate IP address format
validate_ip() {
    local ip="$1"
    local description="$2"
    
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        # Check each octet is valid (0-255)
        IFS='.' read -ra ADDR <<< "$ip"
        for octet in "${ADDR[@]}"; do
            if [ "$octet" -gt 255 ]; then
                add_issue "$description: Invalid IP address: $ip (octet $octet > 255)"
                return 1
            fi
        done
        print_status "$description: Valid IP format: $ip"
        return 0
    else
        add_issue "$description: Invalid IP address format: $ip"
        return 1
    fi
}

# Function to validate WireGuard key format
validate_key() {
    local key="$1"
    local description="$2"
    
    # WireGuard keys are 44 characters, base64 encoded
    if [ ${#key} -eq 44 ] && [[ $key =~ ^[A-Za-z0-9+/]+={0,2}$ ]]; then
        print_status "$description: Valid key format"
        return 0
    else
        add_issue "$description: Invalid key format (length: ${#key}, expected: 44)"
        return 1
    fi
}

# Function to validate port number
validate_port() {
    local port="$1"
    local description="$2"
    
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        print_status "$description: Valid port: $port"
        return 0
    else
        add_issue "$description: Invalid port number: $port"
        return 1
    fi
}

# Function to validate network CIDR
validate_cidr() {
    local cidr="$1"
    local description="$2"
    
    if [[ $cidr =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        local ip_part="${cidr%/*}"
        local mask_part="${cidr#*/}"
        
        if validate_ip "$ip_part" "CIDR IP part" >/dev/null 2>&1 && [ "$mask_part" -ge 0 ] && [ "$mask_part" -le 32 ]; then
            print_status "$description: Valid CIDR: $cidr"
            return 0
        fi
    fi
    
    add_issue "$description: Invalid CIDR format: $cidr"
    return 1
}

# Function to validate server configuration
validate_server_config() {
    print_header "Server Configuration Validation"
    
    validate_permissions "$WG_CONFIG" "600" "Server config file"
    
    if [ ! -f "$WG_CONFIG" ]; then
        add_issue "Server configuration file not found: $WG_CONFIG"
        return 1
    fi
    
    # Check if config is valid WireGuard syntax
    if wg-quick strip wg0 >/dev/null 2>&1; then
        print_status "WireGuard configuration syntax is valid"
    else
        add_issue "WireGuard configuration syntax is invalid"
    fi
    
    # Extract and validate configuration values
    local private_key=$(grep "^PrivateKey" "$WG_CONFIG" | cut -d' ' -f3)
    local address=$(grep "^Address" "$WG_CONFIG" | cut -d' ' -f3)
    local listen_port=$(grep "^ListenPort" "$WG_CONFIG" | cut -d' ' -f3)
    
    if [ -n "$private_key" ]; then
        validate_key "$private_key" "Server private key"
    else
        add_issue "Server private key not found in configuration"
    fi
    
    if [ -n "$address" ]; then
        validate_cidr "$address" "Server address"
    else
        add_issue "Server address not found in configuration"
    fi
    
    if [ -n "$listen_port" ]; then
        validate_port "$listen_port" "Server listen port"
    else
        add_issue "Server listen port not found in configuration"
    fi
    
    # Check if PostUp and PostDown rules exist
    if grep -q "PostUp" "$WG_CONFIG"; then
        print_status "PostUp rules found"
    else
        add_warning "No PostUp rules found (NAT may not work)"
    fi
    
    if grep -q "PostDown" "$WG_CONFIG"; then
        print_status "PostDown rules found"
    else
        add_warning "No PostDown rules found (cleanup may not work properly)"
    fi
}

# Function to validate server info file
validate_server_info() {
    print_header "Server Info File Validation"
    
    validate_permissions "$SERVER_CONFIG" "600" "Server info file"
    
    if [ ! -f "$SERVER_CONFIG" ]; then
        add_issue "Server info file not found: $SERVER_CONFIG"
        return 1
    fi
    
    # Source the server config to validate variables
    if source "$SERVER_CONFIG" 2>/dev/null; then
        print_status "Server info file syntax is valid"
        
        # Validate server variables
        [ -n "$SERVER_PUBLIC_KEY" ] && validate_key "$SERVER_PUBLIC_KEY" "Server public key (info file)"
        [ -n "$SERVER_PRIVATE_KEY" ] && validate_key "$SERVER_PRIVATE_KEY" "Server private key (info file)"
        [ -n "$SERVER_PUBLIC_IP" ] && validate_ip "$SERVER_PUBLIC_IP" "Server public IP"
        [ -n "$SERVER_PORT" ] && validate_port "$SERVER_PORT" "Server port (info file)"
        [ -n "$SERVER_NETWORK" ] && validate_cidr "$SERVER_NETWORK" "Server network"
        [ -n "$SERVER_IP" ] && validate_ip "$SERVER_IP" "Server IP (info file)"
        
        if [ -d "$CLIENTS_DIR" ]; then
            print_status "Clients directory exists: $CLIENTS_DIR"
        else
            add_warning "Clients directory not found: $CLIENTS_DIR"
        fi
    else
        add_issue "Server info file has syntax errors"
    fi
}

# Function to validate client configurations
validate_client_configs() {
    print_header "Client Configurations Validation"
    
    if [ ! -d "$CLIENTS_DIR" ]; then
        add_warning "No clients directory found"
        return 0
    fi
    
    client_count=0
    for client_dir in "$CLIENTS_DIR"/*; do
        if [ -d "$client_dir" ]; then
            client_name=$(basename "$client_dir")
            client_config="$client_dir/$client_name.conf"
            client_info="$client_dir/client.info"
            
            print_info "Validating client: $client_name"
            
            # Validate client config file
            if [ -f "$client_config" ]; then
                validate_permissions "$client_config" "600" "Client config: $client_name"
                
                # Check client config syntax (basic check)
                local client_private_key=$(grep "^PrivateKey" "$client_config" | cut -d' ' -f3)
                local client_address=$(grep "^Address" "$client_config" | cut -d' ' -f3)
                
                [ -n "$client_private_key" ] && validate_key "$client_private_key" "Client private key: $client_name"
                [ -n "$client_address" ] && validate_cidr "$client_address" "Client address: $client_name"
            else
                add_issue "Client config file not found: $client_config"
            fi
            
            # Validate client info file
            if [ -f "$client_info" ]; then
                validate_permissions "$client_info" "600" "Client info: $client_name"
            else
                add_warning "Client info file not found: $client_info"
            fi
            
            ((client_count++))
        fi
    done
    
    print_status "Validated $client_count client configurations"
}

# Function to validate system integration
validate_system_integration() {
    print_header "System Integration Validation"
    
    # Check if WireGuard service is enabled and running
    if systemctl is-enabled wg-quick@wg0 >/dev/null 2>&1; then
        print_status "WireGuard service is enabled"
    else
        add_issue "WireGuard service is not enabled"
    fi
    
    if systemctl is-active wg-quick@wg0 >/dev/null 2>&1; then
        print_status "WireGuard service is running"
    else
        add_issue "WireGuard service is not running"
    fi
    
    # Check if WireGuard interface exists
    if ip link show wg0 >/dev/null 2>&1; then
        print_status "WireGuard interface exists"
    else
        add_issue "WireGuard interface does not exist"
    fi
    
    # Check IP forwarding
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" ]; then
        print_status "IP forwarding is enabled"
    else
        add_issue "IP forwarding is disabled"
    fi
    
    # Check if port is listening
    if ss -lun | grep -q ":51820"; then
        print_status "WireGuard is listening on port 51820"
    else
        add_issue "WireGuard is not listening on port 51820"
    fi
}

# Function to validate fail2ban integration
validate_fail2ban() {
    print_header "Fail2ban Integration Validation"
    
    if command -v fail2ban-client >/dev/null 2>&1; then
        print_status "Fail2ban is installed"
        
        if systemctl is-active fail2ban >/dev/null 2>&1; then
            print_status "Fail2ban service is running"
            
            # Check for SSH jail
            if fail2ban-client status | grep -q sshd; then
                print_status "SSH jail is active"
            else
                add_warning "SSH jail is not active"
            fi
        else
            add_warning "Fail2ban service is not running"
        fi
        
        # Check for custom configuration
        if [ -f "/etc/fail2ban/jail.local" ]; then
            print_status "Custom fail2ban configuration found"
        else
            add_warning "No custom fail2ban configuration found"
        fi
    else
        add_warning "Fail2ban is not installed"
    fi
}

# Function to generate validation report
generate_report() {
    print_header "Validation Report"
    
    echo "Issues found: $issues_found"
    echo "Warnings found: $warnings_found"
    echo ""
    
    if [ $issues_found -eq 0 ] && [ $warnings_found -eq 0 ]; then
        print_status "Configuration validation passed! No issues found."
        exit 0
    elif [ $issues_found -eq 0 ]; then
        print_warning "Configuration validation completed with $warnings_found warning(s)."
        print_info "Warnings do not prevent operation but should be reviewed."
        exit 0
    else
        print_error "Configuration validation failed with $issues_found error(s) and $warnings_found warning(s)."
        print_error "Critical issues must be resolved before the system will work properly."
        exit 1
    fi
}

# Main function
main() {
    print_header "WireGuard Configuration Validator"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_error "This script should be run as root for complete validation"
        exit 1
    fi
    
    # Run validation checks
    validate_server_config
    validate_server_info
    validate_client_configs
    validate_system_integration
    validate_fail2ban
    
    # Generate final report
    generate_report
}

# Run main function
main "$@"
