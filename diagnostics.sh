#!/bin/bash

# WireGuard Server Diagnostics Script
# This script helps diagnose common issues with WireGuard server setup

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

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script should be run as root for complete diagnostics"
        echo "Some checks may not work properly without root privileges"
        echo ""
    else
        print_status "Running with root privileges"
    fi
}

# Function to check system information
check_system_info() {
    print_header "System Information"
    
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "Kernel: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Hostname: $(hostname)"
    echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo ""
}

# Function to check WireGuard installation
check_wireguard_installation() {
    print_header "WireGuard Installation Check"
    
    # Check if WireGuard kernel module is available
    if lsmod | grep -q wireguard; then
        print_status "WireGuard kernel module is loaded"
    elif modinfo wireguard >/dev/null 2>&1; then
        print_warning "WireGuard kernel module is available but not loaded"
        echo "Try: modprobe wireguard"
    else
        print_error "WireGuard kernel module not found"
    fi
    
    # Check WireGuard tools
    if command -v wg >/dev/null 2>&1; then
        print_status "WireGuard tools installed: $(wg --version 2>/dev/null || echo 'version unknown')"
    else
        print_error "WireGuard tools (wg) not found"
    fi
    
    if command -v wg-quick >/dev/null 2>&1; then
        print_status "wg-quick utility available"
    else
        print_error "wg-quick utility not found"
    fi
    
    echo ""
}

# Function to check configuration files
check_configuration() {
    print_header "Configuration Check"
    
    WG_DIR="/etc/wireguard"
    WG_CONFIG="/etc/wireguard/wg0.conf"
    
    if [ -d "$WG_DIR" ]; then
        print_status "WireGuard directory exists: $WG_DIR"
        echo "Permissions: $(ls -ld $WG_DIR | awk '{print $1 " " $3 ":" $4}')"
    else
        print_error "WireGuard directory not found: $WG_DIR"
    fi
    
    if [ -f "$WG_CONFIG" ]; then
        print_status "Main configuration file exists: $WG_CONFIG"
        echo "Permissions: $(ls -l $WG_CONFIG | awk '{print $1 " " $3 ":" $4}')"
        
        # Check configuration syntax
        if wg-quick strip wg0 >/dev/null 2>&1; then
            print_status "Configuration syntax is valid"
        else
            print_error "Configuration syntax error detected"
        fi
    else
        print_error "Main configuration file not found: $WG_CONFIG"
    fi
    
    echo ""
}

# Function to check service status
check_service_status() {
    print_header "Service Status Check"
    
    # Check if systemd service exists
    if systemctl list-unit-files | grep -q "wg-quick@wg0"; then
        print_status "WireGuard service unit exists"
        
        # Check service status
        if systemctl is-active --quiet wg-quick@wg0; then
            print_status "WireGuard service is active and running"
        else
            print_error "WireGuard service is not running"
            echo "Status: $(systemctl is-active wg-quick@wg0)"
        fi
        
        # Check if service is enabled
        if systemctl is-enabled --quiet wg-quick@wg0; then
            print_status "WireGuard service is enabled (will start on boot)"
        else
            print_warning "WireGuard service is not enabled for auto-start"
        fi
    else
        print_error "WireGuard service unit not found"
    fi
    
    echo ""
}

# Function to check network interface
check_network_interface() {
    print_header "Network Interface Check"
    
    # Check if wg0 interface exists
    if ip link show wg0 >/dev/null 2>&1; then
        print_status "WireGuard interface (wg0) exists"
        
        # Get interface details
        echo "Interface status:"
        ip addr show wg0 | grep -E "(inet|state)" | sed 's/^/  /'
        
        # Check if interface is up
        if ip link show wg0 | grep -q "state UP"; then
            print_status "Interface is UP"
        else
            print_warning "Interface is DOWN"
        fi
    else
        print_error "WireGuard interface (wg0) not found"
    fi
    
    echo ""
}

# Function to check IP forwarding
check_ip_forwarding() {
    print_header "IP Forwarding Check"
    
    # Check IPv4 forwarding
    ipv4_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [ "$ipv4_forward" = "1" ]; then
        print_status "IPv4 forwarding is enabled"
    else
        print_error "IPv4 forwarding is disabled"
        echo "Enable with: echo 1 > /proc/sys/net/ipv4/ip_forward"
    fi
    
    # Check IPv6 forwarding
    if [ -f /proc/sys/net/ipv6/conf/all/forwarding ]; then
        ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "0")
        if [ "$ipv6_forward" = "1" ]; then
            print_status "IPv6 forwarding is enabled"
        else
            print_warning "IPv6 forwarding is disabled"
        fi
    fi
    
    echo ""
}

# Function to check firewall rules
check_firewall() {
    print_header "Firewall Check"
    
    # Check UFW
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW Status:"
        ufw_status=$(ufw status 2>/dev/null || echo "inactive")
        echo "  $ufw_status" | sed 's/^/  /'
        
        if echo "$ufw_status" | grep -q "51820"; then
            print_status "UFW rule for WireGuard port found"
        else
            print_warning "No UFW rule found for WireGuard port 51820"
        fi
    fi
    
    # Check firewalld
    if command -v firewall-cmd >/dev/null 2>&1; then
        if systemctl is-active --quiet firewalld; then
            echo "Firewalld Status: Active"
            
            if firewall-cmd --list-ports | grep -q "51820"; then
                print_status "Firewalld rule for WireGuard port found"
            else
                print_warning "No firewalld rule found for WireGuard port 51820"
            fi
        else
            echo "Firewalld Status: Inactive"
        fi
    fi
    
    # Check iptables
    if command -v iptables >/dev/null 2>&1; then
        echo "Checking iptables rules..."
        
        # Check INPUT rules for WireGuard port
        if iptables -L INPUT -n | grep -q "51820"; then
            print_status "iptables INPUT rule for WireGuard port found"
        else
            print_warning "No iptables INPUT rule found for port 51820"
        fi
        
        # Check NAT rules
        if iptables -t nat -L POSTROUTING -n 2>/dev/null | grep -q "MASQUERADE"; then
            print_status "NAT/MASQUERADE rules found"
        else
            print_warning "No NAT/MASQUERADE rules found"
        fi
    fi
    
    echo ""
}

# Function to check connected peers
check_peers() {
    print_header "Connected Peers Check"
    
    if command -v wg >/dev/null 2>&1; then
        peer_count=$(wg show wg0 2>/dev/null | grep -c "peer:" || echo "0")
        
        if [ "$peer_count" -gt 0 ]; then
            print_status "Connected peers: $peer_count"
            echo ""
            echo "Peer details:"
            wg show wg0 2>/dev/null | sed 's/^/  /' || echo "  Unable to show peer details"
        else
            print_info "No peers currently connected"
        fi
    else
        print_error "Cannot check peers - wg command not available"
    fi
    
    echo ""
}

# Function to check public IP
check_public_ip() {
    print_header "Public IP Check"
    
    echo "Attempting to detect public IP..."
    
    public_ip=$(curl -s --connect-timeout 5 ipv4.icanhazip.com 2>/dev/null || \
                curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || \
                curl -s --connect-timeout 5 ipecho.net/plain 2>/dev/null || \
                echo "Unable to detect")
    
    if [ "$public_ip" != "Unable to detect" ]; then
        print_status "Public IP detected: $public_ip"
    else
        print_warning "Unable to automatically detect public IP"
        echo "This might affect client connections if using dynamic IP"
    fi
    
    echo ""
}

# Function to check DNS resolution
check_dns() {
    print_header "DNS Resolution Check"
    
    # Test DNS servers commonly used in VPN configs
    dns_servers=("1.1.1.1" "8.8.8.8" "9.9.9.9")
    
    for dns in "${dns_servers[@]}"; do
        if nslookup google.com "$dns" >/dev/null 2>&1; then
            print_status "DNS server $dns is reachable"
        else
            print_warning "DNS server $dns is not reachable"
        fi
    done
    
    echo ""
}

# Function to show system resources
check_resources() {
    print_header "System Resources"
    
    # Memory usage
    echo "Memory Usage:"
    free -h | sed 's/^/  /'
    
    echo ""
    
    # Disk space
    echo "Disk Space:"
    df -h / | sed 's/^/  /'
    
    echo ""
    
    # CPU load
    echo "CPU Load:"
    echo "  $(uptime | awk -F'load average:' '{print $2}')"
    
    echo ""
}

# Function to check fail2ban status
check_fail2ban() {
    print_header "Fail2ban Security Check"
    
    # Check if fail2ban is installed
    if command -v fail2ban-client >/dev/null 2>&1; then
        print_status "Fail2ban is installed"
        
        # Check service status
        if systemctl is-active --quiet fail2ban; then
            print_status "Fail2ban service is running"
            
            # Show jail status
            echo "Active jails:"
            fail2ban_status=$(fail2ban-client status 2>/dev/null || echo "Unable to get status")
            echo "$fail2ban_status" | sed 's/^/  /'
            
            # Show SSH jail details if active
            if echo "$fail2ban_status" | grep -q "sshd"; then
                echo ""
                echo "SSH jail details:"
                fail2ban-client status sshd 2>/dev/null | sed 's/^/  /' || echo "  Unable to get SSH jail details"
            fi
            
            # Check for banned IPs
            banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "0")
            if [ "$banned_count" -gt 0 ]; then
                print_warning "Currently banned IPs: $banned_count"
            else
                print_status "No currently banned IPs"
            fi
        else
            print_error "Fail2ban service is not running"
        fi
        
        # Check configuration
        if [ -f "/etc/fail2ban/jail.local" ]; then
            print_status "Custom jail configuration found"
        else
            print_warning "No custom jail configuration found"
        fi
    else
        print_error "Fail2ban is not installed"
    fi
    
    echo ""
}

# Function to generate summary report
generate_summary() {
    print_header "Diagnostic Summary"
    
    issues_found=0
    
    # List critical issues
    echo "Critical Issues:"
    
    if ! systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        print_error "WireGuard service is not running"
        ((issues_found++))
    fi
    
    if [ ! -f "/etc/wireguard/wg0.conf" ]; then
        print_error "Main configuration file missing"
        ((issues_found++))
    fi
    
    if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" != "1" ]; then
        print_error "IP forwarding is disabled"
        ((issues_found++))
    fi
    
    if ! command -v wg >/dev/null 2>&1; then
        print_error "WireGuard tools not installed"
        ((issues_found++))
    fi
    
    if [ $issues_found -eq 0 ]; then
        print_status "No critical issues found"
    else
        echo ""
        echo "Found $issues_found critical issue(s) that need attention"
    fi
    
    echo ""
    echo "For detailed setup instructions, see README.md"
    echo "For management commands, run: ./wireguard-manager.sh help"
}

# Main function
main() {
    echo "WireGuard Server Diagnostics"
    echo "Generated on: $(date)"
    echo ""
    
    check_root
    check_system_info
    check_wireguard_installation
    check_configuration
    check_service_status
    check_network_interface
    check_ip_forwarding
    check_firewall
    check_fail2ban
    check_peers
    check_public_ip
    check_dns
    check_resources
    generate_summary
}

# Run diagnostics
main "$@"
