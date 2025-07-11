#!/bin/bash

# WireGuard Server Uninstall Script
# This script completely removes WireGuard server installation

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
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

# Function to create backup before uninstall
create_backup() {
    print_header "Creating Backup"
    
    if [ -d "/etc/wireguard" ]; then
        BACKUP_FILE="/root/wireguard-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        tar -czf "$BACKUP_FILE" /etc/wireguard/ 2>/dev/null || true
        
        if [ -f "$BACKUP_FILE" ]; then
            print_status "Configuration backed up to: $BACKUP_FILE"
        else
            print_warning "Failed to create backup"
        fi
    else
        print_warning "No WireGuard configuration found to backup"
    fi
}

# Function to stop and disable services
stop_services() {
    print_header "Stopping WireGuard Services"
    
    # Stop WireGuard interface
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        systemctl stop wg-quick@wg0
        print_status "WireGuard service stopped"
    fi
    
    # Disable WireGuard service
    if systemctl is-enabled --quiet wg-quick@wg0 2>/dev/null; then
        systemctl disable wg-quick@wg0
        print_status "WireGuard service disabled"
    fi
    
    # Bring down interface manually if still up
    if ip link show wg0 >/dev/null 2>&1; then
        ip link delete wg0 2>/dev/null || true
        print_status "WireGuard interface removed"
    fi
}

# Function to remove firewall rules
remove_firewall_rules() {
    print_header "Removing Firewall Rules"
    
    # Remove UFW rules
    if command -v ufw >/dev/null 2>&1; then
        ufw --force delete allow 51820/udp 2>/dev/null || true
        print_status "UFW rules removed"
    fi
    
    # Remove firewalld rules
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --permanent --remove-port=51820/udp 2>/dev/null || true
        firewall-cmd --permanent --remove-masquerade 2>/dev/null || true
        firewall-cmd --reload 2>/dev/null || true
        print_status "Firewalld rules removed"
    fi
    
    # Remove iptables rules (best effort)
    print_warning "Manual iptables rule cleanup may be required"
    print_warning "Check: iptables -L and iptables -t nat -L"
}

# Function to remove configuration files
remove_configuration() {
    print_header "Removing Configuration Files"
    
    if [ -d "/etc/wireguard" ]; then
        rm -rf /etc/wireguard
        print_status "WireGuard configuration directory removed"
    fi
    
    # Remove management script if installed
    if [ -f "/usr/local/bin/wg-manager" ]; then
        rm -f /usr/local/bin/wg-manager
        print_status "Management script removed"
    fi
    
    # Remove fail2ban configuration
    if [ -f "/etc/fail2ban/jail.local" ]; then
        rm -f /etc/fail2ban/jail.local
        print_status "Fail2ban custom configuration removed"
    fi
    
    if [ -f "/etc/fail2ban/filter.d/wireguard.conf" ]; then
        rm -f /etc/fail2ban/filter.d/wireguard.conf
        print_status "WireGuard fail2ban filter removed"
    fi
}

# Function to remove WireGuard packages
remove_packages() {
    print_header "Removing WireGuard Packages"
    
    case $OS in
        "Ubuntu"|"Debian"*)
            apt remove --purge -y wireguard wireguard-tools fail2ban 2>/dev/null || true
            apt autoremove -y 2>/dev/null || true
            print_status "WireGuard and fail2ban packages removed (Debian/Ubuntu)"
            ;;
        "CentOS"*|"Red Hat"*|"Fedora"*)
            if command -v dnf &> /dev/null; then
                dnf remove -y wireguard-tools fail2ban 2>/dev/null || true
            else
                yum remove -y wireguard-tools fail2ban 2>/dev/null || true
            fi
            print_status "WireGuard and fail2ban packages removed (RHEL/CentOS/Fedora)"
            ;;
        *)
            print_warning "Unknown OS: $OS - manual package removal may be required"
            ;;
    esac
}

# Function to clean up kernel module
cleanup_kernel_module() {
    print_header "Cleaning Up Kernel Module"
    
    # Remove kernel module if loaded
    if lsmod | grep -q wireguard; then
        modprobe -r wireguard 2>/dev/null || true
        print_status "WireGuard kernel module unloaded"
    fi
}

# Function to restore system settings
restore_system_settings() {
    print_header "Restoring System Settings"
    
    # Note: We don't disable IP forwarding as it might be needed by other services
    print_warning "IP forwarding was left enabled (may be used by other services)"
    print_warning "To disable: echo 0 > /proc/sys/net/ipv4/ip_forward"
    print_warning "And remove 'net.ipv4.ip_forward=1' from /etc/sysctl.conf"
}

# Function to verify uninstallation
verify_uninstall() {
    print_header "Verification"
    
    errors=0
    
    # Check if service still exists
    if systemctl list-unit-files | grep -q "wg-quick@wg0"; then
        print_warning "WireGuard service unit still exists"
        ((errors++))
    fi
    
    # Check if configuration directory still exists
    if [ -d "/etc/wireguard" ]; then
        print_warning "Configuration directory still exists"
        ((errors++))
    fi
    
    # Check if interface still exists
    if ip link show wg0 >/dev/null 2>&1; then
        print_warning "WireGuard interface still exists"
        ((errors++))
    fi
    
    # Check if packages are still installed
    if command -v wg >/dev/null 2>&1; then
        print_warning "WireGuard tools still installed"
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        print_status "WireGuard uninstalled successfully"
    else
        print_warning "Uninstallation completed with $errors warning(s)"
    fi
}

# Main uninstall function
main() {
    print_header "WireGuard Server Uninstall"
    
    # Confirmation prompt
    echo "This will completely remove WireGuard server from your system."
    echo "All client configurations will be deleted."
    read -p "Are you sure you want to continue? (y/N): " confirm
    
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_status "Uninstall cancelled"
        exit 0
    fi
    
    # Preliminary checks
    check_root
    detect_os
    print_status "Detected OS: $OS $VER"
    
    # Uninstall steps
    create_backup
    stop_services
    remove_firewall_rules
    remove_configuration
    remove_packages
    cleanup_kernel_module
    restore_system_settings
    verify_uninstall
    
    print_header "Uninstall Complete"
    print_status "WireGuard has been removed from your system"
    
    if ls /root/wireguard-backup-*.tar.gz >/dev/null 2>&1; then
        echo ""
        print_status "Configuration backup(s) available in /root/:"
        ls -la /root/wireguard-backup-*.tar.gz
    fi
    
    echo ""
    print_warning "You may need to:"
    print_warning "1. Manually clean up any remaining iptables rules"
    print_warning "2. Remove IP forwarding settings from /etc/sysctl.conf if not needed"
    print_warning "3. Reboot the system to ensure all changes take effect"
}

# Run the main function
main "$@"
