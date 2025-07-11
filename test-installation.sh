#!/bin/bash

# WireGuard Installation Test Script
# This script performs comprehensive testing of the WireGuard setup

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

# Test counter
tests_passed=0
tests_failed=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    print_info "Testing: $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        print_status "$test_name: PASSED"
        ((tests_passed++))
        return 0
    else
        print_error "$test_name: FAILED"
        ((tests_failed++))
        return 1
    fi
}

# Function to test basic system requirements
test_system_requirements() {
    print_header "System Requirements Tests"
    
    run_test "Root privileges" "[ \$EUID -eq 0 ]"
    run_test "Curl available" "command -v curl"
    run_test "IP command available" "command -v ip"
    run_test "Systemctl available" "command -v systemctl"
    run_test "Awk available" "command -v awk"
    run_test "Grep available" "command -v grep"
}

# Function to test WireGuard installation
test_wireguard_installation() {
    print_header "WireGuard Installation Tests"
    
    run_test "WireGuard tools installed" "command -v wg"
    run_test "WireGuard quick tools installed" "command -v wg-quick"
    run_test "WireGuard configuration exists" "[ -f /etc/wireguard/wg0.conf ]"
    run_test "WireGuard config permissions" "[ \$(stat -c '%a' /etc/wireguard/wg0.conf) = '600' ]"
    run_test "WireGuard config syntax" "wg-quick strip wg0"
}

# Function to test network configuration
test_network_configuration() {
    print_header "Network Configuration Tests"
    
    run_test "IP forwarding enabled" "[ \$(cat /proc/sys/net/ipv4/ip_forward) = '1' ]"
    run_test "WireGuard interface exists" "ip link show wg0"
    run_test "WireGuard interface has IP" "ip addr show wg0 | grep -q 'inet 10.8.0.1'"
    run_test "Default route exists" "ip route | grep -q default"
}

# Function to test service status
test_service_status() {
    print_header "Service Status Tests"
    
    run_test "WireGuard service enabled" "systemctl is-enabled wg-quick@wg0"
    run_test "WireGuard service active" "systemctl is-active wg-quick@wg0"
    run_test "WireGuard listening on port" "ss -lun | grep -q ':51820'"
}

# Function to test security configuration
test_security_configuration() {
    print_header "Security Configuration Tests"
    
    run_test "Fail2ban installed" "command -v fail2ban-client"
    run_test "Fail2ban service active" "systemctl is-active fail2ban"
    run_test "Fail2ban SSH jail active" "fail2ban-client status | grep -q sshd"
    run_test "Iptables rules present" "iptables -L | grep -q ACCEPT"
}

# Function to test management tools
test_management_tools() {
    print_header "Management Tools Tests"
    
    run_test "Management script exists" "[ -f ./wireguard-manager.sh ]"
    run_test "Management script executable" "[ -x ./wireguard-manager.sh ]"
    run_test "Diagnostics script exists" "[ -f ./diagnostics.sh ]"
    run_test "Diagnostics script executable" "[ -x ./diagnostics.sh ]"
    run_test "Server config file exists" "[ -f /etc/wireguard/server.conf ]"
    run_test "Clients directory exists" "[ -d /etc/wireguard/clients ]"
}

# Function to test client operations
test_client_operations() {
    print_header "Client Operations Tests"
    
    # Test adding a client
    print_info "Testing client addition..."
    if ./wireguard-manager.sh add test-client >/dev/null 2>&1; then
        print_status "Client addition: PASSED"
        ((tests_passed++))
        
        # Test if client config was created
        run_test "Client config created" "[ -f /etc/wireguard/clients/test-client/test-client.conf ]"
        run_test "Client added to server config" "grep -q test-client /etc/wireguard/wg0.conf"
        
        # Test client removal
        print_info "Testing client removal..."
        if ./wireguard-manager.sh remove test-client >/dev/null 2>&1; then
            print_status "Client removal: PASSED"
            ((tests_passed++))
            
            run_test "Client config removed" "[ ! -f /etc/wireguard/clients/test-client/test-client.conf ]"
            run_test "Client removed from server config" "! grep -q test-client /etc/wireguard/wg0.conf"
        else
            print_error "Client removal: FAILED"
            ((tests_failed++))
        fi
    else
        print_error "Client addition: FAILED"
        ((tests_failed++))
    fi
}

# Function to test connectivity
test_connectivity() {
    print_header "Connectivity Tests"
    
    # Test local connectivity
    run_test "Ping WireGuard interface" "ping -c 1 -W 2 10.8.0.1"
    
    # Test external connectivity (if available)
    print_info "Testing external connectivity..."
    if ping -c 1 -W 5 8.8.8.8 >/dev/null 2>&1; then
        print_status "External connectivity: PASSED"
        ((tests_passed++))
    else
        print_warning "External connectivity: FAILED (may be expected in some environments)"
    fi
}

# Function to test performance
test_performance() {
    print_header "Performance Tests"
    
    # Test WireGuard interface throughput (basic test)
    print_info "Testing interface performance..."
    if command -v iperf3 >/dev/null 2>&1; then
        print_status "iperf3 available for performance testing"
        ((tests_passed++))
    else
        print_info "iperf3 not available - skipping performance tests"
    fi
    
    # Test system resource usage
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    
    print_info "CPU usage: ${cpu_usage}%"
    print_info "Memory usage: ${memory_usage}%"
    
    # Basic resource usage checks
    run_test "CPU usage reasonable" "[ \$(echo \"$cpu_usage < 90\" | bc -l) = 1 ]" 2>/dev/null || {
        print_info "CPU usage check skipped (bc not available)"
    }
}

# Function to generate test report
generate_report() {
    print_header "Test Report"
    
    total_tests=$((tests_passed + tests_failed))
    
    echo "Total tests run: $total_tests"
    echo "Tests passed: $tests_passed"
    echo "Tests failed: $tests_failed"
    
    if [ $tests_failed -eq 0 ]; then
        print_status "All tests passed! WireGuard installation is working correctly."
        exit 0
    else
        print_error "$tests_failed test(s) failed. Please review the output above."
        exit 1
    fi
}

# Main function
main() {
    print_header "WireGuard Installation Test Suite"
    echo "Starting comprehensive testing..."
    echo ""
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_error "This test script should be run as root for complete testing"
        exit 1
    fi
    
    # Run all tests
    test_system_requirements
    test_wireguard_installation
    test_network_configuration
    test_service_status
    test_security_configuration
    test_management_tools
    test_client_operations
    test_connectivity
    test_performance
    
    # Generate final report
    generate_report
}

# Run main function
main "$@"
