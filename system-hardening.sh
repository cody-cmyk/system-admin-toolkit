#!/usr/bin/env bash

################################################################################
# System Hardening and Administration Toolkit
# Cybersecurity Competition Edition
# 
# This script automates critical system hardening tasks including:
# - User and group management
# - Password policy enforcement
# - Service management
# - Security configuration
# - Forensic investigation
################################################################################

set -u
IFS=$'\n\t'

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
AUTHORIZED_ADMINS=("chowe" "ezekiel" "albert" "rabia")
AUTHORIZED_USERS=("rowan" "kaia" "nolan" "finn" "bennett" "quinn" "reed" "aria" "nova" "elias" "ivy" "sienna")
SPIDER_GROUP_MEMBERS=("nova" "rowan" "finn" "quinn")
MIN_PASSWORD_LENGTH=12
MAX_PASSWORD_AGE=90
CRITICAL_SERVICES=("ssh" "vsftpd")
UNWANTED_SERVICES=("nginx" "squid")
UNWANTED_SOFTWARE=("doona" "xprobe")

# Logging
LOG_FILE="/var/log/system-hardening.log"

################################################################################
# Utility Functions
################################################################################

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${BLUE}"
    echo "========================================"
    echo "$1"
    echo "========================================"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Ensure script is run as root
check_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

################################################################################
# Forensic Investigation Functions
################################################################################

forensic_backdoor_check() {
    print_header "Forensic Question 1: Python Backdoor Detection"
    
    echo "Checking for listening Python processes..."
    echo ""
    
    # Display network listeners
    echo "Network listeners:"
    ss -tlnp | grep -E "python|LISTEN" || echo "No Python processes listening"
    echo ""
    
    # Check for suspicious Python processes
    echo "All Python processes:"
    ps -ef | grep python | grep -v grep || echo "No Python processes found"
    echo ""
    
    echo "If a backdoor is found:"
    echo "  - Directory path: /usr/share/zod"
    echo "  - File: kneelB4zod.py"
    echo "  - Port: 1337"
    echo ""
    read -rp "Press Enter to continue..."
}

forensic_steghide_check() {
    print_header "Forensic Question 2: Steganography Analysis"
    
    echo "Checking for override.txt with embedded passphrase..."
    
    if [[ -f "/srv/ftp/Sales/override.txt" ]]; then
        echo "Found override.txt"
        echo "Content (base64 encoded):"
        cat /srv/ftp/Sales/override.txt
        echo ""
        
        echo "Decoded content:"
        cat /srv/ftp/Sales/override.txt | base64 -d || print_error "Failed to decode"
        echo ""
    else
        print_warning "override.txt not found"
    fi
    
    echo "To extract steganographic message:"
    echo "  steghide extract -p <PASSPHRASE> -sf stanlee.jpg"
    echo "  md5sum message.txt"
    echo ""
    read -rp "Press Enter to continue..."
}

################################################################################
# User Management Functions
################################################################################

remove_unauthorized_users() {
    print_header "Removing Unauthorized Users"
    
    local all_users=$(getent passwd | cut -d: -f1)
    local authorized_list=("${AUTHORIZED_ADMINS[@]}" "${AUTHORIZED_USERS[@]}")
    local removed_count=0
    
    for user in $all_users; do
        # Skip system users (uid >= 1000 or specific system accounts)
        local uid=$(id -u "$user" 2>/dev/null || echo "0")
        
        if [[ $uid -lt 1000 && $uid -ne 0 ]] || [[ "$user" == "root" ]]; then
            # Check if user is authorized
            local is_authorized=0
            for auth_user in "${authorized_list[@]}"; do
                if [[ "$user" == "$auth_user" ]]; then
                    is_authorized=1
                    break
                fi
            done
            
            if [[ $is_authorized -eq 0 && $uid -lt 1000 && $uid -ne 0 ]]; then
                print_warning "Found unauthorized system user: $user (uid: $uid)"
                read -rp "Remove user $user? [y/N]: " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    deluser --remove-home "$user" 2>/dev/null && \
                        print_success "Removed user: $user" && \
                        ((removed_count++)) || \
                        print_error "Failed to remove user: $user"
                    log "INFO" "Removed unauthorized user: $user"
                fi
            fi
        fi
    done
    
    echo ""
    print_success "Unauthorized user removal complete. Removed: $removed_count users"
    log "INFO" "Unauthorized user removal: $removed_count users removed"
}

manage_admin_privileges() {
    print_header "Managing Administrator Privileges"
    
    echo "Authorized Administrators:"
    for admin in "${AUTHORIZED_ADMINS[@]}"; do
        echo "  - $admin"
    done
    echo ""
    
    # Remove unauthorized users from sudo group
    local sudo_members=$(getent group sudo | cut -d: -f4 | tr ',' '\n')
    local removed_count=0
    
    for user in $sudo_members; do
        [[ -z "$user" ]] && continue
        
        local is_admin=0
        for admin in "${AUTHORIZED_ADMINS[@]}"; do
            if [[ "$user" == "$admin" ]]; then
                is_admin=1
                break
            fi
        done
        
        if [[ $is_admin -eq 0 ]]; then
            print_warning "Found unauthorized sudo member: $user"
            read -rp "Remove $user from sudo group? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                gpasswd -d "$user" sudo 2>/dev/null && \
                    print_success "Removed $user from sudo group" && \
                    ((removed_count++)) || \
                    print_error "Failed to remove $user from sudo"
                log "INFO" "Removed sudo privileges from: $user"
            fi
        fi
    done
    
    echo ""
    print_success "Administrator privilege management complete"
}

create_spider_group() {
    print_header "Creating Spider Group"
    
    if getent group spider >/dev/null 2>&1; then
        print_warning "Group 'spider' already exists"
    else
        addgroup spider 2>/dev/null && \
            print_success "Created group 'spider'" || \
            print_error "Failed to create group 'spider'"
        log "INFO" "Created group: spider"
    fi
    
    # Add authorized members
    echo ""
    echo "Adding members to spider group:"
    for member in "${SPIDER_GROUP_MEMBERS[@]}"; do
        if id "$member" >/dev/null 2>&1; then
            gpasswd -a "$member" spider 2>/dev/null && \
                print_success "Added $member to spider group" || \
                print_warning "Could not add $member to spider group"
        else
            print_warning "User $member does not exist"
        fi
    done
    
    # Alternative: set multiple members at once
    echo ""
    echo "Setting complete membership (alternative method):"
    echo "  gpasswd -M ${SPIDER_GROUP_MEMBERS[@]} spider"
    
    log "INFO" "Configured spider group with members: ${SPIDER_GROUP_MEMBERS[@]}"
}

list_all_users() {
    print_header "System Users"
    
    echo "Authorized Administrators:"
    for admin in "${AUTHORIZED_ADMINS[@]}"; do
        if id "$admin" >/dev/null 2>&1; then
            echo "  ✓ $admin"
        else
            echo "  ✗ $admin (missing)"
        fi
    done
    
    echo ""
    echo "Authorized Users:"
    for user in "${AUTHORIZED_USERS[@]}"; do
        if id "$user" >/dev/null 2>&1; then
            echo "  ✓ $user"
        else
            echo "  ✗ $user (missing)"
        fi
    done
    
    echo ""
    echo "All system users:"
    getent passwd | awk -F: '{print $1, "(uid: " $3 ")"}' | sort -k3 -t: -n
}

################################################################################
# Password Policy Functions
################################################################################

configure_password_policy() {
    print_header "Configuring Password Policies"
    
    echo "Setting password policies..."
    echo ""
    
    # Set minimum password length
    echo "1. Configuring minimum password length ($MIN_PASSWORD_LENGTH characters)..."
    
    if [[ -f /etc/pam.d/common-password ]]; then
        # Backup original
        cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
        
        # Update minimum length requirement
        sed -i "s/pam_unix\.so obscure yescrypt/pam_unix.so obscure yescrypt minlen=$MIN_PASSWORD_LENGTH/" \
            /etc/pam.d/common-password
        
        if grep -q "minlen=$MIN_PASSWORD_LENGTH" /etc/pam.d/common-password; then
            print_success "Minimum password length set to $MIN_PASSWORD_LENGTH"
            log "INFO" "Set minimum password length: $MIN_PASSWORD_LENGTH"
        else
            print_error "Failed to set minimum password length"
        fi
    else
        print_warning "/etc/pam.d/common-password not found"
    fi
    
    echo ""
    
    # Remove nullok option
    echo "2. Disabling null passwords..."
    if [[ -f /etc/pam.d/common-auth ]]; then
        cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bak
        sed -i 's/nullok//g' /etc/pam.d/common-auth
        print_success "Removed nullok option from common-auth"
        log "INFO" "Removed nullok from common-auth (null passwords disabled)"
    else
        print_warning "/etc/pam.d/common-auth not found"
    fi
    
    echo ""
    
    # Set password expiration
    echo "3. Configuring password expiration policies..."
    for user in "${AUTHORIZED_USERS[@]}" "${AUTHORIZED_ADMINS[@]}"; do
        if id "$user" >/dev/null 2>&1; then
            chage -M "$MAX_PASSWORD_AGE" "$user" 2>/dev/null && \
                echo "  Set maximum password age for $user to $MAX_PASSWORD_AGE days"
        fi
    done
    
    print_success "Password policies configured"
}

set_user_password_expiration() {
    print_header "Setting User Password Expiration"
    
    read -rp "Enter username: " username
    
    if ! id "$username" >/dev/null 2>&1; then
        print_error "User '$username' does not exist"
        return
    fi
    
    read -rp "Enter maximum password age (days) [$MAX_PASSWORD_AGE]: " max_age
    max_age=${max_age:-$MAX_PASSWORD_AGE}
    
    chage -M "$max_age" "$username" && \
        print_success "Set maximum password age for $username to $max_age days" || \
        print_error "Failed to set password expiration"
    
    echo ""
    echo "Password expiration details:"
    getent shadow "$username" | cut -d: -f1,5
}

secure_root_password() {
    print_header "Securing Root Password"
    
    echo "Current root password status:"
    getent shadow root | cut -d: -f1,2
    echo ""
    
    if getent shadow root | cut -d: -f2 | grep -q "^!"; then
        print_success "Root password is already locked"
    else
        read -rp "Lock root password? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            passwd -l root && \
                print_success "Root password locked" || \
                print_error "Failed to lock root password"
            log "INFO" "Root password locked"
        fi
    fi
    
    echo ""
    echo "New root password status:"
    getent shadow root | cut -d: -f1,2
}

################################################################################
# Service Management Functions
################################################################################

disable_unwanted_services() {
    print_header "Disabling Unwanted Services"
    
    for service in "${UNWANTED_SERVICES[@]}"; do
        echo "Checking service: $service"
        
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            print_warning "Service $service is enabled"
            read -rp "Disable and stop $service? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                systemctl disable --now "$service" 2>/dev/null && \
                    print_success "Disabled and stopped $service" || \
                    print_error "Failed to disable $service"
                log "INFO" "Disabled service: $service"
            fi
        else
            print_success "Service $service is already disabled"
        fi
        echo ""
    done
}

enable_critical_services() {
    print_header "Ensuring Critical Services are Enabled"
    
    for service in "${CRITICAL_SERVICES[@]}"; do
        echo "Checking critical service: $service"
        
        if ! systemctl is-enabled "$service" >/dev/null 2>&1; then
            print_warning "Critical service $service is not enabled"
            read -rp "Enable $service? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                systemctl enable --now "$service" 2>/dev/null && \
                    print_success "Enabled $service" || \
                    print_error "Failed to enable $service"
                log "INFO" "Enabled critical service: $service"
            fi
        else
            print_success "Critical service $service is enabled"
        fi
        echo ""
    done
}

remove_unwanted_software() {
    print_header "Removing Unwanted Software"
    
    echo "Checking for unwanted packages: ${UNWANTED_SOFTWARE[@]}"
    echo ""
    
    for software in "${UNWANTED_SOFTWARE[@]}"; do
        if apt list --installed 2>/dev/null | grep -q "^$software"; then
            print_warning "Found unwanted software: $software"
            read -rp "Remove $software? [y/N]: " confirm
            if [[ "$confirm" =~ ^[Yy]$ ]]; then
                apt purge -y "$software" 2>/dev/null && \
                    print_success "Removed $software" || \
                    print_error "Failed to remove $software"
                log "INFO" "Removed software: $software"
            fi
        else
            print_success "$software is not installed"
        fi
    done
}

################################################################################
# Firewall Configuration
################################################################################

configure_firewall() {
    print_header "Configuring Firewall (UFW)"
    
    echo "Checking UFW status..."
    ufw status
    echo ""
    
    if ! ufw status | grep -q "Status: active"; then
        print_warning "UFW is not enabled"
        read -rp "Enable UFW? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            ufw --force enable && \
                print_success "UFW enabled" || \
                print_error "Failed to enable UFW"
            log "INFO" "Enabled UFW firewall"
        fi
    else
        print_success "UFW is already enabled"
    fi
}

################################################################################
# Kernel Security Configuration
################################################################################

configure_kernel_security() {
    print_header "Configuring Kernel Security Parameters"
    
    echo "Enabling TCP SYN cookies..."
    
    if [[ -f /etc/sysctl.conf ]]; then
        cp /etc/sysctl.conf /etc/sysctl.conf.bak
        
        if grep -q "net.ipv4.tcp_syncookies" /etc/sysctl.conf; then
            sed -i 's/net.ipv4.tcp_syncookies=.*/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf
        else
            echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
        fi
        
        sysctl --system >/dev/null 2>&1 && \
            print_success "TCP SYN cookies enabled" || \
            print_error "Failed to enable TCP SYN cookies"
        
        log "INFO" "Enabled TCP SYN cookies (net.ipv4.tcp_syncookies=1)"
    else
        print_error "/etc/sysctl.conf not found"
    fi
}

################################################################################
# Backdoor Removal
################################################################################

remove_backdoors() {
    print_header "Removing Backdoors"
    
    local backdoor_file="/usr/share/zod/kneelB4zod.py"
    
    if [[ -f "$backdoor_file" ]]; then
        print_warning "Found backdoor: $backdoor_file"
        read -rp "Remove backdoor? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            rm -f "$backdoor_file" && \
                print_success "Removed backdoor file" || \
                print_error "Failed to remove backdoor"
            
            pkill -f kneelB4zod.py 2>/dev/null && \
                print_success "Killed backdoor process" || \
                print_warning "Could not find running backdoor process"
            
            log "INFO" "Removed backdoor: kneelB4zod.py"
        fi
    else
        print_success "No known backdoors detected"
    fi
}

################################################################################
# Prohibited Files Removal
################################################################################

remove_prohibited_files() {
    print_header "Removing Prohibited Files"
    
    echo "Searching for prohibited OGG media files..."
    
    if command -v locate &>/dev/null; then
        ogg_files=$(locate '*.ogg' 2>/dev/null)
    else
        ogg_files=$(find / -name '*.ogg' -type f 2>/dev/null)
    fi
    
    if [[ -n "$ogg_files" ]]; then
        echo "Found OGG files:"
        echo "$ogg_files"
        echo ""
        
        read -rp "Remove all OGG files? [y/N]: " confirm
        if [[ "$confirm" =~ ^[Yy]$ ]]; then
            echo "$ogg_files" | while read -r file; do
                rm -f "$file" && echo "  Removed: $file"
            done
            log "INFO" "Removed prohibited OGG files"
        fi
    else
        print_success "No prohibited OGG files found"
    fi
    
    echo ""
    echo "Searching for prohibited archives..."
    
    zip_files=$(locate '*.zip' 2>/dev/null || find / -name '*.zip' -type f 2>/dev/null)
    
    if [[ -n "$zip_files" ]]; then
        echo "$zip_files" | grep -E "pyrdp|unauthorized" && \
            print_warning "Found suspicious archives - review manually" || \
            print_success "No obviously malicious archives found"
    fi
}

################################################################################
# System Status Functions
################################################################################

system_status() {
    print_header "System Status Report"
    
    echo -e "${BLUE}System Information${NC}"
    echo "===================="
    echo "Hostname: $(hostname)"
    echo "OS: $(lsb_release -ds 2>/dev/null || uname -s)"
    echo "Kernel: $(uname -r)"
    echo "Uptime: $(uptime -p)"
    echo "CPU cores: $(nproc)"
    echo ""
    
    echo -e "${BLUE}Memory${NC}"
    echo "======"
    free -h
    echo ""
    
    echo -e "${BLUE}Disk Usage${NC}"
    echo "=========="
    df -h /
    echo ""
    
    echo -e "${BLUE}Security Status${NC}"
    echo "================"
    echo "Firewall (UFW): $(ufw status | head -1)"
    echo "SSH Service: $(systemctl is-active ssh 2>/dev/null || echo 'inactive')"
    echo "Root account locked: $(getent shadow root | grep -q '^root:!' && echo 'Yes' || echo 'No')"
    echo ""
    
    echo -e "${BLUE}Active Services${NC}"
    echo "================"
    systemctl list-units --type=service --state=active --no-pager 2>/dev/null | \
        awk 'NR>1 {print $1}' | head -10
}

################################################################################
# Main Menu
################################################################################

show_main_menu() {
    echo ""
    print_header "System Hardening and Administration Toolkit"
    
    echo "User & Group Management:"
    echo "  1. Remove unauthorized users"
    echo "  2. Manage administrator privileges"
    echo "  3. Create spider group and add members"
    echo "  4. List all authorized users"
    echo ""
    
    echo "Password & Security Policies:"
    echo "  5. Configure password policies"
    echo "  6. Set user password expiration"
    echo "  7. Secure root password"
    echo ""
    
    echo "Service Management:"
    echo "  8. Disable unwanted services"
    echo "  9. Enable critical services"
    echo " 10. Remove unwanted software"
    echo ""
    
    echo "Firewall & Kernel Security:"
    echo " 11. Configure firewall (UFW)"
    echo " 12. Configure kernel security"
    echo ""
    
    echo "Incident Response & Cleanup:"
    echo " 13. Remove backdoors"
    echo " 14. Remove prohibited files"
    echo ""
    
    echo "Investigation & Monitoring:"
    echo " 15. Forensic backdoor check"
    echo " 16. Forensic steganography check"
    echo " 17. System status report"
    echo ""
    
    echo " 18. Run all hardening tasks"
    echo " 19. Exit"
    echo ""
    echo "========================================="
}

run_all_hardening() {
    print_header "Running All Hardening Tasks"
    
    tasks=(
        "remove_unauthorized_users"
        "manage_admin_privileges"
        "create_spider_group"
        "configure_password_policy"
        "secure_root_password"
        "disable_unwanted_services"
        "enable_critical_services"
        "configure_firewall"
        "configure_kernel_security"
        "remove_backdoors"
        "remove_prohibited_files"
        "remove_unwanted_software"
    )
    
    local total=${#tasks[@]}
    local current=1
    
    for task in "${tasks[@]}"; do
        echo ""
        echo "[$current/$total] Running: $task"
        echo "============================================"
        $task || print_error "Task failed: $task"
        ((current++))
        sleep 1
    done
    
    echo ""
    print_success "All hardening tasks completed"
    log "INFO" "Completed all hardening tasks"
}

################################################################################
# Main Loop
################################################################################

main() {
    check_root
    
    # Ensure log file exists
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"
    
    log "INFO" "System hardening script started by user: $(logname)"
    
    while true; do
        show_main_menu
        read -rp "Enter your choice [1-19]: " choice
        
        case "$choice" in
            1) remove_unauthorized_users ;;
            2) manage_admin_privileges ;;
            3) create_spider_group ;;
            4) list_all_users ;;
            5) configure_password_policy ;;
            6) set_user_password_expiration ;;
            7) secure_root_password ;;
            8) disable_unwanted_services ;;
            9) enable_critical_services ;;
            10) remove_unwanted_software ;;
            11) configure_firewall ;;
            12) configure_kernel_security ;;
            13) remove_backdoors ;;
            14) remove_prohibited_files ;;
            15) forensic_backdoor_check ;;
            16) forensic_steghide_check ;;
            17) system_status ;;
            18) run_all_hardening ;;
            19)
                echo "Exiting. Goodbye!"
                log "INFO" "Script exited normally"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please choose a number between 1 and 19."
                ;;
        esac
        
        echo ""
        read -rp "Press Enter to continue..." dummy
    done
}

# Run main function
main "$@"
