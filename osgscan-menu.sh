#!/bin/bash

# Colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
white='\033[0;37m'
bold='\033[1m'
plain='\033[0m'

# Banner function
show_banner() {
    clear
    echo -e "${cyan}${bold}"
    echo "  ██████╗ ███████╗ ██████╗       ███████╗ ██████╗ █████╗ ███╗   ██╗"
    echo " ██╔═══██╗██╔════╝██╔════╝       ██╔════╝██╔════╝██╔══██╗████╗  ██║"
    echo " ██║   ██║███████╗██║  ███╗█████╗███████╗██║     ███████║██╔██╗ ██║"
    echo " ██║   ██║╚════██║██║   ██║╚════╝╚════██║██║     ██╔══██║██║╚██╗██║"
    echo " ╚██████╔╝███████║╚██████╔╝      ███████║╚██████╗██║  ██║██║ ╚████║"
    echo "  ╚═════╝ ╚══════╝ ╚═════╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    echo -e "${plain}"
    echo -e "${yellow}${bold}          Advanced Port Scanner & Network Security Tool${plain}"
    echo -e "${green}                      Don't think about Nmap when OSG Scan is here${plain}"
    echo ""
    echo -e "${blue}═══════════════════════════════════════════════════════════════════════${plain}"
    echo ""
}

# Main menu
show_menu() {
    echo -e "${white}${bold}Select an option:${plain}"
    echo ""
    echo -e "  ${green}1)${plain} ${bold}Start Scan${plain}           - Begin port scanning"
    echo -e "  ${yellow}2)${plain} ${bold}Update OSG-SCAN${plain}      - Update to latest version"
    echo -e "  ${purple}3)${plain} ${bold}Restart Services${plain}     - Restart scanner services"
    echo -e "  ${cyan}4)${plain} ${bold}View Scan History${plain}    - Show previous scan results"
    echo -e "  ${blue}5)${plain} ${bold}System Status${plain}        - Check system and service status"
    echo -e "  ${white}6)${plain} ${bold}Configuration${plain}       - Manage scanner settings"
    echo -e "  ${red}7)${plain} ${bold}Uninstall${plain}           - Remove OSG-SCAN completely"
    echo -e "  ${white}0)${plain} ${bold}Exit${plain}               - Exit the program"
    echo ""
    echo -e "${blue}═══════════════════════════════════════════════════════════════════════${plain}"
    echo ""
}

# Start scan function
start_scan() {
    clear
    show_banner
    echo -e "${green}${bold}🚀 Starting Port Scan${plain}"
    echo ""
    
    read -p "Enter target (IP/hostname): " target
    if [[ -z "$target" ]]; then
        echo -e "${red}Error: Target cannot be empty${plain}"
        read -p "Press Enter to continue..."
        return
    fi
    
    read -p "Enter port range (default: 1-1000): " ports
    ports=${ports:-1-1000}
    
    echo ""
    echo -e "${yellow}Scan Options:${plain}"
    echo "1) Quick Scan (Fast)"
    echo "2) Normal Scan"
    echo "3) Stealth Scan"
    echo "4) Aggressive Scan"
    echo "5) Custom Options"
    echo ""
    read -p "Select scan type (1-5): " scan_type
    
    case $scan_type in
        1)
            echo -e "${cyan}Starting Quick Scan...${plain}"
            docker run --rm --network host osgscan "$target" -p "$ports" --timing 4
            ;;
        2)
            echo -e "${cyan}Starting Normal Scan...${plain}"
            docker run --rm --network host osgscan "$target" -p "$ports" --timing 3
            ;;
        3)
            echo -e "${cyan}Starting Stealth Scan...${plain}"
            docker run --rm --network host osgscan "$target" -p "$ports" --profile stealth
            ;;
        4)
            echo -e "${cyan}Starting Aggressive Scan...${plain}"
            docker run --rm --network host osgscan "$target" -p "$ports" --profile aggressive --service-detection --vuln-check
            ;;
        5)
            echo ""
            read -p "Enter custom options: " custom_opts
            echo -e "${cyan}Starting Custom Scan...${plain}"
            docker run --rm --network host osgscan "$target" -p "$ports" $custom_opts
            ;;
        *)
            echo -e "${red}Invalid option${plain}"
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

# Update function
update_osgscan() {
    clear
    show_banner
    echo -e "${yellow}${bold}🔄 Updating OSG-SCAN${plain}"
    echo ""
    
    echo -e "${cyan}Downloading latest version...${plain}"
    bash <(curl -Ls https://raw.githubusercontent.com/mohamadm0meni/OSG-SCAN/main/install.sh)
    
    echo ""
    echo -e "${green}✅ Update completed!${plain}"
    read -p "Press Enter to continue..."
}

# Restart services
restart_services() {
    clear
    show_banner
    echo -e "${purple}${bold}🔄 Restarting Services${plain}"
    echo ""
    
    echo -e "${cyan}Stopping scanner service...${plain}"
    systemctl stop scanner 2>/dev/null || true
    
    echo -e "${cyan}Restarting Docker...${plain}"
    systemctl restart docker
    
    echo -e "${cyan}Starting scanner service...${plain}"
    systemctl start scanner
    
    echo -e "${cyan}Rebuilding Docker image...${plain}"
    cd /usr/local/scanner && docker build -t osgscan . >/dev/null 2>&1
    
    echo ""
    echo -e "${green}✅ Services restarted successfully!${plain}"
    read -p "Press Enter to continue..."
}

# View scan history
view_history() {
    clear
    show_banner
    echo -e "${cyan}${bold}📊 Scan History${plain}"
    echo ""
    
    # Check for scan results
    if [[ -d "/usr/local/scanner/scan_results" ]]; then
        echo -e "${yellow}Recent scan results:${plain}"
        echo ""
        
        # List recent scan directories
        find /usr/local/scanner/scan_results -type d -name "[0-9]*" 2>/dev/null | sort -r | head -10 | while read dir; do
            if [[ -f "$dir"/*.json ]]; then
                scan_file=$(ls "$dir"/*.json 2>/dev/null | head -1)
                if [[ -f "$scan_file" ]]; then
                    target=$(grep -o '"target":[^,]*' "$scan_file" 2>/dev/null | cut -d'"' -f4)
                    date=$(basename "$dir")
                    echo -e "  ${green}[$date]${plain} Target: ${white}$target${plain}"
                fi
            fi
        done
        
        echo ""
        echo -e "${yellow}Options:${plain}"
        echo "1) View detailed scan result"
        echo "2) Export scan results"
        echo "3) Clear old results"
        echo "0) Back to main menu"
        echo ""
        read -p "Select option: " history_opt
        
        case $history_opt in
            1)
                read -p "Enter scan date/time: " scan_date
                result_file="/usr/local/scanner/scan_results/$scan_date/*.json"
                if ls $result_file 1> /dev/null 2>&1; then
                    echo ""
                    echo -e "${cyan}Scan Results:${plain}"
                    cat $result_file | python3 -m json.tool 2>/dev/null || cat $result_file
                else
                    echo -e "${red}Scan result not found${plain}"
                fi
                ;;
            2)
                echo -e "${cyan}Exporting results to /tmp/osgscan_export.tar.gz...${plain}"
                tar -czf /tmp/osgscan_export.tar.gz /usr/local/scanner/scan_results 2>/dev/null
                echo -e "${green}✅ Results exported to /tmp/osgscan_export.tar.gz${plain}"
                ;;
            3)
                read -p "Are you sure you want to clear old results? (y/N): " confirm
                if [[ $confirm =~ ^[Yy]$ ]]; then
                    rm -rf /usr/local/scanner/scan_results/*
                    echo -e "${green}✅ Old results cleared${plain}"
                fi
                ;;
        esac
    else
        echo -e "${yellow}No scan results found.${plain}"
        echo "Run some scans first to see history here."
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# System status
system_status() {
    clear
    show_banner
    echo -e "${blue}${bold}🔍 System Status${plain}"
    echo ""
    
    echo -e "${cyan}Docker Status:${plain}"
    if systemctl is-active --quiet docker; then
        echo -e "  ${green}✅ Docker is running${plain}"
    else
        echo -e "  ${red}❌ Docker is not running${plain}"
    fi
    
    echo ""
    echo -e "${cyan}Scanner Service Status:${plain}"
    if systemctl is-active --quiet scanner; then
        echo -e "  ${green}✅ Scanner service is active${plain}"
    else
        echo -e "  ${yellow}⚠️ Scanner service is inactive${plain}"
    fi
    
    echo ""
    echo -e "${cyan}Docker Image Status:${plain}"
    if docker images | grep -q osgscan; then
        echo -e "  ${green}✅ OSG-SCAN image is available${plain}"
        docker images | grep osgscan
    else
        echo -e "  ${red}❌ OSG-SCAN image not found${plain}"
    fi
    
    echo ""
    echo -e "${cyan}Disk Usage:${plain}"
    df -h /usr/local/scanner 2>/dev/null || echo "Scanner directory not found"
    
    echo ""
    echo -e "${cyan}Memory Usage:${plain}"
    free -h
    
    echo ""
    read -p "Press Enter to continue..."
}

# Configuration
configuration() {
    clear
    show_banner
    echo -e "${white}${bold}⚙️ Configuration${plain}"
    echo ""
    
    echo -e "${yellow}Configuration Options:${plain}"
    echo "1) Edit scanner configuration"
    echo "2) View current settings"
    echo "3) Reset to defaults"
    echo "4) Backup configuration"
    echo "0) Back to main menu"
    echo ""
    read -p "Select option: " config_opt
    
    case $config_opt in
        1)
            if [[ -f "/usr/local/scanner/config.yaml" ]]; then
                nano /usr/local/scanner/config.yaml
            else
                echo -e "${red}Configuration file not found${plain}"
            fi
            ;;
        2)
            if [[ -f "/usr/local/scanner/config.yaml" ]]; then
                echo -e "${cyan}Current Configuration:${plain}"
                cat /usr/local/scanner/config.yaml
            else
                echo -e "${yellow}Using default configuration${plain}"
            fi
            ;;
        3)
            read -p "Reset to default configuration? (y/N): " confirm
            if [[ $confirm =~ ^[Yy]$ ]]; then
                rm -f /usr/local/scanner/config.yaml
                echo -e "${green}✅ Configuration reset to defaults${plain}"
            fi
            ;;
        4)
            if [[ -f "/usr/local/scanner/config.yaml" ]]; then
                cp /usr/local/scanner/config.yaml /tmp/osgscan_config_backup.yaml
                echo -e "${green}✅ Configuration backed up to /tmp/osgscan_config_backup.yaml${plain}"
            else
                echo -e "${yellow}No configuration file to backup${plain}"
            fi
            ;;
    esac
    
    echo ""
    read -p "Press Enter to continue..."
}

# Uninstall function
uninstall_osgscan() {
    clear
    show_banner
    echo -e "${red}${bold}🗑️ Uninstall OSG-SCAN${plain}"
    echo ""
    
    echo -e "${red}⚠️ WARNING: This will completely remove OSG-SCAN from your system!${plain}"
    echo ""
    echo -e "${yellow}The following will be removed:${plain}"
    echo "  - Scanner files and directories"
    echo "  - Docker images and containers"
    echo "  - System services"
    echo "  - Command-line tools"
    echo "  - All scan results and logs"
    echo ""
    
    read -p "Are you absolutely sure? Type 'YES' to confirm: " confirm
    if [[ "$confirm" == "YES" ]]; then
        echo ""
        echo -e "${red}Starting uninstall process...${plain}"
        bash <(curl -Ls https://raw.githubusercontent.com/mohamadm0meni/OSG-SCAN/main/uninstall.sh)
        exit 0
    else
        echo -e "${yellow}Uninstall cancelled.${plain}"
        read -p "Press Enter to continue..."
    fi
}

# Main loop
main() {
    while true; do
        show_banner
        show_menu
        
        read -p "Enter your choice (0-7): " choice
        
        case $choice in
            1) start_scan ;;
            2) update_osgscan ;;
            3) restart_services ;;
            4) view_history ;;
            5) system_status ;;
            6) configuration ;;
            7) uninstall_osgscan ;;
            0) 
                clear
                echo -e "${green}Thank you for using OSG-SCAN! 👋${plain}"
                exit 0
                ;;
            *)
                echo -e "${red}Invalid option. Please try again.${plain}"
                sleep 1
                ;;
        esac
    done
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo -e "${red}This script requires root privileges.${plain}"
    echo "Please run with: sudo $0"
    exit 1
fi

# Start main program
main
