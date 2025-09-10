#!/bin/bash

# Colors for output
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
blue='\033[0;34m'
purple='\033[0;35m'
cyan='\033[0;36m'
plain='\033[0m'

# Banner
show_banner() {
    echo -e "${blue}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                    OSG-SCAN Installer                    ║"
    echo "║              Advanced Network Port Scanner               ║"
    echo "║                                                         ║"
    echo "║  🔍 Fast & Stealth Scanning                             ║"
    echo "║  🛡️  IDS/IPS Evasion Capabilities                       ║"
    echo "║  🔧 Service Detection & Vulnerability Assessment        ║"
    echo "║  🐳 Docker Support with Fallback Options               ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${plain}\n"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${red}❌ Error: This script must be run as root${plain}"
        echo -e "${yellow}💡 Please run: sudo $0${plain}\n"
        exit 1
    fi
}

# Detect OS and package manager
detect_os() {
    echo -e "${yellow}🔍 Detecting operating system...${plain}"
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
        echo -e "${green}✓ Detected: $OS $VER${plain}"
    else
        echo -e "${red}❌ Cannot detect OS version${plain}"
        exit 1
    fi

    if command -v apt-get &> /dev/null; then
        PACKAGE_MANAGER="apt"
        INSTALL_CMD="apt-get install -y"
        UPDATE_CMD="apt-get update"
        echo -e "${green}✓ Package manager: APT${plain}"
    elif command -v yum &> /dev/null; then
        PACKAGE_MANAGER="yum"
        INSTALL_CMD="yum install -y"
        UPDATE_CMD="yum check-update"
        echo -e "${green}✓ Package manager: YUM${plain}"
    elif command -v dnf &> /dev/null; then
        PACKAGE_MANAGER="dnf"
        INSTALL_CMD="dnf install -y"
        UPDATE_CMD="dnf check-update"
        echo -e "${green}✓ Package manager: DNF${plain}"
    else
        echo -e "${red}❌ Unsupported package manager${plain}"
        echo -e "${yellow}💡 This script supports: apt, yum, dnf${plain}"
        exit 1
    fi
}

# Check and install Docker
check_docker() {
    echo -e "\n${yellow}🐳 Checking Docker installation...${plain}"
    
    if command -v docker &> /dev/null; then
        echo -e "${green}✓ Docker is already installed${plain}"
        # Ensure Docker is running
        if ! systemctl is-active --quiet docker; then
            echo -e "${yellow}📡 Starting Docker service...${plain}"
            systemctl start docker
            systemctl enable docker
        fi
    else
        echo -e "${yellow}📦 Installing Docker...${plain}"
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        systemctl start docker
        systemctl enable docker
        usermod -aG docker root
        rm -f get-docker.sh
        echo -e "${green}✓ Docker installed successfully${plain}"
    fi
    
    # Test Docker
    if docker --version &> /dev/null; then
        echo -e "${green}✓ Docker is working properly${plain}"
    else
        echo -e "${yellow}⚠ Docker installation may have issues${plain}"
    fi
}

# Install system dependencies
install_dependencies() {
    echo -e "\n${yellow}📦 Installing system dependencies...${plain}"
    
    # Update package repositories
    echo -e "${cyan}🔄 Updating package repositories...${plain}"
    $UPDATE_CMD

    # Install based on package manager
    if [[ "$PACKAGE_MANAGER" == "apt" ]]; then
        echo -e "${cyan}📦 Installing APT packages...${plain}"
        $INSTALL_CMD \
            git \
            curl \
            wget \
            python3 \
            python3-pip \
            python3-dev \
            python3-setuptools \
            python3-wheel \
            python3-venv \
            pkg-config \
            default-libmysqlclient-dev \
            build-essential \
            libssl-dev \
            libffi-dev \
            software-properties-common \
            apt-transport-https \
            ca-certificates \
            gnupg \
            lsb-release
    
    elif [[ "$PACKAGE_MANAGER" == "yum" ]] || [[ "$PACKAGE_MANAGER" == "dnf" ]]; then
        echo -e "${cyan}📦 Installing ${PACKAGE_MANAGER^^} packages...${plain}"
        $INSTALL_CMD \
            git \
            curl \
            wget \
            python3 \
            python3-pip \
            python3-devel \
            python3-setuptools \
            python3-wheel \
            pkgconfig \
            mysql-devel \
            gcc \
            gcc-c++ \
            make \
            openssl-devel \
            libffi-devel \
            redhat-rpm-config
    fi

    # Ensure pip3 is working
    if ! command -v pip3 &> /dev/null; then
        echo -e "${red}❌ pip3 not found after installation${plain}"
        exit 1
    fi

    # Upgrade pip
    echo -e "${cyan}⬆️ Upgrading pip...${plain}"
    python3 -m pip install --upgrade pip setuptools wheel

    echo -e "${green}✓ System dependencies installed successfully${plain}"
}

# Download and setup project
setup_project() {
    echo -e "\n${yellow}📥 Setting up OSG-SCAN project...${plain}"
    
    # Remove existing installation
    if [[ -d /usr/local/scanner ]]; then
        echo -e "${yellow}🧹 Cleaning previous installation...${plain}"
        systemctl stop scanner 2>/dev/null || true
        systemctl disable scanner 2>/dev/null || true
        rm -rf /usr/local/scanner
    fi

    # Create directory and clone
    mkdir -p /usr/local/scanner
    cd /usr/local/scanner || exit 1

    echo -e "${cyan}📡 Cloning OSG-SCAN repository...${plain}"
    if git clone https://github.com/mohamadm0meni/OSG-SCAN.git .; then
        echo -e "${green}✓ Repository cloned successfully${plain}"
    else
        echo -e "${red}❌ Failed to clone repository${plain}"
        echo -e "${yellow}💡 Check your internet connection and try again${plain}"
        exit 1
    fi

    # Fix main.py shebang if needed
    if [[ -f main.py ]]; then
        if ! head -1 main.py | grep -q "^#!"; then
            echo -e "${cyan}🔧 Adding shebang to main.py...${plain}"
            sed -i '1i#!/usr/bin/env python3' main.py
        fi
        chmod +x main.py
        echo -e "${green}✓ main.py configured${plain}"
    else
        echo -e "${red}❌ main.py not found in repository${plain}"
        exit 1
    fi

    # Create necessary directories
    mkdir -p /usr/local/scanner/{scan_results,logs,config,temp}
    chmod -R 755 /usr/local/scanner
    echo -e "${green}✓ Directory structure created${plain}"
}

# Install Python dependencies
install_python_deps() {
    echo -e "\n${yellow}🐍 Installing Python dependencies...${plain}"
    
    cd /usr/local/scanner || exit 1
    
    if [[ -f requirements.txt ]]; then
        echo -e "${cyan}📦 Installing from requirements.txt...${plain}"
        
        # Try to install all at once first
        if pip3 install --no-cache-dir -r requirements.txt; then
            echo -e "${green}✓ All Python packages installed successfully${plain}"
        else
            echo -e "${yellow}⚠ Some packages failed, trying individual installation...${plain}"
            
            # Install packages individually
            while IFS= read -r requirement; do
                # Skip empty lines and comments
                [[ -z "$requirement" || "$requirement" =~ ^[[:space:]]*# ]] && continue
                
                # Clean the requirement string
                package=$(echo "$requirement" | tr -d '\r\n' | sed 's/[[:space:]]*$//')
                [[ -z "$package" ]] && continue
                
                echo -e "${cyan}  📦 Installing: $package${plain}"
                if pip3 install --no-cache-dir "$package"; then
                    echo -e "${green}    ✓ $package installed${plain}"
                else
                    echo -e "${yellow}    ⚠ Failed to install $package (continuing...)${plain}"
                fi
            done < requirements.txt
        fi
        
        # Special handling for mysqlclient
        echo -e "${cyan}🗄️ Checking MySQL client...${plain}"
        if ! python3 -c "import MySQLdb" 2>/dev/null; then
            echo -e "${yellow}📦 Installing mysqlclient separately...${plain}"
            if pip3 install --no-cache-dir mysqlclient; then
                echo -e "${green}✓ mysqlclient installed${plain}"
            else
                echo -e "${yellow}⚠ mysqlclient failed (MySQL features will be limited)${plain}"
            fi
        else
            echo -e "${green}✓ MySQL client is working${plain}"
        fi
        
    else
        echo -e "${red}❌ requirements.txt not found${plain}"
        exit 1
    fi
}

# Setup Docker environment
setup_docker() {
    echo -e "\n${yellow}🐳 Setting up Docker environment...${plain}"
    
    cd /usr/local/scanner || exit 1
    
    # Build Docker image
    if [[ -f Dockerfile ]]; then
        echo -e "${cyan}🔨 Building Docker image...${plain}"
        if docker build -t osgscan:latest .; then
            echo -e "${green}✓ Docker image built successfully${plain}"
            DOCKER_AVAILABLE=true
        else
            echo -e "${yellow}⚠ Docker build failed, will use direct Python execution${plain}"
            DOCKER_AVAILABLE=false
        fi
    else
        echo -e "${yellow}⚠ Dockerfile not found, skipping Docker setup${plain}"
        DOCKER_AVAILABLE=false
    fi

    # Create smart osgscan command
    echo -e "${cyan}🔧 Creating osgscan command...${plain}"
    cat > /usr/local/bin/osgscan << 'EOF'
#!/bin/bash

# OSG-SCAN Command Wrapper
# Intelligently chooses between Docker and direct Python execution

# Show banner for main command
show_banner() {
    echo -e "\033[0;34m"
    echo "╔═══════════════════════════════════════╗"
    echo "║            OSG-SCAN v2.0              ║"
    echo "║     Advanced Network Scanner          ║"
    echo "╚═══════════════════════════════════════╝"
    echo -e "\033[0m"
}

# Function to run with Docker
run_with_docker() {
    if command -v docker &> /dev/null && docker info > /dev/null 2>&1; then
        if docker images osgscan:latest --format "table {{.Repository}}" | grep -q osgscan; then
            docker run --rm \
                --network host \
                -v "$(pwd)":/app/data \
                -v /usr/local/scanner/scan_results:/app/scan_results \
                -w /app \
                osgscan:latest python3 main.py "$@"
            return $?
        fi
    fi
    return 1
}

# Function to run with Python directly
run_with_python() {
    cd /usr/local/scanner && python3 main.py "$@"
    return $?
}

# Main execution logic
main() {
    # Show banner for help or no arguments
    if [[ $# -eq 0 || "$1" == "--help" || "$1" == "-h" ]]; then
        show_banner
        cd /usr/local/scanner && python3 main.py --help
        return $?
    fi

    # Try Docker first, fallback to Python
    if ! run_with_docker "$@" 2>/dev/null; then
        echo -e "\033[0;33m⚠ Docker unavailable, using direct Python execution...\033[0m"
        run_with_python "$@"
    fi
}

# Run main function with all arguments
main "$@"
EOF

    chmod +x /usr/local/bin/osgscan
    echo -e "${green}✓ osgscan command created${plain}"
}

# Create systemd service
create_service() {
    echo -e "\n${yellow}⚙️ Creating systemd service...${plain}"
    
    cat > /etc/systemd/system/scanner.service << 'EOF'
[Unit]
Description=OSG-SCAN Advanced Network Scanner Service
Documentation=https://github.com/mohamadm0meni/OSG-SCAN
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /usr/local/scanner/main.py --daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
User=root
Group=root
WorkingDirectory=/usr/local/scanner

# Environment variables
Environment=PYTHONPATH=/usr/local/scanner
Environment=SCANNER_LOG_LEVEL=INFO
Environment=SCANNER_CONFIG_PATH=/usr/local/scanner/config.json

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/usr/local/scanner/scan_results /usr/local/scanner/logs /usr/local/scanner/temp

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable scanner
    echo -e "${green}✓ Systemd service created and enabled${plain}"
}

# Create default configuration
create_config() {
    echo -e "\n${yellow}⚙️ Creating default configuration...${plain}"
    
    if [[ ! -f /usr/local/scanner/config.json ]]; then
        cat > /usr/local/scanner/config.json << 'EOF'
{
    "scanner": {
        "default_threads": 50,
        "max_threads": 200,
        "default_timeout": 3,
        "max_timeout": 30,
        "max_retries": 3,
        "scan_delay": 0.1,
        "default_ports": "1-1000",
        "stealth_mode": true
    },
    "output": {
        "default_format": "json",
        "results_directory": "/usr/local/scanner/scan_results",
        "log_directory": "/usr/local/scanner/logs",
        "log_level": "INFO"
    },
    "database": {
        "enabled": false,
        "host": "localhost",
        "port": 3306,
        "database": "osgscan"
    },
    "security": {
        "stealth_mode": true,
        "randomize_agents": true,
        "avoid_detection": true
    }
}
EOF
        echo -e "${green}✓ Default configuration created${plain}"
    else
        echo -e "${green}✓ Configuration file already exists${plain}"
    fi
}

# Run installation tests
run_tests() {
    echo -e "\n${yellow}🧪 Running installation tests...${plain}"
    
    # Test Python import
    echo -e "${cyan}🐍 Testing Python imports...${plain}"
    cd /usr/local/scanner || exit 1
    if python3 -c "import main; print('Main module imported successfully')" 2>/dev/null; then
        echo -e "${green}✓ Python module imports working${plain}"
    else
        echo -e "${yellow}⚠ Python import test failed${plain}"
    fi
    
    # Test osgscan command
    echo -e "${cyan}🔧 Testing osgscan command...${plain}"
    if command -v osgscan &> /dev/null; then
        echo -e "${green}✓ osgscan command is available${plain}"
    else
        echo -e "${red}❌ osgscan command not found${plain}"
    fi
    
    # Test service
    echo -e "${cyan}⚙️ Testing systemd service...${plain}"
    if systemctl start scanner 2>/dev/null; then
        sleep 3
        if systemctl is-active --quiet scanner; then
            echo -e "${green}✓ Service started successfully${plain}"
        else
            echo -e "${yellow}⚠ Service failed to start${plain}"
        fi
    else
        echo -e "${yellow}⚠ Failed to start service${plain}"
    fi
    
    # Test Docker (if available)
    if command -v docker &> /dev/null && docker images osgscan:latest --format "table {{.Repository}}" | grep -q osgscan; then
        echo -e "${cyan}🐳 Testing Docker image...${plain}"
        if timeout 10 docker run --rm osgscan:latest python3 --version &> /dev/null; then
            echo -e "${green}✓ Docker image is working${plain}"
        else
            echo -e "${yellow}⚠ Docker image test failed${plain}"
        fi
    fi
}

# Show final information
show_final_info() {
    echo -e "\n${green}╔═══════════════════════════════════════════════════════════╗${plain}"
    echo -e "${green}║                 🎉 Installation Complete! 🎉             ║${plain}"
    echo -e "${green}╚═══════════════════════════════════════════════════════════╝${plain}\n"
    
    echo -e "${blue}📋 Quick Start Commands:${plain}"
    echo -e "  ${cyan}osgscan --help${plain}                    # Show help and options"
    echo -e "  ${cyan}osgscan example.com${plain}               # Basic scan"
    echo -e "  ${cyan}osgscan example.com -p 1-1000${plain}     # Scan port range"
    echo -e "  ${cyan}osgscan example.com --stealth${plain}     # Stealth mode scan"
    
    echo -e "\n${blue}🔧 Service Management:${plain}"
    echo -e "  ${cyan}systemctl status scanner${plain}          # Check service status"
    echo -e "  ${cyan}systemctl restart scanner${plain}         # Restart service"
    echo -e "  ${cyan}journalctl -u scanner -f${plain}          # View service logs"
    
    echo -e "\n${blue}📁 Important Paths:${plain}"
    echo -e "  ${cyan}Config:${plain}      /usr/local/scanner/config.json"
    echo -e "  ${cyan}Results:${plain}     /usr/local/scanner/scan_results/"
    echo -e "  ${cyan}Logs:${plain}        /usr/local/scanner/logs/"
    
    echo -e "\n${blue}🔗 Resources:${plain}"
    echo -e "  ${cyan}GitHub:${plain}      https://github.com/mohamadm0meni/OSG-SCAN"
    echo -e "  ${cyan}Issues:${plain}      https://github.com/mohamadm0meni/OSG-SCAN/issues"
    
    echo -e "\n${green}🚀 Happy Scanning! 🎯${plain}\n"
}

# Cleanup function
cleanup() {
    echo -e "\n${yellow}🧹 Cleaning up temporary files...${plain}"
    rm -f get-docker.sh /tmp/osgscan_install_*
}

# Error handling
handle_error() {
    echo -e "\n${red}❌ Installation failed at step: $1${plain}"
    echo -e "${yellow}💡 Please check the error messages above and try again${plain}"
    echo -e "${yellow}💡 You can also check the GitHub issues for help${plain}"
    cleanup
    exit 1
}

# Main installation function
main() {
    # Set trap for cleanup
    trap cleanup EXIT
    trap 'handle_error "Unknown error"' ERR
    
    show_banner
    
    echo -e "${purple}🚀 Starting OSG-SCAN installation...${plain}\n"
    
    # Installation steps
    check_root || handle_error "Root permission check"
    detect_os || handle_error "OS detection"
    install_dependencies || handle_error "System dependencies installation"
    check_docker || handle_error "Docker setup"
    setup_project || handle_error "Project setup"
    install_python_deps || handle_error "Python dependencies installation"
    setup_docker || handle_error "Docker environment setup"
    create_service || handle_error "Systemd service creation"
    create_config || handle_error "Configuration creation"
    run_tests || handle_error "Installation tests"
    
    show_final_info
    
    echo -e "${green}✅ OSG-SCAN has been installed successfully!${plain}"
    echo -e "${blue}🎯 You can now start scanning with: ${cyan}osgscan --help${plain}\n"
}

# Run the main installation
main "$@"
