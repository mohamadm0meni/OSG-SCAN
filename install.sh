#!/bin/bash

# Colors
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# Check root access
if [[ $EUID -ne 0 ]]; then
    echo -e "${red}Error: ${plain} Please run with root privileges \n "
    exit 1
fi

check_docker() {
    if ! command -v docker &> /dev/null; then
        echo -e "${yellow}Docker is not installed. Installing Docker...${plain}"
        curl -fsSL https://get.docker.com -o get-docker.sh
        sh get-docker.sh
        systemctl start docker
        systemctl enable docker
    fi
}

check_dependencies() {
    echo -e "${yellow}Checking system dependencies...${plain}"
    
    # Install git if not present
    if ! command -v git &> /dev/null; then
        apt-get update
        apt-get install -y git
    fi

    # Install Python and pip if not present
    if ! command -v python3 &> /dev/null; then
        apt-get update
        apt-get install -y python3 python3-pip
    fi
}

download_project() {
    echo -e "${yellow}Downloading project files...${plain}"
    
    # Create project directory
    mkdir -p /usr/local/scanner
    cd /usr/local/scanner || exit 1

    # Clone repository
    git clone https://github.com/mohamadm0meni/OSG-SCAN.git .
    
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Repository cloning failed${plain}"
        return 1
    fi

    # Install Python dependencies
    if [[ -f requirements.txt ]]; then
        pip3 install -r requirements.txt
    else
        echo -e "${red}requirements.txt not found!${plain}"
        return 1
    fi
    
    # Set permissions
    if [[ -f main.py ]]; then
        chmod +x main.py
    else
        echo -e "${red}main.py not found!${plain}"
        return 1
    fi
    
    return 0
}

setup_docker() {
    echo -e "${yellow}Setting up Docker environment...${plain}"
    
    # Build Docker image
    if [[ -f Dockerfile ]]; then
        docker build -t osgscan .
    else
        echo -e "${red}Dockerfile not found!${plain}"
        exit 1
    fi
    
    # Create executable script
    cat > /usr/local/bin/osgscan << 'EOF'
#!/bin/bash
docker run --rm \
    --network host \
    -v $(pwd):/app/data \
    osgscan "$@"
EOF

    chmod +x /usr/local/bin/osgscan
}

check_files() {
    if [[ ! -f Dockerfile ]]; then
        echo -e "${red}Dockerfile not found${plain}"
        exit 1
    fi
    
    if [[ ! -w /usr/local/bin ]]; then
        echo -e "${red}Need sudo access to write to /usr/local/bin${plain}"
        exit 1
    fi
}

create_service() {
    cat > /etc/systemd/system/scanner.service << EOF
[Unit]
Description=Scanner Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/scanner/main.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable scanner
    systemctl start scanner
}

main() {
    echo -e "${green}Starting installation...${plain}"
    
    check_dependencies
    check_docker
    check_files
    
    if download_project; then
        setup_docker
        create_service
        echo -e "${green}Installation completed successfully!${plain}"
        echo -e "You can now use 'osgscan' command or check service status with 'systemctl status scanner'"
    else
        echo -e "${red}Installation failed${plain}"
        exit 1
    fi
}

main
