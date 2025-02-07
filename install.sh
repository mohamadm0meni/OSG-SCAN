#!/bin/bash

check_docker() {
   if ! command -v docker &> /dev/null; then
       echo "Docker is not installed. Installing Docker..."
       curl -fsSL https://get.docker.com -o get-docker.sh
       sudo sh get-docker.sh
   fi
}

check_files() {
   if [ ! -f Dockerfile ]; then
       echo "Dockerfile not found"
       exit 1
   fi

   if [ ! -w /usr/local/bin ]; then
       echo "Need sudo access to write to /usr/local/bin"
       exit 1
   fi
}

setup_docker() {
   echo "Building Docker image..."
   sudo docker build -t osgscan .
   
   echo '#!/bin/bash
sudo docker run --rm osgscan "$@"' > /usr/local/bin/osgscan
   chmod +x /usr/local/bin/osgscan
}

main() {
   check_files
   check_docker
   setup_docker
   echo "Installation complete! You can now use osgscan"
}

main
