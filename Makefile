# OSG-SCAN Makefile
# Comprehensive project management and automation

.PHONY: help install uninstall update build run test clean docker-build docker-run docker-push service-start service-stop lint format security check-deps

# Colors for output
BLUE=\033[0;34m
GREEN=\033[0;32m
YELLOW=\033[0;33m
RED=\033[0;31m
NC=\033[0m # No Color

# Project variables
PROJECT_NAME=OSG-SCAN
PROJECT_VERSION=2.0
DOCKER_IMAGE=osgscan
DOCKER_TAG=latest
DOCKER_REGISTRY=ghcr.io/mohamadm0meni
INSTALL_PATH=/usr/local/scanner
BIN_PATH=/usr/local/bin

# Default target
help:
	@echo -e "$(BLUE)╔═══════════════════════════════════════════════════════════╗$(NC)"
	@echo -e "$(BLUE)║                   OSG-SCAN Management                    ║$(NC)"
	@echo -e "$(BLUE)║                     Version $(PROJECT_VERSION)                        ║$(NC)"
	@echo -e "$(BLUE)╚═══════════════════════════════════════════════════════════╝$(NC)"
	@echo ""
	@echo -e "$(GREEN)📦 Installation Commands:$(NC)"
	@echo "  install              Install OSG-SCAN system-wide"
	@echo "  uninstall            Remove OSG-SCAN from system"
	@echo "  update               Update to latest version"
	@echo "  reinstall            Complete reinstallation"
	@echo ""
	@echo -e "$(GREEN)🔧 Development Commands:$(NC)"
	@echo "  dev-setup            Setup development environment"
	@echo "  build                Build and validate the project"
	@echo "  run                  Run OSG-SCAN locally"
	@echo "  test                 Run comprehensive tests"
	@echo "  clean                Clean temporary files and caches"
	@echo ""
	@echo -e "$(GREEN)🐳 Docker Commands:$(NC)"
	@echo "  docker-build         Build Docker image"
	@echo "  docker-run           Run with Docker"
	@echo "  docker-push          Push image to registry"
	@echo "  docker-compose       Run full stack with Docker Compose"
	@echo "  docker-clean         Clean Docker images and containers"
	@echo ""
	@echo -e "$(GREEN)⚙️ Service Commands:$(NC)"
	@echo "  service-install      Install systemd service"
	@echo "  service-start        Start scanner service"
	@echo "  service-stop         Stop scanner service"
	@echo "  service-restart      Restart scanner service"
	@echo "  service-status       Check service status"
	@echo "  service-logs         View service logs"
	@echo ""
	@echo -e "$(GREEN)🔍 Quality & Security:$(NC)"
	@echo "  lint                 Run code linting"
	@echo "  format               Format code with black and isort"
	@echo "  security             Run security analysis"
	@echo "  check-deps           Check dependencies for vulnerabilities"
	@echo "  pre-commit           Run pre-commit checks"
	@echo ""
	@echo -e "$(GREEN)📊 Analysis & Monitoring:$(NC)"
	@echo "  benchmark            Run performance benchmarks"
	@echo "  profile              Profile application performance"
	@echo "  monitor              Monitor resource usage"
	@echo ""
	@echo -e "$(GREEN)📋 Utility Commands:$(NC)"
	@echo "  show-config          Display current configuration"
	@echo "  backup               Backup current installation"
	@echo "  restore              Restore from backup"
	@echo "  version              Show version information"
	@echo ""
	@echo -e "$(YELLOW)💡 Usage Examples:$(NC)"
	@echo "  make install                    # Install the scanner"
	@echo "  make run TARGET=example.com     # Run scan against target"
	@echo "  make docker-run ARGS='example.com -p 80,443'"
	@echo "  make test VERBOSE=1             # Run tests with verbose output"

# Installation commands
install:
	@echo -e "$(BLUE)📦 Installing OSG-SCAN...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		echo -e "$(RED)❌ Error: Installation requires root privileges$(NC)"; \
		echo -e "$(YELLOW)💡 Please run: sudo make install$(NC)"; \
		exit 1; \
	fi
	@chmod +x install.sh
	@./install.sh

uninstall:
	@echo -e "$(BLUE)🗑️ Uninstalling OSG-SCAN...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		echo -e "$(RED)❌ Error: Uninstallation requires root privileges$(NC)"; \
		echo -e "$(YELLOW)💡 Please run: sudo make uninstall$(NC)"; \
		exit 1; \
	fi
	systemctl stop scanner 2>/dev/null || true
	systemctl disable scanner 2>/dev/null || true
	rm -f /etc/systemd/system/scanner.service
	rm -f $(BIN_PATH)/osgscan
	rm -rf $(INSTALL_PATH)
	systemctl daemon-reload
	@echo -e "$(GREEN)✅ OSG-SCAN uninstalled successfully$(NC)"

update:
	@echo -e "$(BLUE)🔄 Updating OSG-SCAN...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		echo -e "$(RED)❌ Error: Update requires root privileges$(NC)"; \
		echo -e "$(YELLOW)💡 Please run: sudo make update$(NC)"; \
		exit 1; \
	fi
	@if [ -d "$(INSTALL_PATH)/.git" ]; then \
		cd $(INSTALL_PATH) && git pull origin main; \
	else \
		echo -e "$(YELLOW)⚠ Not a git installation, performing fresh install...$(NC)"; \
		make install; \
	fi
	systemctl restart scanner 2>/dev/null || true
	@echo -e "$(GREEN)✅ OSG-SCAN updated successfully$(NC)"

reinstall:
	@echo -e "$(BLUE)🔄 Reinstalling OSG-SCAN...$(NC)"
	@make uninstall
	@make install

# Development commands
dev-setup:
	@echo -e "$(BLUE)🛠️ Setting up development environment...$(NC)"
	@echo -e "$(YELLOW)📦 Installing development dependencies...$(NC)"
	pip3 install -r requirements.txt
	pip3 install black flake8 isort pytest pytest-cov bandit safety pre-commit
	@if [ -f ".pre-commit-config.yaml" ]; then \
		pre-commit install; \
		echo -e "$(GREEN)✅ Pre-commit hooks installed$(NC)"; \
	fi
	chmod +x main.py
	@echo -e "$(GREEN)✅ Development environment ready$(NC)"

build:
	@echo -e "$(BLUE)🔨 Building OSG-SCAN...$(NC)"
	@echo -e "$(YELLOW)🐍 Compiling Python modules...$(NC)"
	python3 -m py_compile main.py
	@if [ -d "modules" ]; then \
		python3 -m py_compile modules/*.py; \
	fi
	@echo -e "$(YELLOW)🧪 Running syntax checks...$(NC)"
	python3 -m flake8 main.py --select=E9,F63,F7,F82 || true
	@echo -e "$(GREEN)✅ Build completed successfully$(NC)"

run:
	@echo -e "$(BLUE)🚀 Running OSG-SCAN...$(NC)"
	@if [ -z "$(TARGET)" ]; then \
		echo -e "$(YELLOW)💡 Usage: make run TARGET=example.com [PORTS=1-1000] [ARGS='--stealth']$(NC)"; \
		python3 main.py --help; \
	else \
		if [ -n "$(PORTS)" ]; then \
			python3 main.py $(TARGET) -p $(PORTS) $(ARGS); \
		else \
			python3 main.py $(TARGET) $(ARGS); \
		fi \
	fi

test:
	@echo -e "$(BLUE)🧪 Running comprehensive tests...$(NC)"
	@echo -e "$(YELLOW)📋 Testing Python imports...$(NC)"
	@python3 -c "import main; print('✅ Main module imports successfully')" 2>/dev/null || \
		echo -e "$(RED)❌ Main module import failed$(NC)"
	
	@echo -e "$(YELLOW)📋 Testing core dependencies...$(NC)"
	@python3 -c "import requests, socket, threading; print('✅ Core dependencies available')" 2>/dev/null || \
		echo -e "$(YELLOW)⚠ Some core dependencies missing$(NC)"
	
	@echo -e "$(YELLOW)📋 Testing configuration...$(NC)"
	@if [ -f "config.json" ]; then \
		python3 -c "import json; json.load(open('config.json')); print('✅ Configuration file is valid JSON')" 2>/dev/null || \
		echo -e "$(YELLOW)⚠ Configuration file has issues$(NC)"; \
	else \
		echo -e "$(YELLOW)⚠ Configuration file not found$(NC)"; \
	fi
	
	@if [ -d "tests" ]; then \
		echo -e "$(YELLOW)📋 Running unit tests...$(NC)"; \
		python3 -m pytest tests/ -v $(if $(VERBOSE),--verbose,) || true; \
	fi
	
	@echo -e "$(YELLOW)📋 Testing help command...$(NC)"
	@timeout 10 python3 main.py --help > /dev/null 2>&1 && \
		echo -e "$(GREEN)✅ Help command works$(NC)" || \
		echo -e "$(YELLOW)⚠ Help command test failed$(NC)"
	
	@echo -e "$(GREEN)🎉 Test suite completed$(NC)"

clean:
	@echo -e "$(BLUE)🧹 Cleaning temporary files...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.pyd" -delete
	find . -type f -name ".coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache/ .mypy_cache/ .tox/
	rm -f *.log debug.log scan_*.json
	@echo -e "$(GREEN)✅ Cleanup completed$(NC)"

# Docker commands
docker-build:
	@echo -e "$(BLUE)🐳 Building Docker image...$(NC)"
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest
	@echo -e "$(GREEN)✅ Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(NC)"

docker-run:
	@echo -e "$(BLUE)🐳 Running OSG-SCAN with Docker...$(NC)"
	@if [ -z "$(ARGS)" ]; then \
		docker run --rm --network host -v $$(pwd):/app/data $(DOCKER_IMAGE):$(DOCKER_TAG) --help; \
	else \
		docker run --rm --network host -v $$(pwd):/app/data $(DOCKER_IMAGE):$(DOCKER_TAG) $(ARGS); \
	fi

docker-push:
	@echo -e "$(BLUE)🐳 Pushing Docker image to registry...$(NC)"
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	@echo -e "$(GREEN)✅ Images pushed to registry$(NC)"

docker-compose:
	@echo -e "$(BLUE)🐳 Starting Docker Compose stack...$(NC)"
	docker-compose up --build $(if $(DETACH),-d,)

docker-clean:
	@echo -e "$(BLUE)🐳 Cleaning Docker resources...$(NC)"
	docker system prune -f
	docker image prune -f
	@echo -e "$(GREEN)✅ Docker cleanup completed$(NC)"

# Service management
service-install:
	@echo -e "$(BLUE)⚙️ Installing systemd service...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		echo -e "$(RED)❌ Error: Service installation requires root privileges$(NC)"; \
		exit 1; \
	fi
	@if [ ! -f "/etc/systemd/system/scanner.service" ]; then \
		echo -e "$(YELLOW)📋 Service file not found, running full installation...$(NC)"; \
		make install; \
	else \
		systemctl daemon-reload; \
		systemctl enable scanner; \
		echo -e "$(GREEN)✅ Service installed and enabled$(NC)"; \
	fi

service-start:
	@echo -e "$(BLUE)▶️ Starting scanner service...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		sudo systemctl start scanner; \
	else \
		systemctl start scanner; \
	fi
	@echo -e "$(GREEN)✅ Scanner service started$(NC)"

service-stop:
	@echo -e "$(BLUE)⏹️ Stopping scanner service...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		sudo systemctl stop scanner; \
	else \
		systemctl stop scanner; \
	fi
	@echo -e "$(GREEN)✅ Scanner service stopped$(NC)"

service-restart:
	@echo -e "$(BLUE)🔄 Restarting scanner service...$(NC)"
	@if [ "$$(id -u)" != "0" ]; then \
		sudo systemctl restart scanner; \
	else \
		systemctl restart scanner; \
	fi
	@echo -e "$(GREEN)✅ Scanner service restarted$(NC)"

service-status:
	@echo -e "$(BLUE)📊 Checking service status...$(NC)"
	@systemctl status scanner --no-pager --lines=10

service-logs:
	@echo -e "$(BLUE)📋 Showing service logs...$(NC)"
	@journalctl -u scanner -f --lines=50

# Quality and security
lint:
	@echo -e "$(BLUE)🔍 Running code linting...$(NC)"
	@echo -e "$(YELLOW)📋 Flake8 analysis...$(NC)"
	@flake8 main.py --max-line-length=88 --extend-ignore=E203,W503 || true
	@if [ -d "modules" ]; then \
		flake8 modules/ --max-line-length=88 --extend-ignore=E203,W503 || true; \
	fi
	@echo -e "$(GREEN)✅ Linting completed$(NC)"

format:
	@echo -e "$(BLUE)🎨 Formatting code...$(NC)"
	@echo -e "$(YELLOW)📋 Running Black formatter...$(NC)"
	@black main.py $(if $(wildcard modules/),modules/,) --line-length=88 || \
		echo -e "$(YELLOW)⚠ Black not installed, skipping formatting$(NC)"
	@echo -e "$(YELLOW)📋 Running isort...$(NC)"
	@isort main.py $(if $(wildcard modules/),modules/,) --profile black || \
		echo -e "$(YELLOW)⚠ isort not installed, skipping import sorting$(NC)"
	@echo -e "$(GREEN)✅ Code formatting completed$(NC)"

security:
	@echo -e "$(BLUE)🔒 Running security analysis...$(NC)"
	@echo -e "$(YELLOW)📋 Bandit security scan...$(NC)"
	@bandit -r . -ll -f json -o bandit-report.json 2>/dev/null || \
		echo -e "$(YELLOW)⚠ Bandit not installed or found issues$(NC)"
	@echo -e "$(YELLOW)📋 Safety dependency check...$(NC)"
	@safety check --json --output safety-report.json 2>/dev/null || \
		echo -e "$(YELLOW)⚠ Safety not installed or found vulnerabilities$(NC)"
	@echo -e "$(GREEN)✅ Security analysis completed$(NC)"

check-deps:
	@echo -e "$(BLUE)📦 Checking dependencies...$(NC)"
	@echo -e "$(YELLOW)📋 Validating requirements...$(NC)"
	@pip3 check || echo -e "$(YELLOW)⚠ Dependency conflicts detected$(NC)"
	@echo -e "$(YELLOW)📋 Checking for outdated packages...$(NC)"
	@pip3 list --outdated || echo -e "$(YELLOW)⚠ Some packages are outdated$(NC)"
	@echo -e "$(GREEN)✅ Dependency check completed$(NC)"

pre-commit:
	@echo -e "$(BLUE)🔍 Running pre-commit checks...$(NC)"
	@make lint
	@make security
	@make test
	@echo -e "$(GREEN)✅ All pre-commit checks completed$(NC)"

# Analysis and monitoring
benchmark:
	@echo -e "$(BLUE)📊 Running performance benchmark...$(NC)"
	@echo -e "$(YELLOW)⏱️ Basic scan benchmark...$(NC)"
	@time timeout 30s python3 main.py 127.0.0.1 -p 1-100 --timing 4 2>/dev/null || \
		echo -e "$(YELLOW)⚠ Benchmark completed (may have timed out)$(NC)"
	@echo -e "$(GREEN)✅ Benchmark completed$(NC)"

profile:
	@echo -e "$(BLUE)📈 Profiling application performance...$(NC)"
	@python3 -m cProfile -o profile.stats main.py 127.0.0.1 -p 1-50 2>/dev/null || \
		echo -e "$(YELLOW)⚠ Profiling completed with warnings$(NC)"
	@echo -e "$(GREEN)✅ Profiling data saved to profile.stats$(NC)"

monitor:
	@echo -e "$(BLUE)📊 Monitoring resource usage...$(NC)"
	@if command -v htop >/dev/null 2>&1; then \
		echo -e "$(YELLOW)💡 Press 'q' to quit htop$(NC)"; \
		htop -p $$(pgrep -f "python3.*main.py" | tr '\n' ',' | sed 's/,$$//') 2>/dev/null || \
		echo -e "$(YELLOW)⚠ No OSG-SCAN processes found$(NC)"; \
	else \
		echo -e "$(YELLOW)⚠ htop not installed, using ps$(NC)"; \
		ps aux | grep -E "(python3.*main.py|scanner)" | grep -v grep; \
	fi

# Utility commands
show-config:
	@echo -e "$(BLUE)📋 OSG-SCAN Configuration$(NC)"
	@echo -e "$(YELLOW)═══════════════════════════$(NC)"
	@echo -e "$(GREEN)Installation:$(NC)"
	@echo "  📁 Installation path: $(INSTALL_PATH)"
	@echo "  🔧 Binary path: $(BIN_PATH)/osgscan"
	@echo "  ⚙️ Service file: /etc/systemd/system/scanner.service"
	@echo ""
	@echo -e "$(GREEN)Configuration:$(NC)"
	@echo "  📄 Config file: $(INSTALL_PATH)/config.json"
	@echo "  📊 Results directory: $(INSTALL_PATH)/scan_results"
	@echo "  📋 Logs directory: $(INSTALL_PATH)/logs"
	@echo ""
	@echo -e "$(GREEN)Status:$(NC)"
	@if command -v osgscan >/dev/null 2>&1; then \
		echo "  ✅ osgscan command: Available"; \
	else \
		echo "  ❌ osgscan command: Not found"; \
	fi
	@if systemctl is-active --quiet scanner 2>/dev/null; then \
		echo "  ✅ Service status: Running"; \
	else \
		echo "  ⏹️ Service status: Stopped"; \
	fi
	@if docker images osgscan:latest --format "table {{.Repository}}" | grep -q osgscan 2>/dev/null; then \
		echo "  ✅ Docker image: Available"; \
	else \
		echo "  ❌ Docker image: Not built"; \
	fi

backup:
	@echo -e "$(BLUE)💾 Creating backup...$(NC)"
	@if [ -d "$(INSTALL_PATH)" ]; then \
		BACKUP_NAME="osgscan-backup-$$(date +%Y%m%d-%H%M%S)"; \
		tar -czf "$$BACKUP_NAME.tar.gz" -C /usr/local scanner/ 2>/dev/null; \
		echo -e "$(GREEN)✅ Backup created: $$BACKUP_NAME.tar.gz$(NC)"; \
	else \
		echo -e "$(YELLOW)⚠ No installation found to backup$(NC)"; \
	fi

restore:
	@echo -e "$(BLUE)🔄 Restoring from backup...$(NC)"
	@if [ -z "$(BACKUP)" ]; then \
		echo -e "$(YELLOW)💡 Usage: make restore BACKUP=backup-file.tar.gz$(NC)"; \
		ls -la osgscan-backup-*.tar.gz 2>/dev/null || echo -e "$(YELLOW)⚠ No backup files found$(NC)"; \
	else \
		if [ -f "$(BACKUP)" ]; then \
			echo -e "$(YELLOW)📋 Stopping services...$(NC)"; \
			make service-stop 2>/dev/null || true; \
			echo -e "$(YELLOW)📋 Extracting backup...$(NC)"; \
			tar -xzf "$(BACKUP)" -C /usr/local/; \
			echo -e "$(YELLOW)📋 Restarting services...$(NC)"; \
			make service-start 2>/dev/null || true; \
			echo -e "$(GREEN)✅ Backup restored successfully$(NC)"; \
		else \
			echo -e "$(RED)❌ Backup file not found: $(BACKUP)$(NC)"; \
		fi \
	fi

version:
	@echo -e "$(BLUE)📋 OSG-SCAN Version Information$(NC)"
	@echo -e "$(YELLOW)══════════════════════════════$(NC)"
	@echo -e "$(GREEN)Project:$(NC) $(PROJECT_NAME)"
	@echo -e "$(GREEN)Version:$(NC) $(PROJECT_VERSION)"
	@if [ -f "main.py" ]; then \
		VERSION_LINE=$$(grep -E "VERSION|__version__" main.py 2>/dev/null | head -1); \
		if [ -n "$$VERSION_LINE" ]; then \
			echo -e "$(GREEN)Code version:$(NC) $$VERSION_LINE"; \
		fi \
	fi
	@if [ -d ".git" ]; then \
		echo -e "$(GREEN)Git commit:$(NC) $$(git rev-parse --short HEAD 2>/dev/null || echo 'Unknown')"; \
		echo -e "$(GREEN)Git branch:$(NC) $$(git branch --show-current 2>/dev/null || echo 'Unknown')"; \
	fi
	@echo -e "$(GREEN)Build date:$(NC) $$(date '+%Y-%m-%d %H:%M:%S')"
	@echo -e "$(GREEN)Platform:$(NC) $$(uname -s) $$(uname -r)"
	@echo -e "$(GREEN)Python:$(NC) $$(python3 --version 2>/dev/null || echo 'Not found')"

# Quick scan shortcuts
scan-local:
	@make run TARGET=127.0.0.1 PORTS=1-1000

scan-common:
	@if [ -z "$(TARGET)" ]; then \
		echo -e "$(YELLOW)💡 Usage: make scan-common TARGET=example.com$(NC)"; \
	else \
		make run TARGET=$(TARGET) PORTS=21,22,23,25,53,80,110,143,443,993,995,3306,5432; \
	fi

scan-web:
	@if [ -z "$(TARGET)" ]; then \
		echo -e "$(YELLOW)💡 Usage: make scan-web TARGET=example.com$(NC)"; \
	else \
		make run TARGET=$(TARGET) PORTS=80,443,8080,8443,9000,9001; \
	fi

scan-stealth:
	@if [ -z "$(TARGET)" ]; then \
		echo -e "$(YELLOW)💡 Usage: make scan-stealth TARGET=example.com$(NC)"; \
	else \
		make run TARGET=$(TARGET) ARGS="--profile stealth --timing 1"; \
	fi

# Package and distribution
package:
	@echo -e "$(BLUE)📦 Creating distribution package...$(NC)"
	@PACKAGE_NAME="osgscan-v$(PROJECT_VERSION)-$$(date +%Y%m%d)"
	@tar -czf "$$PACKAGE_NAME.tar.gz" \
		main.py install.sh requirements.txt Dockerfile \
		config.json README.md CHANGELOG.md Makefile \
		docker-compose.yml .dockerignore \
		--exclude-vcs --exclude='*.pyc' --exclude='__pycache__'
	@echo -e "$(GREEN)✅ Package created: $$PACKAGE_NAME.tar.gz$(NC)"

release:
	@echo -e "$(BLUE)🚀 Preparing release...$(NC)"
	@echo -e "$(YELLOW)📋 Running pre-release checks...$(NC)"
	@make pre-commit
	@make docker-build
	@echo -e "$(YELLOW)📋 Creating release package...$(NC)"
	@make package
	@echo -e "$(GREEN)✅ Release preparation completed$(NC)"
	@echo -e "$(YELLOW)💡 Next steps:$(NC)"
	@echo "  1. Tag the release: git tag v$(PROJECT_VERSION)"
	@echo "  2. Push to GitHub: git push origin v$(PROJECT_VERSION)"
	@echo "  3. Create GitHub release with package"
	@echo "  4. Push Docker images: make docker-push"

# Help for specific commands
help-install:
	@echo -e "$(BLUE)📦 Installation Help$(NC)"
	@echo "The install command will:"
	@echo "  • Detect your operating system and package manager"
	@echo "  • Install all required system dependencies"
	@echo "  • Set up Python environment with dependencies"
	@echo "  • Configure Docker (optional)"
	@echo "  • Create systemd service"
	@echo "  • Set up command-line tool"
	@echo "  • Run tests to verify installation"

help-docker:
	@echo -e "$(BLUE)🐳 Docker Help$(NC)"
	@echo "Docker commands available:"
	@echo "  docker-build    - Build optimized Docker image"
	@echo "  docker-run      - Run scans in container"
	@echo "  docker-compose  - Run full application stack"
	@echo "  docker-clean    - Clean up Docker resources"
	@echo ""
	@echo "Example usage:"
	@echo "  make docker-run ARGS='example.com -p 1-1000 --output json'"

help-service:
	@echo -e "$(BLUE)⚙️ Service Help$(NC)"
	@echo "Service management commands:"
	@echo "  service-install - Install systemd service"
	@echo "  service-start   - Start the scanner service"
	@echo "  service-stop    - Stop the scanner service"
	@echo "  service-restart - Restart the service"
	@echo "  service-status  - Show current status"
	@echo "  service-logs    - Show real-time logs"

# Detect system information
system-info:
	@echo -e "$(BLUE)💻 System Information$(NC)"
	@echo -e "$(YELLOW)═══════════════════$(NC)"
	@echo -e "$(GREEN)Operating System:$(NC)"
	@if [ -f /etc/os-release ]; then \
		. /etc/os-release && echo "  📋 Distribution: $$NAME $$VERSION"; \
	fi
	@echo "  🏗️ Architecture: $$(uname -m)"
	@echo "  🐧 Kernel: $$(uname -r)"
	@echo ""
	@echo -e "$(GREEN)Package Manager:$(NC)"
	@if command -v apt-get >/dev/null 2>&1; then \
		echo "  📦 APT (Debian/Ubuntu)"; \
	elif command -v yum >/dev/null 2>&1; then \
		echo "  📦 YUM (CentOS/RHEL)"; \
	elif command -v dnf >/dev/null 2>&1; then \
		echo "  📦 DNF (Fedora)"; \
	else \
		echo "  ❌ Unknown or unsupported"; \
	fi
	@echo ""
	@echo -e "$(GREEN)Python Environment:$(NC)"
	@echo "  🐍 Python: $$(python3 --version 2>/dev/null || echo 'Not found')"
	@echo "  📦 pip: $$(pip3 --version 2>/dev/null | cut -d' ' -f2 || echo 'Not found')"
	@echo ""
	@echo -e "$(GREEN)Docker:$(NC)"
	@if command -v docker >/dev/null 2>&1; then \
		echo "  🐳 Docker: $$(docker --version | cut -d' ' -f3 | tr -d ',')"; \
		if systemctl is-active --quiet docker 2>/dev/null; then \
			echo "  ✅ Status: Running"; \
		else \
			echo "  ⏹️ Status: Stopped"; \
		fi \
	else \
		echo "  ❌ Docker: Not installed"; \
	fi
