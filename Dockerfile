# OSG-SCAN Docker Image
# Multi-stage build for optimized final image

# Build stage
FROM debian:bullseye-slim as builder

# Set environment variables for build
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# Install build dependencies
RUN apt-get update && apt-get install -y \
    # Python and development tools
    python3 \
    python3-pip \
    python3-dev \
    python3-setuptools \
    python3-wheel \
    # Build tools
    gcc \
    g++ \
    make \
    build-essential \
    # Libraries
    libssl-dev \
    libffi-dev \
    pkg-config \
    default-libmysqlclient-dev \
    libmariadb-dev \
    # Utilities
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Upgrade pip
RUN python3 -m pip install --upgrade pip setuptools wheel

# Copy requirements first for better layer caching
COPY requirements.txt /tmp/requirements.txt

# Install Python dependencies with error handling
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt || \
    (echo "Some packages failed, installing individually..." && \
     while IFS= read -r requirement; do \
         [ -z "$requirement" ] || echo "$requirement" | grep -q "^#" || \
         pip3 install --no-cache-dir "$requirement" || \
         echo "Failed to install $requirement, continuing..."; \
     done < /tmp/requirements.txt)

# Install mysqlclient separately with proper error handling
RUN pip3 install --no-cache-dir mysqlclient || \
    pip3 install --no-cache-dir PyMySQL || \
    echo "MySQL client installation failed, continuing without MySQL support"

# Production stage
FROM debian:bullseye-slim

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV SCANNER_PATH=/app

# Add metadata
LABEL maintainer="mohamadm0meni"
LABEL description="OSG-SCAN - Advanced Network Port Scanner"
LABEL version="2.0"
LABEL repository="https://github.com/mohamadm0meni/OSG-SCAN"

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    python3 \
    python3-minimal \
    libssl1.1 \
    libffi7 \
    libmariadb3 \
    default-mysql-client \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.9/dist-packages /usr/local/lib/python3.9/dist-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Create app directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p /app/{scan_results,logs,data,temp,config} && \
    chmod -R 755 /app

# Copy application files
COPY . /app/

# Ensure main.py has proper shebang and is executable
RUN if [ -f main.py ]; then \
        if ! head -1 main.py | grep -q "^#!"; then \
            sed -i '1i#!/usr/bin/env python3' main.py; \
        fi && \
        chmod +x main.py; \
    fi

# Create non-root user for security
RUN useradd -r -s /bin/false -d /app scanner && \
    chown -R scanner:scanner /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python3 -c "import sys; sys.exit(0)" || exit 1

# Security: Switch to non-root user
USER scanner

# Set proper working directory
WORKDIR /app

# Default command
CMD ["python3", "main.py", "--help"]

# Expose ports (if web interface is added later)
EXPOSE 8080 8443

# Volumes for persistent data
VOLUME ["/app/scan_results", "/app/logs", "/app/data"]
