FROM debian:bullseye-slim

# Set working directory
WORKDIR /app

# Install dependencies and required utilities
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    gcc \
    python3-dev \
    libssl-dev \
    pkg-config \
    default-libmysqlclient-dev \
    python3-setuptools \
    build-essential \
    bash \
    curl \
    nano \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables to avoid Python bytecode files and buffer issues
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Ensure necessary directories exist
RUN mkdir -p /usr/local/scanner/scan_results && chmod -R 777 /usr/local/scanner/scan_results

# Set default shell
SHELL ["/bin/bash", "-c"]

# Allow interactive debugging if needed
CMD ["/bin/bash"]

# Default entrypoint to run the main application
ENTRYPOINT ["python3", "main.py"]
