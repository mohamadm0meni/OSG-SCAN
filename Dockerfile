FROM debian:bullseye-slim
WORKDIR /app

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    gcc \
    python3-dev \
    libssl-dev \
    pkg-config \
    default-libmysqlclient-dev \
    python3-setuptools \
    build-essential

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt
COPY . .
ENTRYPOINT ["python3", "main.py"]
