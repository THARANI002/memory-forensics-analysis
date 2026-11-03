# Enterprise Memory Forensics Platform - Deployment Guide

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the Platform](#running-the-platform)
5. [Docker Deployment](#docker-deployment)
6. [Production Deployment](#production-deployment)
7. [Security Considerations](#security-considerations)
8. [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

| Component | Specification |
|-----------|--------------|
| CPU | 4 cores (x86_64) |
| RAM | 8 GB |
| Storage | 50 GB SSD |
| OS | Linux (Ubuntu 20.04+), Windows 10+, macOS 12+ |
| Python | 3.9 or higher |
| Network | Internet access for threat intelligence APIs |

### Recommended Requirements

| Component | Specification |
|-----------|--------------|
| CPU | 8+ cores (x86_64) |
| RAM | 32 GB |
| Storage | 200 GB NVMe SSD |
| OS | Linux (Ubuntu 22.04 LTS) |

### Memory Analysis Requirements

For analyzing memory dumps:

| Dump Size | RAM Required |
|-----------|-------------|
| 4 GB | 8 GB |
| 8 GB | 16 GB |
| 16 GB | 32 GB |
| 32 GB | 64 GB |
| 64 GB | 128 GB |

## Installation

### Option 1: Native Installation

#### Step 1: System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git build-essential \
    libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev \
    libjpeg-dev libyaml-dev

# For YARA support
sudo apt install -y libyara-dev

# For Volatility 3 symbol tables
sudo apt install -y wget
```

**CentOS/RHEL/Fedora:**
```bash
sudo dnf install -y python3 python3-pip python3-virtualenv git gcc \
    openssl-devel libffi-devel libxml2-devel libxslt-devel zlib-devel \
    libjpeg-devel libyaml-devel

# For YARA support
sudo dnf install -y yara-devel
```

**macOS:**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

brew install python@3.11 git yara
```

**Windows:**
- Install Python 3.11 from https://python.org
- Install Git for Windows
- Install Visual C++ Build Tools
- Install YARA from https://github.com/VirusTotal/yara/releases

#### Step 2: Clone Repository

```bash
git clone https://github.com/your-org/memory-forensics-platform.git
cd memory-forensics-platform
```

#### Step 3: Create Virtual Environment

```bash
python3 -m venv venv

# Activate
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows
```

#### Step 4: Install Python Dependencies

```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

#### Step 5: Install Volatility 3

```bash
pip install volatility3

# Download symbol tables (required for Windows analysis)
python3 -m volatility3.plugins.windows.info
```

#### Step 6: Initialize Database

```bash
python -c "from src.models.database import init_database; init_database()"
```

#### Step 7: Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys and settings
```

### Option 2: Docker Deployment

#### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+

#### Build and Run

```bash
# Build image
docker build -t memory-forensics-platform .

# Run container
docker run -d \
  -p 8501:8501 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/rules:/app/rules \
  --env-file .env \
  --name memory-forensics \
  memory-forensics-platform

# Access at http://localhost:8501
```

#### Docker Compose

```yaml
version: '3.8'

services:
  forensics-platform:
    build: .
    ports:
      - "8501:8501"
    volumes:
      - ./data:/app/data
      - ./rules:/app/rules
      - ./config:/app/config
    env_file:
      - .env
    environment:
      - STREAMLIT_SERVER_PORT=8501
      - STREAMLIT_SERVER_ADDRESS=0.0.0.0
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 16G
        reservations:
          memory: 8G
```

Run with:
```bash
docker-compose up -d
```

### Option 3: Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: memory-forensics-platform
  namespace: forensics
spec:
  replicas: 1
  selector:
    matchLabels:
      app: memory-forensics
  template:
    metadata:
      labels:
        app: memory-forensics
    spec:
      containers:
      - name: forensics
        image: memory-forensics-platform:latest
        ports:
        - containerPort: 8501
        envFrom:
        - secretRef:
            name: forensics-secrets
        resources:
          requests:
            memory: "8Gi"
            cpu: "4"
          limits:
            memory: "32Gi"
            cpu: "8"
        volumeMounts:
        - name: data-storage
          mountPath: /app/data
        - name: rules-storage
          mountPath: /app/rules
      volumes:
      - name: data-storage
        persistentVolumeClaim:
          claimName: forensics-data-pvc
      - name: rules-storage
        persistentVolumeClaim:
          claimName: forensics-rules-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: memory-forensics-service
  namespace: forensics
spec:
  selector:
    app: memory-forensics
  ports:
  - port: 80
    targetPort: 8501
  type: ClusterIP
```

## Configuration

### Environment Variables

Create a `.env` file:

```bash
# API Keys (optional - for threat intelligence)
VT_API_KEY=your_virustotal_api_key
MISP_URL=https://your-misp-instance.com
MISP_API_KEY=your_misp_api_key
OTX_API_KEY=your_otx_api_key

# Platform Settings
LOG_LEVEL=INFO
MAX_FILE_SIZE_GB=64
ANALYSIS_TIMEOUT=3600
MAX_WORKERS=4

# Database
DATABASE_PATH=data/forensics.db

# Streamlit
STREAMLIT_SERVER_PORT=8501
STREAMLIT_SERVER_ADDRESS=0.0.0.0
STREAMLIT_SERVER_HEADLESS=true

# Security
ENABLE_AUTHENTICATION=false
ADMIN_PASSWORD=changeme
SECRET_KEY=your-secret-key-here
```

### YARA Rules Setup

```bash
# Create rules directory
mkdir -p rules/yara

# Download common YARA rules
cd rules/yara

# YARA-Rules project
git clone https://github.com/YARA-Rules/rules.git yara-rules

# ReversingLabs rules
git clone https://github.com/reversinglabs-research/rl-yara-rules.git

# Go back to project root
cd ../..
```

### Volatility 3 Symbol Tables

```bash
# Automatic download
python3 -c "
import volatility3.plugins
import volatility3.symbols
volatility3.symbols.symbol_cache.SymbolCache()
"

# Or download manually
wget https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip -P data/symbols/
wget https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip -P data/symbols/
wget https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip -P data/symbols/
```

## Running the Platform

### Development Mode

```bash
# Activate virtual environment
source venv/bin/activate

# Run Streamlit with auto-reload
streamlit run app.py --server.runOnSave true
```

### Production Mode

```bash
# Run with production settings
streamlit run app.py \
  --server.port 8501 \
  --server.address 0.0.0.0 \
  --server.headless true \
  --server.enableCORS false \
  --server.enableXsrfProtection true
```

### Systemd Service (Linux)

Create `/etc/systemd/system/memory-forensics.service`:

```ini
[Unit]
Description=Enterprise Memory Forensics Platform
After=network.target

[Service]
Type=simple
User=forensics
Group=forensics
WorkingDirectory=/opt/memory-forensics-platform
Environment=PATH=/opt/memory-forensics-platform/venv/bin
Environment=PYTHONPATH=/opt/memory-forensics-platform
ExecStart=/opt/memory-forensics-platform/venv/bin/streamlit run app.py --server.port 8501 --server.address 0.0.0.0
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable memory-forensics
sudo systemctl start memory-forensics

# Check status
sudo systemctl status memory-forensics
```

### Nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name forensics.example.com;
    
    location / {
        proxy_pass http://localhost:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    }
    
    client_max_body_size 128G;
    proxy_read_timeout 3600;
    proxy_connect_timeout 3600;
    proxy_send_timeout 3600;
}
```

## Security Considerations

### Network Security

- Run behind a reverse proxy (Nginx/Apache)
- Use HTTPS with valid certificates
- Restrict access with firewall rules
- Consider VPN access for sensitive environments

### Authentication

Enable basic authentication:

```python
# .streamlit/config.toml
[server]
enableXsrfProtection = true
enableCORS = false

[browser]
gatherUsageStats = false
```

### File Upload Security

- Uploaded files are stored in `data/memory_dumps/`
- Files are hashed (SHA256) for integrity
- Maximum file size is configurable (default 64GB)
- Files should be cleaned up after analysis

### API Key Security

- Store API keys in environment variables
- Use secret management systems in production
- Rotate keys regularly
- Monitor API usage for abuse

## Troubleshooting

### Common Issues

#### Volatility 3 Not Found

```bash
# Verify installation
python -m volatility3 --help

# If not found, reinstall
pip install --force-reinstall volatility3
```

#### YARA Not Available

```bash
# Linux
sudo apt install yara libyara-dev
pip install yara-python

# macOS
brew install yara
pip install yara-python

# Windows: Download from GitHub releases
```

#### Memory Issues with Large Dumps

```bash
# Increase swap space
sudo fallocate -l 32G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile

# Or limit analysis chunk size
export VOLATILITY_MAX_SIZE=8589934592  # 8GB chunks
```

#### Database Locked

```bash
# Remove lock file
rm data/forensics.db-journal

# Or reinitialize
rm data/forensics.db
python -c "from src.models.database import init_database; init_database()"
```

### Performance Optimization

#### For Large Memory Dumps (32GB+)

1. Use SSD storage for temporary files
2. Increase RAM or add swap
3. Reduce parallel workers
4. Use chunked analysis

#### Parallel Processing

Adjust worker count in `config/settings.py`:

```python
MAX_WORKERS = 4  # Reduce for memory-constrained systems
```

#### Caching

Enable result caching to avoid re-analysis:

```bash
# Cache directory is automatically created at data/cache/
# Cache TTL is 1 hour by default
# Adjust in config/settings.py
```

### Log Locations

| Log Type | Location |
|----------|----------|
| Application logs | `data/logs/app.log` |
| Analysis logs | `data/logs/analysis.log` |
| Error logs | `data/logs/errors.log` |
| Access logs | Streamlit console output |

### Getting Help

1. Check logs: `tail -f data/logs/*.log`
2. Enable debug mode: `LOG_LEVEL=DEBUG`
3. Review documentation in `docs/`
4. Submit issues on GitHub

## Upgrade Procedures

### Minor Updates

```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

### Major Updates

```bash
# Backup data
cp -r data data-backup-$(date +%Y%m%d)

# Pull updates
git fetch origin
git checkout main

# Update dependencies
pip install -r requirements.txt --force-reinstall

# Migrate database if needed
python scripts/migrate_db.py

# Restart service
sudo systemctl restart memory-forensics
```

## Monitoring

### Health Check Endpoint

Add to your monitoring system:

```bash
# Streamlit health check
curl -f http://localhost:8501/_stcore/health || exit 1
```

### Metrics to Monitor

- Memory usage during analysis
- Disk space in `data/` directory
- Analysis completion rate
- Error rate in logs
- API rate limit usage (VT, MISP, OTX)

## Backup and Recovery

### Backup Strategy

```bash
# Daily backup script
#!/bin/bash
BACKUP_DIR="/backups/memory-forensics"
DATE=$(date +%Y%m%d)

# Backup database
cp data/forensics.db "$BACKUP_DIR/forensics-$DATE.db"

# Backup reports
tar czf "$BACKUP_DIR/reports-$DATE.tar.gz" data/reports/

# Backup IOCs
tar czf "$BACKUP_DIR/iocs-$DATE.tar.gz" data/iocs/

# Keep only last 30 days
find "$BACKUP_DIR" -mtime +30 -delete
```

### Recovery

```bash
# Restore from backup
cp /backups/memory-forensics/forensics-20240115.db data/forensics.db

# Restore reports
tar xzf /backups/memory-forensics/reports-20240115.tar.gz
```

## Support

For additional support:
- Documentation: `/docs`
- Issue Tracker: GitHub Issues
- Email: security-operations@example.com