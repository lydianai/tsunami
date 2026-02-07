# Deployment & Debugging Guide

## Development Environment Setup

### Prerequisites

```bash
# Python 3.9+
python --version

# Virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### requirements.txt

```
Flask==3.0.0
flask-socketio==5.3.5
python-socketio==5.9.0
python-engineio==4.7.1
flask-cors==4.0.0
aiohttp==3.9.1
asyncio==3.4.3
python-dotenv==1.0.0
redis==5.0.1
requests==2.31.0
gunicorn==21.2.0
gevent==23.9.1
gevent-websocket==0.10.1
```

### .env Configuration

```bash
# Flask
FLASK_ENV=development
FLASK_APP=app.py
SECRET_KEY=your-super-secret-key-change-in-production

# External APIs
GOOGLE_MAPS_API_KEY=your_google_api_key
MAPILLARY_ACCESS_TOKEN=your_mapillary_token
WIGLE_USERNAME=your_wigle_username
WIGLE_API_KEY=your_wigle_api_key
OPENCELLID_API_KEY=your_opencellid_key

# Server
REDIS_HOST=localhost
REDIS_PORT=6379
SOCKETIO_MESSAGE_QUEUE=redis://localhost:6379
CORS_ORIGINS=http://localhost:3000,http://localhost:5000

# Logging
LOG_LEVEL=INFO
```

## Running Locally

### Terminal 1: Redis

```bash
redis-server --port 6379
```

### Terminal 2: Flask Development

```bash
# With debug reloading
FLASK_ENV=development flask run --host 0.0.0.0 --port 5000

# Or with Gunicorn (production-like)
gunicorn -w 1 --worker-class socketio.sanic_app.Worker \
  -b 0.0.0.0:5000 --timeout 120 app:create_app()
```

### Terminal 3: Scanning Agent (Optional)

```bash
python -m app.agents.scanner
```

### Terminal 4: Frontend Development (if separate)

```bash
python -m http.server 3000
# Or with live reload
python -m livereload -o index.html
```

## Common Issues & Solutions

### Issue 1: SocketIO Connection Failures

**Symptoms:**
- WebSocket handshake errors
- "Cannot GET /socket.io/?EIO=4..."

**Solutions:**

```python
# Ensure SocketIO is properly configured
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode='threading',  # or 'gevent'
    logger=True,
    engineio_logger=True
)

# Check CORS headers
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    return response
```

**Debug:**
```bash
# Check if server is running
curl http://localhost:5000/socket.io/?EIO=4&transport=polling

# Check network tab in browser DevTools
# Verify CORS headers are present
```

### Issue 2: Async Tasks Not Running

**Symptoms:**
- Background tasks complete immediately
- Results not being updated

**Solution:**

```python
# Use proper task queue for background work
from celery import Celery

celery = Celery(app.name, broker='redis://localhost:6379')

@celery.task
def run_port_scan(target, ports):
    """Background task"""
    result = asyncio.run(PortScanner.scan(target, ports))
    # Emit result via SocketIO
    socketio.emit('scan_complete', result, broadcast=True)

# Call from route
@app.route('/api/scan', methods=['POST'])
def create_scan():
    data = request.json
    run_port_scan.delay(data['target'], data['ports'])
    return jsonify({'status': 'queued'})
```

### Issue 3: API Key Rate Limiting

**Symptoms:**
- 429 Too Many Requests errors
- Intermittent API failures

**Solution:**

```python
from functools import wraps
from time import time
import redis

cache = redis.Redis(host='localhost', port=6379)

def rate_limit(calls_per_minute=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            key = f"rate_limit:{f.__name__}:{request.remote_addr}"
            count = cache.incr(key)

            if count == 1:
                cache.expire(key, 60)

            if count > calls_per_minute:
                return jsonify({'error': 'Rate limited'}), 429

            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/api/scan', methods=['POST'])
@rate_limit(calls_per_minute=10)
def create_scan():
    # Implementation
    pass
```

### Issue 4: Memory Leaks in Async Code

**Symptoms:**
- Memory usage grows indefinitely
- Server becomes slower over time

**Solution:**

```python
# Properly clean up resources
async def execute_scan(task):
    try:
        result = await PortScanner.scan(task.target, task.ports)
        return result
    finally:
        # Cleanup
        gc.collect()

# Monitor memory
import psutil

def get_memory_usage():
    process = psutil.Process(os.getpid())
    return process.memory_info().rss / 1024 / 1024  # MB

# Periodic cleanup
async def cleanup_loop():
    while True:
        await asyncio.sleep(3600)  # Every hour
        gc.collect()
```

### Issue 5: Street View API Not Responding

**Symptoms:**
- Street View metadata requests timeout
- 403 Forbidden errors

**Solution:**

```python
# Verify API key
# 1. Check if API key is valid
# 2. Verify Street View API is enabled in Google Cloud Console
# 3. Check IP restriction settings
# 4. Implement retry logic

import backoff

@backoff.on_exception(
    backoff.expo,
    requests.exceptions.RequestException,
    max_tries=3
)
def get_streetview_metadata(lat, lng):
    """Auto-retry on failure"""
    params = {
        'location': f'{lat},{lng}',
        'key': GOOGLE_MAPS_API_KEY
    }
    response = requests.get(
        'https://maps.googleapis.com/maps/api/streetview/metadata',
        params=params,
        timeout=5
    )
    return response.json()
```

## Debugging Techniques

### 1. Logging

```python
import logging
import json_log_formatter

# JSON logging for production
formatter = json_log_formatter.JSONFormatter()
handler = logging.FileHandler('app.log')
handler.setFormatter(formatter)

logger = logging.getLogger()
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

# Use in code
logger.info('Scan started', extra={
    'target': target,
    'scan_id': scan_id,
    'user': request.remote_addr
})
```

### 2. Profiling Performance

```python
from functools import wraps
import time

def timing_decorator(f):
    @wraps(f)
    async def wrapper(*args, **kwargs):
        start = time.time()
        result = await f(*args, **kwargs)
        duration = time.time() - start
        logger.info(f"{f.__name__} took {duration:.2f}s")
        return result
    return wrapper

@timing_decorator
async def port_scan(target, ports):
    # Implementation
    pass
```

### 3. Remote Debugging with PyCharm

```bash
# Install pydevd
pip install pydevd-pycharm

# In your code
import pydevd_pycharm
pydevd_pycharm.settrace('localhost', port=5678, stdoutToServer=True, stderrToServer=True)
```

### 4. Health Checks

```python
@app.route('/health', methods=['GET'])
def health_check():
    """Comprehensive health check"""
    checks = {
        'status': 'healthy',
        'redis': check_redis(),
        'apis': check_external_apis(),
        'agents': len(AGENT_REGISTRY),
        'active_scans': len(active_scans),
        'memory_mb': psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
    }

    overall = 'healthy' if all(c for c in checks.values() if isinstance(c, bool)) else 'degraded'
    checks['status'] = overall

    return jsonify(checks), 200 if overall == 'healthy' else 503

def check_redis():
    try:
        redis_client.ping()
        return True
    except:
        return False

def check_external_apis():
    """Check critical API endpoints"""
    try:
        requests.head('https://api.wigle.net', timeout=2)
        return True
    except:
        return False
```

## Production Deployment

### 1. Systemd Service

```ini
# /etc/systemd/system/cybersecurity-dashboard.service
[Unit]
Description=Cybersecurity Dashboard
After=network.target redis.service

[Service]
Type=notify
User=dashboard
WorkingDirectory=/opt/cybersecurity-dashboard
ExecStart=/opt/cybersecurity-dashboard/venv/bin/gunicorn \
    -w 4 \
    --worker-class socketio.sanic_app.Worker \
    -b 0.0.0.0:5000 \
    --timeout 120 \
    --access-logfile /var/log/cybersecurity-dashboard/access.log \
    --error-logfile /var/log/cybersecurity-dashboard/error.log \
    app:create_app()

Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl enable cybersecurity-dashboard
sudo systemctl start cybersecurity-dashboard
sudo systemctl status cybersecurity-dashboard
```

### 2. NGINX Reverse Proxy with SSL

```nginx
upstream flask_backend {
    server localhost:5000;
}

server {
    listen 80;
    server_name api.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/cybersecurity_access.log;
    error_log /var/log/nginx/cybersecurity_error.log;

    location / {
        proxy_pass http://flask_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
```

### 3. Monitoring & Alerting

```python
# Prometheus metrics
from prometheus_client import Counter, Histogram, generate_latest
import time

scan_counter = Counter('scans_total', 'Total scans', ['scan_type'])
scan_duration = Histogram('scan_duration_seconds', 'Scan duration', ['scan_type'])
threats_detected = Counter('threats_detected_total', 'Threats found', ['severity'])

@app.route('/metrics', methods=['GET'])
def metrics():
    return generate_latest()

# Usage
with scan_duration.labels(scan_type='port_scan').time():
    await PortScanner.scan(target, ports)

scan_counter.labels(scan_type='port_scan').inc()
threats_detected.labels(severity='critical').inc(len(critical_threats))
```

### 4. Backup Strategy

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backups/cybersecurity-dashboard"
DATE=$(date +%Y%m%d_%H%M%S)

# Redis backup
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb $BACKUP_DIR/redis_$DATE.rdb

# Database backup
pg_dump cybersecurity_db > $BACKUP_DIR/database_$DATE.sql

# Configuration backup
tar -czf $BACKUP_DIR/config_$DATE.tar.gz /etc/cybersecurity-dashboard

# Clean old backups (keep 30 days)
find $BACKUP_DIR -type f -mtime +30 -delete

# Upload to S3
aws s3 cp $BACKUP_DIR s3://backups-bucket/cybersecurity/ --recursive
```

## Security Hardening

### 1. API Key Management

```python
# Never commit keys to git
import os
from dotenv import load_dotenv

load_dotenv()

# Use environment variables
GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')

# Or use secret manager
from google.cloud import secretmanager

def access_secret_version(secret_id, version_id='latest'):
    client = secretmanager.SecretManagerServiceClient()
    project_id = os.getenv('GCP_PROJECT_ID')
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")
```

### 2. Input Validation

```python
from pydantic import BaseModel, validator

class ScanRequest(BaseModel):
    target: str
    scan_types: List[str]

    @validator('target')
    def validate_target(cls, v):
        # Prevent SSRF attacks
        if v in ['127.0.0.1', 'localhost', '192.168.0.1']:
            raise ValueError('Invalid target')
        return v

    @validator('scan_types')
    def validate_scan_types(cls, v):
        allowed = ['port_scan', 'ssl_check', 'header_analysis']
        if not all(t in allowed for t in v):
            raise ValueError('Invalid scan type')
        return v

@app.route('/api/scan', methods=['POST'])
def create_scan():
    try:
        req = ScanRequest(**request.json)
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400
```

### 3. Rate Limiting & DDoS Protection

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/scan', methods=['POST'])
@limiter.limit("10 per minute")
def create_scan():
    # Implementation
    pass
```

## Performance Optimization

### 1. Caching Strategy

```python
from flask_caching import Cache

cache = Cache(app, config={'CACHE_TYPE': 'redis'})

@app.route('/api/scans', methods=['GET'])
@cache.cached(timeout=60)
def get_scans():
    return jsonify(get_all_scans())

# Invalidate cache when needed
@app.route('/api/scan', methods=['POST'])
def create_scan():
    # Create scan
    cache.delete('get_scans')
    return jsonify({'status': 'created'})
```

### 2. Database Connection Pooling

```python
from sqlalchemy.pool import QueuePool

db_uri = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'poolclass': QueuePool,
    'pool_size': 10,
    'pool_recycle': 3600,
    'pool_pre_ping': True,
}
```

### 3. Async Query Execution

```python
async def fetch_scans():
    """Non-blocking database query"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: db.session.query(Scan).limit(100).all()
    )
```

## File Locations

- Implementation files:
  - `/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR/dalga/IMPLEMENTATION_RESEARCH.md`
  - `/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR/dalga/COMPLETE_API_INTEGRATION.md`
  - `/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR/dalga/streetview_leaflet_example.py`
  - `/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR/dalga/cybersecurity_agent_core.py`
  - `/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR/dalga/geolocation_wigle_opencellid.py`

