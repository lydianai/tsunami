# Advanced Integration Implementation - Quick Reference

## Overview

This directory contains comprehensive implementation guides and working code examples for three advanced technical integrations:

1. **Google Street View / 3D Map Integration with Leaflet**
2. **Autonomous Agent System for Cybersecurity Dashboard**
3. **Real WiFi/Bluetooth Geolocation (WiGLE + OpenCellID)**

All components are designed for production use with Flask/Python backend and JavaScript frontend.

## File Structure

### Documentation Files

| File | Purpose | Content |
|------|---------|---------|
| `IMPLEMENTATION_RESEARCH.md` | Comprehensive technical guide | Street View, agent systems, geolocation theory and best practices |
| `COMPLETE_API_INTEGRATION.md` | Flask + JavaScript integration | Backend patterns, SocketIO setup, REST API, frontend integration |
| `DEPLOYMENT_AND_DEBUGGING.md` | Production deployment | Docker, systemd, NGINX, debugging, security hardening |

### Code Examples

| File | Purpose | Technology |
|------|---------|------------|
| `streetview_leaflet_example.py` | Street View backend | Flask, caching, Google Maps API |
| `cybersecurity_agent_core.py` | Autonomous scanning agents | Python asyncio, threat detection patterns |
| `geolocation_wigle_opencellid.py` | WiFi/cell geolocation | Async API clients, triangulation algorithms |

## Quick Start

### Part 1: Street View Integration

**Objective**: Display interactive Street View on Leaflet maps

**Files to Review**:
1. `IMPLEMENTATION_RESEARCH.md` → Section 1 (Street View)
2. `streetview_leaflet_example.py` (Flask backend)
3. `COMPLETE_API_INTEGRATION.md` → Section 2.3 (Map Integration)

**Key Components**:
- Leaflet-Pegman plugin for drag-and-drop Street View
- Google Street View API with coordinate-based viewing
- Mapillary as open-source alternative
- Click-to-open modal viewers

**Setup**:
```bash
# Dependencies
npm install leaflet leaflet-pegman interact

# Python backend
pip install flask requests aiohttp

# Get API key
# https://console.cloud.google.com/ → Maps JavaScript API + Street View API
```

**Integration Pattern**:
```javascript
// Frontend - Display Street View on map click
const panorama = new google.maps.StreetViewPanorama(container, {
    position: { lat, lng },
    pov: { heading: 0, pitch: 0 }
});

// Backend - Cache metadata to reduce API calls
@app.route('/api/streetview/metadata', methods=['POST'])
def get_streetview_metadata():
    cached = sv_cache.get(f"sv:{lat},{lng}")
    if cached: return cached
    # Fetch from API, cache for 2 hours
```

---

### Part 2: Autonomous Cybersecurity Agents

**Objective**: Event-driven scanning system with real-time threat detection

**Files to Review**:
1. `IMPLEMENTATION_RESEARCH.md` → Section 2 (Autonomous Agents)
2. `cybersecurity_agent_core.py` (scanning implementation)
3. `COMPLETE_API_INTEGRATION.md` → Section 1 (Flask SocketIO)

**Key Components**:
- Async scanning agents (port scan, SSL check, header analysis)
- Pattern-based threat detection (regex matching)
- Real-time WebSocket updates via Flask-SocketIO
- Self-managing agent registration and heartbeats
- Concurrent task processing with asyncio

**Threat Database**:
- SSL expired certificates
- Weak cipher suites
- Default credentials
- SQL injection patterns
- Header injection vulnerabilities

**Setup**:
```bash
pip install flask-socketio python-socketio asyncio aiohttp

# Architecture
Client → WebSocket → Flask-SocketIO → Agent Registry → Scanning Agents
                     ↓
              Threat Detection Engine → Database
```

**Key Pattern**:
```python
# Agent execution loop
async def run():
    await asyncio.gather(
        _heartbeat_loop(),      # Status updates every 30s
        _task_processor_loop(), # Process queued tasks
        _threat_monitor_loop()  # Check for critical threats
    )

# Threat detection
threats = ThreatDetectionEngine.detect_threats(findings)
# Matches findings JSON against 10+ threat signatures
```

**Real-Time Updates**:
```python
@socketio.on('scan_result')
def handle_scan_result(data):
    # Broadcast to all dashboards
    emit('scan_update', data, broadcast=True)

    # Alert on critical threats
    if any(t['severity'] == 'critical' for t in data['threats']):
        emit('critical_threat_alert', {...}, broadcast=True)
```

---

### Part 3: WiFi/Cell Geolocation

**Objective**: Triangulate location from WiFi BSSIDs and cell towers

**Files to Review**:
1. `IMPLEMENTATION_RESEARCH.md` → Section 3 (Geolocation)
2. `geolocation_wigle_opencellid.py` (async clients + triangulation)
3. `COMPLETE_API_INTEGRATION.md` → Section 2.3 (Map Integration)

**Key Components**:
- WiGLE API for WiFi network lookup
- OpenCellID for cell tower geolocation
- Weighted triangulation algorithms
- Hybrid multi-source location estimation
- Accuracy metrics and confidence scoring

**Data Sources**:
| Source | Accuracy | Coverage | API |
|--------|----------|----------|-----|
| WiFi (WiGLE) | 50-100m | Global | wigle.net |
| Cell Towers | 500m-1km | Global | opencellid.org |
| Hybrid | 50-200m | Global | Combined |

**Triangulation Algorithm**:
```python
# WiFi: Weighted by signal strength squared
position = sum(lat/lng * signal²) / sum(signal²)

# Cells: Weighted by accuracy inverse
position = sum(lat/lng * (1/accuracy)) / sum(1/accuracy)

# Hybrid: Confidence-weighted average of both
```

**Setup**:
```bash
pip install aiohttp redis

# Register for APIs
# WiGLE: https://wigle.net/signup
# OpenCellID: https://opencellid.org/
```

**Usage Pattern**:
```python
# Async geolocation
result = await geo_system.locate_hybrid(
    bssids=['AA:BB:CC:DD:EE:FF'],
    towers=[CellTower(mcc=310, mnc=410, lac=123, cid=456)]
)

# Returns: lat, lng, accuracy_m, confidence, sources
```

---

## Architecture Diagrams

### Street View Integration
```
Browser (Leaflet Map)
    ↓ Click marker
    ↓ GET /api/streetview/metadata?lat=40.71&lng=-74.00
Flask Backend
    ↓ Check Redis cache
    ↓ If miss: Call Google Street View API
    ↓ Cache result (2 hours TTL)
    ↓ Return metadata + pano_id
JavaScript
    ↓ Render StreetViewPanorama in modal
    ↓ User can view 360° imagery
```

### Cybersecurity Agent System
```
Dashboard (Browser)
    ↓ "Create Scan"
    ↓ POST /api/scan {target, scan_types}
Flask HTTP Handler
    ↓ Create task, broadcast to agents
    ↓ redis.setex("task:xxx", 3600, data)
WebSocket Broadcast
    ↓
Scanning Agents (Multiple)
    ↓ Receive task on socket
    ↓ Process: Port scan + SSL check + Header analysis
    ↓ Match findings against threat signatures
    ↓ Emit 'scan_result' with threats
SocketIO Server
    ↓ Broadcast to all connected dashboards
    ↓ Store in Redis (24h TTL)
Dashboard
    ↓ Display results + threats in real-time
```

### WiFi/Cell Geolocation
```
Mobile App / Browser
    ↓ Collect nearby BSSIDs (WiFi) + cell towers
    ↓ POST /api/geolocation/hybrid {bssids, towers}
Flask HTTP Handler
    ↓
WiGLE Client (Async)
    ↓ search_by_bssid() × N
    ↓ Get: lat, lng, accuracy for each network
    ↓ Triangulate using signal strength weights

OpenCellID Client (Async)
    ↓ search_cell_location() × M
    ↓ Get: lat, lng, accuracy for each tower
    ↓ Triangulate using accuracy inverse weights

Hybrid Engine
    ↓ Combine WiFi result + Cell result
    ↓ Weighted average by confidence
    ↓ Return: final {lat, lng, accuracy_m, confidence}
Frontend
    ↓ Display location circle on Leaflet map
```

---

## API Endpoints

### Street View
```
POST /api/maps/streetview/metadata
  Request: {lat: float, lng: float}
  Response: {status: "OK", pano_id: string, ...}

GET /api/maps/streetview/coverage?lat=40&lng=-74
  Response: {available: bool, pano_id: string}
```

### Cybersecurity
```
POST /api/security/scan/port
  Request: {target: "example.com", ports: [22, 80, 443]}
  Response: {scan_id: uuid, status: "queued"}

GET /api/security/agents
  Response: {agents: [{id, type, status, ...}], count: int}

GET /api/scans
  Response: {scans: [{scan_id, target, threats_detected, ...}]}
```

### Geolocation
```
POST /api/maps/geolocation/wifi
  Request: {bssids: ["AA:BB:CC:DD:EE:FF"]}
  Response: {success: bool, location: {lat, lng, accuracy_m, confidence}}

POST /api/maps/geolocation/hybrid
  Request: {bssids: [...], cell_towers: [{mcc, mnc, lac, cid, signal}]}
  Response: {success: bool, location: {...}, sources: ["WiFi", "Cell"]}
```

---

## Performance Considerations

### Street View
- Cache metadata for 2 hours (saves $0.05 per request)
- Batch requests when possible
- Use static API preview for thumbnails ($1.50/1000 vs $7/1000)

### Agents
- Concurrent scanning: 5-10 agents per backend instance
- Async I/O for networking (minimal CPU overhead)
- Task queue for persistence (Redis or Celery)
- Monitor memory: agents can leak with long-running scans

### Geolocation
- Cache WiFi network lookups (networks don't move frequently)
- Batch multiple BSSIDs per API call
- Rate limit: WiGLE ~100 req/day free tier
- OpenCellID free tier: unlimited (crowd-sourced data)

---

## Security Best Practices

### API Keys
```python
# ❌ Don't commit keys
GOOGLE_API_KEY = "AIzaSyD..."

# ✓ Use environment variables
import os
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY')

# ✓ Use secret manager (production)
from google.cloud import secretmanager
GOOGLE_API_KEY = access_secret_version('google-api-key')
```

### Input Validation
```python
# ✓ Validate all user input
from pydantic import BaseModel

class ScanRequest(BaseModel):
    target: str  # Will be validated
    ports: List[int]

# ✓ Prevent SSRF attacks
if target in ['127.0.0.1', 'localhost', '192.168.x.x']:
    raise ValueError('Invalid target')
```

### Rate Limiting
```python
# ✓ Implement rate limits
from flask_limiter import Limiter

@app.route('/api/scan', methods=['POST'])
@limiter.limit("10 per minute")
def create_scan():
    pass
```

---

## Monitoring & Debugging

### Enable Detailed Logging
```python
logging.basicConfig(level=logging.DEBUG)
socketio = SocketIO(..., logger=True, engineio_logger=True)
```

### Health Check Endpoint
```
GET /health
Response: {status: "healthy", redis: true, agents: 3, memory_mb: 256}
```

### Performance Metrics
```
GET /metrics
Prometheus format: scan_duration_seconds, threats_detected_total, etc.
```

---

## Common Integration Patterns

### Pattern 1: Caching Layer
```python
cache = redis.Redis()

def get_streetview(lat, lng):
    key = f"sv:{lat},{lng}"
    cached = cache.get(key)
    if cached:
        return json.loads(cached)

    result = fetch_from_api()
    cache.setex(key, 7200, json.dumps(result))  # 2 hour TTL
    return result
```

### Pattern 2: Async Background Tasks
```python
@app.route('/api/scan', methods=['POST'])
def create_scan():
    data = request.json
    # Queue task for background processing
    asyncio.create_task(run_scan(data['target']))
    return {'scan_id': uuid.uuid4()}

async def run_scan(target):
    result = await PortScanner.scan(target, [22, 80, 443])
    socketio.emit('scan_complete', result, broadcast=True)
```

### Pattern 3: WebSocket Broadcasting
```python
@socketio.on('scan_result')
def handle_result(data):
    # Emit to all connected clients
    emit('update', data, broadcast=True)

    # Emit to specific room
    emit('update', data, room='dashboards')

    # Emit back to sender only
    emit('ack', {'status': 'received'})
```

---

## Deployment Checklist

- [ ] Environment variables configured (.env file)
- [ ] API keys obtained and whitelisted
- [ ] Redis server running
- [ ] Database migrations applied
- [ ] HTTPS certificates configured
- [ ] Rate limiting enabled
- [ ] Logging aggregation setup
- [ ] Monitoring alerts configured
- [ ] Backup strategy implemented
- [ ] Health checks responding

---

## File Locations

All files are located in:
```
```

### Reference Files
1. **IMPLEMENTATION_RESEARCH.md** (56KB) - Theory + code patterns for all 3 parts
2. **COMPLETE_API_INTEGRATION.md** (31KB) - Full Flask + JS integration guide
3. **DEPLOYMENT_AND_DEBUGGING.md** (14KB) - Production deployment + debugging

### Working Code Examples
1. **streetview_leaflet_example.py** (5KB) - Flask backend for Street View
2. **cybersecurity_agent_core.py** (16KB) - Scanning agents + threat detection
3. **geolocation_wigle_opencellid.py** (19KB) - WiFi/cell triangulation

---

## Next Steps

1. **Choose your integration priority**:
   - Street View? → Start with Part 1
   - Scanning system? → Start with Part 2
   - Geolocation? → Start with Part 3

2. **Review architecture docs** (IMPLEMENTATION_RESEARCH.md)

3. **Set up local development environment**:
   ```bash
   python -m venv venv
   pip install -r requirements.txt
   cp .env.example .env
   ```

4. **Run examples locally** and test with actual data

5. **Deploy to production** using guide in DEPLOYMENT_AND_DEBUGGING.md

---

## Support & References

- [Leaflet Documentation](https://leafletjs.com/reference.html)
- [Google Maps API](https://developers.google.com/maps/documentation)
- [Flask-SocketIO](https://flask-socketio.readthedocs.io/)
- [Python asyncio](https://docs.python.org/3/library/asyncio.html)
- [WiGLE API](https://wigle.net/api)
- [OpenCellID](https://opencellid.org/)

---

## License & Attribution

These implementation guides combine:
- Google Maps API documentation
- WiGLE community data
- OpenCellID public database
- Flask and asyncio best practices
- Production-tested patterns

All code examples provided as educational reference for production integration.
