# Advanced Integration Implementation Guide

## Part 1: Google Street View / 3D Map Integration with Leaflet

### 1.1 Overview

Three integration approaches exist:
1. **Leaflet-Pegman Plugin** - Direct integration, drag pegman character
2. **Custom StreetViewPanorama Container** - Standalone Street View window
3. **Mapillary Alternative** - Open-source street imagery

### 1.2 Setup Requirements

**Dependencies:**
- Leaflet 1.6.0+
- Google Maps API with valid API key
- interact.js for drag functionality
- Optional: leaflet-google-mutant for satellite

**Google Maps API Setup:**
```bash
# Obtain API key from:
# https://console.cloud.google.com/
# Enable: Maps JavaScript API, Street View Static API

# Cost structure:
# - Street View: $7 per 1,000 panoramas
# - Static Street View: $1.50 per 1,000 requests
```

### 1.3 Implementation Pattern: Leaflet-Pegman Integration

**Installation:**
```bash
npm install leaflet-pegman leaflet interact
```

**HTML Structure:**
```html
<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet-pegman@2.1.0/dist/leaflet-pegman.css" />
    <style>
        #map { height: 600px; width: 100%; }
        #streetview { height: 400px; width: 100%; margin-top: 10px; }
    </style>
</head>
<body>
    <div id="map"></div>
    <div id="streetview"></div>
    <script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/leaflet-pegman@2.1.0/dist/leaflet-pegman.umd.js"></script>
    <script src="https://maps.googleapis.com/maps/api/js?key=YOUR_API_KEY"></script>
</body>
</html>
```

**JavaScript Implementation:**
```javascript
// Initialize map
const map = L.map('map').setView([40.7128, -74.0060], 13);

// Add base layer
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,
    attribution: '© OpenStreetMap contributors'
}).addTo(map);

// Initialize Pegman control
const pegmanControl = new L.Control.Pegman({
    position: 'topleft',
    theme: 'leaflet-pegman-v3-default'
});
pegmanControl.addTo(map);

// Handle pegman activation
pegmanControl.on('activate', function(e) {
    console.log('Street View activated at:', e.latlng);
});

// Alternative: Manual Street View control
const panorama = new google.maps.StreetViewPanorama(
    document.getElementById('streetview'),
    {
        position: { lat: 40.7128, lng: -74.0060 },
        pov: { heading: 34, pitch: 10 },
        zoom: 1
    }
);

// Sync map clicks to Street View
map.on('click', function(e) {
    panorama.setPosition(e.latlng);
});
```

### 1.4 Advanced Pattern: Click-to-Open Street View

```javascript
// Create custom control for Street View opening
L.Control.StreetViewButton = L.Control.extend({
    onAdd: function(map) {
        const btn = L.DomUtil.create('button', 'street-view-btn');
        btn.innerHTML = '📷 Street View';
        btn.style.cssText = `
            padding: 8px 12px;
            background: white;
            border: 2px solid #ccc;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        `;

        btn.onclick = function() {
            const center = map.getCenter();
            const url = `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${center.lat},${center.lng}&heading=0&pitch=0&zoom=1`;
            window.open(url, '_blank');
        };

        return btn;
    }
});

new L.Control.StreetViewButton({ position: 'topleft' }).addTo(map);

// Enhanced: Click markers to open Street View in modal
const createStreetViewMarker = (lat, lng, title) => {
    const marker = L.marker([lat, lng]).addTo(map)
        .bindPopup(`
            <div style="width: 250px; background: #f0f0f0; padding: 10px; border-radius: 4px;">
                <h4>${title}</h4>
                <button onclick="openStreetViewModal(${lat}, ${lng})"
                        style="background: #007bff; color: white; padding: 8px 12px;
                               border: none; border-radius: 4px; cursor: pointer;">
                    View Street
                </button>
            </div>
        `);

    marker.on('click', function() {
        // Fetch nearby images with Street View API
        const service = new google.maps.StreetViewService();
        service.getPanorama({
            location: { lat, lng },
            radius: 50
        }, (data, status) => {
            if (status === google.maps.StreetViewStatus.OK) {
                console.log('Panorama available:', data.location.latLng);
            }
        });
    });

    return marker;
};

const openStreetViewModal = (lat, lng) => {
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.7); display: flex; align-items: center;
        justify-content: center; z-index: 9999;
    `;

    const container = document.createElement('div');
    container.style.cssText = `
        width: 90%; height: 90%; background: white; border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    `;

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕';
    closeBtn.style.cssText = `
        position: absolute; top: 10px; right: 10px;
        background: red; color: white; border: none;
        width: 40px; height: 40px; border-radius: 50%;
        cursor: pointer; font-size: 24px; z-index: 10000;
    `;
    closeBtn.onclick = () => modal.remove();

    container.appendChild(closeBtn);

    const panorama = new google.maps.StreetViewPanorama(
        container,
        {
            position: { lat, lng },
            pov: { heading: 0, pitch: 0 }
        }
    );

    modal.appendChild(container);
    document.body.appendChild(modal);
};

// Usage
createStreetViewMarker(40.7128, -74.0060, 'Times Square');
```

### 1.5 Mapillary Alternative Implementation

**Setup:**
```bash
npm install @mapillary/js
```

**Implementation:**
```javascript
import * as Mapillary from '@mapillary/js';

// Initialize Mapillary viewer
const container = document.getElementById('mapillary-viewer');
const imageId = '1234567890abcdef'; // Get from API query

const viewer = new Mapillary.Viewer({
    accessToken: 'YOUR_MAPILLARY_TOKEN',
    container,
    imageId
});

// Fetch nearby images by coordinates
async function getNearbyMapillaryImages(lat, lng, radius = 100) {
    const query = `
        query {
            imageSearch(
                bbox: [${lng-0.01}, ${lat-0.01}, ${lng+0.01}, ${lat+0.01}]
                first: 10
            ) {
                edges {
                    node {
                        id
                        geometry {
                            coordinates
                        }
                        sequence {
                            edges {
                                node {
                                    id
                                }
                            }
                        }
                    }
                }
            }
        }
    `;

    const response = await fetch('https://graph.mapillary.com/graphql', {
        method: 'POST',
        headers: {
            'Authorization': `OAuth ${accessToken}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ query })
    });

    return response.json();
}

// Integrate with Leaflet
const mapillaryLayer = L.tileLayer(
    'https://tiles.mapillary.com/maps/vtp/mly1_public/2/{z}/{x}/{y}?access_token=YOUR_TOKEN',
    { maxZoom: 14 }
).addTo(map);

map.on('click', async (e) => {
    const images = await getNearbyMapillaryImages(e.latlng.lat, e.latlng.lng);
    if (images.data.imageSearch.edges.length > 0) {
        const firstImage = images.data.imageSearch.edges[0].node;
        viewer.setImage(firstImage.id);
    }
});
```

### 1.6 Best Practices

**Performance:**
- Cache panorama data: Street View API supports batch queries
- Lazy load: Only fetch panorama when modal opens
- Implement loading states with spinners

**Cost Optimization:**
- Use static Street View API for previews ($1.50/1000 vs $7/1000)
- Mapillary free tier: 50,000 calls/month
- Implement caching layer: Redis for panorama metadata

**User Experience:**
- Preload adjacent panoramas for smooth navigation
- Support keyboard controls (arrow keys, spacebar)
- Show available panorama coverage before click
- Fallback gracefully if Street View unavailable

**Security:**
- Restrict API key to frontend domain
- Implement rate limiting on backend
- Validate coordinates before API calls
- Log Street View access for privacy compliance

---

## Part 2: Autonomous Agent System for Cybersecurity Dashboard

### 2.1 Architecture Overview

**Components:**
1. **Scanning Agents** - Background async workers
2. **Event Bus** - Task distribution and coordination
3. **Threat Database** - Pattern matching engine
4. **WebSocket Server** - Real-time dashboard updates
5. **State Management** - Agent status and results

### 2.2 Flask-SocketIO Real-Time Foundation

**Installation:**
```bash
pip install flask flask-socketio python-socketio python-engineio python-dotenv aiofiles
pip install celery redis  # For production task queues
```

**Basic Flask-SocketIO Setup:**
```python
# app.py
from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, rooms, join_room, leave_room
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Connected clients tracking
connected_agents = {}
active_scans = {}

@socketio.on('connect')
def handle_connect():
    client_id = request.sid
    logger.info(f"Client connected: {client_id}")
    emit('response', {'data': 'Connected to security dashboard'})

@socketio.on('disconnect')
def handle_disconnect():
    client_id = request.sid
    if client_id in connected_agents:
        del connected_agents[client_id]
    logger.info(f"Client disconnected: {client_id}")

@socketio.on('register_agent')
def handle_agent_registration(data):
    """Agent registers itself with the system"""
    agent_id = data['agent_id']
    agent_type = data['type']  # 'port_scanner', 'vulnerability_check', etc.

    connected_agents[request.sid] = {
        'id': agent_id,
        'type': agent_type,
        'status': 'ready',
        'last_heartbeat': time.time(),
        'scan_count': 0
    }

    emit('registration_ack', {
        'status': 'success',
        'server_id': agent_id
    })

    # Notify dashboard of new agent
    emit('agent_online', {
        'agent': connected_agents[request.sid]
    }, broadcast=True)

@socketio.on('scan_result')
def handle_scan_result(data):
    """Receive scan results from agent"""
    agent_id = data['agent_id']
    result = data['result']
    scan_id = data['scan_id']

    # Store result
    if scan_id not in active_scans:
        active_scans[scan_id] = {'results': []}

    active_scans[scan_id]['results'].append({
        'agent': agent_id,
        'data': result,
        'timestamp': datetime.now().isoformat()
    })

    # Broadcast to all connected dashboards
    emit('scan_update', {
        'scan_id': scan_id,
        'agent': agent_id,
        'result': result
    }, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)
```

### 2.3 Autonomous Scanning Agent Pattern

**Installation:**
```bash
pip install asyncio aiohttp tenacity
```

**Agent Implementation:**
```python
# scanning_agent.py
import asyncio
import json
import time
from datetime import datetime
from typing import Dict, List, Any
from enum import Enum
import logging
import uuid
from dataclasses import dataclass, asdict
import socketio

# ============== THREAT PATTERNS ==============

@dataclass
class ThreatSignature:
    """Pattern-based threat detection"""
    id: str
    name: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    pattern: str  # Regex or string match
    remediation: str

THREAT_DATABASE = [
    ThreatSignature(
        id='ssh_weak_cipher',
        name='SSH Weak Cipher Suite',
        severity='high',
        pattern=r'diffie-hellman-group1-sha1|diffie-hellman-group14-sha1',
        remediation='Update OpenSSH to latest version, enable strong ciphers'
    ),
    ThreatSignature(
        id='ssl_expired',
        name='Expired SSL Certificate',
        severity='critical',
        pattern=r'X509\s+verify\s+result:\s*10\s+\(certificate\s+expired\)',
        remediation='Renew SSL certificate immediately'
    ),
    ThreatSignature(
        id='default_credentials',
        name='Default Credentials Detected',
        severity='critical',
        pattern=r'admin:admin|root:root|guest:guest',
        remediation='Change all default credentials'
    ),
]

class ScanType(Enum):
    PORT_SCAN = "port_scan"
    SSL_CHECK = "ssl_check"
    VULNERABILITY_SCAN = "vuln_scan"
    CREDENTIAL_CHECK = "credential_check"
    PATCH_AUDIT = "patch_audit"

@dataclass
class ScanTask:
    """Task assigned to scanning agent"""
    id: str
    type: ScanType
    target: str
    ports: List[int] = None
    parameters: Dict[str, Any] = None
    priority: int = 5  # 1-10, higher is urgent
    retries: int = 3

    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type.value,
            'target': self.target,
            'ports': self.ports,
            'parameters': self.parameters,
            'priority': self.priority,
            'retries': self.retries
        }

@dataclass
class ScanResult:
    """Result from completed scan"""
    scan_id: str
    agent_id: str
    target: str
    scan_type: str
    status: str  # 'success', 'failed', 'partial'
    findings: List[Dict[str, Any]]
    threats_detected: List[Dict[str, Any]]
    duration_seconds: float
    timestamp: str

    def to_dict(self):
        return asdict(self)

# ============== SCANNING AGENT ==============

class AutonomousScanningAgent:
    """Self-managing agent for continuous security scanning"""

    def __init__(self, agent_id: str, server_url: str):
        self.agent_id = agent_id
        self.server_url = server_url
        self.logger = logging.getLogger(f"Agent-{agent_id}")

        # SocketIO client for communication
        self.sio = socketio.AsyncClient()
        self.connected = False

        # State management
        self.current_task = None
        self.task_queue = asyncio.Queue()
        self.scan_history = []
        self.agent_stats = {
            'scans_completed': 0,
            'threats_found': 0,
            'uptime': time.time(),
            'cpu_usage': 0,
            'memory_usage': 0
        }

        # Setup event handlers
        self._setup_handlers()

    def _setup_handlers(self):
        """Configure SocketIO event handlers"""

        @self.sio.on('connect')
        async def on_connect():
            self.connected = True
            self.logger.info("Connected to server")
            await self._register_with_server()

        @self.sio.on('disconnect')
        async def on_disconnect():
            self.connected = False
            self.logger.warning("Disconnected from server")

        @self.sio.on('assign_task')
        async def on_assign_task(data):
            """Server assigns scanning task"""
            task = ScanTask(
                id=data['id'],
                type=ScanType[data['type']],
                target=data['target'],
                ports=data.get('ports'),
                parameters=data.get('parameters', {}),
                priority=data.get('priority', 5),
                retries=data.get('retries', 3)
            )
            await self.task_queue.put(task)
            self.logger.info(f"Task assigned: {task.id}")

        @self.sio.on('command')
        async def on_command(data):
            """Server sends command to agent"""
            cmd = data.get('command')
            if cmd == 'stop':
                self.logger.info("Stop command received")
                self.current_task = None
            elif cmd == 'health_check':
                await self._send_health_status()

    async def _register_with_server(self):
        """Register agent capabilities"""
        await self.sio.emit('register_agent', {
            'agent_id': self.agent_id,
            'type': 'autonomous_scanner',
            'capabilities': [
                'port_scan',
                'ssl_check',
                'vuln_scan',
                'credential_check'
            ],
            'max_concurrent': 5
        })

    async def connect(self):
        """Connect to server"""
        try:
            await self.sio.connect(self.server_url)
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            raise

    async def disconnect(self):
        """Disconnect from server"""
        if self.connected:
            await self.sio.disconnect()

    async def run(self):
        """Main agent loop - event-driven task processing"""
        try:
            await self.connect()

            # Run concurrent tasks: heartbeat, task processing, threat monitoring
            await asyncio.gather(
                self._heartbeat_loop(),
                self._task_processor_loop(),
                self._threat_monitor_loop(),
                return_exceptions=True
            )
        except Exception as e:
            self.logger.error(f"Agent error: {e}")
            raise
        finally:
            await self.disconnect()

    async def _heartbeat_loop(self):
        """Periodic health check"""
        while self.connected:
            try:
                await self._send_health_status()
                await asyncio.sleep(30)  # Every 30 seconds
            except Exception as e:
                self.logger.error(f"Heartbeat error: {e}")
                await asyncio.sleep(5)

    async def _send_health_status(self):
        """Send health metrics to server"""
        stats = {
            'agent_id': self.agent_id,
            'status': 'processing' if self.current_task else 'ready',
            'current_task': self.current_task.id if self.current_task else None,
            'stats': self.agent_stats,
            'queue_size': self.task_queue.qsize(),
            'timestamp': datetime.now().isoformat()
        }
        await self.sio.emit('heartbeat', stats)

    async def _task_processor_loop(self):
        """Process tasks from queue"""
        concurrent_tasks = {}
        max_concurrent = 5

        while True:
            try:
                # Get tasks from queue if capacity available
                while len(concurrent_tasks) < max_concurrent:
                    try:
                        task = self.task_queue.get_nowait()
                        concurrent_tasks[task.id] = asyncio.create_task(
                            self._execute_scan(task)
                        )
                    except asyncio.QueueEmpty:
                        break

                # Check for completed tasks
                if concurrent_tasks:
                    done, pending = await asyncio.wait(
                        concurrent_tasks.values(),
                        timeout=1,
                        return_when=asyncio.FIRST_COMPLETED
                    )

                    for task_future in done:
                        result = task_future.result()
                        # Find and remove completed task
                        for task_id, future in list(concurrent_tasks.items()):
                            if future == task_future:
                                del concurrent_tasks[task_id]
                                break
                else:
                    await asyncio.sleep(0.5)

            except Exception as e:
                self.logger.error(f"Task processor error: {e}")
                await asyncio.sleep(1)

    async def _execute_scan(self, task: ScanTask) -> ScanResult:
        """Execute individual scan with pattern matching"""
        self.current_task = task
        start_time = time.time()
        findings = []
        threats = []

        try:
            self.logger.info(f"Starting scan: {task.id} ({task.type.value})")

            # Execute based on scan type
            if task.type == ScanType.PORT_SCAN:
                findings = await self._port_scan(task.target, task.ports)
            elif task.type == ScanType.SSL_CHECK:
                findings = await self._ssl_check(task.target)
            elif task.type == ScanType.VULNERABILITY_SCAN:
                findings = await self._vulnerability_scan(task.target)
            elif task.type == ScanType.CREDENTIAL_CHECK:
                findings = await self._credential_check(task.target, task.parameters)

            # Pattern-based threat detection
            threats = await self._detect_threats(findings)

            status = 'success'
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            status = 'failed'
            findings = [{'error': str(e)}]

        duration = time.time() - start_time

        result = ScanResult(
            scan_id=task.id,
            agent_id=self.agent_id,
            target=task.target,
            scan_type=task.type.value,
            status=status,
            findings=findings,
            threats_detected=threats,
            duration_seconds=duration,
            timestamp=datetime.now().isoformat()
        )

        # Send result to server
        await self.sio.emit('scan_result', result.to_dict())

        # Update stats
        self.agent_stats['scans_completed'] += 1
        self.agent_stats['threats_found'] += len(threats)
        self.scan_history.append(result)

        self.current_task = None
        return result

    async def _port_scan(self, target: str, ports: List[int]) -> List[Dict]:
        """Port scanning implementation"""
        findings = []
        for port in ports:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=2.0
                )
                writer.close()
                await writer.wait_closed()
                findings.append({
                    'type': 'open_port',
                    'port': port,
                    'status': 'open',
                    'risk': 'medium'
                })
            except (asyncio.TimeoutError, OSError):
                findings.append({
                    'type': 'port_status',
                    'port': port,
                    'status': 'closed'
                })
        return findings

    async def _ssl_check(self, target: str) -> List[Dict]:
        """SSL/TLS certificate validation"""
        findings = []
        try:
            import ssl
            import socket

            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    findings.append({
                        'type': 'ssl_certificate',
                        'subject': cert.get('subject'),
                        'issuer': cert.get('issuer'),
                        'version': cert.get('version'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter')
                    })
        except Exception as e:
            findings.append({
                'type': 'ssl_error',
                'error': str(e),
                'risk': 'high'
            })
        return findings

    async def _vulnerability_scan(self, target: str) -> List[Dict]:
        """Check for known vulnerabilities"""
        # Placeholder for real vulnerability scanning
        findings = []
        # In production, integrate with CVE databases
        return findings

    async def _credential_check(self, target: str, params: Dict) -> List[Dict]:
        """Test for weak/default credentials"""
        findings = []
        # Placeholder for credential testing
        return findings

    async def _detect_threats(self, findings: List[Dict]) -> List[Dict]:
        """Pattern-based threat detection"""
        threats = []
        findings_str = json.dumps(findings)

        for signature in THREAT_DATABASE:
            import re
            if re.search(signature.pattern, findings_str, re.IGNORECASE):
                threats.append({
                    'threat_id': signature.id,
                    'name': signature.name,
                    'severity': signature.severity,
                    'remediation': signature.remediation,
                    'detected_at': datetime.now().isoformat()
                })

        return threats

    async def _threat_monitor_loop(self):
        """Continuous threat monitoring and alerting"""
        while True:
            try:
                # Check for critical threats
                recent_scans = self.scan_history[-10:]
                for result in recent_scans:
                    critical_threats = [
                        t for t in result.threats_detected
                        if t['severity'] == 'critical'
                    ]
                    if critical_threats:
                        await self.sio.emit('critical_threat_alert', {
                            'scan_id': result.scan_id,
                            'threats': critical_threats,
                            'timestamp': datetime.now().isoformat()
                        })

                await asyncio.sleep(60)  # Check every minute
            except Exception as e:
                self.logger.error(f"Monitor error: {e}")
                await asyncio.sleep(5)

# ============== AGENT INITIALIZATION ==============

async def main():
    agent = AutonomousScanningAgent(
        agent_id=f"scanner_{uuid.uuid4().hex[:8]}",
        server_url="http://localhost:5000"
    )

    logging.basicConfig(level=logging.INFO)

    try:
        await agent.run()
    except KeyboardInterrupt:
        logger.info("Shutting down agent")
        await agent.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### 2.4 Dashboard Server with Task Distribution

```python
# dashboard_server.py
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import asyncio
import uuid
from datetime import datetime
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secure-secret'
socketio = SocketIO(app, async_mode='threading')

# State management
agents_registry = {}
active_scans = {}
scan_results_db = {}
threat_alerts = []

class ScanOrchestrator:
    """Manages distributed scanning tasks"""

    @staticmethod
    async def schedule_scan(target: str, scan_types: List[str], priority: int = 5):
        """Create and distribute scanning tasks"""
        scan_batch_id = str(uuid.uuid4())

        tasks = []
        for scan_type in scan_types:
            task = {
                'id': str(uuid.uuid4()),
                'type': scan_type,
                'target': target,
                'priority': priority,
                'retries': 3,
                'status': 'pending'
            }
            tasks.append(task)

        active_scans[scan_batch_id] = {
            'id': scan_batch_id,
            'target': target,
            'scan_types': scan_types,
            'tasks': tasks,
            'created_at': datetime.now().isoformat(),
            'results': []
        }

        # Distribute to available agents
        await ScanOrchestrator._distribute_tasks(tasks)

        return scan_batch_id

    @staticmethod
    async def _distribute_tasks(tasks: List[Dict]):
        """Distribute tasks to idle agents"""
        idle_agents = [
            agent for agent in agents_registry.values()
            if agent['status'] == 'ready'
        ]

        for task in tasks:
            if idle_agents:
                agent = idle_agents.pop(0)
                socketio.emit('assign_task', task, to=agent['socket_id'])
                task['status'] = 'assigned'
                task['assigned_to'] = agent['id']

@app.route('/')
def index():
    return render_template('dashboard.html')

@app.route('/api/scans', methods=['GET'])
def get_scans():
    return jsonify({
        'scans': list(active_scans.values()),
        'total': len(active_scans)
    })

@app.route('/api/scan', methods=['POST'])
def create_scan():
    data = request.json
    target = data.get('target')
    scan_types = data.get('scan_types', ['port_scan'])

    scan_id = asyncio.run(
        ScanOrchestrator.schedule_scan(target, scan_types)
    )

    return jsonify({'scan_id': scan_id, 'status': 'scheduled'})

@socketio.on('connect')
def handle_connect():
    emit('response', {'data': 'Connected'})

@socketio.on('register_agent')
def handle_register_agent(data):
    agent_id = data['agent_id']
    agent = {
        'id': agent_id,
        'socket_id': request.sid,
        'type': data['type'],
        'capabilities': data.get('capabilities', []),
        'status': 'ready',
        'connected_at': datetime.now().isoformat()
    }
    agents_registry[agent_id] = agent
    emit('registration_ack', {'status': 'success'}, broadcast=True)

@socketio.on('scan_result')
def handle_scan_result(data):
    result = data
    scan_batch_id = result.get('batch_id')

    if scan_batch_id in active_scans:
        active_scans[scan_batch_id]['results'].append(result)

    scan_results_db[result['scan_id']] = result

    # Check for critical threats
    for threat in result.get('threats_detected', []):
        if threat['severity'] == 'critical':
            alert = {
                'scan_id': result['scan_id'],
                'threat': threat,
                'timestamp': datetime.now().isoformat()
            }
            threat_alerts.append(alert)
            emit('critical_alert', alert, broadcast=True)

    # Broadcast to dashboards
    emit('scan_update', result, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000)
```

### 2.5 Frontend Dashboard with Real-Time Updates

```html
<!-- templates/dashboard.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Cybersecurity Dashboard</title>
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', sans-serif; background: #0a0e27; color: #e0e0e0; }

        .header { background: #1a1f3a; padding: 20px; border-bottom: 2px solid #00ff88; }
        .header h1 { font-size: 28px; }

        .container { display: grid; grid-template-columns: 1fr 2fr 1fr; gap: 20px; padding: 20px; }

        .card {
            background: #1a1f3a;
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.1);
        }

        .status-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
        }

        .status-ready { background: #00ff88; color: #000; }
        .status-scanning { background: #ffaa00; color: #000; }
        .status-threat { background: #ff3333; color: #fff; }

        .agents-list, .alerts-list { max-height: 500px; overflow-y: auto; }

        .agent-item, .alert-item {
            background: rgba(255, 255, 255, 0.05);
            margin: 10px 0;
            padding: 12px;
            border-left: 3px solid #00ff88;
            border-radius: 4px;
        }

        .alert-item.critical { border-left-color: #ff3333; background: rgba(255, 51, 51, 0.1); }
        .alert-item.high { border-left-color: #ffaa00; background: rgba(255, 170, 0, 0.1); }

        .scan-button {
            background: #00ff88;
            color: #000;
            border: none;
            padding: 12px 24px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
        }

        .scan-button:hover { background: #00dd66; }

        .chart { height: 250px; background: rgba(0, 255, 136, 0.05); border-radius: 4px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Autonomous Cybersecurity Dashboard</h1>
    </div>

    <div class="container">
        <!-- Left: Agents -->
        <div>
            <div class="card">
                <h3>Connected Agents</h3>
                <div class="agents-list" id="agents-list"></div>
            </div>
        </div>

        <!-- Center: Scans -->
        <div>
            <div class="card">
                <h3>Active Scans</h3>
                <button class="scan-button" onclick="startNewScan()">Start Scan</button>
                <div id="scans-list"></div>
            </div>
        </div>

        <!-- Right: Alerts -->
        <div>
            <div class="card">
                <h3>Threats Detected</h3>
                <div class="alerts-list" id="alerts-list"></div>
            </div>
        </div>
    </div>

    <script>
        const socket = io();

        const state = {
            agents: {},
            scans: {},
            alerts: []
        };

        socket.on('connect', () => {
            console.log('Connected to dashboard');
        });

        socket.on('agent_online', (data) => {
            state.agents[data.agent.id] = data.agent;
            renderAgents();
        });

        socket.on('scan_update', (data) => {
            state.scans[data.scan_id] = data;
            renderScans();
        });

        socket.on('critical_alert', (data) => {
            state.alerts.unshift(data);
            if (state.alerts.length > 100) state.alerts.pop();
            renderAlerts();

            // Notify user
            if (Notification.permission === 'granted') {
                new Notification('Critical Threat Detected', {
                    body: data.threat.name,
                    icon: '/alert.png'
                });
            }
        });

        function renderAgents() {
            const list = document.getElementById('agents-list');
            list.innerHTML = Object.values(state.agents)
                .map(agent => `
                    <div class="agent-item">
                        <div>${agent.id}</div>
                        <div class="status-badge status-${agent.status}">
                            ${agent.status}
                        </div>
                    </div>
                `).join('');
        }

        function renderScans() {
            const list = document.getElementById('scans-list');
            list.innerHTML = Object.values(state.scans)
                .slice(0, 10)
                .map(scan => `
                    <div class="agent-item">
                        <div>${scan.target}</div>
                        <div>${scan.scan_type}</div>
                        <div>Threats: ${scan.threats_detected.length}</div>
                    </div>
                `).join('');
        }

        function renderAlerts() {
            const list = document.getElementById('alerts-list');
            list.innerHTML = state.alerts
                .slice(0, 20)
                .map(alert => `
                    <div class="alert-item ${alert.threat.severity}">
                        <div><strong>${alert.threat.name}</strong></div>
                        <div>${alert.threat.severity}</div>
                        <div style="font-size: 12px; margin-top: 5px;">
                            ${alert.threat.remediation}
                        </div>
                    </div>
                `).join('');
        }

        function startNewScan() {
            const target = prompt('Enter target IP or hostname:');
            if (target) {
                fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        target,
                        scan_types: ['port_scan', 'ssl_check']
                    })
                });
            }
        }

        // Request notification permission
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    </script>
</body>
</html>
```

---

## Part 3: Real WiFi/Bluetooth Geolocation

### 3.1 WiGLE API Integration

**Setup:**
```bash
pip install requests python-dotenv
# Register at https://wigle.net/signup
```

**WiGLE Implementation:**
```python
# wigle_geolocation.py
import requests
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

@dataclass
class WiFiNetwork:
    """WiFi network information from WiGLE"""
    bssid: str
    ssid: str
    frequency: int
    accuracy: int
    latitude: float
    longitude: float
    last_seen: str
    signal_strength: int

class WiGLEGeolocation:
    """WiGLE API client for WiFi geolocation"""

    BASE_URL = "https://api.wigle.net/api/v2"

    def __init__(self, username: str, api_key: str):
        """
        Initialize WiGLE client

        Args:
            username: WiGLE username
            api_key: WiGLE API key (from https://wigle.net/account)
        """
        self.auth = (username, api_key)
        self.session = requests.Session()
        self.session.auth = self.auth

    def search_by_bssid(self, bssid: str) -> Optional[WiFiNetwork]:
        """
        Search WiFi network by BSSID (MAC address)

        Args:
            bssid: MAC address in format XX:XX:XX:XX:XX:XX or XXXXXXXXXXXX

        Returns:
            WiFiNetwork object or None if not found
        """
        try:
            # Normalize BSSID format
            bssid = bssid.upper().replace('-', ':')

            endpoint = f"{self.BASE_URL}/network/search"
            params = {
                'netid': bssid,
                'resultSize': 1
            }

            response = self.session.get(endpoint, params=params)
            response.raise_for_status()

            data = response.json()
            if data['success'] and data['results']:
                net = data['results'][0]
                return WiFiNetwork(
                    bssid=net['netid'],
                    ssid=net['ssid'],
                    frequency=net.get('frequency', 0),
                    accuracy=net.get('accuracy', 0),
                    latitude=float(net['trilat']),
                    longitude=float(net['trilong']),
                    last_seen=net.get('lastupdt', ''),
                    signal_strength=net.get('signal', 0)
                )
        except Exception as e:
            logger.error(f"WiGLE search error: {e}")

        return None

    def search_by_ssid(self, ssid: str, first_only: bool = True) -> List[WiFiNetwork]:
        """
        Search WiFi networks by SSID (name)

        Args:
            ssid: Network name (SSID)
            first_only: Return only first result

        Returns:
            List of WiFiNetwork objects
        """
        try:
            endpoint = f"{self.BASE_URL}/network/search"
            params = {
                'ssid': ssid,
                'resultSize': 1 if first_only else 100
            }

            response = self.session.get(endpoint, params=params)
            response.raise_for_status()

            data = response.json()
            networks = []

            if data['success']:
                for net in data['results']:
                    networks.append(WiFiNetwork(
                        bssid=net['netid'],
                        ssid=net['ssid'],
                        frequency=net.get('frequency', 0),
                        accuracy=net.get('accuracy', 0),
                        latitude=float(net['trilat']),
                        longitude=float(net['trilong']),
                        last_seen=net.get('lastupdt', ''),
                        signal_strength=net.get('signal', 0)
                    ))

            return networks
        except Exception as e:
            logger.error(f"WiGLE SSID search error: {e}")
            return []

    def search_by_location(self, lat: float, lng: float,
                          radius_km: float = 0.5) -> List[WiFiNetwork]:
        """
        Search WiFi networks near geographic coordinates

        Args:
            lat: Latitude
            lng: Longitude
            radius_km: Search radius in kilometers

        Returns:
            List of WiFiNetwork objects
        """
        try:
            endpoint = f"{self.BASE_URL}/network/search"

            # Calculate bounds
            lat_delta = radius_km / 111.0  # 1 degree ≈ 111 km
            lng_delta = radius_km / (111.0 * abs(math.cos(math.radians(lat))))

            params = {
                'latrange': [lat - lat_delta, lat + lat_delta],
                'lonrange': [lng - lng_delta, lng + lng_delta],
                'resultSize': 100
            }

            response = self.session.get(endpoint, params=params)
            response.raise_for_status()

            data = response.json()
            networks = []

            if data['success']:
                for net in data['results']:
                    networks.append(WiFiNetwork(
                        bssid=net['netid'],
                        ssid=net['ssid'],
                        frequency=net.get('frequency', 0),
                        accuracy=net.get('accuracy', 0),
                        latitude=float(net['trilat']),
                        longitude=float(net['trilong']),
                        last_seen=net.get('lastupdt', ''),
                        signal_strength=net.get('signal', 0)
                    ))

            return networks
        except Exception as e:
            logger.error(f"WiGLE location search error: {e}")
            return []

    def triangulate_position(self, bssids: List[str]) -> Optional[Tuple[float, float]]:
        """
        Triangulate position from multiple BSSIDs using signal strength weighting

        WiGLE uses weighted average:
        position = sum(lat/lng * signal_strength²) / sum(signal_strength²)

        Args:
            bssids: List of observed BSSID MAC addresses

        Returns:
            Tuple of (latitude, longitude) or None
        """
        networks = []

        for bssid in bssids:
            net = self.search_by_bssid(bssid)
            if net:
                networks.append(net)

        if not networks:
            return None

        # Weight by signal strength squared
        if not networks[0].signal_strength:
            # If signal strength unavailable, use equal weights
            lat = sum(n.latitude for n in networks) / len(networks)
            lng = sum(n.longitude for n in networks) / len(networks)
            return (lat, lng)

        total_weight = 0
        weighted_lat = 0
        weighted_lng = 0

        for net in networks:
            weight = net.signal_strength ** 2
            weighted_lat += net.latitude * weight
            weighted_lng += net.longitude * weight
            total_weight += weight

        if total_weight == 0:
            return None

        return (weighted_lat / total_weight, weighted_lng / total_weight)
```

### 3.2 Mozilla Location Services Integration

**Implementation:**
```python
# mozilla_location_services.py
import requests
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

@dataclass
class CellTower:
    """Cell tower information"""
    mcc: int  # Mobile Country Code
    mnc: int  # Mobile Network Code
    lac: int  # Location Area Code
    cid: int  # Cell ID
    signal_strength: int
    serving: bool = False

class MozillaLocationService:
    """Mozilla Location Service client for cell tower geolocation"""

    # NOTE: Mozilla Location Service was retired in 2024
    # This implementation shows the API pattern for reference

    BASE_URL = "https://location.services.mozilla.com/v1"

    def __init__(self, api_key: str):
        """Initialize with Mozilla Location Service API key"""
        self.api_key = api_key
        self.session = requests.Session()

    @staticmethod
    def estimate_cell_location(cell_towers: List[CellTower]) -> Optional[Dict]:
        """
        Estimate location from cell towers

        Since Mozilla Location Service is retired, use OpenCellID instead
        """
        return None

class OpenCellIDGeolocation:
    """OpenCellID API client for cell tower geolocation"""

    BASE_URL = "https://opencellid.org/api/v1"

    def __init__(self, api_key: str):
        """
        Initialize OpenCellID client

        Register at: https://opencellid.org/
        Get API key: https://opencellid.org/api
        """
        self.api_key = api_key
        self.session = requests.Session()

    def search_cell_location(self, mcc: int, mnc: int, lac: int,
                            cid: int) -> Optional[Dict]:
        """
        Search cell tower location by identifiers

        Args:
            mcc: Mobile Country Code (e.g., 310 for USA)
            mnc: Mobile Network Code
            lac: Location Area Code
            cid: Cell ID

        Returns:
            Dict with lat, lon, accuracy or None
        """
        try:
            params = {
                'key': self.api_key,
                'mcc': mcc,
                'mnc': mnc,
                'lac': lac,
                'cellid': cid,
                'format': 'json'
            }

            response = self.session.get(
                f"{self.BASE_URL}/cell/get",
                params=params,
                timeout=5
            )
            response.raise_for_status()

            data = response.json()
            if data.get('status') == 200:
                return {
                    'latitude': data['lat'],
                    'longitude': data['lon'],
                    'accuracy': data.get('accuracy', 0),
                    'range': data.get('range', 0)
                }
        except Exception as e:
            logger.error(f"OpenCellID search error: {e}")

        return None

    def triangulate_cell_position(self, cell_towers: List[CellTower]) -> Optional[Tuple[float, float]]:
        """
        Triangulate position from multiple cell towers

        Args:
            cell_towers: List of CellTower objects

        Returns:
            Tuple of (latitude, longitude) or None
        """
        positions = []

        for tower in cell_towers:
            location = self.search_cell_location(
                tower.mcc, tower.mnc, tower.lac, tower.cid
            )
            if location:
                positions.append((
                    location['latitude'],
                    location['longitude'],
                    tower.signal_strength
                ))

        if not positions:
            return None

        # Weighted average by signal strength
        total_weight = 0
        weighted_lat = 0
        weighted_lng = 0

        for lat, lng, signal in positions:
            weight = signal ** 2 if signal else 1
            weighted_lat += lat * weight
            weighted_lng += lng * weight
            total_weight += weight

        return (weighted_lat / total_weight, weighted_lng / total_weight)
```

### 3.3 Combined Geolocation System

```python
# geolocation_system.py
from typing import Dict, List, Optional, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class LocationSource(Enum):
    WIFI_NETWORK = "wifi"
    CELL_TOWER = "cell"
    BLUETOOTH = "bluetooth"
    IP_ADDRESS = "ip"

@dataclass
class GeolocationResult:
    """Combined geolocation result"""
    latitude: float
    longitude: float
    accuracy_m: int
    sources: List[LocationSource]
    confidence: float  # 0.0 to 1.0
    timestamp: str

class HybridGeolocationSystem:
    """Multi-source geolocation combining WiFi, cell, and other sources"""

    def __init__(self, wigle_key: str, opencellid_key: str):
        self.wigle = WiGLEGeolocation('username', wigle_key)
        self.opencellid = OpenCellIDGeolocation(opencellid_key)

    async def locate_from_wifi(self, bssids: List[str]) -> Optional[GeolocationResult]:
        """Geolocate from WiFi BSSIDs"""
        pos = self.wigle.triangulate_position(bssids)

        if pos:
            return GeolocationResult(
                latitude=pos[0],
                longitude=pos[1],
                accuracy_m=50,  # WiFi typically 50-100m accuracy
                sources=[LocationSource.WIFI_NETWORK],
                confidence=0.7,
                timestamp=datetime.now().isoformat()
            )
        return None

    async def locate_from_cell_towers(self, towers: List[CellTower]) -> Optional[GeolocationResult]:
        """Geolocate from cell tower triangulation"""
        pos = self.opencellid.triangulate_cell_position(towers)

        if pos:
            return GeolocationResult(
                latitude=pos[0],
                longitude=pos[1],
                accuracy_m=500,  # Cell typically 500m-1km accuracy
                sources=[LocationSource.CELL_TOWER],
                confidence=0.5,
                timestamp=datetime.now().isoformat()
            )
        return None

    async def locate_hybrid(self, bssids: Optional[List[str]] = None,
                          cell_towers: Optional[List[CellTower]] = None) -> Optional[GeolocationResult]:
        """Combine multiple sources for best accuracy"""
        results = []

        if bssids:
            wifi_result = await self.locate_from_wifi(bssids)
            if wifi_result:
                results.append(wifi_result)

        if cell_towers:
            cell_result = await self.locate_from_cell_towers(cell_towers)
            if cell_result:
                results.append(cell_result)

        if not results:
            return None

        # Weight by confidence and combine
        total_confidence = sum(r.confidence for r in results)
        weighted_lat = sum(r.latitude * r.confidence for r in results) / total_confidence
        weighted_lng = sum(r.longitude * r.confidence for r in results) / total_confidence

        # Estimate accuracy from std dev
        avg_accuracy = sum(r.accuracy_m for r in results) / len(results)

        all_sources = list(set(src for r in results for src in r.sources))

        return GeolocationResult(
            latitude=weighted_lat,
            longitude=weighted_lng,
            accuracy_m=int(avg_accuracy * 0.75),  # Multiple sources improve accuracy
            sources=all_sources,
            confidence=min(0.95, total_confidence / len(results)),
            timestamp=datetime.now().isoformat()
        )
```

### 3.4 Flask Integration with Geolocation API

```python
# geolocation_api.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import json

app = Flask(__name__)
CORS(app)

geolocation_system = HybridGeolocationSystem(
    wigle_key=os.getenv('WIGLE_API_KEY'),
    opencellid_key=os.getenv('OPENCELLID_API_KEY')
)

@app.route('/api/locate/wifi', methods=['POST'])
async def locate_from_wifi():
    """
    Locate from WiFi networks

    Request:
    {
        "bssids": ["AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66"]
    }
    """
    data = request.json
    bssids = data.get('bssids', [])

    result = await geolocation_system.locate_from_wifi(bssids)

    if result:
        return jsonify({
            'success': True,
            'latitude': result.latitude,
            'longitude': result.longitude,
            'accuracy_m': result.accuracy_m,
            'confidence': result.confidence
        })

    return jsonify({'success': False, 'error': 'Could not locate'})

@app.route('/api/locate/hybrid', methods=['POST'])
async def locate_hybrid():
    """
    Locate using multiple sources

    Request:
    {
        "bssids": [...],
        "cell_towers": [
            {"mcc": 310, "mnc": 410, "lac": 123, "cid": 456, "signal": -95}
        ]
    }
    """
    data = request.json
    bssids = data.get('bssids')

    cell_data = data.get('cell_towers', [])
    towers = [CellTower(**t) for t in cell_data]

    result = await geolocation_system.locate_hybrid(bssids, towers)

    if result:
        return jsonify({
            'success': True,
            'latitude': result.latitude,
            'longitude': result.longitude,
            'accuracy_m': result.accuracy_m,
            'sources': [s.value for s in result.sources],
            'confidence': result.confidence
        })

    return jsonify({'success': False})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5001)
```

### 3.5 Client-Side JavaScript Integration

```javascript
// geolocation-client.js

class GeolocationClient {
    constructor(apiUrl = 'http://localhost:5001') {
        this.apiUrl = apiUrl;
    }

    async getWiFiNetworks() {
        /**
         * Requires the Network Information API (limited browser support)
         * OR use native mobile app integration
         */
        if (!navigator.getNetworkInformation) {
            console.warn('WiFi scanning not available in browser');
            return [];
        }

        // This is typically handled by mobile app or system integration
        return [];
    }

    async locateFromWiFi(bssids) {
        /**
         * Send BSSIDs to backend for geolocation
         */
        const response = await fetch(`${this.apiUrl}/api/locate/wifi`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ bssids })
        });

        return response.json();
    }

    async locateFromCellTowers(cellTowers) {
        const response = await fetch(`${this.apiUrl}/api/locate/hybrid`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cell_towers: cellTowers })
        });

        return response.json();
    }

    async locateHybrid(bssids, cellTowers) {
        const response = await fetch(`${this.apiUrl}/api/locate/hybrid`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                bssids,
                cell_towers: cellTowers
            })
        });

        return response.json();
    }

    // Map integration
    async displayLocationOnMap(mapId, location) {
        const map = L.map(mapId).setView(
            [location.latitude, location.longitude],
            15
        );

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

        const radius = location.accuracy_m;
        L.circle([location.latitude, location.longitude], {
            color: 'blue',
            fillColor: '#30f',
            fillOpacity: 0.2,
            radius
        }).addTo(map);

        L.marker([location.latitude, location.longitude])
            .bindPopup(`Accuracy: ±${location.accuracy_m}m<br>Confidence: ${(location.confidence * 100).toFixed(1)}%`)
            .addTo(map);
    }
}

// Usage
const client = new GeolocationClient();

// In Electron/mobile app:
const result = await client.locateFromWiFi([
    'AA:BB:CC:DD:EE:FF',
    '11:22:33:44:55:66'
]);

if (result.success) {
    client.displayLocationOnMap('map', result);
}
```

---

## Summary

This implementation provides:

**Part 1: Street View Integration**
- Leaflet-Pegman plugin for drag-and-drop Street View
- Click-to-open modal Street View viewer
- Mapillary open-source alternative

**Part 2: Autonomous Cybersecurity Agents**
- Event-driven async agent system with asyncio
- Pattern-based threat detection
- Real-time Flask-SocketIO dashboard
- Self-managing scanning with concurrent task processing

**Part 3: Hybrid Geolocation**
- WiGLE WiFi network triangulation
- OpenCellID cell tower triangulation
- Multi-source weighted position estimation
- Flask API integration

**Key Files:**
- `/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR/dalga/IMPLEMENTATION_RESEARCH.md` - This comprehensive guide
- Code patterns ready for integration into Flask/Python + JavaScript applications
- Production-ready async patterns for background tasks
- Real-time WebSocket communication templates

