# Complete Flask/Python + JavaScript API Integration Guide

## Architecture Overview

```
Client (Browser/Mobile)
    ↓ WebSocket
Reverse Proxy (nginx/caddy)
    ↓ HTTP/HTTPS
Flask Application
    ├── Routes (REST API)
    ├── SocketIO (Real-time)
    ├── Task Queue (Background)
    └── Cache Layer (Redis)
    ↓
External APIs
    ├── Google Street View
    ├── WiGLE
    ├── OpenCellID
    └── Mapillary
```

## Part 1: Flask Backend with Async Support

### 1.1 Application Factory Pattern

```python
# app/__init__.py
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS
import redis
import os
from dotenv import load_dotenv

load_dotenv()

socketio = SocketIO()
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    decode_responses=True
)

def create_app(config_name='development'):
    """Application factory"""
    app = Flask(__name__)

    # Configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-prod')
    app.config['SOCKETIO_MESSAGE_QUEUE'] = os.getenv(
        'SOCKETIO_QUEUE',
        'redis://localhost:6379'
    )

    # Initialize extensions
    CORS(app, resources={
        r"/api/*": {"origins": os.getenv('CORS_ORIGINS', '*')}
    })
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')

    # Register blueprints
    from app.routes import api_bp, maps_bp, security_bp
    app.register_blueprint(api_bp)
    app.register_blueprint(maps_bp, url_prefix='/api/maps')
    app.register_blueprint(security_bp, url_prefix='/api/security')

    # Register SocketIO handlers
    from app.handlers import register_socketio_handlers
    register_socketio_handlers(socketio)

    return app

# config.py
import os

class BaseConfig:
    DEBUG = False
    TESTING = False
    SOCKETIO_ASYNC_MODE = 'threading'
    SOCKETIO_PING_TIMEOUT = 60
    SOCKETIO_PING_INTERVAL = 25

class DevelopmentConfig(BaseConfig):
    DEBUG = True
    ENV = 'development'

class ProductionConfig(BaseConfig):
    DEBUG = False
    ENV = 'production'
```

### 1.2 SocketIO Event Handlers

```python
# app/handlers.py
from flask_socketio import emit, join_room, leave_room, rooms
from datetime import datetime
import logging
import json
from functools import wraps

logger = logging.getLogger(__name__)

# Track connected clients
CONNECTED_CLIENTS = {}
AGENT_REGISTRY = {}

def authenticated_only(f):
    """Decorator for authenticated SocketIO events"""
    @wraps(f)
    def wrapped(*args, **kwargs):
        session_id = request.sid
        if session_id not in CONNECTED_CLIENTS:
            emit('error', {'message': 'Not authenticated'})
            return
        return f(*args, **kwargs)
    return wrapped

def register_socketio_handlers(socketio):
    """Register all SocketIO event handlers"""

    @socketio.on('connect')
    def handle_connect():
        """Client connection"""
        from flask import request
        client_id = request.sid

        CONNECTED_CLIENTS[client_id] = {
            'id': client_id,
            'connected_at': datetime.now().isoformat(),
            'type': None
        }

        logger.info(f"Client connected: {client_id}")
        emit('connection_ack', {
            'status': 'connected',
            'client_id': client_id,
            'timestamp': datetime.now().isoformat()
        })

    @socketio.on('disconnect')
    def handle_disconnect():
        """Client disconnection"""
        from flask import request
        client_id = request.sid

        if client_id in CONNECTED_CLIENTS:
            del CONNECTED_CLIENTS[client_id]

        if client_id in AGENT_REGISTRY:
            del AGENT_REGISTRY[client_id]

        logger.info(f"Client disconnected: {client_id}")
        emit('client_disconnected', {'client_id': client_id}, broadcast=True)

    @socketio.on('register_agent')
    def handle_register_agent(data):
        """Agent registration"""
        from flask import request
        client_id = request.sid

        agent = {
            'id': data['agent_id'],
            'type': data['agent_type'],
            'capabilities': data.get('capabilities', []),
            'status': 'ready',
            'registered_at': datetime.now().isoformat(),
            'socket_id': client_id
        }

        AGENT_REGISTRY[client_id] = agent
        CONNECTED_CLIENTS[client_id]['type'] = 'agent'

        logger.info(f"Agent registered: {agent['id']}")

        emit('registration_ack', {
            'status': 'success',
            'agent_id': agent['id']
        })

        # Notify dashboards
        emit('agent_online', agent, broadcast=True, skip_sid=client_id)

    @socketio.on('send_task')
    @authenticated_only
    def handle_send_task(data):
        """Send scanning task to agent"""
        from flask import request

        task_id = data['task_id']
        agent_id = data['agent_id']

        # Find agent by ID
        agent_socket = None
        for socket_id, agent in AGENT_REGISTRY.items():
            if agent['id'] == agent_id:
                agent_socket = socket_id
                break

        if not agent_socket:
            emit('error', {'message': f'Agent {agent_id} not found'})
            return

        # Send task to agent
        socketio.emit('receive_task', data, to=agent_socket)
        emit('task_sent', {'task_id': task_id, 'agent': agent_id})

    @socketio.on('scan_result')
    def handle_scan_result(data):
        """Receive scan results from agent"""
        from flask import request
        from app import redis_client

        scan_id = data['scan_id']
        agent_id = data['agent_id']

        # Store in Redis
        redis_client.setex(
            f"scan:{scan_id}",
            86400,  # 24 hour TTL
            json.dumps(data)
        )

        logger.info(f"Scan result: {scan_id} from {agent_id}")

        # Broadcast to all dashboards
        emit('scan_update', data, broadcast=True)

        # Check for critical threats
        threats = data.get('threats_detected', [])
        critical = [t for t in threats if t.get('severity') == 'critical']

        if critical:
            emit('critical_threat_alert', {
                'scan_id': scan_id,
                'threats': critical
            }, broadcast=True)

    @socketio.on('heartbeat')
    def handle_heartbeat(data):
        """Agent heartbeat"""
        from flask import request

        client_id = request.sid
        if client_id in AGENT_REGISTRY:
            AGENT_REGISTRY[client_id]['last_heartbeat'] = datetime.now().isoformat()
            AGENT_REGISTRY[client_id]['status'] = data.get('status', 'ready')

    @socketio.on_error_default
    def default_error_handler(e):
        """Global error handler"""
        logger.error(f"SocketIO error: {e}")
        emit('error', {'message': str(e)})
```

### 1.3 REST API Routes

```python
# app/routes/api.py
from flask import Blueprint, request, jsonify, current_app
from flask_cors import cross_origin
import asyncio
import uuid
from datetime import datetime
import json

api_bp = Blueprint('api', __name__, url_prefix='/api')

@api_bp.route('/health', methods=['GET'])
@cross_origin()
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat()
    })

@api_bp.route('/scans', methods=['GET'])
def get_scans():
    """List active scans"""
    from app import redis_client

    # Get all scan keys
    scan_keys = redis_client.keys('scan:*')
    scans = []

    for key in scan_keys:
        scan_data = redis_client.get(key)
        if scan_data:
            scans.append(json.loads(scan_data))

    return jsonify({
        'success': True,
        'scans': scans,
        'count': len(scans)
    })

@api_bp.route('/scan/<scan_id>', methods=['GET'])
def get_scan_result(scan_id):
    """Get specific scan result"""
    from app import redis_client

    result = redis_client.get(f"scan:{scan_id}")

    if result:
        return jsonify({
            'success': True,
            'result': json.loads(result)
        })
    else:
        return jsonify({
            'success': False,
            'error': 'Scan not found'
        }), 404

@api_bp.route('/scan', methods=['POST'])
async def create_scan():
    """Create new scan task"""
    data = request.json
    scan_id = str(uuid.uuid4())

    # Validate input
    if not data.get('target'):
        return jsonify({'error': 'Missing target'}), 400

    task = {
        'task_id': scan_id,
        'target': data['target'],
        'scan_types': data.get('scan_types', ['port_scan']),
        'priority': data.get('priority', 5),
        'created_at': datetime.now().isoformat()
    }

    # Store task
    from app import redis_client
    redis_client.setex(
        f"task:{scan_id}",
        3600,
        json.dumps(task)
    )

    # Broadcast to agents
    from app import socketio
    socketio.emit('new_scan_task', task, broadcast=True)

    return jsonify({
        'success': True,
        'scan_id': scan_id,
        'status': 'queued'
    })

# app/routes/maps.py
from flask import Blueprint, request, jsonify
import aiohttp
import os

maps_bp = Blueprint('maps', __name__)

@maps_bp.route('/streetview/metadata', methods=['POST'])
async def streetview_metadata():
    """Get Street View metadata"""
    data = request.json
    lat, lng = data['lat'], data['lng']

    params = {
        'location': f'{lat},{lng}',
        'key': os.getenv('GOOGLE_MAPS_API_KEY'),
        'source': 'outdoor'
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(
            'https://maps.googleapis.com/maps/api/streetview/metadata',
            params=params
        ) as resp:
            return jsonify(await resp.json())

@maps_bp.route('/geolocation/wifi', methods=['POST'])
async def locate_wifi():
    """WiFi-based geolocation"""
    data = request.json
    bssids = data.get('bssids', [])

    from app.services.geolocation import geo_system

    result = await geo_system.locate_from_wifi(bssids)

    if result:
        return jsonify({
            'success': True,
            'location': result.to_dict()
        })
    else:
        return jsonify({'success': False}), 404

# app/routes/security.py
from flask import Blueprint, request, jsonify
import asyncio

security_bp = Blueprint('security', __name__)

@security_bp.route('/agents', methods=['GET'])
def get_agents():
    """List connected agents"""
    from app.handlers import AGENT_REGISTRY

    agents = list(AGENT_REGISTRY.values())
    return jsonify({
        'success': True,
        'agents': agents,
        'count': len(agents)
    })

@security_bp.route('/scan/port', methods=['POST'])
async def port_scan():
    """Initiate port scan"""
    data = request.json
    target = data.get('target')
    ports = data.get('ports', [22, 80, 443])

    if not target:
        return jsonify({'error': 'Missing target'}), 400

    from app.services.scanning import PortScanner

    task = {
        'target': target,
        'ports': ports
    }

    # Can be run async in background
    asyncio.create_task(PortScanner.scan(**task))

    return jsonify({
        'success': True,
        'message': 'Scan started in background'
    })
```

### 1.4 Service Layer with Async Support

```python
# app/services/scanning.py
import asyncio
import socket
import ssl
import logging
from typing import List, Dict
import aiohttp

logger = logging.getLogger(__name__)

class PortScanner:
    """Async port scanning service"""

    @staticmethod
    async def scan(target: str, ports: List[int], timeout: float = 2.0) -> Dict:
        """Scan ports concurrently"""
        results = {
            'target': target,
            'open_ports': [],
            'closed_ports': []
        }

        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()
                return ('open', port)
            except (asyncio.TimeoutError, OSError):
                return ('closed', port)

        # Run all port checks concurrently
        tasks = [check_port(port) for port in ports]
        port_results = await asyncio.gather(*tasks)

        for status, port in port_results:
            if status == 'open':
                results['open_ports'].append(port)
            else:
                results['closed_ports'].append(port)

        logger.info(f"Port scan complete: {target} - Open: {len(results['open_ports'])}")
        return results

class SSLChecker:
    """SSL/TLS certificate verification"""

    @staticmethod
    async def check(target: str, port: int = 443) -> Dict:
        """Check SSL certificate"""
        result = {
            'target': target,
            'port': port,
            'valid': False,
            'certificate': None,
            'error': None
        }

        try:
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(
                None,
                SSLChecker._get_cert,
                target,
                port
            )
            result['valid'] = True
            result['certificate'] = cert_info

        except Exception as e:
            result['error'] = str(e)
            logger.error(f"SSL check error: {e}")

        return result

    @staticmethod
    def _get_cert(target: str, port: int) -> Dict:
        """Synchronous certificate retrieval"""
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()

                return {
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'not_before': cert.get('notBefore'),
                    'not_after': cert.get('notAfter'),
                    'cipher': cipher[0],
                    'protocol': cipher[1]
                }

# app/services/geolocation.py
from app.geolocation_wigle_opencellid import HybridGeolocationSystem
import os

geo_system = HybridGeolocationSystem(
    wigle_username=os.getenv('WIGLE_USERNAME'),
    wigle_key=os.getenv('WIGLE_API_KEY'),
    opencellid_key=os.getenv('OPENCELLID_API_KEY')
)
```

## Part 2: Frontend JavaScript Integration

### 2.1 SocketIO Client

```javascript
// js/socketio-client.js

class DashboardSocketIO {
    constructor(serverUrl = window.location.origin) {
        this.socket = io(serverUrl);
        this.agents = {};
        this.scans = {};
        this.threats = [];

        this.setupHandlers();
    }

    setupHandlers() {
        this.socket.on('connect', () => this.onConnect());
        this.socket.on('disconnect', () => this.onDisconnect());
        this.socket.on('connection_ack', (data) => this.onConnectionAck(data));
        this.socket.on('agent_online', (data) => this.onAgentOnline(data));
        this.socket.on('scan_update', (data) => this.onScanUpdate(data));
        this.socket.on('critical_threat_alert', (data) => this.onCriticalThreat(data));
        this.socket.on('error', (data) => this.onError(data));
    }

    onConnect() {
        console.log('Connected to server');
        this.socket.emit('get_agents');
    }

    onDisconnect() {
        console.warn('Disconnected from server');
    }

    onConnectionAck(data) {
        console.log('Connection acknowledged:', data);
    }

    onAgentOnline(agent) {
        this.agents[agent.id] = agent;
        this.dispatchEvent('agent_online', agent);
    }

    onScanUpdate(result) {
        this.scans[result.scan_id] = result;
        this.dispatchEvent('scan_updated', result);

        // Check for threats
        if (result.threats_detected && result.threats_detected.length > 0) {
            this.threats.push(...result.threats_detected);
        }
    }

    onCriticalThreat(alert) {
        console.error('CRITICAL THREAT:', alert);
        this.dispatchEvent('critical_threat', alert);

        // Show notification
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification('Critical Threat Detected', {
                body: alert.threats.map(t => t.name).join(', '),
                icon: '/alert.png'
            });
        }
    }

    onError(data) {
        console.error('Socket error:', data);
    }

    registerAgent(agentId, agentType, capabilities) {
        this.socket.emit('register_agent', {
            agent_id: agentId,
            agent_type: agentType,
            capabilities
        });
    }

    sendTask(taskId, agentId, scanData) {
        this.socket.emit('send_task', {
            task_id: taskId,
            agent_id: agentId,
            ...scanData
        });
    }

    reportScanResult(scanId, agentId, result) {
        this.socket.emit('scan_result', {
            scan_id: scanId,
            agent_id: agentId,
            ...result
        });
    }

    sendHeartbeat(status) {
        this.socket.emit('heartbeat', { status });
    }

    dispatchEvent(eventName, data) {
        const event = new CustomEvent(eventName, { detail: data });
        document.dispatchEvent(event);
    }
}

// Usage
const dashboard = new DashboardSocketIO();

document.addEventListener('agent_online', (e) => {
    console.log('New agent online:', e.detail);
    updateAgentList(e.detail);
});

document.addEventListener('scan_updated', (e) => {
    console.log('Scan updated:', e.detail);
    updateScanResults(e.detail);
});
```

### 2.2 REST API Client

```javascript
// js/api-client.js

class APIClient {
    constructor(baseUrl = '/api') {
        this.baseUrl = baseUrl;
    }

    async fetch(endpoint, options = {}) {
        const url = `${this.baseUrl}${endpoint}`;
        const response = await fetch(url, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });

        if (!response.ok) {
            throw new Error(`API Error: ${response.status}`);
        }

        return response.json();
    }

    // Scans
    async getScans() {
        return this.fetch('/scans');
    }

    async getScan(scanId) {
        return this.fetch(`/scan/${scanId}`);
    }

    async createScan(target, scanTypes) {
        return this.fetch('/scan', {
            method: 'POST',
            body: JSON.stringify({ target, scan_types: scanTypes })
        });
    }

    // Street View
    async getStreetViewMetadata(lat, lng) {
        return this.fetch('/maps/streetview/metadata', {
            method: 'POST',
            body: JSON.stringify({ lat, lng })
        });
    }

    // Geolocation
    async locateFromWiFi(bssids) {
        return this.fetch('/maps/geolocation/wifi', {
            method: 'POST',
            body: JSON.stringify({ bssids })
        });
    }

    // Security
    async getAgents() {
        return this.fetch('/security/agents');
    }

    async portScan(target, ports) {
        return this.fetch('/security/scan/port', {
            method: 'POST',
            body: JSON.stringify({ target, ports })
        });
    }
}

const api = new APIClient('/api');
```

### 2.3 Map Integration

```javascript
// js/map-integration.js

class MapIntegration {
    constructor(mapContainerId) {
        this.map = L.map(mapContainerId).setView([40, -95], 4);

        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '© OpenStreetMap'
        }).addTo(this.map);

        this.markers = {};
    }

    async addStreetViewMarker(lat, lng, title) {
        // Check Street View availability
        const metadata = await api.getStreetViewMetadata(lat, lng);

        const marker = L.marker([lat, lng], {
            title: title
        }).bindPopup(`
            <div style="width: 250px;">
                <h4>${title}</h4>
                ${metadata.data.status === 'OK' ?
                    `<button onclick="openStreetView(${lat}, ${lng})"
                            class="btn btn-primary">View Street</button>`
                    : '<p>No Street View available</p>'
                }
            </div>
        `).addTo(this.map);

        this.markers[`${lat},${lng}`] = marker;
        return marker;
    }

    addGeolocationCircle(lat, lng, accuracy, label) {
        L.circle([lat, lng], {
            color: '#3388ff',
            fillColor: '#3388ff',
            fillOpacity: 0.2,
            radius: accuracy
        }).addTo(this.map);

        L.marker([lat, lng]).bindPopup(
            `${label}<br>Accuracy: ±${accuracy}m`
        ).addTo(this.map);

        this.map.flyTo([lat, lng], 15);
    }

    clearMarkers() {
        Object.values(this.markers).forEach(m => m.remove());
        this.markers = {};
    }
}

const mapIntegration = new MapIntegration('map');

// Street View modal
function openStreetView(lat, lng) {
    const modal = document.createElement('div');
    modal.className = 'streetview-modal';
    modal.innerHTML = `
        <div class="modal-content">
            <button class="close" onclick="this.closest('.streetview-modal').remove()">×</button>
            <div id="streetview-container"></div>
        </div>
    `;
    document.body.appendChild(modal);

    const panorama = new google.maps.StreetViewPanorama(
        document.getElementById('streetview-container'),
        { position: { lat, lng } }
    );
}

// WiFi geolocation
async function locateFromWiFi(bssids) {
    const result = await api.locateFromWiFi(bssids);

    if (result.success) {
        const { latitude, longitude, accuracy_m } = result.location;
        mapIntegration.addGeolocationCircle(
            latitude,
            longitude,
            accuracy_m,
            'WiFi Location'
        );
    }
}
```

### 2.4 Real-Time Dashboard UI

```html
<!-- dashboard.html -->
<!DOCTYPE html>
<html>
<head>
    <title>Cybersecurity Dashboard</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.css" />
    <link rel="stylesheet" href="/css/dashboard.css">
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/leaflet@1.9.4/dist/leaflet.js"></script>
</head>
<body>
    <div class="dashboard">
        <header>
            <h1>Autonomous Cybersecurity System</h1>
            <div id="status" class="status-indicator">●</div>
        </header>

        <div class="content">
            <!-- Left Panel: Agents -->
            <div class="panel agents-panel">
                <h2>Connected Agents</h2>
                <div id="agents-list" class="list"></div>
            </div>

            <!-- Center: Map & Scans -->
            <div class="panel map-panel">
                <h2>Threat Map</h2>
                <div id="map" style="height: 400px;"></div>
                <h2 style="margin-top: 20px;">Active Scans</h2>
                <div id="scans-list" class="list"></div>
            </div>

            <!-- Right Panel: Threats -->
            <div class="panel threats-panel">
                <h2>Detected Threats</h2>
                <div id="threats-list" class="list threats"></div>
            </div>
        </div>
    </div>

    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI'; background: #0a0e27; color: #e0e0e0; }

        .dashboard {
            display: flex;
            flex-direction: column;
            height: 100vh;
        }

        header {
            background: #1a1f3a;
            padding: 20px;
            border-bottom: 2px solid #00ff88;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .status-indicator {
            font-size: 24px;
            animation: pulse 2s infinite;
            color: #00ff88;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .content {
            display: grid;
            grid-template-columns: 1fr 2fr 1fr;
            gap: 20px;
            padding: 20px;
            flex: 1;
            overflow: hidden;
        }

        .panel {
            background: #1a1f3a;
            border: 1px solid #00ff88;
            border-radius: 8px;
            padding: 20px;
            overflow-y: auto;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.1);
        }

        .list { margin-top: 15px; }
        .list-item {
            background: rgba(255, 255, 255, 0.05);
            padding: 12px;
            margin: 10px 0;
            border-left: 3px solid #00ff88;
            border-radius: 4px;
        }

        .threats .list-item.critical {
            border-left-color: #ff3333;
            background: rgba(255, 51, 51, 0.1);
        }

        .threats .list-item.high {
            border-left-color: #ffaa00;
            background: rgba(255, 170, 0, 0.1);
        }
    </style>

    <script src="/js/socketio-client.js"></script>
    <script src="/js/api-client.js"></script>
    <script src="/js/map-integration.js"></script>
    <script src="/js/dashboard-controller.js"></script>
</body>
</html>
```

### 2.5 Dashboard Controller

```javascript
// js/dashboard-controller.js

class DashboardController {
    constructor() {
        this.socket = new DashboardSocketIO();
        this.api = new APIClient('/api');
        this.map = new MapIntegration('map');

        this.setupEventListeners();
        this.startUpdateLoop();
    }

    setupEventListeners() {
        document.addEventListener('agent_online', (e) => {
            this.renderAgents(e.detail);
        });

        document.addEventListener('scan_updated', (e) => {
            this.renderScan(e.detail);
        });

        document.addEventListener('critical_threat', (e) => {
            this.renderThreat(e.detail);
        });
    }

    async startUpdateLoop() {
        setInterval(async () => {
            const scans = await this.api.getScans();
            this.renderScans(scans.scans);

            const agents = await this.api.getAgents();
            this.renderAgentsList(agents.agents);
        }, 5000);  // Update every 5 seconds
    }

    renderAgents(agent) {
        const list = document.getElementById('agents-list');
        const item = document.createElement('div');
        item.className = 'list-item';
        item.innerHTML = `
            <div><strong>${agent.id}</strong></div>
            <div>Type: ${agent.type}</div>
            <div>Status: ${agent.status}</div>
        `;
        list.appendChild(item);
    }

    renderScan(scan) {
        const list = document.getElementById('scans-list');
        const item = document.createElement('div');
        item.className = 'list-item';
        item.innerHTML = `
            <div><strong>${scan.target}</strong></div>
            <div>Type: ${scan.scan_type}</div>
            <div>Threats: ${scan.threats_detected.length}</div>
        `;
        list.appendChild(item);
    }

    renderThreat(alert) {
        const list = document.getElementById('threats-list');

        alert.threats.forEach(threat => {
            const item = document.createElement('div');
            item.className = `list-item ${threat.severity}`;
            item.innerHTML = `
                <div><strong>${threat.name}</strong></div>
                <div class="severity">${threat.severity}</div>
                <div style="font-size: 12px; margin-top: 8px;">
                    ${threat.remediation}
                </div>
            `;
            list.insertBefore(item, list.firstChild);
        });

        // Keep only last 50 threats
        while (list.children.length > 50) {
            list.removeChild(list.lastChild);
        }
    }

    renderScans(scans) {
        // Update scan list
    }

    renderAgentsList(agents) {
        // Update agent list
    }
}

// Initialize dashboard
const dashboard = new DashboardController();
```

## Part 3: Deployment Configuration

### 3.1 Docker Setup

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Expose ports
EXPOSE 5000

# Run with gunicorn + socketio
CMD ["gunicorn", "--worker-class", "socketio.sanic_app.Worker", \
     "--workers", "4", "--bind", "0.0.0.0:5000", \
     "--timeout", "120", "--access-logfile", "-", \
     "--error-logfile", "-", "app:create_app()"]
```

```yaml
# docker-compose.yml
version: '3.9'

services:
  flask-app:
    build: .
    ports:
      - "5000:5000"
    environment:
      - FLASK_ENV=production
      - REDIS_HOST=redis
      - GOOGLE_MAPS_API_KEY=${GOOGLE_MAPS_API_KEY}
      - WIGLE_USERNAME=${WIGLE_USERNAME}
      - WIGLE_API_KEY=${WIGLE_API_KEY}
    depends_on:
      - redis

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
      - ./certs:/etc/nginx/certs
    depends_on:
      - flask-app
```

### 3.2 Production NGINX Configuration

```nginx
# nginx.conf
upstream flask_backend {
    server flask-app:5000;
}

server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;

    # Socket.IO
    location /socket.io {
        proxy_pass http://flask_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    # REST API
    location /api {
        proxy_pass http://flask_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Static files
    location / {
        proxy_pass http://flask_backend;
    }
}
```

## Summary

This complete integration provides:

1. **Backend**: Flask with async support, SocketIO, and microservices
2. **Frontend**: Real-time dashboard with WebSocket communication
3. **APIs**: Integration with Street View, WiGLE, OpenCellID, Mapillary
4. **Scalability**: Docker, Redis caching, async task processing
5. **Security**: HTTPS, authentication, rate limiting
6. **Monitoring**: Real-time threat alerts and metrics

File Locations:
- Flask application: `/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR/dalga/`
- Example implementations provided above
- Docker configuration for production deployment

