# DALGA SIGINT Module - Comprehensive Architecture Plan

## Executive Summary

DALGA (Dalga Analiz ve Lokasyon Gozetim Araci) is a **next-generation wireless SIGINT platform** for TSUNAMI that EXCEEDS WireTapper's capabilities while integrating seamlessly with existing infrastructure. This document provides the complete architectural blueprint.

---

## 1. Feature Comparison Matrix

### WireTapper Features vs DALGA Enhanced Features

| Feature | WireTapper | DALGA | Enhancement |
|---------|------------|-------|-------------|
| WiFi Detection | Basic WiGLE | Local + WiGLE + Custom | **Multi-source correlation** |
| Bluetooth/BLE | Basic | Classify 50+ device types | **Advanced fingerprinting** |
| Cell Towers | OpenCellID | OpenCellID + MLS + Local | **Multi-API triangulation** |
| IoT Detection | Shodan only | Shodan + Censys + Local | **Expanded coverage** |
| Device Classification | Basic | ML-powered 100+ categories | **10x more categories** |
| Map Visualization | Basic Leaflet | F-35 cockpit style | **Already superior in harita.html** |
| Threat Correlation | None | 43K+ IOC database | **UNIQUE: Real-time threat intel** |
| Drone Detection | No | Yes (ADS-B + RF) | **UNIQUE** |
| SDR Integration | No | Yes (RTL-SDR/HackRF) | **UNIQUE** |
| GPS Tracker Detection | No | Yes | **UNIQUE** |
| Historical Tracking | No | Full timeline | **UNIQUE** |
| Network Topology | No | Graph visualization | **UNIQUE** |
| Stealth Modes | No | 3 levels | **UNIQUE** |
| API Key Encryption | Basic | AES-256-GCM vault | **Military-grade** |
| Turkish Interface | No | Full Turkish | **Native support** |
| RFID/NFC Detection | No | Yes (with hardware) | **UNIQUE** |

---

## 2. Module Architecture

### 2.1 High-Level Component Diagram

```
                           DALGA SIGINT ARCHITECTURE
+===============================================================================+
|                                                                               |
|  +------------------+  +------------------+  +------------------+              |
|  |   DALGA CLI      |  |  DALGA WEB API   |  |  TSUNAMI HARITA  |              |
|  |  (dalga.py)      |  |  (dalga_web.py)  |  |  (harita.html)   |              |
|  +--------+---------+  +--------+---------+  +--------+---------+              |
|           |                     |                     |                        |
|           +----------+----------+----------+----------+                        |
|                      |                     |                                   |
|              +-------v-------+     +-------v-------+                           |
|              | DALGA SIGINT  |     | WebSocket Hub |                           |
|              |    CORE       |<--->| (Real-time)   |                           |
|              +-------+-------+     +---------------+                           |
|                      |                                                         |
|  +-------------------+-------------------+-------------------+                 |
|  |                   |                   |                   |                 |
|  v                   v                   v                   v                 |
| +---------+   +-----------+   +------------+   +-------------+                 |
| | SCANNER |   | CLASSIFIER|   | CORRELATOR |   | VISUALIZER  |                 |
| | ENGINE  |   |  ENGINE   |   |   ENGINE   |   |   ENGINE    |                 |
| +---------+   +-----------+   +------------+   +-------------+                 |
|      |              |               |                |                         |
|      v              v               v                v                         |
| +--------+    +----------+   +------------+   +-------------+                  |
| |Scanners|    |   ML     |   |  Threat    |   |   Map       |                  |
| | WiFi   |    | Models   |   |  Intel DB  |   | Layers      |                  |
| | BT/BLE |    | (Device  |   | (43K+ IOC) |   | (Leaflet)   |                  |
| | Cell   |    |  Types)  |   +------------+   +-------------+                  |
| | IoT    |    +----------+                                                     |
| | Drone  |                                                                     |
| | SDR    |         PERSISTENCE LAYER                                           |
| +--------+   +========================================================+        |
|              |                                                        |        |
|              |  +-------------+  +---------+  +------------------+    |        |
|              |  | SQLite DB   |  | VAULT   |  | Export Manager   |    |        |
|              |  | (Devices,   |  | (AES-256|  | (JSON/CSV/KML)   |    |        |
|              |  |  History)   |  |  Keys)  |  |                  |    |        |
|              |  +-------------+  +---------+  +------------------+    |        |
|              +========================================================+        |
+===============================================================================+
```

### 2.2 Core Components

#### A. Scanner Engine (`dalga_sigint_scanner.py`)

```python
class ScannerEngine:
    """
    Multi-protocol wireless signal scanner.
    Manages: WiFi, Bluetooth, Cell, IoT, Drone, SDR scanners.
    """

    - WiFiScanner: iwlist/iw/nmcli + monitor mode
    - BluetoothScanner: hcitool/bluetoothctl + BLE
    - CellScanner: OpenCellID + Mozilla Location Services
    - IoTScanner: Shodan + Censys + local network
    - DroneScanner: ADS-B + RF signature detection
    - SDRScanner: RTL-SDR/HackRF frequency analysis
    - GPSTrackerDetector: Known tracker frequencies
```

#### B. Classifier Engine (`dalga_sigint_classifier.py`)

```python
class ClassifierEngine:
    """
    ML-powered device classification.
    100+ device categories with vendor fingerprinting.
    """

    Categories:
    - Phones (iPhone, Samsung, Pixel, etc.)
    - Tablets (iPad, Galaxy Tab, etc.)
    - Laptops (MacBook, ThinkPad, etc.)
    - Wearables (Apple Watch, Fitbit, etc.)
    - Audio (AirPods, Bose, Sony, etc.)
    - Vehicles (Tesla, Ford SYNC, etc.)
    - Cameras (Ring, Nest, Hikvision, etc.)
    - IoT (Smart TVs, Speakers, Plugs, etc.)
    - Drones (DJI, Parrot, etc.)
    - Network (Routers, APs, etc.)
    - Industrial (SCADA, PLC, etc.)
    - Medical (Pacemakers, Monitors, etc.)
    - Military (Known RF signatures)
```

#### C. Correlator Engine (`dalga_sigint_correlator.py`)

```python
class CorrelatorEngine:
    """
    Real-time threat correlation with TSUNAMI's 43K+ IOC database.
    Cross-references discovered devices against known threats.
    """

    Functions:
    - mac_to_threat(): Check MAC against malware C2
    - ip_to_apt(): APT group attribution
    - ssid_to_honeypot(): Honeypot/evil twin detection
    - vendor_to_cve(): Known vulnerabilities
    - device_to_risk(): Risk scoring (0-100)
```

#### D. Visualizer Engine (`dalga_sigint_visualizer.py`)

```python
class VisualizerEngine:
    """
    Map and graph visualization for harita.html integration.
    """

    Layers:
    - WiFi Networks (clustered markers)
    - Bluetooth Devices (category icons)
    - Cell Towers (coverage circles)
    - IoT Devices (risk-colored)
    - Drones (real-time tracking)
    - Threat Heatmap
    - Network Topology Graph
    - Device Timeline
```

---

## 3. Database Schema

### 3.1 SQLite Tables

```sql
-- ==================== DALGA SIGINT DATABASE SCHEMA ====================

-- Wireless devices master table
CREATE TABLE IF NOT EXISTS sigint_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE NOT NULL,  -- SHA256(mac/bssid)
    device_type TEXT NOT NULL,       -- wifi/bluetooth/cell/iot/drone
    mac_address TEXT,
    bssid TEXT,
    name TEXT,
    vendor TEXT,
    category TEXT,                   -- phone/laptop/camera/etc
    subcategory TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    seen_count INTEGER DEFAULT 1,
    latitude REAL,
    longitude REAL,
    altitude REAL,
    accuracy_m REAL,
    signal_strength INTEGER,
    signal_quality INTEGER,
    risk_score INTEGER DEFAULT 0,    -- 0-100
    threat_level TEXT,               -- info/low/medium/high/critical
    is_known_threat BOOLEAN DEFAULT 0,
    threat_ioc_id TEXT,              -- Reference to threat intel
    metadata JSON,
    notes TEXT
);

-- WiFi specific data
CREATE TABLE IF NOT EXISTS sigint_wifi (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES sigint_devices(device_id),
    ssid TEXT,
    channel INTEGER,
    frequency INTEGER,
    bandwidth TEXT,
    encryption TEXT,                 -- WPA2/WPA3/WEP/Open
    cipher TEXT,
    auth_type TEXT,
    hidden BOOLEAN DEFAULT 0,
    wps_enabled BOOLEAN,
    client_count INTEGER,
    last_seen TIMESTAMP
);

-- Bluetooth specific data
CREATE TABLE IF NOT EXISTS sigint_bluetooth (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES sigint_devices(device_id),
    device_class TEXT,
    service_classes TEXT,            -- JSON array
    major_class TEXT,
    minor_class TEXT,
    bluetooth_version TEXT,
    le_supported BOOLEAN,
    manufacturer_data TEXT,
    services JSON,
    last_seen TIMESTAMP
);

-- Cell tower data
CREATE TABLE IF NOT EXISTS sigint_cell_towers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES sigint_devices(device_id),
    cell_id TEXT,
    lac INTEGER,
    mcc INTEGER,
    mnc INTEGER,
    radio_type TEXT,                 -- GSM/LTE/5G
    operator TEXT,
    tower_type TEXT,                 -- macro/small/femto
    azimuth INTEGER,
    range_m INTEGER,
    pci INTEGER,
    tac INTEGER,
    last_seen TIMESTAMP
);

-- IoT device data
CREATE TABLE IF NOT EXISTS sigint_iot (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES sigint_devices(device_id),
    ip_address TEXT,
    port INTEGER,
    protocol TEXT,
    product TEXT,
    version TEXT,
    os TEXT,
    cpe TEXT,
    cves JSON,                       -- Known vulnerabilities
    banner TEXT,
    http_title TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_subject TEXT,
    ssl_cert_fingerprint TEXT,
    open_ports JSON,
    shodan_id TEXT,
    censys_id TEXT,
    last_seen TIMESTAMP
);

-- Drone detection data
CREATE TABLE IF NOT EXISTS sigint_drones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES sigint_devices(device_id),
    drone_model TEXT,
    manufacturer TEXT,               -- DJI/Parrot/etc
    serial_number TEXT,
    pilot_lat REAL,
    pilot_lon REAL,
    altitude_m REAL,
    speed_mps REAL,
    heading INTEGER,
    home_lat REAL,
    home_lon REAL,
    rf_frequency REAL,
    signal_type TEXT,                -- WiFi/RemoteID/ADS-B
    flight_id TEXT,
    last_seen TIMESTAMP
);

-- SDR signal captures
CREATE TABLE IF NOT EXISTS sigint_sdr_signals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id TEXT UNIQUE,
    frequency_hz REAL,
    bandwidth_hz REAL,
    modulation TEXT,
    signal_strength_dbm REAL,
    duration_ms INTEGER,
    sample_rate INTEGER,
    center_freq REAL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    decoded_data TEXT,
    protocol TEXT,
    classification TEXT,
    raw_file_path TEXT,
    metadata JSON
);

-- Device location history
CREATE TABLE IF NOT EXISTS sigint_location_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES sigint_devices(device_id),
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    latitude REAL,
    longitude REAL,
    altitude REAL,
    signal_strength INTEGER,
    source TEXT                      -- local/wigle/opencellid
);

-- Device relationships (network topology)
CREATE TABLE IF NOT EXISTS sigint_device_relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_a_id TEXT REFERENCES sigint_devices(device_id),
    device_b_id TEXT REFERENCES sigint_devices(device_id),
    relationship_type TEXT,          -- connected_to/communicates_with/near
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    connection_count INTEGER DEFAULT 1,
    metadata JSON
);

-- Scan sessions
CREATE TABLE IF NOT EXISTS sigint_scan_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT UNIQUE,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ended_at TIMESTAMP,
    scan_type TEXT,                  -- wifi/bluetooth/cell/all
    location_lat REAL,
    location_lon REAL,
    devices_found INTEGER DEFAULT 0,
    threats_detected INTEGER DEFAULT 0,
    parameters JSON,
    status TEXT                      -- running/completed/failed
);

-- Threat correlations
CREATE TABLE IF NOT EXISTS sigint_threat_correlations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT REFERENCES sigint_devices(device_id),
    ioc_type TEXT,                   -- ip/domain/mac/ssid
    ioc_value TEXT,
    threat_source TEXT,              -- feodo/urlhaus/custom
    threat_category TEXT,            -- malware/c2/botnet
    severity TEXT,
    confidence REAL,
    first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_detected TIMESTAMP,
    resolved BOOLEAN DEFAULT 0,
    resolution_notes TEXT
);

-- API key storage (encrypted references)
CREATE TABLE IF NOT EXISTS sigint_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT UNIQUE,
    vault_key TEXT,                  -- Reference to encrypted key in vault
    last_used TIMESTAMP,
    usage_count INTEGER DEFAULT 0,
    daily_limit INTEGER,
    is_active BOOLEAN DEFAULT 1
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_devices_type ON sigint_devices(device_type);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON sigint_devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_risk ON sigint_devices(risk_score);
CREATE INDEX IF NOT EXISTS idx_wifi_ssid ON sigint_wifi(ssid);
CREATE INDEX IF NOT EXISTS idx_location_device ON sigint_location_history(device_id);
CREATE INDEX IF NOT EXISTS idx_location_time ON sigint_location_history(timestamp);
CREATE INDEX IF NOT EXISTS idx_threats_device ON sigint_threat_correlations(device_id);
```

---

## 4. API Endpoints

### 4.1 Flask REST API (`dalga_web.py` Integration)

```python
# ==================== DALGA SIGINT API ENDPOINTS ====================

# Scanning Endpoints
POST   /api/sigint/scan/start           # Start scan session
POST   /api/sigint/scan/stop            # Stop active scan
GET    /api/sigint/scan/status          # Get scan status
GET    /api/sigint/scan/history         # Get scan history

# Device Endpoints
GET    /api/sigint/devices              # List all devices
GET    /api/sigint/devices/<id>         # Get device details
GET    /api/sigint/devices/wifi         # List WiFi networks
GET    /api/sigint/devices/bluetooth    # List Bluetooth devices
GET    /api/sigint/devices/cell         # List cell towers
GET    /api/sigint/devices/iot          # List IoT devices
GET    /api/sigint/devices/drones       # List detected drones
DELETE /api/sigint/devices/<id>         # Delete device record

# Analysis Endpoints
GET    /api/sigint/devices/<id>/history # Device location history
GET    /api/sigint/devices/<id>/threats # Device threat correlations
GET    /api/sigint/topology             # Network topology graph
GET    /api/sigint/heatmap              # Device density heatmap
GET    /api/sigint/timeline             # Activity timeline

# Threat Correlation Endpoints
GET    /api/sigint/threats              # All threat correlations
POST   /api/sigint/threats/check        # Check specific indicator
GET    /api/sigint/threats/stats        # Threat statistics

# SDR Endpoints (if hardware present)
GET    /api/sigint/sdr/status           # SDR hardware status
POST   /api/sigint/sdr/capture          # Start frequency capture
GET    /api/sigint/sdr/signals          # List captured signals

# Configuration Endpoints
GET    /api/sigint/config               # Get configuration
PUT    /api/sigint/config               # Update configuration
GET    /api/sigint/config/apis          # List API integrations
POST   /api/sigint/config/apis          # Add API key

# Export Endpoints
GET    /api/sigint/export/json          # Export as JSON
GET    /api/sigint/export/csv           # Export as CSV
GET    /api/sigint/export/kml           # Export as KML (Google Earth)

# WebSocket Events (for real-time updates)
WS     /ws/sigint/live                  # Real-time device updates
       - device_discovered
       - device_updated
       - threat_detected
       - scan_progress
       - drone_alert
```

### 4.2 Example API Responses

```json
// GET /api/sigint/devices
{
    "success": true,
    "count": 47,
    "devices": [
        {
            "device_id": "d8f4a2...",
            "device_type": "wifi",
            "name": "TURKCELL-FIBER-5G",
            "vendor": "Huawei",
            "category": "router",
            "last_seen": "2026-02-03T21:30:00Z",
            "location": {
                "lat": 41.0082,
                "lon": 28.9784
            },
            "risk_score": 12,
            "threat_level": "info"
        }
    ]
}

// GET /api/sigint/devices/<id>/threats
{
    "success": true,
    "device_id": "d8f4a2...",
    "threats": [
        {
            "ioc_type": "ip",
            "ioc_value": "185.220.101.xxx",
            "source": "feodo_tracker",
            "category": "c2",
            "severity": "high",
            "confidence": 0.92,
            "mitre_techniques": ["T1071", "T1105"]
        }
    ],
    "risk_summary": {
        "total_threats": 1,
        "highest_severity": "high",
        "recommendation": "Isolate device and investigate"
    }
}
```

---

## 5. Frontend Integration (harita.html)

### 5.1 New Map Layers

```javascript
// ==================== DALGA SIGINT MAP LAYERS ====================

const sigintLayers = {
    // WiFi Networks Layer
    wifi: L.markerClusterGroup({
        iconCreateFunction: (cluster) => createSigintClusterIcon(cluster, 'wifi'),
        disableClusteringAtZoom: 18
    }),

    // Bluetooth Devices Layer
    bluetooth: L.markerClusterGroup({
        iconCreateFunction: (cluster) => createSigintClusterIcon(cluster, 'bluetooth'),
        disableClusteringAtZoom: 18
    }),

    // Cell Towers Layer
    cellTowers: L.layerGroup(),

    // IoT Devices Layer
    iot: L.layerGroup(),

    // Drones Layer (real-time tracking)
    drones: L.layerGroup(),

    // Threat Heatmap
    threatHeatmap: L.heatLayer([], {
        radius: 25,
        blur: 15,
        gradient: {
            0.0: '#00ff88',  // Safe
            0.3: '#ffcc00',  // Low risk
            0.6: '#ff8800',  // Medium risk
            0.8: '#ff3355',  // High risk
            1.0: '#cc0033'   // Critical
        }
    }),

    // Device Trails (historical movement)
    deviceTrails: L.layerGroup()
};
```

### 5.2 Device Markers

```javascript
// Device type icons with F-35 cockpit style
const sigintMarkerStyles = {
    wifi: {
        router: { icon: 'fas fa-wifi', color: '#00b4ff' },
        accessPoint: { icon: 'fas fa-broadcast-tower', color: '#00e5ff' },
        hidden: { icon: 'fas fa-eye-slash', color: '#ff9900' }
    },
    bluetooth: {
        phone: { icon: 'fas fa-mobile-alt', color: '#00ff88' },
        laptop: { icon: 'fas fa-laptop', color: '#00b4ff' },
        headphone: { icon: 'fas fa-headphones', color: '#8855ff' },
        watch: { icon: 'fas fa-clock', color: '#ff6699' },
        speaker: { icon: 'fas fa-volume-up', color: '#ffcc00' },
        car: { icon: 'fas fa-car', color: '#ff5722' },
        camera: { icon: 'fas fa-video', color: '#e91e63' },
        unknown: { icon: 'fas fa-question', color: '#888888' }
    },
    cell: {
        tower: { icon: 'fas fa-signal', color: '#ff3355' },
        femto: { icon: 'fas fa-house-signal', color: '#ff8800' }
    },
    iot: {
        camera: { icon: 'fas fa-video', color: '#e91e63' },
        thermostat: { icon: 'fas fa-thermometer-half', color: '#00bcd4' },
        smart_plug: { icon: 'fas fa-plug', color: '#4caf50' },
        doorbell: { icon: 'fas fa-bell', color: '#ff9800' }
    },
    drone: {
        quadcopter: { icon: 'fas fa-helicopter', color: '#ff0040' }
    }
};
```

### 5.3 Control Panel HTML

```html
<!-- SIGINT Control Panel for harita.html -->
<div id="sigint-panel" class="sigint-panel">
    <div class="sigint-header">
        <h3>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/>
            </svg>
            DALGA SIGINT
        </h3>
        <button class="sigint-close" onclick="toggleSigintPanel()">x</button>
    </div>

    <div class="sigint-body">
        <!-- Scan Controls -->
        <div class="sigint-section">
            <h4>Tarama Kontrolleri</h4>
            <div class="sigint-btn-group">
                <button class="sigint-btn" onclick="startSigintScan('wifi')">
                    <i class="fas fa-wifi"></i> WiFi
                </button>
                <button class="sigint-btn" onclick="startSigintScan('bluetooth')">
                    <i class="fab fa-bluetooth-b"></i> Bluetooth
                </button>
                <button class="sigint-btn" onclick="startSigintScan('cell')">
                    <i class="fas fa-signal"></i> Hucresel
                </button>
                <button class="sigint-btn" onclick="startSigintScan('all')">
                    <i class="fas fa-broadcast-tower"></i> Tumunu Tara
                </button>
            </div>
        </div>

        <!-- Stats -->
        <div class="sigint-section">
            <h4>Istatistikler</h4>
            <div class="sigint-stats">
                <div class="stat-item">
                    <span class="stat-value" id="sigint-wifi-count">0</span>
                    <span class="stat-label">WiFi Agi</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value" id="sigint-bt-count">0</span>
                    <span class="stat-label">Bluetooth</span>
                </div>
                <div class="stat-item">
                    <span class="stat-value" id="sigint-cell-count">0</span>
                    <span class="stat-label">Baz Ist.</span>
                </div>
                <div class="stat-item threat">
                    <span class="stat-value" id="sigint-threat-count">0</span>
                    <span class="stat-label">Tehdit</span>
                </div>
            </div>
        </div>

        <!-- Layers -->
        <div class="sigint-section">
            <h4>Katmanlar</h4>
            <div class="sigint-layers">
                <label><input type="checkbox" id="layer-wifi" checked> WiFi Aglari</label>
                <label><input type="checkbox" id="layer-bt" checked> Bluetooth</label>
                <label><input type="checkbox" id="layer-cell" checked> Baz Istasyonlari</label>
                <label><input type="checkbox" id="layer-iot"> IoT Cihazlar</label>
                <label><input type="checkbox" id="layer-drones"> Dronlar</label>
                <label><input type="checkbox" id="layer-heatmap"> Tehdit Isisi</label>
            </div>
        </div>

        <!-- Threat Alerts -->
        <div class="sigint-section">
            <h4>Son Tehdit Uyarilari</h4>
            <div id="sigint-alerts" class="sigint-alerts">
                <!-- Dynamically populated -->
            </div>
        </div>
    </div>
</div>
```

---

## 6. Security Considerations

### 6.1 API Key Protection

```python
# All API keys stored in TSUNAMI Vault (dalga_vault.py)
# AES-256-GCM encryption with PBKDF2 key derivation

REQUIRED_API_KEYS = {
    'WIGLE_NAME': 'WiGLE API username',
    'WIGLE_TOKEN': 'WiGLE API token',
    'OPENCELLID_KEY': 'OpenCellID API key',
    'SHODAN_KEY': 'Shodan API key',
    'CENSYS_ID': 'Censys API ID',
    'CENSYS_SECRET': 'Censys API secret',
    'GOOGLE_GEOLOCATION_KEY': 'Google Geolocation API (optional)',
}
```

### 6.2 Stealth Modes

```python
class StealthLevel(Enum):
    """
    Operational security levels for SIGINT operations.
    """
    NORMAL = 0      # Standard operation, all features
    REDUCED = 1     # No API calls, local scanning only
    GHOST = 2       # Passive only, no transmissions

# Implementation:
# NORMAL: Full functionality
# REDUCED: Disable external API calls, use cached data
# GHOST: Passive WiFi/BT monitoring only (monitor mode)
#        No probe requests, no API calls, no writes to disk
```

### 6.3 Data Privacy

```python
# Privacy controls:
# 1. MAC address hashing (optional, configurable)
# 2. Location fuzzing (configurable precision)
# 3. Auto-expiry of old data
# 4. Secure deletion (overwrite on delete)
# 5. No cloud sync (all data local)
```

---

## 7. Implementation Phases

### Phase 1: Core Infrastructure (Week 1)
- [P] Create `dalga_sigint_core.py` - base classes and utilities
- [P] Create `dalga_sigint_db.py` - database operations
- [P] Integrate with existing `dalga_vault.py` for API keys
- [ ] Unit tests for core functionality

### Phase 2: Scanner Engines (Week 2)
- [P] WiFi scanner enhancement (monitor mode support)
- [P] Bluetooth scanner enhancement (BLE deep scan)
- [P] Cell tower scanner (multi-API)
- [P] IoT scanner (Shodan + Censys)
- [ ] Integration tests

### Phase 3: Classification & Correlation (Week 3)
- [P] Device classifier with 100+ categories
- [P] Threat correlator with IOC database
- [P] APT attribution engine
- [ ] ML model training (optional)

### Phase 4: Visualization (Week 4)
- [P] harita.html integration
- [P] Real-time WebSocket updates
- [P] Network topology graph
- [P] Timeline visualization
- [ ] UI/UX polish

### Phase 5: Advanced Features (Week 5)
- [P] Drone detection (if ADS-B hardware available)
- [P] SDR integration (if RTL-SDR available)
- [P] GPS tracker detection
- [P] RFID/NFC detection (if hardware available)
- [ ] Documentation

### Phase 6: Testing & Hardening (Week 6)
- [ ] Security audit
- [ ] Performance optimization
- [ ] Edge case handling
- [ ] Production deployment guide

**[P] = Parallelizable task**

---

## 8. File Structure

```
/home/lydian/Desktop/TSUNAMI/
|-- dalga.py                       # Original CLI (enhanced)
|-- dalga_web.py                   # Flask app (add SIGINT routes)
|-- dalga_vault.py                 # API key encryption (existing)
|-- dalga_threat_intel.py          # Threat IOC database (existing)
|
|-- dalga_sigint/                  # NEW: SIGINT module directory
|   |-- __init__.py
|   |-- core.py                    # Base classes, enums, types
|   |-- db.py                      # Database operations
|   |-- config.py                  # Configuration management
|   |
|   |-- scanners/                  # Scanner engines
|   |   |-- __init__.py
|   |   |-- wifi.py                # Enhanced WiFi scanner
|   |   |-- bluetooth.py           # Enhanced Bluetooth scanner
|   |   |-- cell.py                # Cell tower scanner
|   |   |-- iot.py                 # IoT device scanner
|   |   |-- drone.py               # Drone detection
|   |   |-- sdr.py                 # SDR signal analysis
|   |   |-- gps_tracker.py         # GPS tracker detection
|   |
|   |-- classifiers/               # Device classification
|   |   |-- __init__.py
|   |   |-- device_classifier.py   # Main classifier
|   |   |-- vendor_db.py           # OUI/vendor database
|   |   |-- fingerprints.py        # Device fingerprints
|   |
|   |-- correlators/               # Threat correlation
|   |   |-- __init__.py
|   |   |-- threat_correlator.py   # IOC matching
|   |   |-- apt_attribution.py     # APT group identification
|   |   |-- risk_scorer.py         # Risk scoring engine
|   |
|   |-- visualizers/               # Visualization
|   |   |-- __init__.py
|   |   |-- map_layers.py          # Leaflet layer generators
|   |   |-- topology_graph.py      # Network topology
|   |   |-- timeline.py            # Activity timeline
|   |
|   |-- api/                       # REST API
|   |   |-- __init__.py
|   |   |-- routes.py              # Flask routes
|   |   |-- websocket.py           # WebSocket handlers
|   |
|   |-- utils/                     # Utilities
|   |   |-- __init__.py
|   |   |-- oui_lookup.py          # MAC vendor lookup
|   |   |-- geo_utils.py           # Geolocation utilities
|   |   |-- export.py              # Export functions
|
|-- templates/
|   |-- harita.html                # Updated with SIGINT layers
|
|-- static/
|   |-- sigint/
|   |   |-- sigint.css             # SIGINT panel styles
|   |   |-- sigint.js              # SIGINT JavaScript
```

---

## 9. Dependencies

### 9.1 Required Python Packages

```txt
# Add to requirements.txt:

# Wireless scanning
scapy>=2.5.0              # Packet manipulation (optional, for advanced scanning)
pybluez>=0.23             # Bluetooth (optional, Linux)

# API clients
requests>=2.28.0          # HTTP client (existing)
aiohttp>=3.8.0            # Async HTTP (for concurrent API calls)

# Database
sqlalchemy>=2.0.0         # ORM (optional, can use raw SQLite)

# Geolocation
geopy>=2.3.0              # Geocoding utilities

# SDR (optional)
rtlsdr>=0.2.0             # RTL-SDR support

# Visualization (frontend)
# Leaflet, D3.js (CDN in harita.html)
```

### 9.2 System Dependencies (Linux)

```bash
# Required
apt install wireless-tools iw bluez

# Optional (for advanced features)
apt install rtl-sdr         # RTL-SDR support
apt install hackrf          # HackRF support
apt install aircrack-ng     # Monitor mode
apt install libnfc-dev      # NFC support
```

---

## 10. Summary

DALGA SIGINT module will provide:

1. **Multi-Protocol Scanning**: WiFi, Bluetooth, Cell, IoT, Drones, SDR
2. **Advanced Classification**: 100+ device categories with ML
3. **Threat Correlation**: Real-time IOC matching with 43K+ database
4. **Rich Visualization**: Integrated with TSUNAMI's F-35 cockpit UI
5. **Secure Operations**: AES-256 encrypted keys, stealth modes
6. **Turkish Interface**: Native language support
7. **Extensible Architecture**: Modular design for future additions

This architecture EXCEEDS WireTapper in every dimension while maintaining TSUNAMI's security standards and UI consistency.

---

**Document Version**: 1.0
**Last Updated**: 2026-02-03
**Author**: TSUNAMI Development Team
