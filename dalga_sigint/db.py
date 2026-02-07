"""
DALGA SIGINT Database - SQLite operations for device tracking
"""

import os
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from .core import (
    SigintDevice, WiFiNetwork, BluetoothDevice, CellTower, IoTDevice, Drone,
    DeviceType, DeviceCategory, ThreatLevel, RadioType, EncryptionType,
    ScanSession, get_threat_level_from_score
)


class SigintDatabase:
    """
    SQLite database manager for DALGA SIGINT
    Thread-safe with connection pooling
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, db_path: str = None):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self, db_path: str = None):
        if self._initialized:
            return

        if db_path is None:
            # Default: ~/.dalga/sigint.db
            dalga_dir = Path.home() / '.dalga'
            dalga_dir.mkdir(exist_ok=True)
            db_path = str(dalga_dir / 'sigint.db')

        self.db_path = db_path
        self._local = threading.local()
        self._init_database()
        self._initialized = True

    @property
    def conn(self) -> sqlite3.Connection:
        """Get thread-local connection"""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA foreign_keys = ON")
            self._local.conn.execute("PRAGMA journal_mode = WAL")
        return self._local.conn

    def _init_database(self):
        """Initialize database schema"""
        schema = """
        -- Wireless devices master table
        CREATE TABLE IF NOT EXISTS sigint_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT UNIQUE NOT NULL,
            device_type TEXT NOT NULL,
            mac_address TEXT,
            bssid TEXT,
            name TEXT,
            vendor TEXT,
            category TEXT,
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
            risk_score INTEGER DEFAULT 0,
            threat_level TEXT DEFAULT 'info',
            is_known_threat BOOLEAN DEFAULT 0,
            threat_ioc_id TEXT,
            metadata JSON,
            notes TEXT
        );

        -- WiFi specific data
        CREATE TABLE IF NOT EXISTS sigint_wifi (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            ssid TEXT,
            channel INTEGER,
            frequency INTEGER,
            bandwidth TEXT,
            encryption TEXT,
            cipher TEXT,
            auth_type TEXT,
            hidden BOOLEAN DEFAULT 0,
            wps_enabled BOOLEAN,
            client_count INTEGER DEFAULT 0,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Bluetooth specific data
        CREATE TABLE IF NOT EXISTS sigint_bluetooth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            device_class TEXT,
            service_classes TEXT,
            major_class TEXT,
            minor_class TEXT,
            bluetooth_version TEXT,
            le_supported BOOLEAN DEFAULT 0,
            manufacturer_data TEXT,
            services TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Cell tower data
        CREATE TABLE IF NOT EXISTS sigint_cell_towers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            cell_id TEXT,
            lac INTEGER,
            mcc INTEGER,
            mnc INTEGER,
            radio_type TEXT,
            operator TEXT,
            tower_type TEXT,
            azimuth INTEGER,
            range_m INTEGER,
            pci INTEGER,
            tac INTEGER,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- IoT device data
        CREATE TABLE IF NOT EXISTS sigint_iot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            ip_address TEXT,
            port INTEGER,
            protocol TEXT,
            product TEXT,
            version TEXT,
            os TEXT,
            cpe TEXT,
            cves TEXT,
            banner TEXT,
            http_title TEXT,
            ssl_cert_issuer TEXT,
            ssl_cert_subject TEXT,
            ssl_cert_fingerprint TEXT,
            open_ports TEXT,
            shodan_id TEXT,
            censys_id TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Drone detection data
        CREATE TABLE IF NOT EXISTS sigint_drones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            drone_model TEXT,
            manufacturer TEXT,
            serial_number TEXT,
            pilot_lat REAL,
            pilot_lon REAL,
            altitude_m REAL,
            speed_mps REAL,
            heading INTEGER,
            home_lat REAL,
            home_lon REAL,
            rf_frequency REAL,
            signal_type TEXT,
            flight_id TEXT,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            metadata TEXT
        );

        -- Device location history
        CREATE TABLE IF NOT EXISTS sigint_location_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            latitude REAL,
            longitude REAL,
            altitude REAL,
            signal_strength INTEGER,
            source TEXT
        );

        -- Device relationships (network topology)
        CREATE TABLE IF NOT EXISTS sigint_device_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_a_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            device_b_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            relationship_type TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            connection_count INTEGER DEFAULT 1,
            metadata TEXT
        );

        -- Scan sessions
        CREATE TABLE IF NOT EXISTS sigint_scan_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ended_at TIMESTAMP,
            scan_type TEXT,
            location_lat REAL,
            location_lon REAL,
            devices_found INTEGER DEFAULT 0,
            threats_detected INTEGER DEFAULT 0,
            parameters TEXT,
            status TEXT DEFAULT 'running'
        );

        -- Threat correlations
        CREATE TABLE IF NOT EXISTS sigint_threat_correlations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES sigint_devices(device_id) ON DELETE CASCADE,
            ioc_type TEXT,
            ioc_value TEXT,
            threat_source TEXT,
            threat_category TEXT,
            severity TEXT,
            confidence REAL,
            first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved BOOLEAN DEFAULT 0,
            resolution_notes TEXT
        );

        -- Indexes for performance
        CREATE INDEX IF NOT EXISTS idx_devices_type ON sigint_devices(device_type);
        CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON sigint_devices(last_seen);
        CREATE INDEX IF NOT EXISTS idx_devices_risk ON sigint_devices(risk_score);
        CREATE INDEX IF NOT EXISTS idx_devices_threat ON sigint_devices(is_known_threat);
        CREATE INDEX IF NOT EXISTS idx_wifi_ssid ON sigint_wifi(ssid);
        CREATE INDEX IF NOT EXISTS idx_location_device ON sigint_location_history(device_id);
        CREATE INDEX IF NOT EXISTS idx_location_time ON sigint_location_history(timestamp);
        CREATE INDEX IF NOT EXISTS idx_threats_device ON sigint_threat_correlations(device_id);
        CREATE INDEX IF NOT EXISTS idx_relationships ON sigint_device_relationships(device_a_id, device_b_id);
        """

        cursor = self.conn.cursor()
        cursor.executescript(schema)
        self.conn.commit()

    # ==================== Device Operations ====================

    def upsert_device(self, device: SigintDevice) -> str:
        """Insert or update a device"""
        cursor = self.conn.cursor()

        # Check if exists
        cursor.execute(
            "SELECT id, seen_count FROM sigint_devices WHERE device_id = ?",
            (device.device_id,)
        )
        existing = cursor.fetchone()

        metadata_json = json.dumps(device.metadata) if device.metadata else None

        if existing:
            # Update existing
            cursor.execute("""
                UPDATE sigint_devices SET
                    name = COALESCE(?, name),
                    vendor = COALESCE(?, vendor),
                    category = ?,
                    last_seen = CURRENT_TIMESTAMP,
                    seen_count = seen_count + 1,
                    latitude = COALESCE(?, latitude),
                    longitude = COALESCE(?, longitude),
                    signal_strength = ?,
                    risk_score = ?,
                    threat_level = ?,
                    is_known_threat = ?,
                    metadata = ?
                WHERE device_id = ?
            """, (
                device.name, device.vendor, device.category.value,
                device.latitude, device.longitude, device.signal_strength,
                device.risk_score, device.threat_level.value, device.is_known_threat,
                metadata_json, device.device_id
            ))
        else:
            # Insert new
            cursor.execute("""
                INSERT INTO sigint_devices (
                    device_id, device_type, mac_address, bssid, name, vendor,
                    category, subcategory, latitude, longitude, altitude,
                    accuracy_m, signal_strength, signal_quality, risk_score,
                    threat_level, is_known_threat, threat_ioc_id, metadata, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device.device_id, device.device_type.value, device.mac_address,
                device.bssid, device.name, device.vendor, device.category.value,
                device.subcategory, device.latitude, device.longitude,
                device.altitude, device.accuracy_m, device.signal_strength,
                device.signal_quality, device.risk_score, device.threat_level.value,
                device.is_known_threat, device.threat_ioc_id, metadata_json, device.notes
            ))

        self.conn.commit()

        # Record location history if coordinates present
        if device.latitude and device.longitude:
            self.add_location_history(
                device.device_id, device.latitude, device.longitude,
                device.altitude, device.signal_strength, 'local'
            )

        return device.device_id

    def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device by ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM sigint_devices WHERE device_id = ?", (device_id,))
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def get_devices(
        self,
        device_type: Optional[DeviceType] = None,
        threat_level: Optional[ThreatLevel] = None,
        min_risk_score: int = 0,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get devices with filters"""
        cursor = self.conn.cursor()

        query = "SELECT * FROM sigint_devices WHERE 1=1"
        params = []

        if device_type:
            query += " AND device_type = ?"
            params.append(device_type.value)

        if threat_level:
            query += " AND threat_level = ?"
            params.append(threat_level.value)

        if min_risk_score > 0:
            query += " AND risk_score >= ?"
            params.append(min_risk_score)

        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

    def get_device_count(self, device_type: Optional[DeviceType] = None) -> int:
        """Get total device count"""
        cursor = self.conn.cursor()
        if device_type:
            cursor.execute(
                "SELECT COUNT(*) FROM sigint_devices WHERE device_type = ?",
                (device_type.value,)
            )
        else:
            cursor.execute("SELECT COUNT(*) FROM sigint_devices")
        return cursor.fetchone()[0]

    def delete_device(self, device_id: str) -> bool:
        """Delete device and related data"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM sigint_devices WHERE device_id = ?", (device_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    # ==================== WiFi Operations ====================

    def upsert_wifi(self, network: WiFiNetwork) -> str:
        """Insert or update WiFi network"""
        # First upsert base device
        self.upsert_device(network)

        cursor = self.conn.cursor()

        # Check if WiFi record exists
        cursor.execute(
            "SELECT id FROM sigint_wifi WHERE device_id = ?",
            (network.device_id,)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE sigint_wifi SET
                    ssid = ?, channel = ?, frequency = ?, bandwidth = ?,
                    encryption = ?, cipher = ?, auth_type = ?, hidden = ?,
                    wps_enabled = ?, client_count = ?, last_seen = CURRENT_TIMESTAMP
                WHERE device_id = ?
            """, (
                network.ssid, network.channel, network.frequency, network.bandwidth,
                network.encryption.value if network.encryption else None,
                network.cipher, network.auth_type, network.hidden,
                network.wps_enabled, network.client_count, network.device_id
            ))
        else:
            cursor.execute("""
                INSERT INTO sigint_wifi (
                    device_id, ssid, channel, frequency, bandwidth, encryption,
                    cipher, auth_type, hidden, wps_enabled, client_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                network.device_id, network.ssid, network.channel, network.frequency,
                network.bandwidth, network.encryption.value if network.encryption else None,
                network.cipher, network.auth_type, network.hidden,
                network.wps_enabled, network.client_count
            ))

        self.conn.commit()
        return network.device_id

    def get_wifi_networks(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all WiFi networks with details"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT d.*, w.ssid, w.channel, w.frequency, w.encryption,
                   w.hidden, w.wps_enabled, w.client_count
            FROM sigint_devices d
            LEFT JOIN sigint_wifi w ON d.device_id = w.device_id
            WHERE d.device_type = 'wifi'
            ORDER BY d.last_seen DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ==================== Bluetooth Operations ====================

    def upsert_bluetooth(self, device: BluetoothDevice) -> str:
        """Insert or update Bluetooth device"""
        self.upsert_device(device)

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id FROM sigint_bluetooth WHERE device_id = ?",
            (device.device_id,)
        )
        existing = cursor.fetchone()

        services_json = json.dumps(device.services) if device.services else None
        service_classes_json = json.dumps(device.service_classes) if device.service_classes else None

        if existing:
            cursor.execute("""
                UPDATE sigint_bluetooth SET
                    device_class = ?, service_classes = ?, major_class = ?,
                    minor_class = ?, bluetooth_version = ?, le_supported = ?,
                    manufacturer_data = ?, services = ?, last_seen = CURRENT_TIMESTAMP
                WHERE device_id = ?
            """, (
                device.device_class, service_classes_json, device.major_class,
                device.minor_class, device.bluetooth_version, device.le_supported,
                device.manufacturer_data, services_json, device.device_id
            ))
        else:
            cursor.execute("""
                INSERT INTO sigint_bluetooth (
                    device_id, device_class, service_classes, major_class,
                    minor_class, bluetooth_version, le_supported,
                    manufacturer_data, services
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device.device_id, device.device_class, service_classes_json,
                device.major_class, device.minor_class, device.bluetooth_version,
                device.le_supported, device.manufacturer_data, services_json
            ))

        self.conn.commit()
        return device.device_id

    def get_bluetooth_devices(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all Bluetooth devices with details"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT d.*, b.device_class, b.major_class, b.minor_class,
                   b.bluetooth_version, b.le_supported
            FROM sigint_devices d
            LEFT JOIN sigint_bluetooth b ON d.device_id = b.device_id
            WHERE d.device_type = 'bluetooth'
            ORDER BY d.last_seen DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ==================== Cell Tower Operations ====================

    def upsert_cell_tower(self, tower: CellTower) -> str:
        """Insert or update cell tower"""
        self.upsert_device(tower)

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id FROM sigint_cell_towers WHERE device_id = ?",
            (tower.device_id,)
        )
        existing = cursor.fetchone()

        if existing:
            cursor.execute("""
                UPDATE sigint_cell_towers SET
                    cell_id = ?, lac = ?, mcc = ?, mnc = ?, radio_type = ?,
                    operator = ?, tower_type = ?, azimuth = ?, range_m = ?,
                    pci = ?, tac = ?, last_seen = CURRENT_TIMESTAMP
                WHERE device_id = ?
            """, (
                tower.cell_id, tower.lac, tower.mcc, tower.mnc,
                tower.radio_type.value if tower.radio_type else None,
                tower.operator, tower.tower_type, tower.azimuth, tower.range_m,
                tower.pci, tower.tac, tower.device_id
            ))
        else:
            cursor.execute("""
                INSERT INTO sigint_cell_towers (
                    device_id, cell_id, lac, mcc, mnc, radio_type,
                    operator, tower_type, azimuth, range_m, pci, tac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tower.device_id, tower.cell_id, tower.lac, tower.mcc, tower.mnc,
                tower.radio_type.value if tower.radio_type else None,
                tower.operator, tower.tower_type, tower.azimuth, tower.range_m,
                tower.pci, tower.tac
            ))

        self.conn.commit()
        return tower.device_id

    def get_cell_towers(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all cell towers with details"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT d.*, c.cell_id, c.lac, c.mcc, c.mnc, c.radio_type,
                   c.operator, c.tower_type, c.range_m
            FROM sigint_devices d
            LEFT JOIN sigint_cell_towers c ON d.device_id = c.device_id
            WHERE d.device_type = 'cell'
            ORDER BY d.last_seen DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ==================== IoT Operations ====================

    def upsert_iot(self, device: IoTDevice) -> str:
        """Insert or update IoT device"""
        self.upsert_device(device)

        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id FROM sigint_iot WHERE device_id = ?",
            (device.device_id,)
        )
        existing = cursor.fetchone()

        cves_json = json.dumps(device.cves) if device.cves else None
        ports_json = json.dumps(device.open_ports) if device.open_ports else None

        if existing:
            cursor.execute("""
                UPDATE sigint_iot SET
                    ip_address = ?, port = ?, protocol = ?, product = ?,
                    version = ?, os = ?, cpe = ?, cves = ?, banner = ?,
                    http_title = ?, ssl_cert_issuer = ?, ssl_cert_subject = ?,
                    ssl_cert_fingerprint = ?, open_ports = ?, shodan_id = ?,
                    censys_id = ?, last_seen = CURRENT_TIMESTAMP
                WHERE device_id = ?
            """, (
                device.ip_address, device.port, device.protocol, device.product,
                device.version, device.os, device.cpe, cves_json, device.banner,
                device.http_title, device.ssl_cert_issuer, device.ssl_cert_subject,
                device.ssl_cert_fingerprint, ports_json, device.shodan_id,
                device.censys_id, device.device_id
            ))
        else:
            cursor.execute("""
                INSERT INTO sigint_iot (
                    device_id, ip_address, port, protocol, product, version,
                    os, cpe, cves, banner, http_title, ssl_cert_issuer,
                    ssl_cert_subject, ssl_cert_fingerprint, open_ports,
                    shodan_id, censys_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device.device_id, device.ip_address, device.port, device.protocol,
                device.product, device.version, device.os, device.cpe, cves_json,
                device.banner, device.http_title, device.ssl_cert_issuer,
                device.ssl_cert_subject, device.ssl_cert_fingerprint, ports_json,
                device.shodan_id, device.censys_id
            ))

        self.conn.commit()
        return device.device_id

    def get_iot_devices(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all IoT devices with details"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT d.*, i.ip_address, i.port, i.product, i.version,
                   i.os, i.cves, i.open_ports
            FROM sigint_devices d
            LEFT JOIN sigint_iot i ON d.device_id = i.device_id
            WHERE d.device_type = 'iot'
            ORDER BY d.last_seen DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ==================== Location History ====================

    def add_location_history(
        self,
        device_id: str,
        latitude: float,
        longitude: float,
        altitude: Optional[float] = None,
        signal_strength: Optional[int] = None,
        source: str = 'local'
    ):
        """Add location history entry"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO sigint_location_history (
                device_id, latitude, longitude, altitude, signal_strength, source
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (device_id, latitude, longitude, altitude, signal_strength, source))
        self.conn.commit()

    def get_location_history(
        self,
        device_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get device location history"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM sigint_location_history
            WHERE device_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (device_id, limit))
        return [dict(row) for row in cursor.fetchall()]

    # ==================== Threat Correlations ====================

    def add_threat_correlation(
        self,
        device_id: str,
        ioc_type: str,
        ioc_value: str,
        threat_source: str,
        threat_category: str,
        severity: str,
        confidence: float
    ):
        """Add threat correlation for a device"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO sigint_threat_correlations (
                device_id, ioc_type, ioc_value, threat_source,
                threat_category, severity, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id, ioc_type, ioc_value, threat_source,
            threat_category, severity, confidence
        ))

        # Update device threat status
        risk_score = int(confidence * 100)
        threat_level = get_threat_level_from_score(risk_score)

        cursor.execute("""
            UPDATE sigint_devices SET
                is_known_threat = 1,
                risk_score = MAX(risk_score, ?),
                threat_level = ?
            WHERE device_id = ?
        """, (risk_score, threat_level.value, device_id))

        self.conn.commit()

    def get_device_threats(self, device_id: str) -> List[Dict[str, Any]]:
        """Get all threat correlations for a device"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM sigint_threat_correlations
            WHERE device_id = ?
            ORDER BY last_detected DESC
        """, (device_id,))
        return [dict(row) for row in cursor.fetchall()]

    def get_all_threats(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get all threat correlations"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT t.*, d.name as device_name, d.device_type
            FROM sigint_threat_correlations t
            JOIN sigint_devices d ON t.device_id = d.device_id
            WHERE t.resolved = 0
            ORDER BY t.last_detected DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ==================== Scan Sessions ====================

    def create_scan_session(self, session: ScanSession) -> str:
        """Create new scan session"""
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT INTO sigint_scan_sessions (
                session_id, scan_type, location_lat, location_lon, parameters
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            session.session_id, session.scan_type,
            session.location_lat, session.location_lon,
            json.dumps(session.parameters)
        ))
        self.conn.commit()
        return session.session_id

    def complete_scan_session(
        self,
        session_id: str,
        devices_found: int,
        threats_detected: int,
        status: str = 'completed'
    ):
        """Mark scan session as complete"""
        cursor = self.conn.cursor()
        cursor.execute("""
            UPDATE sigint_scan_sessions SET
                ended_at = CURRENT_TIMESTAMP,
                devices_found = ?,
                threats_detected = ?,
                status = ?
            WHERE session_id = ?
        """, (devices_found, threats_detected, status, session_id))
        self.conn.commit()

    def get_scan_sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get scan session history"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM sigint_scan_sessions
            ORDER BY started_at DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    # ==================== Statistics ====================

    def get_statistics(self) -> Dict[str, Any]:
        """Get overall statistics"""
        cursor = self.conn.cursor()

        stats = {
            'total_devices': 0,
            'by_type': {},
            'threats': {
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'recent_24h': 0,
            'recent_7d': 0
        }

        # Total devices by type
        cursor.execute("""
            SELECT device_type, COUNT(*) as count
            FROM sigint_devices
            GROUP BY device_type
        """)
        for row in cursor.fetchall():
            stats['by_type'][row['device_type']] = row['count']
            stats['total_devices'] += row['count']

        # Threat counts
        cursor.execute("""
            SELECT threat_level, COUNT(*) as count
            FROM sigint_devices
            WHERE is_known_threat = 1
            GROUP BY threat_level
        """)
        for row in cursor.fetchall():
            level = row['threat_level']
            if level in stats['threats']:
                stats['threats'][level] = row['count']
                stats['threats']['total'] += row['count']

        # Recent activity
        cursor.execute("""
            SELECT COUNT(*) FROM sigint_devices
            WHERE last_seen > datetime('now', '-1 day')
        """)
        stats['recent_24h'] = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*) FROM sigint_devices
            WHERE last_seen > datetime('now', '-7 days')
        """)
        stats['recent_7d'] = cursor.fetchone()[0]

        return stats

    # ==================== Cleanup ====================

    def cleanup_old_data(self, days: int = 90):
        """Remove data older than specified days"""
        cursor = self.conn.cursor()

        cutoff = datetime.now() - timedelta(days=days)
        cutoff_str = cutoff.strftime('%Y-%m-%d %H:%M:%S')

        # Delete old location history
        cursor.execute(
            "DELETE FROM sigint_location_history WHERE timestamp < ?",
            (cutoff_str,)
        )

        # Delete old devices (cascades to related tables)
        cursor.execute(
            "DELETE FROM sigint_devices WHERE last_seen < ?",
            (cutoff_str,)
        )

        self.conn.commit()
        return cursor.rowcount

    def close(self):
        """Close database connection"""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
