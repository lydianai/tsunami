#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI IoT Monitor Module
Palantir-style IoT device monitoring and multi-source data fusion
Integrates Shodan API, MQTT brokers, and real-time sensor data
"""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime
import asyncio
import json
import logging
import aiohttp
import paho.mqtt.client as mqtt
from threading import Thread
import queue

logger = logging.getLogger(__name__)


@dataclass
class IoTDevice:
    """
    IoT device metadata and real-time status
    Palantir-style multi-source device tracking
    """
    device_id: str
    name: str
    device_type: str  # camera/sensor/lock/router/iot/industrial/medical
    location: List[float]  # [latitude, longitude]
    ip_address: str
    mac_address: str = ''
    status: str = 'online'  # online/offline/error/alert
    protocol: str = ''  # mqtt/http/coap/modbus
    port: int = 0
    manufacturer: str = ''
    model: str = ''
    firmware_version: str = ''
    last_seen: datetime = field(default_factory=datetime.now)
    vulnerability_count: int = 0
    open_ports: List[int] = field(default_factory=list)
    sensors: List[str] = field(default_factory=list)  # temperature/humidity/motion/door/window
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['last_seen'] = self.last_seen.isoformat()
        return data

    def to_geojson(self) -> Dict[str, Any]:
        """Convert to GeoJSON format for Leaflet map"""
        return {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [self.location[1], self.location[0]]
            },
            "properties": {
                "id": self.device_id,
                "name": self.name,
                "device_type": self.device_type,
                "status": self.status,
                "protocol": self.protocol,
                "manufacturer": self.manufacturer,
                "ip_address": self.ip_address,
                "vulnerability_count": self.vulnerability_count,
                "sensors": self.sensors,
                "last_seen": self.last_seen.isoformat()
            }
        }


class IoTMonitor:
    """
    Manages IoT devices and real-time sensor data
    Palantir-style multi-source monitoring
    """

    def __init__(self):
        self.devices: Dict[str, IoTDevice] = {}
        self.active_streams: Dict[str, Any] = {}
        self.device_stats: Dict[str, Dict] = {}
        self.mqtt_client = None
        self.mqtt_queue = queue.Queue()

        # Zoom-based device limits (Palantir-style performance)
        self.zoom_limits = {
            1: 10,    # Country view - 10 devices
            2: 25,    # Regional view - 25 devices
            3: 50,    # City view - 50 devices
            4: 100,   # District view - 100 devices
            5: 200,   # Neighborhood view - 200 devices
            6: 500,   # Street view - 500 devices
            7: 1000,  # Building view - 1000 devices
            8: 2000   # Detailed view - 2000 devices
        }

        # Initialize with sample IoT devices
        self._initialize_sample_devices()

        # Setup MQTT client
        self._setup_mqtt_client()

    def _initialize_sample_devices(self):
        """
        Initialize with sample IoT devices from major Turkish cities
        Palantir-style multi-category coverage
        """
        sample_devices = [
            {
                "device_id": "iot-istanbul-sensor-001",
                "name": "İstanbul Hava Kalite Sensörü",
                "device_type": "sensor",
                "location": [41.0082, 28.9784],
                "ip_address": "192.168.1.101",
                "mac_address": "00:1B:44:11:3A:B7",
                "status": "online",
                "protocol": "mqtt",
                "manufacturer": "Bosch",
                "model": "AQMS",
                "sensors": ["temperature", "humidity", "pm25"],
                "metadata": {"building": "Havalimanı", "floor": 2}
            },
            {
                "device_id": "iot-ankara-lock-001",
                "name": "Ankara Devlet Kapısı Kiliti",
                "device_type": "lock",
                "location": [39.9208, 32.8541],
                "ip_address": "10.0.0.51",
                "mac_address": "00:1A:2B:3C:4D:5E",
                "status": "online",
                "protocol": "http",
                "manufacturer": "Assa Abloy",
                "model": "SMARTair",
                "sensors": ["door", "motion"],
                "metadata": {"building": "Devlet Bakanlığı", "floor": 1}
            },
            {
                "device_id": "iot-izmir-camera-001",
                "name": "İzmir Limanı Güvenlik Kamerası",
                "device_type": "camera",
                "location": [38.4237, 27.1428],
                "ip_address": "172.16.0.201",
                "mac_address": "00:11:22:33:44:55",
                "status": "online",
                "protocol": "rtsp",
                "port": 554,
                "manufacturer": "Hikvision",
                "model": "DS-2CD2043G0",
                "sensors": ["motion"],
                "metadata": {"building": "Liman İşletmesi", "floor": 3}
            },
            {
                "device_id": "iot-bursa-router-001",
                "name": "Bursa Sanayi Bölgesi Router",
                "device_type": "router",
                "location": [40.1885, 29.0610],
                "ip_address": "212.154.10.50",
                "mac_address": "AA:BB:CC:DD:EE:FF",
                "status": "online",
                "protocol": "http",
                "port": 80,
                "manufacturer": "Cisco",
                "model": "Catalyst 9300",
                "open_ports": [22, 80, 443, 8080],
                "vulnerability_count": 2,
                "metadata": {"building": "Sanayi Tesisi", "network": "corporate"}
            },
            {
                "device_id": "iot-istanbul-industrial-001",
                "name": "İstanbul Endüstriyel PLC",
                "device_type": "industrial",
                "location": [41.0378, 28.9770],
                "ip_address": "10.20.30.40",
                "mac_address": "DE:AD:BE:EF:CA:FE",
                "status": "online",
                "protocol": "modbus",
                "port": 502,
                "manufacturer": "Siemens",
                "model": "S7-1500",
                "sensors": ["temperature", "pressure", "flow"],
                "vulnerability_count": 5,
                "metadata": {"building": "Üretim Tesisi", "line": 1}
            },
            {
                "device_id": "iot-ankara-medical-001",
                "name": "Ankara Şehir Hastanesi Medikal Cihaz",
                "device_type": "medical",
                "location": [39.9334, 32.8597],
                "ip_address": "192.168.100.15",
                "mac_address": "12:34:56:78:9A:BC",
                "status": "online",
                "protocol": "http",
                "manufacturer": "Philips",
                "model": "MX450",
                "sensors": ["ecg", "spo2", "temperature"],
                "metadata": {"building": "Hastane", "department": "YOÜB"}
            }
        ]

        for device_data in sample_devices:
            device = IoTDevice(**device_data)
            self.add_device(device)

        logger.info(f"Initialized {len(sample_devices)} sample IoT devices")

    def _setup_mqtt_client(self):
        """Setup MQTT client for real-time sensor data"""
        try:
            self.mqtt_client = mqtt.Client(client_id="tsunami_iot_monitor", protocol=3)
            self.mqtt_client.on_connect = self._on_mqtt_connect
            self.mqtt_client.on_message = self._on_mqtt_message
            self.mqtt_client.on_disconnect = self._on_mqtt_disconnect

            # Connect to MQTT broker (replace with actual broker)
            # self.mqtt_client.connect("localhost", 1883, 60)

            # Start MQTT loop in background thread
            # mqtt_thread = Thread(target=self._mqtt_loop, daemon=True)
            # mqtt_thread.start()

            logger.info("MQTT client configured (not connected)")
        except Exception as e:
            logger.error(f"Error setting up MQTT client: {str(e)}")

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        """MQTT connect callback"""
        if rc == 0:
            logger.info("MQTT client connected successfully")
            # Subscribe to IoT topics
            client.subscribe("sensors/+/data")
            client.subscribe("devices/+/status")
        else:
            logger.error(f"MQTT connection failed with code {rc}")

    def _on_mqtt_message(self, client, userdata, msg):
        """MQTT message callback"""
        try:
            topic = msg.topic
            payload = msg.payload.decode('utf-8')
            data = json.loads(payload)

            # Update device status from MQTT
            device_id = data.get('device_id')
            if device_id and device_id in self.devices:
                self.update_device_status(device_id, data.get('status', 'online'))
                logger.debug(f"MQTT update: {device_id} from topic {topic}")

        except Exception as e:
            logger.error(f"Error processing MQTT message: {str(e)}")

    def _on_mqtt_disconnect(self, client, userdata, rc):
        """MQTT disconnect callback"""
        if rc != 0:
            logger.warning(f"MQTT client disconnected with code {rc}")

    def _mqtt_loop(self):
        """MQTT background loop"""
        try:
            self.mqtt_client.loop_forever()
        except Exception as e:
            logger.error(f"MQTT loop error: {str(e)}")

    def add_device(self, device: IoTDevice) -> bool:
        """
        Add new IoT device to the system
        Returns True if successful, False otherwise
        """
        try:
            self.devices[device.device_id] = device
            self.device_stats[device.device_id] = {
                "added_at": datetime.now().isoformat(),
                "requests_count": 0,
                "last_accessed": None,
                "sensor_readings": 0
            }
            logger.info(f"Added IoT device: {device.device_id} - {device.name}")
            return True
        except Exception as e:
            logger.error(f"Error adding device {device.device_id}: {str(e)}")
            return False

    def remove_device(self, device_id: str) -> bool:
        """Remove device from system"""
        if device_id in self.devices:
            del self.devices[device_id]
            if device_id in self.device_stats:
                del self.device_stats[device_id]
            logger.info(f"Removed IoT device: {device_id}")
            return True
        return False

    def get_device(self, device_id: str) -> Optional[IoTDevice]:
        """Get specific device by ID"""
        return self.devices.get(device_id)

    def get_active_devices(self, zoom_level: int = 6,
                          status_filter: Optional[str] = None,
                          type_filter: Optional[str] = None) -> List[Dict]:
        """
        Get devices filtered by zoom level (Palantir-style performance optimization)

        Args:
            zoom_level: Map zoom level (1-8)
            status_filter: Optional status filter ('online', 'offline', 'error', 'alert')
            type_filter: Optional device type filter

        Returns:
            List of device dictionaries
        """
        max_devices = self.zoom_limits.get(zoom_level, 500)

        devices = list(self.devices.values())

        # Filter by status if specified
        if status_filter:
            devices = [d for d in devices if d.status == status_filter]

        # Filter by type if specified
        if type_filter:
            devices = [d for d in devices if d.device_type == type_filter]

        # Sort by last seen (newest first)
        devices.sort(key=lambda x: x.last_seen, reverse=True)

        # Limit by zoom level
        devices = devices[:max_devices]

        # Update device stats
        for device in devices:
            if device.device_id in self.device_stats:
                self.device_stats[device.device_id]["requests_count"] += 1
                self.device_stats[device.device_id]["last_accessed"] = datetime.now().isoformat()

        return [device.to_dict() for device in devices]

    def get_devices_by_region(self, lat: float, lon: float,
                             radius_km: int = 10) -> List[Dict]:
        """
        Get devices within geographic radius
        Palantir-style regional filtering

        Args:
            lat: Center latitude
            lon: Center longitude
            radius_km: Search radius in kilometers

        Returns:
            List of devices within radius
        """
        from math import radians, cos, sin, asin, sqrt

        def haversine_distance(lat1, lon1, lat2, lon2):
            """Calculate distance between two points in km"""
            lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
            dlat = lat2 - lat1
            dlon = lon2 - lon1
            a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
            c = 2 * asin(sqrt(a))
            return 6371 * c

        devices_in_region = []

        for device in self.devices.values():
            distance = haversine_distance(lat, lon, device.location[0], device.location[1])
            if distance <= radius_km:
                devices_in_region.append(device.to_dict())

        return devices_in_region

    async def search_shodan_devices(self, query: str, radius_km: int = 10,
                                    limit: int = 100) -> List[Dict]:
        """
        Search for IoT devices using Shodan API
        Palantir-style external data integration

        Args:
            query: Shodan search query
            radius_km: Geographic search radius
            limit: Maximum results

        Returns:
            List of discovered devices
        """
        try:
            # Shodan API integration (replace with actual API key)
            shodan_api_key = "YOUR_SHODAN_API_KEY"
            url = f"https://api.shodan.io/shodan/host/search?key={shodan_api_key}&query={query}&limit={limit}"

            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        discovered_devices = []

                        for match in data.get('matches', [])[:limit]:
                            # Convert Shodan result to IoTDevice
                            device_data = {
                                "device_id": f"shodan-{match.get('ip_str', 'unknown')}",
                                "name": match.get('hostnames', ['Unknown'])[0] if match.get('hostnames') else match.get('ip_str', 'Unknown'),
                                "device_type": self._classify_shodan_device(match),
                                "location": [0, 0],  # Shodan doesn't provide location
                                "ip_address": match.get('ip_str', ''),
                                "mac_address": '',
                                "status": "online",
                                "protocol": match.get('port', 0) > 0,
                                "port": match.get('port', 0),
                                "manufacturer": "",
                                "model": "",
                                "open_ports": match.get('ports', []),
                                "vulnerability_count": match.get('vulns', 0),
                                "metadata": {"shodan_data": match}
                            }

                            discovered_devices.append(device_data)

                        logger.info(f"Discovered {len(discovered_devices)} devices from Shodan")
                        return discovered_devices
                    else:
                        logger.error(f"Shodan API error: {response.status}")
                        return []

        except Exception as e:
            logger.error(f"Error searching Shodan: {str(e)}")
            return []

    def _classify_shodan_device(self, shodan_data: Dict) -> str:
        """Classify device type from Shodan data"""
        ports = shodan_data.get('ports', [])
        if 80 in ports or 443 in ports or 8080 in ports:
            return "router"
        elif 554 in ports or 554 in ports:
            return "camera"
        elif 502 in ports or 502 in ports:
            return "industrial"
        elif 161 in ports:
            return "sensor"
        else:
            return "iot"

    def get_device_statistics(self) -> Dict[str, Any]:
        """
        Get overall IoT system statistics
        Palantir-style dashboard metrics
        """
        total_devices = len(self.devices)
        online_devices = sum(1 for d in self.devices.values() if d.status == 'online')
        offline_devices = sum(1 for d in self.devices.values() if d.status == 'offline')
        error_devices = sum(1 for d in self.devices.values() if d.status == 'error')
        alert_devices = sum(1 for d in self.devices.values() if d.status == 'alert')

        devices_by_type = {}
        for device in self.devices.values():
            devices_by_type[device.device_type] = devices_by_type.get(device.device_type, 0) + 1

        devices_by_protocol = {}
        for device in self.devices.values():
            devices_by_protocol[device.protocol] = devices_by_protocol.get(device.protocol, 0) + 1

        # Vulnerability statistics
        total_vulnerabilities = sum(d.vulnerability_count for d in self.devices.values())
        high_risk_devices = sum(1 for d in self.devices.values() if d.vulnerability_count > 5)

        # Sensor statistics
        all_sensors = {}
        for device in self.devices.values():
            for sensor in device.sensors:
                all_sensors[sensor] = all_sensors.get(sensor, 0) + 1

        return {
            "total_devices": total_devices,
            "online": online_devices,
            "offline": offline_devices,
            "error": error_devices,
            "alert": alert_devices,
            "uptime_percentage": round((online_devices / total_devices * 100) if total_devices > 0 else 0, 2),
            "by_type": devices_by_type,
            "by_protocol": devices_by_protocol,
            "total_vulnerabilities": total_vulnerabilities,
            "high_risk_devices": high_risk_devices,
            "sensor_types": all_sensors,
            "total_requests": sum(stats.get("requests_count", 0) for stats in self.device_stats.values()),
            "sensor_readings": sum(stats.get("sensor_readings", 0) for stats in self.device_stats.values())
        }

    def update_device_status(self, device_id: str, status: str) -> bool:
        """
        Update device status
        Used for health checks and monitoring
        """
        device = self.devices.get(device_id)
        if device:
            device.status = status
            device.last_seen = datetime.now()
            if device_id in self.device_stats:
                self.device_stats[device_id]["sensor_readings"] += 1
            logger.info(f"Updated device {device_id} status to {status}")
            return True
        return False

    def get_device_geojson(self, zoom_level: int = 6,
                          status_filter: Optional[str] = None,
                          type_filter: Optional[str] = None) -> Dict[str, Any]:
        """
        Get all devices as GeoJSON FeatureCollection
        For direct Leaflet.js integration
        """
        devices = self.get_active_devices(zoom_level, status_filter, type_filter)

        features = []
        for device_dict in devices:
            device = self.devices.get(device_dict['device_id'])
            if device:
                features.append(device.to_geojson())

        return {
            "type": "FeatureCollection",
            "features": features
        }

    async def process_mqtt_messages(self):
        """Process MQTT messages from queue"""
        while True:
            try:
                if not self.mqtt_queue.empty():
                    topic, payload = self.mqtt_queue.get()
                    # Process sensor data
                    await self._handle_sensor_data(topic, payload)
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"Error processing MQTT queue: {str(e)}")

    async def _handle_sensor_data(self, topic: str, payload: Any):
        """Handle incoming sensor data"""
        try:
            data = json.loads(payload) if isinstance(payload, str) else payload
            device_id = data.get('device_id')

            if device_id and device_id in self.devices:
                # Update device with new sensor reading
                device = self.devices[device_id]
                device.metadata.update(data)
                device.last_seen = datetime.now()

                # Check for alerts
                if data.get('alert'):
                    device.status = 'alert'
                    logger.warning(f"Alert on device {device_id}: {data.get('message')}")

        except Exception as e:
            logger.error(f"Error handling sensor data: {str(e)}")


# Global singleton instance
_iot_monitor = None

def get_iot_monitor() -> IoTMonitor:
    """Get or create global IoT monitor instance"""
    global _iot_monitor
    if _iot_monitor is None:
        _iot_monitor = IoTMonitor()
        logger.info("Created global IoTMonitor instance")
    return _iot_monitor


# Export key functions for Flask routes
def add_iot_device(device_data: Dict) -> bool:
    """Add IoT device from dictionary data"""
    device = IoTDevice(**device_data)
    monitor = get_iot_monitor()
    return monitor.add_device(device)


def get_active_devices(zoom_level: int = 6, status_filter: Optional[str] = None,
                       type_filter: Optional[str] = None) -> List[Dict]:
    """Get active IoT devices filtered by zoom level"""
    monitor = get_iot_monitor()
    return monitor.get_active_devices(zoom_level, status_filter, type_filter)


def get_device_geojson(zoom_level: int = 6, status_filter: Optional[str] = None,
                       type_filter: Optional[str] = None) -> Dict[str, Any]:
    """Get IoT devices as GeoJSON for map display"""
    monitor = get_iot_monitor()
    return monitor.get_device_geojson(zoom_level, status_filter, type_filter)


def get_device_statistics() -> Dict[str, Any]:
    """Get IoT device system statistics"""
    monitor = get_iot_monitor()
    return monitor.get_device_statistics()


def update_device_status(device_id: str, status: str) -> bool:
    """Update device status"""
    monitor = get_iot_monitor()
    return monitor.update_device_status(device_id, status)


async def search_shodan_devices(query: str, radius_km: int = 10, limit: int = 100) -> List[Dict]:
    """Search for IoT devices using Shodan API"""
    monitor = get_iot_monitor()
    return await monitor.search_shodan_devices(query, radius_km, limit)
