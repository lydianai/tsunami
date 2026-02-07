"""
DALGA SIGINT Core - Base classes, enums, and type definitions
"""

import hashlib
import time
import uuid
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime


class StealthLevel(Enum):
    """Operational security levels for SIGINT operations"""
    NORMAL = 0      # Full functionality, all features
    REDUCED = 1     # No API calls, local scanning only
    GHOST = 2       # Passive only, no transmissions, no disk writes


class DeviceType(Enum):
    """Primary device type categories"""
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"
    CELL_TOWER = "cell"
    IOT = "iot"
    DRONE = "drone"
    SDR_SIGNAL = "sdr"
    UNKNOWN = "unknown"


class DeviceCategory(Enum):
    """Detailed device categories (100+)"""
    # Phones
    PHONE_IPHONE = "phone_iphone"
    PHONE_SAMSUNG = "phone_samsung"
    PHONE_PIXEL = "phone_pixel"
    PHONE_HUAWEI = "phone_huawei"
    PHONE_XIAOMI = "phone_xiaomi"
    PHONE_OPPO = "phone_oppo"
    PHONE_ONEPLUS = "phone_oneplus"
    PHONE_OTHER = "phone_other"

    # Tablets
    TABLET_IPAD = "tablet_ipad"
    TABLET_SAMSUNG = "tablet_samsung"
    TABLET_OTHER = "tablet_other"

    # Laptops
    LAPTOP_MACBOOK = "laptop_macbook"
    LAPTOP_THINKPAD = "laptop_thinkpad"
    LAPTOP_DELL = "laptop_dell"
    LAPTOP_HP = "laptop_hp"
    LAPTOP_ASUS = "laptop_asus"
    LAPTOP_OTHER = "laptop_other"

    # Wearables
    WEARABLE_APPLE_WATCH = "wearable_apple_watch"
    WEARABLE_SAMSUNG_WATCH = "wearable_samsung_watch"
    WEARABLE_FITBIT = "wearable_fitbit"
    WEARABLE_GARMIN = "wearable_garmin"
    WEARABLE_OTHER = "wearable_other"

    # Audio
    AUDIO_AIRPODS = "audio_airpods"
    AUDIO_GALAXY_BUDS = "audio_galaxy_buds"
    AUDIO_BOSE = "audio_bose"
    AUDIO_SONY = "audio_sony"
    AUDIO_JABRA = "audio_jabra"
    AUDIO_JBL = "audio_jbl"
    AUDIO_BEATS = "audio_beats"
    AUDIO_SPEAKER = "audio_speaker"
    AUDIO_OTHER = "audio_other"

    # Vehicles
    VEHICLE_TESLA = "vehicle_tesla"
    VEHICLE_BMW = "vehicle_bmw"
    VEHICLE_MERCEDES = "vehicle_mercedes"
    VEHICLE_AUDI = "vehicle_audi"
    VEHICLE_FORD = "vehicle_ford"
    VEHICLE_TOYOTA = "vehicle_toyota"
    VEHICLE_DASHCAM = "vehicle_dashcam"
    VEHICLE_TRACKER = "vehicle_tracker"
    VEHICLE_OTHER = "vehicle_other"

    # Cameras
    CAMERA_RING = "camera_ring"
    CAMERA_NEST = "camera_nest"
    CAMERA_ARLO = "camera_arlo"
    CAMERA_HIKVISION = "camera_hikvision"
    CAMERA_DAHUA = "camera_dahua"
    CAMERA_WYZE = "camera_wyze"
    CAMERA_REOLINK = "camera_reolink"
    CAMERA_EUFY = "camera_eufy"
    CAMERA_IP = "camera_ip"
    CAMERA_CCTV = "camera_cctv"
    CAMERA_OTHER = "camera_other"

    # Smart Home / IoT
    IOT_SMART_TV = "iot_smart_tv"
    IOT_SMART_SPEAKER = "iot_smart_speaker"
    IOT_SMART_PLUG = "iot_smart_plug"
    IOT_SMART_LIGHT = "iot_smart_light"
    IOT_THERMOSTAT = "iot_thermostat"
    IOT_DOORBELL = "iot_doorbell"
    IOT_LOCK = "iot_lock"
    IOT_VACUUM = "iot_vacuum"
    IOT_APPLIANCE = "iot_appliance"
    IOT_HUB = "iot_hub"
    IOT_SENSOR = "iot_sensor"
    IOT_OTHER = "iot_other"

    # Network Equipment
    NETWORK_ROUTER = "network_router"
    NETWORK_ACCESS_POINT = "network_access_point"
    NETWORK_SWITCH = "network_switch"
    NETWORK_MODEM = "network_modem"
    NETWORK_EXTENDER = "network_extender"
    NETWORK_MESH = "network_mesh"
    NETWORK_FIREWALL = "network_firewall"
    NETWORK_OTHER = "network_other"

    # Drones
    DRONE_DJI = "drone_dji"
    DRONE_PARROT = "drone_parrot"
    DRONE_SKYDIO = "drone_skydio"
    DRONE_AUTEL = "drone_autel"
    DRONE_CUSTOM = "drone_custom"
    DRONE_OTHER = "drone_other"

    # Industrial
    INDUSTRIAL_SCADA = "industrial_scada"
    INDUSTRIAL_PLC = "industrial_plc"
    INDUSTRIAL_HMI = "industrial_hmi"
    INDUSTRIAL_RTU = "industrial_rtu"
    INDUSTRIAL_ICS = "industrial_ics"
    INDUSTRIAL_OTHER = "industrial_other"

    # Medical
    MEDICAL_MONITOR = "medical_monitor"
    MEDICAL_INFUSION = "medical_infusion"
    MEDICAL_IMAGING = "medical_imaging"
    MEDICAL_PACEMAKER = "medical_pacemaker"
    MEDICAL_WEARABLE = "medical_wearable"
    MEDICAL_OTHER = "medical_other"

    # Military/Government
    MILITARY_RADIO = "military_radio"
    MILITARY_TRACKER = "military_tracker"
    MILITARY_SENSOR = "military_sensor"
    MILITARY_OTHER = "military_other"

    # Cell Towers
    CELL_MACRO = "cell_macro"
    CELL_MICRO = "cell_micro"
    CELL_PICO = "cell_pico"
    CELL_FEMTO = "cell_femto"

    # Printers
    PRINTER_NETWORK = "printer_network"
    PRINTER_SCANNER = "printer_scanner"

    # Gaming
    GAMING_CONSOLE = "gaming_console"
    GAMING_CONTROLLER = "gaming_controller"
    GAMING_VR = "gaming_vr"

    # Other
    POS_TERMINAL = "pos_terminal"
    ATM = "atm"
    KIOSK = "kiosk"
    BEACON = "beacon"
    GPS_TRACKER = "gps_tracker"
    RFID_READER = "rfid_reader"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = "info"           # 0-20 risk score
    LOW = "low"             # 21-40
    MEDIUM = "medium"       # 41-60
    HIGH = "high"           # 61-80
    CRITICAL = "critical"   # 81-100


class RadioType(Enum):
    """Cell tower radio types"""
    GSM = "GSM"
    UMTS = "UMTS"
    LTE = "LTE"
    NR = "5G-NR"
    CDMA = "CDMA"


class EncryptionType(Enum):
    """WiFi encryption types"""
    OPEN = "Open"
    WEP = "WEP"
    WPA = "WPA"
    WPA2 = "WPA2"
    WPA3 = "WPA3"
    WPA2_ENTERPRISE = "WPA2-Enterprise"
    WPA3_ENTERPRISE = "WPA3-Enterprise"


@dataclass
class SigintDevice:
    """Represents a detected wireless device"""
    device_id: str
    device_type: DeviceType
    mac_address: Optional[str] = None
    bssid: Optional[str] = None
    name: Optional[str] = None
    vendor: Optional[str] = None
    category: DeviceCategory = DeviceCategory.UNKNOWN
    subcategory: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    seen_count: int = 1
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    accuracy_m: Optional[float] = None
    signal_strength: Optional[int] = None
    signal_quality: Optional[int] = None
    risk_score: int = 0
    threat_level: ThreatLevel = ThreatLevel.INFO
    is_known_threat: bool = False
    threat_ioc_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    notes: Optional[str] = None

    @staticmethod
    def generate_device_id(identifier: str) -> str:
        """Generate unique device ID from MAC/BSSID"""
        return hashlib.sha256(identifier.lower().encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'device_id': self.device_id,
            'device_type': self.device_type.value,
            'mac_address': self.mac_address,
            'bssid': self.bssid,
            'name': self.name,
            'vendor': self.vendor,
            'category': self.category.value,
            'subcategory': self.subcategory,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'seen_count': self.seen_count,
            'location': {
                'lat': self.latitude,
                'lon': self.longitude,
                'altitude': self.altitude,
                'accuracy': self.accuracy_m
            } if self.latitude else None,
            'signal_strength': self.signal_strength,
            'signal_quality': self.signal_quality,
            'risk_score': self.risk_score,
            'threat_level': self.threat_level.value,
            'is_known_threat': self.is_known_threat,
            'metadata': self.metadata,
            'notes': self.notes
        }


@dataclass
class WiFiNetwork(SigintDevice):
    """WiFi network specific data"""
    ssid: Optional[str] = None
    channel: Optional[int] = None
    frequency: Optional[int] = None
    bandwidth: Optional[str] = None
    encryption: EncryptionType = EncryptionType.OPEN
    cipher: Optional[str] = None
    auth_type: Optional[str] = None
    hidden: bool = False
    wps_enabled: Optional[bool] = None
    client_count: int = 0

    def __post_init__(self):
        self.device_type = DeviceType.WIFI


@dataclass
class BluetoothDevice(SigintDevice):
    """Bluetooth device specific data"""
    device_class: Optional[str] = None
    service_classes: List[str] = field(default_factory=list)
    major_class: Optional[str] = None
    minor_class: Optional[str] = None
    bluetooth_version: Optional[str] = None
    le_supported: bool = False
    manufacturer_data: Optional[str] = None
    services: List[str] = field(default_factory=list)

    def __post_init__(self):
        self.device_type = DeviceType.BLUETOOTH


@dataclass
class CellTower(SigintDevice):
    """Cell tower specific data"""
    cell_id: Optional[str] = None
    lac: Optional[int] = None
    mcc: Optional[int] = None
    mnc: Optional[int] = None
    radio_type: RadioType = RadioType.LTE
    operator: Optional[str] = None
    tower_type: Optional[str] = None
    azimuth: Optional[int] = None
    range_m: Optional[int] = None
    pci: Optional[int] = None
    tac: Optional[int] = None

    def __post_init__(self):
        self.device_type = DeviceType.CELL_TOWER


@dataclass
class IoTDevice(SigintDevice):
    """IoT device specific data"""
    ip_address: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    os: Optional[str] = None
    cpe: Optional[str] = None
    cves: List[str] = field(default_factory=list)
    banner: Optional[str] = None
    http_title: Optional[str] = None
    ssl_cert_issuer: Optional[str] = None
    ssl_cert_subject: Optional[str] = None
    ssl_cert_fingerprint: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    shodan_id: Optional[str] = None
    censys_id: Optional[str] = None

    def __post_init__(self):
        self.device_type = DeviceType.IOT


@dataclass
class Drone(SigintDevice):
    """Drone specific data"""
    drone_model: Optional[str] = None
    manufacturer: Optional[str] = None
    serial_number: Optional[str] = None
    pilot_lat: Optional[float] = None
    pilot_lon: Optional[float] = None
    altitude_m: Optional[float] = None
    speed_mps: Optional[float] = None
    heading: Optional[int] = None
    home_lat: Optional[float] = None
    home_lon: Optional[float] = None
    rf_frequency: Optional[float] = None
    signal_type: Optional[str] = None
    flight_id: Optional[str] = None

    def __post_init__(self):
        self.device_type = DeviceType.DRONE


@dataclass
class SDRSignal:
    """Software Defined Radio signal capture"""
    capture_id: str
    frequency_hz: float
    bandwidth_hz: float
    modulation: Optional[str] = None
    signal_strength_dbm: Optional[float] = None
    duration_ms: Optional[int] = None
    sample_rate: Optional[int] = None
    center_freq: Optional[float] = None
    timestamp: datetime = field(default_factory=datetime.now)
    decoded_data: Optional[str] = None
    protocol: Optional[str] = None
    classification: Optional[str] = None
    raw_file_path: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanSession:
    """Represents a scanning session"""
    session_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at: datetime = field(default_factory=datetime.now)
    ended_at: Optional[datetime] = None
    scan_type: str = "all"
    location_lat: Optional[float] = None
    location_lon: Optional[float] = None
    devices_found: int = 0
    threats_detected: int = 0
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: str = "running"

    def complete(self, devices_found: int = 0, threats_detected: int = 0):
        """Mark session as completed"""
        self.ended_at = datetime.now()
        self.devices_found = devices_found
        self.threats_detected = threats_detected
        self.status = "completed"

    def fail(self, error: str):
        """Mark session as failed"""
        self.ended_at = datetime.now()
        self.status = "failed"
        self.parameters['error'] = error


@dataclass
class SigintConfig:
    """SIGINT module configuration"""
    stealth_level: StealthLevel = StealthLevel.NORMAL

    # Scanning parameters
    wifi_scan_interval: int = 30          # seconds
    bluetooth_scan_interval: int = 60
    cell_scan_interval: int = 120
    iot_scan_interval: int = 300

    # API settings
    wigle_enabled: bool = True
    opencellid_enabled: bool = True
    shodan_enabled: bool = True
    censys_enabled: bool = False

    # Privacy settings
    hash_mac_addresses: bool = False
    location_precision: int = 6           # decimal places
    auto_expire_days: int = 90
    secure_delete: bool = True

    # Threat correlation
    threat_correlation_enabled: bool = True
    auto_alert_critical: bool = True

    # Hardware features
    sdr_enabled: bool = False
    drone_detection_enabled: bool = False
    nfc_enabled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'stealth_level': self.stealth_level.value,
            'wifi_scan_interval': self.wifi_scan_interval,
            'bluetooth_scan_interval': self.bluetooth_scan_interval,
            'cell_scan_interval': self.cell_scan_interval,
            'iot_scan_interval': self.iot_scan_interval,
            'wigle_enabled': self.wigle_enabled,
            'opencellid_enabled': self.opencellid_enabled,
            'shodan_enabled': self.shodan_enabled,
            'censys_enabled': self.censys_enabled,
            'hash_mac_addresses': self.hash_mac_addresses,
            'location_precision': self.location_precision,
            'auto_expire_days': self.auto_expire_days,
            'secure_delete': self.secure_delete,
            'threat_correlation_enabled': self.threat_correlation_enabled,
            'auto_alert_critical': self.auto_alert_critical,
            'sdr_enabled': self.sdr_enabled,
            'drone_detection_enabled': self.drone_detection_enabled,
            'nfc_enabled': self.nfc_enabled
        }


# Turkish translations for UI
TURKISH_TRANSLATIONS = {
    # Device types
    'wifi': 'WiFi Agi',
    'bluetooth': 'Bluetooth',
    'cell': 'Baz Istasyonu',
    'iot': 'IoT Cihaz',
    'drone': 'Drone',
    'sdr': 'SDR Sinyal',
    'unknown': 'Bilinmeyen',

    # Threat levels
    'info': 'Bilgi',
    'low': 'Dusuk',
    'medium': 'Orta',
    'high': 'Yuksek',
    'critical': 'Kritik',

    # Categories
    'phone': 'Telefon',
    'tablet': 'Tablet',
    'laptop': 'Dizustu',
    'wearable': 'Giyilebilir',
    'camera': 'Kamera',
    'router': 'Yonlendirici',
    'speaker': 'Hoparlor',
    'headphone': 'Kulaklik',
    'vehicle': 'Arac',
    'tracker': 'Izleyici',

    # Status
    'scanning': 'Taraniyor',
    'completed': 'Tamamlandi',
    'failed': 'Basarisiz',
    'running': 'Calisiyor',

    # Actions
    'start_scan': 'Tarama Baslat',
    'stop_scan': 'Tarama Durdur',
    'export': 'Disari Aktar',
    'clear': 'Temizle'
}


def get_threat_level_from_score(risk_score: int) -> ThreatLevel:
    """Convert risk score (0-100) to threat level"""
    if risk_score <= 20:
        return ThreatLevel.INFO
    elif risk_score <= 40:
        return ThreatLevel.LOW
    elif risk_score <= 60:
        return ThreatLevel.MEDIUM
    elif risk_score <= 80:
        return ThreatLevel.HIGH
    else:
        return ThreatLevel.CRITICAL


def get_threat_color(threat_level: ThreatLevel) -> str:
    """Get color code for threat level"""
    colors = {
        ThreatLevel.INFO: '#00ff88',      # Green
        ThreatLevel.LOW: '#00d2d3',        # Cyan
        ThreatLevel.MEDIUM: '#feca57',     # Yellow
        ThreatLevel.HIGH: '#ff9f43',       # Orange
        ThreatLevel.CRITICAL: '#ff4757'    # Red
    }
    return colors.get(threat_level, '#888888')
