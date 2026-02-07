"""
DALGA SIGINT IoT Scanner - Internet-connected device discovery
"""

import os
import logging
from typing import Dict, List, Optional, Any

try:
    import requests
except ImportError:
    requests = None

from ..core import (
    IoTDevice, DeviceType, DeviceCategory, ThreatLevel, StealthLevel, SigintDevice,
    get_threat_level_from_score
)
from ..db import SigintDatabase

logger = logging.getLogger('dalga_sigint.iot')


class IoTScanner:
    """
    IoT device scanner using Shodan and Censys APIs

    Discovers:
    - IP cameras (Hikvision, Dahua, Axis, etc.)
    - Smart home devices (Ring, Nest, etc.)
    - Industrial control systems (SCADA, PLCs)
    - Network appliances
    - Medical devices
    - ATMs, POS terminals
    """

    # Product patterns for categorization
    PRODUCT_PATTERNS = {
        # Cameras
        'hikvision': DeviceCategory.CAMERA_HIKVISION,
        'dahua': DeviceCategory.CAMERA_DAHUA,
        'axis': DeviceCategory.CAMERA_IP,
        'vivotek': DeviceCategory.CAMERA_IP,
        'foscam': DeviceCategory.CAMERA_IP,
        'amcrest': DeviceCategory.CAMERA_IP,
        'reolink': DeviceCategory.CAMERA_REOLINK,
        'wyze': DeviceCategory.CAMERA_WYZE,
        'ring': DeviceCategory.CAMERA_RING,
        'nest': DeviceCategory.CAMERA_NEST,
        'arlo': DeviceCategory.CAMERA_ARLO,
        'eufy': DeviceCategory.CAMERA_EUFY,
        'dvr': DeviceCategory.CAMERA_CCTV,
        'nvr': DeviceCategory.CAMERA_CCTV,

        # Network
        'mikrotik': DeviceCategory.NETWORK_ROUTER,
        'ubiquiti': DeviceCategory.NETWORK_ACCESS_POINT,
        'cisco': DeviceCategory.NETWORK_ROUTER,
        'netgear': DeviceCategory.NETWORK_ROUTER,
        'tplink': DeviceCategory.NETWORK_ROUTER,
        'asus router': DeviceCategory.NETWORK_ROUTER,
        'zyxel': DeviceCategory.NETWORK_ROUTER,
        'synology': DeviceCategory.IOT_HUB,
        'qnap': DeviceCategory.IOT_HUB,

        # Industrial
        'scada': DeviceCategory.INDUSTRIAL_SCADA,
        'plc': DeviceCategory.INDUSTRIAL_PLC,
        'hmi': DeviceCategory.INDUSTRIAL_HMI,
        'siemens s7': DeviceCategory.INDUSTRIAL_PLC,
        'modbus': DeviceCategory.INDUSTRIAL_ICS,
        'bacnet': DeviceCategory.INDUSTRIAL_ICS,
        'ics': DeviceCategory.INDUSTRIAL_ICS,

        # Smart Home
        'philips hue': DeviceCategory.IOT_SMART_LIGHT,
        'sonos': DeviceCategory.AUDIO_SPEAKER,
        'ecobee': DeviceCategory.IOT_THERMOSTAT,
        'nest thermostat': DeviceCategory.IOT_THERMOSTAT,
        'august lock': DeviceCategory.IOT_LOCK,
        'wemo': DeviceCategory.IOT_SMART_PLUG,
        'smart plug': DeviceCategory.IOT_SMART_PLUG,
        'smart tv': DeviceCategory.IOT_SMART_TV,
        'roku': DeviceCategory.IOT_SMART_TV,
        'chromecast': DeviceCategory.IOT_SMART_TV,
        'apple tv': DeviceCategory.IOT_SMART_TV,
        'amazon echo': DeviceCategory.IOT_SMART_SPEAKER,
        'google home': DeviceCategory.IOT_SMART_SPEAKER,

        # Printers
        'printer': DeviceCategory.PRINTER_NETWORK,
        'cups': DeviceCategory.PRINTER_NETWORK,
        'xerox': DeviceCategory.PRINTER_NETWORK,
        'hp printer': DeviceCategory.PRINTER_NETWORK,
        'canon printer': DeviceCategory.PRINTER_NETWORK,

        # Other
        'atm': DeviceCategory.ATM,
        'pos': DeviceCategory.POS_TERMINAL,
        'kiosk': DeviceCategory.KIOSK,
    }

    # High-risk ports
    HIGH_RISK_PORTS = {
        23: 'Telnet',
        80: 'HTTP (unencrypted)',
        102: 'S7comm (SCADA)',
        502: 'Modbus',
        554: 'RTSP (camera)',
        1883: 'MQTT',
        1900: 'UPnP',
        3389: 'RDP',
        5000: 'UPnP/Synology',
        5900: 'VNC',
        8080: 'HTTP alt',
        8443: 'HTTPS alt',
        47808: 'BACnet',
    }

    def __init__(
        self,
        shodan_key: str = None,
        censys_id: str = None,
        censys_secret: str = None,
        stealth_level: StealthLevel = StealthLevel.NORMAL
    ):
        self.shodan_key = shodan_key or os.environ.get('SHODAN_API_KEY', '')
        self.censys_id = censys_id or os.environ.get('CENSYS_ID', '')
        self.censys_secret = censys_secret or os.environ.get('CENSYS_SECRET', '')
        self.stealth_level = stealth_level
        self.db = SigintDatabase()

    def scan_shodan(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 10.0,
        query_filter: str = None
    ) -> List[IoTDevice]:
        """Search Shodan for devices near location"""
        devices = []

        if self.stealth_level in [StealthLevel.GHOST, StealthLevel.REDUCED]:
            logger.info("[SIGINT] Stealth mode - skipping Shodan API")
            return devices

        if not self.shodan_key:
            logger.warning("[SIGINT] Shodan API key not configured")
            return devices

        if not requests:
            return devices

        try:
            # Build geo query
            query = f"geo:{latitude},{longitude},{int(radius_km)}"
            if query_filter:
                query += f" {query_filter}"

            url = "https://api.shodan.io/shodan/host/search"
            params = {
                'key': self.shodan_key,
                'query': query,
                'minify': False
            }

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                matches = data.get('matches', [])

                for match in matches[:100]:
                    device = self._parse_shodan_match(match)
                    if device:
                        devices.append(device)

                logger.info(f"[SIGINT] Shodan returned {len(devices)} devices")

            elif response.status_code == 401:
                logger.warning("[SIGINT] Shodan API key invalid")
            elif response.status_code == 402:
                logger.warning("[SIGINT] Shodan API quota exceeded")
            else:
                logger.warning(f"[SIGINT] Shodan error: {response.status_code}")

        except Exception as e:
            logger.error(f"[SIGINT] Shodan scan error: {e}")

        return devices

    def _parse_shodan_match(self, match: Dict[str, Any]) -> Optional[IoTDevice]:
        """Parse Shodan search result"""
        try:
            ip = match.get('ip_str')
            if not ip:
                return None

            device_id = SigintDevice.generate_device_id(ip)
            location = match.get('location', {})

            # Get product info
            product = match.get('product', '')
            version = match.get('version', '')
            os_info = match.get('os')

            # Categorize device
            category = self._categorize_device(product, match)

            # Get CVEs if available
            vulns = match.get('vulns', {})
            cves = list(vulns.keys()) if vulns else []

            # Calculate risk score
            risk_score = self._calculate_risk_score(match, cves)
            threat_level = get_threat_level_from_score(risk_score)

            # Get open ports from this match
            port = match.get('port')
            open_ports = [port] if port else []

            device = IoTDevice(
                device_id=device_id,
                device_type=DeviceType.IOT,
                name=product or f"Device at {ip}",
                category=category,
                latitude=location.get('latitude'),
                longitude=location.get('longitude'),
                ip_address=ip,
                port=port,
                protocol=match.get('transport', 'tcp'),
                product=product,
                version=version,
                os=os_info,
                cves=cves,
                banner=match.get('data', '')[:500] if match.get('data') else None,
                http_title=match.get('http', {}).get('title'),
                open_ports=open_ports,
                shodan_id=match.get('_shodan', {}).get('id'),
                risk_score=risk_score,
                threat_level=threat_level,
                is_known_threat=len(cves) > 0,
                metadata={
                    'source': 'shodan',
                    'org': match.get('org'),
                    'isp': match.get('isp'),
                    'asn': match.get('asn'),
                    'hostnames': match.get('hostnames', []),
                    'domains': match.get('domains', []),
                    'country': location.get('country_code'),
                    'city': location.get('city'),
                    'timestamp': match.get('timestamp')
                }
            )

            # SSL certificate info
            ssl = match.get('ssl', {})
            if ssl:
                cert = ssl.get('cert', {})
                device.ssl_cert_issuer = str(cert.get('issuer', {}))[:200]
                device.ssl_cert_subject = str(cert.get('subject', {}))[:200]
                device.ssl_cert_fingerprint = cert.get('fingerprint', {}).get('sha256')

            return device

        except Exception as e:
            logger.debug(f"Error parsing Shodan match: {e}")
            return None

    def _categorize_device(
        self, product: str, match: Dict[str, Any]
    ) -> DeviceCategory:
        """Categorize device based on product and service info"""
        if not product:
            product = ''

        product_lower = product.lower()

        # Check product patterns
        for pattern, category in self.PRODUCT_PATTERNS.items():
            if pattern in product_lower:
                return category

        # Check banner/data for hints
        data = match.get('data', '').lower()
        for pattern, category in self.PRODUCT_PATTERNS.items():
            if pattern in data:
                return category

        # Check by port
        port = match.get('port')
        if port == 554:
            return DeviceCategory.CAMERA_IP
        elif port in [502, 102]:
            return DeviceCategory.INDUSTRIAL_ICS
        elif port == 1883:
            return DeviceCategory.IOT_HUB
        elif port in [80, 443, 8080, 8443]:
            if 'webcam' in data or 'camera' in data:
                return DeviceCategory.CAMERA_IP

        return DeviceCategory.IOT_OTHER

    def _calculate_risk_score(
        self, match: Dict[str, Any], cves: List[str]
    ) -> int:
        """Calculate risk score (0-100) based on vulnerabilities and exposure"""
        score = 0

        # Base score for being exposed
        score += 10

        # CVE count
        score += min(len(cves) * 15, 50)

        # Critical CVEs
        vulns = match.get('vulns', {})
        for cve, info in vulns.items():
            if info.get('cvss', 0) >= 9.0:
                score += 20
            elif info.get('cvss', 0) >= 7.0:
                score += 10

        # Dangerous ports
        port = match.get('port')
        if port in [23, 21]:  # Telnet, FTP
            score += 15
        elif port in [502, 102]:  # Industrial
            score += 20
        elif port == 5900:  # VNC
            score += 10

        # Default credentials suspected
        data = match.get('data', '').lower()
        if 'admin' in data or 'password' in data or 'login' in data:
            score += 5

        # Industrial/SCADA systems
        if any(p in data for p in ['scada', 'plc', 'modbus', 's7comm']):
            score += 15

        return min(score, 100)

    def search_by_query(self, query: str) -> List[IoTDevice]:
        """Search Shodan with custom query"""
        devices = []

        if not self.shodan_key or not requests:
            return devices

        try:
            url = "https://api.shodan.io/shodan/host/search"
            params = {
                'key': self.shodan_key,
                'query': query,
                'minify': False
            }

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for match in data.get('matches', [])[:100]:
                    device = self._parse_shodan_match(match)
                    if device:
                        devices.append(device)

        except Exception as e:
            logger.error(f"Shodan query error: {e}")

        return devices

    def get_device_details(self, ip: str) -> Optional[IoTDevice]:
        """Get detailed information for specific IP"""
        if not self.shodan_key or not requests:
            return None

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}"
            params = {'key': self.shodan_key}

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()

                device_id = SigintDevice.generate_device_id(ip)

                # Aggregate CVEs from all services
                all_cves = []
                all_ports = []
                for service in data.get('data', []):
                    all_cves.extend(list(service.get('vulns', {}).keys()))
                    if service.get('port'):
                        all_ports.append(service['port'])

                all_cves = list(set(all_cves))

                risk_score = 0
                for service in data.get('data', []):
                    risk_score = max(risk_score, self._calculate_risk_score(service, all_cves))

                device = IoTDevice(
                    device_id=device_id,
                    device_type=DeviceType.IOT,
                    name=f"Device at {ip}",
                    ip_address=ip,
                    latitude=data.get('latitude'),
                    longitude=data.get('longitude'),
                    os=data.get('os'),
                    cves=all_cves,
                    open_ports=all_ports,
                    risk_score=risk_score,
                    threat_level=get_threat_level_from_score(risk_score),
                    is_known_threat=len(all_cves) > 0,
                    metadata={
                        'source': 'shodan',
                        'org': data.get('org'),
                        'isp': data.get('isp'),
                        'asn': data.get('asn'),
                        'hostnames': data.get('hostnames', []),
                        'domains': data.get('domains', []),
                        'country': data.get('country_code'),
                        'city': data.get('city'),
                        'last_update': data.get('last_update')
                    }
                )

                return device

        except Exception as e:
            logger.error(f"Shodan host lookup error: {e}")

        return None

    def scan_and_save(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 10.0,
        query_filter: str = None
    ) -> Dict[str, Any]:
        """Perform scan and save results"""
        all_devices = []

        # Shodan scan
        devices = self.scan_shodan(latitude, longitude, radius_km, query_filter)
        all_devices.extend(devices)

        # Save to database
        saved_count = 0
        threats_found = 0
        for device in all_devices:
            try:
                self.db.upsert_iot(device)
                saved_count += 1
                if device.is_known_threat:
                    threats_found += 1
            except Exception as e:
                logger.error(f"Error saving IoT device: {e}")

        # Statistics
        by_category = {}
        by_risk = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for device in all_devices:
            cat = device.category.value if device.category else 'unknown'
            by_category[cat] = by_category.get(cat, 0) + 1
            by_risk[device.threat_level.value] = by_risk.get(device.threat_level.value, 0) + 1

        return {
            'total': len(all_devices),
            'saved': saved_count,
            'threats_found': threats_found,
            'by_category': by_category,
            'by_risk': by_risk,
            'devices': [d.to_dict() for d in all_devices[:50]]
        }
