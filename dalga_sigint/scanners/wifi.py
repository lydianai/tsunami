"""
DALGA SIGINT WiFi Scanner - WiFi network detection and analysis
Supports: Local scanning, WiGLE API, monitor mode
"""

import os
import re
import json
import hashlib
import subprocess
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

from ..core import (
    WiFiNetwork, DeviceType, DeviceCategory, ThreatLevel,
    EncryptionType, SigintDevice, StealthLevel
)
from ..db import SigintDatabase

logger = logging.getLogger('dalga_sigint.wifi')


class WiFiScanner:
    """
    Multi-source WiFi network scanner

    Sources:
    - Local: iwlist, iw, nmcli
    - WiGLE: Historical network database
    - Monitor mode: Passive capture (if hardware supports)
    """

    # OUI vendor database (first 3 octets -> vendor)
    OUI_VENDORS = {
        '00:03:93': 'Apple',
        '00:0a:95': 'Apple',
        '00:0d:93': 'Apple',
        '00:11:24': 'Apple',
        '00:14:51': 'Apple',
        '00:16:cb': 'Apple',
        '00:17:f2': 'Apple',
        '00:19:e3': 'Apple',
        '00:1b:63': 'Apple',
        '00:1c:b3': 'Apple',
        '00:1d:4f': 'Apple',
        '00:1e:52': 'Apple',
        '00:1e:c2': 'Apple',
        '00:1f:5b': 'Apple',
        '00:1f:f3': 'Apple',
        '00:21:e9': 'Apple',
        '00:22:41': 'Apple',
        '00:23:12': 'Apple',
        '00:23:32': 'Apple',
        '00:23:6c': 'Apple',
        '00:23:df': 'Apple',
        '00:24:36': 'Apple',
        '00:25:00': 'Apple',
        '00:25:4b': 'Apple',
        '00:25:bc': 'Apple',
        '00:26:08': 'Apple',
        '00:26:4a': 'Apple',
        '00:26:b0': 'Apple',
        '00:26:bb': 'Apple',

        '00:1a:11': 'Google',
        '3c:5a:b4': 'Google',
        '54:60:09': 'Google',
        '94:eb:2c': 'Google',
        'f4:f5:d8': 'Google',
        'f4:f5:e8': 'Google',

        '00:09:2d': 'Cisco',
        '00:0a:41': 'Cisco',
        '00:0a:b7': 'Cisco',
        '00:0b:45': 'Cisco',
        '00:0b:be': 'Cisco',

        '00:0c:43': 'Ralink',
        '00:17:7c': 'Ralink',

        '00:13:10': 'TP-Link',
        '00:1d:0f': 'TP-Link',
        '00:23:cd': 'TP-Link',
        '00:27:19': 'TP-Link',
        'e8:94:f6': 'TP-Link',
        'f4:ec:38': 'TP-Link',

        '00:18:e7': 'Huawei',
        '00:1e:10': 'Huawei',
        '00:25:68': 'Huawei',
        '00:25:9e': 'Huawei',
        '00:46:4b': 'Huawei',

        '00:1a:2b': 'Turkcell',
        '28:6c:07': 'Vodafone',
        '00:26:44': 'Türk Telekom',

        '00:50:f2': 'Microsoft',
        '00:0d:3a': 'Microsoft',
        '28:18:78': 'Microsoft',

        '00:15:5d': 'Hyper-V',
        '00:0c:29': 'VMware',
        '00:50:56': 'VMware',
        '08:00:27': 'VirtualBox',
    }

    # SSID patterns for categorization
    SSID_PATTERNS = {
        'router': [
            r'turkcell.*fiber', r'superonline', r'turktelekom', r'vodafone',
            r'netspeed', r'millenicom', r'ttnet', r'd-smart',
            r'asus.*router', r'tplink', r'netgear', r'linksys', r'dlink',
            r'zyxel', r'huawei', r'xiaomi', r'ubnt'
        ],
        'hotspot': [
            r'iphone', r'android.*ap', r'galaxy', r'huawei.*mobile',
            r'pixel', r'redmi', r'oneplus', r'oppo', r'vivo'
        ],
        'enterprise': [
            r'eduroam', r'corporate', r'office', r'staff', r'employee',
            r'guest', r'visitor', r'conference'
        ],
        'iot': [
            r'ring', r'nest', r'arlo', r'wyze', r'eufy', r'reolink',
            r'smartthings', r'hue', r'wemo', r'tuya', r'sonoff'
        ],
        'camera': [
            r'hikvision', r'dahua', r'axis', r'vivotek', r'foscam',
            r'ipcam', r'dvr', r'nvr', r'cctv'
        ]
    }

    def __init__(
        self,
        wigle_name: str = None,
        wigle_token: str = None,
        stealth_level: StealthLevel = StealthLevel.NORMAL
    ):
        self.wigle_name = wigle_name or os.environ.get('WIGLE_NAME', '')
        self.wigle_token = wigle_token or os.environ.get('WIGLE_TOKEN', '')
        self.stealth_level = stealth_level
        self.db = SigintDatabase()

    def scan_local(self, interface: str = None) -> List[WiFiNetwork]:
        """Scan local WiFi networks using system tools"""
        networks = []

        if self.stealth_level == StealthLevel.GHOST:
            logger.info("[SIGINT] GHOST mode - skipping active local scan")
            return networks

        # Try iwlist first
        try:
            networks = self._scan_iwlist(interface)
            if networks:
                return networks
        except Exception as e:
            logger.debug(f"iwlist scan failed: {e}")

        # Fall back to nmcli
        try:
            networks = self._scan_nmcli()
            if networks:
                return networks
        except Exception as e:
            logger.debug(f"nmcli scan failed: {e}")

        # Fall back to iw
        try:
            networks = self._scan_iw(interface)
        except Exception as e:
            logger.debug(f"iw scan failed: {e}")

        return networks

    def _scan_iwlist(self, interface: str = None) -> List[WiFiNetwork]:
        """Scan using iwlist"""
        networks = []

        if not interface:
            interface = self._get_wireless_interface()
            if not interface:
                return networks

        try:
            result = subprocess.run(
                ['iwlist', interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )
            output = result.stdout

            # Parse iwlist output
            cells = output.split('Cell ')
            for cell in cells[1:]:
                network = self._parse_iwlist_cell(cell)
                if network:
                    networks.append(network)

        except subprocess.TimeoutExpired:
            logger.warning("iwlist scan timed out")
        except FileNotFoundError:
            pass

        return networks

    def _parse_iwlist_cell(self, cell_text: str) -> Optional[WiFiNetwork]:
        """Parse single iwlist cell output"""
        try:
            # Extract BSSID
            bssid_match = re.search(r'Address:\s*([0-9A-Fa-f:]{17})', cell_text)
            if not bssid_match:
                return None
            bssid = bssid_match.group(1).upper()

            # Extract SSID
            ssid_match = re.search(r'ESSID:"([^"]*)"', cell_text)
            ssid = ssid_match.group(1) if ssid_match else None

            # Extract channel
            channel_match = re.search(r'Channel:(\d+)', cell_text)
            channel = int(channel_match.group(1)) if channel_match else None

            # Extract frequency
            freq_match = re.search(r'Frequency:(\d+\.?\d*)', cell_text)
            frequency = int(float(freq_match.group(1)) * 1000) if freq_match else None

            # Extract signal
            signal_match = re.search(r'Signal level[=:](-?\d+)', cell_text)
            signal = int(signal_match.group(1)) if signal_match else None

            # Extract encryption
            encryption = EncryptionType.OPEN
            if 'WPA3' in cell_text:
                encryption = EncryptionType.WPA3
            elif 'WPA2' in cell_text:
                encryption = EncryptionType.WPA2
            elif 'WPA' in cell_text:
                encryption = EncryptionType.WPA
            elif 'WEP' in cell_text:
                encryption = EncryptionType.WEP
            elif 'Encryption key:on' in cell_text:
                encryption = EncryptionType.WEP

            # Create network object
            device_id = SigintDevice.generate_device_id(bssid)
            vendor = self._lookup_vendor(bssid)
            category = self._categorize_ssid(ssid)

            network = WiFiNetwork(
                device_id=device_id,
                device_type=DeviceType.WIFI,
                bssid=bssid,
                mac_address=bssid,
                name=ssid,
                ssid=ssid,
                vendor=vendor,
                category=category,
                channel=channel,
                frequency=frequency,
                signal_strength=signal,
                encryption=encryption,
                hidden=not ssid
            )

            return network

        except Exception as e:
            logger.debug(f"Error parsing iwlist cell: {e}")
            return None

    def _scan_nmcli(self) -> List[WiFiNetwork]:
        """Scan using NetworkManager nmcli"""
        networks = []

        try:
            result = subprocess.run(
                ['nmcli', '-t', '-f', 'BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY', 'device', 'wifi', 'list'],
                capture_output=True, text=True, timeout=30
            )

            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue

                # nmcli escapes : in BSSID as \: so we need to handle this
                # Format: BSSID:SSID:CHAN:FREQ:SIGNAL:SECURITY
                # BSSID has format like: 20\:3A\:EB\:C2\:78\:D2

                # First, replace escaped colons in BSSID with placeholder
                line_fixed = line.replace('\\:', '@@')
                parts = line_fixed.split(':')

                if len(parts) >= 6:
                    bssid = parts[0].replace('@@', ':').strip().upper()
                    ssid = parts[1].replace('@@', ':').strip()
                    channel = int(parts[2]) if parts[2] and parts[2].isdigit() else None
                    freq_str = parts[3].replace(' MHz', '').strip()
                    freq = int(freq_str) if freq_str and freq_str.isdigit() else None
                    signal = int(parts[4]) if parts[4] and parts[4].lstrip('-').isdigit() else None
                    security = ':'.join(parts[5:]).replace('@@', ':').strip()

                    # Parse encryption
                    encryption = EncryptionType.OPEN
                    if 'WPA3' in security:
                        encryption = EncryptionType.WPA3
                    elif 'WPA2' in security:
                        encryption = EncryptionType.WPA2
                    elif 'WPA' in security:
                        encryption = EncryptionType.WPA
                    elif 'WEP' in security:
                        encryption = EncryptionType.WEP

                    device_id = SigintDevice.generate_device_id(bssid)
                    vendor = self._lookup_vendor(bssid)
                    category = self._categorize_ssid(ssid)

                    network = WiFiNetwork(
                        device_id=device_id,
                        device_type=DeviceType.WIFI,
                        bssid=bssid,
                        mac_address=bssid,
                        name=ssid,
                        ssid=ssid,
                        vendor=vendor,
                        category=category,
                        channel=channel,
                        frequency=freq,
                        signal_strength=signal,
                        signal_quality=signal,
                        encryption=encryption,
                        hidden=not ssid
                    )
                    networks.append(network)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return networks

    def _scan_iw(self, interface: str = None) -> List[WiFiNetwork]:
        """Scan using iw tool"""
        networks = []

        if not interface:
            interface = self._get_wireless_interface()
            if not interface:
                return networks

        try:
            result = subprocess.run(
                ['iw', interface, 'scan'],
                capture_output=True, text=True, timeout=30
            )

            # Parse iw output (similar to iwlist but different format)
            current_bss = None
            current_data = {}

            for line in result.stdout.split('\n'):
                if line.startswith('BSS '):
                    if current_bss and current_data:
                        network = self._create_network_from_iw(current_bss, current_data)
                        if network:
                            networks.append(network)

                    bss_match = re.match(r'BSS ([0-9a-f:]+)', line, re.I)
                    current_bss = bss_match.group(1).upper() if bss_match else None
                    current_data = {}

                elif current_bss:
                    if 'SSID:' in line:
                        current_data['ssid'] = line.split('SSID:')[1].strip()
                    elif 'signal:' in line:
                        sig_match = re.search(r'(-?\d+)', line)
                        if sig_match:
                            current_data['signal'] = int(sig_match.group(1))
                    elif 'primary channel:' in line:
                        ch_match = re.search(r'(\d+)', line)
                        if ch_match:
                            current_data['channel'] = int(ch_match.group(1))
                    elif 'freq:' in line:
                        freq_match = re.search(r'(\d+)', line)
                        if freq_match:
                            current_data['frequency'] = int(freq_match.group(1))

            # Don't forget the last one
            if current_bss and current_data:
                network = self._create_network_from_iw(current_bss, current_data)
                if network:
                    networks.append(network)

        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return networks

    def _create_network_from_iw(
        self, bssid: str, data: Dict[str, Any]
    ) -> Optional[WiFiNetwork]:
        """Create WiFiNetwork from iw scan data"""
        try:
            device_id = SigintDevice.generate_device_id(bssid)
            ssid = data.get('ssid', '')
            vendor = self._lookup_vendor(bssid)
            category = self._categorize_ssid(ssid)

            return WiFiNetwork(
                device_id=device_id,
                device_type=DeviceType.WIFI,
                bssid=bssid,
                mac_address=bssid,
                name=ssid,
                ssid=ssid,
                vendor=vendor,
                category=category,
                channel=data.get('channel'),
                frequency=data.get('frequency'),
                signal_strength=data.get('signal'),
                hidden=not ssid
            )
        except Exception:
            return None

    def scan_wigle(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 0.5
    ) -> List[WiFiNetwork]:
        """
        Search WiGLE database for networks near location

        Requires WiGLE API credentials (free account available)
        """
        networks = []

        if self.stealth_level == StealthLevel.GHOST:
            logger.info("[SIGINT] GHOST mode - skipping WiGLE API call")
            return networks

        if self.stealth_level == StealthLevel.REDUCED:
            logger.info("[SIGINT] REDUCED mode - skipping external API calls")
            return networks

        if not self.wigle_name or not self.wigle_token:
            logger.warning("[SIGINT] WiGLE credentials not configured")
            return networks

        if not requests:
            logger.warning("[SIGINT] requests library not available")
            return networks

        try:
            # Calculate bounding box
            lat_delta = radius_km / 111.0
            lon_delta = radius_km / (111.0 * abs(latitude) if latitude != 0 else 111.0)

            url = "https://api.wigle.net/api/v2/network/search"
            params = {
                'latrange1': latitude - lat_delta,
                'latrange2': latitude + lat_delta,
                'longrange1': longitude - lon_delta,
                'longrange2': longitude + lon_delta,
                'resultsPerPage': 100
            }

            response = requests.get(
                url,
                params=params,
                auth=(self.wigle_name, self.wigle_token),
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                for result in data.get('results', []):
                    network = self._parse_wigle_result(result)
                    if network:
                        networks.append(network)

                logger.info(f"[SIGINT] WiGLE returned {len(networks)} networks")

            else:
                logger.warning(f"[SIGINT] WiGLE API error: {response.status_code}")

        except Exception as e:
            logger.error(f"[SIGINT] WiGLE scan error: {e}")

        return networks

    def _parse_wigle_result(self, result: Dict[str, Any]) -> Optional[WiFiNetwork]:
        """Parse WiGLE API result into WiFiNetwork"""
        try:
            bssid = result.get('netid', '').upper()
            if not bssid:
                return None

            ssid = result.get('ssid', '')
            device_id = SigintDevice.generate_device_id(bssid)
            vendor = self._lookup_vendor(bssid)
            category = self._categorize_ssid(ssid)

            # Parse encryption
            encryption_str = result.get('encryption', 'unknown')
            encryption = EncryptionType.OPEN
            if 'wpa3' in encryption_str.lower():
                encryption = EncryptionType.WPA3
            elif 'wpa2' in encryption_str.lower():
                encryption = EncryptionType.WPA2
            elif 'wpa' in encryption_str.lower():
                encryption = EncryptionType.WPA
            elif 'wep' in encryption_str.lower():
                encryption = EncryptionType.WEP

            network = WiFiNetwork(
                device_id=device_id,
                device_type=DeviceType.WIFI,
                bssid=bssid,
                mac_address=bssid,
                name=ssid,
                ssid=ssid,
                vendor=vendor,
                category=category,
                latitude=result.get('trilat'),
                longitude=result.get('trilong'),
                channel=result.get('channel'),
                encryption=encryption,
                metadata={
                    'source': 'wigle',
                    'first_seen': result.get('firsttime'),
                    'last_seen': result.get('lasttime'),
                    'qos': result.get('qos')
                }
            )

            return network

        except Exception as e:
            logger.debug(f"Error parsing WiGLE result: {e}")
            return None

    def _get_wireless_interface(self) -> Optional[str]:
        """Get first wireless interface name"""
        try:
            result = subprocess.run(
                ['ls', '/sys/class/net'],
                capture_output=True, text=True
            )
            interfaces = result.stdout.strip().split()

            for iface in interfaces:
                wireless_path = f'/sys/class/net/{iface}/wireless'
                if os.path.exists(wireless_path):
                    return iface

            # Also check /proc/net/wireless
            if os.path.exists('/proc/net/wireless'):
                with open('/proc/net/wireless') as f:
                    content = f.read()
                    for line in content.split('\n')[2:]:
                        if ':' in line:
                            return line.split(':')[0].strip()

        except Exception:
            pass

        return None

    def _lookup_vendor(self, mac: str) -> Optional[str]:
        """Lookup vendor from OUI database"""
        if not mac:
            return None

        oui = mac[:8].upper()
        return self.OUI_VENDORS.get(oui)

    def _categorize_ssid(self, ssid: str) -> DeviceCategory:
        """Categorize network based on SSID patterns"""
        if not ssid:
            return DeviceCategory.NETWORK_ROUTER

        ssid_lower = ssid.lower()

        for category, patterns in self.SSID_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, ssid_lower):
                    if category == 'router':
                        return DeviceCategory.NETWORK_ROUTER
                    elif category == 'hotspot':
                        return DeviceCategory.PHONE_OTHER
                    elif category == 'iot':
                        return DeviceCategory.IOT_HUB
                    elif category == 'camera':
                        return DeviceCategory.CAMERA_IP

        return DeviceCategory.NETWORK_ACCESS_POINT

    def scan_and_save(
        self,
        latitude: float = None,
        longitude: float = None,
        use_wigle: bool = True
    ) -> Dict[str, Any]:
        """Perform scan and save results to database"""
        all_networks = []

        # Local scan
        local_networks = self.scan_local()
        for network in local_networks:
            if latitude and longitude:
                network.latitude = latitude
                network.longitude = longitude
            all_networks.append(network)

        # WiGLE scan (if coordinates provided)
        if use_wigle and latitude and longitude:
            wigle_networks = self.scan_wigle(latitude, longitude)
            for network in wigle_networks:
                # Avoid duplicates
                if not any(n.bssid == network.bssid for n in all_networks):
                    all_networks.append(network)

        # Save to database
        saved_count = 0
        for network in all_networks:
            try:
                self.db.upsert_wifi(network)
                saved_count += 1
            except Exception as e:
                logger.error(f"Error saving network {network.bssid}: {e}")

        return {
            'total': len(all_networks),
            'saved': saved_count,
            'local': len(local_networks),
            'wigle': len(all_networks) - len(local_networks),
            'networks': [n.to_dict() for n in all_networks[:50]]  # Return first 50
        }
