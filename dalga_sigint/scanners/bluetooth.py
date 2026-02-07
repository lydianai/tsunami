"""
DALGA SIGINT Bluetooth Scanner - BLE and classic Bluetooth device detection
"""

import os
import re
import subprocess
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    import requests
except ImportError:
    requests = None

from ..core import (
    BluetoothDevice, DeviceType, DeviceCategory, StealthLevel, SigintDevice
)
from ..db import SigintDatabase

logger = logging.getLogger('dalga_sigint.bluetooth')


class BluetoothScanner:
    """
    Bluetooth/BLE device scanner

    Sources:
    - Local: hcitool, bluetoothctl
    - WiGLE: Bluetooth database (with API key)
    """

    # Device class to category mapping
    DEVICE_CLASS_MAP = {
        # Major class: Computer
        '0x100': DeviceCategory.LAPTOP_OTHER,
        '0x104': DeviceCategory.LAPTOP_OTHER,
        '0x108': DeviceCategory.LAPTOP_OTHER,
        '0x10c': DeviceCategory.LAPTOP_OTHER,

        # Major class: Phone
        '0x200': DeviceCategory.PHONE_OTHER,
        '0x204': DeviceCategory.PHONE_OTHER,
        '0x208': DeviceCategory.PHONE_IPHONE,

        # Major class: Audio/Video
        '0x400': DeviceCategory.AUDIO_OTHER,
        '0x404': DeviceCategory.AUDIO_OTHER,
        '0x408': DeviceCategory.AUDIO_OTHER,
        '0x418': DeviceCategory.AUDIO_SPEAKER,
        '0x420': DeviceCategory.CAMERA_OTHER,
        '0x428': DeviceCategory.VEHICLE_DASHCAM,

        # Major class: Peripheral
        '0x500': DeviceCategory.GAMING_CONTROLLER,
        '0x540': DeviceCategory.GAMING_CONTROLLER,

        # Major class: Imaging
        '0x600': DeviceCategory.CAMERA_OTHER,
        '0x680': DeviceCategory.PRINTER_NETWORK,

        # Major class: Wearable
        '0x700': DeviceCategory.WEARABLE_OTHER,
        '0x704': DeviceCategory.WEARABLE_OTHER,
        '0x708': DeviceCategory.WEARABLE_OTHER,

        # Major class: Toy
        '0x800': DeviceCategory.IOT_OTHER,
    }

    # Name patterns for better categorization
    NAME_PATTERNS = {
        'airpods': DeviceCategory.AUDIO_AIRPODS,
        'galaxy buds': DeviceCategory.AUDIO_GALAXY_BUDS,
        'bose': DeviceCategory.AUDIO_BOSE,
        'sony wh': DeviceCategory.AUDIO_SONY,
        'sony wf': DeviceCategory.AUDIO_SONY,
        'jabra': DeviceCategory.AUDIO_JABRA,
        'jbl': DeviceCategory.AUDIO_JBL,
        'beats': DeviceCategory.AUDIO_BEATS,

        'apple watch': DeviceCategory.WEARABLE_APPLE_WATCH,
        'galaxy watch': DeviceCategory.WEARABLE_SAMSUNG_WATCH,
        'fitbit': DeviceCategory.WEARABLE_FITBIT,
        'garmin': DeviceCategory.WEARABLE_GARMIN,
        'mi band': DeviceCategory.WEARABLE_OTHER,
        'amazfit': DeviceCategory.WEARABLE_OTHER,

        'iphone': DeviceCategory.PHONE_IPHONE,
        'galaxy': DeviceCategory.PHONE_SAMSUNG,
        'pixel': DeviceCategory.PHONE_PIXEL,
        'huawei': DeviceCategory.PHONE_HUAWEI,
        'xiaomi': DeviceCategory.PHONE_XIAOMI,
        'redmi': DeviceCategory.PHONE_XIAOMI,
        'oneplus': DeviceCategory.PHONE_ONEPLUS,
        'oppo': DeviceCategory.PHONE_OPPO,

        'macbook': DeviceCategory.LAPTOP_MACBOOK,
        'thinkpad': DeviceCategory.LAPTOP_THINKPAD,

        'tesla': DeviceCategory.VEHICLE_TESLA,
        'bmw': DeviceCategory.VEHICLE_BMW,
        'mercedes': DeviceCategory.VEHICLE_MERCEDES,
        'audi': DeviceCategory.VEHICLE_AUDI,
        'ford sync': DeviceCategory.VEHICLE_FORD,
        'toyota': DeviceCategory.VEHICLE_TOYOTA,

        'tile': DeviceCategory.GPS_TRACKER,
        'airtag': DeviceCategory.GPS_TRACKER,
        'chipolo': DeviceCategory.GPS_TRACKER,
        'smarttag': DeviceCategory.GPS_TRACKER,

        'gopro': DeviceCategory.CAMERA_OTHER,
        'insta360': DeviceCategory.CAMERA_OTHER,
        'dji': DeviceCategory.DRONE_DJI,
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

    def scan_local(self) -> List[BluetoothDevice]:
        """Scan local Bluetooth devices using system tools"""
        devices = []

        if self.stealth_level == StealthLevel.GHOST:
            logger.info("[SIGINT] GHOST mode - skipping active Bluetooth scan")
            return devices

        # Try hcitool
        try:
            devices = self._scan_hcitool()
            if devices:
                return devices
        except Exception as e:
            logger.debug(f"hcitool scan failed: {e}")

        # Try bluetoothctl
        try:
            devices = self._scan_bluetoothctl()
        except Exception as e:
            logger.debug(f"bluetoothctl scan failed: {e}")

        return devices

    def _scan_hcitool(self) -> List[BluetoothDevice]:
        """Scan using hcitool"""
        devices = []

        try:
            # Classic Bluetooth scan
            result = subprocess.run(
                ['hcitool', 'scan', '--flush'],
                capture_output=True, text=True, timeout=30
            )

            for line in result.stdout.strip().split('\n')[1:]:
                match = re.match(r'\s*([0-9A-Fa-f:]{17})\s+(.*)', line)
                if match:
                    mac = match.group(1).upper()
                    name = match.group(2).strip()

                    device = self._create_device(mac, name)
                    devices.append(device)

            # BLE scan (lescan)
            try:
                result = subprocess.run(
                    ['timeout', '5', 'hcitool', 'lescan', '--duplicates'],
                    capture_output=True, text=True, timeout=10
                )

                for line in result.stdout.strip().split('\n'):
                    match = re.match(r'([0-9A-Fa-f:]{17})\s*(.*)', line)
                    if match:
                        mac = match.group(1).upper()
                        name = match.group(2).strip() or 'Unknown BLE'

                        # Avoid duplicates
                        if not any(d.mac_address == mac for d in devices):
                            device = self._create_device(mac, name, le_supported=True)
                            devices.append(device)

            except Exception:
                pass

        except subprocess.TimeoutExpired:
            logger.warning("Bluetooth scan timed out")
        except FileNotFoundError:
            pass

        return devices

    def _scan_bluetoothctl(self) -> List[BluetoothDevice]:
        """Scan using bluetoothctl"""
        devices = []

        try:
            # Start scan
            subprocess.run(
                ['bluetoothctl', 'scan', 'on'],
                capture_output=True, timeout=2
            )

            import time
            time.sleep(5)

            # Stop scan
            subprocess.run(
                ['bluetoothctl', 'scan', 'off'],
                capture_output=True, timeout=2
            )

            # Get devices
            result = subprocess.run(
                ['bluetoothctl', 'devices'],
                capture_output=True, text=True, timeout=5
            )

            for line in result.stdout.strip().split('\n'):
                match = re.match(r'Device\s+([0-9A-Fa-f:]{17})\s+(.*)', line)
                if match:
                    mac = match.group(1).upper()
                    name = match.group(2).strip()

                    device = self._create_device(mac, name)
                    devices.append(device)

        except Exception as e:
            logger.debug(f"bluetoothctl error: {e}")

        return devices

    def _create_device(
        self, mac: str, name: str, le_supported: bool = False
    ) -> BluetoothDevice:
        """Create BluetoothDevice from scan data"""
        device_id = SigintDevice.generate_device_id(mac)
        category = self._categorize_device(name)

        return BluetoothDevice(
            device_id=device_id,
            device_type=DeviceType.BLUETOOTH,
            mac_address=mac,
            name=name,
            category=category,
            le_supported=le_supported,
            metadata={'source': 'local'}
        )

    def _categorize_device(self, name: str) -> DeviceCategory:
        """Categorize device based on name patterns"""
        if not name:
            return DeviceCategory.UNKNOWN

        name_lower = name.lower()
        for pattern, category in self.NAME_PATTERNS.items():
            if pattern in name_lower:
                return category

        return DeviceCategory.UNKNOWN

    def scan_wigle(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 0.5
    ) -> List[BluetoothDevice]:
        """Search WiGLE Bluetooth database"""
        devices = []

        if self.stealth_level in [StealthLevel.GHOST, StealthLevel.REDUCED]:
            return devices

        if not self.wigle_name or not self.wigle_token or not requests:
            return devices

        try:
            lat_delta = radius_km / 111.0
            lon_delta = radius_km / 111.0

            url = "https://api.wigle.net/api/v2/bluetooth/search"
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
                    mac = result.get('netid', '').upper()
                    if mac:
                        name = result.get('name', '')
                        device = self._create_device(mac, name)
                        device.latitude = result.get('trilat')
                        device.longitude = result.get('trilong')
                        device.metadata['source'] = 'wigle'
                        devices.append(device)

        except Exception as e:
            logger.error(f"WiGLE Bluetooth scan error: {e}")

        return devices

    def scan_and_save(
        self,
        latitude: float = None,
        longitude: float = None,
        use_wigle: bool = True
    ) -> Dict[str, Any]:
        """Perform scan and save results"""
        all_devices = []

        # Local scan
        local_devices = self.scan_local()
        for device in local_devices:
            if latitude and longitude:
                device.latitude = latitude
                device.longitude = longitude
            all_devices.append(device)

        # WiGLE scan
        if use_wigle and latitude and longitude:
            wigle_devices = self.scan_wigle(latitude, longitude)
            for device in wigle_devices:
                if not any(d.mac_address == device.mac_address for d in all_devices):
                    all_devices.append(device)

        # Save to database
        saved_count = 0
        for device in all_devices:
            try:
                self.db.upsert_bluetooth(device)
                saved_count += 1
            except Exception as e:
                logger.error(f"Error saving BT device {device.mac_address}: {e}")

        return {
            'total': len(all_devices),
            'saved': saved_count,
            'local': len(local_devices),
            'wigle': len(all_devices) - len(local_devices),
            'devices': [d.to_dict() for d in all_devices[:50]]
        }
