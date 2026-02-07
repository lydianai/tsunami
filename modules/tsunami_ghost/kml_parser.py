"""
GHOST WiGLE KML Parser
======================

Parse WiGLE KML export files for wireless network import.
"""

import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path


class WiGLEKMLParser:
    """
    Parser for WiGLE KML export files.

    WiGLE (Wireless Geographic Logging Engine) exports network
    data as KML files that can be imported into GHOST.
    """

    # KML namespaces
    KML_NS = {
        'kml': 'http://www.opengis.net/kml/2.2',
        'gx': 'http://www.google.com/kml/ext/2.2'
    }

    def __init__(self):
        self.networks = []
        self.parse_errors = []

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a WiGLE KML file.

        Args:
            file_path: Path to KML file

        Returns:
            List of parsed network dictionaries
        """
        self.networks = []
        self.parse_errors = []

        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"KML file not found: {file_path}")

        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()

        return self.parse_string(content, source_file=str(path.name))

    def parse_string(self, kml_content: str, source_file: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Parse KML content string.

        Args:
            kml_content: KML XML string
            source_file: Original filename for reference

        Returns:
            List of parsed network dictionaries
        """
        self.networks = []
        self.parse_errors = []

        try:
            # Remove namespace prefixes for easier parsing
            kml_content = re.sub(r'\s+xmlns[^"]*"[^"]*"', '', kml_content)

            root = ET.fromstring(kml_content)

            # Find all Placemarks
            placemarks = root.findall('.//Placemark')

            for pm in placemarks:
                try:
                    network = self._parse_placemark(pm, source_file)
                    if network:
                        self.networks.append(network)
                except Exception as e:
                    self.parse_errors.append(str(e))

        except ET.ParseError as e:
            raise ValueError(f"Invalid KML format: {e}")

        return self.networks

    def _parse_placemark(self, placemark: ET.Element, source_file: Optional[str]) -> Optional[Dict[str, Any]]:
        """Parse a single KML Placemark element"""
        network = {
            'import_source': 'wigle_kml',
            'import_file': source_file,
            'network_type': 'WIFI'
        }

        # Name (SSID)
        name_elem = placemark.find('name')
        if name_elem is not None and name_elem.text:
            network['ssid'] = name_elem.text.strip()
        else:
            return None  # Skip networks without SSID

        # Description (contains detailed info)
        desc_elem = placemark.find('description')
        if desc_elem is not None and desc_elem.text:
            self._parse_description(desc_elem.text, network)

        # Coordinates
        coords_elem = placemark.find('.//coordinates')
        if coords_elem is not None and coords_elem.text:
            coords_text = coords_elem.text.strip()
            parts = coords_text.split(',')
            if len(parts) >= 2:
                try:
                    network['longitude'] = float(parts[0])
                    network['latitude'] = float(parts[1])
                    if len(parts) >= 3:
                        network['accuracy'] = float(parts[2])
                except ValueError:
                    pass

        # Extended data
        ext_data = placemark.find('.//ExtendedData')
        if ext_data is not None:
            self._parse_extended_data(ext_data, network)

        # Only return if we have valid data
        if network.get('ssid'):
            return network
        return None

    def _parse_description(self, description: str, network: Dict[str, Any]):
        """Parse WiGLE description field"""
        # WiGLE format: "Network ID: XX:XX:XX:XX:XX:XX\nEncryption: WPA2\n..."
        lines = description.strip().split('\n')

        for line in lines:
            line = line.strip()

            # BSSID/MAC
            if 'network id' in line.lower() or 'mac' in line.lower() or 'bssid' in line.lower():
                match = re.search(r'([0-9A-Fa-f:]{17})', line)
                if match:
                    network['bssid'] = match.group(1).upper()

            # Encryption
            elif 'encryption' in line.lower() or 'security' in line.lower():
                enc_match = re.search(r'(WPA3|WPA2|WPA|WEP|Open|None)', line, re.IGNORECASE)
                if enc_match:
                    enc = enc_match.group(1)
                    network['encryption'] = self._normalize_encryption(enc)

            # Channel
            elif 'channel' in line.lower():
                chan_match = re.search(r'(\d+)', line)
                if chan_match:
                    network['channel'] = int(chan_match.group(1))

            # Frequency
            elif 'frequency' in line.lower() or 'freq' in line.lower():
                if '5' in line or '5ghz' in line.lower():
                    network['frequency'] = '5GHz'
                elif '6' in line or '6ghz' in line.lower():
                    network['frequency'] = '6GHz'
                else:
                    network['frequency'] = '2.4GHz'

            # Signal
            elif 'signal' in line.lower() or 'rssi' in line.lower():
                sig_match = re.search(r'(-?\d+)', line)
                if sig_match:
                    network['signal_strength'] = int(sig_match.group(1))

            # First/Last seen
            elif 'first' in line.lower() and 'seen' in line.lower():
                date_match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                if date_match:
                    network['first_seen'] = date_match.group(1)

            elif 'last' in line.lower() and 'seen' in line.lower():
                date_match = re.search(r'(\d{4}-\d{2}-\d{2})', line)
                if date_match:
                    network['last_seen'] = date_match.group(1)

    def _parse_extended_data(self, ext_data: ET.Element, network: Dict[str, Any]):
        """Parse KML ExtendedData element"""
        for data in ext_data.findall('.//Data'):
            name = data.get('name', '').lower()
            value_elem = data.find('value')
            if value_elem is None or not value_elem.text:
                continue

            value = value_elem.text.strip()

            if name in ['mac', 'bssid', 'netid']:
                network['bssid'] = value.upper()
            elif name in ['ssid', 'name']:
                network['ssid'] = value
            elif name in ['encryption', 'security', 'authmode']:
                network['encryption'] = self._normalize_encryption(value)
            elif name == 'channel':
                try:
                    network['channel'] = int(value)
                except ValueError:
                    pass
            elif name in ['signal', 'rssi', 'level']:
                try:
                    network['signal_strength'] = int(value)
                except ValueError:
                    pass
            elif name in ['frequency', 'freq']:
                network['frequency'] = value
            elif name in ['type', 'nettype']:
                if 'bt' in value.lower() or 'bluetooth' in value.lower():
                    network['network_type'] = 'BLUETOOTH'
                elif 'cell' in value.lower():
                    network['network_type'] = 'CELL'

    def _normalize_encryption(self, encryption: str) -> str:
        """Normalize encryption type string"""
        enc = encryption.upper().strip()

        if 'WPA3' in enc:
            return 'WPA3'
        elif 'WPA2' in enc:
            if 'ENTERPRISE' in enc or 'EAP' in enc:
                return 'WPA2-Enterprise'
            return 'WPA2'
        elif 'WPA' in enc:
            if 'ENTERPRISE' in enc or 'EAP' in enc:
                return 'WPA-Enterprise'
            return 'WPA'
        elif 'WEP' in enc:
            return 'WEP'
        elif 'OPEN' in enc or 'NONE' in enc or enc == '':
            return 'Open'

        return 'Unknown'

    def get_summary(self) -> Dict[str, Any]:
        """Get parsing summary"""
        summary = {
            'total_networks': len(self.networks),
            'parse_errors': len(self.parse_errors),
            'by_encryption': {},
            'by_frequency': {},
            'by_type': {},
            'with_location': 0,
            'unique_ssids': set(),
            'unique_bssids': set()
        }

        for net in self.networks:
            enc = net.get('encryption', 'Unknown')
            summary['by_encryption'][enc] = summary['by_encryption'].get(enc, 0) + 1

            freq = net.get('frequency')
            if freq:
                summary['by_frequency'][freq] = summary['by_frequency'].get(freq, 0) + 1

            net_type = net.get('network_type', 'WIFI')
            summary['by_type'][net_type] = summary['by_type'].get(net_type, 0) + 1

            if net.get('latitude') and net.get('longitude'):
                summary['with_location'] += 1

            summary['unique_ssids'].add(net.get('ssid'))
            if net.get('bssid'):
                summary['unique_bssids'].add(net.get('bssid'))

        summary['unique_ssids'] = len(summary['unique_ssids'])
        summary['unique_bssids'] = len(summary['unique_bssids'])

        return summary


def parse_wigle_kml(file_path: str) -> List[Dict[str, Any]]:
    """
    Convenience function to parse a WiGLE KML file.

    Args:
        file_path: Path to KML file

    Returns:
        List of parsed network dictionaries
    """
    parser = WiGLEKMLParser()
    return parser.parse_file(file_path)


def parse_wigle_kml_string(kml_content: str) -> List[Dict[str, Any]]:
    """
    Convenience function to parse KML string content.

    Args:
        kml_content: KML XML string

    Returns:
        List of parsed network dictionaries
    """
    parser = WiGLEKMLParser()
    return parser.parse_string(kml_content)
