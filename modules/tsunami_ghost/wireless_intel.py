"""
GHOST Wireless Intelligence
============================

WiFi network tracking, WiGLE integration, and wireless OSINT.
"""

from enum import Enum
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from datetime import datetime


class NetworkEncryption(Enum):
    """WiFi encryption types"""
    OPEN = 'Open'
    WEP = 'WEP'
    WPA = 'WPA'
    WPA2 = 'WPA2'
    WPA3 = 'WPA3'
    WPA_ENTERPRISE = 'WPA-Enterprise'
    WPA2_ENTERPRISE = 'WPA2-Enterprise'
    UNKNOWN = 'Unknown'


class NetworkType(Enum):
    """Wireless network types"""
    WIFI = 'WIFI'
    BLUETOOTH = 'BLUETOOTH'
    CELL = 'CELL'
    LORA = 'LORA'
    ZIGBEE = 'ZIGBEE'


class FrequencyBand(Enum):
    """WiFi frequency bands"""
    BAND_2_4GHZ = '2.4GHz'
    BAND_5GHZ = '5GHz'
    BAND_6GHZ = '6GHz'  # WiFi 6E/7


class AssociationType(Enum):
    """Network-entity association types"""
    OWNED = 'owned'  # Entity owns the network
    ACCESSED = 'accessed'  # Entity accessed/connected
    NEARBY = 'nearby'  # Detected near entity location
    SUSPECTED = 'suspected'  # Suspected connection


@dataclass
class WirelessNetwork:
    """Wireless network data model"""
    id: Optional[int] = None
    ssid: str = ''
    bssid: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    accuracy: Optional[float] = None

    # Technical details
    encryption: str = 'Unknown'
    auth_mode: Optional[str] = None
    signal_strength: Optional[int] = None  # dBm
    frequency: Optional[str] = None
    channel: Optional[int] = None
    network_type: str = 'WIFI'

    # Association
    entity_id: Optional[int] = None
    case_id: Optional[int] = None
    association_type: Optional[str] = None
    association_confidence: int = 50
    association_note: Optional[str] = None

    # Import info
    import_source: Optional[str] = None
    import_file: Optional[str] = None
    password: Optional[str] = None  # Captured password (encrypted)

    # Timestamps
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        for ts_field in ['first_seen', 'last_seen', 'created_at']:
            if result.get(ts_field):
                val = result[ts_field]
                result[ts_field] = val.isoformat() if isinstance(val, datetime) else val
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WirelessNetwork':
        """Create from dictionary"""
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class WirelessIntelManager:
    """
    Manager for wireless network intelligence.

    Handles WiFi network tracking, entity association, and map visualization.
    """

    def __init__(self, db=None):
        from .db import GhostDatabase
        from .crypto import get_ghost_crypto
        self.db = db or GhostDatabase()
        self.crypto = get_ghost_crypto()

    def add_network(
        self,
        ssid: str,
        bssid: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
        encryption: str = 'Unknown',
        signal_strength: Optional[int] = None,
        frequency: Optional[str] = None,
        channel: Optional[int] = None,
        import_source: str = 'manual',
        **kwargs
    ) -> WirelessNetwork:
        """
        Add a wireless network.

        Args:
            ssid: Network SSID
            bssid: MAC address
            latitude: GPS latitude
            longitude: GPS longitude
            encryption: Encryption type
            signal_strength: Signal in dBm
            frequency: Frequency band
            channel: WiFi channel
            import_source: Source of data (manual, wigle_kml, sigint_scan)
            **kwargs: Additional fields

        Returns:
            Created WirelessNetwork object
        """
        # Encrypt password if provided
        password = kwargs.pop('password', None)
        if password:
            password = self.crypto.encrypt(password)

        network_data = {
            'ssid': ssid,
            'bssid': bssid,
            'latitude': latitude,
            'longitude': longitude,
            'encryption': encryption,
            'signal_strength': signal_strength,
            'frequency': frequency,
            'channel': channel,
            'import_source': import_source,
            'password': password,
            'last_seen': datetime.now().isoformat(),
            **kwargs
        }

        # Remove None values
        network_data = {k: v for k, v in network_data.items() if v is not None}

        network_id = self.db.add_wireless_network(network_data)
        networks = self.db.get_wireless_networks(ssid=ssid)
        for net in networks:
            if net['id'] == network_id:
                return WirelessNetwork.from_dict(net)
        return WirelessNetwork(**network_data, id=network_id)

    def get(self, network_id: int) -> Optional[WirelessNetwork]:
        """Get network by ID"""
        networks = self.db.get_wireless_networks()
        for net in networks:
            if net['id'] == network_id:
                return WirelessNetwork.from_dict(net)
        return None

    def list(
        self,
        entity_id: Optional[int] = None,
        case_id: Optional[int] = None,
        ssid: Optional[str] = None,
        encryption: Optional[str] = None,
        limit: int = 500
    ) -> List[WirelessNetwork]:
        """
        List wireless networks with filters.

        Args:
            entity_id: Filter by associated entity
            case_id: Filter by case
            ssid: Filter by SSID (partial match)
            encryption: Filter by encryption type
            limit: Maximum results

        Returns:
            List of WirelessNetwork objects
        """
        networks = self.db.get_wireless_networks(
            entity_id=entity_id,
            case_id=case_id,
            ssid=ssid,
            limit=limit
        )

        if encryption:
            networks = [n for n in networks if n.get('encryption') == encryption]

        return [WirelessNetwork.from_dict(n) for n in networks]

    def associate_to_entity(
        self,
        network_id: int,
        entity_id: int,
        association_type: str = 'accessed',
        confidence: int = 50,
        note: Optional[str] = None
    ) -> bool:
        """
        Associate a network with an entity.

        Args:
            network_id: Network ID
            entity_id: Entity ID
            association_type: Type of association
            confidence: Confidence level (0-100)
            note: Association note

        Returns:
            True if successful
        """
        return self.db.associate_network_to_entity(
            network_id=network_id,
            entity_id=entity_id,
            association_type=association_type,
            confidence=confidence,
            note=note
        )

    def disassociate(self, network_id: int) -> bool:
        """Remove entity association from network"""
        return self.db.update_wireless_network(network_id, {
            'entity_id': None,
            'association_type': None,
            'association_confidence': None,
            'association_note': None
        })

    def get_entity_networks(self, entity_id: int) -> List[WirelessNetwork]:
        """Get all networks associated with an entity"""
        return self.list(entity_id=entity_id)

    def find_nearby(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 0.5
    ) -> List[WirelessNetwork]:
        """
        Find networks near a location.

        Args:
            latitude: Center latitude
            longitude: Center longitude
            radius_km: Search radius in kilometers

        Returns:
            List of nearby networks
        """
        import math

        networks = self.db.get_wireless_networks(limit=5000)
        nearby = []

        for net in networks:
            if net.get('latitude') and net.get('longitude'):
                # Haversine formula for distance
                lat1, lon1 = math.radians(latitude), math.radians(longitude)
                lat2 = math.radians(net['latitude'])
                lon2 = math.radians(net['longitude'])

                dlat = lat2 - lat1
                dlon = lon2 - lon1

                a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
                c = 2 * math.asin(math.sqrt(a))
                r = 6371  # Earth radius in km

                distance = r * c

                if distance <= radius_km:
                    net_obj = WirelessNetwork.from_dict(net)
                    nearby.append((distance, net_obj))

        # Sort by distance
        nearby.sort(key=lambda x: x[0])
        return [n[1] for n in nearby]

    def get_map_data(
        self,
        case_id: Optional[int] = None,
        entity_id: Optional[int] = None,
        bounds: Optional[Dict[str, float]] = None
    ) -> List[Dict[str, Any]]:
        """
        Get network data for map visualization.

        Args:
            case_id: Filter by case
            entity_id: Filter by entity
            bounds: Map bounds {north, south, east, west}

        Returns:
            List of marker data
        """
        networks = self.db.get_wireless_networks(
            case_id=case_id,
            entity_id=entity_id,
            limit=1000
        )

        markers = []
        for net in networks:
            if not net.get('latitude') or not net.get('longitude'):
                continue

            lat, lng = net['latitude'], net['longitude']

            # Filter by bounds if provided
            if bounds:
                if lat < bounds.get('south', -90) or lat > bounds.get('north', 90):
                    continue
                if lng < bounds.get('west', -180) or lng > bounds.get('east', 180):
                    continue

            markers.append({
                'id': net['id'],
                'lat': lat,
                'lng': lng,
                'ssid': net['ssid'],
                'bssid': net.get('bssid'),
                'encryption': net.get('encryption', 'Unknown'),
                'signal': net.get('signal_strength'),
                'frequency': net.get('frequency'),
                'entity_id': net.get('entity_id'),
                'association_type': net.get('association_type'),
                'color': self._get_marker_color(net.get('encryption')),
                'icon': self._get_marker_icon(net.get('encryption'))
            })

        return markers

    def _get_marker_color(self, encryption: Optional[str]) -> str:
        """Get marker color based on encryption"""
        colors = {
            'Open': '#ff3333',  # Red - insecure
            'WEP': '#ff6633',  # Orange - weak
            'WPA': '#ffcc00',  # Yellow - moderate
            'WPA2': '#00cc00',  # Green - secure
            'WPA3': '#0066ff',  # Blue - very secure
            'WPA-Enterprise': '#9933ff',  # Purple - enterprise
            'WPA2-Enterprise': '#9933ff'
        }
        return colors.get(encryption, '#888888')

    def _get_marker_icon(self, encryption: Optional[str]) -> str:
        """Get marker icon based on encryption"""
        if encryption in ['Open']:
            return 'wifi-off'
        elif encryption in ['WEP']:
            return 'wifi-low'
        else:
            return 'wifi'

    def get_statistics(
        self,
        case_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get wireless network statistics.

        Args:
            case_id: Filter by case

        Returns:
            Statistics dictionary
        """
        networks = self.db.get_wireless_networks(case_id=case_id, limit=10000)

        stats = {
            'total_networks': len(networks),
            'by_encryption': {},
            'by_frequency': {},
            'by_association_type': {},
            'with_location': 0,
            'with_entity': 0,
            'unique_ssids': set(),
            'unique_bssids': set()
        }

        for net in networks:
            # Encryption stats
            enc = net.get('encryption', 'Unknown')
            stats['by_encryption'][enc] = stats['by_encryption'].get(enc, 0) + 1

            # Frequency stats
            freq = net.get('frequency')
            if freq:
                stats['by_frequency'][freq] = stats['by_frequency'].get(freq, 0) + 1

            # Association stats
            assoc = net.get('association_type')
            if assoc:
                stats['by_association_type'][assoc] = stats['by_association_type'].get(assoc, 0) + 1

            # Location stats
            if net.get('latitude') and net.get('longitude'):
                stats['with_location'] += 1

            # Entity stats
            if net.get('entity_id'):
                stats['with_entity'] += 1

            # Unique counts
            stats['unique_ssids'].add(net.get('ssid'))
            if net.get('bssid'):
                stats['unique_bssids'].add(net.get('bssid'))

        stats['unique_ssids'] = len(stats['unique_ssids'])
        stats['unique_bssids'] = len(stats['unique_bssids'])

        return stats

    def import_from_sigint(self, sigint_networks: List[Dict]) -> int:
        """
        Import networks from TSUNAMI SIGINT module.

        Args:
            sigint_networks: List of SIGINT WiFi network data

        Returns:
            Number of imported networks
        """
        imported = 0
        for net in sigint_networks:
            try:
                self.add_network(
                    ssid=net.get('ssid', 'Unknown'),
                    bssid=net.get('bssid'),
                    latitude=net.get('latitude') or net.get('lat'),
                    longitude=net.get('longitude') or net.get('lng') or net.get('lon'),
                    encryption=net.get('encryption') or net.get('security'),
                    signal_strength=net.get('signal_strength') or net.get('signal') or net.get('rssi'),
                    frequency=net.get('frequency') or net.get('freq'),
                    channel=net.get('channel'),
                    import_source='sigint_scan',
                    first_seen=net.get('first_seen'),
                    network_type='WIFI'
                )
                imported += 1
            except Exception:
                continue

        return imported

    def update_password(
        self,
        network_id: int,
        password: str,
        source: str = 'manual'
    ) -> bool:
        """
        Update network password (encrypted storage).

        Args:
            network_id: Network ID
            password: Plain text password
            source: How password was obtained

        Returns:
            True if successful
        """
        encrypted_password = self.crypto.encrypt(password)

        return self.db.update_wireless_network(network_id, {
            'password': encrypted_password
        })

    def get_password(self, network_id: int) -> Optional[str]:
        """
        Get decrypted network password.

        Args:
            network_id: Network ID

        Returns:
            Decrypted password or None
        """
        network = self.get(network_id)
        if network and network.password:
            return self.crypto.decrypt(network.password)
        return None
