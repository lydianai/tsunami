# WiFi/Bluetooth Geolocation Integration - WiGLE + OpenCellID

import asyncio
import math
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import aiohttp
import json

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============== DATA MODELS ==============

@dataclass
class WiFiNetwork:
    """WiFi network from WiGLE database"""
    bssid: str
    ssid: str
    frequency: int
    latitude: float
    longitude: float
    accuracy_m: int
    last_seen: str
    signal_strength: int = 0

    def to_dict(self):
        return {
            'bssid': self.bssid,
            'ssid': self.ssid,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'accuracy': self.accuracy_m
        }

@dataclass
class CellTower:
    """Cell tower information"""
    mcc: int  # Mobile Country Code
    mnc: int  # Mobile Network Code
    lac: int  # Location Area Code
    cid: int  # Cell ID
    signal_strength: int  # dBm
    latitude: float = None
    longitude: float = None

@dataclass
class GeolocationResult:
    """Final geolocation result"""
    latitude: float
    longitude: float
    accuracy_m: int
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.5
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    details: Dict = field(default_factory=dict)

    def to_dict(self):
        return {
            'latitude': self.latitude,
            'longitude': self.longitude,
            'accuracy_m': self.accuracy_m,
            'sources': self.sources,
            'confidence': self.confidence,
            'timestamp': self.timestamp
        }

# ============== WiGLE CLIENT ==============

class WiGLEClient:
    """Async client for WiGLE API - WiFi geolocation"""

    BASE_URL = "https://api.wigle.net/api/v2"

    def __init__(self, username: str, api_key: str):
        self.username = username
        self.api_key = api_key
        self.auth = aiohttp.BasicAuth(username, api_key)

    async def search_by_bssid(self, bssid: str) -> Optional[WiFiNetwork]:
        """
        Search WiFi network by BSSID (MAC address)

        Args:
            bssid: MAC address in format XX:XX:XX:XX:XX:XX

        Returns:
            WiFiNetwork object or None
        """
        try:
            # Normalize BSSID
            bssid = bssid.upper().replace('-', ':')

            async with aiohttp.ClientSession(auth=self.auth) as session:
                params = {
                    'netid': bssid,
                    'resultSize': 1
                }

                async with session.get(
                    f"{self.BASE_URL}/network/search",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data.get('success') and data.get('results'):
                            net = data['results'][0]
                            return WiFiNetwork(
                                bssid=net['netid'],
                                ssid=net['ssid'],
                                frequency=net.get('frequency', 0),
                                latitude=float(net['trilat']),
                                longitude=float(net['trilong']),
                                accuracy_m=net.get('accuracy', 100),
                                last_seen=net.get('lastupdt', ''),
                                signal_strength=net.get('signal', 0)
                            )

        except asyncio.TimeoutError:
            logger.error(f"WiGLE timeout for BSSID {bssid}")
        except Exception as e:
            logger.error(f"WiGLE search error: {e}")

        return None

    async def search_by_ssid(self, ssid: str, limit: int = 10) -> List[WiFiNetwork]:
        """
        Search WiFi networks by SSID

        Args:
            ssid: Network name
            limit: Maximum results

        Returns:
            List of WiFiNetwork objects
        """
        try:
            async with aiohttp.ClientSession(auth=self.auth) as session:
                params = {
                    'ssid': ssid,
                    'resultSize': min(limit, 100)
                }

                async with session.get(
                    f"{self.BASE_URL}/network/search",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        networks = []

                        if data.get('success'):
                            for net in data.get('results', []):
                                networks.append(WiFiNetwork(
                                    bssid=net['netid'],
                                    ssid=net['ssid'],
                                    frequency=net.get('frequency', 0),
                                    latitude=float(net['trilat']),
                                    longitude=float(net['trilong']),
                                    accuracy_m=net.get('accuracy', 100),
                                    last_seen=net.get('lastupdt', ''),
                                    signal_strength=net.get('signal', 0)
                                ))

                        return networks

        except Exception as e:
            logger.error(f"WiGLE SSID search error: {e}")

        return []

    async def search_by_location(self, lat: float, lng: float,
                                radius_km: float = 0.5) -> List[WiFiNetwork]:
        """
        Search WiFi networks near coordinates

        Args:
            lat: Latitude
            lng: Longitude
            radius_km: Search radius

        Returns:
            List of WiFiNetwork objects
        """
        try:
            # Calculate bounding box
            lat_delta = radius_km / 111.0
            lng_delta = radius_km / (111.0 * abs(math.cos(math.radians(lat))))

            lat_min, lat_max = lat - lat_delta, lat + lat_delta
            lng_min, lng_max = lng - lng_delta, lng + lng_delta

            async with aiohttp.ClientSession(auth=self.auth) as session:
                params = {
                    'latrange': [lat_min, lat_max],
                    'lonrange': [lng_min, lng_max],
                    'resultSize': 100
                }

                async with session.get(
                    f"{self.BASE_URL}/network/search",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        networks = []

                        if data.get('success'):
                            for net in data.get('results', []):
                                networks.append(WiFiNetwork(
                                    bssid=net['netid'],
                                    ssid=net['ssid'],
                                    frequency=net.get('frequency', 0),
                                    latitude=float(net['trilat']),
                                    longitude=float(net['trilong']),
                                    accuracy_m=net.get('accuracy', 100),
                                    last_seen=net.get('lastupdt', ''),
                                    signal_strength=net.get('signal', 0)
                                ))

                        return networks

        except Exception as e:
            logger.error(f"WiGLE location search error: {e}")

        return []

    @staticmethod
    def triangulate_wifi(networks: List[WiFiNetwork]) -> Optional[Tuple[float, float, int]]:
        """
        Triangulate position from multiple WiFi networks

        WiGLE uses: position = sum(lat/lng * signal_strength²) / sum(signal_strength²)

        Args:
            networks: List of WiFiNetwork objects

        Returns:
            Tuple of (latitude, longitude, accuracy_m) or None
        """
        if not networks:
            return None

        # If signal strength available, use weighted average
        if any(n.signal_strength != 0 for n in networks):
            total_weight = 0
            weighted_lat = 0
            weighted_lng = 0

            for net in networks:
                weight = (net.signal_strength ** 2) if net.signal_strength else 1
                weighted_lat += net.latitude * weight
                weighted_lng += net.longitude * weight
                total_weight += weight

            if total_weight > 0:
                lat = weighted_lat / total_weight
                lng = weighted_lng / total_weight

                # Estimate accuracy from spread
                max_dist = max(
                    math.sqrt((n.latitude - lat)**2 + (n.longitude - lng)**2) * 111000
                    for n in networks
                )

                return (lat, lng, int(max_dist * 1.5))

        # Fallback: simple average
        avg_lat = sum(n.latitude for n in networks) / len(networks)
        avg_lng = sum(n.longitude for n in networks) / len(networks)
        avg_accuracy = sum(n.accuracy_m for n in networks) // len(networks)

        return (avg_lat, avg_lng, avg_accuracy)

# ============== OPENCELLID CLIENT ==============

class OpenCellIDClient:
    """Async client for OpenCellID API - cell tower geolocation"""

    BASE_URL = "https://opencellid.org/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key

    async def search_cell_location(self, mcc: int, mnc: int, lac: int,
                                   cid: int) -> Optional[Dict]:
        """
        Get cell tower location by identifiers

        Args:
            mcc: Mobile Country Code (310 = USA, 440 = Japan, etc.)
            mnc: Mobile Network Code
            lac: Location Area Code
            cid: Cell ID

        Returns:
            Dict with lat, lon, accuracy or None
        """
        try:
            params = {
                'key': self.api_key,
                'mcc': mcc,
                'mnc': mnc,
                'lac': lac,
                'cellid': cid,
                'format': 'json'
            }

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.BASE_URL}/cell/get",
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data.get('status') == 200:
                            return {
                                'latitude': data['lat'],
                                'longitude': data['lon'],
                                'accuracy_m': data.get('accuracy', 1000),
                                'range': data.get('range', 0)
                            }

        except Exception as e:
            logger.error(f"OpenCellID search error: {e}")

        return None

    @staticmethod
    def triangulate_cells(cell_results: List[Dict]) -> Optional[Tuple[float, float, int]]:
        """
        Triangulate position from multiple cell towers

        Args:
            cell_results: List of dicts with lat, lon, accuracy

        Returns:
            Tuple of (latitude, longitude, accuracy_m) or None
        """
        if not cell_results:
            return None

        # Weighted average by accuracy (inverse: higher accuracy = lower weight penalty)
        total_weight = 0
        weighted_lat = 0
        weighted_lng = 0
        accuracies = []

        for result in cell_results:
            # Weight inversely to accuracy
            weight = 1.0 / (result['accuracy_m'] / 1000.0 + 1)

            weighted_lat += result['latitude'] * weight
            weighted_lng += result['longitude'] * weight
            total_weight += weight
            accuracies.append(result['accuracy_m'])

        if total_weight > 0:
            lat = weighted_lat / total_weight
            lng = weighted_lng / total_weight

            # Estimate combined accuracy
            avg_accuracy = sum(accuracies) // len(accuracies)
            return (lat, lng, avg_accuracy)

        return None

# ============== HYBRID GEOLOCATION SYSTEM ==============

class HybridGeolocationSystem:
    """Multi-source geolocation system"""

    def __init__(self, wigle_username: str, wigle_key: str,
                 opencellid_key: str):
        self.wigle = WiGLEClient(wigle_username, wigle_key)
        self.opencellid = OpenCellIDClient(opencellid_key)

    async def locate_from_wifi(self, bssids: List[str],
                              use_signal_strength: bool = True) -> Optional[GeolocationResult]:
        """Geolocate from WiFi BSSIDs"""
        networks = []

        # Fetch network info for each BSSID
        for bssid in bssids:
            net = await self.wigle.search_by_bssid(bssid)
            if net:
                networks.append(net)

        if not networks:
            logger.warning(f"No WiFi networks found for BSSIDs: {bssids}")
            return None

        result = WiGLEClient.triangulate_wifi(networks)

        if result:
            lat, lng, accuracy = result

            return GeolocationResult(
                latitude=lat,
                longitude=lng,
                accuracy_m=accuracy,
                sources=['WiFi'],
                confidence=0.75,
                details={
                    'networks_found': len(networks),
                    'bssids': bssids,
                    'networks': [n.to_dict() for n in networks]
                }
            )

        return None

    async def locate_from_cell_towers(self, towers: List[CellTower]) -> Optional[GeolocationResult]:
        """Geolocate from cell tower triangulation"""
        results = []

        for tower in towers:
            location = await self.opencellid.search_cell_location(
                tower.mcc, tower.mnc, tower.lac, tower.cid
            )
            if location:
                results.append(location)

        if not results:
            logger.warning("No cell tower locations found")
            return None

        triangulated = OpenCellIDClient.triangulate_cells(results)

        if triangulated:
            lat, lng, accuracy = triangulated

            return GeolocationResult(
                latitude=lat,
                longitude=lng,
                accuracy_m=accuracy,
                sources=['Cell Towers'],
                confidence=0.5,
                details={
                    'towers_found': len(results),
                    'cell_count': len(towers)
                }
            )

        return None

    async def locate_hybrid(self, bssids: Optional[List[str]] = None,
                           towers: Optional[List[CellTower]] = None) -> Optional[GeolocationResult]:
        """
        Combine multiple geolocation sources for best accuracy

        Args:
            bssids: WiFi BSSIDs to search
            towers: Cell towers to triangulate

        Returns:
            Combined GeolocationResult or None
        """
        results = []

        # Get WiFi location
        if bssids:
            wifi_result = await self.locate_from_wifi(bssids)
            if wifi_result:
                results.append(wifi_result)

        # Get cell tower location
        if towers:
            cell_result = await self.locate_from_cell_towers(towers)
            if cell_result:
                results.append(cell_result)

        if not results:
            logger.error("No geolocation results from any source")
            return None

        # Combine results using weighted average
        total_confidence = sum(r.confidence for r in results)
        weighted_lat = sum(r.latitude * r.confidence for r in results) / total_confidence
        weighted_lng = sum(r.longitude * r.confidence for r in results) / total_confidence

        # Combined accuracy: lower is better
        combined_accuracy = int(sum(r.accuracy_m / (r.confidence or 0.1) for r in results) / len(results))

        all_sources = list(set(s for r in results for s in r.sources))

        return GeolocationResult(
            latitude=weighted_lat,
            longitude=weighted_lng,
            accuracy_m=combined_accuracy,
            sources=all_sources,
            confidence=min(0.95, total_confidence / len(results)),
            details={
                'sources_used': len(results),
                'component_results': [r.to_dict() for r in results]
            }
        )

# ============== EXAMPLE USAGE ==============

async def main():
    """Demonstrate geolocation"""

    # Initialize system
    geo_system = HybridGeolocationSystem(
        wigle_username='YOUR_WIGLE_USERNAME',
        wigle_key='YOUR_WIGLE_API_KEY',
        opencellid_key='YOUR_OPENCELLID_KEY'
    )

    # Example: WiFi geolocation
    print("=== WiFi Geolocation ===")
    result = await geo_system.locate_from_wifi([
        'AA:BB:CC:DD:EE:FF',
        '11:22:33:44:55:66'
    ])

    if result:
        print(f"Location: {result.latitude}, {result.longitude}")
        print(f"Accuracy: ±{result.accuracy_m}m")
        print(f"Confidence: {result.confidence * 100:.1f}%")
        print(json.dumps(result.to_dict(), indent=2))

    # Example: Cell tower geolocation
    print("\n=== Cell Tower Geolocation ===")
    towers = [
        CellTower(mcc=310, mnc=410, lac=1234, cid=5678, signal_strength=-90),
        CellTower(mcc=310, mnc=410, lac=1235, cid=5679, signal_strength=-95)
    ]

    result = await geo_system.locate_from_cell_towers(towers)

    if result:
        print(f"Location: {result.latitude}, {result.longitude}")
        print(f"Accuracy: ±{result.accuracy_m}m")
        print(json.dumps(result.to_dict(), indent=2))

    # Example: Hybrid geolocation
    print("\n=== Hybrid Geolocation ===")
    result = await geo_system.locate_hybrid(
        bssids=['AA:BB:CC:DD:EE:FF'],
        towers=towers
    )

    if result:
        print(f"Location: {result.latitude}, {result.longitude}")
        print(f"Accuracy: ±{result.accuracy_m}m")
        print(f"Sources: {', '.join(result.sources)}")
        print(f"Confidence: {result.confidence * 100:.1f}%")

if __name__ == '__main__':
    asyncio.run(main())
