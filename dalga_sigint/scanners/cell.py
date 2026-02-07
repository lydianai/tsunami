"""
DALGA SIGINT Cell Tower Scanner - Mobile network infrastructure detection
"""

import os
import logging
from typing import Dict, List, Optional, Any

try:
    import requests
except ImportError:
    requests = None

from ..core import (
    CellTower, DeviceType, DeviceCategory, RadioType, StealthLevel, SigintDevice
)
from ..db import SigintDatabase

logger = logging.getLogger('dalga_sigint.cell')


# Turkish mobile operator MNC codes
TURKEY_OPERATORS = {
    (286, 1): 'Turkcell',
    (286, 2): 'Vodafone TR',
    (286, 3): 'Türk Telekom',
    (286, 4): 'Aycell',  # Historical
}


class CellTowerScanner:
    """
    Cell tower scanner using OpenCellID and Mozilla Location Services

    Data sources:
    - OpenCellID: Open cell tower database
    - Mozilla Location Services (MLS): Additional coverage
    """

    def __init__(
        self,
        opencellid_key: str = None,
        mls_key: str = None,
        stealth_level: StealthLevel = StealthLevel.NORMAL
    ):
        self.opencellid_key = opencellid_key or os.environ.get('OPENCELLID_API_KEY', '')
        self.mls_key = mls_key or os.environ.get('MLS_API_KEY', '')
        self.stealth_level = stealth_level
        self.db = SigintDatabase()

    def scan_opencellid(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 5.0
    ) -> List[CellTower]:
        """Query OpenCellID for cell towers"""
        towers = []

        if self.stealth_level in [StealthLevel.GHOST, StealthLevel.REDUCED]:
            logger.info("[SIGINT] Stealth mode - skipping OpenCellID API")
            return towers

        if not self.opencellid_key:
            logger.warning("[SIGINT] OpenCellID API key not configured")
            return towers

        if not requests:
            return towers

        try:
            # Calculate bounding box
            lat_delta = radius_km / 111.0
            lon_delta = radius_km / 111.0

            url = "https://opencellid.org/cell/getInArea"
            params = {
                'key': self.opencellid_key,
                'BBOX': f"{longitude - lon_delta},{latitude - lat_delta},{longitude + lon_delta},{latitude + lat_delta}",
                'format': 'json'
            }

            response = requests.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                cells = data.get('cells', [])

                for cell in cells[:200]:  # Limit to 200
                    tower = self._parse_opencellid_cell(cell)
                    if tower:
                        towers.append(tower)

                logger.info(f"[SIGINT] OpenCellID returned {len(towers)} towers")

            else:
                logger.warning(f"[SIGINT] OpenCellID error: {response.status_code}")

        except Exception as e:
            logger.error(f"[SIGINT] OpenCellID scan error: {e}")

        return towers

    def _parse_opencellid_cell(self, cell: Dict[str, Any]) -> Optional[CellTower]:
        """Parse OpenCellID cell data"""
        try:
            mcc = cell.get('mcc')
            mnc = cell.get('mnc')
            lac = cell.get('lac')
            cell_id = cell.get('cellid')

            if not all([mcc, mnc, cell_id]):
                return None

            # Generate unique ID
            unique_key = f"{mcc}:{mnc}:{lac}:{cell_id}"
            device_id = SigintDevice.generate_device_id(unique_key)

            # Determine radio type
            radio_str = cell.get('radio', 'LTE')
            radio_type = RadioType.LTE
            if 'GSM' in radio_str.upper():
                radio_type = RadioType.GSM
            elif 'UMTS' in radio_str.upper() or '3G' in radio_str.upper():
                radio_type = RadioType.UMTS
            elif '5G' in radio_str.upper() or 'NR' in radio_str.upper():
                radio_type = RadioType.NR
            elif 'CDMA' in radio_str.upper():
                radio_type = RadioType.CDMA

            # Get operator name
            operator = TURKEY_OPERATORS.get((mcc, mnc))
            if not operator:
                operator = f"MCC:{mcc}/MNC:{mnc}"

            # Determine tower type by range
            range_m = cell.get('range', 1000)
            tower_type = 'macro'
            if range_m < 200:
                tower_type = 'femto'
            elif range_m < 500:
                tower_type = 'pico'
            elif range_m < 2000:
                tower_type = 'micro'

            tower = CellTower(
                device_id=device_id,
                device_type=DeviceType.CELL_TOWER,
                name=f"{operator} {radio_type.value}",
                category=DeviceCategory.CELL_MACRO if tower_type == 'macro' else DeviceCategory.CELL_FEMTO,
                latitude=cell.get('lat'),
                longitude=cell.get('lon'),
                cell_id=str(cell_id),
                lac=lac,
                mcc=mcc,
                mnc=mnc,
                radio_type=radio_type,
                operator=operator,
                tower_type=tower_type,
                range_m=range_m,
                signal_strength=cell.get('averageSignal', -70),
                metadata={
                    'source': 'opencellid',
                    'samples': cell.get('samples'),
                    'changeable': cell.get('changeable'),
                    'created': cell.get('created'),
                    'updated': cell.get('updated')
                }
            )

            return tower

        except Exception as e:
            logger.debug(f"Error parsing cell: {e}")
            return None

    def scan_mls(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 5.0
    ) -> List[CellTower]:
        """Query Mozilla Location Services"""
        towers = []

        if self.stealth_level in [StealthLevel.GHOST, StealthLevel.REDUCED]:
            return towers

        if not self.mls_key or not requests:
            return towers

        # MLS doesn't have a direct "get cells in area" endpoint
        # It's primarily for geolocation from known cell data
        # We can use their geosubmit API for contributing data
        # For now, return empty list (OpenCellID is primary source)

        return towers

    def triangulate_position(
        self,
        cell_measurements: List[Dict[str, Any]]
    ) -> Optional[Dict[str, float]]:
        """
        Triangulate position from multiple cell tower measurements

        Each measurement should have: mcc, mnc, lac, cid, signal
        """
        if not cell_measurements:
            return None

        if not self.opencellid_key or not requests:
            return None

        try:
            # Use OpenCellID geolocation API
            url = "https://opencellid.org/cell/get"

            positions = []
            weights = []

            for cell in cell_measurements:
                params = {
                    'key': self.opencellid_key,
                    'mcc': cell.get('mcc'),
                    'mnc': cell.get('mnc'),
                    'lac': cell.get('lac'),
                    'cellid': cell.get('cid'),
                    'format': 'json'
                }

                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('lat') and data.get('lon'):
                        positions.append((data['lat'], data['lon']))
                        # Weight by signal strength (higher = closer)
                        signal = cell.get('signal', -70)
                        weight = max(0, 100 + signal)  # Convert dBm to positive weight
                        weights.append(weight)

            if not positions:
                return None

            # Weighted centroid calculation
            total_weight = sum(weights)
            if total_weight == 0:
                total_weight = len(positions)
                weights = [1] * len(positions)

            lat = sum(p[0] * w for p, w in zip(positions, weights)) / total_weight
            lon = sum(p[1] * w for p, w in zip(positions, weights)) / total_weight

            # Estimate accuracy based on number of towers and weight spread
            base_accuracy = 1000 if len(positions) == 1 else 500
            accuracy = base_accuracy / (len(positions) ** 0.5)

            return {
                'latitude': lat,
                'longitude': lon,
                'accuracy_m': accuracy,
                'towers_used': len(positions),
                'method': 'weighted_centroid'
            }

        except Exception as e:
            logger.error(f"Triangulation error: {e}")
            return None

    def scan_and_save(
        self,
        latitude: float,
        longitude: float,
        radius_km: float = 5.0
    ) -> Dict[str, Any]:
        """Perform scan and save results"""
        all_towers = []

        # OpenCellID scan
        towers = self.scan_opencellid(latitude, longitude, radius_km)
        all_towers.extend(towers)

        # MLS scan (if available)
        mls_towers = self.scan_mls(latitude, longitude, radius_km)
        for tower in mls_towers:
            if not any(t.cell_id == tower.cell_id for t in all_towers):
                all_towers.append(tower)

        # Save to database
        saved_count = 0
        for tower in all_towers:
            try:
                self.db.upsert_cell_tower(tower)
                saved_count += 1
            except Exception as e:
                logger.error(f"Error saving cell tower: {e}")

        # Statistics by operator
        by_operator = {}
        for tower in all_towers:
            op = tower.operator or 'Unknown'
            by_operator[op] = by_operator.get(op, 0) + 1

        return {
            'total': len(all_towers),
            'saved': saved_count,
            'by_operator': by_operator,
            'towers': [
                {
                    'device_id': t.device_id,
                    'cell_id': t.cell_id,
                    'operator': t.operator,
                    'radio': t.radio_type.value if t.radio_type else None,
                    'lat': t.latitude,
                    'lon': t.longitude,
                    'range_m': t.range_m,
                    'signal': t.signal_strength
                }
                for t in all_towers[:100]
            ]
        }
