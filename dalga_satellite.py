#!/usr/bin/env python3
"""
TSUNAMI SATELLITE MODULE - Gerçek Zamanlı Uydu Takibi
=====================================================

N2YO API + CelesTrak TLE verileri + Open Notify ISS ile uydu izleme
"""

import os
import time
import requests

# .env dosyasından API anahtarlarını yükle
try:
    from dotenv import load_dotenv
    env_path = os.path.join(os.path.dirname(__file__), '.env')
    load_dotenv(env_path)
except ImportError:
    pass
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import threading
import math


@dataclass
class Satellite:
    """Uydu verisi"""
    norad_id: int
    name: str
    latitude: float
    longitude: float
    altitude: float  # km
    velocity: float  # km/s
    azimuth: float
    elevation: float
    timestamp: datetime


class N2YOTracker:
    """N2YO API ile uydu takibi"""

    BASE_URL = "https://api.n2yo.com/rest/v1/satellite"

    # Önemli uydular - NORAD ID'leri
    SATELLITES = {
        'ISS': 25544,
        'HUBBLE': 20580,
        'TIANGONG': 48274,
        'STARLINK-1007': 44713,
        'TURKSAT-4A': 39522,
        'TURKSAT-4B': 40984,
        'TURKSAT-5A': 47306,
        'TURKSAT-5B': 50742,
        'GOKTURK-1': 41875,
        'GOKTURK-2': 39030,
        'RASAT': 37791,
        'CSS-TIANHE': 48274,
    }

    # Uydu kategorileri
    CATEGORIES = {
        0: 'Tümü',
        1: 'Parlak Uydular',
        2: 'ISS',
        3: 'Hava Durumu',
        4: 'NOAA',
        5: 'GOES',
        6: 'Earth Resources',
        7: 'Search & Rescue',
        8: 'Disaster Monitoring',
        9: 'Tracking & Data Relay',
        10: 'CubeSat',
        11: 'Space Stations',
        12: 'Geodetic',
        13: 'Engineering',
        14: 'Education',
        15: 'Military',
        16: 'Radar Calibration',
        17: 'TV',
        18: 'Beidou',
        19: 'Yaogan',
        20: 'Westford Needles',
        21: 'Iridium',
        22: 'Iridium NEXT',
        23: 'Globalstar',
        24: 'Amateur Radio',
        25: 'GPS',
        26: 'GLONASS',
        27: 'Galileo',
        28: 'Starlink',
        29: 'OneWeb',
    }

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('N2YO_API_KEY', '')
        self._cache: Dict[str, any] = {}
        self._cache_time: Dict[str, float] = {}
        self._cache_ttl: int = 30  # saniye

    def _api_call(self, endpoint: str, params: Dict = None) -> Optional[Dict]:
        """N2YO API çağrısı"""
        if not self.api_key:
            return None

        try:
            url = f"{self.BASE_URL}/{endpoint}"
            if '?' in url:
                url = f"{url}&apiKey={self.api_key}"
            else:
                url = f"{url}?apiKey={self.api_key}"

            response = requests.get(url, params=params, timeout=15)

            if response.status_code == 200:
                return response.json()
            else:
                print(f"[SATELLITE] N2YO HTTP {response.status_code}")

        except Exception as e:
            print(f"[SATELLITE] N2YO hatası: {e}")

        return None

    def get_position(self, norad_id: int, lat: float = 39.93, lon: float = 32.85,
                     alt: float = 0, seconds: int = 1) -> Optional[Satellite]:
        """Uydu konumunu getir"""
        cache_key = f"pos_{norad_id}"
        now = time.time()

        if cache_key in self._cache and (now - self._cache_time.get(cache_key, 0)) < self._cache_ttl:
            return self._cache[cache_key]

        data = self._api_call(f"positions/{norad_id}/{lat}/{lon}/{alt}/{seconds}")

        if data:
            info = data.get('info', {})
            positions = data.get('positions', [])

            if positions:
                pos = positions[0]
                satellite = Satellite(
                    norad_id=norad_id,
                    name=info.get('satname', 'Unknown'),
                    latitude=pos.get('satlatitude', 0),
                    longitude=pos.get('satlongitude', 0),
                    altitude=pos.get('sataltitude', 0),
                    velocity=0,  # N2YO bu veriyi sağlamıyor
                    azimuth=pos.get('azimuth', 0),
                    elevation=pos.get('elevation', 0),
                    timestamp=datetime.fromtimestamp(pos.get('timestamp', time.time()))
                )

                self._cache[cache_key] = satellite
                self._cache_time[cache_key] = now

                return satellite

        return None

    def get_satellites_above(self, lat: float, lon: float, alt: float = 0,
                             radius: int = 70, category: int = 0) -> List[Satellite]:
        """Belirli konumun üzerindeki uyduları getir"""
        cache_key = f"above_{lat}_{lon}_{radius}_{category}"
        now = time.time()

        if cache_key in self._cache and (now - self._cache_time.get(cache_key, 0)) < self._cache_ttl:
            return self._cache[cache_key]

        data = self._api_call(f"above/{lat}/{lon}/{alt}/{radius}/{category}")

        if data:
            satellites = []

            for sat in data.get('above', []):
                satellites.append(Satellite(
                    norad_id=sat.get('satid'),
                    name=sat.get('satname'),
                    latitude=sat.get('satlat'),
                    longitude=sat.get('satlng'),
                    altitude=sat.get('satalt'),
                    velocity=0,
                    azimuth=sat.get('az'),
                    elevation=sat.get('el'),
                    timestamp=datetime.now()
                ))

            self._cache[cache_key] = satellites
            self._cache_time[cache_key] = now

            return satellites

        return []

    def get_visual_passes(self, norad_id: int, lat: float, lon: float, alt: float = 0,
                          days: int = 7, min_visibility: int = 60) -> List[Dict]:
        """Görünür geçişleri getir"""
        data = self._api_call(f"visualpasses/{norad_id}/{lat}/{lon}/{alt}/{days}/{min_visibility}")

        if data:
            passes = []
            for p in data.get('passes', []):
                passes.append({
                    'start_time': datetime.fromtimestamp(p.get('startUTC', 0)),
                    'start_azimuth': p.get('startAz'),
                    'start_elevation': p.get('startEl'),
                    'max_time': datetime.fromtimestamp(p.get('maxUTC', 0)),
                    'max_azimuth': p.get('maxAz'),
                    'max_elevation': p.get('maxEl'),
                    'end_time': datetime.fromtimestamp(p.get('endUTC', 0)),
                    'end_azimuth': p.get('endAz'),
                    'magnitude': p.get('mag')
                })
            return passes

        return []

    def get_iss(self) -> Optional[Satellite]:
        """ISS konumunu getir"""
        return self.get_position(25544)

    def get_turksat(self) -> List[Satellite]:
        """TURKSAT uydularını getir"""
        turksat_ids = [39522, 40984, 47306, 50742]
        satellites = []

        for sat_id in turksat_ids:
            sat = self.get_position(sat_id)
            if sat:
                satellites.append(sat)

        return satellites

    def get_starlink_above(self, lat: float, lon: float, radius: int = 70) -> List[Satellite]:
        """Starlink uydularını getir (kategori 28)"""
        return self.get_satellites_above(lat, lon, 0, radius, 28)


class ISSTracker:
    """ISS için özel takip (Open Notify - API key gerektirmez)"""

    # HTTPS ile daha stabil bağlantı
    ISS_API = "https://api.open-notify.org/iss-now.json"
    ASTROS_API = "https://api.open-notify.org/astros.json"
    # Alternatif ISS API
    ISS_API_ALT = "http://api.wheretheiss.at/v1/satellites/25544"

    def __init__(self):
        self._last_pos: Optional[Dict] = None
        self._last_update: float = 0
        self._update_interval: float = 3  # saniye

    def get_position(self) -> Optional[Dict]:
        """ISS anlık konum"""
        now = time.time()

        # Rate limiting
        if self._last_pos and (now - self._last_update) < self._update_interval:
            return self._last_pos

        # Önce ana API'yi dene
        try:
            response = requests.get(self.ISS_API, timeout=10)

            if response.status_code == 200:
                data = response.json()

                if data.get('message') == 'success':
                    pos = data.get('iss_position', {})
                    self._last_pos = {
                        'lat': float(pos.get('latitude', 0)),
                        'lng': float(pos.get('longitude', 0)),
                        'timestamp': data.get('timestamp', int(now))
                    }
                    self._last_update = now
                    return self._last_pos

        except Exception as e:
            print(f"[ISS] Ana API hatası: {e}")

        # Alternatif API dene (wheretheiss.at)
        try:
            response = requests.get(self.ISS_API_ALT, timeout=10)
            if response.status_code == 200:
                data = response.json()
                self._last_pos = {
                    'lat': float(data.get('latitude', 0)),
                    'lng': float(data.get('longitude', 0)),
                    'timestamp': int(data.get('timestamp', now)),
                    'altitude': float(data.get('altitude', 0)),
                    'velocity': float(data.get('velocity', 0))
                }
                self._last_update = now
                return self._last_pos
        except Exception as e2:
            print(f"[ISS] Alternatif API hatası: {e2}")

        return self._last_pos

    def get_astronauts(self) -> List[Dict]:
        """Uzaydaki astronotlar"""
        try:
            response = requests.get(self.ASTROS_API, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('message') == 'success':
                    return data.get('people', [])
        except Exception as e:
            print(f"[ISS] Astronot hatası: {e}")

        return []

    def get_pass_times(self, lat: float, lon: float, alt: float = 0, n: int = 5) -> List[Dict]:
        """ISS geçiş zamanları (deprecated API - bakım gerekebilir)"""
        try:
            url = f"http://api.open-notify.org/iss-pass.json?lat={lat}&lon={lon}&alt={alt}&n={n}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('message') == 'success':
                    passes = []
                    for p in data.get('response', []):
                        passes.append({
                            'risetime': datetime.fromtimestamp(p.get('risetime', 0)),
                            'duration': p.get('duration', 0)
                        })
                    return passes
        except Exception as e:
            print(f"[ISS] Geçiş zamanları hatası: {e}")

        return []


class CelesTrakTLE:
    """
    CelesTrak TLE verileri (ücretsiz, API key gerektirmez)
    İstemci tarafında satellite.js ile kullanılabilir
    """

    BASE_URL = "https://celestrak.org/NORAD/elements/gp.php"

    GROUPS = {
        'stations': 'stations',  # ISS, Tiangong
        'visual': 'visual',  # Parlak uydular
        'starlink': 'starlink',
        'oneweb': 'oneweb',
        'gps-ops': 'gps-ops',
        'galileo': 'galileo',
        'beidou': 'beidou',
        'glonass': 'glonass',
        'weather': 'weather',
        'noaa': 'noaa',
        'geo': 'geo',  # Geostationary
        'active': 'active',  # Tüm aktif uydular
    }

    def __init__(self):
        self._cache: Dict[str, str] = {}
        self._cache_time: Dict[str, float] = {}
        self._cache_ttl: int = 3600  # 1 saat

    def get_tle(self, group: str = 'stations', format: str = 'json') -> Optional[List[Dict]]:
        """TLE verisi getir"""
        cache_key = f"tle_{group}"
        now = time.time()

        if cache_key in self._cache and (now - self._cache_time.get(cache_key, 0)) < self._cache_ttl:
            return self._cache[cache_key]

        try:
            url = f"{self.BASE_URL}?GROUP={group}&FORMAT={format}"
            response = requests.get(url, timeout=30)

            if response.status_code == 200:
                if format == 'json':
                    data = response.json()
                    self._cache[cache_key] = data
                    self._cache_time[cache_key] = now
                    return data
                else:
                    return response.text

        except Exception as e:
            print(f"[TLE] CelesTrak hatası: {e}")

        return None

    def get_tle_by_norad(self, norad_id: int, format: str = 'json') -> Optional[Dict]:
        """Belirli NORAD ID için TLE"""
        try:
            url = f"{self.BASE_URL}?CATNR={norad_id}&FORMAT={format}"
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                if format == 'json':
                    data = response.json()
                    if data:
                        return data[0] if isinstance(data, list) else data
                else:
                    return response.text

        except Exception as e:
            print(f"[TLE] NORAD {norad_id} hatası: {e}")

        return None


class SatelliteCalculator:
    """
    Uydu konum hesaplamaları
    TLE verilerinden anlık konum hesaplar
    """

    @staticmethod
    def calculate_position_from_tle(tle_line1: str, tle_line2: str, timestamp: datetime = None) -> Optional[Dict]:
        """
        TLE'den uydu konumu hesapla
        NOT: Bu fonksiyon satellite.js'nin Python eşdeğeri - sgp4 kütüphanesi gerektirir
        """
        try:
            from sgp4.api import Satrec, jday

            satellite = Satrec.twoline2rv(tle_line1, tle_line2)

            if timestamp is None:
                timestamp = datetime.utcnow()

            jd, fr = jday(
                timestamp.year, timestamp.month, timestamp.day,
                timestamp.hour, timestamp.minute, timestamp.second + timestamp.microsecond / 1e6
            )

            e, r, v = satellite.sgp4(jd, fr)

            if e != 0:
                return None

            # ECI koordinatlarını lat/lon'a çevir
            lat, lon, alt = SatelliteCalculator._eci_to_geodetic(r, jd + fr)

            return {
                'latitude': lat,
                'longitude': lon,
                'altitude': alt,
                'velocity': math.sqrt(v[0]**2 + v[1]**2 + v[2]**2)
            }

        except ImportError:
            print("[SATELLITE] sgp4 kütüphanesi yüklü değil: pip install sgp4")
            return None
        except Exception as e:
            print(f"[SATELLITE] TLE hesaplama hatası: {e}")
            return None

    @staticmethod
    def _eci_to_geodetic(r: Tuple[float, float, float], julian_date: float) -> Tuple[float, float, float]:
        """ECI koordinatlarını geodetic (lat/lon/alt) çevir"""
        x, y, z = r

        # Earth parameters (WGS84)
        a = 6378.137  # km
        f = 1 / 298.257223563
        e2 = f * (2 - f)

        # GMST (Greenwich Mean Sidereal Time)
        t = (julian_date - 2451545.0) / 36525.0
        gmst = 280.46061837 + 360.98564736629 * (julian_date - 2451545.0) + 0.000387933 * t**2
        gmst = gmst % 360
        if gmst < 0:
            gmst += 360

        # Longitude
        lon = math.degrees(math.atan2(y, x)) - gmst
        if lon > 180:
            lon -= 360
        elif lon < -180:
            lon += 360

        # Latitude (iterative)
        r_xy = math.sqrt(x**2 + y**2)
        lat = math.degrees(math.atan2(z, r_xy))

        for _ in range(10):
            sin_lat = math.sin(math.radians(lat))
            N = a / math.sqrt(1 - e2 * sin_lat**2)
            lat = math.degrees(math.atan2(z + e2 * N * sin_lat, r_xy))

        # Altitude
        sin_lat = math.sin(math.radians(lat))
        N = a / math.sqrt(1 - e2 * sin_lat**2)
        alt = r_xy / math.cos(math.radians(lat)) - N

        return lat, lon, alt


# Global singleton instances
_satellite_tracker: Optional[N2YOTracker] = None
_iss_tracker: Optional[ISSTracker] = None
_celestrak: Optional[CelesTrakTLE] = None


def satellite_tracker_al() -> N2YOTracker:
    """N2YO tracker singleton"""
    global _satellite_tracker
    if _satellite_tracker is None:
        _satellite_tracker = N2YOTracker()
    return _satellite_tracker


def iss_tracker_al() -> ISSTracker:
    """ISS tracker singleton (API key gerektirmez)"""
    global _iss_tracker
    if _iss_tracker is None:
        _iss_tracker = ISSTracker()
    return _iss_tracker


def celestrak_al() -> CelesTrakTLE:
    """CelesTrak TLE singleton"""
    global _celestrak
    if _celestrak is None:
        _celestrak = CelesTrakTLE()
    return _celestrak
