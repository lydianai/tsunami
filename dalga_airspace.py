#!/usr/bin/env python3
"""
TSUNAMI AIRSPACE MODULE - Gerçek Zamanlı Hava Sahası Takibi
===========================================================

OpenSky Network API ile ADS-B tabanlı uçak takibi
"""

import os
import time
import requests
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import threading


@dataclass
class Aircraft:
    """Uçak verisi"""
    icao24: str
    callsign: Optional[str]
    origin_country: str
    latitude: float
    longitude: float
    altitude: float  # metre
    velocity: float  # m/s
    heading: float  # derece
    vertical_rate: float
    on_ground: bool
    last_update: datetime


class OpenSkyTracker:
    """OpenSky Network API istemcisi"""

    BASE_URL = "https://opensky-network.org/api"

    def __init__(self, username: str = None, password: str = None):
        self.auth = (username, password) if username else None
        self._cache: Dict[str, List[Aircraft]] = {}
        self._cache_time: float = 0
        self._cache_ttl: int = 10  # saniye
        self._lock = threading.Lock()

    def get_aircraft_in_area(self, bbox: Tuple[float, float, float, float]) -> List[Aircraft]:
        """
        Belirli bir alandaki uçakları getir

        Args:
            bbox: (lat_min, lon_min, lat_max, lon_max)

        Returns:
            List[Aircraft]: Uçak listesi
        """
        # Rate limiting - cache kontrolü
        now = time.time()
        cache_key = str(bbox)

        with self._lock:
            if cache_key in self._cache and (now - self._cache_time) < self._cache_ttl:
                return self._cache[cache_key]

        try:
            url = f"{self.BASE_URL}/states/all"
            params = {
                'lamin': bbox[0],
                'lomin': bbox[1],
                'lamax': bbox[2],
                'lomax': bbox[3]
            }

            response = requests.get(url, params=params, auth=self.auth, timeout=30)

            if response.status_code == 200:
                data = response.json()
                aircraft = []

                for state in (data.get('states') or []):
                    # state[5] = longitude, state[6] = latitude
                    if state[6] is not None and state[5] is not None:
                        aircraft.append(Aircraft(
                            icao24=state[0],
                            callsign=state[1].strip() if state[1] else None,
                            origin_country=state[2],
                            latitude=state[6],
                            longitude=state[5],
                            altitude=state[13] or state[7] or 0,
                            velocity=state[9] or 0,
                            heading=state[10] or 0,
                            vertical_rate=state[11] or 0,
                            on_ground=state[8],
                            last_update=datetime.now()
                        ))

                with self._lock:
                    self._cache[cache_key] = aircraft
                    self._cache_time = now

                return aircraft

            elif response.status_code == 429:
                print("[AIRSPACE] Rate limit - bekliyor...")
                time.sleep(10)
                return []

            else:
                print(f"[AIRSPACE] OpenSky HTTP {response.status_code}")
                return []

        except requests.exceptions.Timeout:
            print("[AIRSPACE] OpenSky timeout")
            return []
        except requests.exceptions.RequestException as e:
            print(f"[AIRSPACE] OpenSky bağlantı hatası: {e}")
            return []
        except Exception as e:
            print(f"[AIRSPACE] OpenSky hatası: {e}")
            return []

    def get_aircraft_by_icao(self, icao24: str) -> Optional[Aircraft]:
        """ICAO24 koduna göre uçak bilgisi"""
        try:
            url = f"{self.BASE_URL}/states/all"
            params = {'icao24': icao24.lower()}

            response = requests.get(url, params=params, auth=self.auth, timeout=15)

            if response.status_code == 200:
                data = response.json()
                states = data.get('states', [])

                if states and states[0][6] is not None and states[0][5] is not None:
                    state = states[0]
                    return Aircraft(
                        icao24=state[0],
                        callsign=state[1].strip() if state[1] else None,
                        origin_country=state[2],
                        latitude=state[6],
                        longitude=state[5],
                        altitude=state[13] or state[7] or 0,
                        velocity=state[9] or 0,
                        heading=state[10] or 0,
                        vertical_rate=state[11] or 0,
                        on_ground=state[8],
                        last_update=datetime.now()
                    )
        except Exception as e:
            print(f"[AIRSPACE] Uçak sorgu hatası: {e}")

        return None

    def get_turkey_aircraft(self) -> List[Aircraft]:
        """Türkiye hava sahası uçakları"""
        # Türkiye bbox: lat 36-42, lon 26-45
        return self.get_aircraft_in_area((36.0, 26.0, 42.0, 45.0))

    def get_flight_track(self, icao24: str, time_begin: int = 0) -> List[Dict]:
        """
        Uçuş rotası geçmişi (son 30 gün, authenticated kullanıcılar için)

        Args:
            icao24: ICAO24 kodu
            time_begin: Unix timestamp (0 = son uçuş)
        """
        if not self.auth:
            print("[AIRSPACE] Uçuş geçmişi için authentication gerekli")
            return []

        try:
            url = f"{self.BASE_URL}/tracks/all"
            params = {
                'icao24': icao24.lower(),
                'time': time_begin
            }

            response = requests.get(url, params=params, auth=self.auth, timeout=30)

            if response.status_code == 200:
                data = response.json()
                track = []

                for point in data.get('path', []):
                    track.append({
                        'timestamp': point[0],
                        'latitude': point[1],
                        'longitude': point[2],
                        'altitude': point[3],
                        'heading': point[4],
                        'on_ground': point[5]
                    })

                return track

        except Exception as e:
            print(f"[AIRSPACE] Uçuş geçmişi hatası: {e}")

        return []


class ADSBExchangeTracker:
    """
    ADS-B Exchange API (alternatif kaynak)
    Ücretsiz tier için RapidAPI üzerinden erişim
    """

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv('ADSBX_API_KEY', '')
        self.headers = {
            'X-RapidAPI-Key': self.api_key,
            'X-RapidAPI-Host': 'adsbexchange-com1.p.rapidapi.com'
        }

    def get_aircraft_in_area(self, lat: float, lon: float, radius_nm: int = 250) -> List[Dict]:
        """Belirli koordinat etrafındaki uçaklar"""
        if not self.api_key:
            return []

        try:
            url = f"https://adsbexchange-com1.p.rapidapi.com/v2/lat/{lat}/lon/{lon}/dist/{radius_nm}/"
            response = requests.get(url, headers=self.headers, timeout=15)

            if response.status_code == 200:
                data = response.json()
                return data.get('ac', [])

        except Exception as e:
            print(f"[ADSBX] Hata: {e}")

        return []


class ADSBLolTracker:
    """
    ADSB.lol API (tamamen ücretsiz, API key gerektirmez)
    """

    BASE_URL = "https://api.adsb.lol/v2"

    def __init__(self):
        self._cache: Dict[str, any] = {}
        self._cache_time: float = 0
        self._cache_ttl: int = 5  # saniye

    def get_aircraft_in_area(self, lat: float, lon: float, radius_nm: int = 250) -> List[Aircraft]:
        """Belirli koordinat etrafındaki uçaklar"""
        now = time.time()
        cache_key = f"{lat}:{lon}:{radius_nm}"

        if cache_key in self._cache and (now - self._cache_time) < self._cache_ttl:
            return self._cache[cache_key]

        try:
            url = f"{self.BASE_URL}/lat/{lat}/lon/{lon}/dist/{radius_nm}"
            response = requests.get(url, timeout=15)

            if response.status_code == 200:
                data = response.json()
                aircraft = []

                for ac in data.get('ac', []):
                    if ac.get('lat') is not None and ac.get('lon') is not None:
                        aircraft.append(Aircraft(
                            icao24=ac.get('hex', ''),
                            callsign=ac.get('flight', '').strip() if ac.get('flight') else None,
                            origin_country=ac.get('r', 'Unknown'),  # registration country
                            latitude=ac['lat'],
                            longitude=ac['lon'],
                            altitude=ac.get('alt_baro', 0) or ac.get('alt_geom', 0) or 0,
                            velocity=ac.get('gs', 0) * 0.514444 if ac.get('gs') else 0,  # knots -> m/s
                            heading=ac.get('track', 0) or 0,
                            vertical_rate=ac.get('baro_rate', 0) * 0.00508 if ac.get('baro_rate') else 0,  # ft/min -> m/s
                            on_ground=ac.get('alt_baro') == 'ground',
                            last_update=datetime.now()
                        ))

                self._cache[cache_key] = aircraft
                self._cache_time = now
                return aircraft

        except Exception as e:
            print(f"[ADSB.lol] Hata: {e}")

        return []

    def get_turkey_aircraft(self) -> List[Aircraft]:
        """Türkiye merkezi etrafındaki uçaklar"""
        # Türkiye merkezi: Ankara yakını
        return self.get_aircraft_in_area(39.0, 35.0, 400)


# Global tracker instance
_airspace_tracker: Optional[OpenSkyTracker] = None
_adsblol_tracker: Optional[ADSBLolTracker] = None


def airspace_tracker_al() -> OpenSkyTracker:
    """OpenSky tracker singleton"""
    global _airspace_tracker
    if _airspace_tracker is None:
        username = os.getenv('OPENSKY_USERNAME')
        password = os.getenv('OPENSKY_PASSWORD')
        _airspace_tracker = OpenSkyTracker(username, password)
    return _airspace_tracker


def adsblol_tracker_al() -> ADSBLolTracker:
    """ADSB.lol tracker singleton (API key gerektirmez)"""
    global _adsblol_tracker
    if _adsblol_tracker is None:
        _adsblol_tracker = ADSBLolTracker()
    return _adsblol_tracker


def get_best_tracker():
    """
    En iyi mevcut tracker'ı döndür
    OpenSky tercih edilir, yoksa ADSB.lol kullanılır
    """
    opensky = airspace_tracker_al()

    # Test OpenSky
    try:
        test = opensky.get_aircraft_in_area((39.0, 32.0, 40.0, 33.0))
        if test is not None:
            return opensky
    except:
        pass

    # Fallback to ADSB.lol
    return adsblol_tracker_al()
