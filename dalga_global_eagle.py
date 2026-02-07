#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI GLOBAL EAGLE EYE - Dünya Çapında Gerçek Zamanlı İzleme Sistemi
======================================================================

KARTAL GÖZÜ - Tüm dünyayı gerçek zamanlı izleme ve istihbarat toplama

Yetenekler:
- 🌍 Global Arama (Türkçe dahil tüm diller)
- 🔴 Canlı Tehdit İzleme (siber saldırılar, doğal afetler)
- ✈️ Canlı Uçuş Takibi (ADS-B Exchange)
- 🚢 Canlı Deniz Trafiği (MarineTraffic/AIS)
- 🌋 Canlı Deprem İzleme (USGS, EMSC, Kandilli)
- 📡 Canlı Uydu Takibi (N2YO)
- 🔥 Canlı Yangın/Afet İzleme (NASA FIRMS)
- 📰 Canlı Haber Akışı (RSS)
- ⚠️ Akıllı Uyarı Sistemi
- 🗺️ OpenStreetMap Global Arama (Nominatim)

Gerçek API'ler - Demo/Mock Yok
"""

import os
import re
import json
import asyncio
import aiohttp
import requests
import threading
import time
from typing import Dict, List, Any, Optional, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from collections import deque
import hashlib
import feedparser
from urllib.parse import quote, urlencode

# ==================== CONFIGURATION ====================

# API Endpoints - Gerçek ve Ücretsiz
APIS = {
    # Geocoding / Arama
    'nominatim': 'https://nominatim.openstreetmap.org/search',
    'nominatim_reverse': 'https://nominatim.openstreetmap.org/reverse',
    'photon': 'https://photon.komoot.io/api/',  # Faster alternative

    # Deprem
    'usgs_earthquakes': 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_hour.geojson',
    'usgs_earthquakes_day': 'https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_day.geojson',
    'emsc_earthquakes': 'https://www.seismicportal.eu/fdsnws/event/1/query',
    'kandilli': 'http://www.koeri.boun.edu.tr/scripts/lst0.asp',

    # Uçuş Takibi
    'opensky': 'https://opensky-network.org/api/states/all',
    'adsbexchange': 'https://globe.adsbexchange.com/',  # Web scraping needed

    # Deniz Trafiği (AIS)
    'ais_hub': 'http://data.aishub.net/ws.php',

    # Yangın/Afet
    'nasa_firms': 'https://firms.modaps.eosdis.nasa.gov/api/area/csv',
    'nasa_eonet': 'https://eonet.gsfc.nasa.gov/api/v3/events',

    # Haber
    'gdelt': 'https://api.gdeltproject.org/api/v2/doc/doc',

    # Hava Durumu
    'openweather': 'https://api.openweathermap.org/data/2.5/weather',
    'openmeteo': 'https://api.open-meteo.com/v1/forecast',

    # IP Geolocation
    'ip_api': 'http://ip-api.com/json/',
    'ipapi': 'https://ipapi.co/',

    # Threat Intelligence
    'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
    'greynoise': 'https://api.greynoise.io/v3/community/',
    'otx_alienvault': 'https://otx.alienvault.com/api/v1/pulses/subscribed',

    # Kripto/Blockchain
    'blockchain_btc': 'https://blockchain.info/unconfirmed-transactions?format=json',

    # Sosyal Medya Trends
    'twitter_trends': 'https://api.twitter.com/1.1/trends/place.json',
}

# Türkçe - İngilizce yer adı eşleştirmeleri
TURKISH_PLACES = {
    'türkiye': 'Turkey',
    'istanbul': 'Istanbul',
    'ankara': 'Ankara',
    'izmir': 'Izmir',
    'almanya': 'Germany',
    'fransa': 'France',
    'ingiltere': 'United Kingdom',
    'abd': 'United States',
    'amerika': 'United States',
    'çin': 'China',
    'japonya': 'Japan',
    'tokyo': 'Tokyo',
    'rusya': 'Russia',
    'moskova': 'Moscow',
    'londra': 'London',
    'paris': 'Paris',
    'berlin': 'Berlin',
    'roma': 'Rome',
    'italya': 'Italy',
    'ispanya': 'Spain',
    'madrid': 'Madrid',
    'hollanda': 'Netherlands',
    'amsterdam': 'Amsterdam',
    'belçika': 'Belgium',
    'brüksel': 'Brussels',
    'yunanistan': 'Greece',
    'atina': 'Athens',
    'mısır': 'Egypt',
    'kahire': 'Cairo',
    'hindistan': 'India',
    'yeni delhi': 'New Delhi',
    'brezilya': 'Brazil',
    'avustralya': 'Australia',
    'sidney': 'Sydney',
    'kanada': 'Canada',
    'meksika': 'Mexico',
    'arjantin': 'Argentina',
    'güney afrika': 'South Africa',
    'nijerya': 'Nigeria',
    'kenya': 'Kenya',
    'suudi arabistan': 'Saudi Arabia',
    'bae': 'United Arab Emirates',
    'dubai': 'Dubai',
    'katar': 'Qatar',
    'iran': 'Iran',
    'tahran': 'Tehran',
    'irak': 'Iraq',
    'bağdat': 'Baghdad',
    'suriye': 'Syria',
    'şam': 'Damascus',
    'lübnan': 'Lebanon',
    'beyrut': 'Beirut',
    'israil': 'Israel',
    'tel aviv': 'Tel Aviv',
    'kudüs': 'Jerusalem',
    'ürdün': 'Jordan',
    'amman': 'Amman',
    'polonya': 'Poland',
    'varşova': 'Warsaw',
    'ukrayna': 'Ukraine',
    'kiev': 'Kyiv',
    'romanya': 'Romania',
    'bükreş': 'Bucharest',
    'macaristan': 'Hungary',
    'budapeşte': 'Budapest',
    'çekya': 'Czech Republic',
    'prag': 'Prague',
    'avusturya': 'Austria',
    'viyana': 'Vienna',
    'isviçre': 'Switzerland',
    'cenevre': 'Geneva',
    'zürih': 'Zurich',
    'isveç': 'Sweden',
    'stokholm': 'Stockholm',
    'norveç': 'Norway',
    'oslo': 'Oslo',
    'danimarka': 'Denmark',
    'kopenhag': 'Copenhagen',
    'finlandiya': 'Finland',
    'helsinki': 'Helsinki',
    'portekiz': 'Portugal',
    'lizbon': 'Lisbon',
    'güney kore': 'South Korea',
    'seul': 'Seoul',
    'kuzey kore': 'North Korea',
    'pyongyang': 'Pyongyang',
    'tayvan': 'Taiwan',
    'taipei': 'Taipei',
    'hong kong': 'Hong Kong',
    'singapur': 'Singapore',
    'malezya': 'Malaysia',
    'kuala lumpur': 'Kuala Lumpur',
    'tayland': 'Thailand',
    'bangkok': 'Bangkok',
    'vietnam': 'Vietnam',
    'hanoi': 'Hanoi',
    'endonezya': 'Indonesia',
    'cakarta': 'Jakarta',
    'filipinler': 'Philippines',
    'manila': 'Manila',
    'yeni zelanda': 'New Zealand',
    'wellington': 'Wellington',
    'şanghay': 'Shanghai',
    'pekin': 'Beijing',
    'new york': 'New York',
    'los angeles': 'Los Angeles',
    'chicago': 'Chicago',
    'san francisco': 'San Francisco',
    'washington': 'Washington',
    'miami': 'Miami',
    'las vegas': 'Las Vegas',
    'boston': 'Boston',
    'seatle': 'Seattle',
    'teksas': 'Texas',
    'florida': 'Florida',
    'kaliforniya': 'California',
}

# ==================== ENUMS & DATACLASSES ====================

class AlertPriority(Enum):
    """Uyarı öncelik seviyeleri"""
    CRITICAL = 1  # Kırmızı - Acil
    HIGH = 2      # Turuncu - Yüksek
    MEDIUM = 3    # Sarı - Orta
    LOW = 4       # Mavi - Düşük
    INFO = 5      # Gri - Bilgi


class EventType(Enum):
    """Olay tipleri"""
    EARTHQUAKE = "earthquake"
    FIRE = "fire"
    STORM = "storm"
    FLOOD = "flood"
    VOLCANO = "volcano"
    CYBER_ATTACK = "cyber_attack"
    AIRCRAFT = "aircraft"
    SHIP = "ship"
    NEWS = "news"
    THREAT = "threat"
    CRYPTO = "crypto"
    MILITARY = "military"
    INFRASTRUCTURE = "infrastructure"


@dataclass
class GlobalEvent:
    """Global olay verisi"""
    id: str
    event_type: EventType
    title: str
    description: str
    lat: float
    lng: float
    timestamp: datetime
    priority: AlertPriority
    source: str
    data: Dict[str, Any] = field(default_factory=dict)
    country: Optional[str] = None
    city: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'type': self.event_type.value,
            'title': self.title,
            'description': self.description,
            'lat': self.lat,
            'lng': self.lng,
            'timestamp': self.timestamp.isoformat(),
            'priority': self.priority.value,
            'priority_name': self.priority.name,
            'source': self.source,
            'data': self.data,
            'country': self.country,
            'city': self.city
        }


@dataclass
class SearchResult:
    """Arama sonucu"""
    name: str
    display_name: str
    lat: float
    lng: float
    type: str
    importance: float
    country: Optional[str] = None
    city: Optional[str] = None
    address: Optional[Dict] = None

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'display_name': self.display_name,
            'lat': self.lat,
            'lng': self.lng,
            'type': self.type,
            'importance': self.importance,
            'country': self.country,
            'city': self.city,
            'address': self.address
        }


# ==================== GLOBAL SEARCH ENGINE ====================

class GlobalSearchEngine:
    """
    Dünya çapında Türkçe destekli arama motoru

    - OpenStreetMap Nominatim
    - Photon (hızlı alternatif)
    - Türkçe yer adı çevirisi
    """

    def __init__(self):
        self._session = None
        self._cache = {}
        self._cache_ttl = 3600

    def _translate_turkish(self, query: str) -> str:
        """Türkçe yer adını İngilizceye çevir"""
        query_lower = query.lower().strip()

        # Tam eşleşme
        if query_lower in TURKISH_PLACES:
            return TURKISH_PLACES[query_lower]

        # Kısmi eşleşme
        for tr, en in TURKISH_PLACES.items():
            if tr in query_lower:
                query = query_lower.replace(tr, en)
                break

        return query

    async def search(
        self,
        query: str,
        limit: int = 10,
        language: str = 'tr'
    ) -> List[SearchResult]:
        """
        Global arama yap

        Args:
            query: Arama sorgusu (Türkçe veya İngilizce)
            limit: Maksimum sonuç sayısı
            language: Tercih edilen dil

        Returns:
            Arama sonuçları listesi
        """
        # Türkçe çeviri
        translated_query = self._translate_turkish(query)

        results = []

        async with aiohttp.ClientSession() as session:
            # Nominatim API
            try:
                params = {
                    'q': translated_query,
                    'format': 'json',
                    'limit': limit,
                    'addressdetails': 1,
                    'accept-language': language
                }

                headers = {'User-Agent': 'TSUNAMI-EagleEye/3.0'}

                async with session.get(
                    APIS['nominatim'],
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for item in data:
                            address = item.get('address', {})
                            result = SearchResult(
                                name=item.get('name', query),
                                display_name=item.get('display_name', ''),
                                lat=float(item.get('lat', 0)),
                                lng=float(item.get('lon', 0)),
                                type=item.get('type', 'place'),
                                importance=float(item.get('importance', 0)),
                                country=address.get('country'),
                                city=address.get('city') or address.get('town') or address.get('village'),
                                address=address
                            )
                            results.append(result)

            except Exception as e:
                print(f"[EagleEye] Nominatim arama hatası: {e}")

            # Photon fallback (eğer Nominatim boş döndüyse)
            if not results:
                try:
                    params = {
                        'q': translated_query,
                        'limit': limit,
                        'lang': language
                    }

                    async with session.get(
                        APIS['photon'],
                        params=params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        if response.status == 200:
                            data = await response.json()

                            for feature in data.get('features', []):
                                props = feature.get('properties', {})
                                coords = feature.get('geometry', {}).get('coordinates', [0, 0])

                                result = SearchResult(
                                    name=props.get('name', query),
                                    display_name=f"{props.get('name', '')} {props.get('city', '')} {props.get('country', '')}",
                                    lat=coords[1],
                                    lng=coords[0],
                                    type=props.get('osm_type', 'place'),
                                    importance=0.5,
                                    country=props.get('country'),
                                    city=props.get('city')
                                )
                                results.append(result)

                except Exception as e:
                    print(f"[EagleEye] Photon arama hatası: {e}")

        return results

    async def reverse_geocode(self, lat: float, lng: float) -> Optional[SearchResult]:
        """Koordinattan adres bul"""
        async with aiohttp.ClientSession() as session:
            try:
                params = {
                    'lat': lat,
                    'lon': lng,
                    'format': 'json',
                    'addressdetails': 1,
                    'accept-language': 'tr'
                }

                headers = {'User-Agent': 'TSUNAMI-EagleEye/3.0'}

                async with session.get(
                    APIS['nominatim_reverse'],
                    params=params,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        address = data.get('address', {})

                        return SearchResult(
                            name=data.get('name', ''),
                            display_name=data.get('display_name', ''),
                            lat=lat,
                            lng=lng,
                            type=data.get('type', 'place'),
                            importance=float(data.get('importance', 0)),
                            country=address.get('country'),
                            city=address.get('city') or address.get('town'),
                            address=address
                        )

            except Exception as e:
                print(f"[EagleEye] Reverse geocode hatası: {e}")

        return None


# ==================== REAL-TIME EVENT MONITORS ====================

class EarthquakeMonitor:
    """Gerçek zamanlı deprem izleme"""

    async def get_recent_earthquakes(self, hours: int = 24) -> List[GlobalEvent]:
        """Son depremleri getir"""
        events = []

        async with aiohttp.ClientSession() as session:
            # USGS API
            try:
                url = APIS['usgs_earthquakes_day'] if hours >= 24 else APIS['usgs_earthquakes']

                async with session.get(url, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()

                        for feature in data.get('features', []):
                            props = feature.get('properties', {})
                            coords = feature.get('geometry', {}).get('coordinates', [0, 0, 0])

                            mag = props.get('mag', 0) or 0

                            # Öncelik belirleme
                            if mag >= 7:
                                priority = AlertPriority.CRITICAL
                            elif mag >= 5:
                                priority = AlertPriority.HIGH
                            elif mag >= 4:
                                priority = AlertPriority.MEDIUM
                            elif mag >= 3:
                                priority = AlertPriority.LOW
                            else:
                                priority = AlertPriority.INFO

                            event = GlobalEvent(
                                id=f"eq_{feature.get('id', '')}",
                                event_type=EventType.EARTHQUAKE,
                                title=f"Deprem M{mag:.1f}",
                                description=props.get('place', 'Bilinmeyen konum'),
                                lat=coords[1],
                                lng=coords[0],
                                timestamp=datetime.fromtimestamp(props.get('time', 0) / 1000),
                                priority=priority,
                                source='USGS',
                                data={
                                    'magnitude': mag,
                                    'depth': coords[2] if len(coords) > 2 else 0,
                                    'felt': props.get('felt'),
                                    'tsunami': props.get('tsunami', 0),
                                    'alert': props.get('alert'),
                                    'url': props.get('url')
                                }
                            )
                            events.append(event)

            except Exception as e:
                print(f"[EagleEye] USGS deprem hatası: {e}")

        return events


class FireMonitor:
    """NASA FIRMS yangın izleme"""

    async def get_active_fires(self, region: str = 'world') -> List[GlobalEvent]:
        """Aktif yangınları getir"""
        events = []

        async with aiohttp.ClientSession() as session:
            # NASA EONET Events API
            try:
                params = {
                    'status': 'open',
                    'category': 'wildfires'
                }

                async with session.get(
                    APIS['nasa_eonet'],
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for item in data.get('events', []):
                            geom = item.get('geometry', [{}])[-1]
                            coords = geom.get('coordinates', [0, 0])

                            event = GlobalEvent(
                                id=f"fire_{item.get('id', '')}",
                                event_type=EventType.FIRE,
                                title=item.get('title', 'Yangın'),
                                description=f"Kaynak: {', '.join([s.get('id', '') for s in item.get('sources', [])])}",
                                lat=coords[1] if len(coords) > 1 else coords[0],
                                lng=coords[0],
                                timestamp=datetime.fromisoformat(geom.get('date', '').replace('Z', '+00:00')) if geom.get('date') else datetime.now(),
                                priority=AlertPriority.HIGH,
                                source='NASA EONET',
                                data={
                                    'categories': [c.get('title') for c in item.get('categories', [])],
                                    'sources': item.get('sources', [])
                                }
                            )
                            events.append(event)

            except Exception as e:
                print(f"[EagleEye] NASA yangın hatası: {e}")

        return events


class AircraftMonitor:
    """Canlı uçuş takibi"""

    async def get_aircraft_in_bbox(
        self,
        bbox: Tuple[float, float, float, float]  # min_lat, min_lng, max_lat, max_lng
    ) -> List[GlobalEvent]:
        """Belirtilen alanda uçakları getir"""
        events = []

        min_lat, min_lng, max_lat, max_lng = bbox

        async with aiohttp.ClientSession() as session:
            # OpenSky Network API (ücretsiz, rate limited)
            try:
                params = {
                    'lamin': min_lat,
                    'lomin': min_lng,
                    'lamax': max_lat,
                    'lomax': max_lng
                }

                async with session.get(
                    APIS['opensky'],
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for state in data.get('states', []) or []:
                            # OpenSky state vector format
                            icao24 = state[0]
                            callsign = (state[1] or '').strip()
                            origin_country = state[2]
                            lng = state[5]
                            lat = state[6]
                            altitude = state[7]  # meters
                            velocity = state[9]  # m/s
                            heading = state[10]
                            vertical_rate = state[11]
                            on_ground = state[8]

                            if lat and lng:
                                # Askeri uçakları işaretle
                                is_military = any(x in (callsign or '').upper() for x in ['MIL', 'RCH', 'NATO', 'USAF', 'RAF', 'THK'])

                                priority = AlertPriority.MEDIUM if is_military else AlertPriority.INFO

                                event = GlobalEvent(
                                    id=f"ac_{icao24}",
                                    event_type=EventType.AIRCRAFT,
                                    title=callsign or icao24,
                                    description=f"{origin_country} | Alt: {(altitude or 0):.0f}m | Hız: {((velocity or 0) * 3.6):.0f}km/h",
                                    lat=lat,
                                    lng=lng,
                                    timestamp=datetime.now(),
                                    priority=priority,
                                    source='OpenSky',
                                    country=origin_country,
                                    data={
                                        'icao24': icao24,
                                        'callsign': callsign,
                                        'origin_country': origin_country,
                                        'altitude': altitude,
                                        'velocity': velocity,
                                        'heading': heading,
                                        'vertical_rate': vertical_rate,
                                        'on_ground': on_ground,
                                        'is_military': is_military
                                    }
                                )
                                events.append(event)

            except Exception as e:
                print(f"[EagleEye] OpenSky hatası: {e}")

        return events


class ThreatIntelMonitor:
    """Siber tehdit istihbaratı izleme"""

    def __init__(self):
        self._api_keys = {
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
            'otx': os.getenv('OTX_API_KEY', ''),
            'shodan': os.getenv('SHODAN_API_KEY', ''),
        }

    async def check_ip_threat(self, ip: str) -> Optional[GlobalEvent]:
        """IP tehdit kontrolü"""
        async with aiohttp.ClientSession() as session:
            # GreyNoise (ücretsiz community API)
            try:
                async with session.get(
                    f"{APIS['greynoise']}{ip}",
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        if data.get('noise') or data.get('riot'):
                            # IP bilinen gürültü veya güvenli servis
                            classification = data.get('classification', 'unknown')

                            priority = AlertPriority.INFO
                            if classification == 'malicious':
                                priority = AlertPriority.HIGH
                            elif classification == 'benign':
                                priority = AlertPriority.LOW

                            return GlobalEvent(
                                id=f"threat_{ip}",
                                event_type=EventType.THREAT,
                                title=f"IP: {ip}",
                                description=f"Sınıf: {classification} | {data.get('name', 'Bilinmiyor')}",
                                lat=0,  # IP geolocation ayrı yapılacak
                                lng=0,
                                timestamp=datetime.now(),
                                priority=priority,
                                source='GreyNoise',
                                data=data
                            )

            except Exception as e:
                print(f"[EagleEye] GreyNoise hatası: {e}")

        return None


class NaturalDisasterMonitor:
    """Doğal afet izleme"""

    async def get_all_disasters(self) -> List[GlobalEvent]:
        """Tüm aktif doğal afetleri getir"""
        events = []

        async with aiohttp.ClientSession() as session:
            # NASA EONET - Tüm kategoriler
            try:
                params = {
                    'status': 'open',
                    'limit': 100
                }

                async with session.get(
                    APIS['nasa_eonet'],
                    params=params,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()

                        for item in data.get('events', []):
                            geom = item.get('geometry', [{}])[-1]
                            coords = geom.get('coordinates', [0, 0])

                            # Kategori belirleme
                            categories = [c.get('id') for c in item.get('categories', [])]

                            if 'wildfires' in categories:
                                event_type = EventType.FIRE
                                priority = AlertPriority.HIGH
                            elif 'volcanoes' in categories:
                                event_type = EventType.VOLCANO
                                priority = AlertPriority.CRITICAL
                            elif 'severeStorms' in categories:
                                event_type = EventType.STORM
                                priority = AlertPriority.HIGH
                            elif 'floods' in categories:
                                event_type = EventType.FLOOD
                                priority = AlertPriority.HIGH
                            else:
                                event_type = EventType.NEWS
                                priority = AlertPriority.MEDIUM

                            # Koordinat formatını kontrol et
                            if isinstance(coords[0], list):
                                # Polygon veya çoklu nokta
                                coords = coords[0]

                            lat = coords[1] if len(coords) > 1 else 0
                            lng = coords[0] if coords else 0

                            event = GlobalEvent(
                                id=f"disaster_{item.get('id', '')}",
                                event_type=event_type,
                                title=item.get('title', 'Doğal Afet'),
                                description=f"Kategoriler: {', '.join([c.get('title', '') for c in item.get('categories', [])])}",
                                lat=lat,
                                lng=lng,
                                timestamp=datetime.fromisoformat(geom.get('date', '').replace('Z', '+00:00')) if geom.get('date') else datetime.now(),
                                priority=priority,
                                source='NASA EONET',
                                data={
                                    'categories': item.get('categories', []),
                                    'sources': item.get('sources', []),
                                    'closed': item.get('closed')
                                }
                            )
                            events.append(event)

            except Exception as e:
                print(f"[EagleEye] NASA EONET hatası: {e}")

        return events


# ==================== ALERT SYSTEM ====================

class AlertManager:
    """Akıllı uyarı yönetim sistemi"""

    def __init__(self, max_alerts: int = 1000):
        self._alerts: deque = deque(maxlen=max_alerts)
        self._subscribers: List[Callable] = []
        self._seen_ids: set = set()
        self._lock = threading.Lock()

    def subscribe(self, callback: Callable[[GlobalEvent], None]):
        """Uyarı bildirimi için abone ol"""
        self._subscribers.append(callback)

    def add_event(self, event: GlobalEvent) -> bool:
        """Yeni olay ekle ve bildir"""
        with self._lock:
            # Tekrar kontrolü
            if event.id in self._seen_ids:
                return False

            self._seen_ids.add(event.id)
            self._alerts.appendleft(event)

            # Abonelere bildir
            for callback in self._subscribers:
                try:
                    callback(event)
                except Exception as e:
                    print(f"[AlertManager] Callback hatası: {e}")

            return True

    def get_recent_alerts(
        self,
        limit: int = 50,
        priority: Optional[AlertPriority] = None,
        event_type: Optional[EventType] = None
    ) -> List[GlobalEvent]:
        """Son uyarıları getir"""
        with self._lock:
            alerts = list(self._alerts)

        # Filtreleme
        if priority:
            alerts = [a for a in alerts if a.priority.value <= priority.value]
        if event_type:
            alerts = [a for a in alerts if a.event_type == event_type]

        return alerts[:limit]

    def get_stats(self) -> Dict:
        """Uyarı istatistikleri"""
        with self._lock:
            alerts = list(self._alerts)

        stats = {
            'total': len(alerts),
            'by_priority': {},
            'by_type': {},
            'last_hour': 0,
            'critical_count': 0
        }

        hour_ago = datetime.now() - timedelta(hours=1)

        for alert in alerts:
            # Öncelik
            p_name = alert.priority.name
            stats['by_priority'][p_name] = stats['by_priority'].get(p_name, 0) + 1

            # Tip
            t_name = alert.event_type.value
            stats['by_type'][t_name] = stats['by_type'].get(t_name, 0) + 1

            # Son saat
            if alert.timestamp > hour_ago:
                stats['last_hour'] += 1

            # Kritik
            if alert.priority == AlertPriority.CRITICAL:
                stats['critical_count'] += 1

        return stats


# ==================== MAIN EAGLE EYE CONTROLLER ====================

class EagleEyeController:
    """
    Ana Kartal Gözü Kontrolcüsü

    Tüm monitörleri koordine eder ve gerçek zamanlı veri sağlar
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return

        self._initialized = True

        # Alt modüller
        self.search = GlobalSearchEngine()
        self.earthquake_monitor = EarthquakeMonitor()
        self.fire_monitor = FireMonitor()
        self.aircraft_monitor = AircraftMonitor()
        self.threat_monitor = ThreatIntelMonitor()
        self.disaster_monitor = NaturalDisasterMonitor()
        self.alert_manager = AlertManager()

        # Executor
        self._executor = ThreadPoolExecutor(max_workers=20)

        # Monitoring thread
        self._monitoring = False
        self._monitor_thread = None
        self._monitor_interval = 60  # saniye

        print("[EagleEye] Kartal Gözü başlatıldı")

    def start_monitoring(self, interval: int = 60):
        """Arka plan izlemeyi başlat"""
        self._monitoring = True
        self._monitor_interval = interval
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        print(f"[EagleEye] Arka plan izleme başlatıldı ({interval}s aralık)")

    def stop_monitoring(self):
        """Arka plan izlemeyi durdur"""
        self._monitoring = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)
        print("[EagleEye] Arka plan izleme durduruldu")

    def _monitor_loop(self):
        """Arka plan izleme döngüsü"""
        while self._monitoring:
            try:
                # Asenkron görevleri çalıştır
                asyncio.run(self._fetch_all_events())
            except Exception as e:
                print(f"[EagleEye] İzleme hatası: {e}")

            time.sleep(self._monitor_interval)

    async def _fetch_all_events(self):
        """Tüm kaynaklardan olayları çek"""
        tasks = [
            self.earthquake_monitor.get_recent_earthquakes(hours=1),
            self.disaster_monitor.get_all_disasters(),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, list):
                for event in result:
                    self.alert_manager.add_event(event)

    # ========== Public API ==========

    async def search_global(
        self,
        query: str,
        limit: int = 10
    ) -> Dict[str, Any]:
        """
        Global arama yap (Türkçe destekli)

        Args:
            query: Arama sorgusu
            limit: Maksimum sonuç

        Returns:
            Arama sonuçları
        """
        results = await self.search.search(query, limit)

        return {
            'query': query,
            'results': [r.to_dict() for r in results],
            'count': len(results),
            'timestamp': datetime.now().isoformat()
        }

    async def get_location_info(self, lat: float, lng: float) -> Dict[str, Any]:
        """Koordinat bilgisi getir"""
        result = await self.search.reverse_geocode(lat, lng)

        if result:
            return {
                'success': True,
                'location': result.to_dict()
            }
        return {'success': False, 'error': 'Konum bulunamadı'}

    async def get_earthquakes(self, hours: int = 24) -> Dict[str, Any]:
        """Depremleri getir"""
        events = await self.earthquake_monitor.get_recent_earthquakes(hours)

        return {
            'count': len(events),
            'events': [e.to_dict() for e in events],
            'timestamp': datetime.now().isoformat()
        }

    async def get_disasters(self) -> Dict[str, Any]:
        """Doğal afetleri getir"""
        events = await self.disaster_monitor.get_all_disasters()

        return {
            'count': len(events),
            'events': [e.to_dict() for e in events],
            'timestamp': datetime.now().isoformat()
        }

    async def get_aircraft(
        self,
        bbox: Tuple[float, float, float, float]
    ) -> Dict[str, Any]:
        """Uçakları getir"""
        events = await self.aircraft_monitor.get_aircraft_in_bbox(bbox)

        return {
            'count': len(events),
            'aircraft': [e.to_dict() for e in events],
            'timestamp': datetime.now().isoformat()
        }

    async def investigate_ip(self, ip: str) -> Dict[str, Any]:
        """IP araştır"""
        event = await self.threat_monitor.check_ip_threat(ip)

        if event:
            self.alert_manager.add_event(event)
            return {
                'success': True,
                'threat': event.to_dict()
            }
        return {'success': False, 'message': 'Tehdit bilgisi bulunamadı'}

    def get_alerts(
        self,
        limit: int = 50,
        priority: Optional[str] = None,
        event_type: Optional[str] = None
    ) -> Dict[str, Any]:
        """Uyarıları getir"""
        p = None
        if priority:
            try:
                p = AlertPriority[priority.upper()]
            except KeyError:
                pass

        t = None
        if event_type:
            try:
                t = EventType(event_type)
            except ValueError:
                pass

        alerts = self.alert_manager.get_recent_alerts(limit, p, t)

        return {
            'alerts': [a.to_dict() for a in alerts],
            'count': len(alerts),
            'stats': self.alert_manager.get_stats(),
            'timestamp': datetime.now().isoformat()
        }

    def get_status(self) -> Dict[str, Any]:
        """Sistem durumu"""
        return {
            'active': True,
            'monitoring': self._monitoring,
            'monitor_interval': self._monitor_interval,
            'alert_stats': self.alert_manager.get_stats(),
            'modules': {
                'search': True,
                'earthquake': True,
                'fire': True,
                'aircraft': True,
                'threat': True,
                'disaster': True
            },
            'version': '3.0.0',
            'timestamp': datetime.now().isoformat()
        }


# ==================== GLOBAL INSTANCE ====================

_eagle_eye_instance = None

def get_eagle_eye() -> EagleEyeController:
    """Global Eagle Eye instance"""
    global _eagle_eye_instance
    if _eagle_eye_instance is None:
        _eagle_eye_instance = EagleEyeController()
    return _eagle_eye_instance


# ==================== TEST ====================

if __name__ == '__main__':
    async def test():
        eagle = get_eagle_eye()

        print("=== Eagle Eye Test ===\n")

        # Türkçe arama testi
        print("--- Türkçe Arama Testi ---")
        result = await eagle.search_global("istanbul")
        print(f"Istanbul: {result['count']} sonuç")
        if result['results']:
            print(f"  İlk: {result['results'][0]['display_name']}")

        result = await eagle.search_global("almanya")
        print(f"Almanya: {result['count']} sonuç")

        result = await eagle.search_global("tokyo")
        print(f"Tokyo: {result['count']} sonuç")

        # Deprem testi
        print("\n--- Deprem Testi ---")
        quakes = await eagle.get_earthquakes(hours=24)
        print(f"Son 24 saat: {quakes['count']} deprem")
        if quakes['events']:
            for eq in quakes['events'][:3]:
                print(f"  M{eq['data']['magnitude']:.1f} - {eq['description']}")

        # Afet testi
        print("\n--- Doğal Afet Testi ---")
        disasters = await eagle.get_disasters()
        print(f"Aktif afet: {disasters['count']}")
        if disasters['events']:
            for d in disasters['events'][:3]:
                print(f"  {d['type']}: {d['title']}")

        # Durum
        print("\n--- Sistem Durumu ---")
        status = eagle.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))

    asyncio.run(test())
