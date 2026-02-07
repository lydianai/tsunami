#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI DEPREM MODULE - Gerçek Zamanlı Deprem Takibi
====================================================

AFAD ve USGS API'leri ile Türkiye deprem takibi
Fay hatları görselleştirmesi
Anlık deprem bildirimleri
"""

import os
import time
import requests
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading

@dataclass
class Deprem:
    """Deprem verisi"""
    id: str
    tarih: str
    saat: str
    enlem: float
    boylam: float
    derinlik: float  # km
    buyukluk: float  # magnitude
    il: str
    ilce: str
    yer: str
    kaynak: str
    timestamp: int

    def to_dict(self):
        return asdict(self)


class AFADTracker:
    """AFAD Deprem API İstemcisi"""

    BASE_URL = "https://deprem.afad.gov.tr/apiv2/event"

    def __init__(self):
        self._cache = []
        self._cache_time = 0
        self._cache_ttl = 60  # 60 saniye cache
        self._last_earthquake_id = None

    def son_depremler(self, limit: int = 50, min_buyukluk: float = 0.0) -> List[Deprem]:
        """Son depremleri getir"""
        now = time.time()

        # Cache kontrolü
        if self._cache and (now - self._cache_time) < self._cache_ttl:
            filtered = [d for d in self._cache if d.buyukluk >= min_buyukluk]
            return filtered[:limit]

        try:
            # Son 24 saat
            end = datetime.now()
            start = end - timedelta(hours=24)

            url = f"{self.BASE_URL}/filter"
            params = {
                'start': start.strftime('%Y-%m-%dT%H:%M:%S'),
                'end': end.strftime('%Y-%m-%dT%H:%M:%S'),
                'orderby': 'timedesc',
                'limit': 100
            }

            response = requests.get(url, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                depremler = []

                for item in data:
                    try:
                        # Tarih parse et
                        date_str = item.get('date', '')
                        if 'T' in date_str:
                            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                            tarih = dt.strftime('%Y-%m-%d')
                            saat = dt.strftime('%H:%M:%S')
                            timestamp = int(dt.timestamp())
                        else:
                            tarih = date_str
                            saat = ''
                            timestamp = 0

                        # Lokasyon parse et
                        location = item.get('location', item.get('title', ''))
                        il, ilce = self._parse_location(location)

                        deprem = Deprem(
                            id=str(item.get('eventID', item.get('id', ''))),
                            tarih=tarih,
                            saat=saat,
                            enlem=float(item.get('latitude', item.get('lat', 0))),
                            boylam=float(item.get('longitude', item.get('lng', item.get('lon', 0)))),
                            derinlik=float(item.get('depth', 0)),
                            buyukluk=float(item.get('magnitude', item.get('mag', 0))),
                            il=il,
                            ilce=ilce,
                            yer=location,
                            kaynak='AFAD',
                            timestamp=timestamp
                        )
                        depremler.append(deprem)
                    except Exception as e:
                        print(f"[DEPREM] Parse hatası: {e}")
                        continue

                self._cache = depremler
                self._cache_time = now

                filtered = [d for d in depremler if d.buyukluk >= min_buyukluk]
                return filtered[:limit]

        except Exception as e:
            print(f"[DEPREM] AFAD API hatası: {e}")

        return self._cache[:limit] if self._cache else []

    def _parse_location(self, location: str) -> Tuple[str, str]:
        """Lokasyon stringinden il ve ilçe çıkar"""
        il = ''
        ilce = ''

        if not location:
            return il, ilce

        # Parantez içini al: "AKDENIZ (ANTALYA)" -> il=ANTALYA
        if '(' in location and ')' in location:
            start = location.rfind('(')
            end = location.rfind(')')
            il = location[start+1:end].strip()

            # Parantez öncesi ilçe olabilir
            parts = location[:start].strip().split()
            if parts:
                ilce = ' '.join(parts[-2:]) if len(parts) > 1 else parts[0]
        else:
            # Virgülle ayrılmış olabilir
            parts = location.split(',')
            if len(parts) >= 2:
                il = parts[-1].strip()
                ilce = parts[0].strip()
            else:
                il = location.strip()

        return il, ilce

    def yeni_deprem_var_mi(self) -> Optional[Deprem]:
        """Yeni deprem kontrolü (bildirim için)"""
        depremler = self.son_depremler(limit=1)

        if depremler:
            son = depremler[0]
            if self._last_earthquake_id and son.id != self._last_earthquake_id:
                self._last_earthquake_id = son.id
                return son
            elif not self._last_earthquake_id:
                self._last_earthquake_id = son.id

        return None


class USGSTracker:
    """USGS Deprem API İstemcisi (Yedek)"""

    BASE_URL = "https://earthquake.usgs.gov/fdsnws/event/1/query"

    # Türkiye sınırları
    TURKEY_BBOX = {
        'minlatitude': 35.5,
        'maxlatitude': 42.5,
        'minlongitude': 25.5,
        'maxlongitude': 45.0
    }

    def son_depremler(self, limit: int = 50, min_buyukluk: float = 2.0) -> List[Deprem]:
        """Türkiye bölgesindeki son depremleri getir"""
        try:
            end = datetime.utcnow()
            start = end - timedelta(days=7)

            params = {
                'format': 'geojson',
                'starttime': start.strftime('%Y-%m-%dT%H:%M:%S'),
                'endtime': end.strftime('%Y-%m-%dT%H:%M:%S'),
                'minmagnitude': min_buyukluk,
                'orderby': 'time',
                'limit': limit,
                **self.TURKEY_BBOX
            }

            response = requests.get(self.BASE_URL, params=params, timeout=15)

            if response.status_code == 200:
                data = response.json()
                depremler = []

                for feature in data.get('features', []):
                    props = feature.get('properties', {})
                    coords = feature.get('geometry', {}).get('coordinates', [0, 0, 0])

                    ts = props.get('time', 0) / 1000
                    dt = datetime.fromtimestamp(ts) if ts else datetime.now()

                    deprem = Deprem(
                        id=str(feature.get('id', '')),
                        tarih=dt.strftime('%Y-%m-%d'),
                        saat=dt.strftime('%H:%M:%S'),
                        enlem=coords[1],
                        boylam=coords[0],
                        derinlik=coords[2] if len(coords) > 2 else 0,
                        buyukluk=float(props.get('mag', 0)),
                        il='',
                        ilce='',
                        yer=props.get('place', ''),
                        kaynak='USGS',
                        timestamp=int(ts)
                    )
                    depremler.append(deprem)

                return depremler

        except Exception as e:
            print(f"[DEPREM] USGS API hatası: {e}")

        return []


# Türkiye Fay Hatları (basitleştirilmiş GeoJSON)
TURKIYE_FAY_HATLARI = {
    "type": "FeatureCollection",
    "features": [
        {
            "type": "Feature",
            "properties": {"name": "Kuzey Anadolu Fay Hattı", "risk": "Çok Yüksek", "length_km": 1500},
            "geometry": {
                "type": "LineString",
                "coordinates": [
                    [26.0, 40.7], [27.5, 40.8], [29.0, 40.75], [30.5, 40.7],
                    [32.0, 40.5], [33.5, 40.3], [35.0, 40.0], [36.5, 39.5],
                    [38.0, 39.2], [39.5, 39.5], [41.0, 40.0], [42.5, 40.5]
                ]
            }
        },
        {
            "type": "Feature",
            "properties": {"name": "Doğu Anadolu Fay Hattı", "risk": "Çok Yüksek", "length_km": 700},
            "geometry": {
                "type": "LineString",
                "coordinates": [
                    [35.5, 36.0], [36.5, 36.8], [37.5, 37.5], [38.5, 38.2],
                    [39.5, 38.8], [40.5, 39.3], [41.5, 39.8]
                ]
            }
        },
        {
            "type": "Feature",
            "properties": {"name": "Batı Anadolu Graben Sistemi", "risk": "Yüksek", "length_km": 400},
            "geometry": {
                "type": "LineString",
                "coordinates": [
                    [27.0, 38.0], [27.5, 38.2], [28.0, 38.5], [28.5, 38.8],
                    [29.0, 39.0], [29.5, 39.3]
                ]
            }
        },
        {
            "type": "Feature",
            "properties": {"name": "Ege Graben Sistemi", "risk": "Yüksek", "length_km": 300},
            "geometry": {
                "type": "LineString",
                "coordinates": [
                    [26.5, 37.5], [27.0, 37.8], [27.5, 38.0], [28.0, 38.3],
                    [28.5, 38.5]
                ]
            }
        },
        {
            "type": "Feature",
            "properties": {"name": "Bitlis-Zagros Bindirme Kuşağı", "risk": "Orta", "length_km": 500},
            "geometry": {
                "type": "LineString",
                "coordinates": [
                    [38.0, 37.0], [39.0, 37.5], [40.0, 38.0], [41.0, 38.3],
                    [42.0, 38.5], [43.0, 38.7], [44.0, 39.0]
                ]
            }
        },
        {
            "type": "Feature",
            "properties": {"name": "Ecemiş Fay Zonu", "risk": "Orta", "length_km": 150},
            "geometry": {
                "type": "LineString",
                "coordinates": [
                    [34.8, 37.0], [35.0, 37.5], [35.2, 38.0], [35.4, 38.5]
                ]
            }
        },
        {
            "type": "Feature",
            "properties": {"name": "Tuz Gölü Fay Zonu", "risk": "Orta", "length_km": 200},
            "geometry": {
                "type": "LineString",
                "coordinates": [
                    [33.0, 38.0], [33.3, 38.5], [33.5, 39.0], [33.8, 39.5]
                ]
            }
        }
    ]
}

# Türkiye illeri koordinatları (hava durumu için)
TURKIYE_ILLERI = {
    "Adana": {"lat": 37.0, "lng": 35.33},
    "Adıyaman": {"lat": 37.76, "lng": 38.28},
    "Afyonkarahisar": {"lat": 38.74, "lng": 30.54},
    "Ağrı": {"lat": 39.72, "lng": 43.05},
    "Aksaray": {"lat": 38.37, "lng": 34.03},
    "Amasya": {"lat": 40.65, "lng": 35.83},
    "Ankara": {"lat": 39.93, "lng": 32.86},
    "Antalya": {"lat": 36.89, "lng": 30.71},
    "Ardahan": {"lat": 41.11, "lng": 42.70},
    "Artvin": {"lat": 41.18, "lng": 41.82},
    "Aydın": {"lat": 37.85, "lng": 27.84},
    "Balıkesir": {"lat": 39.65, "lng": 27.89},
    "Bartın": {"lat": 41.64, "lng": 32.34},
    "Batman": {"lat": 37.89, "lng": 41.13},
    "Bayburt": {"lat": 40.26, "lng": 40.23},
    "Bilecik": {"lat": 40.05, "lng": 30.00},
    "Bingöl": {"lat": 38.88, "lng": 40.50},
    "Bitlis": {"lat": 38.40, "lng": 42.12},
    "Bolu": {"lat": 40.74, "lng": 31.61},
    "Burdur": {"lat": 37.72, "lng": 30.29},
    "Bursa": {"lat": 40.19, "lng": 29.06},
    "Çanakkale": {"lat": 40.15, "lng": 26.41},
    "Çankırı": {"lat": 40.60, "lng": 33.62},
    "Çorum": {"lat": 40.55, "lng": 34.96},
    "Denizli": {"lat": 37.78, "lng": 29.09},
    "Diyarbakır": {"lat": 37.92, "lng": 40.22},
    "Düzce": {"lat": 40.84, "lng": 31.16},
    "Edirne": {"lat": 41.68, "lng": 26.56},
    "Elazığ": {"lat": 38.68, "lng": 39.23},
    "Erzincan": {"lat": 39.75, "lng": 39.50},
    "Erzurum": {"lat": 39.91, "lng": 41.28},
    "Eskişehir": {"lat": 39.78, "lng": 30.52},
    "Gaziantep": {"lat": 37.07, "lng": 37.38},
    "Giresun": {"lat": 40.91, "lng": 38.39},
    "Gümüşhane": {"lat": 40.46, "lng": 39.48},
    "Hakkari": {"lat": 37.58, "lng": 43.74},
    "Hatay": {"lat": 36.40, "lng": 36.35},
    "Iğdır": {"lat": 39.92, "lng": 44.05},
    "Isparta": {"lat": 37.76, "lng": 30.55},
    "İstanbul": {"lat": 41.01, "lng": 28.98},
    "İzmir": {"lat": 38.42, "lng": 27.14},
    "Kahramanmaraş": {"lat": 37.58, "lng": 36.94},
    "Karabük": {"lat": 41.20, "lng": 32.62},
    "Karaman": {"lat": 37.19, "lng": 33.23},
    "Kars": {"lat": 40.61, "lng": 43.10},
    "Kastamonu": {"lat": 41.39, "lng": 33.78},
    "Kayseri": {"lat": 38.73, "lng": 35.49},
    "Kırıkkale": {"lat": 39.85, "lng": 33.51},
    "Kırklareli": {"lat": 41.73, "lng": 27.23},
    "Kırşehir": {"lat": 39.15, "lng": 34.16},
    "Kilis": {"lat": 36.72, "lng": 37.12},
    "Kocaeli": {"lat": 40.77, "lng": 29.92},
    "Konya": {"lat": 37.87, "lng": 32.48},
    "Kütahya": {"lat": 39.42, "lng": 29.98},
    "Malatya": {"lat": 38.35, "lng": 38.31},
    "Manisa": {"lat": 38.62, "lng": 27.43},
    "Mardin": {"lat": 37.31, "lng": 40.74},
    "Mersin": {"lat": 36.80, "lng": 34.64},
    "Muğla": {"lat": 37.22, "lng": 28.36},
    "Muş": {"lat": 38.74, "lng": 41.49},
    "Nevşehir": {"lat": 38.63, "lng": 34.71},
    "Niğde": {"lat": 37.97, "lng": 34.69},
    "Ordu": {"lat": 40.98, "lng": 37.88},
    "Osmaniye": {"lat": 37.07, "lng": 36.25},
    "Rize": {"lat": 41.02, "lng": 40.52},
    "Sakarya": {"lat": 40.69, "lng": 30.40},
    "Samsun": {"lat": 41.29, "lng": 36.33},
    "Şanlıurfa": {"lat": 37.17, "lng": 38.79},
    "Siirt": {"lat": 37.93, "lng": 41.94},
    "Sinop": {"lat": 42.03, "lng": 35.15},
    "Sivas": {"lat": 39.75, "lng": 37.02},
    "Şırnak": {"lat": 37.42, "lng": 42.46},
    "Tekirdağ": {"lat": 41.00, "lng": 27.51},
    "Tokat": {"lat": 40.31, "lng": 36.55},
    "Trabzon": {"lat": 41.00, "lng": 39.73},
    "Tunceli": {"lat": 39.11, "lng": 39.55},
    "Uşak": {"lat": 38.68, "lng": 29.41},
    "Van": {"lat": 38.49, "lng": 43.38},
    "Yalova": {"lat": 40.65, "lng": 29.28},
    "Yozgat": {"lat": 39.82, "lng": 34.81},
    "Zonguldak": {"lat": 41.45, "lng": 31.79}
}


class HavaDurumuTracker:
    """Open-Meteo Hava Durumu API İstemcisi"""

    BASE_URL = "https://api.open-meteo.com/v1/forecast"

    # Hava durumu kodları -> açıklama ve emoji
    WEATHER_CODES = {
        0: ("Açık", "☀️"),
        1: ("Az Bulutlu", "🌤️"),
        2: ("Parçalı Bulutlu", "⛅"),
        3: ("Bulutlu", "☁️"),
        45: ("Sisli", "🌫️"),
        48: ("Kırağılı Sis", "🌫️"),
        51: ("Hafif Çisenti", "🌧️"),
        53: ("Orta Çisenti", "🌧️"),
        55: ("Yoğun Çisenti", "🌧️"),
        61: ("Hafif Yağmur", "🌧️"),
        63: ("Orta Yağmur", "🌧️"),
        65: ("Şiddetli Yağmur", "🌧️"),
        66: ("Hafif Dondurucu Yağmur", "🌨️"),
        67: ("Şiddetli Dondurucu Yağmur", "🌨️"),
        71: ("Hafif Kar", "🌨️"),
        73: ("Orta Kar", "❄️"),
        75: ("Şiddetli Kar", "❄️"),
        77: ("Kar Taneleri", "❄️"),
        80: ("Hafif Sağanak", "🌦️"),
        81: ("Orta Sağanak", "🌦️"),
        82: ("Şiddetli Sağanak", "⛈️"),
        85: ("Hafif Kar Sağanağı", "🌨️"),
        86: ("Şiddetli Kar Sağanağı", "🌨️"),
        95: ("Gök Gürültülü Fırtına", "⛈️"),
        96: ("Hafif Dolu", "⛈️"),
        99: ("Şiddetli Dolu", "⛈️")
    }

    def __init__(self):
        self._cache = {}
        self._cache_ttl = 1800  # 30 dakika cache

    def hava_durumu_al(self, lat: float, lng: float, il: str = "") -> Optional[Dict]:
        """Belirli koordinat için hava durumu"""
        cache_key = f"{lat:.2f}_{lng:.2f}"
        now = time.time()

        if cache_key in self._cache:
            data, cache_time = self._cache[cache_key]
            if now - cache_time < self._cache_ttl:
                return data

        try:
            params = {
                'latitude': lat,
                'longitude': lng,
                'current': 'temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m,wind_direction_10m',
                'daily': 'temperature_2m_max,temperature_2m_min,precipitation_sum,weather_code,sunrise,sunset',
                'timezone': 'Europe/Istanbul',
                'forecast_days': 3
            }

            response = requests.get(self.BASE_URL, params=params, timeout=10)

            if response.status_code == 200:
                raw = response.json()

                # Current weather
                current = raw.get('current', {})
                weather_code = current.get('weather_code', 0)
                desc, emoji = self.WEATHER_CODES.get(weather_code, ("Bilinmiyor", "❓"))

                result = {
                    'il': il,
                    'lat': lat,
                    'lng': lng,
                    'guncel': {
                        'sicaklik': current.get('temperature_2m'),
                        'hissedilen': current.get('apparent_temperature'),
                        'nem': current.get('relative_humidity_2m'),
                        'ruzgar_hiz': current.get('wind_speed_10m'),
                        'ruzgar_yon': current.get('wind_direction_10m'),
                        'durum': desc,
                        'emoji': emoji,
                        'kod': weather_code
                    },
                    'gunluk': []
                }

                # Daily forecast
                daily = raw.get('daily', {})
                times = daily.get('time', [])

                for i, t in enumerate(times):
                    code = daily.get('weather_code', [0])[i] if daily.get('weather_code') else 0
                    d, e = self.WEATHER_CODES.get(code, ("Bilinmiyor", "❓"))

                    result['gunluk'].append({
                        'tarih': t,
                        'max': daily.get('temperature_2m_max', [0])[i] if daily.get('temperature_2m_max') else 0,
                        'min': daily.get('temperature_2m_min', [0])[i] if daily.get('temperature_2m_min') else 0,
                        'yagis': daily.get('precipitation_sum', [0])[i] if daily.get('precipitation_sum') else 0,
                        'durum': d,
                        'emoji': e,
                        'gundogumu': daily.get('sunrise', [''])[i] if daily.get('sunrise') else '',
                        'gunbatimi': daily.get('sunset', [''])[i] if daily.get('sunset') else ''
                    })

                self._cache[cache_key] = (result, now)
                return result

        except Exception as e:
            print(f"[HAVA] API hatası: {e}")

        return None

    def il_hava_durumu(self, il: str) -> Optional[Dict]:
        """İl adına göre hava durumu"""
        il_bilgi = TURKIYE_ILLERI.get(il)
        if il_bilgi:
            return self.hava_durumu_al(il_bilgi['lat'], il_bilgi['lng'], il)
        return None


# Global singleton'lar
_afad_tracker = None
_usgs_tracker = None
_hava_tracker = None

def afad_tracker_al() -> AFADTracker:
    global _afad_tracker
    if _afad_tracker is None:
        _afad_tracker = AFADTracker()
    return _afad_tracker

def usgs_tracker_al() -> USGSTracker:
    global _usgs_tracker
    if _usgs_tracker is None:
        _usgs_tracker = USGSTracker()
    return _usgs_tracker

def hava_tracker_al() -> HavaDurumuTracker:
    global _hava_tracker
    if _hava_tracker is None:
        _hava_tracker = HavaDurumuTracker()
    return _hava_tracker

def fay_hatlari_al() -> Dict:
    """Türkiye fay hatları GeoJSON"""
    return TURKIYE_FAY_HATLARI

def iller_listesi_al() -> Dict:
    """Türkiye illeri listesi"""
    return TURKIYE_ILLERI
