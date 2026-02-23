#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Live Threat Stream - Palantir-Style Real-Time Threat Map
==========================================================================
Gerçek zamanlı siber güvenlik tehditlerini harita üzerinde canlı göster

Yetenekler:
- Gerçek tehdit simülasyonu (Türkiye ve global)
- Anlık threat markerları haritada belirir
- Zoom seviyesine göre otomatik filtreleme
- WebSocket ile gerçek zamanlı güncelleme
- Threat ping animasyonları
- Sıcaklık grafiği ile görselleştirme
"""

import asyncio
import json
import random
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import math

try:
    import requests
except ImportError:
    requests = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """Tehdit şiddet seviyeleri"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatType(Enum):
    """Tehdit türleri"""
    DDOS = "ddos"
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    BOTNET = "botnet"
    BRUTE_FORCE = "brute_force"
    SQL_INJECTION = "sqli"
    XSS = "xss"
    APT = "apt"
    SCAN = "scan"
    EXPLOIT = "exploit"
    C2 = "c2"
    DEFACEMENT = "defacement"


@dataclass
class ThreatEvent:
    """Tehdit olayı"""
    id: str
    type: ThreatType
    severity: ThreatSeverity
    latitude: float
    longitude: float
    source_ip: str
    target_ip: str
    description: str
    timestamp: datetime
    confidence: float
    country: str = "TR"
    city: str = ""
    details: Dict = None

    def to_dict(self) -> Dict:
        """Dict formatına çevir"""
        return {
            'id': self.id,
            'type': self.type.value,
            'severity': self.severity.value,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'confidence': self.confidence,
            'country': self.country,
            'city': self.city,
            'details': self.details or {}
        }

    def to_geojson(self) -> Dict:
        """GeoJSON formatına çevir"""
        return {
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': [self.longitude, self.latitude]
            },
            'properties': {
                'id': self.id,
                'type': self.type.value,
                'severity': self.severity.value,
                'description': self.description,
                'source_ip': self.source_ip,
                'target_ip': self.target_ip,
                'timestamp': self.timestamp.isoformat(),
                'confidence': self.confidence,
                'country': self.country,
                'city': self.city,
                'ping': True  # Animasyon için
            }
        }


class LiveThreatGenerator:
    """Gerçek zamanlı tehdit üreteici"""

    # Türkiye'nin önemli şehirleri (gerçek koordinatlar)
    TURKEY_CITIES = {
        'Istanbul': (41.0082, 28.9784, 'critical'),
        'Ankara': (39.9334, 32.8597, 'high'),
        'Izmir': (38.4237, 27.1428, 'high'),
        'Bursa': (40.1885, 29.0610, 'medium'),
        'Adana': (37.0642, 37.3833, 'high'),
        'Gaziantep': (37.0642, 37.3833, 'critical'),
        'Konya': (37.8713, 32.4846, 'medium'),
        'Antalya': (36.8969, 30.7133, 'medium'),
        'Kayseri': (38.7351, 35.4810, 'medium'),
        'Samsun': (41.2922, 36.3313, 'medium'),
        'Trabzon': (41.0027, 39.7248, 'medium'),
        'Eskişehir': (39.7667, 30.5185, 'low'),
        'Diyarbakır': (37.9101, 40.2302, 'low'),
        'Şanlıurfa': (37.1674, 38.7955, 'high'),
        'Mersin': (36.8121, 27.8876, 'medium'),
        'İzmit': (40.7657, 29.9391, 'high'),
        'Balıkesir': (39.6485, 27.8826, 'medium'),
        'Manisa': (38.6191, 27.4289, 'medium'),
    }

    # Global önemli şehirler
    GLOBAL_CITIES = {
        'Moscow': (55.7558, 37.6173, 'critical'),
        'Beijing': (39.9042, 116.4074, 'critical'),
        'Washington': (38.9072, -77.0369, 'critical'),
        'London': (51.5074, -0.1278, 'high'),
        'Berlin': (52.5200, 13.4050, 'high'),
        'Paris': (48.8566, 2.3522, 'medium'),
        'Tokyo': (35.6762, 139.6503, 'high'),
        'Sydney': (-33.8687, 151.2093, 'medium'),
        'Tel_Aviv': (32.0853, 34.7818, 'critical'),
        'Dubai': (25.2048, 55.2708, 'high'),
    }

    # Tehdit tipleri ve dağılım ağırlıkları
    THREAT_WEIGHTS = {
        ThreatType.DDOS: 0.15,
        ThreatType.MALWARE: 0.20,
        ThreatType.PHISHING: 0.18,
        ThreatType.RANSOMWARE: 0.12,
        ThreatType.BOTNET: 0.10,
        ThreatType.BRUTE_FORCE: 0.08,
        ThreatType.SQL_INJECTION: 0.07,
        ThreatType.XSS: 0.06,
        ThreatType.APT: 0.03,
        ThreatType.SCAN: 0.01,
    }

    # Türkiye'ye odaklı tehdit senaryoları
    TURKEY_THREAT_SCENARIOS = [
        {
            'type': ThreatType.PHISHING,
            'description': 'Türkçe bankacılığı phishing kampanyası',
            'severity': ThreatSeverity.HIGH,
            'regions': ['Istanbul', 'Ankara', 'Izmir'],
            'weight': 0.25
        },
        {
            'type': ThreatType.RANSOMWARE,
            'description': 'KOBİT sistemlerini hedef alan ransomware',
            'severity': ThreatSeverity.CRITICAL,
            'regions': ['Istanbul', 'Bursa', 'Kocaeli'],
            'weight': 0.20
        },
        {
            'type': ThreatType.DDOS,
            'description': 'Kamu kurumlarına yönelik DDoS saldırıları',
            'severity': ThreatSeverity.HIGH,
            'regions': ['Ankara', 'Istanbul', 'İzmir'],
            'weight': 0.20
        },
        {
            'type': ThreatType.APT,
            'description': 'Kritik altyapılara APT saldırıları',
            'severity': ThreatSeverity.CRITICAL,
            'regions': ['Gaziantep', 'Şanlıurfa', 'Mersin'],
            'weight': 0.15
        },
        {
            'type': ThreatType.MALWARE,
            'description': 'Endüstriyel casus suçlarına malware bulaşması',
            'severity': ThreatSeverity.MEDIUM,
            'regions': ['Konya', 'Kayseri', 'Samsun'],
            'weight': 0.10
        },
        {
            'type': ThreatType.BOTNET,
            'description': 'IoT cihazlardan botnet kurulumu',
            'severity': ThreatSeverity.MEDIUM,
            'regions': ['Istanbul', 'İzmir', 'Bursa', 'Balıkesir'],
            'weight': 0.10
        },
    ]

    def __init__(self, rate_per_minute: int = 5):
        """
        Args:
            rate_per_minute: Dakika başına üretilecek tehdit sayısı
        """
        self.rate_per_minute = rate_per_minute
        self.active_threats = []
        self.threat_history = []
        self.is_running = False
        self.generation_interval = 60 / rate_per_minute  # saniye cinsinden

        logger.info(f"Live Threat Generator başlatıldı - {rate_per_minute} tehdit/dakika")

    def generate_threat(self) -> Optional[ThreatEvent]:
        """Rastgele bir tehdit olayı üret"""
        # Senaryo seç (Türkiye ağırlıklı)
        scenario = random.choices(
            self.TURKEY_THREAT_SCENARIOS,
            weights=[s['weight'] for s in self.TURKEY_THREAT_SCENARIOS],
            k=1
        )[0]

        # Bölge seç
        region_name = random.choice(scenario['regions'])
        city_info = self.TURKEY_CITIES.get(region_name)

        if city_info:
            lat, lng, base_severity = city_info
        else:
            lat, lng = self.TURKEY_CITIES['Istanbul']
            base_severity = ThreatSeverity.HIGH

        # Şehir merkezine yakın rastgele koordinat (±0.5 derece ~55km)
        lat_offset = random.uniform(-0.5, 0.5)
        lng_offset = random.uniform(-0.5, 0.5)

        latitude = lat + lat_offset
        longitude = lng + lng_offset

        # Şiddet seviyesi belirle
        severity_roll = random.random()
        if severity_roll < 0.3:
            severity = ThreatSeverity.CRITICAL
        elif severity_roll < 0.6:
            severity = ThreatSeverity.HIGH
        elif severity_roll < 0.85:
            severity = ThreatSeverity.MEDIUM
        else:
            severity = ThreatSeverity.LOW

        # IP adresleri oluştur
        source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        target_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

        # Confidence belirle (0.6 - 0.95)
        confidence = random.uniform(0.6, 0.95)

        # Timestamp
        timestamp = datetime.now()

        # Unique ID
        threat_id = f"TR-{timestamp.strftime('%Y%m%d%H%M%S')}-{random.randint(1000, 9999)}"

        # Detaylar
        details = {
            'attack_vector': self._get_attack_vector(scenario['type']),
            'affected_systems': random.randint(1, 100),
            'estimated_impact': random.choice(['low', 'medium', 'high', 'critical']),
            'mitigation_status': 'active'
        }

        threat = ThreatEvent(
            id=threat_id,
            type=scenario['type'],
            severity=severity,
            latitude=latitude,
            longitude=longitude,
            source_ip=source_ip,
            target_ip=target_ip,
            description=scenario['description'],
            timestamp=timestamp,
            confidence=confidence,
            country='TR',
            city=region_name,
            details=details
        )

        return threat

    def _get_attack_vector(self, threat_type: ThreatType) -> str:
        """Tehdit tipi için attack vector"""
        vectors = {
            ThreatType.PHISHING: 'email + web',
            ThreatType.RANSOMWARE: 'smb + rdp',
            ThreatType.DDOS: 'udp + tcp flood',
            ThreatType.APT: 'spear phishing + zero-day',
            ThreatType.MALWARE: 'email attachment + drive-by',
            ThreatType.BOTNET: 'iot + ssh',
            ThreatType.BRUTE_FORCE: 'ssh + ftp',
            ThreatType.SQL_INJECTION: 'web form',
            ThreatType.XSS: 'web reflected + stored',
        }
        return vectors.get(threat_type, 'network')

    async def start_streaming(self, duration_minutes: int = 60):
        """
        Tehdit akışını başlat

        Args:
            duration_minutes: Çalışma süresi (dakika)
        """
        self.is_running = True
        end_time = datetime.now() + timedelta(minutes=duration_minutes)

        logger.info(f"Threat streaming başlatılıyor - {duration_minutes} dakika")

        threat_count = 0

        while self.is_running and datetime.now() < end_time:
            # Yeni threat üret
            threat = self.generate_threat()

            if threat:
                self.active_threats.append(threat)
                self.threat_history.append(threat)

                # Eski tehditleri temizle (30 dakikadan sonra)
                cutoff_time = datetime.now() - timedelta(minutes=30)
                self.active_threats = [
                    t for t in self.active_threats
                    if t.timestamp > cutoff_time
                ]

                # Log
                logger.info(
                    f"[THREAT_STREAM] Yeni tehdit: {threat.type.value} - "
                    f"{threat.city} ({threat.latitude:.4f}, {threat.longitude:.4f}) - "
                    f"Severity: {threat.severity.value}"
                )

                threat_count += 1

            # Belirli bir süre bekle (threat generation rate)
            await asyncio.sleep(self.generation_interval)

        logger.info(f"Threat streaming durduruldu - {threat_count} toplam tehdit üretildi")

    def stop_streaming(self):
        """Tehdit akışını durdur"""
        self.is_running = False
        logger.info("Threat streaming durduruldu")

    def get_active_threats(self, zoom_level: int = 6) -> List[Dict]:
        """
        Zoom seviyesine göre tehditleri filtrele

        Args:
            zoom_level: Harita zoom seviyesi (1-18)

        Returns:
            Filtrelenmiş tehdit listesi
        """
        # Zoom seviyesine göre görüntülenebilir tehdit sayısı
        max_threats = {
            1: 5,      # Ülke genel bakış
            2: 10,     # Bölgesel bakış
            3: 20,     # Şehir bakışı
            4: 30,     # Detaylı şehir
            5: 50,     # Mahalle düzeyi
            6: 100,    # Sokak düzeyi
            7: 150,    # Bina düzeyi
            8: 200,    # Detaylı bina
        }

        max_count = max_threats.get(zoom_level, 100)

        # En son tehditleri öncelik ver (zoom seviyesi düşükse daha fazla göster)
        threats_to_show = self.active_threats[-max_count:]

        return [t.to_dict() for t in threats_to_show]

    def get_threat_heatmap_data(self, center_lat: float, center_lng: float,
                            radius_km: float = 50) -> List[Tuple[float, float, float]]:
        """
        Tehdit ısı haritası için veri üret

        Args:
            center_lat: Merkez enlem
            center_lng: Merkez boylam
            radius_km: Yarıçap (km)

        Returns:
            [(lat, lng, intensity), ...]
        """
        heatmap_points = []

        # Her aktif tehdit için ısı haritası noktası
        for threat in self.active_threats[-50:]:  # Son 50 tehdit
            # Mesafe hesapla
            distance = math.sqrt(
                (threat.latitude - center_lat)**2 +
                (threat.longitude - center_lng)**2
            ) * 111  # Yaklaşım km

            if distance <= radius_km:
                # Şiddet hesapla (0.1 - 1.0)
                intensity = {
                    ThreatSeverity.CRITICAL: 1.0,
                    ThreatSeverity.HIGH: 0.8,
                    ThreatSeverity.MEDIUM: 0.5,
                    ThreatSeverity.LOW: 0.2
                }.get(threat.severity, 0.5)

                # Rastgele varyasyon ekle
                intensity *= random.uniform(0.8, 1.2)

                heatmap_points.append((
                    threat.latitude,
                    threat.longitude,
                    min(intensity, 1.0)
                ))

        return heatmap_points


# Global instance
live_threat_generator = LiveThreatGenerator(rate_per_minute=10)


def get_live_threats(zoom_level: int = 6) -> List[Dict]:
    """Wrapper function - aktif tehditleri getir"""
    return live_threat_generator.get_active_threats(zoom_level)


def get_threat_heatmap(center_lat: float, center_lng: float, radius_km: float = 50) -> List[Tuple[float, float, float]]:
    """Wrapper function - tehdit ısı haritası ver"""
    return live_threat_generator.get_threat_heatmap_data(center_lat, center_lng, radius_km)


async def start_threat_stream(duration_minutes: int = 60):
    """Wrapper function - tehdit akışını başlat"""
    await live_threat_generator.start_streaming(duration_minutes)


def stop_threat_stream():
    """Wrapper function - tehdit akışını durdur"""
    live_threat_generator.stop_streaming()


if __name__ == '__main__':
    # Test
    async def test():
        await start_threat_stream(duration_minutes=1)
        threats = get_live_threats(zoom_level=6)
        print(f"Test: {len(threats)} tehdit üretildi")

    asyncio.run(test())
