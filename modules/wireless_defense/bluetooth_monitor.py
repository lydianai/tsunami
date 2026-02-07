#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Bluetooth Guvenlik Izleyici (Bluetooth Security Monitor)
    Yalnizca Pasif Izleme - Aktif Saldiri Yetenegi Yok
================================================================================

    Ozellikler:
    - Supheli Bluetooth cihaz tespiti
    - Eslesme girisimleri izleme
    - Ad sahteciligi (name spoofing) algilama
    - Pasif BLE/Classic Bluetooth tarama

    Bu modul dalga_sigint Bluetooth tarayicisini kullanir.
    Yalnizca PASIF tarama yapar - aktif saldiri YOKTUR.

================================================================================
"""

import logging
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# TSUNAMI icsel bagimliliklari
try:
    from dalga_sigint import SigintDevice, ThreatLevel, DeviceType
    from dalga_sigint.scanners.bluetooth import BluetoothScanner
    from dalga_sigint.core import BluetoothDevice, DeviceCategory, StealthLevel
except ImportError:
    # Test ortami icin yedek tanimlar
    BluetoothScanner = None
    class ThreatLevel(Enum):
        INFO = "info"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class DeviceCategory(Enum):
        PHONE_OTHER = "phone_other"
        LAPTOP_OTHER = "laptop_other"
        AUDIO_OTHER = "audio_other"
        UNKNOWN = "unknown"

logger = logging.getLogger('tsunami.wireless_defense.bluetooth')


# ============================================================================
# VERI YAPILARI
# ============================================================================

class SuspicionReason(Enum):
    """Supheli cihaz nedenleri"""
    UNKNOWN_DEVICE = "bilinmeyen_cihaz"         # Yetkili listede yok
    UNUSUAL_CLASS = "olagan_disi_sinif"         # Beklenmeyen cihaz sinifi
    HIGH_POWER = "yuksek_guc"                   # Anormal yuksek sinyal
    RAPID_RSSI_CHANGE = "hizli_rssi_degisimi"   # Sinyal oynakligi
    NAME_SPOOFING = "ad_sahteciligi"            # Sahte isim
    TRACKING_DEVICE = "izleme_cihazi"           # Takip cihazi (AirTag vb)
    UNUSUAL_SERVICES = "olagan_disi_servisler"  # Supheli servisler
    FIRST_SEEN = "ilk_gorulme"                  # Yeni tespit


@dataclass
class SuspiciousDevice:
    """
    Supheli Bluetooth Cihazi
    Guvenlik riski olusturabilecek cihazlarin tespiti
    """
    mac_address: str                            # Cihaz MAC adresi
    name: Optional[str]                         # Cihaz adi
    device_class: Optional[str]                 # Bluetooth cihaz sinifi
    category: str                               # Kategori (telefon, bilgisayar, vb)
    first_seen: datetime                        # Ilk tespit
    last_seen: datetime                         # Son gorunme
    seen_count: int                             # Gorunme sayisi
    signal_strength: Optional[int]              # Sinyal gucu (RSSI)
    suspicion_reasons: List[SuspicionReason]    # Suphe nedenleri
    threat_level: ThreatLevel                   # Tehdit seviyesi
    confidence: float                           # Guven skoru (0-1)
    vendor: Optional[str]                       # Uretici (OUI)
    services: List[str] = field(default_factory=list)       # BLE servisleri
    metadata: Dict[str, Any] = field(default_factory=dict)  # Ek bilgi

    def to_dict(self) -> Dict[str, Any]:
        """JSON serializasyonu icin dict'e donustur"""
        return {
            'mac_address': self.mac_address,
            'name': self.name,
            'device_class': self.device_class,
            'category': self.category,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'seen_count': self.seen_count,
            'signal_strength': self.signal_strength,
            'suspicion_reasons': [r.value for r in self.suspicion_reasons],
            'threat_level': self.threat_level.value,
            'confidence': self.confidence,
            'vendor': self.vendor,
            'services': self.services,
            'metadata': self.metadata
        }


@dataclass
class PairingAttempt:
    """
    Eslesme Girisimi
    Bluetooth eslesme isteklerinin kaydi
    """
    timestamp: datetime                     # Girisim zamani
    source_mac: str                         # Kaynak MAC
    source_name: Optional[str]              # Kaynak cihaz adi
    target_mac: Optional[str]               # Hedef MAC (biliniyorsa)
    target_name: Optional[str]              # Hedef cihaz adi
    pairing_type: str                       # Eslesme tipi (SSP, Legacy, BLE)
    was_accepted: Optional[bool]            # Kabul edildi mi
    pin_used: bool                          # PIN kullanildi mi
    threat_level: ThreatLevel               # Tehdit seviyesi
    notes: str                              # Notlar

    def to_dict(self) -> Dict[str, Any]:
        return {
            'timestamp': self.timestamp.isoformat(),
            'source_mac': self.source_mac,
            'source_name': self.source_name,
            'target_mac': self.target_mac,
            'target_name': self.target_name,
            'pairing_type': self.pairing_type,
            'was_accepted': self.was_accepted,
            'pin_used': self.pin_used,
            'threat_level': self.threat_level.value,
            'notes': self.notes
        }


@dataclass
class SpoofedNameDetection:
    """
    Ad Sahteciligi Tespiti
    Sahte/yaniltici cihaz adlarinin algilanmasi
    """
    mac_address: str                        # Cihaz MAC adresi
    detected_name: str                      # Tespit edilen ad
    spoofed_target: str                     # Taklit edilen hedef (ornegin "iPhone")
    detected_at: datetime                   # Tespit zamani
    threat_level: ThreatLevel               # Tehdit seviyesi
    confidence: float                       # Guven skoru
    indicators: List[str]                   # Gostergeler
    expected_vendor: Optional[str]          # Beklenen uretici
    actual_vendor: Optional[str]            # Gercek uretici (OUI'dan)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'mac_address': self.mac_address,
            'detected_name': self.detected_name,
            'spoofed_target': self.spoofed_target,
            'detected_at': self.detected_at.isoformat(),
            'threat_level': self.threat_level.value,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'expected_vendor': self.expected_vendor,
            'actual_vendor': self.actual_vendor
        }


# ============================================================================
# ANA MONITOR SINIFI
# ============================================================================

class BluetoothSecurityMonitor:
    """
    Bluetooth Guvenlik Izleyici

    Pasif Bluetooth/BLE guvenlik izleme ve tehdit tespiti.
    AKTIF SALDIRI YETENEGI YOKTUR.

    Ozellikler:
    - Supheli cihaz tespiti (whitelist karsilastirmasi)
    - Eslesme girisimi izleme
    - Ad sahteciligi algilama (vendor/OUI dogrulama)
    - Takip cihazi tespiti (AirTag, Tile, vb)

    Kullanim:
        monitor = BluetoothSecurityMonitor()

        # Supheli cihaz taramasi
        suspicious = monitor.detect_suspicious_devices()

        # Eslesme izleme
        pairings = monitor.monitor_pairing_attempts()

        # Ad sahteciligi kontrolu
        spoofed = monitor.detect_spoofed_names()
    """

    # Vendor OUI -> Marka eslestirmesi
    VENDOR_OUI_MAP = {
        # Apple
        '00:03:93': 'Apple', '00:0A:95': 'Apple', '00:0D:93': 'Apple',
        '00:11:24': 'Apple', '00:14:51': 'Apple', '00:16:CB': 'Apple',
        '00:17:F2': 'Apple', '00:19:E3': 'Apple', '00:1B:63': 'Apple',
        '00:1C:B3': 'Apple', '00:1D:4F': 'Apple', '00:1E:52': 'Apple',
        '00:1F:5B': 'Apple', '00:1F:F3': 'Apple', '00:21:E9': 'Apple',
        '00:22:41': 'Apple', '00:23:12': 'Apple', '00:23:32': 'Apple',
        '00:23:6C': 'Apple', '00:23:DF': 'Apple', '00:24:36': 'Apple',
        '00:25:00': 'Apple', '00:25:4B': 'Apple', '00:25:BC': 'Apple',
        '00:26:08': 'Apple', '00:26:4A': 'Apple', '00:26:B0': 'Apple',
        '00:26:BB': 'Apple', 'AC:BC:32': 'Apple', 'E0:B9:BA': 'Apple',

        # Samsung
        '00:12:47': 'Samsung', '00:13:77': 'Samsung', '00:15:B9': 'Samsung',
        '00:16:32': 'Samsung', '00:17:C9': 'Samsung', '00:18:AF': 'Samsung',
        '00:1A:8A': 'Samsung', '00:1C:43': 'Samsung', '00:1D:25': 'Samsung',
        '00:1D:F6': 'Samsung', '00:1E:7D': 'Samsung', '00:1F:CC': 'Samsung',

        # Google
        '00:1A:11': 'Google', '3C:5A:B4': 'Google', '54:60:09': 'Google',
        '94:EB:2C': 'Google', 'F4:F5:D8': 'Google', 'F4:F5:E8': 'Google',

        # Xiaomi
        '00:9E:C8': 'Xiaomi', '04:CF:8C': 'Xiaomi', '0C:1D:AF': 'Xiaomi',
        '14:F6:5A': 'Xiaomi', '18:59:36': 'Xiaomi', '20:34:FB': 'Xiaomi',

        # Huawei
        '00:18:82': 'Huawei', '00:1E:10': 'Huawei', '00:25:68': 'Huawei',
        '00:25:9E': 'Huawei', '00:46:4B': 'Huawei', '04:C0:6F': 'Huawei',

        # Sony
        '00:01:4A': 'Sony', '00:13:A9': 'Sony', '00:19:63': 'Sony',
        '00:1D:BA': 'Sony', '00:1E:DC': 'Sony', '00:24:BE': 'Sony',

        # Bose
        '00:0C:8A': 'Bose', '04:52:C7': 'Bose', '08:DF:1F': 'Bose',

        # JBL/Harman
        '00:14:9A': 'Harman', '00:1D:DF': 'Harman', '70:99:1C': 'Harman',

        # Tile (takip cihazi)
        '60:5A:3C': 'Tile', 'C4:4E:AC': 'Tile',

        # Fitbit
        '8C:D9:D6': 'Fitbit', 'C8:FF:77': 'Fitbit',
    }

    # Ad kaliplari -> Beklenen vendor
    NAME_VENDOR_PATTERNS = {
        r'(?i)^iphone': 'Apple',
        r'(?i)^ipad': 'Apple',
        r'(?i)^macbook': 'Apple',
        r'(?i)^airpods': 'Apple',
        r'(?i)^apple\s?watch': 'Apple',
        r'(?i)^airtag': 'Apple',

        r'(?i)^galaxy': 'Samsung',
        r'(?i)^samsung': 'Samsung',

        r'(?i)^pixel': 'Google',
        r'(?i)^google\s?home': 'Google',
        r'(?i)^nest': 'Google',
        r'(?i)^chromecast': 'Google',

        r'(?i)^huawei': 'Huawei',
        r'(?i)^honor': 'Huawei',

        r'(?i)^xiaomi': 'Xiaomi',
        r'(?i)^redmi': 'Xiaomi',
        r'(?i)^mi\s': 'Xiaomi',
        r'(?i)^poco': 'Xiaomi',

        r'(?i)^sony': 'Sony',
        r'(?i)^wh-\d': 'Sony',  # Sony kulakliklari
        r'(?i)^wf-\d': 'Sony',

        r'(?i)^bose': 'Bose',
        r'(?i)^quietcomfort': 'Bose',

        r'(?i)^jbl': 'Harman',
        r'(?i)^harman': 'Harman',

        r'(?i)^fitbit': 'Fitbit',
        r'(?i)^tile': 'Tile',
    }

    # Bilinen takip cihazi isim kaliplari
    TRACKER_PATTERNS = [
        r'(?i)airtag',
        r'(?i)tile\s',
        r'(?i)chipolo',
        r'(?i)smarttag',
        r'(?i)galaxy\s?smart\s?tag',
        r'(?i)tracker',
        r'(?i)find\s?my',
    ]

    # Supheli servis UUID'leri
    SUSPICIOUS_SERVICES = {
        '0000180f-0000-1000-8000-00805f9b34fb': 'Battery Service (izleme cihazi olabilir)',
        '0000fd6f-0000-1000-8000-00805f9b34fb': 'Apple Find My (AirTag)',
        'feed-0000-0000-0000-000000000000': 'Tile Tracker',
    }

    def __init__(
        self,
        scanner: Optional[Any] = None,
        alert_callback: Optional[callable] = None,
        known_devices: Optional[List[str]] = None,
        scan_interval: int = 60
    ):
        """
        Bluetooth Guvenlik Izleyici baslatici

        Args:
            scanner: dalga_sigint BluetoothScanner ornegi (opsiyonel)
            alert_callback: Alarm geri cagrisi
            known_devices: Bilinen guvenli cihaz MAC adresleri
            scan_interval: Tarama araligi (saniye)
        """
        self.scanner = scanner
        self.alert_callback = alert_callback
        self.known_devices = set(
            mac.upper() for mac in (known_devices or [])
        )
        self.scan_interval = scan_interval

        # Dahili durum
        self._device_history: Dict[str, Dict] = {}      # MAC -> cihaz bilgisi
        self._rssi_history: Dict[str, List[Tuple[datetime, int]]] = defaultdict(list)  # MAC -> [(zaman, rssi)]
        self._pairing_attempts: List[PairingAttempt] = []  # Eslesme gecmisi
        self._suspicious_cache: Dict[str, SuspiciousDevice] = {}  # MAC -> supheli cihaz
        self._scan_history: List[Dict] = []             # Tarama gecmisi

        logger.info("[Bluetooth Monitor] Pasif Bluetooth guvenlik izleme baslatildi")

    def detect_suspicious_devices(
        self,
        scan_now: bool = True
    ) -> List[SuspiciousDevice]:
        """
        Supheli Cihaz Tespiti

        Tum Bluetooth cihazlarini tarar ve supheli olanlari raporlar.

        Args:
            scan_now: Hemen tarama yap

        Returns:
            List[SuspiciousDevice]: Tespit edilen supheli cihazlar
        """
        suspicious_devices: List[SuspiciousDevice] = []
        now = datetime.now()

        # Mevcut cihazlari tara
        current_devices = self._get_current_devices(scan_now)

        for device in current_devices:
            mac = device.get('mac_address', '').upper()
            if not mac:
                continue

            name = device.get('name', '')
            device_class = device.get('device_class', '')
            rssi = device.get('signal_strength')

            # Suphe nedenlerini topla
            suspicion_reasons: List[SuspicionReason] = []
            confidence = 0.0

            # 1. Bilinmeyen cihaz kontrolu
            if mac not in self.known_devices:
                suspicion_reasons.append(SuspicionReason.UNKNOWN_DEVICE)
                confidence += 0.3

            # 2. Ilk kez gorulen cihaz
            if mac not in self._device_history:
                suspicion_reasons.append(SuspicionReason.FIRST_SEEN)
                confidence += 0.1
                self._device_history[mac] = {
                    'first_seen': now,
                    'last_seen': now,
                    'seen_count': 1
                }
            else:
                self._device_history[mac]['last_seen'] = now
                self._device_history[mac]['seen_count'] += 1

            # 3. Takip cihazi kontrolu
            if self._is_tracking_device(name, device.get('services', [])):
                suspicion_reasons.append(SuspicionReason.TRACKING_DEVICE)
                confidence += 0.5

            # 4. RSSI anomalisi kontrolu
            if rssi:
                self._rssi_history[mac].append((now, rssi))
                # Son 10 olcumu tut
                self._rssi_history[mac] = self._rssi_history[mac][-10:]

                if len(self._rssi_history[mac]) >= 3:
                    rssi_variance = self._calculate_rssi_variance(mac)
                    if rssi_variance > 15:  # 15 dBm'den fazla oynaklık
                        suspicion_reasons.append(SuspicionReason.RAPID_RSSI_CHANGE)
                        confidence += 0.2

            # 5. Yuksek sinyal gucu (cok yakin veya amplified)
            if rssi and rssi > -30:  # -30 dBm'den guclu
                suspicion_reasons.append(SuspicionReason.HIGH_POWER)
                confidence += 0.15

            # 6. Vendor tutarsizligi (ad sahteciligi on kontrolu)
            if name:
                actual_vendor = self._get_vendor_from_oui(mac)
                expected_vendor = self._get_expected_vendor_from_name(name)
                if expected_vendor and actual_vendor and expected_vendor != actual_vendor:
                    suspicion_reasons.append(SuspicionReason.NAME_SPOOFING)
                    confidence += 0.4

            # 7. Supheli servisler
            services = device.get('services', [])
            for service in services:
                if service in self.SUSPICIOUS_SERVICES:
                    suspicion_reasons.append(SuspicionReason.UNUSUAL_SERVICES)
                    confidence += 0.2
                    break

            # Tehdit seviyesi belirle
            if not suspicion_reasons:
                continue  # Supheli degil

            if confidence >= 0.8:
                threat_level = ThreatLevel.CRITICAL
            elif confidence >= 0.6:
                threat_level = ThreatLevel.HIGH
            elif confidence >= 0.4:
                threat_level = ThreatLevel.MEDIUM
            elif confidence >= 0.2:
                threat_level = ThreatLevel.LOW
            else:
                threat_level = ThreatLevel.INFO

            # Supheli cihaz olustur
            suspicious = SuspiciousDevice(
                mac_address=mac,
                name=name if name else None,
                device_class=device_class,
                category=device.get('category', 'unknown'),
                first_seen=self._device_history[mac]['first_seen'],
                last_seen=now,
                seen_count=self._device_history[mac]['seen_count'],
                signal_strength=rssi,
                suspicion_reasons=suspicion_reasons,
                threat_level=threat_level,
                confidence=min(confidence, 1.0),
                vendor=self._get_vendor_from_oui(mac),
                services=services,
                metadata={'raw_device': device}
            )
            suspicious_devices.append(suspicious)

            # Cache'e kaydet
            self._suspicious_cache[mac] = suspicious

            # Yuksek tehdit icin alarm
            if threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                if self.alert_callback:
                    self.alert_callback('suspicious_bluetooth', suspicious.to_dict())

                logger.warning(
                    f"[Bluetooth Monitor] Supheli cihaz: MAC={mac}, "
                    f"Ad={name}, Seviye={threat_level.value}, "
                    f"Nedenler={[r.value for r in suspicion_reasons]}"
                )

        return suspicious_devices

    def monitor_pairing_attempts(
        self,
        duration_seconds: int = 60
    ) -> List[PairingAttempt]:
        """
        Eslesme Girisimi Izleme

        Bluetooth eslesme isteklerini pasif olarak izler.

        Args:
            duration_seconds: Izleme suresi

        Returns:
            List[PairingAttempt]: Tespit edilen eslesme girisimleri

        NOT: Gercek implementasyon icin DBus/bluez entegrasyonu gereklidir.
             Bu fonksiyon kayitli eslesme gecmisini dondurur.
        """
        now = datetime.now()
        cutoff = now - timedelta(seconds=duration_seconds)

        # Son N saniyedeki girisimleri filtrele
        recent_attempts = [
            attempt for attempt in self._pairing_attempts
            if attempt.timestamp > cutoff
        ]

        logger.info(
            f"[Bluetooth Monitor] Eslesme izleme - "
            f"Son {duration_seconds}s: {len(recent_attempts)} girisim"
        )

        return recent_attempts

    def record_pairing_attempt(
        self,
        source_mac: str,
        source_name: Optional[str] = None,
        target_mac: Optional[str] = None,
        target_name: Optional[str] = None,
        pairing_type: str = "SSP",
        was_accepted: Optional[bool] = None,
        pin_used: bool = False
    ) -> PairingAttempt:
        """
        Eslesme Girisimi Kaydet

        Harici kaynaklardan gelen eslesme bilgisini kaydeder.
        (DBus/bluez agent'dan cagrilabilir)

        Args:
            source_mac: Kaynak MAC
            source_name: Kaynak cihaz adi
            target_mac: Hedef MAC
            target_name: Hedef cihaz adi
            pairing_type: Eslesme tipi
            was_accepted: Kabul edildi mi
            pin_used: PIN kullanildi mi

        Returns:
            PairingAttempt: Kaydedilen girisim
        """
        now = datetime.now()

        # Tehdit seviyesi belirle
        threat_level = ThreatLevel.INFO

        # Bilinmeyen cihazdan girisim
        if source_mac.upper() not in self.known_devices:
            threat_level = ThreatLevel.MEDIUM

        # PIN olmadan kabul - guvenlik riski
        if was_accepted and not pin_used:
            threat_level = ThreatLevel.HIGH

        # Notlar
        notes = ""
        if source_mac.upper() not in self.known_devices:
            notes = "Bilinmeyen cihazdan eslesme istegi"
        if was_accepted:
            notes += " - KABUL EDiLDi"
        elif was_accepted is False:
            notes += " - REDDEDiLDi"

        attempt = PairingAttempt(
            timestamp=now,
            source_mac=source_mac.upper(),
            source_name=source_name,
            target_mac=target_mac.upper() if target_mac else None,
            target_name=target_name,
            pairing_type=pairing_type,
            was_accepted=was_accepted,
            pin_used=pin_used,
            threat_level=threat_level,
            notes=notes.strip()
        )

        self._pairing_attempts.append(attempt)

        # Alarm callback
        if threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
            if self.alert_callback:
                self.alert_callback('pairing_attempt', attempt.to_dict())

            logger.warning(
                f"[Bluetooth Monitor] Eslesme girisimi: "
                f"Kaynak={source_mac}, Hedef={target_mac}, "
                f"Seviye={threat_level.value}"
            )

        return attempt

    def detect_spoofed_names(
        self,
        scan_now: bool = True
    ) -> List[SpoofedNameDetection]:
        """
        Ad Sahteciligi Tespiti

        Cihaz adlarini vendor OUI bilgisiyle karsilastirir.
        Tutarsizliklari (sahte adlari) tespit eder.

        Args:
            scan_now: Hemen tarama yap

        Returns:
            List[SpoofedNameDetection]: Tespit edilen ad sahtecilikleri
        """
        spoofed_detections: List[SpoofedNameDetection] = []
        now = datetime.now()

        current_devices = self._get_current_devices(scan_now)

        for device in current_devices:
            mac = device.get('mac_address', '').upper()
            name = device.get('name', '')

            if not mac or not name:
                continue

            # OUI'dan gercek vendor'u al
            actual_vendor = self._get_vendor_from_oui(mac)

            # Isimden beklenen vendor'u al
            expected_vendor = self._get_expected_vendor_from_name(name)

            # Tutarsizlik kontrolu
            if expected_vendor and actual_vendor:
                if expected_vendor.lower() != actual_vendor.lower():
                    # Sahteciligi gostergeleri
                    indicators = []
                    confidence = 0.7

                    indicators.append(
                        f"Cihaz adi '{expected_vendor}' onerirken, "
                        f"OUI '{actual_vendor}' gosteriyor"
                    )

                    # Bilinen taklit kaliplari
                    if re.match(r'(?i)^(iphone|ipad|macbook|airpods)', name):
                        if actual_vendor != 'Apple':
                            indicators.append("Apple cihaz adi, Apple olmayan OUI")
                            confidence += 0.2

                    # Tehdit seviyesi
                    if confidence >= 0.8:
                        threat_level = ThreatLevel.HIGH
                    else:
                        threat_level = ThreatLevel.MEDIUM

                    # Hedef tespiti (hangi marka taklit ediliyor)
                    spoofed_target = expected_vendor

                    detection = SpoofedNameDetection(
                        mac_address=mac,
                        detected_name=name,
                        spoofed_target=spoofed_target,
                        detected_at=now,
                        threat_level=threat_level,
                        confidence=min(confidence, 1.0),
                        indicators=indicators,
                        expected_vendor=expected_vendor,
                        actual_vendor=actual_vendor
                    )
                    spoofed_detections.append(detection)

                    # Alarm callback
                    if self.alert_callback:
                        self.alert_callback('name_spoofing', detection.to_dict())

                    logger.warning(
                        f"[Bluetooth Monitor] Ad sahteciligi tespiti: "
                        f"MAC={mac}, Ad={name}, "
                        f"Beklenen={expected_vendor}, Gercek={actual_vendor}"
                    )

        return spoofed_detections

    # ========================================================================
    # YARDIMCI METODLAR
    # ========================================================================

    def _get_current_devices(self, scan_now: bool) -> List[Dict]:
        """
        Mevcut cihazlari getir

        Scanner varsa tarama yapar, yoksa cache dondurur.
        """
        if scan_now and self.scanner:
            try:
                devices = self.scanner.scan_local()
                result = []
                for dev in devices:
                    if hasattr(dev, 'to_dict'):
                        result.append(dev.to_dict())
                    elif hasattr(dev, '__dict__'):
                        result.append(dev.__dict__)
                    else:
                        result.append(dev)
                return result
            except Exception as e:
                logger.error(f"[Bluetooth Monitor] Tarama hatasi: {e}")
                return []

        # Cache'den dondur
        return [
            {'mac_address': mac, **info}
            for mac, info in self._device_history.items()
        ]

    def _get_vendor_from_oui(self, mac: str) -> Optional[str]:
        """MAC adresinden vendor'u OUI ile bul"""
        mac_upper = mac.upper().replace('-', ':')
        oui = mac_upper[:8]  # Ilk 3 oktet
        return self.VENDOR_OUI_MAP.get(oui)

    def _get_expected_vendor_from_name(self, name: str) -> Optional[str]:
        """Cihaz adindan beklenen vendor'u bul"""
        for pattern, vendor in self.NAME_VENDOR_PATTERNS.items():
            if re.search(pattern, name):
                return vendor
        return None

    def _is_tracking_device(
        self,
        name: str,
        services: List[str]
    ) -> bool:
        """Cihazin takip cihazi olup olmadigini kontrol et"""
        # Isim kontrolu
        if name:
            for pattern in self.TRACKER_PATTERNS:
                if re.search(pattern, name):
                    return True

        # Servis UUID kontrolu
        for service in services:
            if service in self.SUSPICIOUS_SERVICES:
                service_desc = self.SUSPICIOUS_SERVICES[service]
                if 'tracker' in service_desc.lower() or 'find' in service_desc.lower():
                    return True

        return False

    def _calculate_rssi_variance(self, mac: str) -> float:
        """RSSI varyansini hesapla"""
        readings = [rssi for _, rssi in self._rssi_history[mac]]
        if len(readings) < 2:
            return 0.0

        mean = sum(readings) / len(readings)
        variance = sum((x - mean) ** 2 for x in readings) / len(readings)
        return variance ** 0.5  # Standart sapma

    def add_known_device(self, mac: str):
        """Bilinen cihaz listesine MAC ekle"""
        self.known_devices.add(mac.upper())
        logger.info(f"[Bluetooth Monitor] Bilinen cihaz eklendi: {mac}")

    def remove_known_device(self, mac: str):
        """Bilinen cihaz listesinden MAC kaldir"""
        self.known_devices.discard(mac.upper())
        logger.info(f"[Bluetooth Monitor] Bilinen cihaz kaldirildi: {mac}")

    def get_statistics(self) -> Dict[str, Any]:
        """Izleme istatistiklerini getir"""
        return {
            'known_devices_count': len(self.known_devices),
            'tracked_devices': len(self._device_history),
            'suspicious_devices': len(self._suspicious_cache),
            'pairing_attempts': len(self._pairing_attempts),
            'rssi_tracked_devices': len(self._rssi_history)
        }
