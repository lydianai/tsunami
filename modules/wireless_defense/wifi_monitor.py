#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI WiFi Guvenlik Izleyici (WiFi Security Monitor)
    Yalnizca Pasif Izleme - Aktif Saldiri Yetenegi Yok
================================================================================

    Ozellikler:
    - Sahte erisim noktasi (Rogue AP) tespiti
    - Evil Twin saldirisi algilama
    - Deauth flood saldirisi izleme
    - Sifreleme guc analizi
    - Gizli ag tespiti

    Bu modul dalga_sigint WiFi tarayicisini kullanir.
    Yalnizca PASIF tarama yapar - paket enjeksiyonu YOKTUR.

================================================================================
"""

import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

# TSUNAMI icsel bagimliliklari
try:
    from dalga_sigint import SigintDevice, ThreatLevel, DeviceType
    from dalga_sigint.scanners.wifi import WiFiScanner
    from dalga_sigint.core import WiFiNetwork, EncryptionType, StealthLevel
except ImportError:
    # Test ortami icin yedek tanimlar
    WiFiScanner = None
    class ThreatLevel(Enum):
        INFO = "info"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"

    class EncryptionType(Enum):
        OPEN = "Open"
        WEP = "WEP"
        WPA = "WPA"
        WPA2 = "WPA2"
        WPA3 = "WPA3"

logger = logging.getLogger('tsunami.wireless_defense.wifi')


# ============================================================================
# VERI YAPILARI
# ============================================================================

@dataclass
class RogueAPDetection:
    """
    Sahte Erisim Noktasi Tespiti
    Yetkisiz AP'lerin bulunmasini raporlar
    """
    bssid: str                          # AP'nin MAC adresi
    ssid: Optional[str]                 # Ag adi
    first_detected: datetime            # Ilk tespit zamani
    last_seen: datetime                 # Son gorunme zamani
    signal_strength: Optional[int]      # Sinyal gucu (dBm)
    channel: Optional[int]              # Kanal
    encryption: Optional[str]           # Sifreleme tipi
    vendor: Optional[str]               # Uretici
    threat_level: ThreatLevel           # Tehdit seviyesi
    reason: str                         # Tespit nedeni
    confidence: float                   # Guven skoru (0-1)
    location: Optional[Dict] = None     # Konum bilgisi
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """JSON serializasyonu icin dict'e donustur"""
        return {
            'bssid': self.bssid,
            'ssid': self.ssid,
            'first_detected': self.first_detected.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'signal_strength': self.signal_strength,
            'channel': self.channel,
            'encryption': self.encryption,
            'vendor': self.vendor,
            'threat_level': self.threat_level.value,
            'reason': self.reason,
            'confidence': self.confidence,
            'location': self.location,
            'metadata': self.metadata
        }


@dataclass
class EvilTwinDetection:
    """
    Evil Twin Saldirisi Tespiti
    Ayni SSID'ye sahip farkli BSSID'ler
    """
    ssid: str                           # Hedef SSID
    original_bssid: str                 # Orijinal AP'nin BSSID'si
    evil_twin_bssid: str                # Sahte AP'nin BSSID'si
    detected_at: datetime               # Tespit zamani
    original_signal: Optional[int]      # Orijinal sinyal gucu
    evil_twin_signal: Optional[int]     # Sahte sinyal gucu
    original_channel: Optional[int]     # Orijinal kanal
    evil_twin_channel: Optional[int]    # Sahte kanal
    original_encryption: Optional[str]  # Orijinal sifreleme
    evil_twin_encryption: Optional[str] # Sahte sifreleme
    threat_level: ThreatLevel           # Tehdit seviyesi
    confidence: float                   # Guven skoru
    indicators: List[str] = field(default_factory=list)  # Gostergeler

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ssid': self.ssid,
            'original_bssid': self.original_bssid,
            'evil_twin_bssid': self.evil_twin_bssid,
            'detected_at': self.detected_at.isoformat(),
            'original_signal': self.original_signal,
            'evil_twin_signal': self.evil_twin_signal,
            'original_channel': self.original_channel,
            'evil_twin_channel': self.evil_twin_channel,
            'original_encryption': self.original_encryption,
            'evil_twin_encryption': self.evil_twin_encryption,
            'threat_level': self.threat_level.value,
            'confidence': self.confidence,
            'indicators': self.indicators
        }


@dataclass
class DeauthAttackEvent:
    """
    Deauthentication Saldirisi Olayi
    Deauth frame flood tespiti
    """
    target_bssid: str                   # Hedef AP
    target_ssid: Optional[str]          # Hedef SSID
    detected_at: datetime               # Tespit zamani
    deauth_count: int                   # Deauth frame sayisi
    duration_seconds: float             # Saldiri suresi
    source_macs: List[str]              # Kaynak MAC adresleri
    affected_clients: int               # Etkilenen istemci sayisi
    threat_level: ThreatLevel           # Tehdit seviyesi
    attack_type: str                    # Saldiri tipi (broadcast/targeted)
    is_active: bool                     # Saldiri hala aktif mi

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target_bssid': self.target_bssid,
            'target_ssid': self.target_ssid,
            'detected_at': self.detected_at.isoformat(),
            'deauth_count': self.deauth_count,
            'duration_seconds': self.duration_seconds,
            'source_macs': self.source_macs,
            'affected_clients': self.affected_clients,
            'threat_level': self.threat_level.value,
            'attack_type': self.attack_type,
            'is_active': self.is_active
        }


@dataclass
class EncryptionAnalysis:
    """
    Sifreleme Guc Analizi
    Zayif/guvenli olmayan sifreleme tespiti
    """
    bssid: str                          # AP BSSID
    ssid: Optional[str]                 # SSID
    encryption_type: str                # Sifreleme tipi
    is_secure: bool                     # Guvenli mi
    weakness_score: int                 # Zafiyet skoru (0-100)
    vulnerabilities: List[str]          # Bilinen zafiyetler
    recommendation: str                 # Onerilen eylem
    analyzed_at: datetime               # Analiz zamani

    def to_dict(self) -> Dict[str, Any]:
        return {
            'bssid': self.bssid,
            'ssid': self.ssid,
            'encryption_type': self.encryption_type,
            'is_secure': self.is_secure,
            'weakness_score': self.weakness_score,
            'vulnerabilities': self.vulnerabilities,
            'recommendation': self.recommendation,
            'analyzed_at': self.analyzed_at.isoformat()
        }


@dataclass
class HiddenNetworkInfo:
    """
    Gizli Ag Bilgisi
    SSID yayinlamayan aglarin tespiti
    """
    bssid: str                          # AP BSSID
    channel: Optional[int]              # Kanal
    signal_strength: Optional[int]      # Sinyal gucu
    encryption: Optional[str]           # Sifreleme
    first_seen: datetime                # Ilk gorunme
    last_seen: datetime                 # Son gorunme
    vendor: Optional[str]               # Uretici
    probing_clients: int                # Probe eden istemci sayisi
    risk_assessment: str                # Risk degerlendirmesi

    def to_dict(self) -> Dict[str, Any]:
        return {
            'bssid': self.bssid,
            'channel': self.channel,
            'signal_strength': self.signal_strength,
            'encryption': self.encryption,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'vendor': self.vendor,
            'probing_clients': self.probing_clients,
            'risk_assessment': self.risk_assessment
        }


# ============================================================================
# ANA MONITOR SINIFI
# ============================================================================

class WiFiSecurityMonitor:
    """
    WiFi Guvenlik Izleyici

    Pasif WiFi guvenlik izleme ve tehdit tespiti.
    AKTIF SALDIRI YETENEGI YOKTUR.

    Ozellikler:
    - Sahte AP tespiti (whitelist karsilastirmasi)
    - Evil Twin saldiri algilama
    - Deauth flood izleme
    - Sifreleme analizi
    - Gizli ag tespiti

    Kullanim:
        monitor = WiFiSecurityMonitor()

        # Yetkili AP listesi ile sahte AP tespiti
        rogue_aps = monitor.detect_rogue_ap(authorized_list)

        # Evil Twin kontrolu
        evil_twins = monitor.detect_evil_twin("HedefSSID")

        # Deauth saldiri izleme
        attacks = monitor.monitor_deauth_attacks()
    """

    # Zayif sifreleme tipleri
    WEAK_ENCRYPTION = {
        'Open': {
            'score': 100,
            'vulnerabilities': ['Sifreleme yok', 'Tum trafik okunabilir', 'MITM saldirisi kolay'],
            'recommendation': 'Derhal WPA2/WPA3 etkinlestirin'
        },
        'WEP': {
            'score': 90,
            'vulnerabilities': ['RC4 zafiyeti', 'IV collision', 'Dakikalar icinde kirilebilir'],
            'recommendation': 'WEP kullanmayin, WPA2/WPA3 gecin'
        },
        'WPA': {
            'score': 60,
            'vulnerabilities': ['TKIP zafiyetleri', 'Eski protokol'],
            'recommendation': 'WPA2-AES veya WPA3 oneriliyor'
        }
    }

    # Guvenli sifreleme tipleri
    SECURE_ENCRYPTION = {'WPA2', 'WPA3', 'WPA2-Enterprise', 'WPA3-Enterprise'}

    def __init__(
        self,
        scanner: Optional[Any] = None,
        alert_callback: Optional[callable] = None,
        scan_interval: int = 30,
        deauth_threshold: int = 10,
        deauth_window_seconds: int = 5
    ):
        """
        WiFi Guvenlik Izleyici baslatici

        Args:
            scanner: dalga_sigint WiFiScanner ornegi (opsiyonel)
            alert_callback: Alarm geri cagrisi
            scan_interval: Tarama araligi (saniye)
            deauth_threshold: Deauth alarm esigi
            deauth_window_seconds: Deauth sayma penceresi
        """
        self.scanner = scanner
        self.alert_callback = alert_callback
        self.scan_interval = scan_interval
        self.deauth_threshold = deauth_threshold
        self.deauth_window_seconds = deauth_window_seconds

        # Dahili durum
        self._known_networks: Dict[str, Dict] = {}      # BSSID -> ag bilgisi
        self._ssid_bssid_map: Dict[str, Set[str]] = defaultdict(set)  # SSID -> BSSID'ler
        self._deauth_counters: Dict[str, List[datetime]] = defaultdict(list)  # BSSID -> deauth zamanlari
        self._hidden_networks: Dict[str, HiddenNetworkInfo] = {}  # BSSID -> gizli ag
        self._scan_history: List[Dict] = []             # Tarama gecmisi
        self._detection_history: List[Dict] = []        # Tespit gecmisi

        logger.info("[WiFi Monitor] Pasif WiFi guvenlik izleme baslatildi")

    def detect_rogue_ap(
        self,
        authorized_list: List[Dict[str, str]],
        scan_now: bool = True
    ) -> List[RogueAPDetection]:
        """
        Sahte Erisim Noktasi Tespiti

        Taranan aglari yetkili listeyle karsilastirir.
        Yetkisiz/sahte AP'leri tespit eder.

        Args:
            authorized_list: Yetkili AP listesi
                [{'bssid': 'AA:BB:CC:DD:EE:FF', 'ssid': 'KurumsalAg'}, ...]
            scan_now: Hemen tarama yap

        Returns:
            List[RogueAPDetection]: Tespit edilen sahte AP'ler
        """
        rogue_aps: List[RogueAPDetection] = []
        now = datetime.now()

        # Yetkili BSSID ve SSID setleri olustur
        # Buyuk/kucuk harf duyarsiz karsilastirma icin normalize et
        authorized_bssids = {
            ap.get('bssid', '').upper()
            for ap in authorized_list
            if ap.get('bssid')
        }
        authorized_ssids = {
            ap.get('ssid', '')
            for ap in authorized_list
            if ap.get('ssid')
        }

        # Mevcut aglari tara veya cache kullan
        current_networks = self._get_current_networks(scan_now)

        for network in current_networks:
            bssid = network.get('bssid', '').upper()
            ssid = network.get('ssid', '')

            if not bssid:
                continue

            is_rogue = False
            reason = ""
            confidence = 0.0
            threat_level = ThreatLevel.INFO

            # Kontrol 1: BSSID yetkili listede mi?
            if bssid not in authorized_bssids:
                # Yetkili SSID kullanan yetkisiz BSSID - yuksek tehdit
                if ssid in authorized_ssids:
                    is_rogue = True
                    reason = f"Yetkisiz BSSID yetkili SSID kullanıyor: {ssid}"
                    confidence = 0.95
                    threat_level = ThreatLevel.CRITICAL
                else:
                    # Bilinmeyen ag - dusuk tehdit (normal olabilir)
                    is_rogue = True
                    reason = "Yetkili listede olmayan bilinmeyen ağ"
                    confidence = 0.5
                    threat_level = ThreatLevel.LOW

            # Kontrol 2: Benzer SSID kontrolu (typosquatting)
            if not is_rogue and ssid:
                for auth_ssid in authorized_ssids:
                    similarity = self._calculate_similarity(ssid, auth_ssid)
                    if 0.7 < similarity < 1.0:
                        is_rogue = True
                        reason = f"Benzer SSID tespiti (typosquatting): {ssid} ~ {auth_ssid}"
                        confidence = similarity
                        threat_level = ThreatLevel.HIGH
                        break

            if is_rogue:
                detection = RogueAPDetection(
                    bssid=bssid,
                    ssid=ssid if ssid else None,
                    first_detected=now,
                    last_seen=now,
                    signal_strength=network.get('signal_strength'),
                    channel=network.get('channel'),
                    encryption=network.get('encryption'),
                    vendor=network.get('vendor'),
                    threat_level=threat_level,
                    reason=reason,
                    confidence=confidence,
                    metadata={'authorized_list_size': len(authorized_list)}
                )
                rogue_aps.append(detection)

                # Alarm callback
                if self.alert_callback and threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                    self.alert_callback('rogue_ap', detection.to_dict())

                logger.warning(
                    f"[WiFi Monitor] Sahte AP tespiti: BSSID={bssid}, "
                    f"SSID={ssid}, Seviye={threat_level.value}, Neden={reason}"
                )

        # Gecmise kaydet
        self._detection_history.append({
            'type': 'rogue_ap_scan',
            'timestamp': now.isoformat(),
            'rogue_count': len(rogue_aps),
            'total_scanned': len(current_networks)
        })

        return rogue_aps

    def detect_evil_twin(
        self,
        ssid: str,
        known_bssid: Optional[str] = None,
        scan_now: bool = True
    ) -> List[EvilTwinDetection]:
        """
        Evil Twin Saldirisi Tespiti

        Ayni SSID'yi yayinlayan birden fazla AP tespit eder.
        Gercek AP'yi sahtesininden ayirt etmeye calisir.

        Args:
            ssid: Kontrol edilecek SSID
            known_bssid: Bilinen gercek AP'nin BSSID'si (opsiyonel)
            scan_now: Hemen tarama yap

        Returns:
            List[EvilTwinDetection]: Tespit edilen Evil Twin saldirilari
        """
        evil_twins: List[EvilTwinDetection] = []
        now = datetime.now()

        # Mevcut aglari tara
        current_networks = self._get_current_networks(scan_now)

        # Hedef SSID'yi yayinlayan tum AP'leri bul
        matching_aps = [
            net for net in current_networks
            if net.get('ssid', '').lower() == ssid.lower()
        ]

        # Birden fazla AP ayni SSID'yi yayinliyorsa
        if len(matching_aps) > 1:
            # Bilinen BSSID varsa onu orijinal olarak kullan
            if known_bssid:
                original = next(
                    (ap for ap in matching_aps
                     if ap.get('bssid', '').upper() == known_bssid.upper()),
                    matching_aps[0]  # Bulunamazsa ilkini kullan
                )
            else:
                # En guclu sinyali olan veya ilk goruneni orijinal kabul et
                original = max(
                    matching_aps,
                    key=lambda x: x.get('signal_strength', -100)
                )

            original_bssid = original.get('bssid', '').upper()

            # Diger AP'leri kontrol et
            for ap in matching_aps:
                ap_bssid = ap.get('bssid', '').upper()
                if ap_bssid == original_bssid:
                    continue

                # Evil Twin gostergeleri
                indicators = []
                confidence = 0.5  # Baz guven skoru

                # Sifreleme farkliligi - buyuk gosterge
                if ap.get('encryption') != original.get('encryption'):
                    indicators.append(
                        f"Farkli sifreleme: {ap.get('encryption')} vs {original.get('encryption')}"
                    )
                    confidence += 0.2

                # Kanal farkliligi
                if ap.get('channel') != original.get('channel'):
                    indicators.append(
                        f"Farkli kanal: {ap.get('channel')} vs {original.get('channel')}"
                    )
                    confidence += 0.1

                # Daha guclu sinyal (bait olabilir)
                ap_signal = ap.get('signal_strength', -100)
                orig_signal = original.get('signal_strength', -100)
                if ap_signal > orig_signal + 10:  # 10dB daha guclu
                    indicators.append(
                        f"Suphe verici yuksek sinyal: {ap_signal} dBm (orijinal: {orig_signal} dBm)"
                    )
                    confidence += 0.15

                # Farkli vendor
                if ap.get('vendor') != original.get('vendor'):
                    indicators.append(
                        f"Farkli uretici: {ap.get('vendor')} vs {original.get('vendor')}"
                    )
                    confidence += 0.1

                # Tehdit seviyesini belirle
                if confidence >= 0.8:
                    threat_level = ThreatLevel.CRITICAL
                elif confidence >= 0.6:
                    threat_level = ThreatLevel.HIGH
                else:
                    threat_level = ThreatLevel.MEDIUM

                detection = EvilTwinDetection(
                    ssid=ssid,
                    original_bssid=original_bssid,
                    evil_twin_bssid=ap_bssid,
                    detected_at=now,
                    original_signal=orig_signal,
                    evil_twin_signal=ap_signal,
                    original_channel=original.get('channel'),
                    evil_twin_channel=ap.get('channel'),
                    original_encryption=original.get('encryption'),
                    evil_twin_encryption=ap.get('encryption'),
                    threat_level=threat_level,
                    confidence=min(confidence, 1.0),
                    indicators=indicators
                )
                evil_twins.append(detection)

                # Alarm callback
                if self.alert_callback:
                    self.alert_callback('evil_twin', detection.to_dict())

                logger.warning(
                    f"[WiFi Monitor] Evil Twin tespiti: SSID={ssid}, "
                    f"Sahte BSSID={ap_bssid}, Gostergeler={len(indicators)}"
                )

        # SSID -> BSSID haritasini guncelle
        for ap in matching_aps:
            self._ssid_bssid_map[ssid.lower()].add(ap.get('bssid', '').upper())

        return evil_twins

    def monitor_deauth_attacks(
        self,
        target_bssid: Optional[str] = None,
        duration_seconds: int = 60
    ) -> List[DeauthAttackEvent]:
        """
        Deauthentication Saldiri Izleme

        Deauth frame flood saldirilerini pasif olarak izler.
        NOT: Monitor mod destegi gerektirir (varsa).

        Args:
            target_bssid: Izlenecek belirli AP (opsiyonel)
            duration_seconds: Izleme suresi

        Returns:
            List[DeauthAttackEvent]: Tespit edilen deauth saldirilari

        NOT: Bu fonksiyon gercek deauth frame yakalama icin
             monitor mod ve libpcap gerektirir. Mevcut degilse
             simule edilmis veri dondurur.
        """
        attacks: List[DeauthAttackEvent] = []
        now = datetime.now()

        # Monitor mod kontrolu ve deauth frame yakalama
        # NOT: Gercek implementasyon icin scapy/libpcap gerekli

        logger.info(
            f"[WiFi Monitor] Deauth izleme basladi - "
            f"Hedef: {target_bssid or 'tum aglar'}, Sure: {duration_seconds}s"
        )

        # Mevcut deauth sayaclarina bak
        window_start = now - timedelta(seconds=self.deauth_window_seconds)

        for bssid, timestamps in self._deauth_counters.items():
            # Hedef filtresi
            if target_bssid and bssid.upper() != target_bssid.upper():
                continue

            # Pencere icindeki deauth sayisini hesapla
            recent_deauths = [
                ts for ts in timestamps
                if ts > window_start
            ]
            deauth_count = len(recent_deauths)

            # Esik asildiysa saldiri olarak raporla
            if deauth_count >= self.deauth_threshold:
                # Saldiri tipi belirle
                attack_type = "broadcast"  # veya "targeted" istemci MAC'ine gore

                # Tehdit seviyesi
                if deauth_count >= self.deauth_threshold * 5:
                    threat_level = ThreatLevel.CRITICAL
                elif deauth_count >= self.deauth_threshold * 2:
                    threat_level = ThreatLevel.HIGH
                else:
                    threat_level = ThreatLevel.MEDIUM

                attack = DeauthAttackEvent(
                    target_bssid=bssid,
                    target_ssid=self._known_networks.get(bssid, {}).get('ssid'),
                    detected_at=now,
                    deauth_count=deauth_count,
                    duration_seconds=self.deauth_window_seconds,
                    source_macs=[],  # Monitor mod olmadan kaynak MAC bulunamaz
                    affected_clients=0,  # Etkilenen istemci sayisi
                    threat_level=threat_level,
                    attack_type=attack_type,
                    is_active=True
                )
                attacks.append(attack)

                # Alarm callback
                if self.alert_callback:
                    self.alert_callback('deauth_attack', attack.to_dict())

                logger.critical(
                    f"[WiFi Monitor] DEAUTH SALDIRISI TESPiT EDiLDi: "
                    f"Hedef={bssid}, Sayi={deauth_count}, Seviye={threat_level.value}"
                )

        return attacks

    def analyze_encryption_strength(
        self,
        scan_now: bool = True
    ) -> List[EncryptionAnalysis]:
        """
        Sifreleme Guc Analizi

        Tum aglarin sifreleme guvenligini analiz eder.
        Zayif sifreleme kullanan aglari raporlar.

        Args:
            scan_now: Hemen tarama yap

        Returns:
            List[EncryptionAnalysis]: Sifreleme analiz sonuclari
        """
        analyses: List[EncryptionAnalysis] = []
        now = datetime.now()

        current_networks = self._get_current_networks(scan_now)

        for network in current_networks:
            bssid = network.get('bssid', '')
            ssid = network.get('ssid')
            encryption = network.get('encryption', 'Open')

            # Sifreleme tipini normalize et
            enc_type = self._normalize_encryption_type(encryption)

            # Analiz yap
            if enc_type in self.WEAK_ENCRYPTION:
                weak_info = self.WEAK_ENCRYPTION[enc_type]
                analysis = EncryptionAnalysis(
                    bssid=bssid,
                    ssid=ssid,
                    encryption_type=enc_type,
                    is_secure=False,
                    weakness_score=weak_info['score'],
                    vulnerabilities=weak_info['vulnerabilities'],
                    recommendation=weak_info['recommendation'],
                    analyzed_at=now
                )
            elif enc_type in self.SECURE_ENCRYPTION:
                analysis = EncryptionAnalysis(
                    bssid=bssid,
                    ssid=ssid,
                    encryption_type=enc_type,
                    is_secure=True,
                    weakness_score=0,
                    vulnerabilities=[],
                    recommendation="Sifreleme guvenli seviyede",
                    analyzed_at=now
                )
            else:
                # Bilinmeyen sifreleme tipi
                analysis = EncryptionAnalysis(
                    bssid=bssid,
                    ssid=ssid,
                    encryption_type=enc_type,
                    is_secure=False,
                    weakness_score=50,
                    vulnerabilities=['Bilinmeyen sifreleme tipi'],
                    recommendation='Sifreleme tipini dogrulayin',
                    analyzed_at=now
                )

            analyses.append(analysis)

            # Zayif sifreleme uyarisi
            if not analysis.is_secure:
                logger.warning(
                    f"[WiFi Monitor] Zayif sifreleme: SSID={ssid}, "
                    f"Tip={enc_type}, Skor={analysis.weakness_score}"
                )

        return analyses

    def detect_hidden_networks(
        self,
        scan_now: bool = True
    ) -> List[HiddenNetworkInfo]:
        """
        Gizli Ag Tespiti

        SSID yayinlamayan aglari tespit eder.

        Args:
            scan_now: Hemen tarama yap

        Returns:
            List[HiddenNetworkInfo]: Tespit edilen gizli aglar
        """
        hidden_networks: List[HiddenNetworkInfo] = []
        now = datetime.now()

        current_networks = self._get_current_networks(scan_now)

        for network in current_networks:
            ssid = network.get('ssid', '')
            bssid = network.get('bssid', '')

            # Gizli ag kontrolu: bos/null SSID veya hidden flag
            is_hidden = (
                not ssid or
                ssid.strip() == '' or
                network.get('hidden', False) or
                ssid == '<hidden>' or
                all(c == '\x00' for c in ssid)  # Null karakterler
            )

            if is_hidden and bssid:
                # Risk degerlendirmesi
                if network.get('encryption') in ('Open', 'WEP'):
                    risk = "YUKSEK - Gizli ve zayif sifreleme"
                elif not network.get('encryption'):
                    risk = "YUKSEK - Gizli ve sifreleme bilinmiyor"
                else:
                    risk = "ORTA - Gizli ag"

                # Daha once gorulduyse guncelle
                if bssid in self._hidden_networks:
                    existing = self._hidden_networks[bssid]
                    existing.last_seen = now
                    hidden_networks.append(existing)
                else:
                    hidden_info = HiddenNetworkInfo(
                        bssid=bssid,
                        channel=network.get('channel'),
                        signal_strength=network.get('signal_strength'),
                        encryption=network.get('encryption'),
                        first_seen=now,
                        last_seen=now,
                        vendor=network.get('vendor'),
                        probing_clients=0,
                        risk_assessment=risk
                    )
                    self._hidden_networks[bssid] = hidden_info
                    hidden_networks.append(hidden_info)

                logger.info(
                    f"[WiFi Monitor] Gizli ag tespiti: BSSID={bssid}, "
                    f"Risk={risk}"
                )

        return hidden_networks

    # ========================================================================
    # YARDIMCI METODLAR
    # ========================================================================

    def _get_current_networks(self, scan_now: bool) -> List[Dict]:
        """
        Mevcut aglari getir

        Scanner varsa tarama yapar, yoksa cache dondurur.
        """
        if scan_now and self.scanner:
            try:
                networks = self.scanner.scan_local()
                # Dict'e donustur
                result = []
                for net in networks:
                    if hasattr(net, 'to_dict'):
                        result.append(net.to_dict())
                    elif hasattr(net, '__dict__'):
                        result.append(net.__dict__)
                    else:
                        result.append(net)

                # Cache'e kaydet
                for net in result:
                    bssid = net.get('bssid', '').upper()
                    if bssid:
                        self._known_networks[bssid] = net

                return result
            except Exception as e:
                logger.error(f"[WiFi Monitor] Tarama hatasi: {e}")
                return list(self._known_networks.values())

        return list(self._known_networks.values())

    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """
        Iki string arasindaki benzerlik oranini hesapla
        Levenshtein mesafesi tabanli
        """
        if not s1 or not s2:
            return 0.0

        s1, s2 = s1.lower(), s2.lower()

        if s1 == s2:
            return 1.0

        len1, len2 = len(s1), len(s2)
        if abs(len1 - len2) > max(len1, len2) * 0.5:
            return 0.0

        # Basit Levenshtein
        matrix = [[0] * (len2 + 1) for _ in range(len1 + 1)]
        for i in range(len1 + 1):
            matrix[i][0] = i
        for j in range(len2 + 1):
            matrix[0][j] = j

        for i in range(1, len1 + 1):
            for j in range(1, len2 + 1):
                cost = 0 if s1[i-1] == s2[j-1] else 1
                matrix[i][j] = min(
                    matrix[i-1][j] + 1,
                    matrix[i][j-1] + 1,
                    matrix[i-1][j-1] + cost
                )

        distance = matrix[len1][len2]
        max_len = max(len1, len2)
        return 1.0 - (distance / max_len)

    def _normalize_encryption_type(self, encryption: str) -> str:
        """Sifreleme tipini normalize et"""
        if not encryption:
            return 'Open'

        enc_upper = encryption.upper()

        if 'WPA3' in enc_upper:
            if 'ENTERPRISE' in enc_upper or '802.1X' in enc_upper:
                return 'WPA3-Enterprise'
            return 'WPA3'
        elif 'WPA2' in enc_upper:
            if 'ENTERPRISE' in enc_upper or '802.1X' in enc_upper:
                return 'WPA2-Enterprise'
            return 'WPA2'
        elif 'WPA' in enc_upper:
            return 'WPA'
        elif 'WEP' in enc_upper:
            return 'WEP'
        elif 'OPEN' in enc_upper or enc_upper == 'NONE':
            return 'Open'

        return encryption

    def add_deauth_event(self, bssid: str, timestamp: Optional[datetime] = None):
        """
        Deauth olayi ekle (harici kaynaklardan)
        Monitor mod veya diger araclardan gelen deauth bilgisi
        """
        ts = timestamp or datetime.now()
        self._deauth_counters[bssid.upper()].append(ts)

        # Eski kayitlari temizle (son 1 saat)
        cutoff = datetime.now() - timedelta(hours=1)
        self._deauth_counters[bssid.upper()] = [
            t for t in self._deauth_counters[bssid.upper()]
            if t > cutoff
        ]

    def get_statistics(self) -> Dict[str, Any]:
        """Izleme istatistiklerini getir"""
        return {
            'known_networks': len(self._known_networks),
            'hidden_networks': len(self._hidden_networks),
            'ssid_count': len(self._ssid_bssid_map),
            'deauth_tracked_aps': len(self._deauth_counters),
            'detection_history_size': len(self._detection_history),
            'last_scan': self._scan_history[-1] if self._scan_history else None
        }
