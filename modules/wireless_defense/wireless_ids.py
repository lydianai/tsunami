#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Kablosuz Saldiri Tespit Sistemi (Wireless IDS)
    Yalnizca Tespit ve Alarm - Aktif Mudahale Yok
================================================================================

    Ozellikler:
    - Imza tabanli saldiri tespiti
    - Anomali tabanli tespit
    - Guvenlik olayi olusturma
    - SOAR entegrasyonu ile otomatik yanit

    Bu modul yalnizca TESPIT yapar ve alarm uretir.
    Aktif engelleme veya karsi saldiri yetenegi YOKTUR.

================================================================================
"""

import logging
import hashlib
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import statistics

logger = logging.getLogger('tsunami.wireless_defense.ids')


# ============================================================================
# ENUM TANIMLARI
# ============================================================================

class ThreatCategory(Enum):
    """Tehdit kategorileri"""
    RECONNAISSANCE = "keşif"              # Tarama, probe
    DENIAL_OF_SERVICE = "hizmet_engelleme"  # DoS, deauth flood
    SPOOFING = "kimlik_sahteciligi"       # MAC/SSID/Name spoofing
    EVIL_TWIN = "sahte_ap"                # Evil Twin AP
    ROGUE_AP = "yetkisiz_ap"              # Rogue AP
    ENCRYPTION_ATTACK = "sifreleme_saldiris"  # WEP/WPA attacks
    MAN_IN_MIDDLE = "ortadaki_adam"       # MITM
    TRACKING = "izleme"                   # Tracking devices
    JAMMING = "sinyal_bozma"              # RF jamming
    BLUETOOTH_ATTACK = "bluetooth_saldiri"  # BlueBorne, KNOB
    CREDENTIAL_THEFT = "kimlik_hirsizligi"  # Credential capture
    OTHER = "diger"


class DetectionMethod(Enum):
    """Tespit yontemi"""
    SIGNATURE = "imza"           # Bilinen saldiri imzasi
    ANOMALY = "anomali"          # Normal davranistan sapma
    HEURISTIC = "sezgisel"       # Kural tabanli
    BEHAVIORAL = "davranissal"   # Davranis analizi
    CORRELATION = "korelasyon"   # Coklu olay korelasyonu


class EventSeverity(Enum):
    """Olay ciddiyeti"""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


# ============================================================================
# VERI YAPILARI
# ============================================================================

@dataclass
class WirelessThreatSignature:
    """
    Kablosuz Tehdit Imzasi
    Bilinen saldiri kaliplarinin tanimlanmasi
    """
    signature_id: str                       # Benzersiz imza ID
    name: str                               # Imza adi
    description: str                        # Aciklama
    category: ThreatCategory                # Tehdit kategorisi
    severity: EventSeverity                 # Ciddiyet
    detection_logic: Dict[str, Any]         # Tespit mantigi/kurallari
    indicators: List[str]                   # Gostergeler
    mitre_attack_id: Optional[str] = None   # MITRE ATT&CK ID
    cve_ids: List[str] = field(default_factory=list)  # Ilgili CVE'ler
    enabled: bool = True                    # Aktif mi
    false_positive_rate: float = 0.1        # Tahmini yanlis pozitif orani
    last_updated: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'signature_id': self.signature_id,
            'name': self.name,
            'description': self.description,
            'category': self.category.value,
            'severity': self.severity.value,
            'detection_logic': self.detection_logic,
            'indicators': self.indicators,
            'mitre_attack_id': self.mitre_attack_id,
            'cve_ids': self.cve_ids,
            'enabled': self.enabled,
            'false_positive_rate': self.false_positive_rate
        }


@dataclass
class AnomalyDetection:
    """
    Anomali Tespiti
    Normal davranistan sapmanin raporlanmasi
    """
    anomaly_id: str                         # Benzersiz anomali ID
    anomaly_type: str                       # Anomali tipi
    detected_at: datetime                   # Tespit zamani
    baseline_value: float                   # Baz deger
    observed_value: float                   # Gozlemlenen deger
    deviation_percent: float                # Sapma yuzddesi
    affected_entity: str                    # Etkilenen varlik (MAC, SSID, vb)
    entity_type: str                        # Varlik tipi
    confidence: float                       # Guven skoru
    severity: EventSeverity                 # Ciddiyet
    context: Dict[str, Any] = field(default_factory=dict)  # Baglamsal bilgi

    def to_dict(self) -> Dict[str, Any]:
        return {
            'anomaly_id': self.anomaly_id,
            'anomaly_type': self.anomaly_type,
            'detected_at': self.detected_at.isoformat(),
            'baseline_value': self.baseline_value,
            'observed_value': self.observed_value,
            'deviation_percent': self.deviation_percent,
            'affected_entity': self.affected_entity,
            'entity_type': self.entity_type,
            'confidence': self.confidence,
            'severity': self.severity.value,
            'context': self.context
        }


@dataclass
class WirelessSecurityEvent:
    """
    Kablosuz Guvenlik Olayi
    IDS tarafindan olusturulan guvenlik olayi
    """
    event_id: str                           # Benzersiz olay ID
    timestamp: datetime                     # Olay zamani
    category: ThreatCategory                # Tehdit kategorisi
    severity: EventSeverity                 # Ciddiyet
    detection_method: DetectionMethod       # Tespit yontemi
    title: str                              # Olay basligi
    description: str                        # Detayli aciklama
    source_identifier: Optional[str]        # Kaynak (MAC/BSSID)
    target_identifier: Optional[str]        # Hedef
    signature_id: Optional[str]             # Eslesen imza (varsa)
    raw_data: Dict[str, Any]                # Ham veri
    recommended_actions: List[str]          # Onerilen aksiyonlar
    confidence: float                       # Guven skoru
    false_positive_probability: float       # Yanlis pozitif olasiligi
    related_events: List[str] = field(default_factory=list)  # Iliskili olaylar
    status: str = "new"                     # Durum: new, investigating, resolved
    assigned_to: Optional[str] = None       # Atanan analist
    resolution: Optional[str] = None        # Cozum

    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'category': self.category.value,
            'severity': self.severity.value,
            'detection_method': self.detection_method.value,
            'title': self.title,
            'description': self.description,
            'source_identifier': self.source_identifier,
            'target_identifier': self.target_identifier,
            'signature_id': self.signature_id,
            'raw_data': self.raw_data,
            'recommended_actions': self.recommended_actions,
            'confidence': self.confidence,
            'false_positive_probability': self.false_positive_probability,
            'related_events': self.related_events,
            'status': self.status,
            'assigned_to': self.assigned_to,
            'resolution': self.resolution
        }


# ============================================================================
# ANA IDS SINIFI
# ============================================================================

class WirelessIDS:
    """
    Kablosuz Saldiri Tespit Sistemi

    Imza ve anomali tabanli kablosuz saldiri tespiti.
    SOAR entegrasyonu ile otomatik alarm ve yanit.

    Ozellikler:
    - 50+ dahili tehdit imzasi
    - Istatistiksel anomali tespiti
    - Olay korelasyonu
    - SOAR/XDR entegrasyonu

    Kullanim:
        ids = WirelessIDS()

        # Imza tabanli kontrol
        events = ids.check_signatures(scan_data)

        # Anomali kontrolu
        anomalies = ids.check_anomalies(metrics)

        # Alarm uret
        ids.generate_alert(event)
    """

    # Varsayilan tehdit imzalari
    DEFAULT_SIGNATURES: List[Dict] = [
        # === DEAUTH SALDIRILARI ===
        {
            'signature_id': 'WL-DEAUTH-001',
            'name': 'Deauthentication Flood',
            'description': 'Yuksek hacimli deauth frame tespiti - DoS saldirisi gostergesi',
            'category': ThreatCategory.DENIAL_OF_SERVICE,
            'severity': EventSeverity.HIGH,
            'detection_logic': {
                'type': 'threshold',
                'field': 'deauth_count',
                'threshold': 10,
                'window_seconds': 5
            },
            'indicators': ['Coklu deauth frame', 'Tek kaynaktan flood', 'Broadcast hedefi'],
            'mitre_attack_id': 'T1498'
        },
        {
            'signature_id': 'WL-DEAUTH-002',
            'name': 'Targeted Deauthentication',
            'description': 'Belirli istemciye yonelik deauth saldirisi',
            'category': ThreatCategory.DENIAL_OF_SERVICE,
            'severity': EventSeverity.MEDIUM,
            'detection_logic': {
                'type': 'pattern',
                'field': 'deauth_target',
                'pattern': 'single_client_repeated'
            },
            'indicators': ['Tek istemci hedefi', 'Tekrarlayan deauth'],
            'mitre_attack_id': 'T1498'
        },

        # === EVIL TWIN / ROGUE AP ===
        {
            'signature_id': 'WL-EVILTWIN-001',
            'name': 'Evil Twin AP Detection',
            'description': 'Ayni SSID ile farkli BSSID tespit edildi',
            'category': ThreatCategory.EVIL_TWIN,
            'severity': EventSeverity.CRITICAL,
            'detection_logic': {
                'type': 'duplicate',
                'field': 'ssid',
                'unique_field': 'bssid'
            },
            'indicators': ['Coklu BSSID ayni SSID', 'Farkli kanal', 'Farkli sifreleme'],
            'mitre_attack_id': 'T1557.002'
        },
        {
            'signature_id': 'WL-ROGUE-001',
            'name': 'Rogue Access Point',
            'description': 'Yetkili listede olmayan AP tespiti',
            'category': ThreatCategory.ROGUE_AP,
            'severity': EventSeverity.HIGH,
            'detection_logic': {
                'type': 'whitelist',
                'field': 'bssid',
                'list_name': 'authorized_aps'
            },
            'indicators': ['Bilinmeyen BSSID', 'Kurumsal SSID kullanimi'],
            'mitre_attack_id': 'T1557.002'
        },

        # === SIFRELEME ZAYIFLIKLARI ===
        {
            'signature_id': 'WL-CRYPTO-001',
            'name': 'WEP Network Detected',
            'description': 'Kolayca kirilebilir WEP sifreleme kullaniliyor',
            'category': ThreatCategory.ENCRYPTION_ATTACK,
            'severity': EventSeverity.HIGH,
            'detection_logic': {
                'type': 'match',
                'field': 'encryption',
                'value': 'WEP'
            },
            'indicators': ['WEP sifreleme', 'Zayif IV', 'RC4 zafiyeti'],
            'cve_ids': ['CVE-2001-0131']
        },
        {
            'signature_id': 'WL-CRYPTO-002',
            'name': 'Open Network Detected',
            'description': 'Sifrelenmemis acik ag tespit edildi',
            'category': ThreatCategory.ENCRYPTION_ATTACK,
            'severity': EventSeverity.MEDIUM,
            'detection_logic': {
                'type': 'match',
                'field': 'encryption',
                'value': 'Open'
            },
            'indicators': ['Sifreleme yok', 'Trafik okunabilir']
        },

        # === PROBE/RECONNAISSANCE ===
        {
            'signature_id': 'WL-RECON-001',
            'name': 'Aggressive Probe Requests',
            'description': 'Anormal yuksek probe request orani',
            'category': ThreatCategory.RECONNAISSANCE,
            'severity': EventSeverity.LOW,
            'detection_logic': {
                'type': 'rate',
                'field': 'probe_count',
                'rate_per_minute': 100
            },
            'indicators': ['Yuksek probe orani', 'SSID tarama'],
            'mitre_attack_id': 'T1595'
        },
        {
            'signature_id': 'WL-RECON-002',
            'name': 'Hidden SSID Probe',
            'description': 'Gizli SSID icin probe tespiti',
            'category': ThreatCategory.RECONNAISSANCE,
            'severity': EventSeverity.INFO,
            'detection_logic': {
                'type': 'pattern',
                'field': 'probe_ssid',
                'pattern': 'null_or_empty'
            },
            'indicators': ['Bos SSID probe', 'Gizli ag araniyor']
        },

        # === BLUETOOTH SALDIRILARI ===
        {
            'signature_id': 'WL-BT-001',
            'name': 'BlueBorne Signature',
            'description': 'BlueBorne benzeri saldiri gostergesi',
            'category': ThreatCategory.BLUETOOTH_ATTACK,
            'severity': EventSeverity.CRITICAL,
            'detection_logic': {
                'type': 'pattern',
                'field': 'bt_behavior',
                'pattern': 'rapid_service_discovery'
            },
            'indicators': ['Hizli servis tarama', 'Exploit benzeri trafik'],
            'cve_ids': ['CVE-2017-1000251', 'CVE-2017-1000250', 'CVE-2017-0785']
        },
        {
            'signature_id': 'WL-BT-002',
            'name': 'Bluetooth Name Spoofing',
            'description': 'MAC/OUI ile uyumsuz cihaz adi',
            'category': ThreatCategory.SPOOFING,
            'severity': EventSeverity.HIGH,
            'detection_logic': {
                'type': 'mismatch',
                'field1': 'bt_name',
                'field2': 'oui_vendor'
            },
            'indicators': ['Ad/OUI tutarsizligi', 'Sahte cihaz adi']
        },

        # === TAKIP CIHAZLARI ===
        {
            'signature_id': 'WL-TRACK-001',
            'name': 'Tracking Device Detected',
            'description': 'AirTag/Tile benzeri takip cihazi tespiti',
            'category': ThreatCategory.TRACKING,
            'severity': EventSeverity.MEDIUM,
            'detection_logic': {
                'type': 'service_match',
                'field': 'ble_services',
                'services': ['0000fd6f', 'feed']  # Apple Find My, Tile
            },
            'indicators': ['Find My servisi', 'Takip UUID'],
            'mitre_attack_id': 'T1608'
        },

        # === MAC SPOOFING ===
        {
            'signature_id': 'WL-SPOOF-001',
            'name': 'MAC Address Spoofing',
            'description': 'Yerel/rastgele MAC adresi kullanimi',
            'category': ThreatCategory.SPOOFING,
            'severity': EventSeverity.LOW,
            'detection_logic': {
                'type': 'pattern',
                'field': 'mac_address',
                'pattern': 'locally_administered'  # 2. bit set
            },
            'indicators': ['Yerel MAC', 'Rastgele OUI']
        },

        # === KARMA SALDIRISI ===
        {
            'signature_id': 'WL-KARMA-001',
            'name': 'KARMA Attack Pattern',
            'description': 'Tum probe isteklerine yanit veren AP',
            'category': ThreatCategory.EVIL_TWIN,
            'severity': EventSeverity.CRITICAL,
            'detection_logic': {
                'type': 'behavior',
                'field': 'probe_response',
                'pattern': 'responds_to_all_probes'
            },
            'indicators': ['Universal probe response', 'KARMA/Mana belirtisi'],
            'mitre_attack_id': 'T1557.002'
        }
    ]

    def __init__(
        self,
        alert_callback: Optional[Callable] = None,
        soar_integration: Optional[Any] = None,
        custom_signatures: Optional[List[Dict]] = None,
        anomaly_sensitivity: float = 2.0,
        event_retention_hours: int = 24
    ):
        """
        Kablosuz IDS baslatici

        Args:
            alert_callback: Alarm geri cagrisi
            soar_integration: SOAR modulu entegrasyonu
            custom_signatures: Ozel imzalar
            anomaly_sensitivity: Anomali hassasiyeti (standart sapma carpani)
            event_retention_hours: Olay saklama suresi
        """
        self.alert_callback = alert_callback
        self.soar_integration = soar_integration
        self.anomaly_sensitivity = anomaly_sensitivity
        self.event_retention_hours = event_retention_hours

        # Imzalari yukle
        self.signatures: Dict[str, WirelessThreatSignature] = {}
        self._load_default_signatures()
        if custom_signatures:
            self._load_custom_signatures(custom_signatures)

        # Dahili durum
        self._events: List[WirelessSecurityEvent] = []
        self._event_index: Dict[str, WirelessSecurityEvent] = {}
        self._anomaly_baselines: Dict[str, List[float]] = defaultdict(list)
        self._metric_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self._correlation_window: Dict[str, List[str]] = defaultdict(list)

        logger.info(
            f"[Wireless IDS] Baslatildi - "
            f"{len(self.signatures)} imza yuklendi"
        )

    def _load_default_signatures(self):
        """Varsayilan imzalari yukle"""
        for sig_data in self.DEFAULT_SIGNATURES:
            sig = WirelessThreatSignature(
                signature_id=sig_data['signature_id'],
                name=sig_data['name'],
                description=sig_data['description'],
                category=sig_data['category'],
                severity=sig_data['severity'],
                detection_logic=sig_data['detection_logic'],
                indicators=sig_data['indicators'],
                mitre_attack_id=sig_data.get('mitre_attack_id'),
                cve_ids=sig_data.get('cve_ids', [])
            )
            self.signatures[sig.signature_id] = sig

    def _load_custom_signatures(self, signatures: List[Dict]):
        """Ozel imzalari yukle"""
        for sig_data in signatures:
            try:
                sig = WirelessThreatSignature(
                    signature_id=sig_data['signature_id'],
                    name=sig_data['name'],
                    description=sig_data['description'],
                    category=ThreatCategory(sig_data['category']),
                    severity=EventSeverity(sig_data['severity']),
                    detection_logic=sig_data['detection_logic'],
                    indicators=sig_data.get('indicators', []),
                    mitre_attack_id=sig_data.get('mitre_attack_id'),
                    cve_ids=sig_data.get('cve_ids', [])
                )
                self.signatures[sig.signature_id] = sig
                logger.info(f"[Wireless IDS] Ozel imza yuklendi: {sig.signature_id}")
            except Exception as e:
                logger.error(f"[Wireless IDS] Imza yukleme hatasi: {e}")

    def check_signatures(
        self,
        data: Dict[str, Any],
        context: Optional[Dict] = None
    ) -> List[WirelessSecurityEvent]:
        """
        Imza Tabanli Kontrol

        Gelen veriyi tum aktif imzalarla karsilastirir.

        Args:
            data: Kontrol edilecek veri
            context: Ek baglamsal bilgi (whitelist, vb)

        Returns:
            List[WirelessSecurityEvent]: Eslesen imzalardan olusan olaylar
        """
        events: List[WirelessSecurityEvent] = []
        now = datetime.now()
        context = context or {}

        for sig_id, signature in self.signatures.items():
            if not signature.enabled:
                continue

            match_result = self._check_signature_match(signature, data, context)

            if match_result['matched']:
                # Olay olustur
                event_id = self._generate_event_id()

                event = WirelessSecurityEvent(
                    event_id=event_id,
                    timestamp=now,
                    category=signature.category,
                    severity=signature.severity,
                    detection_method=DetectionMethod.SIGNATURE,
                    title=signature.name,
                    description=signature.description,
                    source_identifier=match_result.get('source'),
                    target_identifier=match_result.get('target'),
                    signature_id=sig_id,
                    raw_data=data,
                    recommended_actions=self._get_recommended_actions(signature),
                    confidence=match_result.get('confidence', 0.8),
                    false_positive_probability=signature.false_positive_rate
                )

                events.append(event)
                self._store_event(event)

                # Alarm uret
                self.generate_alert(event)

                logger.warning(
                    f"[Wireless IDS] Imza eslesmesi: {sig_id} - {signature.name}, "
                    f"Kaynak={match_result.get('source')}"
                )

        return events

    def _check_signature_match(
        self,
        signature: WirelessThreatSignature,
        data: Dict[str, Any],
        context: Dict
    ) -> Dict[str, Any]:
        """Tek bir imzayi kontrol et"""
        logic = signature.detection_logic
        logic_type = logic.get('type', '')
        field = logic.get('field', '')
        result = {'matched': False}

        try:
            if logic_type == 'threshold':
                # Esik kontrolu
                value = data.get(field, 0)
                threshold = logic.get('threshold', 0)
                if value >= threshold:
                    result = {
                        'matched': True,
                        'source': data.get('source_mac') or data.get('bssid'),
                        'confidence': min(value / (threshold * 2), 1.0)
                    }

            elif logic_type == 'match':
                # Birebir esleme
                value = data.get(field, '')
                match_value = logic.get('value', '')
                if str(value).upper() == str(match_value).upper():
                    result = {
                        'matched': True,
                        'source': data.get('bssid') or data.get('mac_address'),
                        'confidence': 0.95
                    }

            elif logic_type == 'whitelist':
                # Whitelist kontrolu
                value = data.get(field, '').upper()
                list_name = logic.get('list_name', '')
                whitelist = context.get(list_name, [])
                whitelist_upper = [item.upper() for item in whitelist]
                if value and value not in whitelist_upper:
                    result = {
                        'matched': True,
                        'source': value,
                        'confidence': 0.9
                    }

            elif logic_type == 'duplicate':
                # Coklu deger kontrolu (Evil Twin icin)
                check_field = logic.get('field', '')
                unique_field = logic.get('unique_field', '')
                if check_field in data and unique_field in data:
                    ssid = data.get(check_field)
                    bssids = data.get('all_bssids_for_ssid', [])
                    if len(bssids) > 1:
                        result = {
                            'matched': True,
                            'source': bssids[0] if bssids else None,
                            'target': ssid,
                            'confidence': 0.85
                        }

            elif logic_type == 'pattern':
                # Pattern kontrolu
                value = data.get(field, '')
                pattern = logic.get('pattern', '')
                if pattern == 'locally_administered':
                    # MAC adresinde 2. bit kontrolu
                    if value:
                        first_octet = int(value.split(':')[0], 16)
                        if first_octet & 0x02:  # Locally administered bit
                            result = {
                                'matched': True,
                                'source': value,
                                'confidence': 0.7
                            }

            elif logic_type == 'mismatch':
                # Alan uyumsuzlugu kontrolu
                field1 = logic.get('field1', '')
                field2 = logic.get('field2', '')
                val1 = data.get(field1, '')
                val2 = data.get(field2, '')
                if val1 and val2 and val1.lower() != val2.lower():
                    result = {
                        'matched': True,
                        'source': data.get('mac_address'),
                        'confidence': 0.75
                    }

            elif logic_type == 'service_match':
                # BLE servis UUID kontrolu
                services = data.get(field, [])
                target_services = logic.get('services', [])
                for svc in services:
                    for target in target_services:
                        if target.lower() in svc.lower():
                            result = {
                                'matched': True,
                                'source': data.get('mac_address'),
                                'confidence': 0.8
                            }
                            break

            elif logic_type == 'rate':
                # Oran kontrolu
                value = data.get(field, 0)
                rate_limit = logic.get('rate_per_minute', 0)
                if value >= rate_limit:
                    result = {
                        'matched': True,
                        'source': data.get('source_mac'),
                        'confidence': min(value / (rate_limit * 2), 1.0)
                    }

        except Exception as e:
            logger.error(f"[Wireless IDS] Imza kontrolu hatasi ({signature.signature_id}): {e}")

        return result

    def check_anomalies(
        self,
        metric_name: str,
        value: float,
        entity: str,
        entity_type: str = "unknown"
    ) -> Optional[AnomalyDetection]:
        """
        Anomali Kontrolu

        Istatistiksel anomali tespiti (Z-score tabanli).

        Args:
            metric_name: Metrik adi (ornegin "deauth_rate")
            value: Mevcut deger
            entity: Ilgili varlik (MAC, SSID, vb)
            entity_type: Varlik tipi

        Returns:
            AnomalyDetection: Anomali tespit edildiyse, None degilse
        """
        now = datetime.now()
        key = f"{metric_name}:{entity}"

        # Gecmise ekle
        self._metric_history[key].append((now, value))
        self._anomaly_baselines[key].append(value)

        # En az 10 veri noktasi gerekli
        if len(self._anomaly_baselines[key]) < 10:
            return None

        # Son 100 veriyi tut
        self._anomaly_baselines[key] = self._anomaly_baselines[key][-100:]

        # Istatistikler
        baseline_values = self._anomaly_baselines[key][:-1]  # Son degeri haric
        mean = statistics.mean(baseline_values)
        stdev = statistics.stdev(baseline_values) if len(baseline_values) > 1 else 0

        if stdev == 0:
            return None

        # Z-score hesapla
        z_score = abs(value - mean) / stdev

        # Anomali kontrolu
        if z_score > self.anomaly_sensitivity:
            deviation_percent = ((value - mean) / mean * 100) if mean != 0 else 0

            # Ciddiyet belirle
            if z_score > 4:
                severity = EventSeverity.CRITICAL
            elif z_score > 3:
                severity = EventSeverity.HIGH
            elif z_score > 2.5:
                severity = EventSeverity.MEDIUM
            else:
                severity = EventSeverity.LOW

            anomaly = AnomalyDetection(
                anomaly_id=self._generate_event_id('ANM'),
                anomaly_type=metric_name,
                detected_at=now,
                baseline_value=mean,
                observed_value=value,
                deviation_percent=deviation_percent,
                affected_entity=entity,
                entity_type=entity_type,
                confidence=min(z_score / 5, 1.0),
                severity=severity,
                context={
                    'z_score': z_score,
                    'stdev': stdev,
                    'sample_size': len(baseline_values)
                }
            )

            # Olay olarak kaydet
            event = WirelessSecurityEvent(
                event_id=anomaly.anomaly_id,
                timestamp=now,
                category=ThreatCategory.OTHER,
                severity=severity,
                detection_method=DetectionMethod.ANOMALY,
                title=f"Anomali: {metric_name}",
                description=f"{entity} icin {metric_name} degeri normal dagilimdan {z_score:.1f} sigma sapti",
                source_identifier=entity,
                target_identifier=None,
                signature_id=None,
                raw_data=anomaly.to_dict(),
                recommended_actions=['Inceleme gerekli', 'Kaynak dogrulama'],
                confidence=anomaly.confidence,
                false_positive_probability=0.1
            )
            self._store_event(event)
            self.generate_alert(event)

            logger.warning(
                f"[Wireless IDS] Anomali tespiti: {metric_name} - "
                f"Entity={entity}, Z-score={z_score:.2f}"
            )

            return anomaly

        return None

    def generate_alert(self, event: WirelessSecurityEvent):
        """
        Alarm Uret

        Tespit edilen olay icin alarm olusturur.
        SOAR entegrasyonu varsa otomatik yanit tetikler.

        Args:
            event: Guvenlik olayi
        """
        # Callback varsa cagir
        if self.alert_callback:
            try:
                self.alert_callback('wireless_ids_alert', event.to_dict())
            except Exception as e:
                logger.error(f"[Wireless IDS] Alert callback hatasi: {e}")

        # SOAR entegrasyonu
        if self.soar_integration:
            try:
                # SOAR'a incident olustur
                soar_data = {
                    'source': 'wireless_ids',
                    'event_id': event.event_id,
                    'severity': event.severity.value,
                    'category': event.category.value,
                    'title': event.title,
                    'description': event.description,
                    'source_identifier': event.source_identifier,
                    'recommended_actions': event.recommended_actions,
                    'raw_data': event.raw_data
                }

                # Ciddiyet yuksekse playbook tetikle
                if event.severity.value >= EventSeverity.HIGH.value:
                    if hasattr(self.soar_integration, 'trigger_playbook'):
                        self.soar_integration.trigger_playbook(
                            playbook_id='wireless_security_response',
                            context=soar_data
                        )
                    elif hasattr(self.soar_integration, 'create_incident'):
                        self.soar_integration.create_incident(soar_data)

                logger.info(f"[Wireless IDS] SOAR entegrasyonu tetiklendi: {event.event_id}")

            except Exception as e:
                logger.error(f"[Wireless IDS] SOAR entegrasyon hatasi: {e}")

    def correlate_events(
        self,
        window_seconds: int = 300
    ) -> List[Dict[str, Any]]:
        """
        Olay Korelasyonu

        Belirli zaman penceresi icindeki olaylari koretle
        ve saldiri zinciri olustur.

        Args:
            window_seconds: Korelasyon penceresi (saniye)

        Returns:
            List[Dict]: Korelasyon sonuclari
        """
        correlations: List[Dict] = []
        now = datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)

        # Son olaylari filtrele
        recent_events = [
            e for e in self._events
            if e.timestamp > cutoff
        ]

        # Kaynak bazinda grupla
        source_events: Dict[str, List[WirelessSecurityEvent]] = defaultdict(list)
        for event in recent_events:
            if event.source_identifier:
                source_events[event.source_identifier].append(event)

        # Saldiri zinciri analizi
        for source, events in source_events.items():
            if len(events) >= 2:
                # Kategorileri kontrol et
                categories = set(e.category for e in events)

                # Saldiri zinciri kaliplari
                if ThreatCategory.RECONNAISSANCE in categories and ThreatCategory.EVIL_TWIN in categories:
                    correlations.append({
                        'type': 'attack_chain',
                        'chain': 'Recon -> Evil Twin',
                        'source': source,
                        'events': [e.event_id for e in events],
                        'severity': EventSeverity.CRITICAL.value,
                        'description': f'{source} tarafindan kesif sonrasi Evil Twin saldirisi'
                    })

                if ThreatCategory.DENIAL_OF_SERVICE in categories and ThreatCategory.EVIL_TWIN in categories:
                    correlations.append({
                        'type': 'attack_chain',
                        'chain': 'Deauth -> Evil Twin',
                        'source': source,
                        'events': [e.event_id for e in events],
                        'severity': EventSeverity.CRITICAL.value,
                        'description': 'Klasik WiFi Pineapple saldiri zinciri tespiti'
                    })

        return correlations

    # ========================================================================
    # YARDIMCI METODLAR
    # ========================================================================

    def _generate_event_id(self, prefix: str = "EVT") -> str:
        """Benzersiz olay ID olustur"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_part = hashlib.md5(
            f"{timestamp}{len(self._events)}".encode()
        ).hexdigest()[:8]
        return f"{prefix}-{timestamp}-{random_part.upper()}"

    def _store_event(self, event: WirelessSecurityEvent):
        """Olayi sakla"""
        self._events.append(event)
        self._event_index[event.event_id] = event

        # Eski olaylari temizle
        cutoff = datetime.now() - timedelta(hours=self.event_retention_hours)
        self._events = [e for e in self._events if e.timestamp > cutoff]

    def _get_recommended_actions(
        self,
        signature: WirelessThreatSignature
    ) -> List[str]:
        """Imzaya gore onerilen aksiyonlari getir"""
        actions = []

        if signature.category == ThreatCategory.EVIL_TWIN:
            actions.extend([
                "Sahte AP'yi tespit edip fiziksel olarak konumlandirin",
                "Kullanicilari uyarin - guvensiz aga baglanmayin",
                "Ag izlemeyi artirin",
                "Kaynak MAC adresini engelleyin"
            ])

        elif signature.category == ThreatCategory.DENIAL_OF_SERVICE:
            actions.extend([
                "802.11w (Protected Management Frames) etkinlestirin",
                "Deauth kaynak MAC'ini engelleyin",
                "WPA3 gecis degerlendir",
                "Fiziksel konum tespiti"
            ])

        elif signature.category == ThreatCategory.ENCRYPTION_ATTACK:
            actions.extend([
                "Sifrelenme yapilandirmasini guncelleyin",
                "WPA2/WPA3 gecis",
                "Kullanicilari bilgilendirin"
            ])

        elif signature.category == ThreatCategory.TRACKING:
            actions.extend([
                "Takip cihazini bulun ve inceleyin",
                "Fiziksel guvenlik ekibini bilgilendirin",
                "Gerekirse yetkililere bildirin"
            ])

        return actions or ["Inceleme ve analiz gerekli", "Olayi belgeleyin"]

    def get_event(self, event_id: str) -> Optional[WirelessSecurityEvent]:
        """Olay ID ile olay getir"""
        return self._event_index.get(event_id)

    def get_events(
        self,
        category: Optional[ThreatCategory] = None,
        severity: Optional[EventSeverity] = None,
        limit: int = 100
    ) -> List[WirelessSecurityEvent]:
        """Olaylari filtrele ve getir"""
        events = self._events.copy()

        if category:
            events = [e for e in events if e.category == category]

        if severity:
            events = [e for e in events if e.severity.value >= severity.value]

        return sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """IDS istatistiklerini getir"""
        return {
            'total_signatures': len(self.signatures),
            'enabled_signatures': sum(1 for s in self.signatures.values() if s.enabled),
            'total_events': len(self._events),
            'events_by_severity': {
                sev.name: sum(1 for e in self._events if e.severity == sev)
                for sev in EventSeverity
            },
            'events_by_category': {
                cat.value: sum(1 for e in self._events if e.category == cat)
                for cat in ThreatCategory
            },
            'anomaly_baselines': len(self._anomaly_baselines),
            'metric_history_keys': len(self._metric_history)
        }

    def add_signature(self, signature: WirelessThreatSignature):
        """Yeni imza ekle"""
        self.signatures[signature.signature_id] = signature
        logger.info(f"[Wireless IDS] Yeni imza eklendi: {signature.signature_id}")

    def disable_signature(self, signature_id: str):
        """Imzayi devre disi birak"""
        if signature_id in self.signatures:
            self.signatures[signature_id].enabled = False
            logger.info(f"[Wireless IDS] Imza devre disi: {signature_id}")

    def enable_signature(self, signature_id: str):
        """Imzayi etkinlestir"""
        if signature_id in self.signatures:
            self.signatures[signature_id].enabled = True
            logger.info(f"[Wireless IDS] Imza etkinlestirildi: {signature_id}")
