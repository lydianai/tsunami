#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI AI-POWERED THREAT HUNTER v1.0
    Yapay Zeka Destekli Tehdit Avcisi ve Davranis Analiz Motoru
================================================================================

    Ozellikler:
    - ML Destekli Anomali Tespiti (Isolation Forest, Autoencoder)
    - UEBA - Kullanici ve Varlik Davranis Analizi
    - Ag Davranis Analizi (Beaconing, DNS Tunneling, Exfiltration)
    - MITRE ATT&CK Entegrasyonu
    - Otomatik IOC Uretimi
    - Hunt Playbook'lari
    - SOAR Entegrasyonu

    Yazar: AILYDIAN
    Lisans: Ozel kullanim

================================================================================
"""

import os
import json
import hashlib
import threading
import pickle
import logging
import re
import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum, auto
from collections import defaultdict, Counter
from abc import ABC, abstractmethod
import ipaddress
import base64

# Makine Ogrenmesi kutuphaneleri
try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler, MinMaxScaler
    from sklearn.cluster import DBSCAN
    from sklearn.decomposition import PCA
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    np = None

# Loglama yapilandirmasi
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
#                           ENUM VE SABITTER
# ============================================================================

class ThreatSeverity(Enum):
    """Tehdit ciddiyet seviyeleri"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 1.0-3.9
    INFO = "info"          # 0.0-0.9


class AlertStatus(Enum):
    """Alarm durumu"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class HuntStatus(Enum):
    """Hunt durumu"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BehaviorType(Enum):
    """Davranis turleri"""
    LOGIN = "login"
    LOGOUT = "logout"
    FILE_ACCESS = "file_access"
    NETWORK_CONNECTION = "network_connection"
    PROCESS_EXECUTION = "process_execution"
    PRIVILEGE_CHANGE = "privilege_change"
    DATA_TRANSFER = "data_transfer"
    CONFIGURATION_CHANGE = "configuration_change"
    AUTHENTICATION_FAILURE = "authentication_failure"
    SUSPICIOUS_COMMAND = "suspicious_command"


class TTPCategory(Enum):
    """Taktik, Teknik, Prosedur kategorileri (MITRE ATT&CK)"""
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    EXFILTRATION = "TA0010"
    COMMAND_AND_CONTROL = "TA0011"
    IMPACT = "TA0040"


# ============================================================================
#                           VERi MODELLERI
# ============================================================================

@dataclass
class BehaviorEvent:
    """Davranis olayi"""
    timestamp: datetime
    entity_type: str  # user, device, application
    entity_id: str
    behavior_type: BehaviorType
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None  # success, failure
    user_agent: Optional[str] = None
    geo_location: Optional[Dict] = None
    raw_data: Dict = field(default_factory=dict)


@dataclass
class BehaviorBaseline:
    """Davranis temel cizelgesi"""
    entity_id: str
    entity_type: str
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

    # Login davranisi
    login_hours: List[int] = field(default_factory=list)  # Normal login saatleri
    login_days: List[int] = field(default_factory=list)   # Normal gunler (0=Pzt)
    login_locations: List[str] = field(default_factory=list)
    login_devices: List[str] = field(default_factory=list)
    avg_login_frequency: float = 0.0  # Gunluk ortalama

    # Ag davranisi
    normal_destinations: List[str] = field(default_factory=list)
    normal_ports: List[int] = field(default_factory=list)
    avg_bytes_per_day: float = 0.0
    avg_connections_per_day: float = 0.0

    # Dosya erisim davranisi
    accessed_resources: List[str] = field(default_factory=list)
    avg_file_access_per_day: float = 0.0
    sensitive_access_count: int = 0

    # Istatistikler
    total_events: int = 0
    training_period_days: int = 30

    # ML model verileri
    feature_means: Optional[Dict[str, float]] = None
    feature_stds: Optional[Dict[str, float]] = None


@dataclass
class AnomalyDetection:
    """Anomali tespit sonucu"""
    entity_id: str
    timestamp: datetime
    anomaly_type: str
    anomaly_score: float  # 0.0 - 1.0
    severity: ThreatSeverity
    description: str
    evidence: List[Dict] = field(default_factory=list)
    baseline_deviation: Dict = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)


@dataclass
class IOCGenerated:
    """Otomatik uretilen IOC"""
    ioc_type: str  # ip, domain, hash, url, email
    value: str
    confidence: float
    source: str
    first_seen: datetime
    last_seen: datetime
    related_alerts: List[str] = field(default_factory=list)
    context: Dict = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class HuntResult:
    """Hunt sonucu"""
    hunt_id: str
    playbook_name: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: HuntStatus = HuntStatus.PENDING
    findings: List[Dict] = field(default_factory=list)
    iocs_generated: List[IOCGenerated] = field(default_factory=list)
    entities_affected: List[str] = field(default_factory=list)
    severity: ThreatSeverity = ThreatSeverity.INFO
    recommendations: List[str] = field(default_factory=list)
    mitre_coverage: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


@dataclass
class ThreatAlert:
    """Tehdit alarmi"""
    alert_id: str
    timestamp: datetime
    title: str
    description: str
    severity: ThreatSeverity
    status: AlertStatus = AlertStatus.NEW
    source: str = "threat_hunter"
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    evidence: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    resolution_notes: Optional[str] = None


# ============================================================================
#                           MITRE ATT&CK ENTEGRASYONU
# ============================================================================

class MitreAttackMapper:
    """
    MITRE ATT&CK Framework entegrasyonu
    Davranislari tekniklere ve taktiklere esler
    """

    # Teknik tanimlari - basitlestirilmis
    TECHNIQUES = {
        # Initial Access (TA0001)
        'T1566': {'name': 'Phishing', 'tactic': 'TA0001', 'description': 'Phishing ile ilk erisim'},
        'T1566.001': {'name': 'Spearphishing Attachment', 'tactic': 'TA0001', 'description': 'Hedefli phishing eki'},
        'T1566.002': {'name': 'Spearphishing Link', 'tactic': 'TA0001', 'description': 'Hedefli phishing linki'},
        'T1190': {'name': 'Exploit Public-Facing Application', 'tactic': 'TA0001', 'description': 'Acik uygulama istismari'},
        'T1078': {'name': 'Valid Accounts', 'tactic': 'TA0001', 'description': 'Gecerli hesap kullanimi'},

        # Execution (TA0002)
        'T1059': {'name': 'Command and Scripting Interpreter', 'tactic': 'TA0002', 'description': 'Komut/script yorumlayici'},
        'T1059.001': {'name': 'PowerShell', 'tactic': 'TA0002', 'description': 'PowerShell calistirma'},
        'T1059.003': {'name': 'Windows Command Shell', 'tactic': 'TA0002', 'description': 'CMD kullanimi'},
        'T1047': {'name': 'Windows Management Instrumentation', 'tactic': 'TA0002', 'description': 'WMI kullanimi'},

        # Persistence (TA0003)
        'T1547': {'name': 'Boot or Logon Autostart Execution', 'tactic': 'TA0003', 'description': 'Otomatik baslatma'},
        'T1547.001': {'name': 'Registry Run Keys', 'tactic': 'TA0003', 'description': 'Registry Run anahtarlari'},
        'T1053': {'name': 'Scheduled Task/Job', 'tactic': 'TA0003', 'description': 'Zamanlanmis gorev'},
        'T1136': {'name': 'Create Account', 'tactic': 'TA0003', 'description': 'Hesap olusturma'},

        # Privilege Escalation (TA0004)
        'T1548': {'name': 'Abuse Elevation Control Mechanism', 'tactic': 'TA0004', 'description': 'Yetki yukseltme istismari'},
        'T1068': {'name': 'Exploitation for Privilege Escalation', 'tactic': 'TA0004', 'description': 'Zafiyet ile yetki yukseltme'},

        # Defense Evasion (TA0005)
        'T1027': {'name': 'Obfuscated Files or Information', 'tactic': 'TA0005', 'description': 'Gizlenmis dosya/bilgi'},
        'T1070': {'name': 'Indicator Removal', 'tactic': 'TA0005', 'description': 'Gosterge silme'},
        'T1036': {'name': 'Masquerading', 'tactic': 'TA0005', 'description': 'Kimlik gizleme'},
        'T1055': {'name': 'Process Injection', 'tactic': 'TA0005', 'description': 'Proses enjeksiyonu'},

        # Credential Access (TA0006)
        'T1110': {'name': 'Brute Force', 'tactic': 'TA0006', 'description': 'Kaba kuvvet saldirisi'},
        'T1003': {'name': 'OS Credential Dumping', 'tactic': 'TA0006', 'description': 'Kimlik bilgisi dokumu'},
        'T1558': {'name': 'Steal or Forge Kerberos Tickets', 'tactic': 'TA0006', 'description': 'Kerberos bilet hirsizligi'},

        # Discovery (TA0007)
        'T1087': {'name': 'Account Discovery', 'tactic': 'TA0007', 'description': 'Hesap kesfi'},
        'T1083': {'name': 'File and Directory Discovery', 'tactic': 'TA0007', 'description': 'Dosya/dizin kesfi'},
        'T1046': {'name': 'Network Service Discovery', 'tactic': 'TA0007', 'description': 'Ag servisi kesfi'},
        'T1135': {'name': 'Network Share Discovery', 'tactic': 'TA0007', 'description': 'Ag paylasimi kesfi'},

        # Lateral Movement (TA0008)
        'T1021': {'name': 'Remote Services', 'tactic': 'TA0008', 'description': 'Uzak servisler'},
        'T1021.001': {'name': 'Remote Desktop Protocol', 'tactic': 'TA0008', 'description': 'RDP kullanimi'},
        'T1021.002': {'name': 'SMB/Windows Admin Shares', 'tactic': 'TA0008', 'description': 'SMB paylasimi'},
        'T1080': {'name': 'Taint Shared Content', 'tactic': 'TA0008', 'description': 'Paylasilmis icerik zehirleme'},

        # Collection (TA0009)
        'T1119': {'name': 'Automated Collection', 'tactic': 'TA0009', 'description': 'Otomatik toplama'},
        'T1005': {'name': 'Data from Local System', 'tactic': 'TA0009', 'description': 'Yerel sistem verisi'},
        'T1039': {'name': 'Data from Network Shared Drive', 'tactic': 'TA0009', 'description': 'Ag paylasimindan veri'},

        # Exfiltration (TA0010)
        'T1041': {'name': 'Exfiltration Over C2 Channel', 'tactic': 'TA0010', 'description': 'C2 uzerinden sizinti'},
        'T1048': {'name': 'Exfiltration Over Alternative Protocol', 'tactic': 'TA0010', 'description': 'Alternatif protokol ile sizinti'},
        'T1567': {'name': 'Exfiltration Over Web Service', 'tactic': 'TA0010', 'description': 'Web servisi ile sizinti'},

        # Command and Control (TA0011)
        'T1071': {'name': 'Application Layer Protocol', 'tactic': 'TA0011', 'description': 'Uygulama katmani protokolu'},
        'T1071.001': {'name': 'Web Protocols', 'tactic': 'TA0011', 'description': 'Web protokolleri (HTTP/HTTPS)'},
        'T1071.004': {'name': 'DNS', 'tactic': 'TA0011', 'description': 'DNS protokolu'},
        'T1095': {'name': 'Non-Application Layer Protocol', 'tactic': 'TA0011', 'description': 'Non-uygulama protokolu'},
        'T1572': {'name': 'Protocol Tunneling', 'tactic': 'TA0011', 'description': 'Protokol tunelleme'},
        'T1573': {'name': 'Encrypted Channel', 'tactic': 'TA0011', 'description': 'Sifreli kanal'},

        # Impact (TA0040)
        'T1486': {'name': 'Data Encrypted for Impact', 'tactic': 'TA0040', 'description': 'Ransomware sifreleme'},
        'T1490': {'name': 'Inhibit System Recovery', 'tactic': 'TA0040', 'description': 'Sistem kurtarma engelleme'},
        'T1489': {'name': 'Service Stop', 'tactic': 'TA0040', 'description': 'Servis durdurma'},
    }

    # Taktik tanimlari
    TACTICS = {
        'TA0001': 'Initial Access',
        'TA0002': 'Execution',
        'TA0003': 'Persistence',
        'TA0004': 'Privilege Escalation',
        'TA0005': 'Defense Evasion',
        'TA0006': 'Credential Access',
        'TA0007': 'Discovery',
        'TA0008': 'Lateral Movement',
        'TA0009': 'Collection',
        'TA0010': 'Exfiltration',
        'TA0011': 'Command and Control',
        'TA0040': 'Impact',
    }

    # Davranis-teknik eslestirme
    BEHAVIOR_TO_TECHNIQUE = {
        'failed_login_burst': ['T1110'],
        'unusual_login_time': ['T1078'],
        'unusual_login_location': ['T1078'],
        'privilege_escalation': ['T1548', 'T1068'],
        'lateral_movement': ['T1021', 'T1021.001', 'T1021.002'],
        'data_exfiltration': ['T1041', 'T1048', 'T1567'],
        'beaconing': ['T1071', 'T1071.001', 'T1095'],
        'dns_tunneling': ['T1071.004', 'T1572'],
        'powershell_execution': ['T1059.001'],
        'cmd_execution': ['T1059.003'],
        'persistence_registry': ['T1547.001'],
        'scheduled_task': ['T1053'],
        'process_injection': ['T1055'],
        'credential_dumping': ['T1003'],
        'account_creation': ['T1136'],
        'ransomware_behavior': ['T1486', 'T1490'],
        'discovery_activity': ['T1087', 'T1083', 'T1046'],
        'sensitive_file_access': ['T1005', 'T1039'],
    }

    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict]:
        """Teknik bilgisi getir"""
        return cls.TECHNIQUES.get(technique_id)

    @classmethod
    def get_tactic(cls, tactic_id: str) -> Optional[str]:
        """Taktik adi getir"""
        return cls.TACTICS.get(tactic_id)

    @classmethod
    def map_behavior_to_techniques(cls, behavior: str) -> List[str]:
        """Davranisi tekniklere esle"""
        return cls.BEHAVIOR_TO_TECHNIQUE.get(behavior, [])

    @classmethod
    def get_attack_chain(cls, techniques: List[str]) -> Dict[str, List[str]]:
        """Saldiri zinciri olustur - taktiklere gore grupla"""
        chain = defaultdict(list)
        for tech_id in techniques:
            tech = cls.TECHNIQUES.get(tech_id)
            if tech:
                chain[tech['tactic']].append(tech_id)

        # Taktik sirasina gore sirala
        tactic_order = list(cls.TACTICS.keys())
        sorted_chain = {}
        for tactic in tactic_order:
            if tactic in chain:
                sorted_chain[tactic] = chain[tactic]

        return sorted_chain

    @classmethod
    def get_coverage_gaps(cls, detected_tactics: List[str]) -> List[str]:
        """Tespit edilmemis taktikleri bul"""
        all_tactics = set(cls.TACTICS.keys())
        detected = set(detected_tactics)
        return list(all_tactics - detected)


# ============================================================================
#                           ML ANOMALI TESPITI
# ============================================================================

class AnomalyDetectorML:
    """
    Makine Ogrenmesi Tabanli Anomali Dedektoru

    Algoritmalar:
    - Isolation Forest: Ag trafigi anomalileri
    - Autoencoder (basit): Davranis anomalileri
    - Statistical: Z-score tabanli
    """

    def __init__(self, contamination: float = 0.1):
        """
        Args:
            contamination: Beklenen anomali orani (0.0-0.5)
        """
        self.contamination = contamination
        self._isolation_forest: Optional[Any] = None
        self._scaler: Optional[Any] = None
        self._is_trained = False
        self._feature_names: List[str] = []
        self._training_stats: Dict = {}

        if not SKLEARN_AVAILABLE:
            logger.warning("[HUNTER] scikit-learn yuklu degil, ML ozellikleri devre disi")

    def train_isolation_forest(self, events: List[BehaviorEvent],
                               features: List[str] = None) -> bool:
        """
        Isolation Forest modelini egit

        Isolation Forest, anomalileri tespit etmek icin veriyi izole eder.
        Normal veriler daha zor izole edilirken, anomaliler daha kolay izole edilir.
        """
        if not SKLEARN_AVAILABLE:
            return False

        if len(events) < 50:
            logger.warning("[HUNTER] Egitim icin yetersiz veri (min 50 gerekli)")
            return False

        # Varsayilan ozellikler
        if features is None:
            features = ['hour', 'day_of_week', 'bytes_sent', 'bytes_received',
                       'connection_count', 'unique_destinations']

        self._feature_names = features

        # Veriyi feature matrix'e donustur
        X = self._events_to_features(events, features)

        if X is None or len(X) == 0:
            return False

        # Olceklendirme
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Model egitimi
        self._isolation_forest = IsolationForest(
            contamination=self.contamination,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            n_jobs=-1
        )
        self._isolation_forest.fit(X_scaled)

        # Egitim istatistikleri
        self._training_stats = {
            'n_samples': len(X),
            'n_features': len(features),
            'features': features,
            'trained_at': datetime.now().isoformat(),
            'contamination': self.contamination
        }

        self._is_trained = True
        logger.info(f"[HUNTER] Isolation Forest egitildi: {len(X)} ornek, {len(features)} ozellik")

        return True

    def predict_anomaly(self, event: BehaviorEvent) -> Tuple[bool, float]:
        """
        Tek bir olay icin anomali tahmini

        Returns:
            (is_anomaly, anomaly_score)
        """
        if not self._is_trained or not SKLEARN_AVAILABLE:
            return (False, 0.0)

        # Olayi feature vektorune donustur
        X = self._events_to_features([event], self._feature_names)

        if X is None or len(X) == 0:
            return (False, 0.0)

        X_scaled = self._scaler.transform(X)

        # Tahmin (-1: anomali, 1: normal)
        prediction = self._isolation_forest.predict(X_scaled)[0]

        # Anomali skoru (dusuk = anomali)
        score = self._isolation_forest.decision_function(X_scaled)[0]

        # Skoru 0-1 araligina normalize et (1 = kesin anomali)
        # decision_function negatif degerlerde anomali verir
        normalized_score = max(0, min(1, 0.5 - score))

        return (prediction == -1, normalized_score)

    def batch_predict(self, events: List[BehaviorEvent]) -> List[Tuple[bool, float]]:
        """Toplu anomali tahmini"""
        if not self._is_trained or not SKLEARN_AVAILABLE:
            return [(False, 0.0)] * len(events)

        X = self._events_to_features(events, self._feature_names)

        if X is None or len(X) == 0:
            return [(False, 0.0)] * len(events)

        X_scaled = self._scaler.transform(X)

        predictions = self._isolation_forest.predict(X_scaled)
        scores = self._isolation_forest.decision_function(X_scaled)

        results = []
        for pred, score in zip(predictions, scores):
            normalized_score = max(0, min(1, 0.5 - score))
            results.append((pred == -1, normalized_score))

        return results

    def _events_to_features(self, events: List[BehaviorEvent],
                           features: List[str]) -> Optional[np.ndarray]:
        """Olaylari feature matrix'e donustur"""
        if not SKLEARN_AVAILABLE:
            return None

        data = []

        for event in events:
            row = []
            for feat in features:
                if feat == 'hour':
                    row.append(event.timestamp.hour)
                elif feat == 'day_of_week':
                    row.append(event.timestamp.weekday())
                elif feat == 'bytes_sent':
                    row.append(event.bytes_sent)
                elif feat == 'bytes_received':
                    row.append(event.bytes_received)
                elif feat == 'connection_count':
                    row.append(1)  # Her olay bir baglanti
                elif feat == 'unique_destinations':
                    row.append(1 if event.destination_ip else 0)
                elif feat == 'source_port':
                    row.append(event.source_port or 0)
                elif feat == 'destination_port':
                    row.append(event.destination_port or 0)
                else:
                    row.append(0)
            data.append(row)

        return np.array(data)

    def save_model(self, filepath: str) -> bool:
        """Modeli dosyaya kaydet - imza ile"""
        import os
        import hashlib
        import hmac

        if not self._is_trained:
            return False

        try:
            model_data = {
                'isolation_forest': self._isolation_forest,
                'scaler': self._scaler,
                'feature_names': self._feature_names,
                'training_stats': self._training_stats,
                'contamination': self.contamination
            }
            with open(filepath, 'wb') as f:
                pickle.dump(model_data, f)

            # Imza dosyasi olustur
            with open(filepath, 'rb') as f:
                file_data = f.read()

            secret_key = os.environ.get('TSUNAMI_MODEL_KEY', 'tsunami-model-key-change-in-prod')
            signature = hmac.new(secret_key.encode(), file_data, hashlib.sha256).hexdigest()

            sig_file = filepath + '.sig'
            with open(sig_file, 'w') as f:
                f.write(signature)

            logger.info(f"[HUNTER] Model kaydedildi (imzali): {filepath}")
            return True
        except Exception as e:
            logger.error(f"[HUNTER] Model kaydetme hatasi: {e}")
            return False

    def load_model(self, filepath: str) -> bool:
        """Modeli dosyadan yukle - guvenlik kontrollu"""
        import os
        import hashlib
        import hmac

        try:
            # Guvenlik: Sadece guvenilir dizinlerden yukle
            TRUSTED_MODEL_DIRS = [
                os.path.expanduser('~/.tsunami/models'),
                '/home/lydian/Desktop/TSUNAMI/models',
                '/var/lib/tsunami/models'
            ]

            abs_path = os.path.abspath(filepath)
            is_trusted = any(abs_path.startswith(d) for d in TRUSTED_MODEL_DIRS)

            if not is_trusted:
                logger.error(f"[HUNTER] Guvenilmeyen model dizini: {filepath}")
                return False

            # Dosya uzantisi kontrolu
            if not filepath.endswith('.pkl') and not filepath.endswith('.model'):
                logger.error(f"[HUNTER] Gecersiz model uzantisi: {filepath}")
                return False

            # Signature dosyasi kontrolu
            sig_file = filepath + '.sig'
            if os.path.exists(sig_file):
                with open(filepath, 'rb') as f:
                    file_data = f.read()
                with open(sig_file, 'r') as f:
                    expected_sig = f.read().strip()

                # HMAC ile dogrula (secret key environment'tan)
                secret_key = os.environ.get('TSUNAMI_MODEL_KEY', 'tsunami-model-key-change-in-prod')
                actual_sig = hmac.new(secret_key.encode(), file_data, hashlib.sha256).hexdigest()

                if not hmac.compare_digest(actual_sig, expected_sig):
                    logger.error(f"[HUNTER] Model imza dogrulamasi basarisiz: {filepath}")
                    return False
                logger.info(f"[HUNTER] Model imzasi dogrulandi: {filepath}")
            else:
                logger.warning(f"[HUNTER] Model imza dosyasi yok, dikkatli yukle: {filepath}")

            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)

            # Beklenen anahtarlari dogrula
            required_keys = {'isolation_forest', 'scaler', 'feature_names', 'training_stats', 'contamination'}
            if not required_keys.issubset(model_data.keys()):
                logger.error(f"[HUNTER] Model yapisi gecersiz: eksik anahtarlar")
                return False

            self._isolation_forest = model_data['isolation_forest']
            self._scaler = model_data['scaler']
            self._feature_names = model_data['feature_names']
            self._training_stats = model_data['training_stats']
            self.contamination = model_data['contamination']
            self._is_trained = True

            logger.info(f"[HUNTER] Model yuklendi: {filepath}")
            return True
        except (pickle.UnpicklingError, KeyError, TypeError) as e:
            logger.error(f"[HUNTER] Model format hatasi: {e}")
            return False
        except Exception as e:
            logger.error(f"[HUNTER] Model yukleme hatasi: {e}")
            return False


class StatisticalAnomalyDetector:
    """
    Istatistiksel Anomali Dedektoru

    Z-score ve IQR tabanli basit anomali tespiti.
    ML kutuphaneleri olmadan da calisir.
    """

    def __init__(self, z_threshold: float = 3.0, iqr_multiplier: float = 1.5):
        self.z_threshold = z_threshold
        self.iqr_multiplier = iqr_multiplier
        self._baselines: Dict[str, Dict] = {}

    def update_baseline(self, entity_id: str, metric_name: str, value: float):
        """Baseline'a yeni deger ekle"""
        key = f"{entity_id}:{metric_name}"

        if key not in self._baselines:
            self._baselines[key] = {
                'values': [],
                'mean': 0.0,
                'std': 0.0,
                'q1': 0.0,
                'q3': 0.0,
                'updated_at': datetime.now()
            }

        baseline = self._baselines[key]
        baseline['values'].append(value)

        # Son 1000 degeri tut
        if len(baseline['values']) > 1000:
            baseline['values'] = baseline['values'][-1000:]

        # Istatistikleri guncelle
        if len(baseline['values']) >= 10:
            baseline['mean'] = statistics.mean(baseline['values'])
            baseline['std'] = statistics.stdev(baseline['values']) if len(baseline['values']) > 1 else 0.0
            sorted_vals = sorted(baseline['values'])
            n = len(sorted_vals)
            baseline['q1'] = sorted_vals[n // 4]
            baseline['q3'] = sorted_vals[3 * n // 4]
            baseline['updated_at'] = datetime.now()

    def detect_z_score(self, entity_id: str, metric_name: str, value: float) -> Tuple[bool, float]:
        """Z-score ile anomali tespiti"""
        key = f"{entity_id}:{metric_name}"
        baseline = self._baselines.get(key)

        if not baseline or baseline['std'] == 0:
            return (False, 0.0)

        z_score = abs((value - baseline['mean']) / baseline['std'])
        is_anomaly = z_score > self.z_threshold

        # Skoru 0-1 araligina normalize et
        normalized_score = min(1.0, z_score / (self.z_threshold * 2))

        return (is_anomaly, normalized_score)

    def detect_iqr(self, entity_id: str, metric_name: str, value: float) -> Tuple[bool, float]:
        """IQR ile anomali tespiti"""
        key = f"{entity_id}:{metric_name}"
        baseline = self._baselines.get(key)

        if not baseline:
            return (False, 0.0)

        iqr = baseline['q3'] - baseline['q1']
        lower_bound = baseline['q1'] - (self.iqr_multiplier * iqr)
        upper_bound = baseline['q3'] + (self.iqr_multiplier * iqr)

        is_anomaly = value < lower_bound or value > upper_bound

        # Skoru hesapla
        if is_anomaly:
            if value < lower_bound:
                distance = lower_bound - value
            else:
                distance = value - upper_bound
            normalized_score = min(1.0, distance / (iqr + 0.001))
        else:
            normalized_score = 0.0

        return (is_anomaly, normalized_score)


# ============================================================================
#                           UEBA - KULLANICI DAVRANIS ANALIZI
# ============================================================================

class UEBAEngine:
    """
    User and Entity Behavior Analytics (UEBA)

    Kullanici ve varlik davranislarini analiz eder, anomalileri tespit eder.
    """

    def __init__(self):
        self._baselines: Dict[str, BehaviorBaseline] = {}
        self._events: List[BehaviorEvent] = []
        self._alerts: List[ThreatAlert] = []
        self._ml_detector = AnomalyDetectorML()
        self._stat_detector = StatisticalAnomalyDetector()
        self._lock = threading.Lock()

        # Risk skorlari
        self._risk_scores: Dict[str, float] = {}

        # Insider threat gostergeleri
        self.INSIDER_THREAT_INDICATORS = {
            'unusual_hours': 0.3,
            'excessive_access': 0.4,
            'sensitive_data_access': 0.5,
            'data_hoarding': 0.6,
            'privilege_abuse': 0.7,
            'resignation_risk': 0.5,
            'policy_violations': 0.4,
        }

        logger.info("[UEBA] UEBA Engine baslatildi")

    def add_event(self, event: BehaviorEvent) -> Optional[AnomalyDetection]:
        """
        Yeni davranis olayi ekle ve analiz et

        Returns:
            Anomali tespit edildiyse AnomalyDetection, yoksa None
        """
        with self._lock:
            self._events.append(event)

            # Son 100000 olayi tut
            if len(self._events) > 100000:
                self._events = self._events[-100000:]

        # Baseline guncelle
        self._update_baseline(event)

        # Anomali kontrolu
        return self._check_anomaly(event)

    def _update_baseline(self, event: BehaviorEvent):
        """Baseline guncelle"""
        entity_id = event.entity_id

        if entity_id not in self._baselines:
            self._baselines[entity_id] = BehaviorBaseline(
                entity_id=entity_id,
                entity_type=event.entity_type
            )

        baseline = self._baselines[entity_id]
        baseline.updated_at = datetime.now()
        baseline.total_events += 1

        # Login davranisi
        if event.behavior_type == BehaviorType.LOGIN:
            hour = event.timestamp.hour
            day = event.timestamp.weekday()

            if hour not in baseline.login_hours:
                baseline.login_hours.append(hour)
            if day not in baseline.login_days:
                baseline.login_days.append(day)
            if event.source_ip and event.source_ip not in baseline.login_locations:
                baseline.login_locations.append(event.source_ip)

        # Ag davranisi
        if event.behavior_type == BehaviorType.NETWORK_CONNECTION:
            if event.destination_ip and event.destination_ip not in baseline.normal_destinations:
                if len(baseline.normal_destinations) < 1000:  # Limit
                    baseline.normal_destinations.append(event.destination_ip)
            if event.destination_port and event.destination_port not in baseline.normal_ports:
                if len(baseline.normal_ports) < 100:
                    baseline.normal_ports.append(event.destination_port)

        # Dosya erisim
        if event.behavior_type == BehaviorType.FILE_ACCESS:
            if event.resource and event.resource not in baseline.accessed_resources:
                if len(baseline.accessed_resources) < 5000:
                    baseline.accessed_resources.append(event.resource)

        # Istatistiksel dedektoru guncelle
        if event.bytes_sent:
            self._stat_detector.update_baseline(entity_id, 'bytes_sent', event.bytes_sent)
        if event.bytes_received:
            self._stat_detector.update_baseline(entity_id, 'bytes_received', event.bytes_received)

    def _check_anomaly(self, event: BehaviorEvent) -> Optional[AnomalyDetection]:
        """Anomali kontrolu"""
        anomalies = []

        baseline = self._baselines.get(event.entity_id)
        if not baseline or baseline.total_events < 100:
            return None  # Yeterli baseline yok

        # Login saat anomalisi
        if event.behavior_type == BehaviorType.LOGIN:
            if baseline.login_hours and event.timestamp.hour not in baseline.login_hours:
                anomalies.append({
                    'type': 'unusual_login_time',
                    'score': 0.6,
                    'description': f'Olagan disi giris saati: {event.timestamp.hour}:00',
                    'techniques': MitreAttackMapper.map_behavior_to_techniques('unusual_login_time')
                })

            # Lokasyon anomalisi
            if baseline.login_locations and event.source_ip:
                if event.source_ip not in baseline.login_locations:
                    anomalies.append({
                        'type': 'unusual_login_location',
                        'score': 0.7,
                        'description': f'Yeni lokasyondan giris: {event.source_ip}',
                        'techniques': MitreAttackMapper.map_behavior_to_techniques('unusual_login_location')
                    })

        # Yetki yukseltme
        if event.behavior_type == BehaviorType.PRIVILEGE_CHANGE:
            anomalies.append({
                'type': 'privilege_escalation',
                'score': 0.8,
                'description': f'Yetki degisikligi tespit edildi: {event.action}',
                'techniques': MitreAttackMapper.map_behavior_to_techniques('privilege_escalation')
            })

        # Basarisiz giris patlamasi
        if event.behavior_type == BehaviorType.AUTHENTICATION_FAILURE:
            recent_failures = sum(
                1 for e in self._events[-1000:]
                if e.entity_id == event.entity_id
                and e.behavior_type == BehaviorType.AUTHENTICATION_FAILURE
                and (event.timestamp - e.timestamp).total_seconds() < 300
            )
            if recent_failures > 5:
                anomalies.append({
                    'type': 'failed_login_burst',
                    'score': 0.9,
                    'description': f'5 dakikada {recent_failures} basarisiz giris',
                    'techniques': MitreAttackMapper.map_behavior_to_techniques('failed_login_burst')
                })

        # Istatistiksel anomali - bytes
        if event.bytes_sent:
            is_anomaly, score = self._stat_detector.detect_z_score(
                event.entity_id, 'bytes_sent', event.bytes_sent
            )
            if is_anomaly:
                anomalies.append({
                    'type': 'unusual_data_transfer',
                    'score': score,
                    'description': f'Anormal veri transferi: {event.bytes_sent} bytes',
                    'techniques': MitreAttackMapper.map_behavior_to_techniques('data_exfiltration')
                })

        # ML tabanli anomali
        if self._ml_detector._is_trained:
            is_anomaly, score = self._ml_detector.predict_anomaly(event)
            if is_anomaly and score > 0.7:
                anomalies.append({
                    'type': 'ml_detected_anomaly',
                    'score': score,
                    'description': 'ML modeli tarafindan tespit edilen anomali',
                    'techniques': []
                })

        # En ciddi anomaliyi dondur
        if anomalies:
            worst = max(anomalies, key=lambda x: x['score'])
            severity = self._score_to_severity(worst['score'])

            all_techniques = []
            for a in anomalies:
                all_techniques.extend(a.get('techniques', []))

            detection = AnomalyDetection(
                entity_id=event.entity_id,
                timestamp=datetime.now(),
                anomaly_type=worst['type'],
                anomaly_score=worst['score'],
                severity=severity,
                description=worst['description'],
                evidence=[{'event': asdict(event)}],
                mitre_techniques=list(set(all_techniques)),
                recommended_actions=self._get_recommendations(worst['type'])
            )

            # Risk skorunu guncelle
            self._update_risk_score(event.entity_id, worst['score'])

            return detection

        return None

    def _score_to_severity(self, score: float) -> ThreatSeverity:
        """Skoru ciddiyet seviyesine cevir"""
        if score >= 0.9:
            return ThreatSeverity.CRITICAL
        elif score >= 0.7:
            return ThreatSeverity.HIGH
        elif score >= 0.4:
            return ThreatSeverity.MEDIUM
        elif score >= 0.1:
            return ThreatSeverity.LOW
        return ThreatSeverity.INFO

    def _get_recommendations(self, anomaly_type: str) -> List[str]:
        """Anomali turune gore oneriler"""
        recommendations = {
            'unusual_login_time': [
                'Kullanici ile iletisime gecin',
                'Oturum aktivitelerini inceleyin',
                'MFA durumunu kontrol edin'
            ],
            'unusual_login_location': [
                'IP adresinin meşruiyetini dogrulayin',
                'VPN veya proxy kullanimi kontrol edin',
                'Kullaniciyi uyarin'
            ],
            'failed_login_burst': [
                'Hesabi gecici olarak kilitleyin',
                'Kaynak IP\'yi bloklama degerlendir',
                'Credential stuffing saldirisi olabilir'
            ],
            'privilege_escalation': [
                'Yetki degisikligini yetkiliden dogrulayin',
                'Denetim kaydini inceleyin',
                'Gerekiyorsa yetkiyi geri alin'
            ],
            'unusual_data_transfer': [
                'Veri icerigini inceleyin',
                'DLP uyarilarini kontrol edin',
                'Baglanti hedefini arastirin'
            ],
            'ml_detected_anomaly': [
                'Detayli log analizi yapin',
                'Iliski kurulu olaylari arastirin',
                'False positive olasiliğini değerlendirin'
            ]
        }
        return recommendations.get(anomaly_type, ['Detayli inceleme yapin'])

    def _update_risk_score(self, entity_id: str, anomaly_score: float):
        """Varlik risk skorunu guncelle"""
        current = self._risk_scores.get(entity_id, 0.0)
        # Zamana gore azalan ortalama
        decay_factor = 0.9
        new_score = (current * decay_factor) + (anomaly_score * (1 - decay_factor))
        self._risk_scores[entity_id] = min(1.0, new_score)

    def get_risk_score(self, entity_id: str) -> float:
        """Varlik risk skorunu getir"""
        return self._risk_scores.get(entity_id, 0.0)

    def get_high_risk_entities(self, threshold: float = 0.6) -> List[Tuple[str, float]]:
        """Yuksek riskli varliklari getir"""
        high_risk = [
            (entity_id, score)
            for entity_id, score in self._risk_scores.items()
            if score >= threshold
        ]
        return sorted(high_risk, key=lambda x: x[1], reverse=True)

    def get_recent_anomalies(self, limit: int = 50) -> List[Dict]:
        """Son anomalileri getir (dalga_web.py uyumlulugu)"""
        result = []

        # Alert'lerden anomali olustur
        for alert in self._alerts[-limit:]:
            result.append({
                'user': alert.entity_id or 'unknown',
                'anomaly_type': alert.title or 'anomaly',
                'risk_score': 0.7,
                'details': alert.description or '',
                'detected_at': alert.timestamp.isoformat() if alert.timestamp else ''
            })

        # Alert yoksa yuksek riskli varliklardan olustur
        if not result:
            for entity_id, score in sorted(
                self._risk_scores.items(), key=lambda x: x[1], reverse=True
            )[:limit]:
                if score > 0.5:
                    result.append({
                        'user': entity_id,
                        'anomaly_type': 'yuksek_risk_skoru',
                        'risk_score': round(score, 2),
                        'details': f'Risk skoru esik degerini asti: {score:.2f}',
                        'detected_at': datetime.now().isoformat()
                    })

        return result[:limit]

    def calculate_insider_threat_score(self, user_id: str) -> Dict[str, Any]:
        """
        Insider threat (ic tehdit) skoru hesapla

        Coklu gostergeler kullanarak kullanicinin ic tehdit riskini degerlendirir.
        """
        indicators = {}
        total_score = 0.0

        baseline = self._baselines.get(user_id)
        if not baseline:
            return {'score': 0.0, 'indicators': {}, 'risk_level': 'unknown'}

        user_events = [e for e in self._events[-10000:] if e.entity_id == user_id]

        # Olagan disi saatler
        off_hours_logins = sum(
            1 for e in user_events
            if e.behavior_type == BehaviorType.LOGIN
            and (e.timestamp.hour < 6 or e.timestamp.hour > 22)
        )
        if off_hours_logins > 5:
            indicators['unusual_hours'] = off_hours_logins
            total_score += self.INSIDER_THREAT_INDICATORS['unusual_hours']

        # Asiri erisim
        unique_resources = len(set(e.resource for e in user_events if e.resource))
        if baseline.accessed_resources:
            access_ratio = unique_resources / (len(baseline.accessed_resources) + 1)
            if access_ratio > 2.0:
                indicators['excessive_access'] = access_ratio
                total_score += self.INSIDER_THREAT_INDICATORS['excessive_access']

        # Hassas veri erisimi
        sensitive_patterns = ['confidential', 'secret', 'password', 'credential', 'key', 'private']
        sensitive_accesses = sum(
            1 for e in user_events
            if e.resource and any(p in e.resource.lower() for p in sensitive_patterns)
        )
        if sensitive_accesses > 10:
            indicators['sensitive_data_access'] = sensitive_accesses
            total_score += self.INSIDER_THREAT_INDICATORS['sensitive_data_access']

        # Veri biriktirme (data hoarding)
        total_downloaded = sum(e.bytes_received for e in user_events if e.bytes_received)
        if total_downloaded > 1_000_000_000:  # 1GB
            indicators['data_hoarding'] = total_downloaded
            total_score += self.INSIDER_THREAT_INDICATORS['data_hoarding']

        # Risk seviyesi
        if total_score >= 1.5:
            risk_level = 'critical'
        elif total_score >= 1.0:
            risk_level = 'high'
        elif total_score >= 0.5:
            risk_level = 'medium'
        elif total_score > 0:
            risk_level = 'low'
        else:
            risk_level = 'minimal'

        return {
            'user_id': user_id,
            'score': min(total_score, 1.0),
            'indicators': indicators,
            'risk_level': risk_level,
            'calculated_at': datetime.now().isoformat()
        }

    def detect_lateral_movement(self, time_window_minutes: int = 60) -> List[Dict]:
        """
        Lateral movement (yanal hareket) tespiti

        Bir kullanicinin kisa surede birden fazla sisteme erisimini tespit eder.
        """
        findings = []
        cutoff = datetime.now() - timedelta(minutes=time_window_minutes)

        # Kullanici bazinda baglantilari grupla
        user_connections: Dict[str, Set[str]] = defaultdict(set)
        user_connection_times: Dict[str, List[datetime]] = defaultdict(list)

        for event in self._events:
            if event.timestamp < cutoff:
                continue
            if event.behavior_type in [BehaviorType.LOGIN, BehaviorType.NETWORK_CONNECTION]:
                if event.destination_ip:
                    user_connections[event.entity_id].add(event.destination_ip)
                    user_connection_times[event.entity_id].append(event.timestamp)

        # Coklu hedef tespiti
        for user_id, destinations in user_connections.items():
            if len(destinations) >= 5:  # 5+ farkli hedef
                times = user_connection_times[user_id]
                time_span = (max(times) - min(times)).total_seconds() / 60

                if time_span < time_window_minutes:
                    findings.append({
                        'user_id': user_id,
                        'detection': 'lateral_movement',
                        'destinations': list(destinations),
                        'destination_count': len(destinations),
                        'time_span_minutes': time_span,
                        'severity': 'high' if len(destinations) > 10 else 'medium',
                        'mitre_techniques': MitreAttackMapper.map_behavior_to_techniques('lateral_movement'),
                        'detected_at': datetime.now().isoformat()
                    })

        return findings

    def get_baseline(self, entity_id: str) -> Optional[BehaviorBaseline]:
        """Varlik baseline'ini getir"""
        return self._baselines.get(entity_id)

    def get_all_baselines(self) -> Dict[str, BehaviorBaseline]:
        """Tum baseline'lari getir"""
        return self._baselines.copy()

    def train_ml_model(self) -> bool:
        """ML modelini egit"""
        return self._ml_detector.train_isolation_forest(self._events)


# ============================================================================
#                           AG DAVRANIS ANALIZI
# ============================================================================

class NetworkBehaviorAnalyzer:
    """
    Ag Davranis Analizi

    - Beaconing tespiti (C2 iletisimi)
    - DNS tunneling tespiti
    - Veri sizintisi tespiti
    - Protokol anomalileri
    """

    def __init__(self):
        self._traffic_history: List[Dict] = []
        self._dns_history: List[Dict] = []
        self._connection_baselines: Dict[str, Dict] = {}
        self._lock = threading.Lock()

        # Beaconing parametreleri
        self.BEACON_INTERVAL_TOLERANCE = 0.1  # %10 tolerans
        self.MIN_BEACON_SAMPLES = 10

        # DNS tunneling parametreleri
        self.DNS_ENTROPY_THRESHOLD = 4.0
        self.DNS_LENGTH_THRESHOLD = 50

        # Bilinen kotu hedefler (ornek)
        self._known_bad_ips: Set[str] = set()
        self._known_bad_domains: Set[str] = set()

        logger.info("[NETWORK] Network Behavior Analyzer baslatildi")

    def add_traffic(self, traffic: Dict) -> List[Dict]:
        """
        Ag trafigi ekle ve analiz et

        Args:
            traffic: {
                'timestamp': datetime,
                'source_ip': str,
                'destination_ip': str,
                'source_port': int,
                'destination_port': int,
                'protocol': str,
                'bytes_sent': int,
                'bytes_received': int,
                'duration': float
            }

        Returns:
            Tespit edilen tehditler listesi
        """
        findings = []

        with self._lock:
            self._traffic_history.append(traffic)

            # Son 100000 kaydi tut
            if len(self._traffic_history) > 100000:
                self._traffic_history = self._traffic_history[-100000:]

        # Analizler
        beacon = self._detect_beaconing(traffic)
        if beacon:
            findings.append(beacon)

        exfil = self._detect_exfiltration(traffic)
        if exfil:
            findings.append(exfil)

        protocol_anomaly = self._detect_protocol_anomaly(traffic)
        if protocol_anomaly:
            findings.append(protocol_anomaly)

        return findings

    def add_dns_query(self, query: Dict) -> Optional[Dict]:
        """
        DNS sorgusu ekle ve analiz et

        Args:
            query: {
                'timestamp': datetime,
                'source_ip': str,
                'query_name': str,
                'query_type': str,
                'response': str
            }
        """
        with self._lock:
            self._dns_history.append(query)

            if len(self._dns_history) > 50000:
                self._dns_history = self._dns_history[-50000:]

        return self._detect_dns_tunneling(query)

    def _detect_beaconing(self, traffic: Dict) -> Optional[Dict]:
        """
        Beaconing tespiti

        Duzgun araliklarla C2 sunucusuna baglanan malware'leri tespit eder.
        """
        dest_ip = traffic.get('destination_ip')
        if not dest_ip:
            return None

        # Bu hedefe olan son baglantilari al
        dest_connections = [
            t for t in self._traffic_history[-1000:]
            if t.get('destination_ip') == dest_ip
        ]

        if len(dest_connections) < self.MIN_BEACON_SAMPLES:
            return None

        # Zaman araliklerini hesapla
        timestamps = sorted([t['timestamp'] for t in dest_connections if isinstance(t.get('timestamp'), datetime)])

        if len(timestamps) < self.MIN_BEACON_SAMPLES:
            return None

        intervals = []
        for i in range(1, len(timestamps)):
            interval = (timestamps[i] - timestamps[i-1]).total_seconds()
            if interval > 0:
                intervals.append(interval)

        if not intervals:
            return None

        # Standart sapma / ortalama (coefficient of variation)
        mean_interval = statistics.mean(intervals)
        if mean_interval == 0:
            return None

        try:
            std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        except statistics.StatisticsError:
            return None

        cv = std_interval / mean_interval

        # Dusuk CV = duzgun araliklarla iletisim = beaconing
        if cv < self.BEACON_INTERVAL_TOLERANCE:
            return {
                'detection': 'beaconing',
                'destination_ip': dest_ip,
                'mean_interval_seconds': mean_interval,
                'coefficient_of_variation': cv,
                'sample_count': len(intervals),
                'severity': 'high',
                'confidence': 1.0 - cv,
                'description': f'{dest_ip} adresine duzgun aralikli baglanti tespit edildi (ortalama {mean_interval:.1f}sn)',
                'mitre_techniques': MitreAttackMapper.map_behavior_to_techniques('beaconing'),
                'recommendations': [
                    'Hedef IP adresini arastirin',
                    'Ilgili sureci tanimlayin',
                    'C2 iletisimi olabilir - sistemleri izole edin'
                ],
                'detected_at': datetime.now().isoformat()
            }

        return None

    def _detect_dns_tunneling(self, query: Dict) -> Optional[Dict]:
        """
        DNS tunneling tespiti

        Veri sizintisi icin DNS sorgularini kullanan saldırılari tespit eder.
        """
        query_name = query.get('query_name', '')

        if not query_name:
            return None

        # Alt domain ayi
        parts = query_name.split('.')
        if len(parts) < 2:
            return None

        subdomain = parts[0]

        # 1. Uzunluk kontrolu
        if len(subdomain) > self.DNS_LENGTH_THRESHOLD:
            suspicious = True
        else:
            suspicious = False

        # 2. Entropi kontrolu (yuksek entropi = rastgele/sifreli veri)
        entropy = self._calculate_entropy(subdomain)

        if entropy > self.DNS_ENTROPY_THRESHOLD:
            suspicious = True

        # 3. Hex/Base64 pattern kontrolu
        hex_pattern = re.match(r'^[0-9a-fA-F]+$', subdomain)
        base64_pattern = re.match(r'^[A-Za-z0-9+/=]+$', subdomain)

        if (hex_pattern and len(subdomain) > 20) or (base64_pattern and len(subdomain) > 30):
            suspicious = True

        # 4. Ayni domain'e yogun sorgu
        domain = '.'.join(parts[-2:])
        recent_queries = sum(
            1 for q in self._dns_history[-500:]
            if q.get('query_name', '').endswith(domain)
        )

        if recent_queries > 50:
            suspicious = True

        if suspicious:
            return {
                'detection': 'dns_tunneling',
                'query_name': query_name,
                'subdomain_length': len(subdomain),
                'entropy': entropy,
                'domain': domain,
                'recent_query_count': recent_queries,
                'severity': 'high',
                'confidence': min(0.9, entropy / 5.0),
                'description': f'DNS tunneling suphelisi: {query_name[:50]}...',
                'mitre_techniques': MitreAttackMapper.map_behavior_to_techniques('dns_tunneling'),
                'recommendations': [
                    'DNS sorgularini detayli inceleyin',
                    'Kaynak sistemi arastirin',
                    'DNS trafigini sinirlayin'
                ],
                'detected_at': datetime.now().isoformat()
            }

        return None

    def _detect_exfiltration(self, traffic: Dict) -> Optional[Dict]:
        """
        Veri sizintisi (exfiltration) tespiti

        Buyuk miktarda verinin dis hedeflere gonderilmesini tespit eder.
        """
        bytes_sent = traffic.get('bytes_sent', 0)
        dest_ip = traffic.get('destination_ip', '')
        source_ip = traffic.get('source_ip', '')

        if bytes_sent < 10_000_000:  # 10MB altini kontrol etme
            return None

        # Baseline'a gore kontrol
        baseline_key = f"{source_ip}:{dest_ip}"
        baseline = self._connection_baselines.get(baseline_key, {'avg_bytes': 0, 'max_bytes': 0})

        # Baseline'i guncelle
        if baseline['avg_bytes'] == 0:
            self._connection_baselines[baseline_key] = {
                'avg_bytes': bytes_sent,
                'max_bytes': bytes_sent,
                'count': 1
            }
        else:
            count = baseline.get('count', 1)
            baseline['avg_bytes'] = (baseline['avg_bytes'] * count + bytes_sent) / (count + 1)
            baseline['max_bytes'] = max(baseline['max_bytes'], bytes_sent)
            baseline['count'] = count + 1
            self._connection_baselines[baseline_key] = baseline

        # Baseline'in 5 kati uzerinde mi?
        if baseline['avg_bytes'] > 0 and bytes_sent > baseline['avg_bytes'] * 5:
            # Ozel IP mi kontrol et
            try:
                dest_obj = ipaddress.ip_address(dest_ip)
                is_private = dest_obj.is_private
            except ValueError:
                is_private = False

            if not is_private:  # Sadece public IP'ler
                return {
                    'detection': 'data_exfiltration',
                    'source_ip': source_ip,
                    'destination_ip': dest_ip,
                    'bytes_sent': bytes_sent,
                    'baseline_avg': baseline['avg_bytes'],
                    'ratio': bytes_sent / baseline['avg_bytes'] if baseline['avg_bytes'] > 0 else 0,
                    'severity': 'critical' if bytes_sent > 100_000_000 else 'high',
                    'confidence': 0.8,
                    'description': f'{source_ip} adresinden {dest_ip} adresine buyuk veri transferi ({bytes_sent / 1_000_000:.1f} MB)',
                    'mitre_techniques': MitreAttackMapper.map_behavior_to_techniques('data_exfiltration'),
                    'recommendations': [
                        'Transfer edilen veriyi tanimlayin',
                        'Kullaniciyi sorgulayın',
                        'DLP loglarini kontrol edin',
                        'Gerekirse baglantiyi kesin'
                    ],
                    'detected_at': datetime.now().isoformat()
                }

        return None

    def _detect_protocol_anomaly(self, traffic: Dict) -> Optional[Dict]:
        """
        Protokol anomalisi tespiti

        Standart disi port kullanimi, protokol uyumsuzlugu vb.
        """
        dest_port = traffic.get('destination_port', 0)
        protocol = traffic.get('protocol', '').lower()
        bytes_sent = traffic.get('bytes_sent', 0)

        anomalies = []

        # HTTP/HTTPS port kontrolu
        if dest_port in [80, 443]:
            if bytes_sent > 50_000_000:  # 50MB uzerinde HTTP trafigi
                anomalies.append('large_http_transfer')

        # DNS port kontrolu
        if dest_port == 53:
            if bytes_sent > 1_000_000:  # DNS'de 1MB uzerinde
                anomalies.append('large_dns_traffic')

        # Yuksek portlara TCP baglantisi
        if dest_port > 10000 and protocol == 'tcp':
            if bytes_sent > 10_000_000:
                anomalies.append('high_port_data_transfer')

        # Standart disi protokol-port kombinasyonu
        standard_ports = {
            'http': [80, 8080, 8000],
            'https': [443, 8443],
            'ssh': [22],
            'ftp': [21, 20],
            'smtp': [25, 587, 465],
            'dns': [53],
        }

        if protocol in standard_ports:
            if dest_port not in standard_ports[protocol] and dest_port > 0:
                anomalies.append(f'nonstandard_{protocol}_port')

        if anomalies:
            return {
                'detection': 'protocol_anomaly',
                'anomalies': anomalies,
                'destination_port': dest_port,
                'protocol': protocol,
                'bytes_sent': bytes_sent,
                'severity': 'medium',
                'confidence': 0.6,
                'description': f'Protokol anomalisi: {", ".join(anomalies)}',
                'mitre_techniques': ['T1071', 'T1095'],
                'detected_at': datetime.now().isoformat()
            }

        return None

    def _calculate_entropy(self, text: str) -> float:
        """Shannon entropisi hesapla"""
        if not text:
            return 0.0

        freq = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in freq.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def get_traffic_baseline(self, source_ip: str = None) -> Dict:
        """Trafik baseline'ini getir"""
        if source_ip:
            return {
                k: v for k, v in self._connection_baselines.items()
                if k.startswith(source_ip)
            }
        return self._connection_baselines.copy()


# ============================================================================
#                           HUNT PLAYBOOK'LARI
# ============================================================================

class HuntPlaybook:
    """Hunt playbook taban sinifi"""

    name: str = "base_playbook"
    description: str = "Base playbook"
    mitre_techniques: List[str] = []
    severity: ThreatSeverity = ThreatSeverity.MEDIUM

    @abstractmethod
    def execute(self, data: Dict) -> HuntResult:
        """Playbook'u calistir"""
        pass


class APTCampaignPlaybook(HuntPlaybook):
    """
    APT Kampanya Hunt Playbook'u

    Gelismis kalici tehdit (APT) gostergelerini arar.
    """

    name = "apt_campaign_hunt"
    description = "APT kampanya gostergelerini arar"
    mitre_techniques = ['T1566', 'T1190', 'T1078', 'T1059', 'T1547']

    # Bilinen APT IOC'leri (ornek)
    APT_INDICATORS = {
        'domains': [
            'apt29-c2.com', 'cozy-bear.net', 'fancy-bear.org',
            'lazarus-group.com', 'apt41-staging.net'
        ],
        'ip_ranges': ['185.141.63.0/24', '91.219.236.0/24'],
        'user_agents': [
            'Mozilla/5.0 (APT)',
            'MSIE 6.0; APT'
        ],
        'file_hashes': [
            'd4a42eb85c25d2feace62e5c4a98d2c0',
            'e6bf14d0c2cfe27e9b3de1e5f30c7e83'
        ],
        'suspicious_paths': [
            '/admin/upload.php',
            '/wp-content/plugins/shell.php',
            '/.hidden/backdoor'
        ]
    }

    def execute(self, data: Dict) -> HuntResult:
        """
        APT hunt'i calistir

        Args:
            data: {
                'logs': List[Dict],  # Web/network logs
                'dns_queries': List[Dict],
                'file_events': List[Dict]
            }
        """
        hunt_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:12]
        result = HuntResult(
            hunt_id=hunt_id,
            playbook_name=self.name,
            started_at=datetime.now(),
            status=HuntStatus.RUNNING
        )

        findings = []
        iocs = []
        entities = set()

        # Domain kontrolleri
        for query in data.get('dns_queries', []):
            domain = query.get('query_name', '').lower()
            for apt_domain in self.APT_INDICATORS['domains']:
                if apt_domain in domain:
                    findings.append({
                        'type': 'apt_domain_match',
                        'indicator': apt_domain,
                        'observed': domain,
                        'source_ip': query.get('source_ip'),
                        'timestamp': query.get('timestamp')
                    })
                    entities.add(query.get('source_ip', ''))
                    iocs.append(IOCGenerated(
                        ioc_type='domain',
                        value=domain,
                        confidence=0.9,
                        source=self.name,
                        first_seen=datetime.now(),
                        last_seen=datetime.now(),
                        related_alerts=[hunt_id],
                        mitre_techniques=self.mitre_techniques
                    ))

        # IP kontrolleri
        for log in data.get('logs', []):
            dest_ip = log.get('destination_ip', '')
            for ip_range in self.APT_INDICATORS['ip_ranges']:
                try:
                    if dest_ip and ipaddress.ip_address(dest_ip) in ipaddress.ip_network(ip_range, strict=False):
                        findings.append({
                            'type': 'apt_ip_match',
                            'indicator': ip_range,
                            'observed': dest_ip,
                            'source': log.get('source_ip'),
                            'timestamp': log.get('timestamp')
                        })
                        entities.add(log.get('source_ip', ''))
                except ValueError:
                    continue

        # User-Agent kontrolleri
        for log in data.get('logs', []):
            ua = log.get('user_agent', '')
            for apt_ua in self.APT_INDICATORS['user_agents']:
                if apt_ua.lower() in ua.lower():
                    findings.append({
                        'type': 'apt_useragent_match',
                        'indicator': apt_ua,
                        'observed': ua,
                        'source_ip': log.get('source_ip'),
                        'timestamp': log.get('timestamp')
                    })
                    entities.add(log.get('source_ip', ''))

        # Sonuclari doldur
        result.findings = findings
        result.iocs_generated = iocs
        result.entities_affected = list(entities)
        result.completed_at = datetime.now()
        result.mitre_coverage = self.mitre_techniques

        if findings:
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.CRITICAL if len(findings) > 5 else ThreatSeverity.HIGH
            result.recommendations = [
                'Etkilenen sistemleri izole edin',
                'Incident Response prosedurunu baslatin',
                'Forensic analiz yapin',
                'IOC\'leri SIEM\'e ekleyin',
                'Lateral movement kontrol edin'
            ]
        else:
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.INFO

        return result


class RansomwarePlaybook(HuntPlaybook):
    """
    Ransomware Hunt Playbook'u

    Ransomware oncusu davranislari tespit eder.
    """

    name = "ransomware_precursor_hunt"
    description = "Ransomware saldirisi oncusu davranislari arar"
    mitre_techniques = ['T1486', 'T1490', 'T1059.001', 'T1070']

    # Ransomware gostergeleri
    INDICATORS = {
        'suspicious_processes': [
            'vssadmin.exe', 'wmic.exe', 'bcdedit.exe',
            'wbadmin.exe', 'cipher.exe', 'schtasks.exe'
        ],
        'suspicious_commands': [
            'delete shadows',
            'resize shadowstorage',
            'recoveryenabled no',
            'delete catalog',
            '/encrypt',
            'cipher /w:'
        ],
        'suspicious_extensions': [
            '.encrypted', '.locked', '.crypto', '.crypt',
            '.locky', '.zepto', '.cerber', '.wannacry'
        ],
        'ransom_note_patterns': [
            'readme.txt', 'how_to_decrypt', 'your_files',
            'ransom', 'decrypt_instructions', 'pay_', 'bitcoin'
        ]
    }

    def execute(self, data: Dict) -> HuntResult:
        """Ransomware hunt'i calistir"""
        hunt_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:12]
        result = HuntResult(
            hunt_id=hunt_id,
            playbook_name=self.name,
            started_at=datetime.now(),
            status=HuntStatus.RUNNING
        )

        findings = []
        entities = set()

        # Proses kontrolleri
        for event in data.get('process_events', []):
            process = event.get('process_name', '').lower()
            cmdline = event.get('command_line', '').lower()

            for susp_proc in self.INDICATORS['suspicious_processes']:
                if susp_proc.lower() in process:
                    for susp_cmd in self.INDICATORS['suspicious_commands']:
                        if susp_cmd.lower() in cmdline:
                            findings.append({
                                'type': 'ransomware_preparation',
                                'process': process,
                                'command': cmdline[:200],
                                'host': event.get('hostname'),
                                'user': event.get('username'),
                                'timestamp': event.get('timestamp'),
                                'severity': 'critical'
                            })
                            entities.add(event.get('hostname', ''))

        # Dosya operasyonu kontrolleri
        for event in data.get('file_events', []):
            filename = event.get('filename', '').lower()

            # Sifrelenmis dosya uzantisi
            for ext in self.INDICATORS['suspicious_extensions']:
                if filename.endswith(ext):
                    findings.append({
                        'type': 'encrypted_file_detected',
                        'filename': filename,
                        'path': event.get('path'),
                        'host': event.get('hostname'),
                        'timestamp': event.get('timestamp'),
                        'severity': 'critical'
                    })
                    entities.add(event.get('hostname', ''))

            # Ransom notu
            for pattern in self.INDICATORS['ransom_note_patterns']:
                if pattern in filename:
                    findings.append({
                        'type': 'ransom_note_detected',
                        'filename': filename,
                        'path': event.get('path'),
                        'host': event.get('hostname'),
                        'timestamp': event.get('timestamp'),
                        'severity': 'critical'
                    })
                    entities.add(event.get('hostname', ''))

        # Sonuclari doldur
        result.findings = findings
        result.entities_affected = list(entities)
        result.completed_at = datetime.now()
        result.mitre_coverage = self.mitre_techniques

        if findings:
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.CRITICAL
            result.recommendations = [
                'ACIL: Etkilenen sistemleri agdan izole edin',
                'Backup sistemlerini kontrol edin',
                'Shadow copy durumunu dogrulayin',
                'Ransomware ornegini guvenli ortamda analiz edin',
                'Law enforcement ile iletisime gecin'
            ]
        else:
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.INFO

        return result


class FilelessMalwarePlaybook(HuntPlaybook):
    """
    Fileless Malware Hunt Playbook'u

    Dosyasiz zararli yazilim davranislarini tespit eder.
    """

    name = "fileless_malware_hunt"
    description = "Dosyasiz (in-memory) zararli yazilim davranislarini arar"
    mitre_techniques = ['T1059.001', 'T1047', 'T1055', 'T1218']

    INDICATORS = {
        'powershell_suspicious': [
            '-encodedcommand', '-enc', '-ec',
            'invoke-expression', 'iex',
            'downloadstring', 'downloadfile',
            'bypass', '-nop', '-noni',
            'hidden', '-w hidden',
            'frombase64string', 'decompress',
            'invoke-mimikatz', 'invoke-shellcode'
        ],
        'wmi_suspicious': [
            'process call create',
            'win32_process',
            'win32_scheduledjob'
        ],
        'lolbins': [
            'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
            'certutil.exe', 'bitsadmin.exe', 'cmstp.exe',
            'msiexec.exe', 'installutil.exe', 'regasm.exe'
        ]
    }

    def execute(self, data: Dict) -> HuntResult:
        """Fileless malware hunt'i calistir"""
        hunt_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:12]
        result = HuntResult(
            hunt_id=hunt_id,
            playbook_name=self.name,
            started_at=datetime.now(),
            status=HuntStatus.RUNNING
        )

        findings = []
        entities = set()

        for event in data.get('process_events', []):
            process = event.get('process_name', '').lower()
            cmdline = event.get('command_line', '').lower()
            parent = event.get('parent_process', '').lower()

            # PowerShell analizi
            if 'powershell' in process:
                for indicator in self.INDICATORS['powershell_suspicious']:
                    if indicator.lower() in cmdline:
                        findings.append({
                            'type': 'suspicious_powershell',
                            'indicator': indicator,
                            'command': cmdline[:300],
                            'host': event.get('hostname'),
                            'user': event.get('username'),
                            'parent_process': parent,
                            'timestamp': event.get('timestamp'),
                            'severity': 'high'
                        })
                        entities.add(event.get('hostname', ''))
                        break

            # WMI analizi
            if 'wmic' in process or 'wmiprvse' in process:
                for indicator in self.INDICATORS['wmi_suspicious']:
                    if indicator.lower() in cmdline:
                        findings.append({
                            'type': 'suspicious_wmi',
                            'indicator': indicator,
                            'command': cmdline[:200],
                            'host': event.get('hostname'),
                            'timestamp': event.get('timestamp'),
                            'severity': 'high'
                        })
                        entities.add(event.get('hostname', ''))

            # LOLBins analizi
            for lolbin in self.INDICATORS['lolbins']:
                if lolbin.lower() in process:
                    # URL veya encoded data iceriyor mu?
                    if 'http' in cmdline or 'ftp' in cmdline or '/e:' in cmdline:
                        findings.append({
                            'type': 'lolbin_abuse',
                            'binary': lolbin,
                            'command': cmdline[:200],
                            'host': event.get('hostname'),
                            'timestamp': event.get('timestamp'),
                            'severity': 'medium'
                        })
                        entities.add(event.get('hostname', ''))

        # Sonuclari doldur
        result.findings = findings
        result.entities_affected = list(entities)
        result.completed_at = datetime.now()
        result.mitre_coverage = self.mitre_techniques

        if findings:
            high_severity = sum(1 for f in findings if f.get('severity') == 'high')
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.HIGH if high_severity > 0 else ThreatSeverity.MEDIUM
            result.recommendations = [
                'Memory dump alin ve analiz edin',
                'Supheli PowerShell scriptlerini inceleyin',
                'Event log\'lari detayli arastirin',
                'AppLocker/WDAC politikalarini guclendirin'
            ]
        else:
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.INFO

        return result


class CredentialTheftPlaybook(HuntPlaybook):
    """
    Credential Theft Hunt Playbook'u

    Kimlik bilgisi hirsizligi davranislarini tespit eder.
    """

    name = "credential_theft_hunt"
    description = "Kimlik bilgisi hirsizligi davranislarini arar"
    mitre_techniques = ['T1003', 'T1110', 'T1558', 'T1552']

    INDICATORS = {
        'credential_tools': [
            'mimikatz', 'procdump', 'lazagne',
            'gsecdump', 'pwdump', 'fgdump',
            'wce', 'hashcat', 'john'
        ],
        'suspicious_access': [
            'lsass', 'sam', 'ntds.dit',
            'security', 'system', 'credential'
        ],
        'kerberos_attacks': [
            'kerberoast', 'golden ticket',
            'silver ticket', 'overpass', 'pass-the-hash'
        ]
    }

    def execute(self, data: Dict) -> HuntResult:
        """Credential theft hunt'i calistir"""
        hunt_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:12]
        result = HuntResult(
            hunt_id=hunt_id,
            playbook_name=self.name,
            started_at=datetime.now(),
            status=HuntStatus.RUNNING
        )

        findings = []
        entities = set()

        # Proses kontrolleri
        for event in data.get('process_events', []):
            process = event.get('process_name', '').lower()
            cmdline = event.get('command_line', '').lower()

            for tool in self.INDICATORS['credential_tools']:
                if tool in process or tool in cmdline:
                    findings.append({
                        'type': 'credential_tool_detected',
                        'tool': tool,
                        'process': process,
                        'command': cmdline[:200],
                        'host': event.get('hostname'),
                        'user': event.get('username'),
                        'timestamp': event.get('timestamp'),
                        'severity': 'critical'
                    })
                    entities.add(event.get('hostname', ''))

        # Hassas dosya erisimi
        for event in data.get('file_events', []):
            path = event.get('path', '').lower()

            for target in self.INDICATORS['suspicious_access']:
                if target in path:
                    findings.append({
                        'type': 'sensitive_credential_access',
                        'target': target,
                        'path': path,
                        'action': event.get('action'),
                        'host': event.get('hostname'),
                        'user': event.get('username'),
                        'timestamp': event.get('timestamp'),
                        'severity': 'high'
                    })
                    entities.add(event.get('hostname', ''))

        # Kimlik dogrulama anomalileri
        for event in data.get('auth_events', []):
            # Kisa surede cok fazla basarisiz deneme
            if event.get('result') == 'failure':
                source_ip = event.get('source_ip')
                recent_failures = sum(
                    1 for e in data.get('auth_events', [])
                    if e.get('source_ip') == source_ip and e.get('result') == 'failure'
                )
                if recent_failures > 10:
                    findings.append({
                        'type': 'brute_force_detected',
                        'source_ip': source_ip,
                        'failure_count': recent_failures,
                        'target_user': event.get('username'),
                        'timestamp': event.get('timestamp'),
                        'severity': 'high'
                    })
                    entities.add(source_ip or '')

        result.findings = findings
        result.entities_affected = list(entities)
        result.completed_at = datetime.now()
        result.mitre_coverage = self.mitre_techniques

        if findings:
            critical_count = sum(1 for f in findings if f.get('severity') == 'critical')
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.CRITICAL if critical_count > 0 else ThreatSeverity.HIGH
            result.recommendations = [
                'Etkilenen hesaplarin parolalarini sifirlayin',
                'Kerberos biletlerini gecersiz kilin',
                'LSASS erisim loglarini inceleyin',
                'Credential Guard\'i etkinlestirin'
            ]
        else:
            result.status = HuntStatus.COMPLETED
            result.severity = ThreatSeverity.INFO

        return result


# ============================================================================
#                           IOC GENERATOR
# ============================================================================

class IOCGenerator:
    """
    Otomatik IOC (Indicator of Compromise) Ureticisi

    Tespit edilen tehditlerden otomatik olarak IOC'ler uretir.
    """

    def __init__(self):
        self._generated_iocs: List[IOCGenerated] = []
        self._lock = threading.Lock()

    def generate_from_alert(self, alert: ThreatAlert) -> List[IOCGenerated]:
        """Alarm'dan IOC uret"""
        iocs = []

        for evidence in alert.evidence:
            # IP cikar
            ips = self._extract_ips(str(evidence))
            for ip in ips:
                ioc = IOCGenerated(
                    ioc_type='ip',
                    value=ip,
                    confidence=0.8,
                    source=f'alert:{alert.alert_id}',
                    first_seen=alert.timestamp,
                    last_seen=alert.timestamp,
                    related_alerts=[alert.alert_id],
                    mitre_techniques=alert.mitre_techniques
                )
                iocs.append(ioc)

            # Domain cikar
            domains = self._extract_domains(str(evidence))
            for domain in domains:
                ioc = IOCGenerated(
                    ioc_type='domain',
                    value=domain,
                    confidence=0.7,
                    source=f'alert:{alert.alert_id}',
                    first_seen=alert.timestamp,
                    last_seen=alert.timestamp,
                    related_alerts=[alert.alert_id],
                    mitre_techniques=alert.mitre_techniques
                )
                iocs.append(ioc)

            # Hash cikar
            hashes = self._extract_hashes(str(evidence))
            for hash_val, hash_type in hashes:
                ioc = IOCGenerated(
                    ioc_type=f'hash_{hash_type}',
                    value=hash_val,
                    confidence=0.9,
                    source=f'alert:{alert.alert_id}',
                    first_seen=alert.timestamp,
                    last_seen=alert.timestamp,
                    related_alerts=[alert.alert_id],
                    mitre_techniques=alert.mitre_techniques
                )
                iocs.append(ioc)

        with self._lock:
            self._generated_iocs.extend(iocs)

        return iocs

    def generate_from_hunt(self, result: HuntResult) -> List[IOCGenerated]:
        """Hunt sonucundan IOC uret"""
        iocs = []

        for finding in result.findings:
            # IP cikar
            ips = self._extract_ips(str(finding))
            for ip in ips:
                ioc = IOCGenerated(
                    ioc_type='ip',
                    value=ip,
                    confidence=0.85,
                    source=f'hunt:{result.hunt_id}',
                    first_seen=result.started_at,
                    last_seen=datetime.now(),
                    related_alerts=[result.hunt_id],
                    mitre_techniques=result.mitre_coverage,
                    context={'playbook': result.playbook_name}
                )
                iocs.append(ioc)

            # Domain cikar
            domains = self._extract_domains(str(finding))
            for domain in domains:
                ioc = IOCGenerated(
                    ioc_type='domain',
                    value=domain,
                    confidence=0.8,
                    source=f'hunt:{result.hunt_id}',
                    first_seen=result.started_at,
                    last_seen=datetime.now(),
                    related_alerts=[result.hunt_id],
                    mitre_techniques=result.mitre_coverage,
                    context={'playbook': result.playbook_name}
                )
                iocs.append(ioc)

        # Hunt'in kendi IOC'lerini de ekle
        iocs.extend(result.iocs_generated)

        with self._lock:
            self._generated_iocs.extend(iocs)

        return iocs

    def _extract_ips(self, text: str) -> List[str]:
        """Metinden IP adresleri cikar"""
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        matches = re.findall(ip_pattern, text)

        valid_ips = []
        for ip in matches:
            try:
                obj = ipaddress.ip_address(ip)
                # Localhost ve private IP'leri atlayabiliriz
                if not obj.is_loopback and not obj.is_private:
                    valid_ips.append(ip)
            except ValueError:
                continue

        return list(set(valid_ips))

    def _extract_domains(self, text: str) -> List[str]:
        """Metinden domain'ler cikar"""
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        matches = re.findall(domain_pattern, text)

        # Yaygın sahte pozitifleri filtrele
        excluded = {'example.com', 'localhost.com', 'test.com'}

        return list(set(m.lower() for m in matches if m.lower() not in excluded))

    def _extract_hashes(self, text: str) -> List[Tuple[str, str]]:
        """Metinden hash'ler cikar"""
        hashes = []

        # MD5
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        for match in re.findall(md5_pattern, text):
            hashes.append((match.lower(), 'md5'))

        # SHA1
        sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        for match in re.findall(sha1_pattern, text):
            hashes.append((match.lower(), 'sha1'))

        # SHA256
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for match in re.findall(sha256_pattern, text):
            hashes.append((match.lower(), 'sha256'))

        return list(set(hashes))

    def get_all_iocs(self) -> List[IOCGenerated]:
        """Tum uretilmis IOC'leri getir"""
        with self._lock:
            return self._generated_iocs.copy()

    def export_stix(self) -> Dict:
        """IOC'leri STIX formatinda disa aktar"""
        stix_bundle = {
            'type': 'bundle',
            'id': f'bundle--{hashlib.md5(str(datetime.now()).encode()).hexdigest()}',
            'objects': []
        }

        for ioc in self._generated_iocs:
            if ioc.ioc_type == 'ip':
                stix_obj = {
                    'type': 'ipv4-addr',
                    'value': ioc.value,
                    'spec_version': '2.1'
                }
            elif ioc.ioc_type == 'domain':
                stix_obj = {
                    'type': 'domain-name',
                    'value': ioc.value,
                    'spec_version': '2.1'
                }
            elif 'hash' in ioc.ioc_type:
                hash_type = ioc.ioc_type.replace('hash_', '')
                stix_obj = {
                    'type': 'file',
                    'hashes': {hash_type.upper(): ioc.value},
                    'spec_version': '2.1'
                }
            else:
                continue

            stix_bundle['objects'].append(stix_obj)

        return stix_bundle


# ============================================================================
#                           ANA THREAT HUNTER SINIFI
# ============================================================================

class ThreatHunter:
    """
    Ana Tehdit Avcisi Sinifi

    Tum threat hunting bilesenlerini yonetir.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        """Singleton instance al"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        # Alt bilesenler
        self.ueba = UEBAEngine()
        self.network_analyzer = NetworkBehaviorAnalyzer()
        self.ioc_generator = IOCGenerator()
        self.mitre = MitreAttackMapper

        # Playbook'lar
        self._playbooks: Dict[str, HuntPlaybook] = {
            'apt_campaign': APTCampaignPlaybook(),
            'ransomware': RansomwarePlaybook(),
            'fileless_malware': FilelessMalwarePlaybook(),
            'credential_theft': CredentialTheftPlaybook()
        }

        # Hunt gecmisi
        self._hunt_history: List[HuntResult] = []
        self._alerts: List[ThreatAlert] = []

        # Running hunts
        self._running_hunts: Dict[str, threading.Thread] = {}

        logger.info("[HUNTER] Threat Hunter baslatildi")

    def add_behavior_event(self, event: BehaviorEvent) -> Optional[AnomalyDetection]:
        """Davranis olayi ekle ve analiz et"""
        return self.ueba.add_event(event)

    def add_network_traffic(self, traffic: Dict) -> List[Dict]:
        """Ag trafigi ekle ve analiz et"""
        return self.network_analyzer.add_traffic(traffic)

    def add_dns_query(self, query: Dict) -> Optional[Dict]:
        """DNS sorgusu ekle ve analiz et"""
        return self.network_analyzer.add_dns_query(query)

    def start_hunt(self, playbook_name: str, data: Dict,
                   async_mode: bool = False) -> Union[HuntResult, str]:
        """
        Hunt baslat

        Args:
            playbook_name: Playbook adi
            data: Hunt verisi
            async_mode: Asenkron mod

        Returns:
            HuntResult veya hunt_id (async modda)
        """
        if playbook_name not in self._playbooks:
            raise ValueError(f"Bilinmeyen playbook: {playbook_name}")

        playbook = self._playbooks[playbook_name]

        if async_mode:
            # Asenkron calistir
            hunt_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:12]

            def run_async():
                result = playbook.execute(data)
                self._hunt_history.append(result)

                # IOC'ler uret
                self.ioc_generator.generate_from_hunt(result)

                # Alert olustur
                if result.findings:
                    self._create_alert_from_hunt(result)

                del self._running_hunts[hunt_id]

            thread = threading.Thread(target=run_async, daemon=True)
            self._running_hunts[hunt_id] = thread
            thread.start()

            return hunt_id
        else:
            # Senkron calistir
            result = playbook.execute(data)
            self._hunt_history.append(result)

            # IOC'ler uret
            self.ioc_generator.generate_from_hunt(result)

            # Alert olustur
            if result.findings:
                self._create_alert_from_hunt(result)

            return result

    def _create_alert_from_hunt(self, result: HuntResult):
        """Hunt sonucundan alert olustur"""
        alert = ThreatAlert(
            alert_id=f"ALERT-{result.hunt_id}",
            timestamp=datetime.now(),
            title=f"{result.playbook_name} - {len(result.findings)} bulgu",
            description=f"{result.playbook_name} playbook'u {len(result.findings)} tehdit bulgusi tespit etti",
            severity=result.severity,
            source='threat_hunter',
            mitre_techniques=result.mitre_coverage,
            evidence=result.findings[:10],  # Ilk 10
            recommendations=result.recommendations
        )
        self._alerts.append(alert)

    def get_hunt_status(self, hunt_id: str) -> Optional[str]:
        """Hunt durumunu getir"""
        if hunt_id in self._running_hunts:
            return 'running'

        for result in self._hunt_history:
            if result.hunt_id == hunt_id:
                return result.status.value

        return None

    def get_hunt_result(self, hunt_id: str) -> Optional[HuntResult]:
        """Hunt sonucunu getir"""
        for result in self._hunt_history:
            if result.hunt_id == hunt_id:
                return result
        return None

    def get_baselines(self) -> Dict[str, BehaviorBaseline]:
        """Tum baseline'lari getir"""
        return self.ueba.get_all_baselines()

    def get_alerts(self, status: AlertStatus = None,
                   severity: ThreatSeverity = None,
                   limit: int = 100) -> List[ThreatAlert]:
        """Alarmları getir"""
        results = []
        for alert in reversed(self._alerts):
            if status and alert.status != status:
                continue
            if severity and alert.severity != severity:
                continue
            results.append(alert)
            if len(results) >= limit:
                break
        return results

    def get_active_threats(self, limit: int = 100) -> List[Dict]:
        """Aktif tehditleri getir (dalga_web.py uyumlulugu)"""
        alerts = self.get_alerts(limit=limit)
        result = []
        for alert in alerts:
            result.append({
                'geo': {'lat': 0.0, 'lng': 0.0},
                'threat_type': alert.severity.value if alert.severity else 'unknown',
                'confidence': 0.8,
                'mitre_technique': alert.mitre_techniques[0] if alert.mitre_techniques else '',
                'source': alert.source or '',
                'target': alert.entity_id or '',
                'detected_at': alert.timestamp.isoformat() if alert.timestamp else '',
                'description': alert.description or alert.title or ''
            })
        return result

    def get_findings(self, limit: int = 100) -> List[Dict]:
        """Tum hunt bulgularini getir"""
        all_findings = []
        for result in self._hunt_history:
            for finding in result.findings:
                finding['hunt_id'] = result.hunt_id
                finding['playbook'] = result.playbook_name
                all_findings.append(finding)

        return all_findings[-limit:]

    def get_iocs(self) -> List[IOCGenerated]:
        """Uretilmis IOC'leri getir"""
        return self.ioc_generator.get_all_iocs()

    def get_mitre_coverage(self) -> Dict:
        """MITRE ATT&CK kapsama analizi"""
        detected_techniques = set()

        for result in self._hunt_history:
            detected_techniques.update(result.mitre_coverage)

        for alert in self._alerts:
            detected_techniques.update(alert.mitre_techniques)

        # Taktiklere gore grupla
        tactic_coverage = defaultdict(list)
        for tech_id in detected_techniques:
            tech = self.mitre.get_technique(tech_id)
            if tech:
                tactic_coverage[tech['tactic']].append(tech_id)

        # Kapsanmayan taktikler
        all_tactics = set(self.mitre.TACTICS.keys())
        covered_tactics = set(tactic_coverage.keys())
        gaps = all_tactics - covered_tactics

        return {
            'detected_techniques': list(detected_techniques),
            'technique_count': len(detected_techniques),
            'tactic_coverage': dict(tactic_coverage),
            'covered_tactics': list(covered_tactics),
            'coverage_gaps': list(gaps),
            'coverage_percentage': len(covered_tactics) / len(all_tactics) * 100
        }

    def get_statistics(self) -> Dict:
        """Istatistikler"""
        return {
            'total_hunts': len(self._hunt_history),
            'total_alerts': len(self._alerts),
            'total_iocs': len(self.ioc_generator.get_all_iocs()),
            'active_hunts': len(self._running_hunts),
            'baselines_count': len(self.ueba.get_all_baselines()),
            'high_risk_entities': len(self.ueba.get_high_risk_entities()),
            'mitre_coverage': self.get_mitre_coverage(),
            'playbooks_available': list(self._playbooks.keys())
        }

    def train_models(self) -> Dict[str, bool]:
        """Tum ML modellerini egit"""
        results = {}
        results['ueba_ml'] = self.ueba.train_ml_model()
        return results


# ============================================================================
#                           FLASK API ENDPOINTS
# ============================================================================

def register_hunter_routes(app):
    """
    Threat Hunter API rotalarini kaydet

    Args:
        app: Flask application
    """
    from flask import Blueprint, request, jsonify

    hunter_bp = Blueprint('hunter', __name__, url_prefix='/api/v1/hunter')

    @hunter_bp.route('/start', methods=['POST'])
    def start_hunt():
        """
        Hunt baslat

        POST /api/v1/hunter/start
        Body: {
            "playbook": "apt_campaign|ransomware|fileless_malware|credential_theft",
            "data": {...},
            "async": true|false
        }
        """
        try:
            hunter = ThreatHunter.get_instance()
            body = request.get_json()

            playbook = body.get('playbook')
            data = body.get('data', {})
            async_mode = body.get('async', False)

            if not playbook:
                return jsonify({'basarili': False, 'hata': 'playbook gerekli'}), 400

            result = hunter.start_hunt(playbook, data, async_mode)

            if async_mode:
                return jsonify({
                    'basarili': True,
                    'hunt_id': result,
                    'mesaj': 'Hunt baslatildi'
                })
            else:
                return jsonify({
                    'basarili': True,
                    'sonuc': asdict(result) if hasattr(result, '__dataclass_fields__') else result
                })

        except ValueError as e:
            return jsonify({'basarili': False, 'hata': str(e)}), 400
        except Exception as e:
            logger.error(f"[HUNTER-API] Hunt baslama hatasi: {e}")
            return jsonify({'basarili': False, 'hata': 'Sunucu hatasi'}), 500

    @hunter_bp.route('/findings', methods=['GET'])
    def get_findings():
        """
        Hunt bulgularini getir

        GET /api/v1/hunter/findings?limit=100
        """
        try:
            hunter = ThreatHunter.get_instance()
            limit = request.args.get('limit', 100, type=int)

            findings = hunter.get_findings(limit)

            return jsonify({
                'basarili': True,
                'bulgular': findings,
                'toplam': len(findings)
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Bulgu alma hatasi: {e}")
            return jsonify({'basarili': False, 'hata': 'Sunucu hatasi'}), 500

    @hunter_bp.route('/baselines', methods=['GET'])
    def get_baselines():
        """
        Davranis baseline'larini getir

        GET /api/v1/hunter/baselines?entity_id=xxx
        """
        try:
            hunter = ThreatHunter.get_instance()
            entity_id = request.args.get('entity_id')

            baselines = hunter.get_baselines()

            if entity_id:
                baseline = baselines.get(entity_id)
                if baseline:
                    return jsonify({
                        'basarili': True,
                        'baseline': asdict(baseline)
                    })
                else:
                    return jsonify({'basarili': False, 'hata': 'Baseline bulunamadi'}), 404

            return jsonify({
                'basarili': True,
                'baseline_sayisi': len(baselines),
                'varliklar': list(baselines.keys())
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Baseline alma hatasi: {e}")
            return jsonify({'basarili': False, 'hata': 'Sunucu hatasi'}), 500

    @hunter_bp.route('/playbooks', methods=['GET', 'POST'])
    def playbooks():
        """
        Playbook'lari listele veya calistir

        GET /api/v1/hunter/playbooks
        POST /api/v1/hunter/playbooks (same as /start)
        """
        hunter = ThreatHunter.get_instance()

        if request.method == 'GET':
            playbooks_info = []
            for name, pb in hunter._playbooks.items():
                playbooks_info.append({
                    'name': name,
                    'description': pb.description,
                    'mitre_techniques': pb.mitre_techniques,
                    'severity': pb.severity.value
                })

            return jsonify({
                'basarili': True,
                'playbooks': playbooks_info
            })

        else:  # POST
            return start_hunt()

    @hunter_bp.route('/alerts', methods=['GET'])
    def get_alerts():
        """
        Alarmlari getir

        GET /api/v1/hunter/alerts?status=new&severity=high&limit=50
        """
        try:
            hunter = ThreatHunter.get_instance()

            status_str = request.args.get('status')
            severity_str = request.args.get('severity')
            limit = request.args.get('limit', 100, type=int)

            status = AlertStatus(status_str) if status_str else None
            severity = ThreatSeverity(severity_str) if severity_str else None

            alerts = hunter.get_alerts(status=status, severity=severity, limit=limit)

            return jsonify({
                'basarili': True,
                'alarmlar': [asdict(a) for a in alerts],
                'toplam': len(alerts)
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Alarm alma hatasi: {e}")
            return jsonify({'basarili': False, 'hata': 'Sunucu hatasi'}), 500

    @hunter_bp.route('/iocs', methods=['GET'])
    def get_iocs():
        """
        Uretilmis IOC'leri getir

        GET /api/v1/hunter/iocs?format=json|stix
        """
        try:
            hunter = ThreatHunter.get_instance()
            format_type = request.args.get('format', 'json')

            if format_type == 'stix':
                stix_bundle = hunter.ioc_generator.export_stix()
                return jsonify(stix_bundle)
            else:
                iocs = hunter.get_iocs()
                return jsonify({
                    'basarili': True,
                    'ioclar': [asdict(ioc) for ioc in iocs],
                    'toplam': len(iocs)
                })

        except Exception as e:
            logger.error(f"[HUNTER-API] IOC alma hatasi: {e}")
            return jsonify({'basarili': False, 'hata': 'Sunucu hatasi'}), 500

    @hunter_bp.route('/mitre/coverage', methods=['GET'])
    def mitre_coverage():
        """
        MITRE ATT&CK kapsama analizi

        GET /api/v1/hunter/mitre/coverage
        """
        try:
            hunter = ThreatHunter.get_instance()
            coverage = hunter.get_mitre_coverage()

            return jsonify({
                'basarili': True,
                'kapsama': coverage
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] MITRE analiz hatasi: {e}")
            return jsonify({'basarili': False, 'hata': 'Sunucu hatasi'}), 500

    @hunter_bp.route('/statistics', methods=['GET'])
    def statistics():
        """
        Istatistikler

        GET /api/v1/hunter/statistics
        """
        try:
            hunter = ThreatHunter.get_instance()
            stats = hunter.get_statistics()

            return jsonify({
                'basarili': True,
                'istatistikler': stats
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Istatistik hatasi: {e}")
            return jsonify({'basarili': False, 'hata': 'Sunucu hatasi'}), 500

    @hunter_bp.route('/behavior/event', methods=['POST'])
    def add_behavior_event():
        """
        Davranis olayi ekle

        POST /api/v1/hunter/behavior/event
        Body: BehaviorEvent alanlari
        """
        try:
            hunter = ThreatHunter.get_instance()
            body = request.get_json()

            # Timestamp donusumu
            if 'timestamp' in body:
                if isinstance(body['timestamp'], str):
                    body['timestamp'] = datetime.fromisoformat(body['timestamp'])
            else:
                body['timestamp'] = datetime.now()

            # BehaviorType donusumu
            if 'behavior_type' in body:
                body['behavior_type'] = BehaviorType(body['behavior_type'])

            event = BehaviorEvent(**body)
            anomaly = hunter.add_behavior_event(event)

            if anomaly:
                return jsonify({
                    'basarili': True,
                    'anomali_tespit_edildi': True,
                    'anomali': asdict(anomaly)
                })

            return jsonify({
                'basarili': True,
                'anomali_tespit_edildi': False
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Olay ekleme hatasi: {e}")
            return jsonify({'basarili': False, 'hata': str(e)}), 400

    @hunter_bp.route('/network/traffic', methods=['POST'])
    def add_network_traffic():
        """
        Ag trafigi ekle

        POST /api/v1/hunter/network/traffic
        Body: traffic alanlari
        """
        try:
            hunter = ThreatHunter.get_instance()
            body = request.get_json()

            if 'timestamp' in body and isinstance(body['timestamp'], str):
                body['timestamp'] = datetime.fromisoformat(body['timestamp'])
            elif 'timestamp' not in body:
                body['timestamp'] = datetime.now()

            findings = hunter.add_network_traffic(body)

            return jsonify({
                'basarili': True,
                'tehdit_tespit_edildi': len(findings) > 0,
                'tespitler': findings
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Trafik ekleme hatasi: {e}")
            return jsonify({'basarili': False, 'hata': str(e)}), 400

    @hunter_bp.route('/risk/entity/<entity_id>', methods=['GET'])
    def get_entity_risk(entity_id: str):
        """
        Varlik risk skorunu getir

        GET /api/v1/hunter/risk/entity/user123
        """
        try:
            hunter = ThreatHunter.get_instance()

            risk_score = hunter.ueba.get_risk_score(entity_id)
            insider_threat = hunter.ueba.calculate_insider_threat_score(entity_id)
            baseline = hunter.ueba.get_baseline(entity_id)

            return jsonify({
                'basarili': True,
                'entity_id': entity_id,
                'risk_skoru': risk_score,
                'ic_tehdit_analizi': insider_threat,
                'baseline_mevcut': baseline is not None
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Risk alma hatasi: {e}")
            return jsonify({'basarili': False, 'hata': str(e)}), 500

    @hunter_bp.route('/train', methods=['POST'])
    def train_models():
        """
        ML modellerini egit

        POST /api/v1/hunter/train
        """
        try:
            hunter = ThreatHunter.get_instance()
            results = hunter.train_models()

            return jsonify({
                'basarili': True,
                'egitim_sonuclari': results
            })

        except Exception as e:
            logger.error(f"[HUNTER-API] Egitim hatasi: {e}")
            return jsonify({'basarili': False, 'hata': str(e)}), 500

    # Blueprint'i kaydet
    app.register_blueprint(hunter_bp)
    logger.info("[HUNTER-API] Threat Hunter API rotlari kaydedildi")


# ============================================================================
#                           SINGLETON ERISIM
# ============================================================================

_threat_hunter = None


def threat_hunter_al() -> ThreatHunter:
    """Threat Hunter instance al"""
    global _threat_hunter
    if _threat_hunter is None:
        _threat_hunter = ThreatHunter.get_instance()
    return _threat_hunter


# Alias
hunter_al = threat_hunter_al


# ============================================================================
#                           MODUL TESTI
# ============================================================================

if __name__ == "__main__":
    # Test
    print("=" * 60)
    print("TSUNAMI AI-Powered Threat Hunter v1.0")
    print("=" * 60)

    hunter = threat_hunter_al()

    # Test davranis olaylari
    print("\n[TEST] Davranis olaylari ekleniyor...")

    for i in range(150):
        event = BehaviorEvent(
            timestamp=datetime.now() - timedelta(hours=i),
            entity_type='user',
            entity_id='user001',
            behavior_type=BehaviorType.LOGIN if i % 10 != 0 else BehaviorType.AUTHENTICATION_FAILURE,
            source_ip=f'192.168.1.{(i % 254) + 1}',
            bytes_sent=1000 + i * 100,
            bytes_received=2000 + i * 50
        )
        anomaly = hunter.add_behavior_event(event)
        if anomaly:
            print(f"  [!] Anomali tespit edildi: {anomaly.anomaly_type} (skor: {anomaly.anomaly_score:.2f})")

    # Test hunt
    print("\n[TEST] APT Campaign Hunt baslatiliyor...")

    test_data = {
        'dns_queries': [
            {'query_name': 'test.apt29-c2.com', 'source_ip': '10.0.0.50'},
            {'query_name': 'normal.google.com', 'source_ip': '10.0.0.51'}
        ],
        'logs': [
            {'destination_ip': '185.141.63.100', 'source_ip': '10.0.0.50'},
            {'user_agent': 'Mozilla/5.0 (APT)', 'source_ip': '10.0.0.52'}
        ]
    }

    result = hunter.start_hunt('apt_campaign', test_data)
    print(f"  Hunt durumu: {result.status.value}")
    print(f"  Bulgu sayisi: {len(result.findings)}")
    print(f"  Ciddiyet: {result.severity.value}")

    # Istatistikler
    print("\n[TEST] Istatistikler:")
    stats = hunter.get_statistics()
    for key, value in stats.items():
        if key != 'mitre_coverage':
            print(f"  {key}: {value}")

    print("\n[TEST] MITRE ATT&CK Kapsama:")
    coverage = stats['mitre_coverage']
    print(f"  Tespit edilen teknik sayisi: {coverage['technique_count']}")
    print(f"  Kapsama orani: {coverage['coverage_percentage']:.1f}%")
    print(f"  Kapsamadaki bosluklar: {coverage['coverage_gaps']}")

    print("\n" + "=" * 60)
    print("Test tamamlandi!")
    print("=" * 60)
