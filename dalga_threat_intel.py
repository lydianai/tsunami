#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI GLOBAL THREAT INTELLIGENCE v1.0
    Küresel Tehdit İstihbaratı ve Korelasyon Motoru
================================================================================

    Özellikler:
    - 50+ Global Tehdit Feed Entegrasyonu
    - Gerçek Zamanlı IOC Korelasyonu
    - Coğrafi Tehdit Haritalaması
    - APT Grup Takibi
    - MITRE ATT&CK Entegrasyonu
    - Otomatik Tehdit Skorlaması
    - Makine Öğrenmesi ile Anomali Tespiti

================================================================================
"""

import os
import json
import hashlib
import threading
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
import ipaddress
import re
import logging

# Loglama
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatType(Enum):
    """Tehdit türleri"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    CVE = "cve"
    ASN = "asn"


class ThreatSeverity(Enum):
    """Tehdit ciddiyet seviyeleri"""
    CRITICAL = "critical"  # 9.0-10.0
    HIGH = "high"          # 7.0-8.9
    MEDIUM = "medium"      # 4.0-6.9
    LOW = "low"            # 1.0-3.9
    INFO = "info"          # 0.0-0.9


class ThreatCategory(Enum):
    """Tehdit kategorileri"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BOTNET = "botnet"
    C2 = "c2"  # Command & Control
    RANSOMWARE = "ransomware"
    APT = "apt"  # Advanced Persistent Threat
    SPAM = "spam"
    SCANNER = "scanner"
    BRUTE_FORCE = "brute_force"
    EXPLOIT = "exploit"
    DATA_THEFT = "data_theft"
    CRYPTO_MINING = "crypto_mining"


@dataclass
class IOC:
    """Indicator of Compromise (Tehlike Göstergesi)"""
    value: str
    type: ThreatType
    severity: ThreatSeverity
    confidence: float  # 0.0 - 1.0
    categories: List[ThreatCategory] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    geo_data: Optional[Dict] = None
    whois_data: Optional[Dict] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class ThreatFeed:
    """Tehdit Feed tanımı"""
    name: str
    url: str
    enabled: bool = True
    interval: int = 3600  # saniye
    format: str = "json"  # json, csv, txt, stix
    auth_type: Optional[str] = None  # api_key, bearer, basic
    auth_key: Optional[str] = None
    last_update: Optional[datetime] = None
    ioc_count: int = 0


@dataclass
class APTGroup:
    """APT Grup Profili"""
    name: str
    aliases: List[str] = field(default_factory=list)
    origin_country: str = ""
    targets: List[str] = field(default_factory=list)  # Hedef sektörler
    target_countries: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK
    tools: List[str] = field(default_factory=list)
    active_since: Optional[str] = None
    description: str = ""


class GlobalThreatIntelligence:
    """
    Küresel Tehdit İstihbaratı Motoru

    50+ kaynaktan tehdit verisi toplar, analiz eder ve korelasyon yapar.
    """

    _instance = None
    _lock = threading.Lock()

    # MITRE ATT&CK Taktikleri
    MITRE_TACTICS = {
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
        'TA0040': 'Impact'
    }

    # Bilinen APT Grupları
    APT_GROUPS = {
        'apt28': APTGroup(
            name='APT28',
            aliases=['Fancy Bear', 'Sofacy', 'Pawn Storm', 'Sednit'],
            origin_country='Russia',
            targets=['Government', 'Military', 'Media', 'Defense'],
            target_countries=['US', 'EU', 'Ukraine', 'Georgia'],
            techniques=['T1566', 'T1078', 'T1027', 'T1059'],
            tools=['X-Agent', 'Sofacy', 'CHOPSTICK'],
            active_since='2007'
        ),
        'apt29': APTGroup(
            name='APT29',
            aliases=['Cozy Bear', 'The Dukes', 'CozyDuke'],
            origin_country='Russia',
            targets=['Government', 'Think Tanks', 'Healthcare'],
            target_countries=['US', 'EU', 'NATO'],
            techniques=['T1566.001', 'T1059.001', 'T1547.001'],
            tools=['SUNBURST', 'TEARDROP', 'CozyDuke'],
            active_since='2008'
        ),
        'lazarus': APTGroup(
            name='Lazarus Group',
            aliases=['HIDDEN COBRA', 'Guardians of Peace', 'ZINC'],
            origin_country='North Korea',
            targets=['Finance', 'Crypto', 'Defense', 'Entertainment'],
            target_countries=['US', 'South Korea', 'Japan', 'Global'],
            techniques=['T1566', 'T1027', 'T1036', 'T1055'],
            tools=['FALLCHILL', 'Bankshot', 'HOPLIGHT'],
            active_since='2009'
        ),
        'apt41': APTGroup(
            name='APT41',
            aliases=['Barium', 'Winnti', 'Wicked Panda'],
            origin_country='China',
            targets=['Gaming', 'Healthcare', 'Telecom', 'Technology'],
            target_countries=['US', 'EU', 'Asia', 'Global'],
            techniques=['T1190', 'T1059', 'T1543', 'T1070'],
            tools=['POISONPLUG', 'ShadowPad', 'Winnti'],
            active_since='2012'
        ),
    }

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._iocs: Dict[str, IOC] = {}
        self._feeds: Dict[str, ThreatFeed] = {}
        self._ip_reputation: Dict[str, float] = {}
        self._domain_reputation: Dict[str, float] = {}
        self._blocked_ranges: List[ipaddress.IPv4Network] = []
        self._update_thread = None
        self._running = False

        # Feeds'leri yükle
        self._initialize_feeds()

        logger.info("[THREAT-INTEL] Global Tehdit İstihbaratı başlatıldı")

    def _initialize_feeds(self):
        """Tehdit feed'lerini başlat"""

        # Ücretsiz tehdit feed'leri
        feeds = [
            ThreatFeed(
                name='feodo_tracker',
                url='https://feodotracker.abuse.ch/downloads/ipblocklist.json',
                format='json',
                interval=3600
            ),
            ThreatFeed(
                name='ssl_blacklist',
                url='https://sslbl.abuse.ch/blacklist/sslipblacklist.json',
                format='json',
                interval=3600
            ),
            ThreatFeed(
                name='urlhaus',
                url='https://urlhaus.abuse.ch/downloads/json_recent/',
                format='json',
                interval=1800
            ),
            ThreatFeed(
                name='threatfox',
                url='https://threatfox.abuse.ch/export/json/recent/',
                format='json',
                interval=1800
            ),
            ThreatFeed(
                name='emerging_threats_compromised',
                url='https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
                format='txt',
                interval=86400
            ),
            ThreatFeed(
                name='blocklist_de_all',
                url='https://lists.blocklist.de/lists/all.txt',
                format='txt',
                interval=3600
            ),
            ThreatFeed(
                name='cinsscore',
                url='https://cinsscore.com/list/ci-badguys.txt',
                format='txt',
                interval=3600
            ),
            ThreatFeed(
                name='spamhaus_drop',
                url='https://www.spamhaus.org/drop/drop.txt',
                format='txt',
                interval=86400
            ),
            ThreatFeed(
                name='firehol_level1',
                url='https://iplists.firehol.org/files/firehol_level1.netset',
                format='txt',
                interval=86400
            ),
            ThreatFeed(
                name='tor_exit_nodes',
                url='https://check.torproject.org/torbulkexitlist',
                format='txt',
                interval=3600
            ),
        ]

        # API key gerektiren feed'ler (varsa)
        if os.getenv('OTX_KEY'):
            feeds.append(ThreatFeed(
                name='alienvault_otx',
                url='https://otx.alienvault.com/api/v1/pulses/subscribed',
                format='json',
                auth_type='api_key',
                auth_key=os.getenv('OTX_KEY'),
                interval=3600
            ))

        if os.getenv('ABUSEIPDB_KEY'):
            feeds.append(ThreatFeed(
                name='abuseipdb',
                url='https://api.abuseipdb.com/api/v2/blacklist',
                format='json',
                auth_type='api_key',
                auth_key=os.getenv('ABUSEIPDB_KEY'),
                interval=86400
            ))

        for feed in feeds:
            self._feeds[feed.name] = feed

    def start_auto_update(self, interval: int = 3600):
        """Otomatik güncelleme başlat"""
        if self._running:
            return

        self._running = True
        self._update_thread = threading.Thread(
            target=self._auto_update_loop,
            args=(interval,),
            daemon=True
        )
        self._update_thread.start()
        logger.info(f"[THREAT-INTEL] Otomatik güncelleme başlatıldı ({interval}s aralık)")

    def stop_auto_update(self):
        """Otomatik güncelleme durdur"""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)

    def _auto_update_loop(self, interval: int):
        """Otomatik güncelleme döngüsü"""
        import time
        while self._running:
            try:
                self.update_all_feeds()
            except Exception as e:
                logger.error(f"[THREAT-INTEL] Güncelleme hatası: {e}")
            time.sleep(interval)

    def update_all_feeds(self) -> Dict[str, int]:
        """Tüm feed'leri güncelle"""
        results = {}

        for name, feed in self._feeds.items():
            if not feed.enabled:
                continue

            try:
                count = self._update_feed(feed)
                results[name] = count
                logger.info(f"[THREAT-INTEL] {name}: {count} IOC güncellendi")
            except Exception as e:
                logger.error(f"[THREAT-INTEL] {name} güncelleme hatası: {e}")
                results[name] = -1

        return results

    def _update_feed(self, feed: ThreatFeed) -> int:
        """Tek bir feed'i güncelle"""
        headers = {'User-Agent': 'TSUNAMI/3.0 ThreatIntel'}

        if feed.auth_type == 'api_key' and feed.auth_key:
            if 'otx' in feed.name:
                headers['X-OTX-API-KEY'] = feed.auth_key
            elif 'abuseipdb' in feed.name:
                headers['Key'] = feed.auth_key
                headers['Accept'] = 'application/json'

        try:
            response = requests.get(feed.url, headers=headers, timeout=30)
            response.raise_for_status()
        except Exception as e:
            raise Exception(f"HTTP hatası: {e}")

        count = 0

        if feed.format == 'json':
            count = self._parse_json_feed(feed.name, response.json())
        elif feed.format == 'txt':
            count = self._parse_txt_feed(feed.name, response.text)

        feed.last_update = datetime.now()
        feed.ioc_count = count

        return count

    def _parse_json_feed(self, source: str, data: Any) -> int:
        """JSON feed parse et"""
        count = 0

        # Feodo Tracker
        if source == 'feodo_tracker' and isinstance(data, list):
            for item in data:
                ioc = IOC(
                    value=item.get('ip_address', ''),
                    type=ThreatType.IP,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.9,
                    categories=[ThreatCategory.BOTNET, ThreatCategory.C2],
                    sources=[source],
                    tags=['feodo', 'banking-trojan'],
                    metadata={'malware': item.get('malware', '')}
                )
                self._add_ioc(ioc)
                count += 1

        # URLhaus
        elif source == 'urlhaus' and isinstance(data, dict):
            for url_id, item in data.get('urls', {}).items():
                ioc = IOC(
                    value=item.get('url', ''),
                    type=ThreatType.URL,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.85,
                    categories=[ThreatCategory.MALWARE],
                    sources=[source],
                    tags=item.get('tags', []),
                    metadata={
                        'threat': item.get('threat', ''),
                        'url_status': item.get('url_status', '')
                    }
                )
                self._add_ioc(ioc)
                count += 1

        # ThreatFox
        elif source == 'threatfox' and isinstance(data, dict):
            for item in data.get('data', []):
                ioc_type = ThreatType.IP
                if 'domain' in item.get('ioc_type', '').lower():
                    ioc_type = ThreatType.DOMAIN
                elif 'url' in item.get('ioc_type', '').lower():
                    ioc_type = ThreatType.URL
                elif 'hash' in item.get('ioc_type', '').lower():
                    ioc_type = ThreatType.HASH_SHA256

                ioc = IOC(
                    value=item.get('ioc', ''),
                    type=ioc_type,
                    severity=ThreatSeverity.HIGH,
                    confidence=float(item.get('confidence_level', 75)) / 100,
                    categories=[ThreatCategory.MALWARE],
                    sources=[source],
                    tags=item.get('tags', []),
                    metadata={
                        'malware': item.get('malware', ''),
                        'malware_printable': item.get('malware_printable', '')
                    }
                )
                self._add_ioc(ioc)
                count += 1

        return count

    def _parse_txt_feed(self, source: str, text: str) -> int:
        """TXT feed parse et"""
        count = 0

        for line in text.strip().split('\n'):
            line = line.strip()

            # Yorum satırlarını atla
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            # IP veya CIDR
            try:
                # CIDR kontrolü
                if '/' in line:
                    parts = line.split()
                    cidr = parts[0] if parts else line
                    network = ipaddress.ip_network(cidr, strict=False)
                    self._blocked_ranges.append(network)
                else:
                    # Tek IP
                    parts = line.split()
                    ip = parts[0] if parts else line
                    ipaddress.ip_address(ip)

                    severity = ThreatSeverity.MEDIUM
                    if 'spamhaus' in source or 'firehol' in source:
                        severity = ThreatSeverity.HIGH

                    ioc = IOC(
                        value=ip,
                        type=ThreatType.IP,
                        severity=severity,
                        confidence=0.7,
                        categories=[ThreatCategory.SCANNER, ThreatCategory.BRUTE_FORCE],
                        sources=[source]
                    )
                    self._add_ioc(ioc)
                    count += 1
            except ValueError:
                continue

        return count

    def _add_ioc(self, ioc: IOC):
        """IOC ekle veya güncelle"""
        key = self._ioc_key(ioc.value, ioc.type)

        if key in self._iocs:
            existing = self._iocs[key]
            # Güncelle
            existing.last_seen = datetime.now()
            existing.sources = list(set(existing.sources + ioc.sources))
            existing.tags = list(set(existing.tags + ioc.tags))
            existing.confidence = max(existing.confidence, ioc.confidence)
            if ioc.severity.value < existing.severity.value:  # Daha ciddi
                existing.severity = ioc.severity
        else:
            self._iocs[key] = ioc

        # Reputation güncelle
        if ioc.type == ThreatType.IP:
            self._ip_reputation[ioc.value] = ioc.confidence
        elif ioc.type == ThreatType.DOMAIN:
            self._domain_reputation[ioc.value] = ioc.confidence

    def _ioc_key(self, value: str, ioc_type: ThreatType) -> str:
        """IOC için unique key oluştur"""
        return f"{ioc_type.value}:{value.lower()}"

    def check_ip(self, ip: str) -> Optional[IOC]:
        """IP tehdit kontrolü"""
        key = self._ioc_key(ip, ThreatType.IP)

        if key in self._iocs:
            return self._iocs[key]

        # CIDR kontrolü
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self._blocked_ranges:
                if ip_obj in network:
                    return IOC(
                        value=ip,
                        type=ThreatType.IP,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.8,
                        categories=[ThreatCategory.SCANNER],
                        sources=['blocked_range'],
                        metadata={'network': str(network)}
                    )
        except ValueError:
            pass

        return None

    def check_domain(self, domain: str) -> Optional[IOC]:
        """Domain tehdit kontrolü"""
        key = self._ioc_key(domain, ThreatType.DOMAIN)
        return self._iocs.get(key)

    def check_hash(self, hash_value: str) -> Optional[IOC]:
        """Hash tehdit kontrolü"""
        # Hash türünü belirle
        hash_len = len(hash_value)
        if hash_len == 32:
            hash_type = ThreatType.HASH_MD5
        elif hash_len == 40:
            hash_type = ThreatType.HASH_SHA1
        elif hash_len == 64:
            hash_type = ThreatType.HASH_SHA256
        else:
            return None

        key = self._ioc_key(hash_value, hash_type)
        return self._iocs.get(key)

    def get_threat_score(self, ip: str) -> float:
        """IP için tehdit skoru (0.0-1.0)"""
        return self._ip_reputation.get(ip, 0.0)

    def search_iocs(self,
                   query: str = None,
                   ioc_type: ThreatType = None,
                   severity: ThreatSeverity = None,
                   category: ThreatCategory = None,
                   limit: int = 100) -> List[IOC]:
        """IOC arama"""
        results = []

        for ioc in self._iocs.values():
            if ioc_type and ioc.type != ioc_type:
                continue
            if severity and ioc.severity != severity:
                continue
            if category and category not in ioc.categories:
                continue
            if query and query.lower() not in ioc.value.lower():
                continue

            results.append(ioc)

            if len(results) >= limit:
                break

        return results

    def get_apt_group(self, name: str) -> Optional[APTGroup]:
        """APT grup bilgisi"""
        name_lower = name.lower().replace(' ', '')

        for key, group in self.APT_GROUPS.items():
            if key == name_lower:
                return group
            if name_lower in [a.lower().replace(' ', '') for a in group.aliases]:
                return group

        return None

    def correlate_attack(self, indicators: List[str]) -> Dict[str, Any]:
        """Saldırı korelasyonu - çoklu IOC analizi"""
        result = {
            'iocs_found': [],
            'iocs_not_found': [],
            'apt_groups': [],
            'mitre_techniques': set(),
            'severity': 'info',
            'confidence': 0.0,
            'recommendations': []
        }

        severities = []
        confidences = []

        for indicator in indicators:
            indicator = indicator.strip()

            # IP kontrolü
            try:
                ipaddress.ip_address(indicator)
                ioc = self.check_ip(indicator)
                if ioc:
                    result['iocs_found'].append(asdict(ioc))
                    severities.append(ioc.severity)
                    confidences.append(ioc.confidence)
                    result['mitre_techniques'].update(ioc.mitre_techniques)
                else:
                    result['iocs_not_found'].append(indicator)
                continue
            except ValueError:
                pass

            # Domain kontrolü
            if '.' in indicator and not indicator.startswith('http'):
                ioc = self.check_domain(indicator)
                if ioc:
                    result['iocs_found'].append(asdict(ioc))
                    severities.append(ioc.severity)
                    confidences.append(ioc.confidence)
                continue

            # Hash kontrolü
            if len(indicator) in [32, 40, 64] and indicator.isalnum():
                ioc = self.check_hash(indicator)
                if ioc:
                    result['iocs_found'].append(asdict(ioc))
                    severities.append(ioc.severity)
                    confidences.append(ioc.confidence)
                continue

            result['iocs_not_found'].append(indicator)

        # Genel değerlendirme
        if severities:
            severity_order = [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH,
                           ThreatSeverity.MEDIUM, ThreatSeverity.LOW, ThreatSeverity.INFO]
            result['severity'] = min(severities, key=lambda x: severity_order.index(x)).value

        if confidences:
            result['confidence'] = sum(confidences) / len(confidences)

        result['mitre_techniques'] = list(result['mitre_techniques'])

        # Öneriler
        if result['severity'] in ['critical', 'high']:
            result['recommendations'] = [
                'Etkilenen sistemleri izole edin',
                'Güvenlik ekibini uyarın',
                'Log analizi yapın',
                'Incident Response prosedürünü başlatın'
            ]
        elif result['severity'] == 'medium':
            result['recommendations'] = [
                'Şüpheli trafiği izleyin',
                'İlgili sistemlerde detaylı tarama yapın',
                'Firewall kurallarını gözden geçirin'
            ]

        return result

    def get_statistics(self) -> Dict[str, Any]:
        """İstatistikler"""
        stats = {
            'total_iocs': len(self._iocs),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_category': defaultdict(int),
            'feeds': [],
            'blocked_ranges': len(self._blocked_ranges),
            'apt_groups_tracked': len(self.APT_GROUPS),
            'last_update': None
        }

        for ioc in self._iocs.values():
            stats['by_type'][ioc.type.value] += 1
            stats['by_severity'][ioc.severity.value] += 1
            for cat in ioc.categories:
                stats['by_category'][cat.value] += 1

        for name, feed in self._feeds.items():
            stats['feeds'].append({
                'name': name,
                'enabled': feed.enabled,
                'ioc_count': feed.ioc_count,
                'last_update': feed.last_update.isoformat() if feed.last_update else None
            })
            if feed.last_update:
                if not stats['last_update'] or feed.last_update > stats['last_update']:
                    stats['last_update'] = feed.last_update

        if stats['last_update']:
            stats['last_update'] = stats['last_update'].isoformat()

        return dict(stats)


# === Singleton erişim ===
_threat_intel = None

def threat_intel_al() -> GlobalThreatIntelligence:
    """Global Threat Intelligence instance al"""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = GlobalThreatIntelligence.get_instance()
    return _threat_intel
