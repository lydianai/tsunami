#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI DNS SINKHOLE v1.0
    DNS Kara Delik ve C2 Kesinti Modulu
================================================================================

    Ozellikler:
    - Zararli Domain Kara Liste Yonetimi
    - Gercek Zamanli IOC Feed Entegrasyonu (abuse.ch, OpenPhish, vb.)
    - Sinkhole Sunucu Islevseligi
    - dnsmasq/Pi-hole/Custom DNS Entegrasyonu
    - C2 (Command & Control) Kesinti Yetenekleri
    - DGA (Domain Generation Algorithm) Tespiti
    - Fast-flux ve Beaconing Analizi
    - Enfekte Cihaz Tespiti
    - Adli Analiz icin Detayli Loglama

================================================================================
"""

import os
import re
import json
import sqlite3
import socket
import threading
import hashlib
import logging
import struct
import time
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, Counter
from pathlib import Path
import ipaddress
import urllib.request
import urllib.parse
import ssl

# Flask entegrasyonu
try:
    from flask import Blueprint, request, jsonify, current_app
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Loglama
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==================== YAPILANDIRMA ====================

SINKHOLE_HOME = Path.home() / ".dalga" / "sinkhole"
SINKHOLE_DB = SINKHOLE_HOME / "sinkhole.db"
SINKHOLE_LOGS = SINKHOLE_HOME / "logs"
SINKHOLE_FEEDS = SINKHOLE_HOME / "feeds"
SINKHOLE_BLOCKLIST = SINKHOLE_HOME / "blocklist.txt"

# Varsayilan sinkhole IP adresleri
DEFAULT_SINKHOLE_IPV4 = "127.0.0.1"
DEFAULT_SINKHOLE_IPV6 = "::1"


# ==================== ENUM'LAR ====================

class ThreatType(Enum):
    """Tehdit turleri"""
    MALWARE = "malware"
    PHISHING = "phishing"
    C2 = "c2"  # Command & Control
    BOTNET = "botnet"
    RANSOMWARE = "ransomware"
    CRYPTOMINER = "cryptominer"
    DGA = "dga"
    FAST_FLUX = "fast_flux"
    SPAM = "spam"
    ADWARE = "adware"
    UNKNOWN = "unknown"


class FeedSource(Enum):
    """IOC kaynaklari"""
    ABUSE_CH = "abuse.ch"
    OPENPHISH = "openphish"
    URLHAUS = "urlhaus"
    THREATFOX = "threatfox"
    PHISHTANK = "phishtank"
    MALWARE_BAZAAR = "malware_bazaar"
    FEODO_TRACKER = "feodo_tracker"
    SSL_BLACKLIST = "ssl_blacklist"
    SPAMHAUS = "spamhaus"
    MANUAL = "manual"
    CUSTOM = "custom"


class BlockStatus(Enum):
    """Engelleme durumu"""
    ACTIVE = "active"
    EXPIRED = "expired"
    WHITELISTED = "whitelisted"
    PENDING = "pending"


# ==================== VERİ SINIFLARI ====================

@dataclass
class BlockedDomain:
    """Engellenen domain kaydi"""
    domain: str
    threat_type: ThreatType
    source: FeedSource
    confidence: float  # 0.0 - 1.0
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    hit_count: int = 0
    status: BlockStatus = BlockStatus.ACTIVE
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    expires_at: Optional[datetime] = None


@dataclass
class SinkholeHit:
    """Sinkhole erisim kaydi"""
    timestamp: datetime
    source_ip: str
    requested_domain: str
    query_type: str  # A, AAAA, CNAME, etc.
    threat_type: ThreatType
    device_info: Dict = field(default_factory=dict)
    response_given: str = ""
    blocked: bool = True


@dataclass
class InfectedDevice:
    """Enfekte cihaz kaydi"""
    ip_address: str
    first_detected: datetime
    last_activity: datetime
    hit_count: int = 0
    unique_domains: Set[str] = field(default_factory=set)
    threat_types: Set[ThreatType] = field(default_factory=set)
    risk_score: float = 0.0
    device_info: Dict = field(default_factory=dict)
    quarantined: bool = False


@dataclass
class BeaconingPattern:
    """Beacon deseni analizi"""
    source_ip: str
    domain: str
    intervals: List[float] = field(default_factory=list)  # saniye
    regularity_score: float = 0.0  # 0.0 - 1.0 (1.0 = cok duzenli)
    is_beaconing: bool = False
    jitter: float = 0.0  # ortalamadan sapma yüzdesi
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)


@dataclass
class ThreatFeed:
    """Tehdit feed tanimi"""
    name: str
    url: str
    source: FeedSource
    enabled: bool = True
    interval: int = 3600  # saniye
    format: str = "txt"  # txt, json, csv
    last_update: Optional[datetime] = None
    domain_count: int = 0
    auth_key: Optional[str] = None


# ==================== DGA TESPİTİ ====================

class DGADetector:
    """
    Domain Generation Algorithm (DGA) tespit motoru

    Makine ogrenmesi ve istatistiksel yontemler kullanarak
    algoritmik olarak uretilmis domainleri tespit eder.
    """

    # Turkce ve Ingilizce yaygin n-gramlar
    COMMON_NGRAMS = {
        'th', 'he', 'in', 'er', 'an', 'on', 'en', 'at', 'es', 'ed',
        'or', 'te', 'ti', 'is', 'it', 'ar', 'al', 'le', 'co', 'de',
        'ra', 'ro', 're', 'ri', 'io', 'ou', 'ea', 'ni', 'ce', 'il',
        've', 'ne', 'me', 'nd', 'se', 'ng', 'nt', 'ma', 'st', 'ta',
        # Turkce
        'la', 'li', 'le', 'da', 'de', 'di', 'bi', 'bu', 'be', 'ka',
        'ke', 'ki', 'sa', 'si', 'se', 'ya', 'ye', 'yi', 'ba', 'bo'
    }

    # Bilinen DGA aileleri pattern'leri
    DGA_PATTERNS = {
        'necurs': r'^[a-z]{6,12}$',
        'cryptolocker': r'^[a-z]{12,18}$',
        'conficker': r'^[a-z]{5,8}\.(biz|info|com|net|org|ws)$',
        'pykspa': r'^[a-z]{7,14}\.(com|net|org|biz)$',
        'qakbot': r'^[a-z0-9]{8,15}$',
    }

    # Sesli harf oranlari (normal: ~0.38)
    VOWELS = set('aeiou')

    def __init__(self):
        self._compiled_patterns = {
            name: re.compile(pattern, re.IGNORECASE)
            for name, pattern in self.DGA_PATTERNS.items()
        }

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """
        Domain'i DGA acisından analiz et

        Returns:
            {
                'is_dga': bool,
                'confidence': float,
                'features': dict,
                'matched_family': str or None
            }
        """
        # Sadece domain adini al (TLD'yi cikar)
        parts = domain.lower().split('.')
        if len(parts) > 1:
            name = parts[0]
        else:
            name = domain.lower()

        # Ozellik cikarimi
        features = self._extract_features(name)

        # DGA skoru hesapla
        dga_score = self._calculate_dga_score(features)

        # Pattern eslestirme
        matched_family = self._match_dga_family(domain)

        # Karar
        is_dga = dga_score > 0.7 or matched_family is not None

        return {
            'is_dga': is_dga,
            'confidence': dga_score,
            'features': features,
            'matched_family': matched_family
        }

    def _extract_features(self, name: str) -> Dict[str, float]:
        """Domain adından ozellik cikar"""
        if not name:
            return {}

        length = len(name)

        # Sesli harf orani
        vowel_count = sum(1 for c in name if c in self.VOWELS)
        vowel_ratio = vowel_count / length if length > 0 else 0

        # Rakam orani
        digit_count = sum(1 for c in name if c.isdigit())
        digit_ratio = digit_count / length if length > 0 else 0

        # Entropi (rastgelelik olcusu)
        entropy = self._calculate_entropy(name)

        # Bigram skoru (anlamli dil benzerligi)
        bigram_score = self._calculate_bigram_score(name)

        # Ardisik ussuz harf sayisi
        consonant_streaks = self._max_consonant_streak(name)

        # Tekrarlayan karakter orani
        repeat_ratio = 1 - len(set(name)) / length if length > 0 else 0

        return {
            'length': length,
            'vowel_ratio': vowel_ratio,
            'digit_ratio': digit_ratio,
            'entropy': entropy,
            'bigram_score': bigram_score,
            'consonant_streak': consonant_streaks,
            'repeat_ratio': repeat_ratio
        }

    def _calculate_entropy(self, s: str) -> float:
        """Shannon entropisi hesapla"""
        if not s:
            return 0.0

        prob = [float(s.count(c)) / len(s) for c in set(s)]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)

        # Normalize (max entropy = log2(len(s)))
        max_entropy = math.log2(len(s)) if len(s) > 1 else 1
        return entropy / max_entropy if max_entropy > 0 else 0

    def _calculate_bigram_score(self, name: str) -> float:
        """Yaygin bigram skoru"""
        if len(name) < 2:
            return 0.0

        bigrams = [name[i:i+2] for i in range(len(name)-1)]
        common_count = sum(1 for bg in bigrams if bg in self.COMMON_NGRAMS)

        return common_count / len(bigrams) if bigrams else 0

    def _max_consonant_streak(self, name: str) -> int:
        """En uzun ussuz harf serisi"""
        max_streak = 0
        current_streak = 0

        for c in name:
            if c.isalpha() and c not in self.VOWELS:
                current_streak += 1
                max_streak = max(max_streak, current_streak)
            else:
                current_streak = 0

        return max_streak

    def _calculate_dga_score(self, features: Dict[str, float]) -> float:
        """DGA olasilik skoru hesapla"""
        if not features:
            return 0.0

        score = 0.0

        # Uzunluk (8-15 arası DGA icin tipik)
        length = features.get('length', 0)
        if 8 <= length <= 15:
            score += 0.2
        elif length > 20:
            score += 0.1

        # Yuksek entropi (> 0.7 supheli)
        entropy = features.get('entropy', 0)
        if entropy > 0.8:
            score += 0.3
        elif entropy > 0.7:
            score += 0.2

        # Dusuk bigram skoru (< 0.2 supheli)
        bigram = features.get('bigram_score', 1)
        if bigram < 0.1:
            score += 0.3
        elif bigram < 0.2:
            score += 0.2

        # Anormal sesli harf orani
        vowel = features.get('vowel_ratio', 0.38)
        if vowel < 0.15 or vowel > 0.6:
            score += 0.15

        # Rakam iceriyorsa
        if features.get('digit_ratio', 0) > 0.3:
            score += 0.15

        # Uzun ussuz harf serisi (> 5)
        if features.get('consonant_streak', 0) > 5:
            score += 0.2

        return min(1.0, score)

    def _match_dga_family(self, domain: str) -> Optional[str]:
        """Bilinen DGA ailesiyle eslesme kontrolu"""
        for family, pattern in self._compiled_patterns.items():
            if pattern.match(domain):
                return family
        return None


# ==================== FAST-FLUX TESPİTİ ====================

class FastFluxDetector:
    """
    Fast-flux tespit motoru

    Hizli degisen DNS kayitlarini ve botnet altyapilarini tespit eder.
    """

    # Esik degerler
    TTL_THRESHOLD = 300  # 5 dakikadan kisa TTL
    IP_CHANGE_THRESHOLD = 5  # Kisa surede 5+ farkli IP
    TIME_WINDOW = 3600  # 1 saat

    def __init__(self):
        self._dns_history: Dict[str, List[Tuple[datetime, str, int]]] = defaultdict(list)
        self._lock = threading.Lock()

    def record_dns_response(self, domain: str, ip: str, ttl: int):
        """DNS yaniti kaydet"""
        with self._lock:
            self._dns_history[domain].append((datetime.now(), ip, ttl))

            # Eski kayitlari temizle (24 saat)
            cutoff = datetime.now() - timedelta(hours=24)
            self._dns_history[domain] = [
                r for r in self._dns_history[domain]
                if r[0] > cutoff
            ]

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Domain'i fast-flux acisından analiz et"""
        with self._lock:
            history = self._dns_history.get(domain, [])

        if len(history) < 3:
            return {
                'is_fast_flux': False,
                'confidence': 0.0,
                'reason': 'Yetersiz veri'
            }

        # Son TIME_WINDOW icindeki kayitlar
        cutoff = datetime.now() - timedelta(seconds=self.TIME_WINDOW)
        recent = [r for r in history if r[0] > cutoff]

        if len(recent) < 2:
            return {
                'is_fast_flux': False,
                'confidence': 0.0,
                'reason': 'Son saatte yetersiz kayit'
            }

        # Benzersiz IP sayisi
        unique_ips = set(r[1] for r in recent)
        ip_count = len(unique_ips)

        # Ortalama TTL
        avg_ttl = sum(r[2] for r in recent) / len(recent)

        # Degisim sikligi
        changes = sum(1 for i in range(1, len(recent)) if recent[i][1] != recent[i-1][1])
        change_rate = changes / len(recent) if len(recent) > 1 else 0

        # Fast-flux skoru
        score = 0.0
        reasons = []

        if ip_count >= self.IP_CHANGE_THRESHOLD:
            score += 0.4
            reasons.append(f'{ip_count} farkli IP')

        if avg_ttl < self.TTL_THRESHOLD:
            score += 0.3
            reasons.append(f'Dusuk TTL ({avg_ttl:.0f}s)')

        if change_rate > 0.5:
            score += 0.3
            reasons.append(f'Yuksek degisim orani ({change_rate:.2f})')

        is_fast_flux = score >= 0.6

        return {
            'is_fast_flux': is_fast_flux,
            'confidence': score,
            'unique_ips': ip_count,
            'avg_ttl': avg_ttl,
            'change_rate': change_rate,
            'reasons': reasons
        }


# ==================== BEACONING ANALİZİ ====================

class BeaconingAnalyzer:
    """
    C2 beacon deseni analiz motoru

    Duzenli aralıklarla yapilan C2 iletisimini tespit eder.
    """

    # Esik degerler
    MIN_SAMPLES = 10
    REGULARITY_THRESHOLD = 0.8
    MAX_JITTER = 0.15  # %15 sapma

    def __init__(self):
        self._patterns: Dict[str, BeaconingPattern] = {}
        self._lock = threading.Lock()

    def record_access(self, source_ip: str, domain: str):
        """Erisim kaydet"""
        key = f"{source_ip}:{domain}"
        now = datetime.now()

        with self._lock:
            if key not in self._patterns:
                self._patterns[key] = BeaconingPattern(
                    source_ip=source_ip,
                    domain=domain,
                    first_seen=now,
                    last_seen=now
                )
            else:
                pattern = self._patterns[key]

                # Interval hesapla
                if pattern.last_seen:
                    interval = (now - pattern.last_seen).total_seconds()
                    if interval > 0:
                        pattern.intervals.append(interval)

                        # Son 100 interval'i tut
                        if len(pattern.intervals) > 100:
                            pattern.intervals = pattern.intervals[-100:]

                pattern.last_seen = now

    def analyze(self, source_ip: str, domain: str) -> Dict[str, Any]:
        """Beacon analizi yap"""
        key = f"{source_ip}:{domain}"

        with self._lock:
            pattern = self._patterns.get(key)

        if not pattern or len(pattern.intervals) < self.MIN_SAMPLES:
            return {
                'is_beaconing': False,
                'confidence': 0.0,
                'reason': 'Yetersiz ornek'
            }

        intervals = pattern.intervals

        # Ortalama ve standart sapma
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance) if variance > 0 else 0

        # Jitter (sapma yüzdesi)
        jitter = std_dev / mean_interval if mean_interval > 0 else 1.0

        # Duzenlilık skoru (dusuk jitter = yuksek duzenlilık)
        regularity = max(0, 1 - jitter)

        # Modal analiz (en sik interval)
        interval_bins = Counter(int(i / 10) * 10 for i in intervals)
        most_common_bin, most_common_count = interval_bins.most_common(1)[0]
        modal_ratio = most_common_count / len(intervals)

        # Beaconing tespiti
        is_beaconing = (
            regularity >= self.REGULARITY_THRESHOLD and
            jitter <= self.MAX_JITTER
        ) or modal_ratio > 0.7

        with self._lock:
            pattern.regularity_score = regularity
            pattern.jitter = jitter
            pattern.is_beaconing = is_beaconing

        return {
            'is_beaconing': is_beaconing,
            'confidence': regularity,
            'mean_interval': mean_interval,
            'jitter': jitter,
            'modal_interval': most_common_bin,
            'modal_ratio': modal_ratio,
            'sample_count': len(intervals)
        }

    def get_all_beaconing(self) -> List[BeaconingPattern]:
        """Tum beacon desenlerini getir"""
        with self._lock:
            return [p for p in self._patterns.values() if p.is_beaconing]


# ==================== VERİTABANI YÖNETİCİSİ ====================

class SinkholeDatabase:
    """SQLite veritabani yonetimi"""

    def __init__(self, db_path: Path = SINKHOLE_DB):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._create_tables()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _create_tables(self):
        """Veritabani tablolarini olustur"""
        cursor = self.conn.cursor()

        # Engellenen domainler tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                threat_type TEXT NOT NULL,
                source TEXT NOT NULL,
                confidence REAL DEFAULT 0.5,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active',
                tags TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}',
                expires_at TIMESTAMP
            )
        """)

        # Sinkhole hit loglari tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sinkhole_hits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                requested_domain TEXT NOT NULL,
                query_type TEXT DEFAULT 'A',
                threat_type TEXT,
                device_info TEXT DEFAULT '{}',
                response_given TEXT,
                blocked INTEGER DEFAULT 1
            )
        """)

        # Enfekte cihazlar tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS infected_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                first_detected TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count INTEGER DEFAULT 0,
                unique_domains TEXT DEFAULT '[]',
                threat_types TEXT DEFAULT '[]',
                risk_score REAL DEFAULT 0.0,
                device_info TEXT DEFAULT '{}',
                quarantined INTEGER DEFAULT 0
            )
        """)

        # Feed durumu tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                url TEXT NOT NULL,
                source TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                interval_seconds INTEGER DEFAULT 3600,
                last_update TIMESTAMP,
                domain_count INTEGER DEFAULT 0,
                last_error TEXT
            )
        """)

        # Whitelist tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                reason TEXT,
                added_by TEXT,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Indeksler
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_domain ON blocked_domains(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_status ON blocked_domains(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hits_timestamp ON sinkhole_hits(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hits_source_ip ON sinkhole_hits(source_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_hits_domain ON sinkhole_hits(requested_domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip ON infected_devices(ip_address)")

        self.conn.commit()

    # === Domain Islemleri ===

    def add_domain(self, domain: BlockedDomain) -> int:
        """Domain ekle veya guncelle"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO blocked_domains (
                    domain, threat_type, source, confidence,
                    first_seen, last_seen, hit_count, status, tags, metadata, expires_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    threat_type = excluded.threat_type,
                    source = excluded.source,
                    confidence = MAX(confidence, excluded.confidence),
                    last_seen = excluded.last_seen,
                    status = excluded.status
            """, (
                domain.domain.lower(),
                domain.threat_type.value,
                domain.source.value,
                domain.confidence,
                domain.first_seen.isoformat(),
                domain.last_seen.isoformat(),
                domain.hit_count,
                domain.status.value,
                json.dumps(domain.tags),
                json.dumps(domain.metadata),
                domain.expires_at.isoformat() if domain.expires_at else None
            ))
            self.conn.commit()
            return cursor.lastrowid

    def get_domain(self, domain: str) -> Optional[BlockedDomain]:
        """Domain bilgisi getir"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT * FROM blocked_domains WHERE domain = ? AND status = 'active'",
            (domain.lower(),)
        )
        row = cursor.fetchone()

        if row:
            return BlockedDomain(
                domain=row['domain'],
                threat_type=ThreatType(row['threat_type']),
                source=FeedSource(row['source']),
                confidence=row['confidence'],
                first_seen=datetime.fromisoformat(row['first_seen']),
                last_seen=datetime.fromisoformat(row['last_seen']),
                hit_count=row['hit_count'],
                status=BlockStatus(row['status']),
                tags=json.loads(row['tags']),
                metadata=json.loads(row['metadata']),
                expires_at=datetime.fromisoformat(row['expires_at']) if row['expires_at'] else None
            )
        return None

    def is_blocked(self, domain: str) -> bool:
        """Domain engelli mi?"""
        cursor = self.conn.cursor()

        # Whitelist kontrolu
        cursor.execute("SELECT 1 FROM whitelist WHERE domain = ?", (domain.lower(),))
        if cursor.fetchone():
            return False

        # Tam eslesme
        cursor.execute(
            "SELECT 1 FROM blocked_domains WHERE domain = ? AND status = 'active'",
            (domain.lower(),)
        )
        if cursor.fetchone():
            return True

        # Alt domain kontrolu (*.example.com)
        parts = domain.lower().split('.')
        for i in range(len(parts) - 1):
            parent = '.'.join(parts[i:])
            cursor.execute(
                "SELECT 1 FROM blocked_domains WHERE domain = ? AND status = 'active'",
                (parent,)
            )
            if cursor.fetchone():
                return True

        return False

    def remove_domain(self, domain: str) -> bool:
        """Domain kaldir"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute(
                "UPDATE blocked_domains SET status = 'expired' WHERE domain = ?",
                (domain.lower(),)
            )
            self.conn.commit()
            return cursor.rowcount > 0

    def get_all_domains(self, status: BlockStatus = BlockStatus.ACTIVE,
                       limit: int = 1000, offset: int = 0) -> List[BlockedDomain]:
        """Tum domainleri getir"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM blocked_domains
            WHERE status = ?
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
        """, (status.value, limit, offset))

        domains = []
        for row in cursor.fetchall():
            domains.append(BlockedDomain(
                domain=row['domain'],
                threat_type=ThreatType(row['threat_type']),
                source=FeedSource(row['source']),
                confidence=row['confidence'],
                first_seen=datetime.fromisoformat(row['first_seen']),
                last_seen=datetime.fromisoformat(row['last_seen']),
                hit_count=row['hit_count'],
                status=BlockStatus(row['status']),
                tags=json.loads(row['tags']),
                metadata=json.loads(row['metadata'])
            ))
        return domains

    def increment_hit_count(self, domain: str):
        """Hit sayisini artir"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                UPDATE blocked_domains
                SET hit_count = hit_count + 1, last_seen = ?
                WHERE domain = ?
            """, (datetime.now().isoformat(), domain.lower()))
            self.conn.commit()

    # === Hit Log Islemleri ===

    def log_hit(self, hit: SinkholeHit):
        """Sinkhole hit logla"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO sinkhole_hits (
                    timestamp, source_ip, requested_domain, query_type,
                    threat_type, device_info, response_given, blocked
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                hit.timestamp.isoformat(),
                hit.source_ip,
                hit.requested_domain,
                hit.query_type,
                hit.threat_type.value if hit.threat_type else None,
                json.dumps(hit.device_info),
                hit.response_given,
                1 if hit.blocked else 0
            ))
            self.conn.commit()

    def get_hits(self, source_ip: str = None, domain: str = None,
                since: datetime = None, limit: int = 100) -> List[Dict]:
        """Hit loglarini getir"""
        cursor = self.conn.cursor()

        query = "SELECT * FROM sinkhole_hits WHERE 1=1"
        params = []

        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)

        if domain:
            query += " AND requested_domain LIKE ?"
            params.append(f"%{domain}%")

        if since:
            query += " AND timestamp > ?"
            params.append(since.isoformat())

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        return [dict(row) for row in cursor.fetchall()]

    # === Enfekte Cihaz Islemleri ===

    def update_infected_device(self, ip: str, domain: str, threat_type: ThreatType):
        """Enfekte cihaz bilgisini guncelle"""
        with self._lock:
            cursor = self.conn.cursor()

            # Mevcut kaydi getir
            cursor.execute("SELECT * FROM infected_devices WHERE ip_address = ?", (ip,))
            row = cursor.fetchone()

            now = datetime.now().isoformat()

            if row:
                # Guncelle
                domains = set(json.loads(row['unique_domains']))
                domains.add(domain)

                types = set(json.loads(row['threat_types']))
                types.add(threat_type.value)

                hit_count = row['hit_count'] + 1

                # Risk skoru hesapla
                risk_score = min(1.0, len(domains) * 0.1 + len(types) * 0.15 + hit_count * 0.01)

                cursor.execute("""
                    UPDATE infected_devices SET
                        last_activity = ?,
                        hit_count = ?,
                        unique_domains = ?,
                        threat_types = ?,
                        risk_score = ?
                    WHERE ip_address = ?
                """, (
                    now,
                    hit_count,
                    json.dumps(list(domains)),
                    json.dumps(list(types)),
                    risk_score,
                    ip
                ))
            else:
                # Yeni kayit
                cursor.execute("""
                    INSERT INTO infected_devices (
                        ip_address, first_detected, last_activity,
                        hit_count, unique_domains, threat_types, risk_score
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip, now, now, 1,
                    json.dumps([domain]),
                    json.dumps([threat_type.value]),
                    0.1
                ))

            self.conn.commit()

    def get_infected_devices(self, min_risk: float = 0.0,
                            limit: int = 100) -> List[Dict]:
        """Enfekte cihazlari getir"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM infected_devices
            WHERE risk_score >= ?
            ORDER BY risk_score DESC
            LIMIT ?
        """, (min_risk, limit))

        return [dict(row) for row in cursor.fetchall()]

    # === Whitelist Islemleri ===

    def add_whitelist(self, domain: str, reason: str = None, added_by: str = None):
        """Whitelist'e domain ekle"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO whitelist (domain, reason, added_by)
                VALUES (?, ?, ?)
            """, (domain.lower(), reason, added_by))
            self.conn.commit()

    def remove_whitelist(self, domain: str):
        """Whitelist'ten domain kaldir"""
        with self._lock:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM whitelist WHERE domain = ?", (domain.lower(),))
            self.conn.commit()

    def is_whitelisted(self, domain: str) -> bool:
        """Domain whitelist'te mi?"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT 1 FROM whitelist WHERE domain = ?", (domain.lower(),))
        return cursor.fetchone() is not None

    # === Istatistikler ===

    def get_statistics(self) -> Dict[str, Any]:
        """Istatistikleri getir"""
        cursor = self.conn.cursor()

        # Domain sayilari
        cursor.execute("SELECT COUNT(*) FROM blocked_domains WHERE status = 'active'")
        active_domains = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM blocked_domains")
        total_domains = cursor.fetchone()[0]

        # Hit sayilari
        cursor.execute("SELECT COUNT(*) FROM sinkhole_hits")
        total_hits = cursor.fetchone()[0]

        # Son 24 saat hit
        yesterday = (datetime.now() - timedelta(days=1)).isoformat()
        cursor.execute("SELECT COUNT(*) FROM sinkhole_hits WHERE timestamp > ?", (yesterday,))
        hits_24h = cursor.fetchone()[0]

        # Enfekte cihaz sayisi
        cursor.execute("SELECT COUNT(*) FROM infected_devices WHERE risk_score > 0.3")
        infected_devices = cursor.fetchone()[0]

        # Tehdit tipi dagilimi
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM blocked_domains WHERE status = 'active'
            GROUP BY threat_type
        """)
        threat_distribution = {row['threat_type']: row['count'] for row in cursor.fetchall()}

        # Kaynak dagilimi
        cursor.execute("""
            SELECT source, COUNT(*) as count
            FROM blocked_domains WHERE status = 'active'
            GROUP BY source
        """)
        source_distribution = {row['source']: row['count'] for row in cursor.fetchall()}

        # En cok hit alan domainler
        cursor.execute("""
            SELECT domain, hit_count FROM blocked_domains
            WHERE status = 'active'
            ORDER BY hit_count DESC
            LIMIT 10
        """)
        top_domains = [{'domain': row['domain'], 'hits': row['hit_count']}
                      for row in cursor.fetchall()]

        return {
            'active_domains': active_domains,
            'total_domains': total_domains,
            'total_hits': total_hits,
            'hits_24h': hits_24h,
            'infected_devices': infected_devices,
            'threat_distribution': threat_distribution,
            'source_distribution': source_distribution,
            'top_domains': top_domains
        }


# ==================== FEED YÖNETİCİSİ ====================

class FeedManager:
    """Tehdit feed yonetimi"""

    # Varsayilan feedler
    DEFAULT_FEEDS = [
        ThreatFeed(
            name='urlhaus_domains',
            url='https://urlhaus.abuse.ch/downloads/text_online/',
            source=FeedSource.URLHAUS,
            format='txt',
            interval=1800
        ),
        ThreatFeed(
            name='openphish',
            url='https://openphish.com/feed.txt',
            source=FeedSource.OPENPHISH,
            format='txt',
            interval=3600
        ),
        ThreatFeed(
            name='threatfox_iocs',
            url='https://threatfox.abuse.ch/export/json/recent/',
            source=FeedSource.THREATFOX,
            format='json',
            interval=1800
        ),
        ThreatFeed(
            name='feodo_domains',
            url='https://feodotracker.abuse.ch/downloads/domainblocklist.txt',
            source=FeedSource.FEODO_TRACKER,
            format='txt',
            interval=3600
        ),
        ThreatFeed(
            name='ssl_abuse_domains',
            url='https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
            source=FeedSource.SSL_BLACKLIST,
            format='txt',
            interval=3600
        ),
        ThreatFeed(
            name='malware_bazaar',
            url='https://bazaar.abuse.ch/export/txt/md5/recent/',
            source=FeedSource.MALWARE_BAZAAR,
            format='txt',
            interval=3600
        ),
    ]

    def __init__(self, db: SinkholeDatabase):
        self.db = db
        self._feeds: Dict[str, ThreatFeed] = {}
        self._running = False
        self._update_thread = None

        # Varsayilan feedleri yukle
        for feed in self.DEFAULT_FEEDS:
            self._feeds[feed.name] = feed

    def add_feed(self, feed: ThreatFeed):
        """Yeni feed ekle"""
        self._feeds[feed.name] = feed
        logger.info(f"[SINKHOLE] Feed eklendi: {feed.name}")

    def remove_feed(self, name: str):
        """Feed kaldir"""
        if name in self._feeds:
            del self._feeds[name]
            logger.info(f"[SINKHOLE] Feed kaldirildi: {name}")

    def update_feed(self, feed: ThreatFeed) -> int:
        """Tek bir feed'i guncelle"""
        logger.info(f"[SINKHOLE] Feed guncelleniyor: {feed.name}")

        headers = {'User-Agent': 'TSUNAMI-Sinkhole/1.0'}

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(feed.url, headers=headers)

            with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
                content = response.read().decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"[SINKHOLE] Feed indirme hatasi ({feed.name}): {e}")
            return 0

        count = 0

        if feed.format == 'txt':
            count = self._parse_txt_feed(feed, content)
        elif feed.format == 'json':
            count = self._parse_json_feed(feed, content)

        feed.last_update = datetime.now()
        feed.domain_count = count

        logger.info(f"[SINKHOLE] Feed guncellendi: {feed.name} ({count} domain)")
        return count

    def _parse_txt_feed(self, feed: ThreatFeed, content: str) -> int:
        """TXT formatındaki feed'i parse et"""
        count = 0

        for line in content.split('\n'):
            line = line.strip()

            # Yorum ve bos satirlari atla
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            # URL'den domain cikar
            domain = self._extract_domain(line)
            if not domain:
                continue

            # Domain dogrulama
            if not self._is_valid_domain(domain):
                continue

            # Tehdit tipini belirle
            threat_type = self._determine_threat_type(feed.source, line)

            blocked = BlockedDomain(
                domain=domain,
                threat_type=threat_type,
                source=feed.source,
                confidence=0.8,
                tags=[feed.name]
            )

            self.db.add_domain(blocked)
            count += 1

        return count

    def _parse_json_feed(self, feed: ThreatFeed, content: str) -> int:
        """JSON formatındaki feed'i parse et"""
        count = 0

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            logger.error(f"[SINKHOLE] JSON parse hatasi: {feed.name}")
            return 0

        # ThreatFox formati
        if feed.source == FeedSource.THREATFOX:
            for item in data.get('data', []):
                ioc_type = item.get('ioc_type', '').lower()

                if 'domain' not in ioc_type and 'url' not in ioc_type:
                    continue

                ioc_value = item.get('ioc', '')
                domain = self._extract_domain(ioc_value)

                if not domain or not self._is_valid_domain(domain):
                    continue

                # Tehdit tipini belirle
                malware = item.get('malware', '').lower()
                threat_type = ThreatType.MALWARE

                if 'c2' in malware or 'c&c' in malware:
                    threat_type = ThreatType.C2
                elif 'botnet' in malware:
                    threat_type = ThreatType.BOTNET
                elif 'ransomware' in malware:
                    threat_type = ThreatType.RANSOMWARE

                blocked = BlockedDomain(
                    domain=domain,
                    threat_type=threat_type,
                    source=feed.source,
                    confidence=float(item.get('confidence_level', 75)) / 100,
                    tags=[feed.name, item.get('malware_printable', '')]
                )

                self.db.add_domain(blocked)
                count += 1

        return count

    def _extract_domain(self, value: str) -> Optional[str]:
        """Degerden domain cikar"""
        value = value.strip().lower()

        # URL formatindaysa
        if value.startswith('http://') or value.startswith('https://'):
            try:
                from urllib.parse import urlparse
                parsed = urlparse(value)
                value = parsed.netloc
            except Exception:
                pass

        # IP adresi mi kontrol et
        try:
            ipaddress.ip_address(value.split(':')[0])
            return None  # IP adresleri icin None don
        except ValueError:
            pass

        # Port'u kaldir
        if ':' in value:
            value = value.split(':')[0]

        # Path'i kaldir
        if '/' in value:
            value = value.split('/')[0]

        return value if value else None

    def _is_valid_domain(self, domain: str) -> bool:
        """Domain gecerli mi?"""
        if not domain:
            return False

        # Uzunluk kontrolu
        if len(domain) < 4 or len(domain) > 253:
            return False

        # Minimum 1 nokta olmali
        if '.' not in domain:
            return False

        # Gecerli karakterler
        pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'
        if not re.match(pattern, domain):
            return False

        return True

    def _determine_threat_type(self, source: FeedSource, line: str) -> ThreatType:
        """Kaynak ve icerigi temel alarak tehdit tipini belirle"""
        line_lower = line.lower()

        if source == FeedSource.FEODO_TRACKER:
            return ThreatType.BOTNET
        elif source == FeedSource.OPENPHISH:
            return ThreatType.PHISHING
        elif source == FeedSource.SSL_BLACKLIST:
            return ThreatType.C2

        # Icerik bazli tespit
        if 'phish' in line_lower:
            return ThreatType.PHISHING
        elif 'c2' in line_lower or 'c&c' in line_lower:
            return ThreatType.C2
        elif 'botnet' in line_lower:
            return ThreatType.BOTNET
        elif 'ransomware' in line_lower or 'ransom' in line_lower:
            return ThreatType.RANSOMWARE
        elif 'miner' in line_lower or 'crypto' in line_lower:
            return ThreatType.CRYPTOMINER

        return ThreatType.MALWARE

    def update_all_feeds(self) -> Dict[str, int]:
        """Tum feedleri guncelle"""
        results = {}

        for name, feed in self._feeds.items():
            if not feed.enabled:
                continue

            try:
                count = self.update_feed(feed)
                results[name] = count
            except Exception as e:
                logger.error(f"[SINKHOLE] Feed guncelleme hatasi ({name}): {e}")
                results[name] = -1

        return results

    def start_auto_update(self, interval: int = 3600):
        """Otomatik guncelleme baslat"""
        if self._running:
            return

        self._running = True
        self._update_thread = threading.Thread(
            target=self._auto_update_loop,
            args=(interval,),
            daemon=True
        )
        self._update_thread.start()
        logger.info(f"[SINKHOLE] Otomatik feed guncelleme baslatildi ({interval}s)")

    def stop_auto_update(self):
        """Otomatik guncelleme durdur"""
        self._running = False

    def _auto_update_loop(self, interval: int):
        """Otomatik guncelleme dongusu"""
        while self._running:
            try:
                self.update_all_feeds()
            except Exception as e:
                logger.error(f"[SINKHOLE] Otomatik guncelleme hatasi: {e}")
            time.sleep(interval)

    def get_feeds_status(self) -> List[Dict]:
        """Feed durumlarini getir"""
        return [
            {
                'name': feed.name,
                'url': feed.url,
                'source': feed.source.value,
                'enabled': feed.enabled,
                'interval': feed.interval,
                'last_update': feed.last_update.isoformat() if feed.last_update else None,
                'domain_count': feed.domain_count
            }
            for feed in self._feeds.values()
        ]


# ==================== ANA SINKHOLE SINIFI ====================

class DNSSinkhole:
    """
    DNS Sinkhole Ana Sinifi

    Zararli domainleri tespit edip engelleyen,
    C2 iletisimini kesen ve enfekte cihazlari tespit eden
    kapsamli bir DNS sinkhole cozumu.
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
        # Dizinleri olustur
        SINKHOLE_HOME.mkdir(parents=True, exist_ok=True)
        SINKHOLE_LOGS.mkdir(parents=True, exist_ok=True)
        SINKHOLE_FEEDS.mkdir(parents=True, exist_ok=True)

        # Bilesenleri baslat
        self.db = SinkholeDatabase()
        self.feed_manager = FeedManager(self.db)
        self.dga_detector = DGADetector()
        self.fast_flux_detector = FastFluxDetector()
        self.beaconing_analyzer = BeaconingAnalyzer()

        # Yapilandirma
        self.sinkhole_ipv4 = DEFAULT_SINKHOLE_IPV4
        self.sinkhole_ipv6 = DEFAULT_SINKHOLE_IPV6
        self.enabled = True

        # DNS sunucu (opsiyonel)
        self._dns_server = None
        self._dns_thread = None

        logger.info("[SINKHOLE] DNS Sinkhole baslatildi")

    # === Domain Yonetimi ===

    def add_domain(self, domain: str, threat_type: ThreatType = ThreatType.MALWARE,
                  source: FeedSource = FeedSource.MANUAL,
                  confidence: float = 0.9,
                  tags: List[str] = None) -> bool:
        """Domain ekle"""
        if self.db.is_whitelisted(domain):
            logger.warning(f"[SINKHOLE] Domain whitelist'te: {domain}")
            return False

        blocked = BlockedDomain(
            domain=domain.lower(),
            threat_type=threat_type,
            source=source,
            confidence=confidence,
            tags=tags or []
        )

        self.db.add_domain(blocked)
        logger.info(f"[SINKHOLE] Domain engellendi: {domain}")
        return True

    def remove_domain(self, domain: str) -> bool:
        """Domain kaldir"""
        return self.db.remove_domain(domain)

    def check_domain(self, domain: str, source_ip: str = None,
                    query_type: str = 'A') -> Dict[str, Any]:
        """
        Domain kontrolu yap

        Returns:
            {
                'blocked': bool,
                'reason': str,
                'threat_type': str,
                'confidence': float,
                'response_ip': str,
                'analysis': dict
            }
        """
        domain = domain.lower()
        result = {
            'blocked': False,
            'reason': None,
            'threat_type': None,
            'confidence': 0.0,
            'response_ip': None,
            'analysis': {}
        }

        # Whitelist kontrolu
        if self.db.is_whitelisted(domain):
            result['reason'] = 'whitelisted'
            return result

        # Blacklist kontrolu
        blocked = self.db.get_domain(domain)
        if blocked:
            result['blocked'] = True
            result['reason'] = 'blacklist'
            result['threat_type'] = blocked.threat_type.value
            result['confidence'] = blocked.confidence
            result['response_ip'] = self.sinkhole_ipv4 if query_type == 'A' else self.sinkhole_ipv6

            # Hit kaydet
            self._record_hit(domain, source_ip, query_type, blocked.threat_type)
            return result

        # DGA analizi
        dga_result = self.dga_detector.analyze_domain(domain)
        result['analysis']['dga'] = dga_result

        if dga_result['is_dga']:
            result['blocked'] = True
            result['reason'] = 'dga_detected'
            result['threat_type'] = ThreatType.DGA.value
            result['confidence'] = dga_result['confidence']
            result['response_ip'] = self.sinkhole_ipv4 if query_type == 'A' else self.sinkhole_ipv6

            # DGA domain'i kaydet
            self.add_domain(domain, ThreatType.DGA, FeedSource.CUSTOM,
                          dga_result['confidence'],
                          ['dga', dga_result.get('matched_family', 'unknown')])

            self._record_hit(domain, source_ip, query_type, ThreatType.DGA)
            return result

        # Beaconing analizi (eger source_ip varsa)
        if source_ip:
            self.beaconing_analyzer.record_access(source_ip, domain)
            beacon_result = self.beaconing_analyzer.analyze(source_ip, domain)
            result['analysis']['beaconing'] = beacon_result

            if beacon_result['is_beaconing']:
                result['analysis']['warning'] = 'Potential C2 beaconing detected'

        return result

    def _record_hit(self, domain: str, source_ip: str, query_type: str,
                   threat_type: ThreatType):
        """Hit kaydet"""
        if not source_ip:
            source_ip = 'unknown'

        # Sinkhole hit kaydet
        hit = SinkholeHit(
            timestamp=datetime.now(),
            source_ip=source_ip,
            requested_domain=domain,
            query_type=query_type,
            threat_type=threat_type,
            response_given=self.sinkhole_ipv4,
            blocked=True
        )
        self.db.log_hit(hit)

        # Domain hit sayisini artir
        self.db.increment_hit_count(domain)

        # Enfekte cihaz kaydet
        self.db.update_infected_device(source_ip, domain, threat_type)

    # === Feed Yonetimi ===

    def import_feed(self, url: str, name: str = None,
                   source: FeedSource = FeedSource.CUSTOM,
                   format: str = 'txt') -> int:
        """Ozel feed import et"""
        if not name:
            name = hashlib.md5(url.encode()).hexdigest()[:8]

        feed = ThreatFeed(
            name=name,
            url=url,
            source=source,
            format=format
        )

        self.feed_manager.add_feed(feed)
        count = self.feed_manager.update_feed(feed)

        return count

    def update_feeds(self) -> Dict[str, int]:
        """Tum feedleri guncelle"""
        return self.feed_manager.update_all_feeds()

    def start_auto_update(self, interval: int = 3600):
        """Otomatik feed guncelleme baslat"""
        self.feed_manager.start_auto_update(interval)

    def stop_auto_update(self):
        """Otomatik feed guncelleme durdur"""
        self.feed_manager.stop_auto_update()

    # === DNS Entegrasyonu ===

    def export_blocklist(self, format: str = 'hosts',
                        output_path: Path = None) -> Path:
        """
        Blocklist'i farkli formatlarda disa aktar

        Formats:
            - hosts: /etc/hosts formatı
            - dnsmasq: dnsmasq config
            - pihole: Pi-hole gravity format
            - unbound: Unbound DNS format
            - bind: BIND RPZ format
        """
        if output_path is None:
            output_path = SINKHOLE_BLOCKLIST

        domains = self.db.get_all_domains(limit=100000)

        lines = []

        if format == 'hosts':
            for d in domains:
                lines.append(f"{self.sinkhole_ipv4} {d.domain}")
                lines.append(f"{self.sinkhole_ipv6} {d.domain}")

        elif format == 'dnsmasq':
            for d in domains:
                lines.append(f"address=/{d.domain}/{self.sinkhole_ipv4}")

        elif format == 'pihole':
            for d in domains:
                lines.append(d.domain)

        elif format == 'unbound':
            for d in domains:
                lines.append(f'local-zone: "{d.domain}" redirect')
                lines.append(f'local-data: "{d.domain} A {self.sinkhole_ipv4}"')

        elif format == 'bind':
            lines.append('$TTL 60')
            lines.append(f'@ IN SOA sinkhole.local. admin.sinkhole.local. (')
            lines.append('    1 ; serial')
            lines.append('    3600 ; refresh')
            lines.append('    600 ; retry')
            lines.append('    86400 ; expire')
            lines.append('    60 ) ; minimum')
            lines.append(f'@ IN NS sinkhole.local.')
            lines.append('')
            for d in domains:
                lines.append(f'{d.domain} IN A {self.sinkhole_ipv4}')
                lines.append(f'*.{d.domain} IN A {self.sinkhole_ipv4}')

        output_path.write_text('\n'.join(lines))
        logger.info(f"[SINKHOLE] Blocklist disa aktarildi: {output_path} ({len(domains)} domain)")

        return output_path

    def start_dns_server(self, host: str = '0.0.0.0', port: int = 5353):
        """Basit DNS sinkhole sunucusu baslat"""
        # Minimal UDP DNS sunucu
        self._dns_thread = threading.Thread(
            target=self._dns_server_loop,
            args=(host, port),
            daemon=True
        )
        self._dns_thread.start()
        logger.info(f"[SINKHOLE] DNS sunucu baslatildi: {host}:{port}")

    def _dns_server_loop(self, host: str, port: int):
        """DNS sunucu dongusu"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))

        while self.enabled:
            try:
                data, addr = sock.recvfrom(512)
                response = self._handle_dns_query(data, addr[0])
                if response:
                    sock.sendto(response, addr)
            except Exception as e:
                logger.error(f"[SINKHOLE] DNS sunucu hatasi: {e}")

    def _handle_dns_query(self, data: bytes, client_ip: str) -> bytes:
        """DNS sorgusunu isle"""
        try:
            # Basit DNS parser
            # Transaction ID
            trans_id = data[:2]

            # Query domain cikar
            domain = self._parse_dns_domain(data[12:])

            # Kontrol et
            result = self.check_domain(domain, client_ip)

            if result['blocked']:
                # Sinkhole yaniti olustur
                return self._build_dns_response(trans_id, domain, self.sinkhole_ipv4)
            else:
                # Normal yanit (upstream DNS'e yonlendir veya NXDOMAIN)
                return None

        except Exception as e:
            logger.error(f"[SINKHOLE] DNS parse hatasi: {e}")
            return None

    def _parse_dns_domain(self, data: bytes) -> str:
        """DNS sorgusundan domain parse et"""
        domain_parts = []
        pos = 0

        while pos < len(data):
            length = data[pos]
            if length == 0:
                break
            pos += 1
            domain_parts.append(data[pos:pos+length].decode('ascii', errors='ignore'))
            pos += length

        return '.'.join(domain_parts)

    def _build_dns_response(self, trans_id: bytes, domain: str, ip: str) -> bytes:
        """DNS yaniti olustur"""
        # Header
        response = bytearray()
        response.extend(trans_id)
        response.extend(b'\x81\x80')  # Flags: response, no error
        response.extend(b'\x00\x01')  # Questions: 1
        response.extend(b'\x00\x01')  # Answers: 1
        response.extend(b'\x00\x00')  # Authority: 0
        response.extend(b'\x00\x00')  # Additional: 0

        # Question section
        for part in domain.split('.'):
            response.append(len(part))
            response.extend(part.encode('ascii'))
        response.append(0)
        response.extend(b'\x00\x01')  # Type A
        response.extend(b'\x00\x01')  # Class IN

        # Answer section
        response.extend(b'\xc0\x0c')  # Pointer to domain
        response.extend(b'\x00\x01')  # Type A
        response.extend(b'\x00\x01')  # Class IN
        response.extend(b'\x00\x00\x00\x3c')  # TTL: 60
        response.extend(b'\x00\x04')  # Data length: 4

        # IP address
        for octet in ip.split('.'):
            response.append(int(octet))

        return bytes(response)

    # === Analiz ve Raporlama ===

    def get_status(self) -> Dict[str, Any]:
        """Sinkhole durumu"""
        stats = self.db.get_statistics()

        return {
            'enabled': self.enabled,
            'sinkhole_ipv4': self.sinkhole_ipv4,
            'sinkhole_ipv6': self.sinkhole_ipv6,
            'statistics': stats,
            'feeds': self.feed_manager.get_feeds_status(),
            'beaconing_detections': len(self.beaconing_analyzer.get_all_beaconing())
        }

    def get_hits(self, source_ip: str = None, domain: str = None,
                since: datetime = None, limit: int = 100) -> List[Dict]:
        """Hit loglarini getir"""
        return self.db.get_hits(source_ip, domain, since, limit)

    def get_infected_devices(self, min_risk: float = 0.3) -> List[Dict]:
        """Enfekte cihazlari getir"""
        return self.db.get_infected_devices(min_risk)

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        """Domain detayli analizi"""
        return {
            'domain': domain,
            'blocked': self.db.is_blocked(domain),
            'whitelisted': self.db.is_whitelisted(domain),
            'domain_info': asdict(self.db.get_domain(domain)) if self.db.get_domain(domain) else None,
            'dga_analysis': self.dga_detector.analyze_domain(domain),
            'fast_flux_analysis': self.fast_flux_detector.analyze_domain(domain)
        }

    # === Whitelist ===

    def add_whitelist(self, domain: str, reason: str = None, added_by: str = None):
        """Whitelist'e ekle"""
        self.db.add_whitelist(domain, reason, added_by)
        logger.info(f"[SINKHOLE] Whitelist'e eklendi: {domain}")

    def remove_whitelist(self, domain: str):
        """Whitelist'ten kaldir"""
        self.db.remove_whitelist(domain)


# ==================== FLASK API ====================

if FLASK_AVAILABLE:
    sinkhole_bp = Blueprint('sinkhole', __name__, url_prefix='/api/v1/sinkhole')

    def get_sinkhole() -> DNSSinkhole:
        """Sinkhole instance al"""
        return DNSSinkhole.get_instance()

    @sinkhole_bp.route('/status', methods=['GET'])
    def api_status():
        """
        GET /api/v1/sinkhole/status
        Sinkhole durumunu getir
        """
        sinkhole = get_sinkhole()
        return jsonify({
            'basarili': True,
            'veri': sinkhole.get_status()
        })

    @sinkhole_bp.route('/domains', methods=['GET', 'POST'])
    def api_domains():
        """
        GET /api/v1/sinkhole/domains - Domain listesi
        POST /api/v1/sinkhole/domains - Domain ekle
        """
        sinkhole = get_sinkhole()

        if request.method == 'GET':
            limit = request.args.get('limit', 100, type=int)
            offset = request.args.get('offset', 0, type=int)

            domains = sinkhole.db.get_all_domains(limit=limit, offset=offset)

            return jsonify({
                'basarili': True,
                'veri': [asdict(d) for d in domains],
                'toplam': len(domains)
            })

        elif request.method == 'POST':
            data = request.get_json()

            if not data:
                return jsonify({'basarili': False, 'hata': 'JSON verisi gerekli'}), 400

            # Tekil domain
            if 'domain' in data:
                domain = data['domain']
                threat_type = ThreatType(data.get('threat_type', 'malware'))
                confidence = data.get('confidence', 0.9)
                tags = data.get('tags', [])

                success = sinkhole.add_domain(domain, threat_type,
                                            FeedSource.MANUAL, confidence, tags)

                return jsonify({
                    'basarili': success,
                    'mesaj': f"Domain {'eklendi' if success else 'eklenemedi'}: {domain}"
                })

            # Coklu domain
            elif 'domains' in data:
                domains = data['domains']
                added = 0

                for d in domains:
                    if isinstance(d, str):
                        if sinkhole.add_domain(d):
                            added += 1
                    elif isinstance(d, dict):
                        if sinkhole.add_domain(
                            d.get('domain'),
                            ThreatType(d.get('threat_type', 'malware')),
                            FeedSource.MANUAL,
                            d.get('confidence', 0.9),
                            d.get('tags', [])
                        ):
                            added += 1

                return jsonify({
                    'basarili': True,
                    'mesaj': f"{added}/{len(domains)} domain eklendi"
                })

            return jsonify({'basarili': False, 'hata': 'domain veya domains alani gerekli'}), 400

    @sinkhole_bp.route('/domains/<domain>', methods=['GET', 'DELETE'])
    def api_domain_detail(domain: str):
        """
        GET /api/v1/sinkhole/domains/<domain> - Domain analizi
        DELETE /api/v1/sinkhole/domains/<domain> - Domain sil
        """
        sinkhole = get_sinkhole()

        if request.method == 'GET':
            analysis = sinkhole.analyze_domain(domain)
            return jsonify({
                'basarili': True,
                'veri': analysis
            })

        elif request.method == 'DELETE':
            success = sinkhole.remove_domain(domain)
            return jsonify({
                'basarili': success,
                'mesaj': f"Domain {'kaldirildi' if success else 'bulunamadi'}: {domain}"
            })

    @sinkhole_bp.route('/check', methods=['POST'])
    def api_check_domain():
        """
        POST /api/v1/sinkhole/check
        Domain kontrolu yap

        Body:
        {
            "domain": "example.com",
            "source_ip": "192.168.1.100"  (opsiyonel)
        }
        """
        sinkhole = get_sinkhole()
        data = request.get_json()

        if not data or 'domain' not in data:
            return jsonify({'basarili': False, 'hata': 'domain alani gerekli'}), 400

        domain = data['domain']
        source_ip = data.get('source_ip', request.remote_addr)

        result = sinkhole.check_domain(domain, source_ip)

        return jsonify({
            'basarili': True,
            'veri': result
        })

    @sinkhole_bp.route('/hits', methods=['GET'])
    def api_hits():
        """
        GET /api/v1/sinkhole/hits
        Sinkhole hit loglarini getir

        Query params:
            - source_ip: Kaynak IP filtresi
            - domain: Domain filtresi
            - since: Baslangic tarihi (ISO format)
            - limit: Maksimum kayit (varsayilan 100)
        """
        sinkhole = get_sinkhole()

        source_ip = request.args.get('source_ip')
        domain = request.args.get('domain')
        since_str = request.args.get('since')
        limit = request.args.get('limit', 100, type=int)

        since = None
        if since_str:
            try:
                since = datetime.fromisoformat(since_str)
            except ValueError:
                pass

        hits = sinkhole.get_hits(source_ip, domain, since, limit)

        return jsonify({
            'basarili': True,
            'veri': hits,
            'toplam': len(hits)
        })

    @sinkhole_bp.route('/feeds', methods=['GET', 'POST'])
    def api_feeds():
        """
        GET /api/v1/sinkhole/feeds - Feed listesi
        POST /api/v1/sinkhole/feeds - Feed import et

        POST Body:
        {
            "url": "https://example.com/blocklist.txt",
            "name": "custom_feed",  (opsiyonel)
            "format": "txt"  (txt/json)
        }
        """
        sinkhole = get_sinkhole()

        if request.method == 'GET':
            return jsonify({
                'basarili': True,
                'veri': sinkhole.feed_manager.get_feeds_status()
            })

        elif request.method == 'POST':
            data = request.get_json()

            if not data or 'url' not in data:
                return jsonify({'basarili': False, 'hata': 'url alani gerekli'}), 400

            url = data['url']
            name = data.get('name')
            format = data.get('format', 'txt')

            try:
                count = sinkhole.import_feed(url, name, FeedSource.CUSTOM, format)
                return jsonify({
                    'basarili': True,
                    'mesaj': f"Feed import edildi: {count} domain"
                })
            except Exception as e:
                return jsonify({
                    'basarili': False,
                    'hata': f"Feed import hatasi: {str(e)}"
                }), 500

    @sinkhole_bp.route('/feeds/update', methods=['POST'])
    def api_update_feeds():
        """
        POST /api/v1/sinkhole/feeds/update
        Tum feedleri guncelle
        """
        sinkhole = get_sinkhole()

        results = sinkhole.update_feeds()

        return jsonify({
            'basarili': True,
            'veri': results,
            'mesaj': 'Feedler guncellendi'
        })

    @sinkhole_bp.route('/infected', methods=['GET'])
    def api_infected_devices():
        """
        GET /api/v1/sinkhole/infected
        Enfekte cihazlari getir

        Query params:
            - min_risk: Minimum risk skoru (0.0-1.0, varsayilan 0.3)
        """
        sinkhole = get_sinkhole()

        min_risk = request.args.get('min_risk', 0.3, type=float)
        devices = sinkhole.get_infected_devices(min_risk)

        return jsonify({
            'basarili': True,
            'veri': devices,
            'toplam': len(devices)
        })

    @sinkhole_bp.route('/whitelist', methods=['GET', 'POST', 'DELETE'])
    def api_whitelist():
        """
        GET /api/v1/sinkhole/whitelist - Whitelist listesi
        POST /api/v1/sinkhole/whitelist - Whitelist'e ekle
        DELETE /api/v1/sinkhole/whitelist - Whitelist'ten sil
        """
        sinkhole = get_sinkhole()

        if request.method == 'POST':
            data = request.get_json()

            if not data or 'domain' not in data:
                return jsonify({'basarili': False, 'hata': 'domain alani gerekli'}), 400

            domain = data['domain']
            reason = data.get('reason')
            added_by = data.get('added_by', 'api')

            sinkhole.add_whitelist(domain, reason, added_by)

            return jsonify({
                'basarili': True,
                'mesaj': f"Whitelist'e eklendi: {domain}"
            })

        elif request.method == 'DELETE':
            data = request.get_json()

            if not data or 'domain' not in data:
                return jsonify({'basarili': False, 'hata': 'domain alani gerekli'}), 400

            sinkhole.remove_whitelist(data['domain'])

            return jsonify({
                'basarili': True,
                'mesaj': f"Whitelist'ten kaldirildi: {data['domain']}"
            })

        # GET - liste getir (henuz implement edilmedi, db'ye eklenebilir)
        return jsonify({
            'basarili': True,
            'veri': []
        })

    @sinkhole_bp.route('/export', methods=['POST'])
    def api_export_blocklist():
        """
        POST /api/v1/sinkhole/export
        Blocklist'i disa aktar

        Body:
        {
            "format": "hosts"  (hosts/dnsmasq/pihole/unbound/bind)
        }
        """
        sinkhole = get_sinkhole()
        data = request.get_json() or {}

        format = data.get('format', 'hosts')

        if format not in ['hosts', 'dnsmasq', 'pihole', 'unbound', 'bind']:
            return jsonify({
                'basarili': False,
                'hata': 'Gecersiz format. hosts/dnsmasq/pihole/unbound/bind kullanin'
            }), 400

        output_path = sinkhole.export_blocklist(format)

        return jsonify({
            'basarili': True,
            'dosya': str(output_path),
            'mesaj': f'Blocklist {format} formatinda disa aktarildi'
        })

    @sinkhole_bp.route('/beaconing', methods=['GET'])
    def api_beaconing():
        """
        GET /api/v1/sinkhole/beaconing
        Beacon deseni tespitlerini getir
        """
        sinkhole = get_sinkhole()

        patterns = sinkhole.beaconing_analyzer.get_all_beaconing()

        return jsonify({
            'basarili': True,
            'veri': [
                {
                    'source_ip': p.source_ip,
                    'domain': p.domain,
                    'regularity_score': p.regularity_score,
                    'jitter': p.jitter,
                    'first_seen': p.first_seen.isoformat(),
                    'last_seen': p.last_seen.isoformat()
                }
                for p in patterns
            ],
            'toplam': len(patterns)
        })


# ==================== SINGLETON ERİŞİM ====================

_sinkhole = None

def sinkhole_al() -> DNSSinkhole:
    """DNS Sinkhole instance al"""
    global _sinkhole
    if _sinkhole is None:
        _sinkhole = DNSSinkhole.get_instance()
    return _sinkhole


# ==================== CLI ====================

def main():
    """CLI giris noktasi"""
    import argparse

    parser = argparse.ArgumentParser(description='TSUNAMI DNS Sinkhole')
    parser.add_argument('--update-feeds', action='store_true', help='Feedleri guncelle')
    parser.add_argument('--export', choices=['hosts', 'dnsmasq', 'pihole', 'unbound', 'bind'],
                       help='Blocklist disa aktar')
    parser.add_argument('--check', type=str, help='Domain kontrol et')
    parser.add_argument('--add', type=str, help='Domain engelle')
    parser.add_argument('--remove', type=str, help='Domain kaldir')
    parser.add_argument('--status', action='store_true', help='Durum goster')
    parser.add_argument('--start-dns', action='store_true', help='DNS sunucu baslat')
    parser.add_argument('--port', type=int, default=5353, help='DNS port (varsayilan: 5353)')

    args = parser.parse_args()

    sinkhole = sinkhole_al()

    if args.update_feeds:
        print("[*] Feedler guncelleniyor...")
        results = sinkhole.update_feeds()
        for name, count in results.items():
            status = f"{count} domain" if count >= 0 else "HATA"
            print(f"    {name}: {status}")

    elif args.export:
        print(f"[*] Blocklist disa aktariliyor ({args.export})...")
        path = sinkhole.export_blocklist(args.export)
        print(f"    Dosya: {path}")

    elif args.check:
        result = sinkhole.check_domain(args.check)
        print(f"Domain: {args.check}")
        print(f"Blocked: {result['blocked']}")
        print(f"Reason: {result['reason']}")
        if result['threat_type']:
            print(f"Threat Type: {result['threat_type']}")
        if result['analysis']:
            print(f"Analysis: {json.dumps(result['analysis'], indent=2)}")

    elif args.add:
        success = sinkhole.add_domain(args.add)
        print(f"{'[+]' if success else '[-]'} Domain {'eklendi' if success else 'eklenemedi'}: {args.add}")

    elif args.remove:
        success = sinkhole.remove_domain(args.remove)
        print(f"{'[+]' if success else '[-]'} Domain {'kaldirildi' if success else 'bulunamadi'}: {args.remove}")

    elif args.status:
        status = sinkhole.get_status()
        print(json.dumps(status, indent=2, default=str))

    elif args.start_dns:
        print(f"[*] DNS sunucu baslatiliyor (port {args.port})...")
        sinkhole.start_dns_server(port=args.port)
        print("[*] DNS sunucu calisiyor. Ctrl+C ile durdurun.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Durduruluyor...")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
