#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Live Threat Intelligence Module v1.0
    Real-time Cyber Threat Data for Turkey and Surrounding Regions
================================================================================

    Features:
    - Multiple free threat intelligence source integration
    - Real-time threat data with 5-minute caching
    - GeoJSON format output for map visualization
    - Turkey and regional focus with filtering
    - Mock data fallback for demo/offline scenarios
    - Comprehensive threat categorization and severity levels

    Sources:
    - AbuseIPDB (free tier)
    - AlienVault OTX (free)
    - GreyNoise (free tier)
    - Shodan (free tier)
    - Turkish CERT data simulation

================================================================================
"""

import os
import json
import time
import random
import hashlib
import logging
import threading
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import wraps
import ipaddress

try:
    import requests
except ImportError:
    requests = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# =============================================================================
# ENUMS AND DATA CLASSES
# =============================================================================

class ThreatCategory(Enum):
    """Threat categories for classification"""
    DDOS = "ddos"
    MALWARE = "malware"
    BOTNET = "botnet"
    SCANNING = "scanning"
    BRUTE_FORCE = "brute_force"
    APT = "apt"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    C2 = "c2"
    SPAM = "spam"
    EXPLOIT = "exploit"
    DATA_EXFILTRATION = "data_exfiltration"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ThreatStatus(Enum):
    """Threat status"""
    ACTIVE = "active"
    MITIGATED = "mitigated"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"


@dataclass
class GeoLocation:
    """Geographic location data"""
    latitude: float
    longitude: float
    country_code: str
    country_name: str
    city: Optional[str] = None
    region: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None


@dataclass
class ThreatIndicator:
    """Threat indicator with full metadata"""
    id: str
    ip_address: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float  # 0.0 - 1.0
    source: str
    first_seen: datetime
    last_seen: datetime
    geo_location: Optional[GeoLocation] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    port: Optional[int] = None
    protocol: Optional[str] = None
    attack_count: int = 1
    status: ThreatStatus = ThreatStatus.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_geojson_feature(self) -> Dict[str, Any]:
        """Convert to GeoJSON Feature format"""
        if not self.geo_location:
            return None

        return {
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [
                    self.geo_location.longitude,
                    self.geo_location.latitude
                ]
            },
            "properties": {
                "id": self.id,
                "ip_address": self.ip_address,
                "category": self.category.value,
                "severity": self.severity.value,
                "confidence": self.confidence,
                "source": self.source,
                "first_seen": self.first_seen.isoformat(),
                "last_seen": self.last_seen.isoformat(),
                "description": self.description,
                "tags": self.tags,
                "port": self.port,
                "protocol": self.protocol,
                "attack_count": self.attack_count,
                "status": self.status.value,
                "country_code": self.geo_location.country_code,
                "country_name": self.geo_location.country_name,
                "city": self.geo_location.city,
                "isp": self.geo_location.isp,
                "asn": self.geo_location.asn
            }
        }


@dataclass
class ThreatStats:
    """Statistics summary for threats"""
    total_threats: int = 0
    by_category: Dict[str, int] = field(default_factory=dict)
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_country: Dict[str, int] = field(default_factory=dict)
    by_source: Dict[str, int] = field(default_factory=dict)
    top_attacking_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_targeted_ports: List[Dict[str, Any]] = field(default_factory=list)
    last_updated: Optional[datetime] = None
    cache_age_seconds: int = 0


# =============================================================================
# CACHING DECORATOR
# =============================================================================

class CacheEntry:
    """Cache entry with TTL"""
    def __init__(self, value: Any, ttl_seconds: int = 300):
        self.value = value
        self.created_at = time.time()
        self.ttl_seconds = ttl_seconds

    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds

    def age_seconds(self) -> int:
        return int(time.time() - self.created_at)


class ThreatCache:
    """Thread-safe cache for threat data"""

    def __init__(self, default_ttl: int = 300):
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._default_ttl = default_ttl

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._cache.get(key)
            if entry and not entry.is_expired():
                return entry.value
            elif entry:
                del self._cache[key]
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        with self._lock:
            self._cache[key] = CacheEntry(value, ttl or self._default_ttl)

    def get_age(self, key: str) -> int:
        with self._lock:
            entry = self._cache.get(key)
            return entry.age_seconds() if entry else -1

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def cleanup_expired(self) -> int:
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
            for key in expired_keys:
                del self._cache[key]
            return len(expired_keys)


def cached(ttl_seconds: int = 300):
    """Decorator for caching function results"""
    def decorator(func):
        cache = {}
        lock = threading.Lock()

        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            key_parts = [func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = hashlib.md5(":".join(key_parts).encode()).hexdigest()

            with lock:
                if cache_key in cache:
                    entry = cache[cache_key]
                    if not entry.is_expired():
                        logger.debug(f"Cache hit for {func.__name__}")
                        return entry.value

            # Cache miss - execute function
            result = func(*args, **kwargs)

            with lock:
                cache[cache_key] = CacheEntry(result, ttl_seconds)

            return result

        wrapper.clear_cache = lambda: cache.clear()
        return wrapper

    return decorator


# =============================================================================
# THREAT SOURCE INTERFACES
# =============================================================================

class ThreatSource(ABC):
    """Abstract base class for threat intelligence sources"""

    def __init__(self, name: str, api_key: Optional[str] = None):
        self.name = name
        self.api_key = api_key
        self.enabled = True
        self.last_fetch: Optional[datetime] = None
        self.error_count = 0
        self.max_errors = 5

    @abstractmethod
    def fetch_threats(self) -> List[ThreatIndicator]:
        """Fetch threats from the source"""
        pass

    def is_available(self) -> bool:
        """Check if source is available"""
        return self.enabled and self.error_count < self.max_errors

    def record_error(self, error: Exception) -> None:
        """Record an error and potentially disable source"""
        self.error_count += 1
        logger.error(f"[{self.name}] Error ({self.error_count}/{self.max_errors}): {error}")
        if self.error_count >= self.max_errors:
            logger.warning(f"[{self.name}] Disabled due to too many errors")
            self.enabled = False

    def reset_errors(self) -> None:
        """Reset error count on successful fetch"""
        self.error_count = 0


class AbuseIPDBSource(ThreatSource):
    """AbuseIPDB threat intelligence source"""

    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("AbuseIPDB", api_key or os.getenv("ABUSEIPDB_KEY"))

    def fetch_threats(self) -> List[ThreatIndicator]:
        if not self.api_key:
            logger.warning(f"[{self.name}] No API key configured")
            return []

        if not requests:
            logger.warning(f"[{self.name}] requests library not available")
            return []

        threats = []
        try:
            headers = {
                "Key": self.api_key,
                "Accept": "application/json"
            }
            params = {
                "confidenceMinimum": 75,
                "limit": 100
            }

            response = requests.get(
                f"{self.BASE_URL}/blacklist",
                headers=headers,
                params=params,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            for item in data.get("data", []):
                threat = self._parse_threat(item)
                if threat:
                    threats.append(threat)

            self.last_fetch = datetime.now()
            self.reset_errors()
            logger.info(f"[{self.name}] Fetched {len(threats)} threats")

        except Exception as e:
            self.record_error(e)

        return threats

    def _parse_threat(self, item: Dict) -> Optional[ThreatIndicator]:
        try:
            ip = item.get("ipAddress", "")
            abuse_score = item.get("abuseConfidenceScore", 0)

            severity = ThreatSeverity.LOW
            if abuse_score >= 90:
                severity = ThreatSeverity.CRITICAL
            elif abuse_score >= 75:
                severity = ThreatSeverity.HIGH
            elif abuse_score >= 50:
                severity = ThreatSeverity.MEDIUM

            category = ThreatCategory.SCANNING
            categories = item.get("usageType", "")
            if "ddos" in categories.lower():
                category = ThreatCategory.DDOS
            elif "malware" in categories.lower():
                category = ThreatCategory.MALWARE

            geo = None
            if item.get("countryCode"):
                geo = GeoLocation(
                    latitude=0.0,
                    longitude=0.0,
                    country_code=item.get("countryCode", ""),
                    country_name=item.get("countryName", ""),
                    isp=item.get("isp"),
                    asn=str(item.get("asn", ""))
                )

            return ThreatIndicator(
                id=hashlib.md5(f"abuseipdb:{ip}".encode()).hexdigest()[:16],
                ip_address=ip,
                category=category,
                severity=severity,
                confidence=abuse_score / 100.0,
                source=self.name,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                geo_location=geo,
                description=f"AbuseIPDB reported with {abuse_score}% confidence",
                tags=["abuseipdb"],
                attack_count=item.get("totalReports", 1)
            )
        except Exception as e:
            logger.error(f"[{self.name}] Parse error: {e}")
            return None


class AlienVaultOTXSource(ThreatSource):
    """AlienVault OTX threat intelligence source"""

    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("AlienVault_OTX", api_key or os.getenv("OTX_KEY"))

    def fetch_threats(self) -> List[ThreatIndicator]:
        if not self.api_key:
            logger.warning(f"[{self.name}] No API key configured")
            return []

        if not requests:
            logger.warning(f"[{self.name}] requests library not available")
            return []

        threats = []
        try:
            headers = {
                "X-OTX-API-KEY": self.api_key,
                "Accept": "application/json"
            }

            # Get recent pulses
            response = requests.get(
                f"{self.BASE_URL}/pulses/subscribed",
                headers=headers,
                params={"limit": 20, "modified_since": (datetime.now() - timedelta(days=1)).isoformat()},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            for pulse in data.get("results", []):
                for indicator in pulse.get("indicators", []):
                    if indicator.get("type") == "IPv4":
                        threat = self._parse_indicator(indicator, pulse)
                        if threat:
                            threats.append(threat)

            self.last_fetch = datetime.now()
            self.reset_errors()
            logger.info(f"[{self.name}] Fetched {len(threats)} threats")

        except Exception as e:
            self.record_error(e)

        return threats

    def _parse_indicator(self, indicator: Dict, pulse: Dict) -> Optional[ThreatIndicator]:
        try:
            ip = indicator.get("indicator", "")

            # Determine category from pulse tags
            tags = pulse.get("tags", [])
            category = ThreatCategory.MALWARE
            for tag in tags:
                tag_lower = tag.lower()
                if "apt" in tag_lower:
                    category = ThreatCategory.APT
                    break
                elif "botnet" in tag_lower:
                    category = ThreatCategory.BOTNET
                    break
                elif "ransomware" in tag_lower:
                    category = ThreatCategory.RANSOMWARE
                    break
                elif "phishing" in tag_lower:
                    category = ThreatCategory.PHISHING
                    break
                elif "c2" in tag_lower or "c&c" in tag_lower:
                    category = ThreatCategory.C2
                    break

            return ThreatIndicator(
                id=hashlib.md5(f"otx:{ip}".encode()).hexdigest()[:16],
                ip_address=ip,
                category=category,
                severity=ThreatSeverity.HIGH,
                confidence=0.8,
                source=self.name,
                first_seen=datetime.fromisoformat(indicator.get("created", datetime.now().isoformat()).replace("Z", "+00:00")),
                last_seen=datetime.now(),
                description=pulse.get("name", "OTX Pulse indicator"),
                tags=tags[:10]
            )
        except Exception as e:
            logger.error(f"[{self.name}] Parse error: {e}")
            return None


class GreyNoiseSource(ThreatSource):
    """GreyNoise threat intelligence source"""

    BASE_URL = "https://api.greynoise.io/v3"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("GreyNoise", api_key or os.getenv("GREYNOISE_KEY"))

    def fetch_threats(self) -> List[ThreatIndicator]:
        if not self.api_key:
            logger.warning(f"[{self.name}] No API key configured")
            return []

        if not requests:
            logger.warning(f"[{self.name}] requests library not available")
            return []

        threats = []
        try:
            headers = {
                "key": self.api_key,
                "Accept": "application/json"
            }

            # Query for malicious IPs targeting Turkey region
            query = "classification:malicious last_seen:1d"
            response = requests.get(
                f"{self.BASE_URL}/v2/experimental/gnql",
                headers=headers,
                params={"query": query, "size": 100},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            for item in data.get("data", []):
                threat = self._parse_threat(item)
                if threat:
                    threats.append(threat)

            self.last_fetch = datetime.now()
            self.reset_errors()
            logger.info(f"[{self.name}] Fetched {len(threats)} threats")

        except Exception as e:
            self.record_error(e)

        return threats

    def _parse_threat(self, item: Dict) -> Optional[ThreatIndicator]:
        try:
            ip = item.get("ip", "")

            category = ThreatCategory.SCANNING
            tags = item.get("tags", [])
            for tag in tags:
                tag_lower = tag.lower()
                if "bruteforce" in tag_lower or "brute" in tag_lower:
                    category = ThreatCategory.BRUTE_FORCE
                    break
                elif "botnet" in tag_lower:
                    category = ThreatCategory.BOTNET
                    break
                elif "exploit" in tag_lower:
                    category = ThreatCategory.EXPLOIT
                    break

            classification = item.get("classification", "unknown")
            severity = ThreatSeverity.MEDIUM
            if classification == "malicious":
                severity = ThreatSeverity.HIGH

            geo = None
            metadata = item.get("metadata", {})
            if metadata.get("country_code"):
                geo = GeoLocation(
                    latitude=metadata.get("latitude", 0.0),
                    longitude=metadata.get("longitude", 0.0),
                    country_code=metadata.get("country_code", ""),
                    country_name=metadata.get("country", ""),
                    city=metadata.get("city"),
                    asn=str(metadata.get("asn", ""))
                )

            return ThreatIndicator(
                id=hashlib.md5(f"greynoise:{ip}".encode()).hexdigest()[:16],
                ip_address=ip,
                category=category,
                severity=severity,
                confidence=0.85,
                source=self.name,
                first_seen=datetime.fromisoformat(item.get("first_seen", datetime.now().isoformat()).replace("Z", "+00:00")),
                last_seen=datetime.fromisoformat(item.get("last_seen", datetime.now().isoformat()).replace("Z", "+00:00")),
                geo_location=geo,
                description=f"GreyNoise: {item.get('actor', 'Unknown actor')} - {classification}",
                tags=tags[:10]
            )
        except Exception as e:
            logger.error(f"[{self.name}] Parse error: {e}")
            return None


class ShodanSource(ThreatSource):
    """Shodan threat intelligence source"""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: Optional[str] = None):
        super().__init__("Shodan", api_key or os.getenv("SHODAN_KEY"))

    def fetch_threats(self) -> List[ThreatIndicator]:
        if not self.api_key:
            logger.warning(f"[{self.name}] No API key configured")
            return []

        if not requests:
            logger.warning(f"[{self.name}] requests library not available")
            return []

        threats = []
        try:
            # Get honeypot data and known malicious IPs
            response = requests.get(
                f"{self.BASE_URL}/shodan/host/search",
                params={
                    "key": self.api_key,
                    "query": "country:TR vuln:*",
                    "minify": True
                },
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            for match in data.get("matches", [])[:50]:
                threat = self._parse_match(match)
                if threat:
                    threats.append(threat)

            self.last_fetch = datetime.now()
            self.reset_errors()
            logger.info(f"[{self.name}] Fetched {len(threats)} threats")

        except Exception as e:
            self.record_error(e)

        return threats

    def _parse_match(self, match: Dict) -> Optional[ThreatIndicator]:
        try:
            ip = match.get("ip_str", "")
            vulns = match.get("vulns", {})

            severity = ThreatSeverity.MEDIUM
            if vulns:
                severity = ThreatSeverity.HIGH

            geo = GeoLocation(
                latitude=match.get("location", {}).get("latitude", 0.0),
                longitude=match.get("location", {}).get("longitude", 0.0),
                country_code=match.get("location", {}).get("country_code", ""),
                country_name=match.get("location", {}).get("country_name", ""),
                city=match.get("location", {}).get("city"),
                isp=match.get("isp"),
                asn=match.get("asn")
            )

            return ThreatIndicator(
                id=hashlib.md5(f"shodan:{ip}".encode()).hexdigest()[:16],
                ip_address=ip,
                category=ThreatCategory.SCANNING,
                severity=severity,
                confidence=0.7,
                source=self.name,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                geo_location=geo,
                port=match.get("port"),
                description=f"Shodan: Vulnerable system detected",
                tags=list(vulns.keys())[:10] if vulns else ["exposed"]
            )
        except Exception as e:
            logger.error(f"[{self.name}] Parse error: {e}")
            return None


class TurkishCERTSource(ThreatSource):
    """
    Turkish CERT (USOM) simulated threat data source.

    In production, this would connect to:
    - USOM (Ulusal Siber Olaylara Mudahale Merkezi)
    - BTK Siber Guvenlik
    - Turkish national cyber threat feeds

    For demo purposes, generates realistic simulated data.
    """

    # Turkish cities with coordinates
    TURKISH_CITIES = {
        "Istanbul": (41.0082, 28.9784),
        "Ankara": (39.9334, 32.8597),
        "Izmir": (38.4237, 27.1428),
        "Bursa": (40.1885, 29.0610),
        "Antalya": (36.8969, 30.7133),
        "Adana": (37.0000, 35.3213),
        "Konya": (37.8746, 32.4932),
        "Gaziantep": (37.0662, 37.3833),
        "Mersin": (36.8000, 34.6333),
        "Diyarbakir": (37.9144, 40.2306),
        "Kayseri": (38.7312, 35.4787),
        "Eskisehir": (39.7767, 30.5206),
        "Samsun": (41.2867, 36.3300),
        "Denizli": (37.7765, 29.0864),
        "Trabzon": (41.0015, 39.7178)
    }

    # Regional threat sources (neighboring countries and common attack origins)
    REGIONAL_SOURCES = {
        "RU": ("Russia", 55.7558, 37.6173),
        "IR": ("Iran", 35.6892, 51.3890),
        "CN": ("China", 39.9042, 116.4074),
        "UA": ("Ukraine", 50.4501, 30.5234),
        "RO": ("Romania", 44.4268, 26.1025),
        "BG": ("Bulgaria", 42.6977, 23.3219),
        "GR": ("Greece", 37.9838, 23.7275),
        "SY": ("Syria", 33.5138, 36.2765),
        "IQ": ("Iraq", 33.3152, 44.3661)
    }

    def __init__(self):
        super().__init__("Turkish_CERT")
        self._threat_templates = self._init_threat_templates()

    def _init_threat_templates(self) -> List[Dict]:
        """Initialize threat templates for simulation"""
        return [
            {
                "category": ThreatCategory.APT,
                "severity": ThreatSeverity.CRITICAL,
                "description": "APT group activity targeting Turkish government infrastructure",
                "tags": ["apt", "government", "espionage"]
            },
            {
                "category": ThreatCategory.DDOS,
                "severity": ThreatSeverity.HIGH,
                "description": "DDoS attack campaign targeting Turkish financial sector",
                "tags": ["ddos", "financial", "volumetric"]
            },
            {
                "category": ThreatCategory.RANSOMWARE,
                "severity": ThreatSeverity.CRITICAL,
                "description": "Ransomware campaign targeting Turkish enterprises",
                "tags": ["ransomware", "enterprise", "encryption"]
            },
            {
                "category": ThreatCategory.PHISHING,
                "severity": ThreatSeverity.MEDIUM,
                "description": "Phishing campaign impersonating Turkish banks",
                "tags": ["phishing", "banking", "credential-theft"]
            },
            {
                "category": ThreatCategory.BOTNET,
                "severity": ThreatSeverity.HIGH,
                "description": "Botnet C2 infrastructure detected in Turkey region",
                "tags": ["botnet", "c2", "mirai-variant"]
            },
            {
                "category": ThreatCategory.BRUTE_FORCE,
                "severity": ThreatSeverity.MEDIUM,
                "description": "SSH brute force attacks targeting Turkish servers",
                "tags": ["bruteforce", "ssh", "credential-stuffing"]
            },
            {
                "category": ThreatCategory.SCANNING,
                "severity": ThreatSeverity.LOW,
                "description": "Port scanning activity from suspicious sources",
                "tags": ["scanning", "reconnaissance", "nmap"]
            },
            {
                "category": ThreatCategory.MALWARE,
                "severity": ThreatSeverity.HIGH,
                "description": "Malware distribution server targeting Turkish users",
                "tags": ["malware", "trojan", "distribution"]
            },
            {
                "category": ThreatCategory.C2,
                "severity": ThreatSeverity.CRITICAL,
                "description": "Command and Control server communication detected",
                "tags": ["c2", "beaconing", "exfiltration"]
            },
            {
                "category": ThreatCategory.DATA_EXFILTRATION,
                "severity": ThreatSeverity.CRITICAL,
                "description": "Data exfiltration attempt to foreign servers",
                "tags": ["exfiltration", "data-theft", "sensitive"]
            }
        ]

    def fetch_threats(self) -> List[ThreatIndicator]:
        """Generate simulated Turkish CERT threat data"""
        threats = []

        # Generate between 15-30 simulated threats
        num_threats = random.randint(15, 30)

        for i in range(num_threats):
            threat = self._generate_threat(i)
            if threat:
                threats.append(threat)

        self.last_fetch = datetime.now()
        logger.info(f"[{self.name}] Generated {len(threats)} simulated threats")
        return threats

    def _generate_threat(self, index: int) -> ThreatIndicator:
        """Generate a single simulated threat"""
        template = random.choice(self._threat_templates)

        # Decide if threat originates from Turkey or external
        is_external = random.random() < 0.7  # 70% external threats

        if is_external:
            source_country = random.choice(list(self.REGIONAL_SOURCES.keys()))
            country_name, lat, lon = self.REGIONAL_SOURCES[source_country]
            # Add some randomness to coordinates
            lat += random.uniform(-2, 2)
            lon += random.uniform(-2, 2)
        else:
            city = random.choice(list(self.TURKISH_CITIES.keys()))
            lat, lon = self.TURKISH_CITIES[city]
            source_country = "TR"
            country_name = "Turkey"
            lat += random.uniform(-0.5, 0.5)
            lon += random.uniform(-0.5, 0.5)

        # Generate random IP
        ip_parts = [random.randint(1, 254) for _ in range(4)]
        ip_address = ".".join(map(str, ip_parts))

        # Random timestamps
        now = datetime.now()
        first_seen = now - timedelta(
            hours=random.randint(1, 72),
            minutes=random.randint(0, 59)
        )
        last_seen = now - timedelta(minutes=random.randint(0, 30))

        # Random port for some threats
        port = None
        protocol = None
        if template["category"] in [ThreatCategory.BRUTE_FORCE, ThreatCategory.SCANNING]:
            common_ports = [22, 23, 80, 443, 445, 3389, 8080, 8443]
            port = random.choice(common_ports)
            protocol = "TCP"

        geo = GeoLocation(
            latitude=lat,
            longitude=lon,
            country_code=source_country,
            country_name=country_name,
            city=random.choice(list(self.TURKISH_CITIES.keys())) if source_country == "TR" else None,
            asn=f"AS{random.randint(1000, 65000)}"
        )

        confidence = random.uniform(0.6, 0.95)
        if template["severity"] == ThreatSeverity.CRITICAL:
            confidence = max(confidence, 0.85)

        return ThreatIndicator(
            id=hashlib.md5(f"trcert:{ip_address}:{index}:{now.timestamp()}".encode()).hexdigest()[:16],
            ip_address=ip_address,
            category=template["category"],
            severity=template["severity"],
            confidence=round(confidence, 2),
            source=self.name,
            first_seen=first_seen,
            last_seen=last_seen,
            geo_location=geo,
            description=template["description"],
            tags=template["tags"],
            port=port,
            protocol=protocol,
            attack_count=random.randint(1, 1000),
            metadata={
                "target_region": "Turkey",
                "simulated": True
            }
        )


# =============================================================================
# MOCK DATA GENERATOR
# =============================================================================

class MockThreatGenerator:
    """
    Generates realistic mock threat data for demo/testing purposes.
    Used when APIs are unavailable or for offline demonstrations.
    """

    # Global attack origins with coordinates
    GLOBAL_SOURCES = {
        "RU": {"name": "Russia", "lat": 55.7558, "lon": 37.6173, "weight": 0.25},
        "CN": {"name": "China", "lat": 39.9042, "lon": 116.4074, "weight": 0.20},
        "US": {"name": "United States", "lat": 39.8283, "lon": -98.5795, "weight": 0.10},
        "IR": {"name": "Iran", "lat": 35.6892, "lon": 51.3890, "weight": 0.15},
        "KP": {"name": "North Korea", "lat": 39.0392, "lon": 125.7625, "weight": 0.05},
        "UA": {"name": "Ukraine", "lat": 50.4501, "lon": 30.5234, "weight": 0.08},
        "BR": {"name": "Brazil", "lat": -14.2350, "lon": -51.9253, "weight": 0.05},
        "IN": {"name": "India", "lat": 20.5937, "lon": 78.9629, "weight": 0.05},
        "VN": {"name": "Vietnam", "lat": 14.0583, "lon": 108.2772, "weight": 0.04},
        "ID": {"name": "Indonesia", "lat": -0.7893, "lon": 113.9213, "weight": 0.03}
    }

    # Turkey-focused targets
    TURKEY_TARGETS = {
        "Istanbul": (41.0082, 28.9784),
        "Ankara": (39.9334, 32.8597),
        "Izmir": (38.4237, 27.1428),
        "Antalya": (36.8969, 30.7133),
        "Bursa": (40.1885, 29.0610)
    }

    @classmethod
    def generate_threats(cls, count: int = 50, turkey_focus: bool = True) -> List[ThreatIndicator]:
        """Generate mock threat data"""
        threats = []

        for i in range(count):
            threat = cls._generate_single_threat(i, turkey_focus)
            threats.append(threat)

        return threats

    @classmethod
    def _generate_single_threat(cls, index: int, turkey_focus: bool) -> ThreatIndicator:
        """Generate a single mock threat"""
        # Select source country weighted by attack frequency
        countries = list(cls.GLOBAL_SOURCES.keys())
        weights = [cls.GLOBAL_SOURCES[c]["weight"] for c in countries]
        source_country = random.choices(countries, weights=weights)[0]
        source_data = cls.GLOBAL_SOURCES[source_country]

        # Randomize coordinates slightly
        lat = source_data["lat"] + random.uniform(-5, 5)
        lon = source_data["lon"] + random.uniform(-5, 5)

        # Generate IP address
        ip_parts = [random.randint(1, 254) for _ in range(4)]
        ip_address = ".".join(map(str, ip_parts))

        # Select category and severity
        categories = list(ThreatCategory)
        category = random.choice(categories)

        severities = [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH,
                     ThreatSeverity.MEDIUM, ThreatSeverity.LOW]
        severity_weights = [0.1, 0.25, 0.40, 0.25]
        severity = random.choices(severities, severity_weights)[0]

        # APT threats are typically critical
        if category == ThreatCategory.APT:
            severity = ThreatSeverity.CRITICAL

        # Time data
        now = datetime.now()
        first_seen = now - timedelta(hours=random.randint(1, 168))
        last_seen = now - timedelta(minutes=random.randint(0, 60))

        # Port information for relevant categories
        port = None
        protocol = None
        if category in [ThreatCategory.BRUTE_FORCE, ThreatCategory.SCANNING]:
            port = random.choice([22, 23, 80, 443, 445, 3389, 8080, 8443, 5900])
            protocol = "TCP"
        elif category == ThreatCategory.DDOS:
            port = random.choice([80, 443, 53])
            protocol = random.choice(["TCP", "UDP"])

        geo = GeoLocation(
            latitude=lat,
            longitude=lon,
            country_code=source_country,
            country_name=source_data["name"],
            asn=f"AS{random.randint(1000, 65000)}",
            isp=f"ISP-{random.randint(1, 100)}"
        )

        tags = [category.value, severity.value, source_country.lower()]
        if turkey_focus:
            target_city = random.choice(list(cls.TURKEY_TARGETS.keys()))
            tags.append(f"target:{target_city.lower()}")

        sources = ["MockGenerator", "AbuseIPDB", "AlienVault_OTX", "GreyNoise", "Turkish_CERT"]
        source = random.choice(sources)

        return ThreatIndicator(
            id=hashlib.md5(f"mock:{ip_address}:{index}:{now.timestamp()}".encode()).hexdigest()[:16],
            ip_address=ip_address,
            category=category,
            severity=severity,
            confidence=round(random.uniform(0.5, 0.99), 2),
            source=source,
            first_seen=first_seen,
            last_seen=last_seen,
            geo_location=geo,
            description=f"Mock {category.value} threat from {source_data['name']}",
            tags=tags,
            port=port,
            protocol=protocol,
            attack_count=random.randint(1, 5000),
            metadata={
                "mock": True,
                "generated_at": now.isoformat()
            }
        )


# =============================================================================
# MAIN THREAT INTELLIGENCE MANAGER
# =============================================================================

class ThreatIntelligenceManager:
    """
    Central manager for threat intelligence aggregation and analysis.

    Aggregates data from multiple sources:
    - AbuseIPDB
    - AlienVault OTX
    - GreyNoise
    - Shodan
    - Turkish CERT (simulated)

    Features:
    - 5-minute caching to respect API rate limits
    - Automatic fallback to mock data
    - GeoJSON format output
    - Regional filtering (Turkey focus)
    - Statistics and analytics
    """

    # Turkey and surrounding region country codes
    TURKEY_REGION = ["TR", "GR", "BG", "RO", "UA", "GE", "AM", "AZ", "IR", "IQ", "SY", "CY"]

    def __init__(self,
                 use_mock_fallback: bool = True,
                 cache_ttl: int = 300):  # 5 minutes default
        """
        Initialize the Threat Intelligence Manager.

        Args:
            use_mock_fallback: If True, use mock data when APIs fail
            cache_ttl: Cache time-to-live in seconds (default: 300 = 5 minutes)
        """
        self.use_mock_fallback = use_mock_fallback
        self.cache_ttl = cache_ttl
        self._cache = ThreatCache(default_ttl=cache_ttl)
        self._threats: Dict[str, ThreatIndicator] = {}
        self._lock = threading.RLock()
        self._sources: List[ThreatSource] = []
        self._initialized = False
        self._last_update: Optional[datetime] = None

        self._initialize_sources()
        logger.info("[ThreatIntelligenceManager] Initialized with 5-minute caching")

    def _initialize_sources(self) -> None:
        """Initialize all threat intelligence sources"""
        self._sources = [
            AbuseIPDBSource(),
            AlienVaultOTXSource(),
            GreyNoiseSource(),
            ShodanSource(),
            TurkishCERTSource()
        ]
        self._initialized = True
        logger.info(f"[ThreatIntelligenceManager] Initialized {len(self._sources)} threat sources")

    def get_live_threats(self,
                         force_refresh: bool = False,
                         include_mock: bool = True) -> Dict[str, Any]:
        """
        Get current live threats in GeoJSON format.

        Args:
            force_refresh: If True, bypass cache and fetch fresh data
            include_mock: If True, include mock data when APIs fail

        Returns:
            GeoJSON FeatureCollection with threat data
        """
        cache_key = "live_threats"

        if not force_refresh:
            cached_data = self._cache.get(cache_key)
            if cached_data:
                logger.debug("[ThreatIntelligenceManager] Returning cached threats")
                cached_data["cache_age_seconds"] = self._cache.get_age(cache_key)
                return cached_data

        # Fetch fresh data from all sources
        threats = self._fetch_all_threats()

        # If no threats from APIs and fallback enabled, use mock data
        if not threats and self.use_mock_fallback and include_mock:
            logger.warning("[ThreatIntelligenceManager] No API data, using mock fallback")
            threats = MockThreatGenerator.generate_threats(50, turkey_focus=True)

        # Store threats
        with self._lock:
            self._threats = {t.id: t for t in threats}
            self._last_update = datetime.now()

        # Convert to GeoJSON
        geojson = self._to_geojson(threats)

        # Cache the result
        self._cache.set(cache_key, geojson, self.cache_ttl)

        return geojson

    def _fetch_all_threats(self) -> List[ThreatIndicator]:
        """Fetch threats from all available sources"""
        all_threats = []

        for source in self._sources:
            if not source.is_available():
                logger.debug(f"[ThreatIntelligenceManager] Source {source.name} not available")
                continue

            try:
                threats = source.fetch_threats()
                all_threats.extend(threats)
                logger.info(f"[ThreatIntelligenceManager] {source.name}: {len(threats)} threats")
            except Exception as e:
                logger.error(f"[ThreatIntelligenceManager] {source.name} failed: {e}")
                source.record_error(e)

        # Deduplicate by IP
        unique_threats = {}
        for threat in all_threats:
            if threat.ip_address not in unique_threats:
                unique_threats[threat.ip_address] = threat
            else:
                # Merge - keep higher severity
                existing = unique_threats[threat.ip_address]
                severities = [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH,
                             ThreatSeverity.MEDIUM, ThreatSeverity.LOW]
                if severities.index(threat.severity) < severities.index(existing.severity):
                    unique_threats[threat.ip_address] = threat

        return list(unique_threats.values())

    def _to_geojson(self, threats: List[ThreatIndicator]) -> Dict[str, Any]:
        """Convert threats to GeoJSON FeatureCollection"""
        features = []

        for threat in threats:
            feature = threat.to_geojson_feature()
            if feature:
                features.append(feature)

        return {
            "type": "FeatureCollection",
            "features": features,
            "properties": {
                "total_threats": len(features),
                "generated_at": datetime.now().isoformat(),
                "cache_ttl_seconds": self.cache_ttl,
                "cache_age_seconds": 0,
                "sources": [s.name for s in self._sources if s.is_available()]
            }
        }

    def get_threat_stats(self, force_refresh: bool = False) -> ThreatStats:
        """
        Get threat statistics summary.

        Args:
            force_refresh: If True, recalculate from fresh data

        Returns:
            ThreatStats object with aggregated statistics
        """
        cache_key = "threat_stats"

        if not force_refresh:
            cached_stats = self._cache.get(cache_key)
            if cached_stats:
                cached_stats.cache_age_seconds = self._cache.get_age(cache_key)
                return cached_stats

        # Ensure we have threat data
        if not self._threats:
            self.get_live_threats()

        with self._lock:
            threats = list(self._threats.values())

        stats = ThreatStats(
            total_threats=len(threats),
            last_updated=self._last_update
        )

        # Aggregate statistics
        by_category: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        by_country: Dict[str, int] = {}
        by_source: Dict[str, int] = {}
        ip_counts: Dict[str, int] = {}
        port_counts: Dict[int, int] = {}

        for threat in threats:
            # By category
            cat = threat.category.value
            by_category[cat] = by_category.get(cat, 0) + 1

            # By severity
            sev = threat.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1

            # By country
            if threat.geo_location:
                country = threat.geo_location.country_code
                by_country[country] = by_country.get(country, 0) + 1

            # By source
            src = threat.source
            by_source[src] = by_source.get(src, 0) + 1

            # IP attack counts
            ip_counts[threat.ip_address] = ip_counts.get(threat.ip_address, 0) + threat.attack_count

            # Port counts
            if threat.port:
                port_counts[threat.port] = port_counts.get(threat.port, 0) + 1

        stats.by_category = by_category
        stats.by_severity = by_severity
        stats.by_country = by_country
        stats.by_source = by_source

        # Top attacking IPs
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        stats.top_attacking_ips = [
            {"ip": ip, "attack_count": count} for ip, count in sorted_ips
        ]

        # Top targeted ports
        sorted_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        stats.top_targeted_ports = [
            {"port": port, "count": count} for port, count in sorted_ports
        ]

        # Cache stats
        self._cache.set(cache_key, stats, self.cache_ttl)

        return stats

    def get_threats_by_region(self,
                              country_code: str = "TR",
                              include_surrounding: bool = True) -> Dict[str, Any]:
        """
        Get threats filtered by region.

        Args:
            country_code: ISO 2-letter country code (default: TR for Turkey)
            include_surrounding: If True, include threats from surrounding region

        Returns:
            GeoJSON FeatureCollection with filtered threats
        """
        cache_key = f"threats_region_{country_code}_{include_surrounding}"

        cached_data = self._cache.get(cache_key)
        if cached_data:
            cached_data["cache_age_seconds"] = self._cache.get_age(cache_key)
            return cached_data

        # Ensure we have threat data
        if not self._threats:
            self.get_live_threats()

        with self._lock:
            threats = list(self._threats.values())

        # Filter by region
        region_codes = [country_code.upper()]
        if include_surrounding and country_code.upper() == "TR":
            region_codes = self.TURKEY_REGION

        filtered_threats = [
            t for t in threats
            if t.geo_location and t.geo_location.country_code in region_codes
        ]

        # Also include threats targeting the region (based on tags/metadata)
        for threat in threats:
            if threat not in filtered_threats:
                target_region = threat.metadata.get("target_region", "")
                if country_code.upper() == "TR" and "turkey" in target_region.lower():
                    filtered_threats.append(threat)

        geojson = self._to_geojson(filtered_threats)
        geojson["properties"]["region_filter"] = country_code
        geojson["properties"]["include_surrounding"] = include_surrounding

        # Cache result
        self._cache.set(cache_key, geojson, self.cache_ttl)

        return geojson

    def simulate_attack_data(self,
                             num_attacks: int = 25,
                             attack_type: Optional[ThreatCategory] = None,
                             target_region: str = "TR") -> Dict[str, Any]:
        """
        Generate simulated attack data for demo/testing purposes.

        Args:
            num_attacks: Number of attack events to simulate
            attack_type: Specific attack type (None for random mix)
            target_region: Target region code (default: TR for Turkey)

        Returns:
            GeoJSON FeatureCollection with simulated attack data
        """
        threats = []

        for i in range(num_attacks):
            if attack_type:
                category = attack_type
            else:
                category = random.choice(list(ThreatCategory))

            # Generate threat with specific parameters
            threat = MockThreatGenerator._generate_single_threat(
                i,
                turkey_focus=(target_region == "TR")
            )

            # Override category if specified
            if attack_type:
                threat.category = attack_type
                threat.tags = [attack_type.value] + threat.tags[1:]
                threat.description = f"Simulated {attack_type.value} attack"

            threats.append(threat)

        geojson = self._to_geojson(threats)
        geojson["properties"]["simulation"] = True
        geojson["properties"]["attack_type"] = attack_type.value if attack_type else "mixed"
        geojson["properties"]["target_region"] = target_region

        return geojson

    def get_threat_by_ip(self, ip_address: str) -> Optional[ThreatIndicator]:
        """
        Get threat details for a specific IP address.

        Args:
            ip_address: IP address to look up

        Returns:
            ThreatIndicator if found, None otherwise
        """
        # Validate IP
        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            logger.error(f"Invalid IP address: {ip_address}")
            return None

        with self._lock:
            for threat in self._threats.values():
                if threat.ip_address == ip_address:
                    return threat

        return None

    def search_threats(self,
                       query: Optional[str] = None,
                       category: Optional[ThreatCategory] = None,
                       severity: Optional[ThreatSeverity] = None,
                       source: Optional[str] = None,
                       limit: int = 100) -> List[ThreatIndicator]:
        """
        Search threats with filters.

        Args:
            query: Text search in IP, description, tags
            category: Filter by threat category
            severity: Filter by severity level
            source: Filter by data source
            limit: Maximum results to return

        Returns:
            List of matching ThreatIndicator objects
        """
        with self._lock:
            threats = list(self._threats.values())

        results = []

        for threat in threats:
            # Category filter
            if category and threat.category != category:
                continue

            # Severity filter
            if severity and threat.severity != severity:
                continue

            # Source filter
            if source and threat.source != source:
                continue

            # Query filter
            if query:
                query_lower = query.lower()
                searchable = f"{threat.ip_address} {threat.description} {' '.join(threat.tags)}".lower()
                if query_lower not in searchable:
                    continue

            results.append(threat)

            if len(results) >= limit:
                break

        return results

    def clear_cache(self) -> None:
        """Clear all cached data"""
        self._cache.clear()
        logger.info("[ThreatIntelligenceManager] Cache cleared")

    def get_source_status(self) -> List[Dict[str, Any]]:
        """Get status of all threat intelligence sources"""
        statuses = []

        for source in self._sources:
            statuses.append({
                "name": source.name,
                "enabled": source.enabled,
                "available": source.is_available(),
                "last_fetch": source.last_fetch.isoformat() if source.last_fetch else None,
                "error_count": source.error_count,
                "has_api_key": bool(source.api_key) if hasattr(source, 'api_key') else True
            })

        return statuses


# =============================================================================
# SINGLETON INSTANCE
# =============================================================================

_manager_instance: Optional[ThreatIntelligenceManager] = None
_manager_lock = threading.Lock()


def get_threat_intelligence_manager(
    use_mock_fallback: bool = True,
    cache_ttl: int = 300
) -> ThreatIntelligenceManager:
    """
    Get the singleton ThreatIntelligenceManager instance.

    Args:
        use_mock_fallback: If True, use mock data when APIs fail
        cache_ttl: Cache time-to-live in seconds

    Returns:
        ThreatIntelligenceManager instance
    """
    global _manager_instance

    with _manager_lock:
        if _manager_instance is None:
            _manager_instance = ThreatIntelligenceManager(
                use_mock_fallback=use_mock_fallback,
                cache_ttl=cache_ttl
            )
        return _manager_instance


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def get_live_threats(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Convenience function to get live threats.

    Returns:
        GeoJSON FeatureCollection with current threats
    """
    manager = get_threat_intelligence_manager()
    return manager.get_live_threats(force_refresh=force_refresh)


def get_threat_stats(force_refresh: bool = False) -> ThreatStats:
    """
    Convenience function to get threat statistics.

    Returns:
        ThreatStats object
    """
    manager = get_threat_intelligence_manager()
    return manager.get_threat_stats(force_refresh=force_refresh)


def get_threats_by_region(country_code: str = "TR") -> Dict[str, Any]:
    """
    Convenience function to get threats by region.

    Args:
        country_code: ISO 2-letter country code

    Returns:
        GeoJSON FeatureCollection with filtered threats
    """
    manager = get_threat_intelligence_manager()
    return manager.get_threats_by_region(country_code=country_code)


def simulate_attack_data(num_attacks: int = 25) -> Dict[str, Any]:
    """
    Convenience function to generate simulated attack data.

    Args:
        num_attacks: Number of attacks to simulate

    Returns:
        GeoJSON FeatureCollection with simulated data
    """
    manager = get_threat_intelligence_manager()
    return manager.simulate_attack_data(num_attacks=num_attacks)


# =============================================================================
# CLI INTERFACE
# =============================================================================

def main():
    """Command-line interface for the threat intelligence module"""
    import argparse

    parser = argparse.ArgumentParser(
        description="TSUNAMI Live Threat Intelligence Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python live_threats.py --live                    # Get live threats
  python live_threats.py --stats                   # Get statistics
  python live_threats.py --region TR               # Get Turkey region threats
  python live_threats.py --simulate 50             # Simulate 50 attacks
  python live_threats.py --search --query botnet   # Search for botnet threats
  python live_threats.py --status                  # Show source status
        """
    )

    parser.add_argument("--live", action="store_true",
                       help="Get live threat data")
    parser.add_argument("--stats", action="store_true",
                       help="Get threat statistics")
    parser.add_argument("--region", type=str, default=None,
                       help="Filter by region (country code, e.g., TR)")
    parser.add_argument("--simulate", type=int, default=None,
                       help="Simulate N attack events")
    parser.add_argument("--search", action="store_true",
                       help="Search threats")
    parser.add_argument("--query", type=str, default=None,
                       help="Search query string")
    parser.add_argument("--category", type=str, default=None,
                       help="Filter by category")
    parser.add_argument("--severity", type=str, default=None,
                       help="Filter by severity")
    parser.add_argument("--status", action="store_true",
                       help="Show source status")
    parser.add_argument("--force-refresh", action="store_true",
                       help="Bypass cache")
    parser.add_argument("--output", type=str, default=None,
                       help="Output file path (default: stdout)")
    parser.add_argument("--pretty", action="store_true",
                       help="Pretty print JSON output")

    args = parser.parse_args()

    manager = get_threat_intelligence_manager()
    result = None

    try:
        if args.status:
            result = manager.get_source_status()
        elif args.simulate:
            result = manager.simulate_attack_data(num_attacks=args.simulate)
        elif args.search:
            category = ThreatCategory(args.category) if args.category else None
            severity = ThreatSeverity(args.severity) if args.severity else None
            threats = manager.search_threats(
                query=args.query,
                category=category,
                severity=severity
            )
            result = [asdict(t) for t in threats]
        elif args.region:
            result = manager.get_threats_by_region(country_code=args.region)
        elif args.stats:
            stats = manager.get_threat_stats(force_refresh=args.force_refresh)
            result = asdict(stats)
        else:
            # Default: get live threats
            result = manager.get_live_threats(force_refresh=args.force_refresh)

        # Output
        indent = 2 if args.pretty else None
        output_str = json.dumps(result, indent=indent, default=str)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(output_str)
            print(f"Output written to {args.output}")
        else:
            print(output_str)

    except Exception as e:
        logger.error(f"Error: {e}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
