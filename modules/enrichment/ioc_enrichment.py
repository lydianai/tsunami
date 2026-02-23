#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - IOC Enrichment Engine
    Multi-Provider Intelligence: VirusTotal, AbuseIPDB, Shodan
================================================================================

    Features:
    - IOC type auto-detection (IP, domain, hash, URL, email)
    - VirusTotal v3 API integration (files, URLs, IPs, domains)
    - AbuseIPDB v2 API integration (IP reputation)
    - Shodan API integration (host intelligence, ports, vulns)
    - Configurable rate limiting per provider
    - TTL-based caching with SQLite persistence
    - Bulk enrichment with concurrency control
    - Enrichment scoring / reputation aggregation
    - Thread-safe operations
    - Flask Blueprint for REST API
    - Enrichment statistics and audit trail

================================================================================
"""

import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type
from urllib.parse import quote_plus, urlparse

logger = logging.getLogger("tsunami.enrichment.ioc")


# ============================================================================
# Enums and Constants
# ============================================================================

class IOCType(Enum):
    """Indicator of Compromise types."""
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"
    UNKNOWN = "unknown"


class ThreatLevel(Enum):
    """Aggregated threat level from enrichment."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    CLEAN = "clean"
    UNKNOWN = "unknown"

    @property
    def numeric(self) -> int:
        mapping = {
            "critical": 5, "high": 4, "medium": 3,
            "low": 2, "clean": 1, "unknown": 0,
        }
        return mapping.get(self.value, 0)


class ProviderStatus(Enum):
    """Provider health status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"
    DISABLED = "disabled"
    RATE_LIMITED = "rate_limited"


# IOC Type Detection Patterns
IOC_PATTERNS = {
    IOCType.MD5: re.compile(r'^[a-fA-F0-9]{32}$'),
    IOCType.SHA1: re.compile(r'^[a-fA-F0-9]{40}$'),
    IOCType.SHA256: re.compile(r'^[a-fA-F0-9]{64}$'),
    IOCType.EMAIL: re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    ),
    IOCType.URL: re.compile(
        r'^https?://', re.IGNORECASE
    ),
}

DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)


# ============================================================================
# IOC Type Detection
# ============================================================================

def detect_ioc_type(value: str) -> IOCType:
    """Auto-detect IOC type from value string."""
    if not value or not isinstance(value, str):
        return IOCType.UNKNOWN

    value = value.strip()

    # Hash detection (check before IP since hex could match)
    for hash_type in (IOCType.SHA256, IOCType.SHA1, IOCType.MD5):
        if IOC_PATTERNS[hash_type].match(value):
            return hash_type

    # Email
    if IOC_PATTERNS[IOCType.EMAIL].match(value):
        return IOCType.EMAIL

    # URL
    if IOC_PATTERNS[IOCType.URL].match(value):
        return IOCType.URL

    # IP address
    try:
        addr = ipaddress.ip_address(value)
        if isinstance(addr, ipaddress.IPv4Address):
            return IOCType.IPV4
        return IOCType.IPV6
    except ValueError:
        pass

    # Domain
    if DOMAIN_PATTERN.match(value):
        return IOCType.DOMAIN

    return IOCType.UNKNOWN


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ProviderResult:
    """Result from a single enrichment provider."""
    provider: str
    ioc_value: str
    ioc_type: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    found: bool = False
    malicious: bool = False
    score: float = 0.0  # 0.0 (clean) to 100.0 (critical)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    error: Optional[str] = None
    cached: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnrichmentResult:
    """Aggregated enrichment result from all providers."""
    ioc_value: str
    ioc_type: str
    enrichment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    threat_level: str = ThreatLevel.UNKNOWN.value
    aggregate_score: float = 0.0
    providers: List[ProviderResult] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)
    whois: Dict[str, Any] = field(default_factory=dict)
    geo: Dict[str, Any] = field(default_factory=dict)
    ports: List[int] = field(default_factory=list)
    vulns: List[str] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)

    def compute_threat_level(self):
        """Compute aggregated threat level from provider scores."""
        if not self.providers:
            self.threat_level = ThreatLevel.UNKNOWN.value
            self.aggregate_score = 0.0
            return

        scores = [p.score for p in self.providers if not p.error]
        if not scores:
            self.threat_level = ThreatLevel.UNKNOWN.value
            self.aggregate_score = 0.0
            return

        # Weighted average — malicious detections weight more
        malicious_count = sum(1 for p in self.providers if p.malicious and not p.error)
        total_valid = sum(1 for p in self.providers if not p.error)

        self.aggregate_score = max(scores) if malicious_count > 0 else sum(scores) / len(scores)

        # Aggregate all tags
        for p in self.providers:
            self.tags.update(p.tags)

        # Determine threat level
        if self.aggregate_score >= 80:
            self.threat_level = ThreatLevel.CRITICAL.value
        elif self.aggregate_score >= 60:
            self.threat_level = ThreatLevel.HIGH.value
        elif self.aggregate_score >= 40:
            self.threat_level = ThreatLevel.MEDIUM.value
        elif self.aggregate_score >= 15:
            self.threat_level = ThreatLevel.LOW.value
        elif total_valid > 0:
            self.threat_level = ThreatLevel.CLEAN.value
        else:
            self.threat_level = ThreatLevel.UNKNOWN.value

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "enrichment_id": self.enrichment_id,
            "timestamp": self.timestamp,
            "threat_level": self.threat_level,
            "aggregate_score": self.aggregate_score,
            "providers": [p.to_dict() for p in self.providers],
            "tags": sorted(self.tags),
            "whois": self.whois,
            "geo": self.geo,
            "ports": self.ports,
            "vulns": self.vulns,
            "related_iocs": self.related_iocs,
        }
        return d


@dataclass
class RateLimitState:
    """Rate limiter state for a provider."""
    requests_per_minute: int = 4
    requests_per_day: int = 500
    minute_count: int = 0
    day_count: int = 0
    minute_reset: float = 0.0
    day_reset: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def can_request(self) -> bool:
        now = time.time()
        with self.lock:
            if now > self.minute_reset:
                self.minute_count = 0
                self.minute_reset = now + 60.0
            if now > self.day_reset:
                self.day_count = 0
                self.day_reset = now + 86400.0

            if self.minute_count >= self.requests_per_minute:
                return False
            if self.day_count >= self.requests_per_day:
                return False
            return True

    def record_request(self):
        now = time.time()
        with self.lock:
            if now > self.minute_reset:
                self.minute_count = 0
                self.minute_reset = now + 60.0
            if now > self.day_reset:
                self.day_count = 0
                self.day_reset = now + 86400.0
            self.minute_count += 1
            self.day_count += 1


# ============================================================================
# Enrichment Cache (SQLite)
# ============================================================================

class EnrichmentCache:
    """SQLite-backed TTL cache for enrichment results."""

    def __init__(self, db_path: Optional[str] = None, default_ttl: int = 3600):
        if db_path is None:
            cache_dir = Path.home() / ".dalga"
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(cache_dir / "enrichment_cache.db")

        self.db_path = db_path
        self.default_ttl = default_ttl
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    cache_key TEXT PRIMARY KEY,
                    ioc_value TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    ttl INTEGER NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_cache_ioc
                ON cache(ioc_value, provider)
            """)
            conn.commit()
            conn.close()

    def _make_key(self, ioc_value: str, provider: str) -> str:
        return hashlib.sha256(f"{provider}:{ioc_value}".encode()).hexdigest()

    def get(self, ioc_value: str, provider: str) -> Optional[ProviderResult]:
        key = self._make_key(ioc_value, provider)
        now = time.time()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            row = conn.execute(
                "SELECT result_json, created_at, ttl FROM cache WHERE cache_key = ?",
                (key,)
            ).fetchone()
            conn.close()

        if not row:
            return None

        result_json, created_at, ttl = row
        if now - created_at > ttl:
            self.delete(ioc_value, provider)
            return None

        try:
            data = json.loads(result_json)
            result = ProviderResult(**data)
            result.cached = True
            return result
        except (json.JSONDecodeError, TypeError):
            return None

    def set(self, ioc_value: str, provider: str, result: ProviderResult,
            ttl: Optional[int] = None):
        key = self._make_key(ioc_value, provider)
        if ttl is None:
            ttl = self.default_ttl

        ioc_type = result.ioc_type
        result_dict = result.to_dict()
        result_json = json.dumps(result_dict, default=str)

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """INSERT OR REPLACE INTO cache
                   (cache_key, ioc_value, ioc_type, provider, result_json, created_at, ttl)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (key, ioc_value, ioc_type, provider, result_json, time.time(), ttl)
            )
            conn.commit()
            conn.close()

    def delete(self, ioc_value: str, provider: str):
        key = self._make_key(ioc_value, provider)
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM cache WHERE cache_key = ?", (key,))
            conn.commit()
            conn.close()

    def clear(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("DELETE FROM cache")
            conn.commit()
            conn.close()

    def clear_expired(self) -> int:
        now = time.time()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                "DELETE FROM cache WHERE (? - created_at) > ttl", (now,)
            )
            count = cursor.rowcount
            conn.commit()
            conn.close()
        return count

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            total = conn.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            expired = conn.execute(
                "SELECT COUNT(*) FROM cache WHERE (? - created_at) > ttl", (now,)
            ).fetchone()[0]
            conn.close()
        return {"total": total, "active": total - expired, "expired": expired}


# ============================================================================
# Provider Base Class
# ============================================================================

class EnrichmentProvider(ABC):
    """Abstract base class for IOC enrichment providers."""

    NAME: str = "base"
    SUPPORTED_TYPES: Set[IOCType] = set()

    def __init__(self, api_key: Optional[str] = None, enabled: bool = True,
                 rate_limit_rpm: int = 4, rate_limit_daily: int = 500,
                 timeout: int = 30):
        self.api_key = api_key
        self.enabled = enabled
        self.timeout = timeout
        self.rate_limiter = RateLimitState(
            requests_per_minute=rate_limit_rpm,
            requests_per_day=rate_limit_daily,
        )
        self._status = ProviderStatus.HEALTHY if api_key else ProviderStatus.DISABLED
        self._error_count = 0
        self._success_count = 0
        self._last_error: Optional[str] = None

    @property
    def status(self) -> ProviderStatus:
        if not self.api_key or not self.enabled:
            return ProviderStatus.DISABLED
        if not self.rate_limiter.can_request():
            return ProviderStatus.RATE_LIMITED
        return self._status

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in self.SUPPORTED_TYPES

    @abstractmethod
    def enrich(self, ioc_value: str, ioc_type: IOCType) -> ProviderResult:
        """Enrich an IOC. Must be implemented by subclasses."""
        pass

    def safe_enrich(self, ioc_value: str, ioc_type: IOCType) -> ProviderResult:
        """Enrich with error handling and rate limiting."""
        if not self.enabled or not self.api_key:
            return ProviderResult(
                provider=self.NAME,
                ioc_value=ioc_value,
                ioc_type=ioc_type.value,
                error="Provider disabled or no API key",
            )

        if not self.supports(ioc_type):
            return ProviderResult(
                provider=self.NAME,
                ioc_value=ioc_value,
                ioc_type=ioc_type.value,
                error=f"IOC type {ioc_type.value} not supported",
            )

        if not self.rate_limiter.can_request():
            self._status = ProviderStatus.RATE_LIMITED
            return ProviderResult(
                provider=self.NAME,
                ioc_value=ioc_value,
                ioc_type=ioc_type.value,
                error="Rate limit exceeded",
            )

        try:
            self.rate_limiter.record_request()
            result = self.enrich(ioc_value, ioc_type)
            self._success_count += 1
            self._error_count = max(0, self._error_count - 1)
            self._status = ProviderStatus.HEALTHY
            return result
        except Exception as e:
            self._error_count += 1
            self._last_error = str(e)
            if self._error_count >= 5:
                self._status = ProviderStatus.DOWN
            else:
                self._status = ProviderStatus.DEGRADED
            logger.error("Provider %s error for %s: %s", self.NAME, ioc_value, e)
            return ProviderResult(
                provider=self.NAME,
                ioc_value=ioc_value,
                ioc_type=ioc_type.value,
                error=str(e),
            )

    def health(self) -> Dict[str, Any]:
        return {
            "name": self.NAME,
            "status": self.status.value,
            "enabled": self.enabled,
            "has_api_key": bool(self.api_key),
            "success_count": self._success_count,
            "error_count": self._error_count,
            "last_error": self._last_error,
            "supported_types": [t.value for t in self.SUPPORTED_TYPES],
        }


# ============================================================================
# VirusTotal Provider
# ============================================================================

class VirusTotalProvider(EnrichmentProvider):
    """VirusTotal v3 API integration."""

    NAME = "virustotal"
    API_BASE = "https://www.virustotal.com/api/v3"
    SUPPORTED_TYPES = {
        IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN,
        IOCType.URL, IOCType.MD5, IOCType.SHA1, IOCType.SHA256,
    }

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        if api_key is None:
            api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        super().__init__(api_key=api_key, rate_limit_rpm=4, rate_limit_daily=500, **kwargs)

    def enrich(self, ioc_value: str, ioc_type: IOCType) -> ProviderResult:
        import urllib.request
        import urllib.error

        endpoint = self._get_endpoint(ioc_value, ioc_type)
        if not endpoint:
            return ProviderResult(
                provider=self.NAME, ioc_value=ioc_value,
                ioc_type=ioc_type.value, error="Unsupported type",
            )

        req = urllib.request.Request(endpoint)
        req.add_header("x-apikey", self.api_key)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ProviderResult(
                    provider=self.NAME, ioc_value=ioc_value,
                    ioc_type=ioc_type.value, found=False,
                )
            raise

        return self._parse_response(data, ioc_value, ioc_type)

    def _get_endpoint(self, ioc_value: str, ioc_type: IOCType) -> Optional[str]:
        if ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            return f"{self.API_BASE}/files/{ioc_value}"
        elif ioc_type in (IOCType.IPV4, IOCType.IPV6):
            return f"{self.API_BASE}/ip_addresses/{ioc_value}"
        elif ioc_type == IOCType.DOMAIN:
            return f"{self.API_BASE}/domains/{ioc_value}"
        elif ioc_type == IOCType.URL:
            url_id = hashlib.sha256(ioc_value.encode()).hexdigest()
            return f"{self.API_BASE}/urls/{url_id}"
        return None

    def _parse_response(self, data: Dict, ioc_value: str,
                        ioc_type: IOCType) -> ProviderResult:
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless

        score = 0.0
        if total > 0:
            score = ((malicious * 100 + suspicious * 50) / total)
            score = min(100.0, score)

        tags = []
        if malicious > 0:
            tags.append("malicious")
        if suspicious > 0:
            tags.append("suspicious")
        popular_threat = attrs.get("popular_threat_classification", {})
        if popular_threat:
            label = popular_threat.get("suggested_threat_label", "")
            if label:
                tags.append(label)

        # Extract additional info based on type
        raw = {
            "malicious": malicious,
            "suspicious": suspicious,
            "undetected": undetected,
            "harmless": harmless,
            "total_engines": total,
            "reputation": attrs.get("reputation", 0),
        }

        if ioc_type in (IOCType.IPV4, IOCType.IPV6):
            raw["country"] = attrs.get("country", "")
            raw["as_owner"] = attrs.get("as_owner", "")
            raw["asn"] = attrs.get("asn", 0)
            raw["network"] = attrs.get("network", "")

        elif ioc_type == IOCType.DOMAIN:
            raw["registrar"] = attrs.get("registrar", "")
            raw["creation_date"] = attrs.get("creation_date", 0)
            raw["categories"] = attrs.get("categories", {})

        elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            raw["type_description"] = attrs.get("type_description", "")
            raw["size"] = attrs.get("size", 0)
            raw["names"] = attrs.get("names", [])[:5]
            raw["sha256"] = attrs.get("sha256", "")
            raw["md5"] = attrs.get("md5", "")

        return ProviderResult(
            provider=self.NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
            found=True,
            malicious=malicious > 0,
            score=round(score, 2),
            raw_data=raw,
            tags=tags,
        )


# ============================================================================
# AbuseIPDB Provider
# ============================================================================

class AbuseIPDBProvider(EnrichmentProvider):
    """AbuseIPDB v2 API integration for IP reputation."""

    NAME = "abuseipdb"
    API_BASE = "https://api.abuseipdb.com/api/v2"
    SUPPORTED_TYPES = {IOCType.IPV4, IOCType.IPV6}

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        if api_key is None:
            api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
        super().__init__(api_key=api_key, rate_limit_rpm=60, rate_limit_daily=1000, **kwargs)

    def enrich(self, ioc_value: str, ioc_type: IOCType) -> ProviderResult:
        import urllib.request
        import urllib.error
        import urllib.parse

        params = urllib.parse.urlencode({
            "ipAddress": ioc_value,
            "maxAgeInDays": 90,
            "verbose": "",
        })
        url = f"{self.API_BASE}/check?{params}"

        req = urllib.request.Request(url)
        req.add_header("Key", self.api_key)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ProviderResult(
                    provider=self.NAME, ioc_value=ioc_value,
                    ioc_type=ioc_type.value, found=False,
                )
            raise

        return self._parse_response(data, ioc_value, ioc_type)

    def _parse_response(self, data: Dict, ioc_value: str,
                        ioc_type: IOCType) -> ProviderResult:
        info = data.get("data", {})
        abuse_score = info.get("abuseConfidenceScore", 0)
        total_reports = info.get("totalReports", 0)
        is_public = info.get("isPublic", True)
        is_whitelisted = info.get("isWhitelisted", False)

        tags = []
        if abuse_score >= 75:
            tags.append("high-abuse")
        elif abuse_score >= 25:
            tags.append("moderate-abuse")
        if total_reports > 0:
            tags.append("reported")
        if is_whitelisted:
            tags.append("whitelisted")
        if info.get("isTor", False):
            tags.append("tor-exit")

        # Map categories
        categories = set()
        for report in info.get("reports", [])[:10]:
            for cat in report.get("categories", []):
                categories.add(cat)

        category_names = {
            1: "dns-compromise", 2: "dns-poisoning", 3: "fraud-orders",
            4: "ddos-attack", 5: "ftp-brute-force", 6: "ping-of-death",
            7: "phishing", 8: "fraud-voip", 9: "open-proxy",
            10: "web-spam", 11: "email-spam", 13: "ping-pong",
            14: "brute-force", 15: "bad-web-bot", 16: "exploited-host",
            17: "web-app-attack", 18: "ssh-attack", 19: "iot-targeted",
            20: "credential-stuffing", 21: "data-scraping",
            22: "port-scan", 23: "hacking",
        }
        for cat_id in categories:
            cat_name = category_names.get(cat_id)
            if cat_name:
                tags.append(cat_name)

        raw = {
            "abuse_confidence_score": abuse_score,
            "total_reports": total_reports,
            "is_public": is_public,
            "is_whitelisted": is_whitelisted,
            "is_tor": info.get("isTor", False),
            "country_code": info.get("countryCode", ""),
            "isp": info.get("isp", ""),
            "domain": info.get("domain", ""),
            "usage_type": info.get("usageType", ""),
            "num_distinct_users": info.get("numDistinctUsers", 0),
            "last_reported_at": info.get("lastReportedAt", ""),
            "attack_categories": sorted(categories),
        }

        return ProviderResult(
            provider=self.NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
            found=True,
            malicious=abuse_score >= 50,
            score=float(abuse_score),
            raw_data=raw,
            tags=tags,
        )


# ============================================================================
# Shodan Provider
# ============================================================================

class ShodanProvider(EnrichmentProvider):
    """Shodan API integration for host intelligence."""

    NAME = "shodan"
    API_BASE = "https://api.shodan.io"
    SUPPORTED_TYPES = {IOCType.IPV4, IOCType.DOMAIN}

    def __init__(self, api_key: Optional[str] = None, **kwargs):
        if api_key is None:
            api_key = os.environ.get("SHODAN_API_KEY", "")
        super().__init__(api_key=api_key, rate_limit_rpm=1, rate_limit_daily=100, **kwargs)

    def enrich(self, ioc_value: str, ioc_type: IOCType) -> ProviderResult:
        import urllib.request
        import urllib.error

        if ioc_type == IOCType.DOMAIN:
            url = f"{self.API_BASE}/dns/resolve?hostnames={ioc_value}&key={self.api_key}"
        else:
            url = f"{self.API_BASE}/shodan/host/{ioc_value}?key={self.api_key}"

        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return ProviderResult(
                    provider=self.NAME, ioc_value=ioc_value,
                    ioc_type=ioc_type.value, found=False,
                )
            raise

        if ioc_type == IOCType.DOMAIN:
            return self._parse_domain_response(data, ioc_value, ioc_type)
        return self._parse_host_response(data, ioc_value, ioc_type)

    def _parse_host_response(self, data: Dict, ioc_value: str,
                             ioc_type: IOCType) -> ProviderResult:
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        tags_list = data.get("tags", [])
        os_name = data.get("os", "")

        score = 0.0
        tags = list(tags_list) if tags_list else []

        # Score based on exposed services and vulnerabilities
        if vulns:
            cve_count = len(vulns)
            score = min(100.0, 30.0 + cve_count * 10)
            tags.append("vulnerable")
            # Check for critical CVEs
            for v in vulns[:5]:
                tags.append(v)

        # High-risk ports
        high_risk_ports = {21, 23, 25, 445, 1433, 3306, 3389, 5900, 6379, 9200, 27017}
        exposed_risky = set(ports) & high_risk_ports
        if exposed_risky:
            score = max(score, 20.0 + len(exposed_risky) * 5)
            tags.append("high-risk-ports")

        if len(ports) > 20:
            tags.append("many-open-ports")

        raw = {
            "ports": ports,
            "vulns": vulns[:20],
            "os": os_name,
            "org": data.get("org", ""),
            "isp": data.get("isp", ""),
            "asn": data.get("asn", ""),
            "city": data.get("city", ""),
            "country_code": data.get("country_code", ""),
            "country_name": data.get("country_name", ""),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "hostnames": data.get("hostnames", []),
            "domains": data.get("domains", []),
            "last_update": data.get("last_update", ""),
        }

        return ProviderResult(
            provider=self.NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
            found=True,
            malicious=score >= 50,
            score=round(score, 2),
            raw_data=raw,
            tags=tags,
        )

    def _parse_domain_response(self, data: Dict, ioc_value: str,
                               ioc_type: IOCType) -> ProviderResult:
        resolved_ip = data.get(ioc_value)
        raw = {"resolved_ip": resolved_ip, "query": ioc_value}

        return ProviderResult(
            provider=self.NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
            found=resolved_ip is not None,
            score=0.0,
            raw_data=raw,
            tags=["dns-resolved"] if resolved_ip else [],
        )


# ============================================================================
# IOC Enrichment Engine
# ============================================================================

class IOCEnrichmentEngine:
    """
    Main enrichment orchestrator.

    Combines results from multiple providers, caches results, and provides
    aggregated threat intelligence for IOCs.
    """

    def __init__(self, cache: Optional[EnrichmentCache] = None,
                 providers: Optional[List[EnrichmentProvider]] = None):
        self.cache = cache or EnrichmentCache()
        self.providers: List[EnrichmentProvider] = providers or []
        self._lock = threading.Lock()
        self._stats = {
            "total_enrichments": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "provider_calls": 0,
            "provider_errors": 0,
            "by_type": {},
            "by_provider": {},
            "by_threat_level": {},
        }

    def register_provider(self, provider: EnrichmentProvider):
        """Register an enrichment provider."""
        with self._lock:
            # Prevent duplicates
            existing = [p for p in self.providers if p.NAME == provider.NAME]
            if existing:
                self.providers = [
                    p for p in self.providers if p.NAME != provider.NAME
                ]
            self.providers.append(provider)
            logger.info("Registered provider: %s", provider.NAME)

    def remove_provider(self, name: str) -> bool:
        """Remove a provider by name."""
        with self._lock:
            before = len(self.providers)
            self.providers = [p for p in self.providers if p.NAME != name]
            return len(self.providers) < before

    def enrich(self, ioc_value: str, ioc_type: Optional[IOCType] = None,
               providers: Optional[List[str]] = None,
               skip_cache: bool = False) -> EnrichmentResult:
        """
        Enrich a single IOC across all applicable providers.

        Args:
            ioc_value: The IOC value to enrich
            ioc_type: Explicit IOC type (auto-detected if None)
            providers: Optional list of provider names to query
            skip_cache: Force fresh lookups

        Returns:
            EnrichmentResult with aggregated intelligence
        """
        if ioc_type is None:
            ioc_type = detect_ioc_type(ioc_value)

        result = EnrichmentResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
        )

        # Get applicable providers
        applicable = self._get_applicable_providers(ioc_type, providers)

        for provider in applicable:
            provider_result = self._enrich_with_provider(
                provider, ioc_value, ioc_type, skip_cache
            )
            result.providers.append(provider_result)

            # Extract geo/port/vuln data from Shodan
            if provider.NAME == "shodan" and not provider_result.error:
                raw = provider_result.raw_data
                if raw.get("latitude") is not None:
                    result.geo = {
                        "city": raw.get("city", ""),
                        "country_code": raw.get("country_code", ""),
                        "country_name": raw.get("country_name", ""),
                        "latitude": raw.get("latitude"),
                        "longitude": raw.get("longitude"),
                    }
                result.ports = raw.get("ports", [])
                result.vulns = raw.get("vulns", [])

            # Extract geo from AbuseIPDB
            if provider.NAME == "abuseipdb" and not provider_result.error:
                raw = provider_result.raw_data
                if not result.geo and raw.get("country_code"):
                    result.geo = {"country_code": raw.get("country_code", "")}
                result.whois = {
                    "isp": raw.get("isp", ""),
                    "domain": raw.get("domain", ""),
                    "usage_type": raw.get("usage_type", ""),
                }

            # Extract file info from VirusTotal
            if provider.NAME == "virustotal" and not provider_result.error:
                raw = provider_result.raw_data
                if raw.get("country"):
                    if not result.geo:
                        result.geo = {"country_code": raw.get("country", "")}
                if raw.get("as_owner"):
                    result.whois["as_owner"] = raw["as_owner"]
                    result.whois["asn"] = raw.get("asn", 0)

        # Compute aggregated threat level
        result.compute_threat_level()

        # Update stats
        with self._lock:
            self._stats["total_enrichments"] += 1
            type_key = ioc_type.value
            self._stats["by_type"][type_key] = self._stats["by_type"].get(type_key, 0) + 1
            tl_key = result.threat_level
            self._stats["by_threat_level"][tl_key] = self._stats["by_threat_level"].get(tl_key, 0) + 1

        return result

    def enrich_bulk(self, iocs: List[str], max_concurrent: int = 5,
                    skip_cache: bool = False) -> List[EnrichmentResult]:
        """
        Enrich multiple IOCs with concurrency control.

        Args:
            iocs: List of IOC values
            max_concurrent: Maximum concurrent enrichments
            skip_cache: Force fresh lookups

        Returns:
            List of EnrichmentResult objects
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed

        results = []
        with ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            future_map = {
                executor.submit(self.enrich, ioc, skip_cache=skip_cache): ioc
                for ioc in iocs
            }
            for future in as_completed(future_map):
                ioc = future_map[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    logger.error("Bulk enrichment error for %s: %s", ioc, e)
                    results.append(EnrichmentResult(
                        ioc_value=ioc,
                        ioc_type=detect_ioc_type(ioc).value,
                        threat_level=ThreatLevel.UNKNOWN.value,
                    ))
        return results

    def _get_applicable_providers(self, ioc_type: IOCType,
                                  provider_names: Optional[List[str]]) -> List[EnrichmentProvider]:
        applicable = []
        for p in self.providers:
            if not p.enabled:
                continue
            if not p.supports(ioc_type):
                continue
            if provider_names and p.NAME not in provider_names:
                continue
            applicable.append(p)
        return applicable

    def _enrich_with_provider(self, provider: EnrichmentProvider,
                              ioc_value: str, ioc_type: IOCType,
                              skip_cache: bool) -> ProviderResult:
        # Check cache first
        if not skip_cache:
            cached = self.cache.get(ioc_value, provider.NAME)
            if cached is not None:
                with self._lock:
                    self._stats["cache_hits"] += 1
                return cached

        with self._lock:
            self._stats["cache_misses"] += 1
            self._stats["provider_calls"] += 1
            prov_key = provider.NAME
            self._stats["by_provider"][prov_key] = self._stats["by_provider"].get(prov_key, 0) + 1

        result = provider.safe_enrich(ioc_value, ioc_type)

        if result.error:
            with self._lock:
                self._stats["provider_errors"] += 1
        else:
            # Cache successful results
            self.cache.set(ioc_value, provider.NAME, result)

        return result

    def provider_health(self) -> List[Dict[str, Any]]:
        """Get health status of all providers."""
        return [p.health() for p in self.providers]

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "providers": len(self.providers),
                "active_providers": sum(
                    1 for p in self.providers
                    if p.status not in (ProviderStatus.DISABLED, ProviderStatus.DOWN)
                ),
                "cache": self.cache.stats(),
            }


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_enrichment_blueprint(engine: Optional[IOCEnrichmentEngine] = None):
    """Create Flask blueprint for IOC enrichment API."""
    try:
        from flask import Blueprint, request, jsonify
    except ImportError:
        logger.warning("Flask not available — enrichment blueprint disabled")
        return None

    bp = Blueprint("ioc_enrichment", __name__, url_prefix="/api/v1/soc/enrich")

    def get_engine() -> IOCEnrichmentEngine:
        return engine or get_enrichment_engine()

    @bp.route("/status", methods=["GET"])
    def status():
        eng = get_engine()
        return jsonify({
            "status": "operational",
            "stats": eng.stats,
            "providers": eng.provider_health(),
        })

    @bp.route("/ioc", methods=["POST"])
    def enrich_ioc():
        data = request.get_json(silent=True) or {}
        ioc_value = data.get("ioc") or data.get("value")
        if not ioc_value:
            return jsonify({"error": "Missing 'ioc' field"}), 400

        ioc_type_str = data.get("type")
        ioc_type = None
        if ioc_type_str:
            try:
                ioc_type = IOCType(ioc_type_str)
            except ValueError:
                pass

        providers = data.get("providers")
        skip_cache = data.get("skip_cache", False)

        eng = get_engine()
        result = eng.enrich(ioc_value, ioc_type=ioc_type,
                           providers=providers, skip_cache=skip_cache)
        return jsonify(result.to_dict())

    @bp.route("/bulk", methods=["POST"])
    def enrich_bulk():
        data = request.get_json(silent=True) or {}
        iocs = data.get("iocs", [])
        if not iocs:
            return jsonify({"error": "Missing 'iocs' list"}), 400
        if len(iocs) > 100:
            return jsonify({"error": "Maximum 100 IOCs per request"}), 400

        skip_cache = data.get("skip_cache", False)
        max_concurrent = min(data.get("max_concurrent", 5), 10)

        eng = get_engine()
        results = eng.enrich_bulk(iocs, max_concurrent=max_concurrent,
                                 skip_cache=skip_cache)
        return jsonify({
            "count": len(results),
            "results": [r.to_dict() for r in results],
        })

    @bp.route("/detect-type", methods=["POST"])
    def detect_type():
        data = request.get_json(silent=True) or {}
        value = data.get("value", "")
        if not value:
            return jsonify({"error": "Missing 'value' field"}), 400

        ioc_type = detect_ioc_type(value)
        return jsonify({
            "value": value,
            "type": ioc_type.value,
        })

    @bp.route("/cache/clear", methods=["POST"])
    def clear_cache():
        eng = get_engine()
        eng.cache.clear()
        return jsonify({"status": "cleared"})

    @bp.route("/cache/stats", methods=["GET"])
    def cache_stats():
        eng = get_engine()
        return jsonify(eng.cache.stats())

    @bp.route("/providers", methods=["GET"])
    def list_providers():
        eng = get_engine()
        return jsonify({
            "providers": eng.provider_health(),
        })

    return bp


# ============================================================================
# Global Singleton
# ============================================================================

_engine_instance: Optional[IOCEnrichmentEngine] = None
_engine_lock = threading.Lock()


def get_enrichment_engine() -> IOCEnrichmentEngine:
    """Get or create the global enrichment engine singleton."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                engine = IOCEnrichmentEngine()

                # Auto-register providers from environment
                vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
                if vt_key:
                    engine.register_provider(VirusTotalProvider(api_key=vt_key))

                abuse_key = os.environ.get("ABUSEIPDB_API_KEY", "")
                if abuse_key:
                    engine.register_provider(AbuseIPDBProvider(api_key=abuse_key))

                shodan_key = os.environ.get("SHODAN_API_KEY", "")
                if shodan_key:
                    engine.register_provider(ShodanProvider(api_key=shodan_key))

                _engine_instance = engine
                logger.info("IOC Enrichment Engine initialized with %d providers",
                           len(engine.providers))
    return _engine_instance
