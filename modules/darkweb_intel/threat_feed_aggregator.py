#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Threat Feed Aggregator
    Aggregate real threat intelligence from multiple free sources
================================================================================

    Integrated Feeds:
    - URLhaus (abuse.ch) - Malicious URLs
    - ThreatFox (abuse.ch) - IOCs and malware
    - MalwareBazaar (abuse.ch) - Malware samples
    - PhishTank - Phishing URLs
    - OpenPhish - Phishing feed
    - FeodoTracker (abuse.ch) - Botnet C&C
    - SSL Blacklist (abuse.ch) - Malicious SSL certificates

================================================================================
"""

import os
import time
import json
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List, Set, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatFeedType(Enum):
    """Types of threat feeds"""
    URL = "url"
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    IOC = "ioc"
    PHISHING = "phishing"
    MALWARE = "malware"
    BOTNET = "botnet"
    SSL = "ssl"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ThreatFeed:
    """Threat feed configuration"""
    name: str
    url: str
    feed_type: ThreatFeedType
    enabled: bool = True
    interval: int = 3600  # Update interval in seconds
    api_key: Optional[str] = None
    last_update: Optional[datetime] = None
    ioc_count: int = 0
    status: str = "unknown"
    error_count: int = 0


@dataclass
class ThreatIOC:
    """Individual Indicator of Compromise"""
    value: str
    ioc_type: str
    source: str
    severity: ThreatSeverity
    confidence: float = 0.8
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    malware_family: Optional[str] = None
    threat_type: Optional[str] = None
    reporter: Optional[str] = None
    reference_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class URLhausClient:
    """
    URLhaus API client (abuse.ch)
    Database of malicious URLs used for malware distribution
    """

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-ThreatIntel/5.0",
            "Accept": "application/json"
        })

    def get_recent_urls(self, limit: int = 1000) -> List[ThreatIOC]:
        """Get recent malicious URLs"""
        try:
            response = self._session.get(
                f"{self.BASE_URL}/urls/recent/",
                params={"limit": limit},
                timeout=60
            )
            response.raise_for_status()
            data = response.json()

            iocs = []
            for url_data in data.get("urls", []):
                ioc = ThreatIOC(
                    value=url_data.get("url", ""),
                    ioc_type="url",
                    source="urlhaus",
                    severity=ThreatSeverity.HIGH,
                    confidence=0.9,
                    first_seen=datetime.fromisoformat(url_data["dateadded"].replace("Z", "+00:00")) if url_data.get("dateadded") else None,
                    tags=url_data.get("tags", []),
                    threat_type=url_data.get("threat", ""),
                    reporter=url_data.get("reporter", ""),
                    reference_url=url_data.get("urlhaus_reference", ""),
                    metadata={
                        "url_status": url_data.get("url_status", ""),
                        "host": url_data.get("host", ""),
                        "url_id": url_data.get("id", "")
                    }
                )
                iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[URLhaus] Error fetching recent URLs: {e}")
            return []

    def query_url(self, url: str) -> Optional[ThreatIOC]:
        """Query a specific URL"""
        try:
            response = self._session.post(
                f"{self.BASE_URL}/url/",
                data={"url": url},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "ok":
                return ThreatIOC(
                    value=url,
                    ioc_type="url",
                    source="urlhaus",
                    severity=ThreatSeverity.HIGH,
                    confidence=0.95,
                    first_seen=datetime.fromisoformat(data["dateadded"].replace("Z", "+00:00")) if data.get("dateadded") else None,
                    tags=data.get("tags", []),
                    threat_type=data.get("threat", ""),
                    metadata={
                        "url_status": data.get("url_status", ""),
                        "blacklists": data.get("blacklists", {}),
                        "payloads": data.get("payloads", [])
                    }
                )
            return None

        except Exception as e:
            logger.error(f"[URLhaus] Error querying URL: {e}")
            return None

    def query_host(self, host: str) -> List[ThreatIOC]:
        """Query by host (IP or domain)"""
        try:
            response = self._session.post(
                f"{self.BASE_URL}/host/",
                data={"host": host},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            iocs = []
            if data.get("query_status") == "ok":
                for url_data in data.get("urls", []):
                    ioc = ThreatIOC(
                        value=url_data.get("url", ""),
                        ioc_type="url",
                        source="urlhaus",
                        severity=ThreatSeverity.HIGH,
                        confidence=0.9,
                        tags=url_data.get("tags", []),
                        threat_type=url_data.get("threat", ""),
                        metadata={"host": host}
                    )
                    iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[URLhaus] Error querying host: {e}")
            return []


class ThreatFoxClient:
    """
    ThreatFox API client (abuse.ch)
    IOC sharing platform for malware
    """

    BASE_URL = "https://threatfox-api.abuse.ch/api/v1"

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-ThreatIntel/5.0",
            "Content-Type": "application/json"
        })

    def get_recent_iocs(self, days: int = 1) -> List[ThreatIOC]:
        """Get recent IOCs"""
        try:
            response = self._session.post(
                f"{self.BASE_URL}/",
                json={"query": "get_iocs", "days": days},
                timeout=60
            )
            response.raise_for_status()
            data = response.json()

            iocs = []
            if data.get("query_status") == "ok":
                for ioc_data in data.get("data", []):
                    ioc_type = ioc_data.get("ioc_type", "").lower()
                    if "ip" in ioc_type:
                        ioc_type = "ip"
                    elif "domain" in ioc_type:
                        ioc_type = "domain"
                    elif "url" in ioc_type:
                        ioc_type = "url"
                    elif "hash" in ioc_type:
                        ioc_type = "hash"

                    ioc = ThreatIOC(
                        value=ioc_data.get("ioc", ""),
                        ioc_type=ioc_type,
                        source="threatfox",
                        severity=ThreatSeverity.HIGH,
                        confidence=float(ioc_data.get("confidence_level", 75)) / 100,
                        first_seen=datetime.fromisoformat(ioc_data["first_seen_utc"].replace(" ", "T")) if ioc_data.get("first_seen_utc") else None,
                        last_seen=datetime.fromisoformat(ioc_data["last_seen_utc"].replace(" ", "T")) if ioc_data.get("last_seen_utc") else None,
                        tags=ioc_data.get("tags", []),
                        malware_family=ioc_data.get("malware", ""),
                        threat_type=ioc_data.get("threat_type", ""),
                        reporter=ioc_data.get("reporter", ""),
                        reference_url=ioc_data.get("reference", ""),
                        metadata={
                            "malware_printable": ioc_data.get("malware_printable", ""),
                            "ioc_id": ioc_data.get("id", "")
                        }
                    )
                    iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[ThreatFox] Error fetching IOCs: {e}")
            return []

    def search_ioc(self, search_term: str) -> List[ThreatIOC]:
        """Search for an IOC"""
        try:
            response = self._session.post(
                f"{self.BASE_URL}/",
                json={"query": "search_ioc", "search_term": search_term},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            iocs = []
            if data.get("query_status") == "ok":
                for ioc_data in data.get("data", []):
                    ioc = ThreatIOC(
                        value=ioc_data.get("ioc", ""),
                        ioc_type=ioc_data.get("ioc_type", "").lower(),
                        source="threatfox",
                        severity=ThreatSeverity.HIGH,
                        confidence=float(ioc_data.get("confidence_level", 75)) / 100,
                        malware_family=ioc_data.get("malware", ""),
                        threat_type=ioc_data.get("threat_type", "")
                    )
                    iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[ThreatFox] Error searching IOC: {e}")
            return []


class MalwareBazaarClient:
    """
    MalwareBazaar API client (abuse.ch)
    Malware sample sharing platform
    """

    BASE_URL = "https://mb-api.abuse.ch/api/v1"

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-ThreatIntel/5.0"
        })

    def get_recent_samples(self, limit: int = 100) -> List[ThreatIOC]:
        """Get recent malware samples"""
        try:
            response = self._session.post(
                f"{self.BASE_URL}/",
                data={"query": "get_recent", "selector": limit},
                timeout=60
            )
            response.raise_for_status()
            data = response.json()

            iocs = []
            if data.get("query_status") == "ok":
                for sample in data.get("data", []):
                    # Add SHA256 hash
                    ioc = ThreatIOC(
                        value=sample.get("sha256_hash", ""),
                        ioc_type="hash_sha256",
                        source="malwarebazaar",
                        severity=ThreatSeverity.CRITICAL,
                        confidence=0.95,
                        first_seen=datetime.fromisoformat(sample["first_seen"].replace(" ", "T")) if sample.get("first_seen") else None,
                        tags=sample.get("tags", []),
                        malware_family=sample.get("signature", ""),
                        reporter=sample.get("reporter", ""),
                        metadata={
                            "sha256": sample.get("sha256_hash", ""),
                            "sha1": sample.get("sha1_hash", ""),
                            "md5": sample.get("md5_hash", ""),
                            "file_type": sample.get("file_type", ""),
                            "file_size": sample.get("file_size", 0),
                            "origin_country": sample.get("origin_country", ""),
                            "delivery_method": sample.get("delivery_method", "")
                        }
                    )
                    iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[MalwareBazaar] Error fetching samples: {e}")
            return []

    def query_hash(self, file_hash: str) -> Optional[ThreatIOC]:
        """Query a file hash"""
        hash_type = "sha256_hash"
        if len(file_hash) == 32:
            hash_type = "md5_hash"
        elif len(file_hash) == 40:
            hash_type = "sha1_hash"

        try:
            response = self._session.post(
                f"{self.BASE_URL}/",
                data={"query": "get_info", "hash": file_hash},
                timeout=30
            )
            response.raise_for_status()
            data = response.json()

            if data.get("query_status") == "ok" and data.get("data"):
                sample = data["data"][0]
                return ThreatIOC(
                    value=file_hash,
                    ioc_type=f"hash_{hash_type.replace('_hash', '')}",
                    source="malwarebazaar",
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.98,
                    tags=sample.get("tags", []),
                    malware_family=sample.get("signature", ""),
                    metadata={
                        "file_type": sample.get("file_type", ""),
                        "file_size": sample.get("file_size", 0),
                        "intelligence": sample.get("intelligence", {})
                    }
                )

            return None

        except Exception as e:
            logger.error(f"[MalwareBazaar] Error querying hash: {e}")
            return None


class PhishTankClient:
    """
    PhishTank API client
    Community-verified phishing URL database
    """

    BASE_URL = "https://checkurl.phishtank.com/checkurl"
    DATA_URL = "http://data.phishtank.com/data"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("PHISHTANK_API_KEY")
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-ThreatIntel/5.0 (phishtank/tsunami@security.local)"
        })

    def check_url(self, url: str) -> Optional[ThreatIOC]:
        """Check if URL is in PhishTank database"""
        try:
            data = {
                "url": url,
                "format": "json"
            }
            if self.api_key:
                data["app_key"] = self.api_key

            response = self._session.post(
                f"{self.BASE_URL}/",
                data=data,
                timeout=30
            )
            response.raise_for_status()
            result = response.json()

            if result.get("results", {}).get("in_database"):
                phish_data = result["results"]
                return ThreatIOC(
                    value=url,
                    ioc_type="url",
                    source="phishtank",
                    severity=ThreatSeverity.HIGH,
                    confidence=0.95 if phish_data.get("verified") else 0.7,
                    tags=["phishing"],
                    threat_type="phishing",
                    reference_url=phish_data.get("phish_detail_page", ""),
                    metadata={
                        "phish_id": phish_data.get("phish_id", ""),
                        "verified": phish_data.get("verified", False),
                        "verified_at": phish_data.get("verified_at", ""),
                        "valid": phish_data.get("valid", False)
                    }
                )

            return None

        except Exception as e:
            logger.error(f"[PhishTank] Error checking URL: {e}")
            return None

    def get_database(self) -> List[ThreatIOC]:
        """
        Download full PhishTank database
        Note: Requires API key and rate limiting applies
        """
        if not self.api_key:
            logger.warning("[PhishTank] API key required for database download")
            return []

        try:
            response = self._session.get(
                f"{self.DATA_URL}/{self.api_key}/online-valid.json",
                timeout=120
            )
            response.raise_for_status()
            data = response.json()

            iocs = []
            for phish in data[:10000]:  # Limit to 10k entries
                ioc = ThreatIOC(
                    value=phish.get("url", ""),
                    ioc_type="url",
                    source="phishtank",
                    severity=ThreatSeverity.HIGH,
                    confidence=0.95 if phish.get("verified") == "yes" else 0.7,
                    tags=["phishing"],
                    threat_type="phishing",
                    first_seen=datetime.fromisoformat(phish["submission_time"].replace(" ", "T")) if phish.get("submission_time") else None,
                    metadata={
                        "phish_id": phish.get("phish_id", ""),
                        "target": phish.get("target", "")
                    }
                )
                iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[PhishTank] Error downloading database: {e}")
            return []


class OpenPhishClient:
    """
    OpenPhish feed client
    Free phishing URL feed
    """

    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-ThreatIntel/5.0"
        })

    def get_feed(self) -> List[ThreatIOC]:
        """Get current OpenPhish feed"""
        try:
            response = self._session.get(self.FEED_URL, timeout=60)
            response.raise_for_status()

            iocs = []
            for line in response.text.strip().split("\n"):
                url = line.strip()
                if url and url.startswith("http"):
                    ioc = ThreatIOC(
                        value=url,
                        ioc_type="url",
                        source="openphish",
                        severity=ThreatSeverity.HIGH,
                        confidence=0.85,
                        tags=["phishing"],
                        threat_type="phishing",
                        first_seen=datetime.now()
                    )
                    iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[OpenPhish] Error fetching feed: {e}")
            return []


class FeodoTrackerClient:
    """
    Feodo Tracker client (abuse.ch)
    Tracks botnet C&C servers
    """

    BASE_URL = "https://feodotracker.abuse.ch"

    def __init__(self):
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-ThreatIntel/5.0"
        })

    def get_recent_c2s(self) -> List[ThreatIOC]:
        """Get recent C&C server IPs"""
        try:
            response = self._session.get(
                f"{self.BASE_URL}/downloads/ipblocklist_recommended.json",
                timeout=60
            )
            response.raise_for_status()
            data = response.json()

            iocs = []
            for entry in data:
                ioc = ThreatIOC(
                    value=entry.get("ip_address", ""),
                    ioc_type="ip",
                    source="feodotracker",
                    severity=ThreatSeverity.CRITICAL,
                    confidence=0.95,
                    first_seen=datetime.fromisoformat(entry["first_seen"]) if entry.get("first_seen") else None,
                    last_seen=datetime.fromisoformat(entry["last_online"]) if entry.get("last_online") else None,
                    tags=["botnet", "c2", entry.get("malware", "")],
                    malware_family=entry.get("malware", ""),
                    threat_type="botnet_c2",
                    metadata={
                        "port": entry.get("port", ""),
                        "status": entry.get("status", ""),
                        "as_name": entry.get("as_name", ""),
                        "country": entry.get("country", "")
                    }
                )
                iocs.append(ioc)

            return iocs

        except Exception as e:
            logger.error(f"[FeodoTracker] Error fetching C2 list: {e}")
            return []


class ThreatFeedAggregator:
    """
    Aggregates threat intelligence from multiple feeds

    Features:
    - Multi-source aggregation
    - Automatic updates
    - IOC deduplication
    - Confidence scoring
    - Callback notifications
    """

    def __init__(self):
        # Initialize feed clients
        self.urlhaus = URLhausClient()
        self.threatfox = ThreatFoxClient()
        self.malwarebazaar = MalwareBazaarClient()
        self.phishtank = PhishTankClient()
        self.openphish = OpenPhishClient()
        self.feodotracker = FeodoTrackerClient()

        # Feed configurations
        self.feeds: Dict[str, ThreatFeed] = {
            "urlhaus": ThreatFeed(
                name="URLhaus",
                url="https://urlhaus-api.abuse.ch/v1/urls/recent/",
                feed_type=ThreatFeedType.URL
            ),
            "threatfox": ThreatFeed(
                name="ThreatFox",
                url="https://threatfox-api.abuse.ch/api/v1/",
                feed_type=ThreatFeedType.IOC
            ),
            "malwarebazaar": ThreatFeed(
                name="MalwareBazaar",
                url="https://mb-api.abuse.ch/api/v1/",
                feed_type=ThreatFeedType.MALWARE
            ),
            "phishtank": ThreatFeed(
                name="PhishTank",
                url="https://checkurl.phishtank.com/",
                feed_type=ThreatFeedType.PHISHING
            ),
            "openphish": ThreatFeed(
                name="OpenPhish",
                url="https://openphish.com/feed.txt",
                feed_type=ThreatFeedType.PHISHING
            ),
            "feodotracker": ThreatFeed(
                name="FeodoTracker",
                url="https://feodotracker.abuse.ch/",
                feed_type=ThreatFeedType.BOTNET
            )
        }

        # IOC storage
        self._iocs: Dict[str, ThreatIOC] = {}
        self._callbacks: List[Callable[[ThreatIOC], None]] = []
        self._running = False
        self._update_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        logger.info("[THREAT-AGGREGATOR] Initialized with 6 feeds")

    def register_callback(self, callback: Callable[[ThreatIOC], None]):
        """Register callback for new IOCs"""
        self._callbacks.append(callback)

    def _notify_callbacks(self, ioc: ThreatIOC):
        """Notify all registered callbacks"""
        for callback in self._callbacks:
            try:
                callback(ioc)
            except Exception as e:
                logger.error(f"[THREAT-AGGREGATOR] Callback error: {e}")

    def _add_ioc(self, ioc: ThreatIOC) -> bool:
        """Add IOC to storage with deduplication"""
        key = f"{ioc.source}:{ioc.ioc_type}:{ioc.value}"

        with self._lock:
            if key in self._iocs:
                # Update existing IOC
                existing = self._iocs[key]
                existing.last_seen = datetime.now()
                if ioc.confidence > existing.confidence:
                    existing.confidence = ioc.confidence
                return False
            else:
                self._iocs[key] = ioc
                self._notify_callbacks(ioc)
                return True

    def update_urlhaus(self) -> int:
        """Update URLhaus feed"""
        try:
            iocs = self.urlhaus.get_recent_urls(limit=1000)
            count = sum(1 for ioc in iocs if self._add_ioc(ioc))

            self.feeds["urlhaus"].last_update = datetime.now()
            self.feeds["urlhaus"].ioc_count = len(iocs)
            self.feeds["urlhaus"].status = "ok"

            logger.info(f"[URLhaus] Updated: {count} new IOCs")
            return count

        except Exception as e:
            self.feeds["urlhaus"].status = "error"
            self.feeds["urlhaus"].error_count += 1
            logger.error(f"[URLhaus] Update error: {e}")
            return 0

    def update_threatfox(self) -> int:
        """Update ThreatFox feed"""
        try:
            iocs = self.threatfox.get_recent_iocs(days=1)
            count = sum(1 for ioc in iocs if self._add_ioc(ioc))

            self.feeds["threatfox"].last_update = datetime.now()
            self.feeds["threatfox"].ioc_count = len(iocs)
            self.feeds["threatfox"].status = "ok"

            logger.info(f"[ThreatFox] Updated: {count} new IOCs")
            return count

        except Exception as e:
            self.feeds["threatfox"].status = "error"
            self.feeds["threatfox"].error_count += 1
            logger.error(f"[ThreatFox] Update error: {e}")
            return 0

    def update_malwarebazaar(self) -> int:
        """Update MalwareBazaar feed"""
        try:
            iocs = self.malwarebazaar.get_recent_samples(limit=100)
            count = sum(1 for ioc in iocs if self._add_ioc(ioc))

            self.feeds["malwarebazaar"].last_update = datetime.now()
            self.feeds["malwarebazaar"].ioc_count = len(iocs)
            self.feeds["malwarebazaar"].status = "ok"

            logger.info(f"[MalwareBazaar] Updated: {count} new IOCs")
            return count

        except Exception as e:
            self.feeds["malwarebazaar"].status = "error"
            self.feeds["malwarebazaar"].error_count += 1
            logger.error(f"[MalwareBazaar] Update error: {e}")
            return 0

    def update_openphish(self) -> int:
        """Update OpenPhish feed"""
        try:
            iocs = self.openphish.get_feed()
            count = sum(1 for ioc in iocs if self._add_ioc(ioc))

            self.feeds["openphish"].last_update = datetime.now()
            self.feeds["openphish"].ioc_count = len(iocs)
            self.feeds["openphish"].status = "ok"

            logger.info(f"[OpenPhish] Updated: {count} new IOCs")
            return count

        except Exception as e:
            self.feeds["openphish"].status = "error"
            self.feeds["openphish"].error_count += 1
            logger.error(f"[OpenPhish] Update error: {e}")
            return 0

    def update_feodotracker(self) -> int:
        """Update FeodoTracker feed"""
        try:
            iocs = self.feodotracker.get_recent_c2s()
            count = sum(1 for ioc in iocs if self._add_ioc(ioc))

            self.feeds["feodotracker"].last_update = datetime.now()
            self.feeds["feodotracker"].ioc_count = len(iocs)
            self.feeds["feodotracker"].status = "ok"

            logger.info(f"[FeodoTracker] Updated: {count} new IOCs")
            return count

        except Exception as e:
            self.feeds["feodotracker"].status = "error"
            self.feeds["feodotracker"].error_count += 1
            logger.error(f"[FeodoTracker] Update error: {e}")
            return 0

    def update_all(self) -> Dict[str, int]:
        """Update all feeds"""
        results = {}

        results["urlhaus"] = self.update_urlhaus()
        time.sleep(1)  # Brief pause between feeds

        results["threatfox"] = self.update_threatfox()
        time.sleep(1)

        results["malwarebazaar"] = self.update_malwarebazaar()
        time.sleep(1)

        results["openphish"] = self.update_openphish()
        time.sleep(1)

        results["feodotracker"] = self.update_feodotracker()

        logger.info(f"[THREAT-AGGREGATOR] All feeds updated: {sum(results.values())} total new IOCs")
        return results

    def start_auto_update(self, interval: int = 3600):
        """Start automatic feed updates"""
        if self._running:
            logger.warning("[THREAT-AGGREGATOR] Already running")
            return

        self._running = True
        self._update_thread = threading.Thread(
            target=self._update_loop,
            args=(interval,),
            daemon=True
        )
        self._update_thread.start()
        logger.info(f"[THREAT-AGGREGATOR] Auto-update started (interval: {interval}s)")

    def stop_auto_update(self):
        """Stop automatic updates"""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=10)
        logger.info("[THREAT-AGGREGATOR] Auto-update stopped")

    def _update_loop(self, interval: int):
        """Background update loop"""
        # Initial update
        self.update_all()

        while self._running:
            time.sleep(interval)
            if self._running:
                self.update_all()

    def query_url(self, url: str) -> List[ThreatIOC]:
        """Query URL across all sources"""
        results = []

        # Check URLhaus
        ioc = self.urlhaus.query_url(url)
        if ioc:
            results.append(ioc)

        # Check PhishTank
        ioc = self.phishtank.check_url(url)
        if ioc:
            results.append(ioc)

        # Check local cache
        with self._lock:
            for key, ioc in self._iocs.items():
                if ioc.value == url:
                    results.append(ioc)

        return results

    def query_hash(self, file_hash: str) -> List[ThreatIOC]:
        """Query file hash across all sources"""
        results = []

        # Check MalwareBazaar
        ioc = self.malwarebazaar.query_hash(file_hash)
        if ioc:
            results.append(ioc)

        # Check ThreatFox
        iocs = self.threatfox.search_ioc(file_hash)
        results.extend(iocs)

        return results

    def query_ip(self, ip: str) -> List[ThreatIOC]:
        """Query IP address"""
        results = []

        # Check URLhaus
        iocs = self.urlhaus.query_host(ip)
        results.extend(iocs)

        # Check ThreatFox
        iocs = self.threatfox.search_ioc(ip)
        results.extend(iocs)

        # Check local cache
        with self._lock:
            for key, ioc in self._iocs.items():
                if ioc.value == ip and ioc.ioc_type == "ip":
                    results.append(ioc)

        return results

    def get_iocs(self,
                 ioc_type: Optional[str] = None,
                 source: Optional[str] = None,
                 min_confidence: float = 0.0,
                 limit: int = 1000) -> List[ThreatIOC]:
        """Get IOCs with optional filters"""
        with self._lock:
            iocs = list(self._iocs.values())

        # Apply filters
        if ioc_type:
            iocs = [i for i in iocs if i.ioc_type == ioc_type]

        if source:
            iocs = [i for i in iocs if i.source == source]

        if min_confidence > 0:
            iocs = [i for i in iocs if i.confidence >= min_confidence]

        # Sort by confidence
        iocs.sort(key=lambda x: x.confidence, reverse=True)

        return iocs[:limit]

    def get_feed_status(self) -> Dict[str, Any]:
        """Get status of all feeds"""
        status = {}
        for name, feed in self.feeds.items():
            status[name] = {
                "name": feed.name,
                "url": feed.url,
                "enabled": feed.enabled,
                "status": feed.status,
                "ioc_count": feed.ioc_count,
                "last_update": feed.last_update.isoformat() if feed.last_update else None,
                "error_count": feed.error_count
            }
        return status

    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregator statistics"""
        with self._lock:
            iocs_copy = list(self._iocs.values())

        stats = {
            "total_iocs": len(iocs_copy),
            "by_type": {},
            "by_source": {},
            "by_severity": {},
            "is_running": self._running,
            "feeds": self.get_feed_status()
        }

        for ioc in iocs_copy:
            stats["by_type"][ioc.ioc_type] = stats["by_type"].get(ioc.ioc_type, 0) + 1
            stats["by_source"][ioc.source] = stats["by_source"].get(ioc.source, 0) + 1
            stats["by_severity"][ioc.severity.value] = stats["by_severity"].get(ioc.severity.value, 0) + 1

        return stats


# Convenience function
_aggregator: Optional[ThreatFeedAggregator] = None

def get_threat_aggregator() -> ThreatFeedAggregator:
    """Get or create global threat aggregator instance"""
    global _aggregator
    if _aggregator is None:
        _aggregator = ThreatFeedAggregator()
    return _aggregator
