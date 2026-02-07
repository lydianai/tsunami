#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Paste Site Monitor
    Monitor clearnet paste sites for credential leaks, API keys, and sensitive data
================================================================================
"""

import os
import re
import time
import json
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PasteSiteType(Enum):
    """Types of paste sites"""
    PASTEBIN = "pastebin"
    GHOSTBIN = "ghostbin"
    DPASTE = "dpaste"
    HASTEBIN = "hastebin"
    RENTRY = "rentry"
    PRIVATEBIN = "privatebin"
    IDEONE = "ideone"
    CODEPAD = "codepad"
    CUSTOM = "custom"


class SensitiveDataType(Enum):
    """Types of sensitive data to detect"""
    EMAIL = "email"
    PASSWORD = "password"
    CREDENTIAL_PAIR = "credential_pair"
    API_KEY = "api_key"
    AWS_KEY = "aws_key"
    GITHUB_TOKEN = "github_token"
    PRIVATE_KEY = "private_key"
    DATABASE_URL = "database_url"
    JWT_TOKEN = "jwt_token"
    CREDIT_CARD = "credit_card"
    SSN = "ssn"
    PHONE = "phone"
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    HASH = "hash"
    BITCOIN_ADDRESS = "bitcoin_address"
    CUSTOM_PATTERN = "custom_pattern"


@dataclass
class PasteSite:
    """Configuration for a paste site to monitor"""
    name: str
    site_type: PasteSiteType
    base_url: str
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    search_url: Optional[str] = None
    scrape_url: Optional[str] = None
    rate_limit: int = 60  # Requests per minute
    enabled: bool = True
    requires_auth: bool = False
    last_check: Optional[datetime] = None


@dataclass
class PasteResult:
    """Result from paste site monitoring"""
    paste_id: str
    site: str
    url: str
    title: Optional[str] = None
    author: Optional[str] = None
    content_preview: str = ""
    full_content: Optional[str] = None
    created_at: Optional[datetime] = None
    discovered_at: datetime = field(default_factory=datetime.now)
    data_types_found: List[SensitiveDataType] = field(default_factory=list)
    matches: Dict[str, List[str]] = field(default_factory=dict)
    keywords_matched: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    hash_sha256: str = ""
    size_bytes: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class SensitiveDataDetector:
    """
    Detects sensitive data patterns in text content
    """

    # Compiled regex patterns for various sensitive data types
    PATTERNS = {
        SensitiveDataType.EMAIL: re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        ),
        SensitiveDataType.PASSWORD: re.compile(
            r'(?:password|passwd|pwd|pass)\s*[:=]\s*["\']?([^\s"\']{4,})["\']?',
            re.IGNORECASE
        ),
        SensitiveDataType.CREDENTIAL_PAIR: re.compile(
            r'(?:email|user|username|login)\s*[:=]\s*["\']?([^\s"\']+)["\']?\s*[,\n]\s*(?:password|passwd|pwd|pass)\s*[:=]\s*["\']?([^\s"\']+)["\']?',
            re.IGNORECASE
        ),
        SensitiveDataType.API_KEY: re.compile(
            r'(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?',
            re.IGNORECASE
        ),
        SensitiveDataType.AWS_KEY: re.compile(
            r'(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}'
        ),
        SensitiveDataType.GITHUB_TOKEN: re.compile(
            r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}'
        ),
        SensitiveDataType.PRIVATE_KEY: re.compile(
            r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            re.IGNORECASE
        ),
        SensitiveDataType.DATABASE_URL: re.compile(
            r'(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s"\'<>]+',
            re.IGNORECASE
        ),
        SensitiveDataType.JWT_TOKEN: re.compile(
            r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
        ),
        SensitiveDataType.CREDIT_CARD: re.compile(
            r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        ),
        SensitiveDataType.SSN: re.compile(
            r'\b\d{3}-\d{2}-\d{4}\b'
        ),
        SensitiveDataType.PHONE: re.compile(
            r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}'
        ),
        SensitiveDataType.IP_ADDRESS: re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        SensitiveDataType.DOMAIN: re.compile(
            r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b',
            re.IGNORECASE
        ),
        SensitiveDataType.HASH: re.compile(
            r'\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8})?(?:[a-fA-F0-9]{24})?\b'  # MD5, SHA1, SHA256
        ),
        SensitiveDataType.BITCOIN_ADDRESS: re.compile(
            r'\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b'
        ),
    }

    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None):
        """
        Initialize detector with optional custom patterns

        Args:
            custom_patterns: Dict of pattern name to regex string
        """
        self.custom_patterns: Dict[str, re.Pattern] = {}
        if custom_patterns:
            for name, pattern in custom_patterns.items():
                try:
                    self.custom_patterns[name] = re.compile(pattern, re.IGNORECASE)
                except re.error as e:
                    logger.error(f"Invalid custom pattern '{name}': {e}")

    def detect(self, content: str) -> Dict[SensitiveDataType, List[str]]:
        """
        Detect all sensitive data in content

        Args:
            content: Text content to analyze

        Returns:
            Dict mapping data type to list of matches
        """
        results = {}

        for data_type, pattern in self.PATTERNS.items():
            matches = pattern.findall(content)
            if matches:
                # Flatten tuples from credential pairs
                if data_type == SensitiveDataType.CREDENTIAL_PAIR:
                    flattened = [f"{m[0]}:{m[1]}" for m in matches if isinstance(m, tuple)]
                    results[data_type] = flattened
                else:
                    results[data_type] = list(set(matches)) if isinstance(matches[0], str) else matches

        # Check custom patterns
        for name, pattern in self.custom_patterns.items():
            matches = pattern.findall(content)
            if matches:
                results[SensitiveDataType.CUSTOM_PATTERN] = results.get(
                    SensitiveDataType.CUSTOM_PATTERN, []
                ) + [(name, m) for m in matches]

        return results

    def calculate_confidence(self, matches: Dict[SensitiveDataType, List[str]], content: str) -> float:
        """
        Calculate confidence score based on matches

        Args:
            matches: Detected sensitive data
            content: Original content

        Returns:
            Confidence score 0.0-1.0
        """
        if not matches:
            return 0.0

        # Weight different data types
        weights = {
            SensitiveDataType.AWS_KEY: 1.0,
            SensitiveDataType.GITHUB_TOKEN: 1.0,
            SensitiveDataType.PRIVATE_KEY: 1.0,
            SensitiveDataType.CREDENTIAL_PAIR: 0.9,
            SensitiveDataType.DATABASE_URL: 0.9,
            SensitiveDataType.JWT_TOKEN: 0.8,
            SensitiveDataType.API_KEY: 0.7,
            SensitiveDataType.CREDIT_CARD: 0.6,
            SensitiveDataType.SSN: 0.6,
            SensitiveDataType.PASSWORD: 0.5,
            SensitiveDataType.EMAIL: 0.3,
            SensitiveDataType.BITCOIN_ADDRESS: 0.4,
            SensitiveDataType.HASH: 0.2,
            SensitiveDataType.IP_ADDRESS: 0.2,
            SensitiveDataType.PHONE: 0.2,
            SensitiveDataType.DOMAIN: 0.1,
        }

        total_weight = 0.0
        for data_type, found_matches in matches.items():
            weight = weights.get(data_type, 0.3)
            # More matches = higher confidence, but diminishing returns
            count_factor = min(len(found_matches) * 0.1, 0.5)
            total_weight += weight * (1 + count_factor)

        # Normalize to 0-1 range
        return min(total_weight / 3.0, 1.0)


class PasteMonitor:
    """
    Monitors multiple paste sites for sensitive data exposure

    Features:
    - Multi-site monitoring (Pastebin, Ghostbin, dpaste, etc.)
    - Keyword-based search
    - Sensitive data pattern detection
    - Rate limiting and respectful crawling
    - Webhook notifications
    """

    def __init__(self):
        self.sites: Dict[str, PasteSite] = {}
        self.detector = SensitiveDataDetector()
        self.keywords: Set[str] = set()
        self.results: List[PasteResult] = []
        self._session: Optional[requests.Session] = None
        self._callbacks: List[Callable[[PasteResult], None]] = []
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Initialize default paste sites
        self._initialize_sites()
        self._create_session()

        logger.info("[PASTE-MONITOR] Initialized with default paste sites")

    def _initialize_sites(self):
        """Initialize default paste sites to monitor"""
        default_sites = [
            PasteSite(
                name="pastebin",
                site_type=PasteSiteType.PASTEBIN,
                base_url="https://pastebin.com",
                scrape_url="https://scrape.pastebin.com/api_scraping.php",
                api_url="https://pastebin.com/api/api_post.php",
                api_key=os.getenv("PASTEBIN_API_KEY"),
                rate_limit=60,
                requires_auth=True
            ),
            PasteSite(
                name="dpaste",
                site_type=PasteSiteType.DPASTE,
                base_url="https://dpaste.org",
                api_url="https://dpaste.org/api/v2/",
                rate_limit=30,
                requires_auth=False
            ),
            PasteSite(
                name="rentry",
                site_type=PasteSiteType.RENTRY,
                base_url="https://rentry.co",
                rate_limit=20,
                requires_auth=False
            ),
            PasteSite(
                name="hastebin",
                site_type=PasteSiteType.HASTEBIN,
                base_url="https://hastebin.com",
                api_url="https://hastebin.com/documents",
                rate_limit=30,
                requires_auth=False
            ),
        ]

        for site in default_sites:
            self.sites[site.name] = site

    def _create_session(self):
        """Create HTTP session with retry logic"""
        self._session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        self._session.headers.update({
            "User-Agent": "TSUNAMI-SecurityMonitor/5.0",
            "Accept": "application/json, text/plain, */*",
        })

    def add_site(self, site: PasteSite):
        """Add a custom paste site to monitor"""
        self.sites[site.name] = site
        logger.info(f"[PASTE-MONITOR] Added site: {site.name}")

    def add_keyword(self, keyword: str):
        """Add a keyword to search for"""
        self.keywords.add(keyword.lower())
        logger.info(f"[PASTE-MONITOR] Added keyword: {keyword}")

    def add_keywords(self, keywords: List[str]):
        """Add multiple keywords"""
        for keyword in keywords:
            self.keywords.add(keyword.lower())
        logger.info(f"[PASTE-MONITOR] Added {len(keywords)} keywords")

    def remove_keyword(self, keyword: str):
        """Remove a keyword"""
        self.keywords.discard(keyword.lower())

    def register_callback(self, callback: Callable[[PasteResult], None]):
        """Register a callback function to be called when sensitive data is found"""
        self._callbacks.append(callback)

    def _notify_callbacks(self, result: PasteResult):
        """Notify all registered callbacks"""
        for callback in self._callbacks:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"[PASTE-MONITOR] Callback error: {e}")

    def check_pastebin_scrape(self) -> List[PasteResult]:
        """
        Check Pastebin's scraping API for recent pastes

        Requires Pastebin PRO account and IP whitelisting
        """
        results = []
        site = self.sites.get("pastebin")

        if not site or not site.api_key:
            logger.debug("[PASTE-MONITOR] Pastebin API key not configured")
            return results

        try:
            # Get recent pastes
            response = self._session.get(
                site.scrape_url,
                params={"limit": 250},
                timeout=30
            )

            if response.status_code != 200:
                logger.warning(f"[PASTE-MONITOR] Pastebin scrape API returned {response.status_code}")
                return results

            pastes = response.json()

            for paste in pastes:
                # Get paste content
                content_response = self._session.get(
                    f"{site.scrape_url}?i={paste['key']}",
                    timeout=30
                )

                if content_response.status_code == 200:
                    content = content_response.text
                    result = self._analyze_paste(
                        paste_id=paste["key"],
                        site_name="pastebin",
                        url=f"https://pastebin.com/{paste['key']}",
                        title=paste.get("title", ""),
                        content=content,
                        author=paste.get("user", ""),
                        created_at=datetime.fromtimestamp(int(paste.get("date", 0))) if paste.get("date") else None
                    )

                    if result and (result.data_types_found or result.keywords_matched):
                        results.append(result)
                        self._notify_callbacks(result)

                # Rate limiting
                time.sleep(60 / site.rate_limit)

        except Exception as e:
            logger.error(f"[PASTE-MONITOR] Pastebin scrape error: {e}")

        site.last_check = datetime.now()
        return results

    def search_pastebin(self, query: str) -> List[PasteResult]:
        """
        Search Pastebin using Google Custom Search API

        Note: Pastebin's native search requires PRO account
        Falls back to Google dorking approach
        """
        results = []
        google_api_key = os.getenv("GOOGLE_API_KEY")
        google_cse_id = os.getenv("GOOGLE_CSE_ID")

        if not google_api_key or not google_cse_id:
            logger.debug("[PASTE-MONITOR] Google API not configured for Pastebin search")
            return results

        try:
            # Google Custom Search API
            response = self._session.get(
                "https://www.googleapis.com/customsearch/v1",
                params={
                    "key": google_api_key,
                    "cx": google_cse_id,
                    "q": f"site:pastebin.com {query}",
                    "num": 10
                },
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()

                for item in data.get("items", []):
                    url = item.get("link", "")

                    # Extract paste ID from URL
                    paste_id = url.split("/")[-1] if url else ""

                    if paste_id:
                        result = self._fetch_and_analyze_paste(
                            site_name="pastebin",
                            paste_id=paste_id,
                            url=url
                        )
                        if result:
                            results.append(result)

        except Exception as e:
            logger.error(f"[PASTE-MONITOR] Pastebin search error: {e}")

        return results

    def check_dpaste(self) -> List[PasteResult]:
        """Check dpaste.org recent pastes"""
        results = []
        site = self.sites.get("dpaste")

        if not site or not site.enabled:
            return results

        try:
            # dpaste has a recent API endpoint
            response = self._session.get(
                f"{site.api_url}",
                headers={"Accept": "application/json"},
                timeout=30
            )

            # dpaste doesn't have public listing, search for specific patterns
            # This is a placeholder - in production, use their actual API

        except Exception as e:
            logger.error(f"[PASTE-MONITOR] dpaste check error: {e}")

        site.last_check = datetime.now()
        return results

    def _fetch_and_analyze_paste(self, site_name: str, paste_id: str, url: str) -> Optional[PasteResult]:
        """Fetch paste content and analyze it"""
        try:
            # Fetch raw content
            raw_url = url
            if site_name == "pastebin":
                raw_url = f"https://pastebin.com/raw/{paste_id}"
            elif site_name == "hastebin":
                raw_url = f"https://hastebin.com/raw/{paste_id}"

            response = self._session.get(raw_url, timeout=30)

            if response.status_code == 200:
                return self._analyze_paste(
                    paste_id=paste_id,
                    site_name=site_name,
                    url=url,
                    content=response.text
                )

        except Exception as e:
            logger.error(f"[PASTE-MONITOR] Fetch error for {url}: {e}")

        return None

    def _analyze_paste(self,
                      paste_id: str,
                      site_name: str,
                      url: str,
                      content: str,
                      title: Optional[str] = None,
                      author: Optional[str] = None,
                      created_at: Optional[datetime] = None) -> Optional[PasteResult]:
        """
        Analyze paste content for sensitive data and keywords

        Args:
            paste_id: Unique paste identifier
            site_name: Name of the paste site
            url: Full URL to paste
            content: Paste content
            title: Optional paste title
            author: Optional author name
            created_at: Optional creation timestamp

        Returns:
            PasteResult if interesting data found, None otherwise
        """
        if not content:
            return None

        # Detect sensitive data
        matches = self.detector.detect(content)
        data_types_found = list(matches.keys())

        # Check for keywords
        content_lower = content.lower()
        keywords_matched = [kw for kw in self.keywords if kw in content_lower]

        # Calculate confidence score
        confidence = self.detector.calculate_confidence(matches, content)

        # If keywords matched, boost confidence
        if keywords_matched:
            confidence = min(confidence + 0.2, 1.0)

        # Create result
        result = PasteResult(
            paste_id=paste_id,
            site=site_name,
            url=url,
            title=title,
            author=author,
            content_preview=content[:500] if content else "",
            full_content=content,
            created_at=created_at,
            data_types_found=data_types_found,
            matches={dt.value: vals for dt, vals in matches.items()},
            keywords_matched=keywords_matched,
            confidence_score=confidence,
            hash_sha256=hashlib.sha256(content.encode()).hexdigest(),
            size_bytes=len(content.encode())
        )

        # Store result
        with self._lock:
            self.results.append(result)
            # Keep last 1000 results
            if len(self.results) > 1000:
                self.results = self.results[-1000:]

        return result

    def search_all_sites(self, query: str) -> List[PasteResult]:
        """
        Search all configured paste sites for a query

        Args:
            query: Search query string

        Returns:
            List of PasteResults
        """
        all_results = []

        # Search Pastebin
        all_results.extend(self.search_pastebin(query))

        # Add other site searches here as they become available

        return all_results

    def start_monitoring(self, interval: int = 300):
        """
        Start continuous monitoring in background

        Args:
            interval: Check interval in seconds (default 5 minutes)
        """
        if self._running:
            logger.warning("[PASTE-MONITOR] Already running")
            return

        self._running = True
        self._monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            args=(interval,),
            daemon=True
        )
        self._monitor_thread.start()
        logger.info(f"[PASTE-MONITOR] Started monitoring (interval: {interval}s)")

    def stop_monitoring(self):
        """Stop background monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=10)
        logger.info("[PASTE-MONITOR] Stopped monitoring")

    def _monitoring_loop(self, interval: int):
        """Background monitoring loop"""
        while self._running:
            try:
                # Check Pastebin scrape API
                self.check_pastebin_scrape()

                # Search for each keyword
                for keyword in list(self.keywords):
                    results = self.search_all_sites(keyword)
                    logger.debug(f"[PASTE-MONITOR] Found {len(results)} results for '{keyword}'")
                    time.sleep(5)  # Brief pause between searches

            except Exception as e:
                logger.error(f"[PASTE-MONITOR] Monitoring loop error: {e}")

            time.sleep(interval)

    def get_recent_results(self, limit: int = 100,
                          min_confidence: float = 0.0,
                          data_types: Optional[List[SensitiveDataType]] = None) -> List[PasteResult]:
        """
        Get recent monitoring results with optional filters

        Args:
            limit: Maximum results to return
            min_confidence: Minimum confidence score filter
            data_types: Filter by specific data types

        Returns:
            List of PasteResults
        """
        with self._lock:
            filtered = self.results.copy()

        # Apply filters
        if min_confidence > 0:
            filtered = [r for r in filtered if r.confidence_score >= min_confidence]

        if data_types:
            filtered = [
                r for r in filtered
                if any(dt in r.data_types_found for dt in data_types)
            ]

        # Sort by discovery time, newest first
        filtered.sort(key=lambda x: x.discovered_at, reverse=True)

        return filtered[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        with self._lock:
            results_copy = self.results.copy()

        stats = {
            "total_results": len(results_copy),
            "keywords_monitored": len(self.keywords),
            "sites_configured": len(self.sites),
            "sites_enabled": len([s for s in self.sites.values() if s.enabled]),
            "by_site": {},
            "by_data_type": {},
            "high_confidence_count": len([r for r in results_copy if r.confidence_score >= 0.7]),
            "is_monitoring": self._running,
            "last_results": []
        }

        # Count by site
        for result in results_copy:
            stats["by_site"][result.site] = stats["by_site"].get(result.site, 0) + 1

            for data_type in result.data_types_found:
                dt_name = data_type.value if isinstance(data_type, SensitiveDataType) else str(data_type)
                stats["by_data_type"][dt_name] = stats["by_data_type"].get(dt_name, 0) + 1

        # Last 5 results preview
        stats["last_results"] = [
            {
                "paste_id": r.paste_id,
                "site": r.site,
                "url": r.url,
                "confidence": r.confidence_score,
                "data_types": [dt.value if isinstance(dt, SensitiveDataType) else str(dt) for dt in r.data_types_found],
                "discovered_at": r.discovered_at.isoformat()
            }
            for r in results_copy[-5:]
        ]

        return stats


# Convenience function
_paste_monitor: Optional[PasteMonitor] = None

def get_paste_monitor() -> PasteMonitor:
    """Get or create global paste monitor instance"""
    global _paste_monitor
    if _paste_monitor is None:
        _paste_monitor = PasteMonitor()
    return _paste_monitor
