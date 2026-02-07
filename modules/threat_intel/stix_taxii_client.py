#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI STIX 2.1 / TAXII 2.1 Client v5.0
    Real Threat Feed Integration
================================================================================

    Connects to REAL threat intelligence feeds:
    - AlienVault OTX (Free API)
    - Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
    - CISA Known Exploited Vulnerabilities
    - MISP (Open Threat Intel)

================================================================================
"""

import os
import json
import time
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Generator
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Optional TAXII client
try:
    from taxii2client.v21 import Server as TAXII21Server
    from taxii2client.v21 import Collection as TAXII21Collection
    from taxii2client.v20 import Server as TAXII20Server
    from taxii2client.v20 import Collection as TAXII20Collection
    TAXII_AVAILABLE = True
except ImportError:
    TAXII_AVAILABLE = False

# Optional STIX2 library
try:
    import stix2
    from stix2 import Bundle, Indicator, Malware, AttackPattern
    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeedType(Enum):
    """Supported feed types"""
    TAXII_21 = "taxii21"
    TAXII_20 = "taxii20"
    STIX_JSON = "stix_json"
    REST_API = "rest_api"
    CSV = "csv"
    JSON = "json"
    TXT = "txt"


class FeedStatus(Enum):
    """Feed status"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    UPDATING = "updating"


@dataclass
class ThreatFeedConfig:
    """Configuration for a threat feed"""
    name: str
    url: str
    feed_type: FeedType
    enabled: bool = True
    api_key: Optional[str] = None
    api_key_header: str = "X-API-KEY"
    username: Optional[str] = None
    password: Optional[str] = None
    collection_id: Optional[str] = None
    update_interval: int = 3600  # seconds
    timeout: int = 30
    verify_ssl: bool = True
    max_results: int = 10000
    description: str = ""


@dataclass
class FeedState:
    """State tracking for a feed"""
    name: str
    status: FeedStatus = FeedStatus.INACTIVE
    last_update: Optional[datetime] = None
    last_error: Optional[str] = None
    indicators_count: int = 0
    update_count: int = 0


class CacheManager:
    """Simple file-based cache with TTL"""

    def __init__(self, cache_dir: Path, default_ttl: int = 3600):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.default_ttl = default_ttl
        self._lock = threading.Lock()

    def _get_cache_path(self, key: str) -> Path:
        """Get cache file path for key"""
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"

    def get(self, key: str) -> Optional[Any]:
        """Get cached value if not expired"""
        with self._lock:
            cache_path = self._get_cache_path(key)
            if not cache_path.exists():
                return None

            try:
                with open(cache_path, 'r') as f:
                    data = json.load(f)

                expires_at = datetime.fromisoformat(data['expires_at'])
                if datetime.now() > expires_at:
                    cache_path.unlink()
                    return None

                return data['value']
            except Exception:
                return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set cached value with TTL"""
        with self._lock:
            ttl = ttl or self.default_ttl
            expires_at = datetime.now() + timedelta(seconds=ttl)

            cache_path = self._get_cache_path(key)
            data = {
                'key': key,
                'value': value,
                'expires_at': expires_at.isoformat(),
                'cached_at': datetime.now().isoformat()
            }

            with open(cache_path, 'w') as f:
                json.dump(data, f)

    def delete(self, key: str) -> None:
        """Delete cached value"""
        with self._lock:
            cache_path = self._get_cache_path(key)
            if cache_path.exists():
                cache_path.unlink()

    def clear(self) -> int:
        """Clear all cached values"""
        with self._lock:
            count = 0
            for cache_file in self.cache_dir.glob("*.json"):
                cache_file.unlink()
                count += 1
            return count


class RateLimiter:
    """Simple rate limiter for API calls"""

    def __init__(self, calls_per_minute: int = 60):
        self.calls_per_minute = calls_per_minute
        self.calls: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def acquire(self, key: str = "default") -> bool:
        """Try to acquire rate limit slot"""
        with self._lock:
            now = time.time()
            minute_ago = now - 60

            if key not in self.calls:
                self.calls[key] = []

            # Clean old calls
            self.calls[key] = [t for t in self.calls[key] if t > minute_ago]

            if len(self.calls[key]) >= self.calls_per_minute:
                return False

            self.calls[key].append(now)
            return True

    def wait(self, key: str = "default") -> None:
        """Wait until rate limit slot is available"""
        while not self.acquire(key):
            time.sleep(0.5)


class STIXTAXIIClient:
    """
    Real STIX 2.1 / TAXII 2.1 Client

    Fetches threat intelligence from multiple public sources.
    """

    # Default feed configurations
    DEFAULT_FEEDS = {
        # Abuse.ch Feeds (No API key required)
        'abuse_ch_urlhaus': ThreatFeedConfig(
            name='abuse_ch_urlhaus',
            url='https://urlhaus.abuse.ch/downloads/json_recent/',
            feed_type=FeedType.JSON,
            update_interval=1800,
            description='URLhaus - Malicious URLs'
        ),
        'abuse_ch_malwarebazaar': ThreatFeedConfig(
            name='abuse_ch_malwarebazaar',
            url='https://bazaar.abuse.ch/export/json/recent/',
            feed_type=FeedType.JSON,
            update_interval=3600,
            description='MalwareBazaar - Malware Samples'
        ),
        'abuse_ch_threatfox': ThreatFeedConfig(
            name='abuse_ch_threatfox',
            url='https://threatfox.abuse.ch/export/json/recent/',
            feed_type=FeedType.JSON,
            update_interval=1800,
            description='ThreatFox - IOCs'
        ),
        'abuse_ch_feodo': ThreatFeedConfig(
            name='abuse_ch_feodo',
            url='https://feodotracker.abuse.ch/downloads/ipblocklist.json',
            feed_type=FeedType.JSON,
            update_interval=3600,
            description='Feodo Tracker - Botnet C2'
        ),
        'abuse_ch_sslbl': ThreatFeedConfig(
            name='abuse_ch_sslbl',
            url='https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
            feed_type=FeedType.TXT,
            update_interval=3600,
            description='SSL Blacklist - Malicious SSL Certificates'
        ),
        # CISA KEV (No API key required)
        'cisa_kev': ThreatFeedConfig(
            name='cisa_kev',
            url='https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
            feed_type=FeedType.JSON,
            update_interval=86400,
            description='CISA Known Exploited Vulnerabilities'
        ),
        # AlienVault OTX (Requires free API key)
        'alienvault_otx': ThreatFeedConfig(
            name='alienvault_otx',
            url='https://otx.alienvault.com/api/v1/pulses/subscribed',
            feed_type=FeedType.REST_API,
            api_key=os.getenv('OTX_API_KEY', ''),
            api_key_header='X-OTX-API-KEY',
            update_interval=3600,
            enabled=bool(os.getenv('OTX_API_KEY')),
            description='AlienVault OTX - Community Threat Intel'
        ),
        # Emerging Threats (No API key required)
        'emerging_threats': ThreatFeedConfig(
            name='emerging_threats',
            url='https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
            feed_type=FeedType.TXT,
            update_interval=86400,
            description='Emerging Threats - Compromised IPs'
        ),
        # Blocklist.de (No API key required)
        'blocklist_de': ThreatFeedConfig(
            name='blocklist_de',
            url='https://lists.blocklist.de/lists/all.txt',
            feed_type=FeedType.TXT,
            update_interval=3600,
            description='Blocklist.de - Attack IPs'
        ),
    }

    def __init__(self, cache_dir: Optional[Path] = None):
        """Initialize the STIX/TAXII client"""
        self.cache_dir = cache_dir or Path.home() / '.tsunami' / 'threat_intel_cache'
        self.cache = CacheManager(self.cache_dir)
        self.rate_limiter = RateLimiter(calls_per_minute=30)

        self.feeds: Dict[str, ThreatFeedConfig] = dict(self.DEFAULT_FEEDS)
        self.feed_states: Dict[str, FeedState] = {}

        self._session = self._create_session()
        self._indicators: Dict[str, dict] = {}
        self._lock = threading.Lock()
        self._update_thread: Optional[threading.Thread] = None
        self._running = False

        # Initialize feed states
        for name in self.feeds:
            self.feed_states[name] = FeedState(name=name)

        logger.info(f"[STIX-TAXII] Client initialized with {len(self.feeds)} feeds")

    def _create_session(self) -> requests.Session:
        """Create HTTP session with retry logic"""
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)
        session.mount("http://", adapter)

        session.headers.update({
            'User-Agent': 'TSUNAMI/5.0 ThreatIntel (https://github.com/tsunami-security)',
            'Accept': 'application/json'
        })

        return session

    def add_feed(self, config: ThreatFeedConfig) -> None:
        """Add a new feed configuration"""
        with self._lock:
            self.feeds[config.name] = config
            self.feed_states[config.name] = FeedState(name=config.name)
            logger.info(f"[STIX-TAXII] Added feed: {config.name}")

    def remove_feed(self, name: str) -> bool:
        """Remove a feed configuration"""
        with self._lock:
            if name in self.feeds:
                del self.feeds[name]
                if name in self.feed_states:
                    del self.feed_states[name]
                logger.info(f"[STIX-TAXII] Removed feed: {name}")
                return True
            return False

    def enable_feed(self, name: str, enabled: bool = True) -> bool:
        """Enable or disable a feed"""
        with self._lock:
            if name in self.feeds:
                self.feeds[name].enabled = enabled
                logger.info(f"[STIX-TAXII] Feed {name} enabled={enabled}")
                return True
            return False

    def set_api_key(self, feed_name: str, api_key: str) -> bool:
        """Set API key for a feed"""
        with self._lock:
            if feed_name in self.feeds:
                self.feeds[feed_name].api_key = api_key
                self.feeds[feed_name].enabled = True
                logger.info(f"[STIX-TAXII] API key set for feed: {feed_name}")
                return True
            return False

    def fetch_feed(self, name: str, force: bool = False) -> List[dict]:
        """
        Fetch indicators from a specific feed

        Args:
            name: Feed name
            force: Force update even if cached

        Returns:
            List of raw indicator data
        """
        if name not in self.feeds:
            raise ValueError(f"Unknown feed: {name}")

        config = self.feeds[name]
        if not config.enabled:
            logger.warning(f"[STIX-TAXII] Feed {name} is disabled")
            return []

        # Check cache
        cache_key = f"feed_{name}"
        if not force:
            cached = self.cache.get(cache_key)
            if cached:
                logger.debug(f"[STIX-TAXII] Using cached data for {name}")
                return cached

        # Rate limiting
        self.rate_limiter.wait(name)

        # Update state
        state = self.feed_states[name]
        state.status = FeedStatus.UPDATING

        try:
            indicators = self._fetch_feed_data(config)

            # Update state
            state.status = FeedStatus.ACTIVE
            state.last_update = datetime.now()
            state.indicators_count = len(indicators)
            state.update_count += 1
            state.last_error = None

            # Cache results
            self.cache.set(cache_key, indicators, ttl=config.update_interval)

            logger.info(f"[STIX-TAXII] Fetched {len(indicators)} indicators from {name}")
            return indicators

        except Exception as e:
            state.status = FeedStatus.ERROR
            state.last_error = str(e)
            logger.error(f"[STIX-TAXII] Error fetching {name}: {e}")
            raise

    def _fetch_feed_data(self, config: ThreatFeedConfig) -> List[dict]:
        """Fetch data based on feed type"""

        if config.feed_type == FeedType.TAXII_21:
            return self._fetch_taxii21(config)
        elif config.feed_type == FeedType.TAXII_20:
            return self._fetch_taxii20(config)
        elif config.feed_type == FeedType.JSON:
            return self._fetch_json(config)
        elif config.feed_type == FeedType.REST_API:
            return self._fetch_rest_api(config)
        elif config.feed_type == FeedType.TXT:
            return self._fetch_txt(config)
        elif config.feed_type == FeedType.CSV:
            return self._fetch_csv(config)
        else:
            raise ValueError(f"Unsupported feed type: {config.feed_type}")

    def _fetch_taxii21(self, config: ThreatFeedConfig) -> List[dict]:
        """Fetch from TAXII 2.1 server"""
        if not TAXII_AVAILABLE:
            raise ImportError("taxii2-client not installed. Run: pip install taxii2-client")

        server = TAXII21Server(
            config.url,
            user=config.username,
            password=config.password
        )

        indicators = []

        for api_root in server.api_roots:
            for collection in api_root.collections:
                if config.collection_id and collection.id != config.collection_id:
                    continue

                try:
                    objects = collection.get_objects()
                    if hasattr(objects, 'objects'):
                        for obj in objects.objects:
                            indicators.append(self._normalize_stix_object(obj))
                except Exception as e:
                    logger.warning(f"Error fetching collection {collection.id}: {e}")

        return indicators

    def _fetch_taxii20(self, config: ThreatFeedConfig) -> List[dict]:
        """Fetch from TAXII 2.0 server"""
        if not TAXII_AVAILABLE:
            raise ImportError("taxii2-client not installed. Run: pip install taxii2-client")

        server = TAXII20Server(
            config.url,
            user=config.username,
            password=config.password
        )

        indicators = []

        for api_root in server.api_roots:
            for collection in api_root.collections:
                if config.collection_id and collection.id != config.collection_id:
                    continue

                try:
                    objects = collection.get_objects()
                    if hasattr(objects, 'objects'):
                        for obj in objects.objects:
                            indicators.append(self._normalize_stix_object(obj))
                except Exception as e:
                    logger.warning(f"Error fetching collection {collection.id}: {e}")

        return indicators

    def _fetch_json(self, config: ThreatFeedConfig) -> List[dict]:
        """Fetch JSON feed"""
        headers = {}
        if config.api_key:
            headers[config.api_key_header] = config.api_key

        response = self._session.get(
            config.url,
            headers=headers,
            timeout=config.timeout,
            verify=config.verify_ssl
        )
        response.raise_for_status()

        data = response.json()
        return self._parse_json_feed(config.name, data)

    def _fetch_rest_api(self, config: ThreatFeedConfig) -> List[dict]:
        """Fetch from REST API"""
        headers = {}
        if config.api_key:
            headers[config.api_key_header] = config.api_key

        # Handle different APIs
        if 'otx.alienvault' in config.url:
            return self._fetch_otx(config, headers)
        elif 'mb-api.abuse.ch' in config.url:
            return self._fetch_malwarebazaar(config, headers)
        else:
            response = self._session.get(
                config.url,
                headers=headers,
                timeout=config.timeout,
                verify=config.verify_ssl
            )
            response.raise_for_status()
            return self._parse_json_feed(config.name, response.json())

    def _fetch_otx(self, config: ThreatFeedConfig, headers: dict) -> List[dict]:
        """Fetch from AlienVault OTX"""
        indicators = []
        page = 1

        while True:
            url = f"{config.url}?page={page}&limit=50"
            response = self._session.get(
                url,
                headers=headers,
                timeout=config.timeout,
                verify=config.verify_ssl
            )
            response.raise_for_status()

            data = response.json()
            pulses = data.get('results', [])

            if not pulses:
                break

            for pulse in pulses:
                for ioc in pulse.get('indicators', []):
                    indicators.append({
                        'type': self._map_otx_type(ioc.get('type', '')),
                        'value': ioc.get('indicator', ''),
                        'source': 'alienvault_otx',
                        'pulse_name': pulse.get('name', ''),
                        'pulse_id': pulse.get('id', ''),
                        'created': ioc.get('created', ''),
                        'tags': pulse.get('tags', []),
                        'tlp': pulse.get('TLP', 'white'),
                        'description': ioc.get('description', '')
                    })

            if len(indicators) >= config.max_results:
                break

            page += 1
            if page > 10:  # Limit pages
                break

        return indicators

    def _fetch_malwarebazaar(self, config: ThreatFeedConfig, headers: dict) -> List[dict]:
        """Fetch from MalwareBazaar"""
        indicators = []

        # Get recent samples
        response = self._session.post(
            config.url,
            data={'query': 'get_recent', 'selector': '100'},
            headers=headers,
            timeout=config.timeout,
            verify=config.verify_ssl
        )
        response.raise_for_status()

        data = response.json()

        if data.get('query_status') == 'ok':
            for sample in data.get('data', []):
                indicators.append({
                    'type': 'hash_sha256',
                    'value': sample.get('sha256_hash', ''),
                    'source': 'abuse_ch_malwarebazaar',
                    'md5': sample.get('md5_hash', ''),
                    'sha1': sample.get('sha1_hash', ''),
                    'file_type': sample.get('file_type', ''),
                    'file_name': sample.get('file_name', ''),
                    'signature': sample.get('signature', ''),
                    'tags': sample.get('tags', []),
                    'first_seen': sample.get('first_seen', ''),
                    'delivery_method': sample.get('delivery_method', '')
                })

        return indicators

    def _fetch_txt(self, config: ThreatFeedConfig) -> List[dict]:
        """Fetch TXT feed (IP lists)"""
        headers = {}
        if config.api_key:
            headers[config.api_key_header] = config.api_key

        response = self._session.get(
            config.url,
            headers=headers,
            timeout=config.timeout,
            verify=config.verify_ssl
        )
        response.raise_for_status()

        indicators = []

        for line in response.text.strip().split('\n'):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#') or line.startswith(';'):
                continue

            # Extract IP (may have additional info after it)
            parts = line.split()
            ip = parts[0] if parts else line

            # Basic IP validation
            if self._is_valid_ip(ip):
                indicators.append({
                    'type': 'ip',
                    'value': ip,
                    'source': config.name,
                    'raw_line': line
                })

        return indicators

    def _fetch_csv(self, config: ThreatFeedConfig) -> List[dict]:
        """Fetch CSV feed"""
        import csv
        from io import StringIO

        headers = {}
        if config.api_key:
            headers[config.api_key_header] = config.api_key

        response = self._session.get(
            config.url,
            headers=headers,
            timeout=config.timeout,
            verify=config.verify_ssl
        )
        response.raise_for_status()

        indicators = []
        reader = csv.DictReader(StringIO(response.text))

        for row in reader:
            indicators.append({
                'source': config.name,
                **row
            })

        return indicators

    def _parse_json_feed(self, source: str, data: Any) -> List[dict]:
        """Parse JSON feed based on source"""
        indicators = []

        # URLhaus
        if source == 'abuse_ch_urlhaus':
            urls = data if isinstance(data, dict) else {}
            for url_id, item in urls.get('urls', {}).items():
                indicators.append({
                    'type': 'url',
                    'value': item.get('url', ''),
                    'source': source,
                    'url_status': item.get('url_status', ''),
                    'date_added': item.get('date_added', ''),
                    'threat': item.get('threat', ''),
                    'tags': item.get('tags', []),
                    'host': item.get('host', ''),
                    'reporter': item.get('reporter', '')
                })

        # ThreatFox
        elif source == 'abuse_ch_threatfox':
            for item in data.get('data', []):
                ioc_type = item.get('ioc_type', '').lower()
                if 'ip' in ioc_type:
                    ind_type = 'ip'
                elif 'domain' in ioc_type:
                    ind_type = 'domain'
                elif 'url' in ioc_type:
                    ind_type = 'url'
                elif 'hash' in ioc_type:
                    ind_type = 'hash_sha256'
                else:
                    ind_type = 'unknown'

                indicators.append({
                    'type': ind_type,
                    'value': item.get('ioc', ''),
                    'source': source,
                    'threat_type': item.get('threat_type', ''),
                    'malware': item.get('malware', ''),
                    'confidence': item.get('confidence_level', 0),
                    'first_seen': item.get('first_seen_utc', ''),
                    'tags': item.get('tags', [])
                })

        # Feodo Tracker
        elif source == 'abuse_ch_feodo':
            for item in data if isinstance(data, list) else []:
                indicators.append({
                    'type': 'ip',
                    'value': item.get('ip_address', ''),
                    'source': source,
                    'port': item.get('port', 0),
                    'status': item.get('status', ''),
                    'malware': item.get('malware', ''),
                    'first_seen': item.get('first_seen', ''),
                    'last_online': item.get('last_online', ''),
                    'as_number': item.get('as_number', ''),
                    'country': item.get('country', '')
                })

        # SSL Blacklist
        elif source == 'abuse_ch_sslbl':
            for item in data if isinstance(data, list) else []:
                indicators.append({
                    'type': 'ip',
                    'value': item.get('ip_address', ''),
                    'source': source,
                    'port': item.get('port', 443),
                    'status': item.get('status', ''),
                    'sha1': item.get('sha1', ''),
                    'reason': item.get('reason', ''),
                    'first_seen': item.get('first_seen', '')
                })

        # CISA KEV
        elif source == 'cisa_kev':
            for vuln in data.get('vulnerabilities', []):
                indicators.append({
                    'type': 'cve',
                    'value': vuln.get('cveID', ''),
                    'source': source,
                    'vendor': vuln.get('vendorProject', ''),
                    'product': vuln.get('product', ''),
                    'vulnerability_name': vuln.get('vulnerabilityName', ''),
                    'date_added': vuln.get('dateAdded', ''),
                    'due_date': vuln.get('dueDate', ''),
                    'short_description': vuln.get('shortDescription', ''),
                    'known_ransomware': vuln.get('knownRansomwareCampaignUse', ''),
                    'notes': vuln.get('notes', '')
                })

        # Generic JSON
        else:
            if isinstance(data, list):
                indicators = [{'source': source, **item} if isinstance(item, dict) else {'source': source, 'value': item} for item in data]
            elif isinstance(data, dict):
                indicators = [{'source': source, **data}]

        return indicators

    def _normalize_stix_object(self, obj: Any) -> dict:
        """Normalize STIX object to standard format"""
        if isinstance(obj, dict):
            return {
                'stix_type': obj.get('type', ''),
                'stix_id': obj.get('id', ''),
                'source': 'stix_bundle',
                **obj
            }

        # For stix2 objects
        return {
            'stix_type': getattr(obj, 'type', ''),
            'stix_id': getattr(obj, 'id', ''),
            'source': 'stix_bundle',
            **obj.serialize()
        }

    def _map_otx_type(self, otx_type: str) -> str:
        """Map OTX indicator type to standard type"""
        type_map = {
            'IPv4': 'ip',
            'IPv6': 'ip',
            'domain': 'domain',
            'hostname': 'domain',
            'URL': 'url',
            'URI': 'url',
            'FileHash-MD5': 'hash_md5',
            'FileHash-SHA1': 'hash_sha1',
            'FileHash-SHA256': 'hash_sha256',
            'email': 'email',
            'CVE': 'cve',
            'YARA': 'yara',
            'CIDR': 'cidr'
        }
        return type_map.get(otx_type, 'unknown')

    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is a valid IP address"""
        import ipaddress
        try:
            # Handle CIDR notation
            if '/' in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def fetch_all_feeds(self, force: bool = False) -> Dict[str, List[dict]]:
        """
        Fetch all enabled feeds

        Returns:
            Dict mapping feed name to list of indicators
        """
        results = {}

        for name, config in self.feeds.items():
            if not config.enabled:
                continue

            try:
                indicators = self.fetch_feed(name, force=force)
                results[name] = indicators
            except Exception as e:
                logger.error(f"[STIX-TAXII] Failed to fetch {name}: {e}")
                results[name] = []

        return results

    def start_auto_update(self, interval: int = 3600) -> None:
        """Start automatic feed updates in background"""
        if self._running:
            return

        self._running = True
        self._update_thread = threading.Thread(
            target=self._auto_update_loop,
            args=(interval,),
            daemon=True
        )
        self._update_thread.start()
        logger.info(f"[STIX-TAXII] Auto-update started (interval: {interval}s)")

    def stop_auto_update(self) -> None:
        """Stop automatic feed updates"""
        self._running = False
        if self._update_thread:
            self._update_thread.join(timeout=5)
        logger.info("[STIX-TAXII] Auto-update stopped")

    def _auto_update_loop(self, interval: int) -> None:
        """Background update loop"""
        while self._running:
            try:
                self.fetch_all_feeds()
            except Exception as e:
                logger.error(f"[STIX-TAXII] Auto-update error: {e}")

            time.sleep(interval)

    def get_feed_status(self) -> Dict[str, dict]:
        """Get status of all feeds"""
        status = {}

        for name, state in self.feed_states.items():
            config = self.feeds.get(name)
            status[name] = {
                'name': name,
                'enabled': config.enabled if config else False,
                'status': state.status.value,
                'last_update': state.last_update.isoformat() if state.last_update else None,
                'last_error': state.last_error,
                'indicators_count': state.indicators_count,
                'update_count': state.update_count,
                'description': config.description if config else '',
                'update_interval': config.update_interval if config else 0
            }

        return status

    def get_statistics(self) -> dict:
        """Get overall statistics"""
        total_indicators = sum(s.indicators_count for s in self.feed_states.values())
        active_feeds = sum(1 for s in self.feed_states.values() if s.status == FeedStatus.ACTIVE)
        error_feeds = sum(1 for s in self.feed_states.values() if s.status == FeedStatus.ERROR)

        return {
            'total_feeds': len(self.feeds),
            'enabled_feeds': sum(1 for f in self.feeds.values() if f.enabled),
            'active_feeds': active_feeds,
            'error_feeds': error_feeds,
            'total_indicators': total_indicators,
            'taxii_available': TAXII_AVAILABLE,
            'stix2_available': STIX2_AVAILABLE,
            'cache_dir': str(self.cache_dir)
        }


# Singleton instance
_stix_client: Optional[STIXTAXIIClient] = None


def get_stix_client() -> STIXTAXIIClient:
    """Get singleton STIX/TAXII client instance"""
    global _stix_client
    if _stix_client is None:
        _stix_client = STIXTAXIIClient()
    return _stix_client
