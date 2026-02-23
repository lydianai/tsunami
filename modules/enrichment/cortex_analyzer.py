#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Cortex Analyzer Integration
    SOAR Observable Analysis via Cortex REST API
================================================================================

    Features:
    - Full Cortex REST API v1 integration (jobs, analyzers, responders)
    - Observable analysis submission and polling
    - Analyzer discovery and capability mapping
    - Responder execution for automated response
    - Job status tracking with configurable polling
    - Taxonomies and report artifact extraction
    - Batch observable analysis
    - Analysis result caching (SQLite-backed)
    - Rate limiting per organization
    - Thread-safe operations
    - Flask Blueprint for REST API
    - Health check and statistics

================================================================================
"""

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("tsunami.enrichment.cortex")


# ============================================================================
# Enums and Constants
# ============================================================================

class JobStatus(Enum):
    """Cortex job status values."""
    WAITING = "Waiting"
    IN_PROGRESS = "InProgress"
    SUCCESS = "Success"
    FAILURE = "Failure"
    DELETED = "Deleted"
    UNKNOWN = "Unknown"


class TlpLevel(Enum):
    """Traffic Light Protocol levels."""
    WHITE = 0
    GREEN = 1
    AMBER = 2
    RED = 3


class PapLevel(Enum):
    """Permissible Actions Protocol levels."""
    WHITE = 0
    GREEN = 1
    AMBER = 2
    RED = 3


class ObservableDataType(Enum):
    """Cortex observable data types."""
    DOMAIN = "domain"
    FQDN = "fqdn"
    FILENAME = "filename"
    HASH = "hash"
    IP = "ip"
    MAIL = "mail"
    URL = "url"
    USER_AGENT = "user-agent"
    REGEXP = "regexp"
    OTHER = "other"
    FILE = "file"


class TaxonomyLevel(Enum):
    """Taxonomy severity levels."""
    INFO = "info"
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class ConnectionStatus(Enum):
    """Cortex connection health status."""
    CONNECTED = "connected"
    DEGRADED = "degraded"
    DISCONNECTED = "disconnected"
    AUTH_ERROR = "auth_error"


POLL_DEFAULTS = {
    "interval": 3.0,
    "max_wait": 300.0,
    "backoff_factor": 1.5,
    "max_interval": 30.0,
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class AnalyzerInfo:
    """Cortex analyzer descriptor."""
    id: str = ""
    name: str = ""
    version: str = ""
    description: str = ""
    data_type_list: List[str] = field(default_factory=list)
    max_tlp: int = 3
    max_pap: int = 3
    author: str = ""
    url: str = ""
    license_str: str = ""
    base_config: str = ""
    rate_per_minute: Optional[int] = None

    def supports_data_type(self, dtype: str) -> bool:
        return dtype in self.data_type_list

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "dataTypeList": self.data_type_list,
            "maxTlp": self.max_tlp,
            "maxPap": self.max_pap,
            "author": self.author,
            "url": self.url,
            "license": self.license_str,
            "baseConfig": self.base_config,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AnalyzerInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", data.get("id", "")),
            version=data.get("version", ""),
            description=data.get("description", ""),
            data_type_list=data.get("dataTypeList", []),
            max_tlp=data.get("maxTlp", 3),
            max_pap=data.get("maxPap", 3),
            author=data.get("author", ""),
            url=data.get("url", ""),
            license_str=data.get("license", ""),
            base_config=data.get("baseConfig", ""),
            rate_per_minute=data.get("rate", {}).get("ratePerMinute") if isinstance(data.get("rate"), dict) else None,
        )


@dataclass
class ResponderInfo:
    """Cortex responder descriptor."""
    id: str = ""
    name: str = ""
    version: str = ""
    description: str = ""
    data_type_list: List[str] = field(default_factory=list)
    max_tlp: int = 3
    max_pap: int = 3
    author: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "dataTypeList": self.data_type_list,
            "maxTlp": self.max_tlp,
            "maxPap": self.max_pap,
            "author": self.author,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResponderInfo":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", data.get("id", "")),
            version=data.get("version", ""),
            description=data.get("description", ""),
            data_type_list=data.get("dataTypeList", []),
            max_tlp=data.get("maxTlp", 3),
            max_pap=data.get("maxPap", 3),
            author=data.get("author", ""),
        )


@dataclass
class Taxonomy:
    """Analyzer report taxonomy entry."""
    level: str = "info"
    namespace: str = ""
    predicate: str = ""
    value: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "namespace": self.namespace,
            "predicate": self.predicate,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Taxonomy":
        return cls(
            level=data.get("level", "info"),
            namespace=data.get("namespace", ""),
            predicate=data.get("predicate", ""),
            value=data.get("value", ""),
        )


@dataclass
class Artifact:
    """Report artifact extracted from analysis."""
    data_type: str = ""
    data: str = ""
    message: str = ""
    tlp: int = 2
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataType": self.data_type,
            "data": self.data,
            "message": self.message,
            "tlp": self.tlp,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Artifact":
        return cls(
            data_type=data.get("dataType", ""),
            data=data.get("data", ""),
            message=data.get("message", ""),
            tlp=data.get("tlp", 2),
            tags=data.get("tags", []),
        )


@dataclass
class AnalysisReport:
    """Result from a completed analysis job."""
    job_id: str = ""
    analyzer_id: str = ""
    analyzer_name: str = ""
    status: str = JobStatus.UNKNOWN.value
    data: str = ""
    data_type: str = ""
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    taxonomies: List[Taxonomy] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    full_report: Dict[str, Any] = field(default_factory=dict)
    error_message: str = ""
    duration_ms: int = 0

    @property
    def success(self) -> bool:
        return self.status == JobStatus.SUCCESS.value

    @property
    def malicious(self) -> bool:
        return any(t.level == TaxonomyLevel.MALICIOUS.value for t in self.taxonomies)

    @property
    def suspicious(self) -> bool:
        return any(t.level == TaxonomyLevel.SUSPICIOUS.value for t in self.taxonomies)

    @property
    def max_severity(self) -> str:
        levels = [TaxonomyLevel.INFO, TaxonomyLevel.SAFE, TaxonomyLevel.SUSPICIOUS, TaxonomyLevel.MALICIOUS]
        level_order = {l.value: i for i, l in enumerate(levels)}
        max_level = "info"
        for t in self.taxonomies:
            if level_order.get(t.level, 0) > level_order.get(max_level, 0):
                max_level = t.level
        return max_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "jobId": self.job_id,
            "analyzerId": self.analyzer_id,
            "analyzerName": self.analyzer_name,
            "status": self.status,
            "data": self.data,
            "dataType": self.data_type,
            "startDate": self.start_date,
            "endDate": self.end_date,
            "taxonomies": [t.to_dict() for t in self.taxonomies],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "success": self.success,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "maxSeverity": self.max_severity,
            "errorMessage": self.error_message,
            "durationMs": self.duration_ms,
        }

    @classmethod
    def from_job_response(cls, job_data: Dict[str, Any], report_data: Optional[Dict[str, Any]] = None) -> "AnalysisReport":
        report = cls(
            job_id=job_data.get("id", ""),
            analyzer_id=job_data.get("analyzerId", ""),
            analyzer_name=job_data.get("analyzerName", job_data.get("analyzerId", "")),
            status=job_data.get("status", JobStatus.UNKNOWN.value),
            data=job_data.get("data", ""),
            data_type=job_data.get("dataType", ""),
        )

        start = job_data.get("startDate")
        end = job_data.get("endDate")
        if start:
            report.start_date = datetime.fromtimestamp(start / 1000, tz=timezone.utc).isoformat() if isinstance(start, (int, float)) else str(start)
        if end:
            report.end_date = datetime.fromtimestamp(end / 1000, tz=timezone.utc).isoformat() if isinstance(end, (int, float)) else str(end)

        if start and end and isinstance(start, (int, float)) and isinstance(end, (int, float)):
            report.duration_ms = int(end - start)

        if report_data:
            report.full_report = report_data
            report._parse_report(report_data)

        return report

    def _parse_report(self, report_data: Dict[str, Any]):
        # Extract taxonomies
        summary = report_data.get("summary", {})
        if isinstance(summary, dict):
            tax_list = summary.get("taxonomies", [])
            self.taxonomies = [Taxonomy.from_dict(t) for t in tax_list if isinstance(t, dict)]

        # Extract artifacts
        art_list = report_data.get("artifacts", [])
        self.artifacts = [Artifact.from_dict(a) for a in art_list if isinstance(a, dict)]

        if report_data.get("errorMessage"):
            self.error_message = report_data["errorMessage"]


@dataclass
class AnalysisBatchResult:
    """Result from a batch analysis."""
    observable: str = ""
    data_type: str = ""
    reports: List[AnalysisReport] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def any_malicious(self) -> bool:
        return any(r.malicious for r in self.reports)

    @property
    def any_suspicious(self) -> bool:
        return any(r.suspicious for r in self.reports)

    @property
    def max_severity(self) -> str:
        levels = [TaxonomyLevel.INFO, TaxonomyLevel.SAFE, TaxonomyLevel.SUSPICIOUS, TaxonomyLevel.MALICIOUS]
        level_order = {l.value: i for i, l in enumerate(levels)}
        max_level = "info"
        for r in self.reports:
            if level_order.get(r.max_severity, 0) > level_order.get(max_level, 0):
                max_level = r.max_severity
        return max_level

    def to_dict(self) -> Dict[str, Any]:
        return {
            "observable": self.observable,
            "dataType": self.data_type,
            "reports": [r.to_dict() for r in self.reports],
            "anyMalicious": self.any_malicious,
            "anySuspicious": self.any_suspicious,
            "maxSeverity": self.max_severity,
            "timestamp": self.timestamp,
        }


# ============================================================================
# Cortex HTTP Client
# ============================================================================

class CortexHTTPClient:
    """HTTP client for Cortex REST API v1."""

    def __init__(self, base_url: str, api_key: str, verify_ssl: bool = True, timeout: int = 30):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._session = None

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _request(self, method: str, path: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make HTTP request to Cortex API. Uses requests if available, falls back to urllib."""
        url = f"{self.base_url}{path}"
        headers = self._get_headers()

        try:
            import requests as req_lib
            resp = req_lib.request(
                method=method,
                url=url,
                headers=headers,
                json=data,
                params=params,
                verify=self.verify_ssl,
                timeout=self.timeout,
            )
            if resp.status_code == 401:
                raise CortexAuthError("Authentication failed: invalid API key")
            if resp.status_code == 403:
                raise CortexAuthError("Authorization failed: insufficient permissions")
            if resp.status_code == 404:
                raise CortexNotFoundError(f"Resource not found: {path}")
            if resp.status_code >= 500:
                raise CortexServerError(f"Server error {resp.status_code}: {resp.text[:200]}")
            if resp.status_code >= 400:
                raise CortexAPIError(f"API error {resp.status_code}: {resp.text[:200]}")
            if resp.status_code == 204:
                return {}
            return resp.json()
        except ImportError:
            # Fallback to urllib
            import urllib.request
            import urllib.error
            import urllib.parse

            if params:
                url += "?" + urllib.parse.urlencode(params)

            body = json.dumps(data).encode("utf-8") if data else None
            req = urllib.request.Request(url, data=body, headers=headers, method=method)

            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    resp_data = resp.read().decode("utf-8")
                    return json.loads(resp_data) if resp_data else {}
            except urllib.error.HTTPError as e:
                if e.code == 401:
                    raise CortexAuthError("Authentication failed") from e
                if e.code == 403:
                    raise CortexAuthError("Authorization failed") from e
                if e.code == 404:
                    raise CortexNotFoundError(f"Not found: {path}") from e
                raise CortexAPIError(f"HTTP {e.code}: {e.reason}") from e

    def get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("GET", path, params=params)

    def post(self, path: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        return self._request("POST", path, data=data)

    def delete(self, path: str) -> Dict[str, Any]:
        return self._request("DELETE", path)

    def health_check(self) -> bool:
        try:
            self.get("/api/status")
            return True
        except Exception:
            return False


# ============================================================================
# Exceptions
# ============================================================================

class CortexError(Exception):
    """Base exception for Cortex operations."""
    pass


class CortexAuthError(CortexError):
    """Authentication/authorization error."""
    pass


class CortexNotFoundError(CortexError):
    """Resource not found."""
    pass


class CortexServerError(CortexError):
    """Server-side error."""
    pass


class CortexAPIError(CortexError):
    """Generic API error."""
    pass


class CortexTimeoutError(CortexError):
    """Job polling timeout."""
    pass


# ============================================================================
# Analysis Cache
# ============================================================================

class AnalysisCache:
    """SQLite-backed TTL cache for analysis results."""

    def __init__(self, db_path: Optional[str] = None, default_ttl: int = 1800):
        if db_path is None:
            cache_dir = Path.home() / ".dalga"
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(cache_dir / "cortex_cache.db")

        self.db_path = db_path
        self.default_ttl = default_ttl
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS analysis_cache (
                    cache_key TEXT PRIMARY KEY,
                    analyzer_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    ttl INTEGER NOT NULL
                )
            """)
            conn.commit()
            conn.close()

    def _make_key(self, observable: str, data_type: str, analyzer_id: str) -> str:
        return f"{analyzer_id}:{data_type}:{observable}"

    def get(self, observable: str, data_type: str, analyzer_id: str) -> Optional[Dict[str, Any]]:
        key = self._make_key(observable, data_type, analyzer_id)
        now = time.time()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                row = conn.execute(
                    "SELECT data, created_at, ttl FROM analysis_cache WHERE cache_key = ?",
                    (key,),
                ).fetchone()
                if row:
                    data_str, created_at, ttl = row
                    if now - created_at < ttl:
                        return json.loads(data_str)
                    conn.execute("DELETE FROM analysis_cache WHERE cache_key = ?", (key,))
                    conn.commit()
                return None
            finally:
                conn.close()

    def set(self, observable: str, data_type: str, analyzer_id: str,
            data: Dict[str, Any], ttl: Optional[int] = None):
        key = self._make_key(observable, data_type, analyzer_id)
        ttl = ttl or self.default_ttl
        now = time.time()
        data_str = json.dumps(data, default=str)
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO analysis_cache (cache_key, analyzer_id, data, created_at, ttl) VALUES (?, ?, ?, ?, ?)",
                    (key, analyzer_id, data_str, now, ttl),
                )
                conn.commit()
            finally:
                conn.close()

    def delete(self, observable: str, data_type: str, analyzer_id: str):
        key = self._make_key(observable, data_type, analyzer_id)
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("DELETE FROM analysis_cache WHERE cache_key = ?", (key,))
                conn.commit()
            finally:
                conn.close()

    def clear(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("DELETE FROM analysis_cache")
                conn.commit()
            finally:
                conn.close()

    def clear_expired(self) -> int:
        now = time.time()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                cursor = conn.execute(
                    "DELETE FROM analysis_cache WHERE (? - created_at) >= ttl",
                    (now,),
                )
                conn.commit()
                return cursor.rowcount
            finally:
                conn.close()

    def stats(self) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                total = conn.execute("SELECT COUNT(*) FROM analysis_cache").fetchone()[0]
                expired = conn.execute(
                    "SELECT COUNT(*) FROM analysis_cache WHERE (? - created_at) >= ttl",
                    (now,),
                ).fetchone()[0]
                return {"total_entries": total, "expired": expired, "active": total - expired}
            finally:
                conn.close()


# ============================================================================
# Cortex Analyzer Client
# ============================================================================

class CortexAnalyzerClient:
    """Client for interacting with Cortex analyzers and responders."""

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        verify_ssl: bool = True,
        timeout: int = 30,
        cache: Optional[AnalysisCache] = None,
        poll_interval: float = POLL_DEFAULTS["interval"],
        poll_max_wait: float = POLL_DEFAULTS["max_wait"],
    ):
        self.base_url = base_url or os.environ.get("CORTEX_URL", "")
        self.api_key = api_key or os.environ.get("CORTEX_API_KEY", "")
        self.verify_ssl = verify_ssl
        self.cache = cache or AnalysisCache()
        self.poll_interval = poll_interval
        self.poll_max_wait = poll_max_wait
        self._lock = threading.Lock()

        # Stats
        self._stats = {
            "jobs_submitted": 0,
            "jobs_completed": 0,
            "jobs_failed": 0,
            "jobs_timeout": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "responder_runs": 0,
            "errors": 0,
        }

        # Analyzer and responder registries
        self._analyzers: Dict[str, AnalyzerInfo] = {}
        self._responders: Dict[str, ResponderInfo] = {}
        self._http: Optional[CortexHTTPClient] = None

        if self.base_url and self.api_key:
            self._http = CortexHTTPClient(self.base_url, self.api_key, verify_ssl, timeout)

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    @property
    def http(self) -> CortexHTTPClient:
        if self._http is None:
            if not self.configured:
                raise CortexError("Cortex client not configured: missing URL or API key")
            self._http = CortexHTTPClient(self.base_url, self.api_key, self.verify_ssl)
        return self._http

    # --- Connection & Health ---

    def check_connection(self) -> ConnectionStatus:
        if not self.configured:
            return ConnectionStatus.DISCONNECTED
        try:
            result = self.http.get("/api/status")
            if result:
                return ConnectionStatus.CONNECTED
            return ConnectionStatus.DEGRADED
        except CortexAuthError:
            return ConnectionStatus.AUTH_ERROR
        except Exception:
            return ConnectionStatus.DISCONNECTED

    def get_status(self) -> Dict[str, Any]:
        return {
            "configured": self.configured,
            "connection": self.check_connection().value,
            "base_url": self.base_url,
            "analyzers_loaded": len(self._analyzers),
            "responders_loaded": len(self._responders),
            "stats": dict(self._stats),
            "cache": self.cache.stats(),
        }

    # --- Analyzer Discovery ---

    def list_analyzers(self, data_type: Optional[str] = None) -> List[AnalyzerInfo]:
        """List available analyzers, optionally filtered by data type."""
        if data_type:
            result = self.http.get(f"/api/analyzer/type/{data_type}")
        else:
            result = self.http.get("/api/analyzer")

        analyzers = []
        items = result if isinstance(result, list) else []
        for item in items:
            if isinstance(item, dict):
                a = AnalyzerInfo.from_dict(item)
                self._analyzers[a.id] = a
                analyzers.append(a)
        return analyzers

    def get_analyzer(self, analyzer_id: str) -> AnalyzerInfo:
        """Get specific analyzer details."""
        if analyzer_id in self._analyzers:
            return self._analyzers[analyzer_id]
        result = self.http.get(f"/api/analyzer/{analyzer_id}")
        a = AnalyzerInfo.from_dict(result)
        self._analyzers[a.id] = a
        return a

    def find_analyzers_for(self, data_type: str) -> List[AnalyzerInfo]:
        """Find analyzers that support a specific data type."""
        if not self._analyzers:
            self.list_analyzers()
        return [a for a in self._analyzers.values() if a.supports_data_type(data_type)]

    # --- Responder Discovery ---

    def list_responders(self, data_type: Optional[str] = None) -> List[ResponderInfo]:
        """List available responders, optionally filtered by data type."""
        if data_type:
            result = self.http.get(f"/api/responder/type/{data_type}")
        else:
            result = self.http.get("/api/responder")

        responders = []
        items = result if isinstance(result, list) else []
        for item in items:
            if isinstance(item, dict):
                r = ResponderInfo.from_dict(item)
                self._responders[r.id] = r
                responders.append(r)
        return responders

    def get_responder(self, responder_id: str) -> ResponderInfo:
        if responder_id in self._responders:
            return self._responders[responder_id]
        result = self.http.get(f"/api/responder/{responder_id}")
        r = ResponderInfo.from_dict(result)
        self._responders[r.id] = r
        return r

    # --- Job Submission ---

    def run_analyzer(
        self,
        analyzer_id: str,
        observable: str,
        data_type: str,
        tlp: int = TlpLevel.AMBER.value,
        pap: int = PapLevel.AMBER.value,
        message: str = "",
        parameters: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> Dict[str, Any]:
        """Submit an observable to an analyzer for analysis."""
        # Check cache first
        if not force:
            cached = self.cache.get(observable, data_type, analyzer_id)
            if cached:
                with self._lock:
                    self._stats["cache_hits"] += 1
                cached["_cached"] = True
                return cached

        with self._lock:
            self._stats["cache_misses"] += 1

        payload = {
            "data": observable,
            "dataType": data_type,
            "tlp": tlp,
            "pap": pap,
            "message": message or f"TSUNAMI SOC analysis: {observable}",
        }
        if parameters:
            payload["parameters"] = parameters

        result = self.http.post(f"/api/analyzer/{analyzer_id}/run", data=payload)

        with self._lock:
            self._stats["jobs_submitted"] += 1

        return result

    def get_job(self, job_id: str) -> Dict[str, Any]:
        """Get job status and details."""
        return self.http.get(f"/api/job/{job_id}")

    def get_job_report(self, job_id: str) -> Dict[str, Any]:
        """Get the full report for a completed job."""
        return self.http.get(f"/api/job/{job_id}/report")

    def wait_for_job(self, job_id: str, poll_interval: Optional[float] = None, max_wait: Optional[float] = None) -> Dict[str, Any]:
        """Poll a job until completion or timeout."""
        interval = poll_interval or self.poll_interval
        max_wait_time = max_wait or self.poll_max_wait
        start = time.time()

        while True:
            elapsed = time.time() - start
            if elapsed >= max_wait_time:
                with self._lock:
                    self._stats["jobs_timeout"] += 1
                raise CortexTimeoutError(f"Job {job_id} did not complete within {max_wait_time}s")

            job_data = self.get_job(job_id)
            status = job_data.get("status", "")

            if status == JobStatus.SUCCESS.value:
                with self._lock:
                    self._stats["jobs_completed"] += 1
                return job_data
            elif status == JobStatus.FAILURE.value:
                with self._lock:
                    self._stats["jobs_failed"] += 1
                return job_data
            elif status == JobStatus.DELETED.value:
                with self._lock:
                    self._stats["jobs_failed"] += 1
                return job_data

            time.sleep(min(interval, max_wait_time - elapsed))
            interval = min(interval * POLL_DEFAULTS["backoff_factor"], POLL_DEFAULTS["max_interval"])

    def delete_job(self, job_id: str) -> Dict[str, Any]:
        """Delete/cancel a job."""
        return self.http.delete(f"/api/job/{job_id}")

    # --- Full Analysis Flow ---

    def analyze(
        self,
        analyzer_id: str,
        observable: str,
        data_type: str,
        tlp: int = TlpLevel.AMBER.value,
        pap: int = PapLevel.AMBER.value,
        message: str = "",
        parameters: Optional[Dict[str, Any]] = None,
        force: bool = False,
        poll_interval: Optional[float] = None,
        max_wait: Optional[float] = None,
    ) -> AnalysisReport:
        """Run analyzer, wait for completion, and return parsed report."""
        # Check cache
        if not force:
            cached = self.cache.get(observable, data_type, analyzer_id)
            if cached:
                with self._lock:
                    self._stats["cache_hits"] += 1
                report = AnalysisReport(**{k: v for k, v in cached.items() if k != "_cached" and k in AnalysisReport.__dataclass_fields__})
                if "taxonomies" in cached:
                    report.taxonomies = [Taxonomy.from_dict(t) if isinstance(t, dict) else t for t in cached["taxonomies"]]
                if "artifacts" in cached:
                    report.artifacts = [Artifact.from_dict(a) if isinstance(a, dict) else a for a in cached["artifacts"]]
                return report

        with self._lock:
            self._stats["cache_misses"] += 1

        try:
            # Submit job
            job_result = self.run_analyzer(analyzer_id, observable, data_type, tlp, pap, message, parameters, force=True)
            job_id = job_result.get("id", "")

            if not job_id:
                raise CortexAPIError("No job ID returned from analyzer run")

            # Wait for completion
            job_data = self.wait_for_job(job_id, poll_interval, max_wait)

            # Get report
            report_data = None
            if job_data.get("status") == JobStatus.SUCCESS.value:
                try:
                    report_data = self.get_job_report(job_id)
                except Exception as e:
                    logger.warning(f"Failed to get report for job {job_id}: {e}")

            report = AnalysisReport.from_job_response(job_data, report_data)

            # Cache successful results
            if report.success:
                cache_data = report.to_dict()
                self.cache.set(observable, data_type, analyzer_id, cache_data)

            return report

        except CortexTimeoutError:
            raise
        except Exception as e:
            with self._lock:
                self._stats["errors"] += 1
            return AnalysisReport(
                analyzer_id=analyzer_id,
                analyzer_name=analyzer_id,
                status=JobStatus.FAILURE.value,
                data=observable,
                data_type=data_type,
                error_message=str(e),
            )

    def analyze_observable(
        self,
        observable: str,
        data_type: str,
        analyzer_ids: Optional[List[str]] = None,
        tlp: int = TlpLevel.AMBER.value,
        pap: int = PapLevel.AMBER.value,
        force: bool = False,
    ) -> AnalysisBatchResult:
        """Analyze an observable with multiple analyzers."""
        if analyzer_ids is None:
            analyzer_ids = [a.id for a in self.find_analyzers_for(data_type)]

        batch = AnalysisBatchResult(observable=observable, data_type=data_type)

        for aid in analyzer_ids:
            try:
                report = self.analyze(aid, observable, data_type, tlp, pap, force=force)
                batch.reports.append(report)
            except Exception as e:
                logger.error(f"Error analyzing {observable} with {aid}: {e}")
                batch.reports.append(AnalysisReport(
                    analyzer_id=aid,
                    status=JobStatus.FAILURE.value,
                    data=observable,
                    data_type=data_type,
                    error_message=str(e),
                ))

        return batch

    # --- Responder Execution ---

    def run_responder(
        self,
        responder_id: str,
        data: Dict[str, Any],
        data_type: str = "thehive:case",
        tlp: int = TlpLevel.AMBER.value,
        pap: int = PapLevel.AMBER.value,
        message: str = "",
        parameters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a responder action."""
        payload = {
            "data": data,
            "dataType": data_type,
            "tlp": tlp,
            "pap": pap,
            "message": message or "TSUNAMI SOC responder action",
        }
        if parameters:
            payload["parameters"] = parameters

        result = self.http.post(f"/api/responder/{responder_id}/run", data=payload)

        with self._lock:
            self._stats["responder_runs"] += 1

        return result

    # --- Stats ---

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self):
        with self._lock:
            for k in self._stats:
                self._stats[k] = 0


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_cortex_blueprint(client: Optional[CortexAnalyzerClient] = None):
    """Create Flask Blueprint for Cortex Analyzer REST API."""
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        logger.warning("Flask not available, Cortex blueprint disabled")
        return None

    bp = Blueprint("cortex_analyzer", __name__, url_prefix="/api/v1/soc/cortex")
    _client = client

    def get_client() -> CortexAnalyzerClient:
        nonlocal _client
        if _client is None:
            _client = get_cortex_client()
        return _client

    @bp.route("/status", methods=["GET"])
    def status():
        c = get_client()
        return jsonify({"success": True, "data": c.get_status()})

    @bp.route("/analyzers", methods=["GET"])
    def list_analyzers():
        c = get_client()
        dtype = request.args.get("dataType")
        try:
            analyzers = c.list_analyzers(dtype)
            return jsonify({"success": True, "data": [a.to_dict() for a in analyzers]})
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/analyzers/<analyzer_id>", methods=["GET"])
    def get_analyzer(analyzer_id):
        c = get_client()
        try:
            a = c.get_analyzer(analyzer_id)
            return jsonify({"success": True, "data": a.to_dict()})
        except CortexNotFoundError:
            return jsonify({"success": False, "error": "Analyzer not found"}), 404
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/responders", methods=["GET"])
    def list_responders():
        c = get_client()
        dtype = request.args.get("dataType")
        try:
            responders = c.list_responders(dtype)
            return jsonify({"success": True, "data": [r.to_dict() for r in responders]})
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/analyze", methods=["POST"])
    def analyze_ioc():
        c = get_client()
        body = request.get_json(silent=True) or {}
        observable = body.get("data", "").strip()
        data_type = body.get("dataType", "").strip()
        analyzer_id = body.get("analyzerId", "").strip()

        if not observable:
            return jsonify({"success": False, "error": "Missing 'data' field"}), 400
        if not data_type:
            return jsonify({"success": False, "error": "Missing 'dataType' field"}), 400
        if not analyzer_id:
            return jsonify({"success": False, "error": "Missing 'analyzerId' field"}), 400

        tlp = body.get("tlp", TlpLevel.AMBER.value)
        pap = body.get("pap", PapLevel.AMBER.value)
        force = body.get("force", False)
        message = body.get("message", "")

        try:
            report = c.analyze(analyzer_id, observable, data_type, tlp, pap, message, force=force)
            return jsonify({"success": True, "data": report.to_dict()})
        except CortexTimeoutError as e:
            return jsonify({"success": False, "error": str(e)}), 408
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/analyze/batch", methods=["POST"])
    def analyze_batch():
        c = get_client()
        body = request.get_json(silent=True) or {}
        observable = body.get("data", "").strip()
        data_type = body.get("dataType", "").strip()
        analyzer_ids = body.get("analyzerIds")

        if not observable:
            return jsonify({"success": False, "error": "Missing 'data' field"}), 400
        if not data_type:
            return jsonify({"success": False, "error": "Missing 'dataType' field"}), 400

        tlp = body.get("tlp", TlpLevel.AMBER.value)
        pap = body.get("pap", PapLevel.AMBER.value)
        force = body.get("force", False)

        try:
            result = c.analyze_observable(observable, data_type, analyzer_ids, tlp, pap, force)
            return jsonify({"success": True, "data": result.to_dict()})
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/run", methods=["POST"])
    def run_analyzer_job():
        c = get_client()
        body = request.get_json(silent=True) or {}
        observable = body.get("data", "").strip()
        data_type = body.get("dataType", "").strip()
        analyzer_id = body.get("analyzerId", "").strip()

        if not observable or not data_type or not analyzer_id:
            return jsonify({"success": False, "error": "Missing required fields (data, dataType, analyzerId)"}), 400

        try:
            result = c.run_analyzer(analyzer_id, observable, data_type)
            return jsonify({"success": True, "data": result})
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/job/<job_id>", methods=["GET"])
    def get_job(job_id):
        c = get_client()
        try:
            result = c.get_job(job_id)
            return jsonify({"success": True, "data": result})
        except CortexNotFoundError:
            return jsonify({"success": False, "error": "Job not found"}), 404
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/job/<job_id>/report", methods=["GET"])
    def get_job_report(job_id):
        c = get_client()
        try:
            result = c.get_job_report(job_id)
            return jsonify({"success": True, "data": result})
        except CortexNotFoundError:
            return jsonify({"success": False, "error": "Job not found"}), 404
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/job/<job_id>", methods=["DELETE"])
    def delete_job(job_id):
        c = get_client()
        try:
            c.delete_job(job_id)
            return jsonify({"success": True, "message": "Job deleted"})
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/responder/run", methods=["POST"])
    def run_responder():
        c = get_client()
        body = request.get_json(silent=True) or {}
        responder_id = body.get("responderId", "").strip()
        data = body.get("data")
        data_type = body.get("dataType", "thehive:case")

        if not responder_id:
            return jsonify({"success": False, "error": "Missing 'responderId'"}), 400
        if not data:
            return jsonify({"success": False, "error": "Missing 'data'"}), 400

        try:
            result = c.run_responder(responder_id, data, data_type)
            return jsonify({"success": True, "data": result})
        except CortexError as e:
            return jsonify({"success": False, "error": str(e)}), 502

    @bp.route("/cache/clear", methods=["POST"])
    def clear_cache():
        c = get_client()
        c.cache.clear()
        return jsonify({"success": True, "message": "Cache cleared"})

    @bp.route("/cache/stats", methods=["GET"])
    def cache_stats():
        c = get_client()
        return jsonify({"success": True, "data": c.cache.stats()})

    @bp.route("/stats", methods=["GET"])
    def stats():
        c = get_client()
        return jsonify({"success": True, "data": c.get_stats()})

    return bp


# ============================================================================
# Global Singleton
# ============================================================================

_global_client: Optional[CortexAnalyzerClient] = None
_global_lock = threading.Lock()


def get_cortex_client() -> CortexAnalyzerClient:
    """Get or create the global Cortex client singleton."""
    global _global_client
    if _global_client is None:
        with _global_lock:
            if _global_client is None:
                _global_client = CortexAnalyzerClient()
    return _global_client


def reset_global_client():
    """Reset global client (for testing)."""
    global _global_client
    with _global_lock:
        _global_client = None
