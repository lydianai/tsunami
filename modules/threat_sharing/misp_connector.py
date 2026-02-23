#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - MISP Threat Intelligence Sharing Connector
    Production-Grade MISP Integration
================================================================================

    Features:
    - MISP REST API full integration (Events, Attributes, Objects, Tags)
    - IOC import: MISP → TSUNAMI (pull indicators)
    - IOC export: TSUNAMI → MISP (push indicators)
    - Feed management (subscribe, fetch, enable/disable)
    - Galaxy/Cluster mapping (threat actors, malware, tools, etc.)
    - Correlation engine (attribute-level and event-level)
    - Sighting management (true positive, false positive, expiration)
    - Sharing group support (TLP mapping)
    - Warninglist integration
    - Taxonomy and tag management
    - Search with MISP query syntax
    - Pagination, filtering, date range queries
    - Connection health check with retry and backoff
    - SQLite sync state tracking
    - Thread-safe operations
    - Flask Blueprint REST API (~35 endpoints)

================================================================================
"""

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("soc.misp")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ThreatLevel(IntEnum):
    """MISP threat level (1=High, 2=Medium, 3=Low, 4=Undefined)."""
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    UNDEFINED = 4


class AnalysisLevel(IntEnum):
    """MISP analysis level (0=Initial, 1=Ongoing, 2=Complete)."""
    INITIAL = 0
    ONGOING = 1
    COMPLETE = 2


class Distribution(IntEnum):
    """MISP distribution level."""
    YOUR_ORGANISATION_ONLY = 0
    THIS_COMMUNITY_ONLY = 1
    CONNECTED_COMMUNITIES = 2
    ALL_COMMUNITIES = 3
    SHARING_GROUP = 4


class AttributeCategory(str, Enum):
    """Common MISP attribute categories."""
    NETWORK_ACTIVITY = "Network activity"
    PAYLOAD_DELIVERY = "Payload delivery"
    PAYLOAD_INSTALLATION = "Payload installation"
    ARTIFACTS_DROPPED = "Artifacts dropped"
    EXTERNAL_ANALYSIS = "External analysis"
    ATTRIBUTION = "Attribution"
    ANTIVIRUS_DETECTION = "Antivirus detection"
    PERSISTENCE_MECHANISM = "Persistence mechanism"
    TARGETING_DATA = "Targeting data"
    FINANCIAL_FRAUD = "Financial fraud"
    SUPPORT_TOOL = "Support Tool"
    SOCIAL_NETWORK = "Social network"
    INTERNAL_REFERENCE = "Internal reference"
    OTHER = "Other"


class AttributeType(str, Enum):
    """Common MISP attribute types."""
    IP_SRC = "ip-src"
    IP_DST = "ip-dst"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL_SRC = "email-src"
    EMAIL_DST = "email-dst"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    FILENAME = "filename"
    FILENAME_MD5 = "filename|md5"
    FILENAME_SHA256 = "filename|sha256"
    MUTEX = "mutex"
    REGKEY = "regkey"
    PATTERN_IN_FILE = "pattern-in-file"
    VULNERABILITY = "vulnerability"
    USER_AGENT = "user-agent"
    AS_NUMBER = "AS"
    COMMENT = "comment"
    TEXT = "text"
    LINK = "link"
    PORT = "port"
    YARA = "yara"
    SIGMA = "sigma"
    SNORT = "snort"


class SightingType(IntEnum):
    """MISP sighting types."""
    TRUE_POSITIVE = 0
    FALSE_POSITIVE = 1
    EXPIRATION = 2


class SyncDirection(str, Enum):
    """Direction of synchronization."""
    MISP_TO_TSUNAMI = "misp_to_tsunami"
    TSUNAMI_TO_MISP = "tsunami_to_misp"
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(str, Enum):
    """Status of sync operations."""
    SYNCED = "synced"
    PENDING = "pending"
    FAILED = "failed"
    CONFLICT = "conflict"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class MISPAttribute:
    """Represents a MISP attribute (IOC)."""
    type: str = ""
    value: str = ""
    category: str = "Other"
    to_ids: bool = True
    comment: str = ""
    distribution: int = Distribution.YOUR_ORGANISATION_ONLY.value
    id: Optional[str] = None
    event_id: Optional[str] = None
    uuid: Optional[str] = None
    timestamp: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    disable_correlation: bool = False
    deleted: bool = False
    tags: List[Dict[str, Any]] = field(default_factory=list)

    def to_create_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "type": self.type,
            "value": self.value,
            "category": self.category,
            "to_ids": self.to_ids,
            "distribution": self.distribution,
            "disable_correlation": self.disable_correlation,
        }
        if self.comment:
            d["comment"] = self.comment
        if self.first_seen:
            d["first_seen"] = self.first_seen
        if self.last_seen:
            d["last_seen"] = self.last_seen
        return d

    def to_dict(self) -> Dict[str, Any]:
        d = self.to_create_dict()
        d["id"] = self.id
        d["event_id"] = self.event_id
        d["uuid"] = self.uuid or str(uuid.uuid4())
        d["timestamp"] = self.timestamp
        d["deleted"] = self.deleted
        d["tags"] = self.tags
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MISPAttribute":
        attr = data.get("Attribute", data)
        return cls(
            type=attr.get("type", ""),
            value=attr.get("value", ""),
            category=attr.get("category", "Other"),
            to_ids=attr.get("to_ids", True) in (True, "1", 1, "true"),
            comment=attr.get("comment", ""),
            distribution=int(attr.get("distribution", 0)),
            id=attr.get("id"),
            event_id=attr.get("event_id"),
            uuid=attr.get("uuid"),
            timestamp=attr.get("timestamp"),
            first_seen=attr.get("first_seen"),
            last_seen=attr.get("last_seen"),
            disable_correlation=attr.get("disable_correlation", False) in (True, "1", 1),
            deleted=attr.get("deleted", False) in (True, "1", 1),
            tags=attr.get("Tag", []),
        )


@dataclass
class MISPEvent:
    """Represents a MISP event (incident/threat report)."""
    info: str = ""
    threat_level_id: int = ThreatLevel.UNDEFINED.value
    analysis: int = AnalysisLevel.INITIAL.value
    distribution: int = Distribution.YOUR_ORGANISATION_ONLY.value
    published: bool = False
    id: Optional[str] = None
    uuid: Optional[str] = None
    org_id: Optional[str] = None
    orgc_id: Optional[str] = None
    date: Optional[str] = None
    timestamp: Optional[str] = None
    publish_timestamp: Optional[str] = None
    sharing_group_id: Optional[str] = None
    extends_uuid: Optional[str] = None
    tags: List[Dict[str, Any]] = field(default_factory=list)
    attributes: List[MISPAttribute] = field(default_factory=list)
    galaxies: List[Dict[str, Any]] = field(default_factory=list)

    def to_create_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "info": self.info,
            "threat_level_id": str(self.threat_level_id),
            "analysis": str(self.analysis),
            "distribution": str(self.distribution),
            "published": self.published,
        }
        if self.date:
            d["date"] = self.date
        if self.sharing_group_id:
            d["sharing_group_id"] = self.sharing_group_id
        if self.extends_uuid:
            d["extends_uuid"] = self.extends_uuid
        return d

    def to_dict(self) -> Dict[str, Any]:
        d = self.to_create_dict()
        d["id"] = self.id
        d["uuid"] = self.uuid or str(uuid.uuid4())
        d["org_id"] = self.org_id
        d["orgc_id"] = self.orgc_id
        d["timestamp"] = self.timestamp
        d["publish_timestamp"] = self.publish_timestamp
        d["Tag"] = self.tags
        d["Attribute"] = [a.to_dict() for a in self.attributes]
        d["Galaxy"] = self.galaxies
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MISPEvent":
        ev = data.get("Event", data)
        attrs_raw = ev.get("Attribute", [])
        attrs = [MISPAttribute.from_dict(a) for a in attrs_raw]
        pub = ev.get("published", False)
        if isinstance(pub, str):
            pub = pub in ("1", "true", "True")
        elif isinstance(pub, int):
            pub = pub == 1
        return cls(
            info=ev.get("info", ""),
            threat_level_id=int(ev.get("threat_level_id", ThreatLevel.UNDEFINED.value)),
            analysis=int(ev.get("analysis", AnalysisLevel.INITIAL.value)),
            distribution=int(ev.get("distribution", Distribution.YOUR_ORGANISATION_ONLY.value)),
            published=pub,
            id=ev.get("id"),
            uuid=ev.get("uuid"),
            org_id=ev.get("org_id"),
            orgc_id=ev.get("orgc_id"),
            date=ev.get("date"),
            timestamp=ev.get("timestamp"),
            publish_timestamp=ev.get("publish_timestamp"),
            sharing_group_id=ev.get("sharing_group_id"),
            extends_uuid=ev.get("extends_uuid"),
            tags=ev.get("Tag", []),
            attributes=attrs,
            galaxies=ev.get("Galaxy", []),
        )


@dataclass
class MISPSighting:
    """Represents a MISP sighting."""
    attribute_id: Optional[str] = None
    attribute_uuid: Optional[str] = None
    type: int = SightingType.TRUE_POSITIVE.value
    source: str = "TSUNAMI-SOC"
    date_sighting: Optional[str] = None
    id: Optional[str] = None
    uuid: Optional[str] = None
    org_id: Optional[str] = None

    def to_create_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"type": str(self.type), "source": self.source}
        if self.attribute_id:
            d["id"] = self.attribute_id
        if self.attribute_uuid:
            d["uuid"] = self.attribute_uuid
        if self.date_sighting:
            d["date_sighting"] = self.date_sighting
        return d

    def to_dict(self) -> Dict[str, Any]:
        d = self.to_create_dict()
        d["sighting_id"] = self.id
        d["sighting_uuid"] = self.uuid
        d["org_id"] = self.org_id
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MISPSighting":
        s = data.get("Sighting", data)
        return cls(
            attribute_id=s.get("attribute_id"),
            attribute_uuid=s.get("attribute_uuid"),
            type=int(s.get("type", 0)),
            source=s.get("source", "TSUNAMI-SOC"),
            date_sighting=s.get("date_sighting"),
            id=s.get("id"),
            uuid=s.get("uuid"),
            org_id=s.get("org_id"),
        )


@dataclass
class MISPFeed:
    """Represents a MISP feed configuration."""
    name: str = ""
    provider: str = ""
    url: str = ""
    enabled: bool = True
    source_format: str = "misp"
    distribution: int = Distribution.YOUR_ORGANISATION_ONLY.value
    id: Optional[str] = None
    caching_enabled: bool = False
    lookup_visible: bool = True
    input_source: str = "network"
    delete_local_file: bool = False

    def to_create_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "url": self.url,
            "enabled": self.enabled,
            "source_format": self.source_format,
            "distribution": str(self.distribution),
            "caching_enabled": self.caching_enabled,
            "lookup_visible": self.lookup_visible,
            "input_source": self.input_source,
            "delete_local_file": self.delete_local_file,
        }

    def to_dict(self) -> Dict[str, Any]:
        d = self.to_create_dict()
        d["id"] = self.id
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MISPFeed":
        f = data.get("Feed", data)
        return cls(
            name=f.get("name", ""),
            provider=f.get("provider", ""),
            url=f.get("url", ""),
            enabled=f.get("enabled", True) in (True, "1", 1, "true"),
            source_format=f.get("source_format", "misp"),
            distribution=int(f.get("distribution", 0)),
            id=f.get("id"),
            caching_enabled=f.get("caching_enabled", False) in (True, "1", 1),
            lookup_visible=f.get("lookup_visible", True) in (True, "1", 1, "true"),
            input_source=f.get("input_source", "network"),
            delete_local_file=f.get("delete_local_file", False) in (True, "1", 1),
        )


@dataclass
class MISPGalaxyCluster:
    """Represents a MISP Galaxy Cluster entry."""
    type: str = ""
    value: str = ""
    description: str = ""
    uuid: Optional[str] = None
    tag_name: Optional[str] = None
    galaxy_id: Optional[str] = None
    source: str = ""
    authors: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "description": self.description,
            "uuid": self.uuid or str(uuid.uuid4()),
            "tag_name": self.tag_name or f'misp-galaxy:{self.type}="{self.value}"',
            "galaxy_id": self.galaxy_id,
            "source": self.source,
            "authors": self.authors,
            "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MISPGalaxyCluster":
        c = data.get("GalaxyCluster", data)
        return cls(
            type=c.get("type", ""),
            value=c.get("value", ""),
            description=c.get("description", ""),
            uuid=c.get("uuid"),
            tag_name=c.get("tag_name"),
            galaxy_id=c.get("galaxy_id"),
            source=c.get("source", ""),
            authors=c.get("authors", []),
            meta=c.get("meta", {}),
        )


@dataclass
class SyncRecord:
    """Tracks synchronization state between TSUNAMI and MISP."""
    tsunami_id: str = ""
    misp_id: str = ""
    entity_type: str = "event"
    direction: str = SyncDirection.TSUNAMI_TO_MISP.value
    status: str = SyncStatus.SYNCED.value
    last_synced: Optional[str] = None
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tsunami_id": self.tsunami_id,
            "misp_id": self.misp_id,
            "entity_type": self.entity_type,
            "direction": self.direction,
            "status": self.status,
            "last_synced": self.last_synced or datetime.now(timezone.utc).isoformat(),
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SyncRecord":
        return cls(
            tsunami_id=data.get("tsunami_id", ""),
            misp_id=data.get("misp_id", ""),
            entity_type=data.get("entity_type", "event"),
            direction=data.get("direction", SyncDirection.TSUNAMI_TO_MISP.value),
            status=data.get("status", SyncStatus.SYNCED.value),
            last_synced=data.get("last_synced"),
            error_message=data.get("error_message"),
        )


# ---------------------------------------------------------------------------
# MISP HTTP Client
# ---------------------------------------------------------------------------

class MISPClient:
    """Low-level MISP REST API client with retry and backoff."""

    def __init__(
        self,
        url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: bool = True,
        max_retries: int = 3,
        timeout: int = 30,
    ):
        self.url = (url or os.environ.get("MISP_URL", "https://localhost")).rstrip("/")
        self.api_key = api_key or os.environ.get("MISP_API_KEY", "")
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.timeout = timeout
        self._session = None
        self._lock = threading.Lock()

    def _get_session(self):
        if self._session is not None:
            return self._session
        try:
            import requests
            s = requests.Session()
            s.headers.update({
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
            s.verify = self.verify_ssl
            self._session = s
            return s
        except ImportError:
            logger.warning("requests library not installed")
            return None

    def _request(
        self, method: str, path: str, data: Optional[Dict] = None
    ) -> Dict[str, Any]:
        session = self._get_session()
        if session is None:
            return {"error": "HTTP client unavailable (requests not installed)"}
        url = f"{self.url}{path}"
        last_error = None
        for attempt in range(self.max_retries):
            try:
                kwargs: Dict[str, Any] = {"timeout": self.timeout}
                if data is not None:
                    kwargs["json"] = data
                resp = getattr(session, method)(url, **kwargs)
                if resp.status_code >= 500:
                    last_error = f"Server error {resp.status_code}"
                    time.sleep(min(2 ** attempt, 8))
                    continue
                if resp.status_code >= 400:
                    try:
                        body = resp.json()
                    except Exception:
                        body = {"message": resp.text}
                    return {"error": body.get("message", resp.text), "status_code": resp.status_code}
                if not resp.content:
                    return {"success": True}
                try:
                    return resp.json()
                except Exception:
                    return {"raw": resp.text}
            except Exception as exc:
                last_error = str(exc)
                time.sleep(min(2 ** attempt, 8))
        return {"error": last_error or "Max retries exceeded"}

    # -- Health --
    def health_check(self) -> Dict[str, Any]:
        result = self._request("get", "/servers/getPyMISPVersion.json")
        if "error" not in result:
            return {"healthy": True, "version": result.get("version", "unknown")}
        return {"healthy": False, "error": result.get("error")}

    # -- Events --
    def create_event(self, event_data: Dict) -> Dict:
        return self._request("post", "/events/add", {"Event": event_data})

    def get_event(self, event_id: str) -> Dict:
        return self._request("get", f"/events/view/{event_id}")

    def update_event(self, event_id: str, event_data: Dict) -> Dict:
        return self._request("put", f"/events/edit/{event_id}", {"Event": event_data})

    def delete_event(self, event_id: str) -> Dict:
        return self._request("delete", f"/events/delete/{event_id}")

    def publish_event(self, event_id: str) -> Dict:
        return self._request("post", f"/events/publish/{event_id}")

    def search_events(self, query: Dict) -> Dict:
        return self._request("post", "/events/restSearch", {"request": query})

    # -- Attributes --
    def add_attribute(self, event_id: str, attr_data: Dict) -> Dict:
        return self._request("post", f"/attributes/add/{event_id}", {"Attribute": attr_data})

    def get_attribute(self, attribute_id: str) -> Dict:
        return self._request("get", f"/attributes/view/{attribute_id}")

    def update_attribute(self, attribute_id: str, attr_data: Dict) -> Dict:
        return self._request("put", f"/attributes/edit/{attribute_id}", {"Attribute": attr_data})

    def delete_attribute(self, attribute_id: str) -> Dict:
        return self._request("delete", f"/attributes/delete/{attribute_id}")

    def search_attributes(self, query: Dict) -> Dict:
        return self._request("post", "/attributes/restSearch", {"request": query})

    # -- Tags --
    def add_tag_to_event(self, event_id: str, tag: str) -> Dict:
        return self._request("post", "/events/addTag", {"event": event_id, "tag": tag})

    def remove_tag_from_event(self, event_id: str, tag: str) -> Dict:
        return self._request("post", "/events/removeTag", {"event": event_id, "tag": tag})

    def add_tag_to_attribute(self, attribute_id: str, tag: str) -> Dict:
        return self._request("post", "/attributes/addTag", {"attribute": attribute_id, "tag": tag})

    def get_all_tags(self) -> Dict:
        return self._request("get", "/tags")

    # -- Sightings --
    def add_sighting(self, sighting_data: Dict) -> Dict:
        return self._request("post", "/sightings/add", sighting_data)

    def list_sightings(self, attribute_id: str) -> Dict:
        return self._request("get", f"/sightings/listSightings/{attribute_id}/attribute")

    # -- Feeds --
    def list_feeds(self) -> Dict:
        return self._request("get", "/feeds")

    def get_feed(self, feed_id: str) -> Dict:
        return self._request("get", f"/feeds/view/{feed_id}")

    def add_feed(self, feed_data: Dict) -> Dict:
        return self._request("post", "/feeds/add", {"Feed": feed_data})

    def update_feed(self, feed_id: str, feed_data: Dict) -> Dict:
        return self._request("put", f"/feeds/edit/{feed_id}", {"Feed": feed_data})

    def enable_feed(self, feed_id: str) -> Dict:
        return self._request("post", f"/feeds/enable/{feed_id}")

    def disable_feed(self, feed_id: str) -> Dict:
        return self._request("post", f"/feeds/disable/{feed_id}")

    def fetch_from_feed(self, feed_id: str) -> Dict:
        return self._request("get", f"/feeds/fetchFromFeed/{feed_id}")

    # -- Galaxies --
    def list_galaxies(self) -> Dict:
        return self._request("get", "/galaxies")

    def get_galaxy(self, galaxy_id: str) -> Dict:
        return self._request("get", f"/galaxies/view/{galaxy_id}")

    def search_galaxy_clusters(self, query: Dict) -> Dict:
        return self._request("post", "/galaxy_clusters/restSearch", query)

    def attach_galaxy_cluster(self, event_id: str, galaxy_cluster_id: str) -> Dict:
        return self._request(
            "post",
            f"/galaxies/attachCluster/{event_id}/event",
            {"Galaxy": {"target_id": galaxy_cluster_id}},
        )

    # -- Warninglists --
    def list_warninglists(self) -> Dict:
        return self._request("get", "/warninglists")

    def check_warninglist(self, values: List[str]) -> Dict:
        return self._request("post", "/warninglists/checkValue", {"value": values})

    # -- Correlation --
    def get_correlations(self, event_id: str) -> Dict:
        return self._request("get", f"/events/view/{event_id}/includeCorrelations:1")


# ---------------------------------------------------------------------------
# Sync Store (SQLite)
# ---------------------------------------------------------------------------

class SyncStore:
    """SQLite-backed synchronization state storage."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.environ.get(
            "MISP_SYNC_DB",
            str(Path.home() / ".tsunami" / "misp_sync.db"),
        )
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tsunami_id TEXT NOT NULL,
                    misp_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL DEFAULT 'event',
                    direction TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'synced',
                    last_synced TEXT,
                    error_message TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tsunami_id ON sync_records(tsunami_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_misp_id ON sync_records(misp_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_entity_type ON sync_records(entity_type)")
            conn.commit()
            conn.close()

    def save_record(self, record: SyncRecord):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute(
                """INSERT INTO sync_records
                   (tsunami_id, misp_id, entity_type, direction, status, last_synced, error_message)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (record.tsunami_id, record.misp_id, record.entity_type,
                 record.direction, record.status,
                 record.last_synced or datetime.now(timezone.utc).isoformat(),
                 record.error_message),
            )
            conn.commit()
            conn.close()

    def get_by_tsunami_id(
        self, tsunami_id: str, entity_type: Optional[str] = None
    ) -> Optional[SyncRecord]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            if entity_type:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE tsunami_id=? AND entity_type=? ORDER BY id DESC LIMIT 1",
                    (tsunami_id, entity_type),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE tsunami_id=? ORDER BY id DESC LIMIT 1",
                    (tsunami_id,),
                ).fetchone()
            conn.close()
            if row:
                return SyncRecord(
                    tsunami_id=row["tsunami_id"], misp_id=row["misp_id"],
                    entity_type=row["entity_type"], direction=row["direction"],
                    status=row["status"], last_synced=row["last_synced"],
                    error_message=row["error_message"],
                )
            return None

    def get_by_misp_id(
        self, misp_id: str, entity_type: Optional[str] = None
    ) -> Optional[SyncRecord]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            if entity_type:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE misp_id=? AND entity_type=? ORDER BY id DESC LIMIT 1",
                    (misp_id, entity_type),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE misp_id=? ORDER BY id DESC LIMIT 1",
                    (misp_id,),
                ).fetchone()
            conn.close()
            if row:
                return SyncRecord(
                    tsunami_id=row["tsunami_id"], misp_id=row["misp_id"],
                    entity_type=row["entity_type"], direction=row["direction"],
                    status=row["status"], last_synced=row["last_synced"],
                    error_message=row["error_message"],
                )
            return None

    def list_records(
        self,
        entity_type: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[SyncRecord]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            query = "SELECT * FROM sync_records WHERE 1=1"
            params: list = []
            if entity_type:
                query += " AND entity_type=?"
                params.append(entity_type)
            if status:
                query += " AND status=?"
                params.append(status)
            query += " ORDER BY id DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            conn.close()
            return [
                SyncRecord(
                    tsunami_id=r["tsunami_id"], misp_id=r["misp_id"],
                    entity_type=r["entity_type"], direction=r["direction"],
                    status=r["status"], last_synced=r["last_synced"],
                    error_message=r["error_message"],
                )
                for r in rows
            ]

    def delete_record(self, tsunami_id: str) -> bool:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute(
                "DELETE FROM sync_records WHERE tsunami_id=?", (tsunami_id,)
            )
            conn.commit()
            deleted = cursor.rowcount > 0
            conn.close()
            return deleted

    def count_records(
        self, entity_type: Optional[str] = None, status: Optional[str] = None
    ) -> int:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            query = "SELECT COUNT(*) FROM sync_records WHERE 1=1"
            params: list = []
            if entity_type:
                query += " AND entity_type=?"
                params.append(entity_type)
            if status:
                query += " AND status=?"
                params.append(status)
            count = conn.execute(query, params).fetchone()[0]
            conn.close()
            return count

    def upsert_record(self, record: SyncRecord):
        existing = self.get_by_tsunami_id(record.tsunami_id, record.entity_type)
        if existing:
            with self._lock:
                conn = sqlite3.connect(self.db_path)
                conn.execute(
                    """UPDATE sync_records SET misp_id=?, direction=?, status=?,
                       last_synced=?, error_message=?
                       WHERE tsunami_id=? AND entity_type=?""",
                    (record.misp_id, record.direction, record.status,
                     record.last_synced or datetime.now(timezone.utc).isoformat(),
                     record.error_message, record.tsunami_id, record.entity_type),
                )
                conn.commit()
                conn.close()
        else:
            self.save_record(record)


# ---------------------------------------------------------------------------
# IOC Type Mapping
# ---------------------------------------------------------------------------

TSUNAMI_TO_MISP_TYPE_MAP = {
    "ip_address": "ip-dst",
    "ip_src": "ip-src",
    "ip_dst": "ip-dst",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "email": "email-src",
    "email_src": "email-src",
    "email_dst": "email-dst",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "filename": "filename",
    "mutex": "mutex",
    "registry_key": "regkey",
    "user_agent": "user-agent",
    "vulnerability": "vulnerability",
    "yara": "yara",
    "sigma": "sigma",
    "snort": "snort",
    "port": "port",
    "as_number": "AS",
}

MISP_TO_TSUNAMI_TYPE_MAP = {v: k for k, v in TSUNAMI_TO_MISP_TYPE_MAP.items()}

# Severity mapping
TSUNAMI_SEVERITY_TO_THREAT_LEVEL = {
    "critical": ThreatLevel.HIGH,
    "high": ThreatLevel.HIGH,
    "medium": ThreatLevel.MEDIUM,
    "low": ThreatLevel.LOW,
    "info": ThreatLevel.UNDEFINED,
    "informational": ThreatLevel.UNDEFINED,
}

THREAT_LEVEL_TO_TSUNAMI_SEVERITY = {
    ThreatLevel.HIGH: "high",
    ThreatLevel.MEDIUM: "medium",
    ThreatLevel.LOW: "low",
    ThreatLevel.UNDEFINED: "info",
}

# TLP tag mapping
TLP_TAG_MAP = {
    "TLP:CLEAR": Distribution.ALL_COMMUNITIES,
    "TLP:WHITE": Distribution.ALL_COMMUNITIES,
    "TLP:GREEN": Distribution.CONNECTED_COMMUNITIES,
    "TLP:AMBER": Distribution.THIS_COMMUNITY_ONLY,
    "TLP:AMBER+STRICT": Distribution.YOUR_ORGANISATION_ONLY,
    "TLP:RED": Distribution.YOUR_ORGANISATION_ONLY,
}


# ---------------------------------------------------------------------------
# MISP Connector (Main Orchestrator)
# ---------------------------------------------------------------------------

class MISPConnector:
    """High-level MISP integration with bidirectional sync and IOC management."""

    def __init__(
        self,
        client: Optional[MISPClient] = None,
        sync_store: Optional[SyncStore] = None,
    ):
        self.client = client or MISPClient()
        self.sync_store = sync_store or SyncStore()
        self._callbacks: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()

    def register_callback(self, event_type: str, callback: Callable):
        with self._lock:
            self._callbacks.setdefault(event_type, []).append(callback)

    def _fire_callbacks(self, event_type: str, data: Dict[str, Any]):
        cbs = self._callbacks.get(event_type, [])
        for cb in cbs:
            try:
                cb(event_type, data)
            except Exception as exc:
                logger.error("Callback error for %s: %s", event_type, exc)

    # -- Health --
    def health_check(self) -> Dict[str, Any]:
        return self.client.health_check()

    # -- Event CRUD --
    def create_event(self, event: MISPEvent) -> Optional[MISPEvent]:
        result = self.client.create_event(event.to_create_dict())
        if "error" in result:
            logger.error("Failed to create event: %s", result["error"])
            return None
        created = MISPEvent.from_dict(result)
        self._fire_callbacks("event_created", created.to_dict())
        return created

    def get_event(self, event_id: str) -> Optional[MISPEvent]:
        result = self.client.get_event(event_id)
        if "error" in result:
            return None
        return MISPEvent.from_dict(result)

    def update_event(self, event_id: str, updates: Dict) -> Optional[MISPEvent]:
        result = self.client.update_event(event_id, updates)
        if "error" in result:
            logger.error("Failed to update event %s: %s", event_id, result["error"])
            return None
        updated = MISPEvent.from_dict(result)
        self._fire_callbacks("event_updated", updated.to_dict())
        return updated

    def delete_event(self, event_id: str) -> bool:
        result = self.client.delete_event(event_id)
        return "error" not in result

    def publish_event(self, event_id: str) -> bool:
        result = self.client.publish_event(event_id)
        return "error" not in result

    def search_events(self, query: Dict) -> List[MISPEvent]:
        result = self.client.search_events(query)
        if "error" in result:
            return []
        response = result.get("response", result)
        if isinstance(response, list):
            return [MISPEvent.from_dict(e) for e in response]
        return []

    # -- Attribute CRUD --
    def add_attribute(self, event_id: str, attribute: MISPAttribute) -> Optional[MISPAttribute]:
        result = self.client.add_attribute(event_id, attribute.to_create_dict())
        if "error" in result:
            logger.error("Failed to add attribute: %s", result["error"])
            return None
        return MISPAttribute.from_dict(result)

    def get_attribute(self, attribute_id: str) -> Optional[MISPAttribute]:
        result = self.client.get_attribute(attribute_id)
        if "error" in result:
            return None
        return MISPAttribute.from_dict(result)

    def update_attribute(self, attribute_id: str, updates: Dict) -> Optional[MISPAttribute]:
        result = self.client.update_attribute(attribute_id, updates)
        if "error" in result:
            return None
        return MISPAttribute.from_dict(result)

    def delete_attribute(self, attribute_id: str) -> bool:
        result = self.client.delete_attribute(attribute_id)
        return "error" not in result

    def search_attributes(self, query: Dict) -> List[MISPAttribute]:
        result = self.client.search_attributes(query)
        if "error" in result:
            return []
        response = result.get("response", result)
        if isinstance(response, dict):
            response = response.get("Attribute", [])
        if isinstance(response, list):
            return [MISPAttribute.from_dict(a) for a in response]
        return []

    # -- Tags --
    def add_tag_to_event(self, event_id: str, tag: str) -> bool:
        result = self.client.add_tag_to_event(event_id, tag)
        return "error" not in result

    def remove_tag_from_event(self, event_id: str, tag: str) -> bool:
        result = self.client.remove_tag_from_event(event_id, tag)
        return "error" not in result

    def add_tag_to_attribute(self, attribute_id: str, tag: str) -> bool:
        result = self.client.add_tag_to_attribute(attribute_id, tag)
        return "error" not in result

    def get_all_tags(self) -> List[Dict]:
        result = self.client.get_all_tags()
        if "error" in result:
            return []
        tags = result.get("Tag", result)
        return tags if isinstance(tags, list) else []

    # -- Sightings --
    def add_sighting(self, sighting: MISPSighting) -> Optional[MISPSighting]:
        result = self.client.add_sighting(sighting.to_create_dict())
        if "error" in result:
            return None
        return MISPSighting.from_dict(result)

    def list_sightings(self, attribute_id: str) -> List[MISPSighting]:
        result = self.client.list_sightings(attribute_id)
        if "error" in result:
            return []
        if isinstance(result, list):
            return [MISPSighting.from_dict(s) for s in result]
        return []

    # -- Feeds --
    def list_feeds(self) -> List[MISPFeed]:
        result = self.client.list_feeds()
        if "error" in result:
            return []
        if isinstance(result, list):
            return [MISPFeed.from_dict(f) for f in result]
        return []

    def get_feed(self, feed_id: str) -> Optional[MISPFeed]:
        result = self.client.get_feed(feed_id)
        if "error" in result:
            return None
        return MISPFeed.from_dict(result)

    def add_feed(self, feed: MISPFeed) -> Optional[MISPFeed]:
        result = self.client.add_feed(feed.to_create_dict())
        if "error" in result:
            return None
        return MISPFeed.from_dict(result)

    def enable_feed(self, feed_id: str) -> bool:
        result = self.client.enable_feed(feed_id)
        return "error" not in result

    def disable_feed(self, feed_id: str) -> bool:
        result = self.client.disable_feed(feed_id)
        return "error" not in result

    def fetch_from_feed(self, feed_id: str) -> Dict:
        return self.client.fetch_from_feed(feed_id)

    # -- Galaxies --
    def list_galaxies(self) -> List[Dict]:
        result = self.client.list_galaxies()
        if "error" in result:
            return []
        if isinstance(result, list):
            return result
        return []

    def get_galaxy(self, galaxy_id: str) -> Optional[Dict]:
        result = self.client.get_galaxy(galaxy_id)
        if "error" in result:
            return None
        return result

    def search_galaxy_clusters(self, query: Dict) -> List[MISPGalaxyCluster]:
        result = self.client.search_galaxy_clusters(query)
        if "error" in result:
            return []
        response = result.get("response", result)
        if isinstance(response, list):
            return [MISPGalaxyCluster.from_dict(c) for c in response]
        return []

    def attach_galaxy_cluster(self, event_id: str, cluster_id: str) -> bool:
        result = self.client.attach_galaxy_cluster(event_id, cluster_id)
        return "error" not in result

    # -- Warninglists --
    def list_warninglists(self) -> List[Dict]:
        result = self.client.list_warninglists()
        if "error" in result:
            return []
        wls = result.get("Warninglists", result)
        return wls if isinstance(wls, list) else []

    def check_warninglist(self, values: List[str]) -> Dict:
        return self.client.check_warninglist(values)

    # -- Correlation --
    def get_correlations(self, event_id: str) -> Dict:
        return self.client.get_correlations(event_id)

    # -- IOC Export: TSUNAMI → MISP --
    def export_iocs_to_misp(
        self,
        tsunami_alert: Dict[str, Any],
        publish: bool = False,
    ) -> Optional[MISPEvent]:
        """Export TSUNAMI alert IOCs as a MISP event with attributes."""
        alert_id = tsunami_alert.get("alert_id") or tsunami_alert.get("id", "")
        if not alert_id:
            logger.error("No alert_id in TSUNAMI alert")
            return None

        existing = self.sync_store.get_by_tsunami_id(str(alert_id), "event")
        if existing and existing.status == SyncStatus.SYNCED.value:
            logger.info("Alert %s already synced to MISP event %s", alert_id, existing.misp_id)
            return self.get_event(existing.misp_id)

        severity = tsunami_alert.get("severity", "medium").lower()
        threat_level = TSUNAMI_SEVERITY_TO_THREAT_LEVEL.get(severity, ThreatLevel.UNDEFINED)

        tlp = tsunami_alert.get("tlp", "").upper()
        distribution = TLP_TAG_MAP.get(tlp, Distribution.YOUR_ORGANISATION_ONLY)

        event = MISPEvent(
            info=tsunami_alert.get("title", f"TSUNAMI Alert {alert_id}"),
            threat_level_id=threat_level.value,
            analysis=AnalysisLevel.INITIAL.value,
            distribution=distribution.value,
            date=tsunami_alert.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d")),
        )

        created_event = self.create_event(event)
        if not created_event or not created_event.id:
            self.sync_store.save_record(SyncRecord(
                tsunami_id=str(alert_id), misp_id="",
                entity_type="event",
                direction=SyncDirection.TSUNAMI_TO_MISP.value,
                status=SyncStatus.FAILED.value,
                error_message="Failed to create MISP event",
            ))
            self._fire_callbacks("sync_error", {
                "tsunami_id": str(alert_id), "error": "Event creation failed"
            })
            return None

        iocs = tsunami_alert.get("iocs") or tsunami_alert.get("indicators", [])
        for ioc in iocs:
            ioc_type = ioc.get("type", "")
            misp_type = TSUNAMI_TO_MISP_TYPE_MAP.get(ioc_type, ioc_type)
            attr = MISPAttribute(
                type=misp_type,
                value=ioc.get("value", ""),
                category=self._guess_category(misp_type),
                to_ids=ioc.get("to_ids", True),
                comment=ioc.get("comment", f"From TSUNAMI alert {alert_id}"),
            )
            self.add_attribute(created_event.id, attr)

        if tlp:
            self.add_tag_to_event(created_event.id, f"tlp:{tlp.lower().replace('tlp:', '')}")

        if publish:
            self.publish_event(created_event.id)

        self.sync_store.save_record(SyncRecord(
            tsunami_id=str(alert_id),
            misp_id=str(created_event.id),
            entity_type="event",
            direction=SyncDirection.TSUNAMI_TO_MISP.value,
            status=SyncStatus.SYNCED.value,
        ))
        self._fire_callbacks("ioc_exported", {
            "tsunami_id": str(alert_id),
            "misp_event_id": created_event.id,
            "ioc_count": len(iocs),
        })
        return created_event

    # -- IOC Import: MISP → TSUNAMI --
    def import_iocs_from_misp(
        self, event_id: str
    ) -> List[Dict[str, Any]]:
        """Import IOCs from a MISP event into TSUNAMI format."""
        event = self.get_event(event_id)
        if not event:
            return []

        tsunami_iocs: List[Dict[str, Any]] = []
        for attr in event.attributes:
            tsunami_type = MISP_TO_TSUNAMI_TYPE_MAP.get(attr.type, attr.type)
            tsunami_iocs.append({
                "type": tsunami_type,
                "value": attr.value,
                "source": "MISP",
                "misp_event_id": event_id,
                "misp_attribute_id": attr.id,
                "category": attr.category,
                "to_ids": attr.to_ids,
                "comment": attr.comment,
                "tags": [t.get("name", "") for t in attr.tags] if attr.tags else [],
            })

        if event.id:
            self.sync_store.save_record(SyncRecord(
                tsunami_id=f"import_{event_id}",
                misp_id=str(event.id),
                entity_type="event",
                direction=SyncDirection.MISP_TO_TSUNAMI.value,
                status=SyncStatus.SYNCED.value,
            ))
        self._fire_callbacks("ioc_imported", {
            "misp_event_id": event_id,
            "ioc_count": len(tsunami_iocs),
        })
        return tsunami_iocs

    # -- Sync Status --
    def get_sync_status(self, tsunami_id: str) -> Optional[Dict]:
        rec = self.sync_store.get_by_tsunami_id(tsunami_id)
        if rec:
            return rec.to_dict()
        return None

    def list_sync_records(self, **kwargs) -> List[Dict]:
        records = self.sync_store.list_records(**kwargs)
        return [r.to_dict() for r in records]

    def get_sync_stats(self) -> Dict[str, Any]:
        return {
            "total": self.sync_store.count_records(),
            "synced": self.sync_store.count_records(status=SyncStatus.SYNCED.value),
            "failed": self.sync_store.count_records(status=SyncStatus.FAILED.value),
            "pending": self.sync_store.count_records(status=SyncStatus.PENDING.value),
            "events": self.sync_store.count_records(entity_type="event"),
            "attributes": self.sync_store.count_records(entity_type="attribute"),
        }

    # -- Helpers --
    @staticmethod
    def _guess_category(misp_type: str) -> str:
        network_types = {"ip-src", "ip-dst", "domain", "hostname", "url", "AS", "port", "user-agent"}
        hash_types = {"md5", "sha1", "sha256", "filename", "filename|md5", "filename|sha256"}
        email_types = {"email-src", "email-dst"}
        rule_types = {"yara", "sigma", "snort", "pattern-in-file"}
        if misp_type in network_types:
            return AttributeCategory.NETWORK_ACTIVITY.value
        if misp_type in hash_types:
            return AttributeCategory.PAYLOAD_DELIVERY.value
        if misp_type in email_types:
            return AttributeCategory.PAYLOAD_DELIVERY.value
        if misp_type in rule_types:
            return AttributeCategory.PAYLOAD_INSTALLATION.value
        if misp_type == "vulnerability":
            return AttributeCategory.EXTERNAL_ANALYSIS.value
        if misp_type in ("regkey", "mutex"):
            return AttributeCategory.PERSISTENCE_MECHANISM.value
        return AttributeCategory.OTHER.value


# ---------------------------------------------------------------------------
# Flask Blueprint
# ---------------------------------------------------------------------------

def create_misp_blueprint(connector: Optional[MISPConnector] = None):
    """Create Flask blueprint for MISP REST API."""
    try:
        from flask import Blueprint, jsonify, request as flask_request
    except ImportError:
        logger.warning("Flask not installed, blueprint unavailable")
        return None

    bp = Blueprint("misp_connector", __name__, url_prefix="/api/v1/soc/misp")
    _connector = connector or get_misp_connector()

    @bp.route("/health", methods=["GET"])
    def health():
        result = _connector.health_check()
        code = 200 if result.get("healthy") else 503
        return jsonify(result), code

    # -- Events --
    @bp.route("/events", methods=["POST"])
    def create_event():
        data = flask_request.get_json(force=True, silent=True) or {}
        if not data.get("info"):
            return jsonify({"error": "info is required"}), 400
        event = MISPEvent(
            info=data["info"],
            threat_level_id=int(data.get("threat_level_id", ThreatLevel.UNDEFINED.value)),
            analysis=int(data.get("analysis", AnalysisLevel.INITIAL.value)),
            distribution=int(data.get("distribution", Distribution.YOUR_ORGANISATION_ONLY.value)),
            date=data.get("date"),
        )
        result = _connector.create_event(event)
        if result:
            return jsonify(result.to_dict()), 201
        return jsonify({"error": "Failed to create event"}), 500

    @bp.route("/events/<event_id>", methods=["GET"])
    def get_event(event_id):
        result = _connector.get_event(event_id)
        if result:
            return jsonify(result.to_dict())
        return jsonify({"error": "Event not found"}), 404

    @bp.route("/events/<event_id>", methods=["PUT"])
    def update_event(event_id):
        data = flask_request.get_json(force=True, silent=True) or {}
        result = _connector.update_event(event_id, data)
        if result:
            return jsonify(result.to_dict())
        return jsonify({"error": "Failed to update event"}), 500

    @bp.route("/events/<event_id>", methods=["DELETE"])
    def delete_event(event_id):
        success = _connector.delete_event(event_id)
        if success:
            return jsonify({"success": True})
        return jsonify({"error": "Failed to delete event"}), 500

    @bp.route("/events/<event_id>/publish", methods=["POST"])
    def publish_event(event_id):
        success = _connector.publish_event(event_id)
        if success:
            return jsonify({"success": True})
        return jsonify({"error": "Failed to publish event"}), 500

    @bp.route("/events/search", methods=["POST"])
    def search_events():
        query = flask_request.get_json(force=True, silent=True) or {}
        results = _connector.search_events(query)
        return jsonify({"events": [e.to_dict() for e in results]})

    # -- Attributes --
    @bp.route("/events/<event_id>/attributes", methods=["POST"])
    def add_attribute(event_id):
        data = flask_request.get_json(force=True, silent=True) or {}
        if not data.get("type") or not data.get("value"):
            return jsonify({"error": "type and value are required"}), 400
        attr = MISPAttribute(
            type=data["type"],
            value=data["value"],
            category=data.get("category", "Other"),
            to_ids=data.get("to_ids", True),
            comment=data.get("comment", ""),
        )
        result = _connector.add_attribute(event_id, attr)
        if result:
            return jsonify(result.to_dict()), 201
        return jsonify({"error": "Failed to add attribute"}), 500

    @bp.route("/attributes/<attribute_id>", methods=["GET"])
    def get_attribute(attribute_id):
        result = _connector.get_attribute(attribute_id)
        if result:
            return jsonify(result.to_dict())
        return jsonify({"error": "Attribute not found"}), 404

    @bp.route("/attributes/<attribute_id>", methods=["PUT"])
    def update_attribute(attribute_id):
        data = flask_request.get_json(force=True, silent=True) or {}
        result = _connector.update_attribute(attribute_id, data)
        if result:
            return jsonify(result.to_dict())
        return jsonify({"error": "Failed to update attribute"}), 500

    @bp.route("/attributes/<attribute_id>", methods=["DELETE"])
    def delete_attribute(attribute_id):
        success = _connector.delete_attribute(attribute_id)
        if success:
            return jsonify({"success": True})
        return jsonify({"error": "Failed to delete attribute"}), 500

    @bp.route("/attributes/search", methods=["POST"])
    def search_attributes():
        query = flask_request.get_json(force=True, silent=True) or {}
        results = _connector.search_attributes(query)
        return jsonify({"attributes": [a.to_dict() for a in results]})

    # -- Tags --
    @bp.route("/events/<event_id>/tags", methods=["POST"])
    def add_tag_to_event(event_id):
        data = flask_request.get_json(force=True, silent=True) or {}
        tag = data.get("tag", "")
        if not tag:
            return jsonify({"error": "tag is required"}), 400
        success = _connector.add_tag_to_event(event_id, tag)
        return jsonify({"success": success})

    @bp.route("/events/<event_id>/tags", methods=["DELETE"])
    def remove_tag_from_event(event_id):
        data = flask_request.get_json(force=True, silent=True) or {}
        tag = data.get("tag", "")
        if not tag:
            return jsonify({"error": "tag is required"}), 400
        success = _connector.remove_tag_from_event(event_id, tag)
        return jsonify({"success": success})

    @bp.route("/tags", methods=["GET"])
    def list_tags():
        tags = _connector.get_all_tags()
        return jsonify({"tags": tags})

    # -- Sightings --
    @bp.route("/sightings", methods=["POST"])
    def add_sighting():
        data = flask_request.get_json(force=True, silent=True) or {}
        sighting = MISPSighting(
            attribute_id=data.get("attribute_id"),
            attribute_uuid=data.get("attribute_uuid"),
            type=int(data.get("type", 0)),
            source=data.get("source", "TSUNAMI-SOC"),
        )
        result = _connector.add_sighting(sighting)
        if result:
            return jsonify(result.to_dict()), 201
        return jsonify({"error": "Failed to add sighting"}), 500

    @bp.route("/sightings/<attribute_id>", methods=["GET"])
    def list_sightings(attribute_id):
        sightings = _connector.list_sightings(attribute_id)
        return jsonify({"sightings": [s.to_dict() for s in sightings]})

    # -- Feeds --
    @bp.route("/feeds", methods=["GET"])
    def list_feeds():
        feeds = _connector.list_feeds()
        return jsonify({"feeds": [f.to_dict() for f in feeds]})

    @bp.route("/feeds/<feed_id>", methods=["GET"])
    def get_feed(feed_id):
        feed = _connector.get_feed(feed_id)
        if feed:
            return jsonify(feed.to_dict())
        return jsonify({"error": "Feed not found"}), 404

    @bp.route("/feeds", methods=["POST"])
    def add_feed():
        data = flask_request.get_json(force=True, silent=True) or {}
        if not data.get("name") or not data.get("url"):
            return jsonify({"error": "name and url are required"}), 400
        feed = MISPFeed(
            name=data["name"],
            provider=data.get("provider", ""),
            url=data["url"],
            source_format=data.get("source_format", "misp"),
        )
        result = _connector.add_feed(feed)
        if result:
            return jsonify(result.to_dict()), 201
        return jsonify({"error": "Failed to add feed"}), 500

    @bp.route("/feeds/<feed_id>/enable", methods=["POST"])
    def enable_feed(feed_id):
        success = _connector.enable_feed(feed_id)
        return jsonify({"success": success})

    @bp.route("/feeds/<feed_id>/disable", methods=["POST"])
    def disable_feed(feed_id):
        success = _connector.disable_feed(feed_id)
        return jsonify({"success": success})

    @bp.route("/feeds/<feed_id>/fetch", methods=["POST"])
    def fetch_feed(feed_id):
        result = _connector.fetch_from_feed(feed_id)
        return jsonify(result)

    # -- Galaxies --
    @bp.route("/galaxies", methods=["GET"])
    def list_galaxies():
        galaxies = _connector.list_galaxies()
        return jsonify({"galaxies": galaxies})

    @bp.route("/galaxies/<galaxy_id>", methods=["GET"])
    def get_galaxy(galaxy_id):
        galaxy = _connector.get_galaxy(galaxy_id)
        if galaxy:
            return jsonify(galaxy)
        return jsonify({"error": "Galaxy not found"}), 404

    @bp.route("/galaxies/clusters/search", methods=["POST"])
    def search_galaxy_clusters():
        query = flask_request.get_json(force=True, silent=True) or {}
        clusters = _connector.search_galaxy_clusters(query)
        return jsonify({"clusters": [c.to_dict() for c in clusters]})

    @bp.route("/events/<event_id>/galaxies", methods=["POST"])
    def attach_galaxy(event_id):
        data = flask_request.get_json(force=True, silent=True) or {}
        cluster_id = data.get("cluster_id", "")
        if not cluster_id:
            return jsonify({"error": "cluster_id is required"}), 400
        success = _connector.attach_galaxy_cluster(event_id, cluster_id)
        return jsonify({"success": success})

    # -- Warninglists --
    @bp.route("/warninglists", methods=["GET"])
    def list_warninglists():
        wls = _connector.list_warninglists()
        return jsonify({"warninglists": wls})

    @bp.route("/warninglists/check", methods=["POST"])
    def check_warninglist():
        data = flask_request.get_json(force=True, silent=True) or {}
        values = data.get("values", [])
        if not values:
            return jsonify({"error": "values list is required"}), 400
        result = _connector.check_warninglist(values)
        return jsonify(result)

    # -- Correlation --
    @bp.route("/events/<event_id>/correlations", methods=["GET"])
    def get_correlations(event_id):
        result = _connector.get_correlations(event_id)
        return jsonify(result)

    # -- IOC Export / Import --
    @bp.route("/export", methods=["POST"])
    def export_iocs():
        data = flask_request.get_json(force=True, silent=True) or {}
        if not data.get("alert_id") and not data.get("id"):
            return jsonify({"error": "alert_id is required"}), 400
        publish = data.pop("publish", False)
        event = _connector.export_iocs_to_misp(data, publish=publish)
        if event:
            return jsonify({"event": event.to_dict()}), 201
        return jsonify({"error": "Export failed"}), 500

    @bp.route("/import/<event_id>", methods=["POST"])
    def import_iocs(event_id):
        iocs = _connector.import_iocs_from_misp(event_id)
        return jsonify({"iocs": iocs, "count": len(iocs)})

    # -- Sync --
    @bp.route("/sync/status/<tsunami_id>", methods=["GET"])
    def sync_status(tsunami_id):
        result = _connector.get_sync_status(tsunami_id)
        if result:
            return jsonify(result)
        return jsonify({"error": "No sync record found"}), 404

    @bp.route("/sync/records", methods=["GET"])
    def sync_records():
        entity_type = flask_request.args.get("entity_type")
        status = flask_request.args.get("status")
        limit = int(flask_request.args.get("limit", 100))
        offset = int(flask_request.args.get("offset", 0))
        records = _connector.list_sync_records(
            entity_type=entity_type, status=status, limit=limit, offset=offset
        )
        return jsonify({"records": records})

    @bp.route("/sync/stats", methods=["GET"])
    def sync_stats():
        return jsonify(_connector.get_sync_stats())

    return bp


# ---------------------------------------------------------------------------
# Global Singleton
# ---------------------------------------------------------------------------

_global_connector: Optional[MISPConnector] = None
_global_lock = threading.Lock()


def get_misp_connector() -> MISPConnector:
    global _global_connector
    if _global_connector is None:
        with _global_lock:
            if _global_connector is None:
                _global_connector = MISPConnector()
    return _global_connector


def reset_global_connector():
    global _global_connector
    with _global_lock:
        _global_connector = None
