#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - TheHive Case Management Connector
    Production-Grade TheHive4 API Integration
================================================================================

    Features:
    - TheHive API v1 full integration (Cases, Tasks, Observables, Alerts)
    - TSUNAMI incident → TheHive case bidirectional sync
    - Observable management with analysis launch
    - Task management with assignee tracking
    - TLP/PAP handling (Traffic Light Protocol / Permissible Actions Protocol)
    - Alert import from TheHive to TSUNAMI
    - Case template support
    - Custom field management
    - Pagination and search with TheHive Query Language
    - Connection health check and retry with backoff
    - SQLite sync state tracking for bidirectional sync
    - Thread-safe operations
    - Flask Blueprint REST API

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

logger = logging.getLogger("soc.thehive")


# ============================================================================
# Enums
# ============================================================================

class TLP(IntEnum):
    """Traffic Light Protocol levels."""
    CLEAR = 0
    GREEN = 1
    AMBER = 2
    AMBER_STRICT = 3
    RED = 4


class PAP(IntEnum):
    """Permissible Actions Protocol levels."""
    CLEAR = 0
    GREEN = 1
    AMBER = 2
    RED = 3


class CaseSeverity(IntEnum):
    """Case severity levels (TheHive convention)."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class CaseStatus(Enum):
    """Case status values."""
    NEW = "New"
    IN_PROGRESS = "InProgress"
    RESOLVED = "Resolved"
    CLOSED = "Closed"
    DELETED = "Deleted"


class TaskStatus(Enum):
    """Task status values."""
    WAITING = "Waiting"
    IN_PROGRESS = "InProgress"
    COMPLETED = "Completed"
    CANCEL = "Cancel"


class AlertStatus(Enum):
    """Alert status values."""
    NEW = "New"
    UPDATED = "Updated"
    IGNORED = "Ignored"
    IMPORTED = "Imported"


class ObservableDataType(Enum):
    """Observable data types supported by TheHive."""
    DOMAIN = "domain"
    FILENAME = "filename"
    FQDN = "fqdn"
    HASH = "hash"
    IP = "ip"
    MAIL = "mail"
    MAIL_SUBJECT = "mail_subject"
    OTHER = "other"
    REGEXP = "regexp"
    REGISTRY = "registry"
    URI_PATH = "uri_path"
    URL = "url"
    USER_AGENT = "user-agent"
    HOSTNAME = "hostname"
    PORT = "port"
    AUTONOMOUS_SYSTEM = "autonomous-system"


class SyncDirection(Enum):
    """Sync direction for bidirectional sync."""
    TSUNAMI_TO_THEHIVE = "tsunami_to_thehive"
    THEHIVE_TO_TSUNAMI = "thehive_to_tsunami"
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(Enum):
    """Sync operation status."""
    PENDING = "pending"
    SYNCED = "synced"
    FAILED = "failed"
    CONFLICT = "conflict"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class TheHiveCase:
    """Represents a TheHive case."""
    id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: int = CaseSeverity.MEDIUM.value
    tlp: int = TLP.AMBER.value
    pap: int = PAP.AMBER.value
    status: str = CaseStatus.NEW.value
    tags: List[str] = field(default_factory=list)
    flag: bool = False
    owner: Optional[str] = None
    assignee: Optional[str] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    summary: Optional[str] = None
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    template: Optional[str] = None
    source: Optional[str] = None
    source_ref: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    tsunami_alert_id: Optional[str] = None

    def to_create_dict(self) -> Dict[str, Any]:
        """Convert to TheHive API case creation payload."""
        d: Dict[str, Any] = {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "tlp": self.tlp,
            "pap": self.pap,
            "tags": self.tags,
            "flag": self.flag,
        }
        if self.owner:
            d["owner"] = self.owner
        if self.assignee:
            d["assignee"] = self.assignee
        if self.start_date:
            d["startDate"] = self.start_date
        if self.template:
            d["template"] = self.template
        if self.custom_fields:
            d["customFields"] = self.custom_fields
        return d

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "tlp": self.tlp,
            "pap": self.pap,
            "status": self.status,
            "tags": list(self.tags),
            "flag": self.flag,
            "owner": self.owner,
            "assignee": self.assignee,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "summary": self.summary,
            "custom_fields": dict(self.custom_fields),
            "template": self.template,
            "source": self.source,
            "source_ref": self.source_ref,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tsunami_alert_id": self.tsunami_alert_id,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TheHiveCase":
        return cls(
            id=d.get("id") or d.get("_id"),
            title=d.get("title", ""),
            description=d.get("description", ""),
            severity=d.get("severity", CaseSeverity.MEDIUM.value),
            tlp=d.get("tlp", TLP.AMBER.value),
            pap=d.get("pap", PAP.AMBER.value),
            status=d.get("status", CaseStatus.NEW.value),
            tags=list(d.get("tags", [])),
            flag=d.get("flag", False),
            owner=d.get("owner"),
            assignee=d.get("assignee"),
            start_date=d.get("start_date") or d.get("startDate"),
            end_date=d.get("end_date") or d.get("endDate"),
            summary=d.get("summary"),
            custom_fields=dict(d.get("custom_fields") or d.get("customFields") or {}),
            template=d.get("template"),
            source=d.get("source"),
            source_ref=d.get("source_ref") or d.get("sourceRef"),
            created_at=d.get("created_at") or d.get("createdAt"),
            updated_at=d.get("updated_at") or d.get("updatedAt"),
            tsunami_alert_id=d.get("tsunami_alert_id"),
        )


@dataclass
class TheHiveTask:
    """Represents a TheHive task within a case."""
    id: Optional[str] = None
    case_id: Optional[str] = None
    title: str = ""
    description: Optional[str] = None
    status: str = TaskStatus.WAITING.value
    group: Optional[str] = None
    owner: Optional[str] = None
    assignee: Optional[str] = None
    order: int = 0
    due_date: Optional[str] = None
    flag: bool = False
    mandatory: bool = False

    def to_create_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "title": self.title,
            "status": self.status,
            "flag": self.flag,
        }
        if self.description:
            d["description"] = self.description
        if self.group:
            d["group"] = self.group
        if self.owner:
            d["owner"] = self.owner
        if self.assignee:
            d["assignee"] = self.assignee
        if self.order:
            d["order"] = self.order
        if self.due_date:
            d["dueDate"] = self.due_date
        return d

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "title": self.title,
            "description": self.description,
            "status": self.status,
            "group": self.group,
            "owner": self.owner,
            "assignee": self.assignee,
            "order": self.order,
            "due_date": self.due_date,
            "flag": self.flag,
            "mandatory": self.mandatory,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TheHiveTask":
        return cls(
            id=d.get("id") or d.get("_id"),
            case_id=d.get("case_id") or d.get("caseId"),
            title=d.get("title", ""),
            description=d.get("description"),
            status=d.get("status", TaskStatus.WAITING.value),
            group=d.get("group"),
            owner=d.get("owner"),
            assignee=d.get("assignee"),
            order=d.get("order", 0),
            due_date=d.get("due_date") or d.get("dueDate"),
            flag=d.get("flag", False),
            mandatory=d.get("mandatory", False),
        )


@dataclass
class TheHiveObservable:
    """Represents a TheHive observable."""
    id: Optional[str] = None
    case_id: Optional[str] = None
    data_type: str = ObservableDataType.OTHER.value
    data: Optional[str] = None
    message: Optional[str] = None
    tlp: int = TLP.AMBER.value
    pap: int = PAP.AMBER.value
    tags: List[str] = field(default_factory=list)
    ioc: bool = False
    sighted: bool = False
    sighted_at: Optional[str] = None
    ignore_similarity: bool = False
    is_zip: bool = False

    def to_create_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "dataType": self.data_type,
            "tlp": self.tlp,
            "pap": self.pap,
            "tags": self.tags,
            "ioc": self.ioc,
            "sighted": self.sighted,
            "ignoreSimilarity": self.ignore_similarity,
        }
        if self.data is not None:
            d["data"] = self.data
        if self.message:
            d["message"] = self.message
        return d

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "case_id": self.case_id,
            "data_type": self.data_type,
            "data": self.data,
            "message": self.message,
            "tlp": self.tlp,
            "pap": self.pap,
            "tags": list(self.tags),
            "ioc": self.ioc,
            "sighted": self.sighted,
            "sighted_at": self.sighted_at,
            "ignore_similarity": self.ignore_similarity,
            "is_zip": self.is_zip,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TheHiveObservable":
        return cls(
            id=d.get("id") or d.get("_id"),
            case_id=d.get("case_id") or d.get("caseId"),
            data_type=d.get("data_type") or d.get("dataType", ObservableDataType.OTHER.value),
            data=d.get("data"),
            message=d.get("message"),
            tlp=d.get("tlp", TLP.AMBER.value),
            pap=d.get("pap", PAP.AMBER.value),
            tags=list(d.get("tags", [])),
            ioc=d.get("ioc", False),
            sighted=d.get("sighted", False),
            sighted_at=d.get("sighted_at") or d.get("sightedAt"),
            ignore_similarity=d.get("ignore_similarity") or d.get("ignoreSimilarity", False),
            is_zip=d.get("is_zip") or d.get("isZip", False),
        )


@dataclass
class TheHiveAlert:
    """Represents a TheHive alert."""
    id: Optional[str] = None
    title: str = ""
    description: str = ""
    severity: int = CaseSeverity.MEDIUM.value
    tlp: int = TLP.AMBER.value
    pap: int = PAP.AMBER.value
    status: str = AlertStatus.NEW.value
    type: str = "external"
    source: str = "TSUNAMI"
    source_ref: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    artifacts: List[Dict[str, Any]] = field(default_factory=list)
    case_template: Optional[str] = None
    follow: bool = True
    date: Optional[str] = None
    custom_fields: Dict[str, Any] = field(default_factory=dict)

    def to_create_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "tlp": self.tlp,
            "pap": self.pap,
            "type": self.type,
            "source": self.source,
            "sourceRef": self.source_ref or str(uuid.uuid4()),
            "tags": self.tags,
            "follow": self.follow,
        }
        if self.artifacts:
            d["artifacts"] = self.artifacts
        if self.case_template:
            d["caseTemplate"] = self.case_template
        if self.custom_fields:
            d["customFields"] = self.custom_fields
        return d

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "tlp": self.tlp,
            "pap": self.pap,
            "status": self.status,
            "type": self.type,
            "source": self.source,
            "source_ref": self.source_ref,
            "tags": list(self.tags),
            "artifacts": list(self.artifacts),
            "case_template": self.case_template,
            "follow": self.follow,
            "date": self.date,
            "custom_fields": dict(self.custom_fields),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "TheHiveAlert":
        return cls(
            id=d.get("id") or d.get("_id"),
            title=d.get("title", ""),
            description=d.get("description", ""),
            severity=d.get("severity", CaseSeverity.MEDIUM.value),
            tlp=d.get("tlp", TLP.AMBER.value),
            pap=d.get("pap", PAP.AMBER.value),
            status=d.get("status", AlertStatus.NEW.value),
            type=d.get("type", "external"),
            source=d.get("source", "TSUNAMI"),
            source_ref=d.get("source_ref") or d.get("sourceRef"),
            tags=list(d.get("tags", [])),
            artifacts=list(d.get("artifacts", [])),
            case_template=d.get("case_template") or d.get("caseTemplate"),
            follow=d.get("follow", True),
            date=d.get("date"),
            custom_fields=dict(d.get("custom_fields") or d.get("customFields") or {}),
        )


@dataclass
class SyncRecord:
    """Tracks sync state between TSUNAMI and TheHive."""
    id: str = ""
    tsunami_id: str = ""
    thehive_id: str = ""
    entity_type: str = ""  # case, task, observable, alert
    direction: str = SyncDirection.TSUNAMI_TO_THEHIVE.value
    status: str = SyncStatus.PENDING.value
    last_synced: Optional[str] = None
    error_message: Optional[str] = None
    created_at: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tsunami_id": self.tsunami_id,
            "thehive_id": self.thehive_id,
            "entity_type": self.entity_type,
            "direction": self.direction,
            "status": self.status,
            "last_synced": self.last_synced,
            "error_message": self.error_message,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SyncRecord":
        return cls(
            id=d.get("id", ""),
            tsunami_id=d.get("tsunami_id", ""),
            thehive_id=d.get("thehive_id", ""),
            entity_type=d.get("entity_type", ""),
            direction=d.get("direction", SyncDirection.TSUNAMI_TO_THEHIVE.value),
            status=d.get("status", SyncStatus.PENDING.value),
            last_synced=d.get("last_synced"),
            error_message=d.get("error_message"),
            created_at=d.get("created_at", ""),
        )


# ============================================================================
# TheHive API Client
# ============================================================================

class TheHiveClient:
    """HTTP client for TheHive API v1."""

    def __init__(
        self,
        url: str = "http://localhost:9000",
        api_key: Optional[str] = None,
        org_name: Optional[str] = None,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_retries: int = 3,
    ):
        self.url = url.rstrip("/")
        self.api_key = api_key or os.environ.get("THEHIVE_API_KEY", "")
        self.org_name = org_name
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self._session = None
        self._lock = threading.Lock()

    def _get_session(self):
        """Lazy-init requests session."""
        if self._session is None:
            with self._lock:
                if self._session is None:
                    try:
                        import requests
                        self._session = requests.Session()
                        self._session.headers.update({
                            "Authorization": f"Bearer {self.api_key}",
                            "Content-Type": "application/json",
                        })
                        if self.org_name:
                            self._session.headers["X-Organisation"] = self.org_name
                        self._session.verify = self.verify_ssl
                    except ImportError:
                        logger.warning("requests library not available")
                        return None
        return self._session

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Execute HTTP request with retry logic."""
        session = self._get_session()
        if session is None:
            return {"error": "requests library not available", "_status_code": 0}

        url = f"{self.url}/api/v1{endpoint}"
        last_error = None

        for attempt in range(self.max_retries):
            try:
                resp = session.request(
                    method=method,
                    url=url,
                    json=data,
                    params=params,
                    timeout=self.timeout,
                )
                result = {}
                try:
                    result = resp.json() if resp.text else {}
                except (ValueError, TypeError):
                    result = {"_raw": resp.text}
                result["_status_code"] = resp.status_code
                if resp.status_code < 500:
                    return result
                last_error = f"HTTP {resp.status_code}"
            except Exception as e:
                last_error = str(e)

            if attempt < self.max_retries - 1:
                time.sleep(0.5 * (2 ** attempt))

        return {"error": last_error or "Unknown error", "_status_code": 0}

    def health_check(self) -> Dict[str, Any]:
        """Check TheHive connectivity."""
        result = self._request("GET", "/user/current")
        status_code = result.get("_status_code", 0)
        return {
            "healthy": 200 <= status_code < 300,
            "status_code": status_code,
            "user": result.get("login"),
            "organisation": result.get("organisation"),
        }

    # ---- Cases ----

    def create_case(self, case: TheHiveCase) -> Dict[str, Any]:
        return self._request("POST", "/case", data=case.to_create_dict())

    def get_case(self, case_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/case/{case_id}")

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("PATCH", f"/case/{case_id}", data=updates)

    def delete_case(self, case_id: str) -> Dict[str, Any]:
        return self._request("DELETE", f"/case/{case_id}")

    def search_cases(
        self,
        query: Optional[Dict] = None,
        sort_by: str = "-createdAt",
        page_size: int = 50,
        page: int = 0,
    ) -> Dict[str, Any]:
        data = {"query": query or [{"_name": "listCase"}]}
        params = {
            "range": f"{page * page_size}-{(page + 1) * page_size}",
            "sort": sort_by,
        }
        return self._request("POST", "/query", data=data, params=params)

    def merge_cases(self, case_id_1: str, case_id_2: str) -> Dict[str, Any]:
        return self._request("POST", f"/case/{case_id_1}/_merge/{case_id_2}")

    # ---- Tasks ----

    def create_task(self, case_id: str, task: TheHiveTask) -> Dict[str, Any]:
        return self._request("POST", f"/case/{case_id}/task", data=task.to_create_dict())

    def get_task(self, task_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/case/task/{task_id}")

    def update_task(self, task_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("PATCH", f"/case/task/{task_id}", data=updates)

    def list_case_tasks(self, case_id: str) -> Dict[str, Any]:
        data = {"query": [
            {"_name": "getCase", "idOrName": case_id},
            {"_name": "tasks"},
        ]}
        return self._request("POST", "/query", data=data)

    def add_task_log(self, task_id: str, message: str, attachments: Optional[List] = None) -> Dict[str, Any]:
        data: Dict[str, Any] = {"message": message}
        return self._request("POST", f"/case/task/{task_id}/log", data=data)

    # ---- Observables ----

    def create_observable(self, case_id: str, observable: TheHiveObservable) -> Dict[str, Any]:
        return self._request(
            "POST", f"/case/{case_id}/observable", data=observable.to_create_dict()
        )

    def get_observable(self, observable_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/case/observable/{observable_id}")

    def update_observable(self, observable_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("PATCH", f"/case/observable/{observable_id}", data=updates)

    def list_case_observables(self, case_id: str) -> Dict[str, Any]:
        data = {"query": [
            {"_name": "getCase", "idOrName": case_id},
            {"_name": "observables"},
        ]}
        return self._request("POST", "/query", data=data)

    def run_analyzer(self, observable_id: str, analyzer_id: str) -> Dict[str, Any]:
        data = {
            "analyzerId": analyzer_id,
            "cortexId": "local",
        }
        return self._request(
            "POST", f"/connector/cortex/job", data={
                "cortexId": "local",
                "analyzerId": analyzer_id,
                "artifactId": observable_id,
            }
        )

    # ---- Alerts ----

    def create_alert(self, alert: TheHiveAlert) -> Dict[str, Any]:
        return self._request("POST", "/alert", data=alert.to_create_dict())

    def get_alert(self, alert_id: str) -> Dict[str, Any]:
        return self._request("GET", f"/alert/{alert_id}")

    def update_alert(self, alert_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        return self._request("PATCH", f"/alert/{alert_id}", data=updates)

    def promote_alert(self, alert_id: str, case_template: Optional[str] = None) -> Dict[str, Any]:
        data = {}
        if case_template:
            data["caseTemplate"] = case_template
        return self._request("POST", f"/alert/{alert_id}/createCase", data=data)

    def merge_alert_into_case(self, alert_id: str, case_id: str) -> Dict[str, Any]:
        return self._request("POST", f"/alert/{alert_id}/merge/{case_id}")

    def search_alerts(
        self,
        query: Optional[Dict] = None,
        sort_by: str = "-date",
        page_size: int = 50,
        page: int = 0,
    ) -> Dict[str, Any]:
        data = {"query": query or [{"_name": "listAlert"}]}
        params = {
            "range": f"{page * page_size}-{(page + 1) * page_size}",
            "sort": sort_by,
        }
        return self._request("POST", "/query", data=data, params=params)


# ============================================================================
# Sync State Store
# ============================================================================

class SyncStore:
    """SQLite-backed sync state tracking."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "data", "thehive_sync.db"
        )
        Path(os.path.dirname(self.db_path)).mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_records (
                    id TEXT PRIMARY KEY,
                    tsunami_id TEXT NOT NULL,
                    thehive_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    status TEXT NOT NULL,
                    last_synced TEXT,
                    error_message TEXT,
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sync_tsunami_id ON sync_records(tsunami_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sync_thehive_id ON sync_records(thehive_id)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_sync_entity_type ON sync_records(entity_type)
            """)
            conn.commit()
            conn.close()

    def save_record(self, record: SyncRecord) -> SyncRecord:
        if not record.id:
            record.id = str(uuid.uuid4())
        if not record.created_at:
            record.created_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("""
                INSERT OR REPLACE INTO sync_records
                (id, tsunami_id, thehive_id, entity_type, direction, status,
                 last_synced, error_message, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                record.id, record.tsunami_id, record.thehive_id,
                record.entity_type, record.direction, record.status,
                record.last_synced, record.error_message, record.created_at,
            ))
            conn.commit()
            conn.close()
        return record

    def get_by_tsunami_id(self, tsunami_id: str, entity_type: Optional[str] = None) -> Optional[SyncRecord]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            if entity_type:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE tsunami_id = ? AND entity_type = ?",
                    (tsunami_id, entity_type)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE tsunami_id = ?",
                    (tsunami_id,)
                ).fetchone()
            conn.close()
            if row:
                return SyncRecord.from_dict(dict(row))
            return None

    def get_by_thehive_id(self, thehive_id: str, entity_type: Optional[str] = None) -> Optional[SyncRecord]:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            if entity_type:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE thehive_id = ? AND entity_type = ?",
                    (thehive_id, entity_type)
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT * FROM sync_records WHERE thehive_id = ?",
                    (thehive_id,)
                ).fetchone()
            conn.close()
            if row:
                return SyncRecord.from_dict(dict(row))
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
            params: List[Any] = []
            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            conn.close()
            return [SyncRecord.from_dict(dict(r)) for r in rows]

    def delete_record(self, record_id: str) -> bool:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.execute("DELETE FROM sync_records WHERE id = ?", (record_id,))
            conn.commit()
            deleted = cursor.rowcount > 0
            conn.close()
            return deleted

    def count_records(self, entity_type: Optional[str] = None, status: Optional[str] = None) -> int:
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            query = "SELECT COUNT(*) FROM sync_records WHERE 1=1"
            params: List[Any] = []
            if entity_type:
                query += " AND entity_type = ?"
                params.append(entity_type)
            if status:
                query += " AND status = ?"
                params.append(status)
            count = conn.execute(query, params).fetchone()[0]
            conn.close()
            return count


# ============================================================================
# TheHive Connector (Main Orchestrator)
# ============================================================================

class TheHiveConnector:
    """Main connector orchestrating TheHive integration."""

    def __init__(
        self,
        client: Optional[TheHiveClient] = None,
        sync_store: Optional[SyncStore] = None,
        url: str = "http://localhost:9000",
        api_key: Optional[str] = None,
        org_name: Optional[str] = None,
        default_tlp: int = TLP.AMBER.value,
        default_pap: int = PAP.AMBER.value,
        auto_sync: bool = False,
    ):
        self.client = client or TheHiveClient(url=url, api_key=api_key, org_name=org_name)
        self.sync_store = sync_store or SyncStore()
        self.default_tlp = default_tlp
        self.default_pap = default_pap
        self.auto_sync = auto_sync
        self._callbacks: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()

    # ---- Callbacks ----

    def on(self, event: str, callback: Callable):
        """Register event callback. Events: case_created, case_updated, alert_synced, sync_error"""
        with self._lock:
            self._callbacks.setdefault(event, []).append(callback)

    def _emit(self, event: str, data: Any = None):
        for cb in self._callbacks.get(event, []):
            try:
                cb(event, data)
            except Exception as e:
                logger.error("Callback error for %s: %s", event, e)

    # ---- Health ----

    def health_check(self) -> Dict[str, Any]:
        return self.client.health_check()

    # ---- Case Management ----

    def create_case(self, case: TheHiveCase) -> Tuple[bool, Dict[str, Any]]:
        """Create a case in TheHive."""
        result = self.client.create_case(case)
        status_code = result.get("_status_code", 0)
        if 200 <= status_code < 300:
            case_id = result.get("_id") or result.get("id", "")
            if case.tsunami_alert_id:
                self.sync_store.save_record(SyncRecord(
                    tsunami_id=case.tsunami_alert_id,
                    thehive_id=case_id,
                    entity_type="case",
                    direction=SyncDirection.TSUNAMI_TO_THEHIVE.value,
                    status=SyncStatus.SYNCED.value,
                    last_synced=datetime.now(timezone.utc).isoformat(),
                ))
            self._emit("case_created", {"case_id": case_id, "result": result})
            return True, result
        return False, result

    def get_case(self, case_id: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.get_case(case_id)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def update_case(self, case_id: str, updates: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.update_case(case_id, updates)
        status_code = result.get("_status_code", 0)
        if 200 <= status_code < 300:
            self._emit("case_updated", {"case_id": case_id, "updates": updates})
        return 200 <= status_code < 300, result

    def close_case(self, case_id: str, summary: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        updates: Dict[str, Any] = {"status": CaseStatus.RESOLVED.value}
        if summary:
            updates["summary"] = summary
        return self.update_case(case_id, updates)

    def delete_case(self, case_id: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.delete_case(case_id)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def search_cases(self, **kwargs) -> Tuple[bool, Any]:
        result = self.client.search_cases(**kwargs)
        status_code = result.get("_status_code", 0) if isinstance(result, dict) else 0
        return 200 <= status_code < 300, result

    def merge_cases(self, case_id_1: str, case_id_2: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.merge_cases(case_id_1, case_id_2)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    # ---- Task Management ----

    def create_task(self, case_id: str, task: TheHiveTask) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.create_task(case_id, task)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def get_task(self, task_id: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.get_task(task_id)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def update_task(self, task_id: str, updates: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.update_task(task_id, updates)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def complete_task(self, task_id: str) -> Tuple[bool, Dict[str, Any]]:
        return self.update_task(task_id, {"status": TaskStatus.COMPLETED.value})

    def list_case_tasks(self, case_id: str) -> Tuple[bool, Any]:
        result = self.client.list_case_tasks(case_id)
        status_code = result.get("_status_code", 0) if isinstance(result, dict) else 0
        return 200 <= status_code < 300, result

    def add_task_log(self, task_id: str, message: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.add_task_log(task_id, message)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    # ---- Observable Management ----

    def add_observable(
        self,
        case_id: str,
        observable: TheHiveObservable,
    ) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.create_observable(case_id, observable)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def get_observable(self, observable_id: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.get_observable(observable_id)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def update_observable(self, observable_id: str, updates: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.update_observable(observable_id, updates)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def list_case_observables(self, case_id: str) -> Tuple[bool, Any]:
        result = self.client.list_case_observables(case_id)
        status_code = result.get("_status_code", 0) if isinstance(result, dict) else 0
        return 200 <= status_code < 300, result

    def run_analyzer(self, observable_id: str, analyzer_id: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.run_analyzer(observable_id, analyzer_id)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    # ---- Alert Management ----

    def create_alert(self, alert: TheHiveAlert) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.create_alert(alert)
        status_code = result.get("_status_code", 0)
        if 200 <= status_code < 300:
            self._emit("alert_synced", {"alert": alert.to_dict(), "result": result})
        return 200 <= status_code < 300, result

    def get_alert(self, alert_id: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.get_alert(alert_id)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def promote_alert_to_case(self, alert_id: str, case_template: Optional[str] = None) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.promote_alert(alert_id, case_template)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    def merge_alert_into_case(self, alert_id: str, case_id: str) -> Tuple[bool, Dict[str, Any]]:
        result = self.client.merge_alert_into_case(alert_id, case_id)
        status_code = result.get("_status_code", 0)
        return 200 <= status_code < 300, result

    # ---- TSUNAMI ↔ TheHive Sync ----

    def sync_tsunami_alert_to_case(
        self,
        alert_data: Dict[str, Any],
        template: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """Create TheHive case from TSUNAMI alert."""
        alert_id = alert_data.get("alert_id", alert_data.get("id", ""))

        # Check for existing sync
        existing = self.sync_store.get_by_tsunami_id(alert_id, "case")
        if existing and existing.status == SyncStatus.SYNCED.value:
            return True, {"message": "Already synced", "thehive_id": existing.thehive_id}

        severity_map = {
            "low": CaseSeverity.LOW.value,
            "medium": CaseSeverity.MEDIUM.value,
            "high": CaseSeverity.HIGH.value,
            "critical": CaseSeverity.CRITICAL.value,
        }

        case = TheHiveCase(
            title=f"[TSUNAMI] {alert_data.get('title', alert_data.get('rule', 'Unknown Alert'))}",
            description=alert_data.get("description", alert_data.get("message", "")),
            severity=severity_map.get(
                str(alert_data.get("severity", "medium")).lower(),
                CaseSeverity.MEDIUM.value
            ),
            tlp=self.default_tlp,
            pap=self.default_pap,
            tags=list(alert_data.get("tags", [])) + ["TSUNAMI", "auto-synced"],
            source="TSUNAMI",
            source_ref=alert_id,
            template=template,
            tsunami_alert_id=alert_id,
        )

        if alert_data.get("assignee"):
            case.assignee = alert_data["assignee"]

        success, result = self.create_case(case)

        if not success:
            self.sync_store.save_record(SyncRecord(
                tsunami_id=alert_id,
                thehive_id="",
                entity_type="case",
                direction=SyncDirection.TSUNAMI_TO_THEHIVE.value,
                status=SyncStatus.FAILED.value,
                error_message=str(result.get("error", result.get("message", "Unknown"))),
            ))
            self._emit("sync_error", {"tsunami_id": alert_id, "error": result})

        return success, result

    def sync_thehive_case_to_tsunami(self, case_id: str) -> Tuple[bool, Dict[str, Any]]:
        """Import TheHive case data for TSUNAMI consumption."""
        success, result = self.get_case(case_id)
        if not success:
            return False, result

        case = TheHiveCase.from_dict(result)

        reverse_severity = {
            CaseSeverity.LOW.value: "low",
            CaseSeverity.MEDIUM.value: "medium",
            CaseSeverity.HIGH.value: "high",
            CaseSeverity.CRITICAL.value: "critical",
        }

        tsunami_data = {
            "source": "thehive",
            "thehive_case_id": case.id,
            "title": case.title,
            "description": case.description,
            "severity": reverse_severity.get(case.severity, "medium"),
            "status": case.status,
            "tags": case.tags,
            "owner": case.owner,
            "assignee": case.assignee,
            "tlp": case.tlp,
            "pap": case.pap,
            "custom_fields": case.custom_fields,
        }

        # Record sync
        self.sync_store.save_record(SyncRecord(
            tsunami_id=f"thehive_{case_id}",
            thehive_id=case_id,
            entity_type="case",
            direction=SyncDirection.THEHIVE_TO_TSUNAMI.value,
            status=SyncStatus.SYNCED.value,
            last_synced=datetime.now(timezone.utc).isoformat(),
        ))

        return True, tsunami_data

    def add_observables_from_alert(
        self,
        case_id: str,
        alert_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Extract IOCs from TSUNAMI alert and add as observables."""
        results = []
        iocs = alert_data.get("iocs", alert_data.get("observables", []))

        for ioc in iocs:
            data_type = ioc.get("type", ioc.get("data_type", ObservableDataType.OTHER.value))
            # Map common types
            type_map = {
                "ip": ObservableDataType.IP.value,
                "ip_address": ObservableDataType.IP.value,
                "src_ip": ObservableDataType.IP.value,
                "dst_ip": ObservableDataType.IP.value,
                "domain": ObservableDataType.DOMAIN.value,
                "url": ObservableDataType.URL.value,
                "hash": ObservableDataType.HASH.value,
                "md5": ObservableDataType.HASH.value,
                "sha1": ObservableDataType.HASH.value,
                "sha256": ObservableDataType.HASH.value,
                "email": ObservableDataType.MAIL.value,
                "filename": ObservableDataType.FILENAME.value,
                "hostname": ObservableDataType.HOSTNAME.value,
            }
            data_type = type_map.get(data_type.lower(), data_type) if isinstance(data_type, str) else data_type

            obs = TheHiveObservable(
                data_type=data_type,
                data=ioc.get("value", ioc.get("data", "")),
                message=ioc.get("description", ioc.get("message", "")),
                tlp=ioc.get("tlp", self.default_tlp),
                pap=ioc.get("pap", self.default_pap),
                tags=list(ioc.get("tags", ["TSUNAMI"])),
                ioc=ioc.get("ioc", True),
            )
            success, result = self.add_observable(case_id, obs)
            results.append({"success": success, "observable": obs.to_dict(), "result": result})

        return results

    # ---- Sync State Queries ----

    def get_sync_status(self, tsunami_id: str) -> Optional[Dict[str, Any]]:
        record = self.sync_store.get_by_tsunami_id(tsunami_id)
        return record.to_dict() if record else None

    def list_sync_records(self, **kwargs) -> List[Dict[str, Any]]:
        records = self.sync_store.list_records(**kwargs)
        return [r.to_dict() for r in records]

    def get_sync_stats(self) -> Dict[str, Any]:
        return {
            "total": self.sync_store.count_records(),
            "synced": self.sync_store.count_records(status=SyncStatus.SYNCED.value),
            "failed": self.sync_store.count_records(status=SyncStatus.FAILED.value),
            "pending": self.sync_store.count_records(status=SyncStatus.PENDING.value),
            "cases": self.sync_store.count_records(entity_type="case"),
            "alerts": self.sync_store.count_records(entity_type="alert"),
        }


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_thehive_blueprint(connector: "TheHiveConnector" = None):
    """Create Flask blueprint for TheHive REST API."""
    try:
        from flask import Blueprint, request, jsonify
    except ImportError:
        logger.warning("Flask not available, REST API disabled")
        return None

    bp = Blueprint("thehive", __name__, url_prefix="/api/v1/soc/thehive")

    def _conn():
        return connector or get_thehive_connector()

    @bp.route("/health", methods=["GET"])
    def health():
        result = _conn().health_check()
        code = 200 if result.get("healthy") else 503
        return jsonify(result), code

    # ---- Cases ----

    @bp.route("/cases", methods=["POST"])
    def create_case():
        data = request.get_json(force=True, silent=True) or {}
        if not data.get("title"):
            return jsonify({"error": "title required"}), 400
        case = TheHiveCase.from_dict(data)
        success, result = _conn().create_case(case)
        return jsonify(result), 201 if success else 400

    @bp.route("/cases/<case_id>", methods=["GET"])
    def get_case(case_id):
        success, result = _conn().get_case(case_id)
        return jsonify(result), 200 if success else 404

    @bp.route("/cases/<case_id>", methods=["PATCH"])
    def update_case(case_id):
        data = request.get_json(force=True, silent=True) or {}
        success, result = _conn().update_case(case_id, data)
        return jsonify(result), 200 if success else 400

    @bp.route("/cases/<case_id>", methods=["DELETE"])
    def delete_case(case_id):
        success, result = _conn().delete_case(case_id)
        return jsonify(result), 200 if success else 404

    @bp.route("/cases/<case_id>/close", methods=["POST"])
    def close_case(case_id):
        data = request.get_json(force=True, silent=True) or {}
        success, result = _conn().close_case(case_id, summary=data.get("summary"))
        return jsonify(result), 200 if success else 400

    @bp.route("/cases/merge", methods=["POST"])
    def merge_cases():
        data = request.get_json(force=True, silent=True) or {}
        c1 = data.get("case_id_1", "")
        c2 = data.get("case_id_2", "")
        if not c1 or not c2:
            return jsonify({"error": "case_id_1 and case_id_2 required"}), 400
        success, result = _conn().merge_cases(c1, c2)
        return jsonify(result), 200 if success else 400

    # ---- Tasks ----

    @bp.route("/cases/<case_id>/tasks", methods=["POST"])
    def create_task(case_id):
        data = request.get_json(force=True, silent=True) or {}
        if not data.get("title"):
            return jsonify({"error": "title required"}), 400
        task = TheHiveTask.from_dict(data)
        success, result = _conn().create_task(case_id, task)
        return jsonify(result), 201 if success else 400

    @bp.route("/cases/<case_id>/tasks", methods=["GET"])
    def list_tasks(case_id):
        success, result = _conn().list_case_tasks(case_id)
        return jsonify(result), 200 if success else 400

    @bp.route("/tasks/<task_id>", methods=["GET"])
    def get_task(task_id):
        success, result = _conn().get_task(task_id)
        return jsonify(result), 200 if success else 404

    @bp.route("/tasks/<task_id>", methods=["PATCH"])
    def update_task(task_id):
        data = request.get_json(force=True, silent=True) or {}
        success, result = _conn().update_task(task_id, data)
        return jsonify(result), 200 if success else 400

    @bp.route("/tasks/<task_id>/complete", methods=["POST"])
    def complete_task(task_id):
        success, result = _conn().complete_task(task_id)
        return jsonify(result), 200 if success else 400

    @bp.route("/tasks/<task_id>/log", methods=["POST"])
    def add_task_log(task_id):
        data = request.get_json(force=True, silent=True) or {}
        if not data.get("message"):
            return jsonify({"error": "message required"}), 400
        success, result = _conn().add_task_log(task_id, data["message"])
        return jsonify(result), 201 if success else 400

    # ---- Observables ----

    @bp.route("/cases/<case_id>/observables", methods=["POST"])
    def add_observable(case_id):
        data = request.get_json(force=True, silent=True) or {}
        obs = TheHiveObservable.from_dict(data)
        success, result = _conn().add_observable(case_id, obs)
        return jsonify(result), 201 if success else 400

    @bp.route("/cases/<case_id>/observables", methods=["GET"])
    def list_observables(case_id):
        success, result = _conn().list_case_observables(case_id)
        return jsonify(result), 200 if success else 400

    @bp.route("/observables/<obs_id>", methods=["GET"])
    def get_observable(obs_id):
        success, result = _conn().get_observable(obs_id)
        return jsonify(result), 200 if success else 404

    @bp.route("/observables/<obs_id>/analyze", methods=["POST"])
    def analyze_observable(obs_id):
        data = request.get_json(force=True, silent=True) or {}
        analyzer = data.get("analyzer_id", "")
        if not analyzer:
            return jsonify({"error": "analyzer_id required"}), 400
        success, result = _conn().run_analyzer(obs_id, analyzer)
        return jsonify(result), 200 if success else 400

    # ---- Alerts ----

    @bp.route("/alerts", methods=["POST"])
    def create_alert():
        data = request.get_json(force=True, silent=True) or {}
        if not data.get("title"):
            return jsonify({"error": "title required"}), 400
        alert = TheHiveAlert.from_dict(data)
        success, result = _conn().create_alert(alert)
        return jsonify(result), 201 if success else 400

    @bp.route("/alerts/<alert_id>", methods=["GET"])
    def get_alert(alert_id):
        success, result = _conn().get_alert(alert_id)
        return jsonify(result), 200 if success else 404

    @bp.route("/alerts/<alert_id>/promote", methods=["POST"])
    def promote_alert(alert_id):
        data = request.get_json(force=True, silent=True) or {}
        success, result = _conn().promote_alert_to_case(alert_id, data.get("case_template"))
        return jsonify(result), 201 if success else 400

    @bp.route("/alerts/<alert_id>/merge/<case_id>", methods=["POST"])
    def merge_alert(alert_id, case_id):
        success, result = _conn().merge_alert_into_case(alert_id, case_id)
        return jsonify(result), 200 if success else 400

    # ---- Sync ----

    @bp.route("/sync/alert-to-case", methods=["POST"])
    def sync_alert_to_case():
        data = request.get_json(force=True, silent=True) or {}
        if not data.get("alert_id") and not data.get("id"):
            return jsonify({"error": "alert_id required"}), 400
        success, result = _conn().sync_tsunami_alert_to_case(data, template=data.get("template"))
        return jsonify(result), 201 if success else 400

    @bp.route("/sync/case-to-tsunami/<case_id>", methods=["POST"])
    def sync_case_to_tsunami(case_id):
        success, result = _conn().sync_thehive_case_to_tsunami(case_id)
        return jsonify(result), 200 if success else 400

    @bp.route("/sync/observables/<case_id>", methods=["POST"])
    def sync_observables(case_id):
        data = request.get_json(force=True, silent=True) or {}
        results = _conn().add_observables_from_alert(case_id, data)
        return jsonify({"results": results}), 200

    @bp.route("/sync/status/<tsunami_id>", methods=["GET"])
    def sync_status(tsunami_id):
        result = _conn().get_sync_status(tsunami_id)
        if result:
            return jsonify(result), 200
        return jsonify({"error": "not found"}), 404

    @bp.route("/sync/records", methods=["GET"])
    def list_sync_records():
        entity_type = request.args.get("entity_type")
        status = request.args.get("status")
        records = _conn().list_sync_records(entity_type=entity_type, status=status)
        return jsonify({"records": records, "total": len(records)}), 200

    @bp.route("/sync/stats", methods=["GET"])
    def sync_stats():
        return jsonify(_conn().get_sync_stats()), 200

    return bp


# ============================================================================
# Global Singleton
# ============================================================================

_global_connector: Optional[TheHiveConnector] = None
_global_lock = threading.Lock()


def get_thehive_connector(**kwargs) -> TheHiveConnector:
    """Get or create the global TheHive connector instance."""
    global _global_connector
    if _global_connector is None:
        with _global_lock:
            if _global_connector is None:
                _global_connector = TheHiveConnector(**kwargs)
    return _global_connector


def reset_global_connector():
    """Reset global connector (for testing)."""
    global _global_connector
    with _global_lock:
        _global_connector = None
