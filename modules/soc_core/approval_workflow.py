#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Approval Workflow Engine
    Production-Grade Automated Action Approval System
================================================================================

    Features:
    - ApprovalRequest lifecycle: PENDING → APPROVED/REJECTED/EXPIRED/CANCELLED
    - Auto-approve rules engine (low-risk actions bypass manual approval)
    - Multi-level escalation (timeout → escalate to higher role)
    - Priority-based SLA timers (P1:5m, P2:15m, P3:60m, P4:4h)
    - Delegation support (approver can delegate to another)
    - Bulk approve/reject operations
    - SQLite persistent storage with WAL mode
    - Audit trail (full history of all approval decisions)
    - Callback system (notify on approval/rejection)
    - Thread-safe operations
    - Flask Blueprint REST API

================================================================================
"""

import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("soc.approval_workflow")


# ============================================================================
# Enums
# ============================================================================

class ApprovalStatus(Enum):
    """Approval request lifecycle status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    ESCALATED = "escalated"


class ApprovalPriority(Enum):
    """Priority levels with SLA timeouts."""
    P1_CRITICAL = 1   # 5 minutes
    P2_HIGH = 2       # 15 minutes
    P3_MEDIUM = 3     # 60 minutes
    P4_LOW = 4        # 4 hours

    @property
    def timeout_minutes(self) -> int:
        return {1: 5, 2: 15, 3: 60, 4: 240}[self.value]

    @property
    def label(self) -> str:
        return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}[self.value]


class ActionType(Enum):
    """Types of SOC actions requiring approval."""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    DISABLE_USER = "disable_user"
    QUARANTINE_FILE = "quarantine_file"
    KILL_PROCESS = "kill_process"
    UPDATE_FIREWALL = "update_firewall"
    DEPLOY_PATCH = "deploy_patch"
    ESCALATE_CASE = "escalate_case"
    RUN_PLAYBOOK = "run_playbook"
    SEND_NOTIFICATION = "send_notification"
    COLLECT_EVIDENCE = "collect_evidence"
    CUSTOM = "custom"


class EscalationLevel(Enum):
    """Escalation hierarchy levels."""
    L1_ANALYST = 1
    L2_SENIOR = 2
    L3_LEAD = 3
    L4_MANAGER = 4
    L5_DIRECTOR = 5


class AuditAction(Enum):
    """Audit trail action types."""
    CREATED = "created"
    APPROVED = "approved"
    REJECTED = "rejected"
    ESCALATED = "escalated"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    DELEGATED = "delegated"
    COMMENT_ADDED = "comment_added"
    AUTO_APPROVED = "auto_approved"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class AutoApproveRule:
    """Rule for automatic approval of low-risk actions."""
    rule_id: str = ""
    name: str = ""
    description: str = ""
    action_type: str = ""          # ActionType value or "*" for all
    conditions: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    max_priority: int = 4          # Max priority level to auto-approve (4 = LOW)
    created_by: str = ""
    created_at: str = ""

    def __post_init__(self):
        if not self.rule_id:
            self.rule_id = str(uuid.uuid4())[:8]
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def matches(self, request: "ApprovalRequest") -> bool:
        """Check if this rule matches a given approval request."""
        if not self.enabled:
            return False
        # Check action type
        if self.action_type != "*" and self.action_type != request.action_type:
            return False
        # Check priority threshold
        if request.priority.value < self.max_priority:
            return False
        # Check conditions
        for key, expected in self.conditions.items():
            actual = request.context.get(key)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif isinstance(expected, dict):
                op = expected.get("op", "eq")
                val = expected.get("value")
                if op == "eq" and actual != val:
                    return False
                elif op == "ne" and actual == val:
                    return False
                elif op == "gt" and (actual is None or actual <= val):
                    return False
                elif op == "lt" and (actual is None or actual >= val):
                    return False
                elif op == "in" and actual not in val:
                    return False
                elif op == "contains" and (actual is None or val not in str(actual)):
                    return False
                elif op == "regex" and (actual is None or not re.search(val, str(actual))):
                    return False
            else:
                if actual != expected:
                    return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "action_type": self.action_type,
            "conditions": self.conditions,
            "enabled": self.enabled,
            "max_priority": self.max_priority,
            "created_by": self.created_by,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AutoApproveRule":
        return cls(
            rule_id=data.get("rule_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            action_type=data.get("action_type", ""),
            conditions=data.get("conditions") or {},
            enabled=data.get("enabled", True),
            max_priority=data.get("max_priority", 4),
            created_by=data.get("created_by", ""),
            created_at=data.get("created_at", ""),
        )


@dataclass
class AuditEntry:
    """Single audit trail entry."""
    entry_id: str = ""
    request_id: str = ""
    action: str = ""           # AuditAction value
    actor: str = ""
    timestamp: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    comment: str = ""

    def __post_init__(self):
        if not self.entry_id:
            self.entry_id = str(uuid.uuid4())[:12]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "request_id": self.request_id,
            "action": self.action,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "details": self.details,
            "comment": self.comment,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        return cls(
            entry_id=data.get("entry_id", ""),
            request_id=data.get("request_id", ""),
            action=data.get("action", ""),
            actor=data.get("actor", ""),
            timestamp=data.get("timestamp", ""),
            details=data.get("details") or {},
            comment=data.get("comment", ""),
        )


@dataclass
class ApprovalRequest:
    """A request for approval of an automated action."""
    request_id: str = ""
    action_type: str = ""          # ActionType value
    action_params: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    requester: str = ""
    approver: str = ""             # Current assigned approver
    delegated_from: str = ""       # Original approver if delegated
    status: ApprovalStatus = ApprovalStatus.PENDING
    priority: ApprovalPriority = ApprovalPriority.P3_MEDIUM
    escalation_level: EscalationLevel = EscalationLevel.L1_ANALYST
    title: str = ""
    description: str = ""
    alert_id: str = ""             # Related alert ID
    case_id: str = ""              # Related case ID
    created_at: str = ""
    updated_at: str = ""
    expires_at: str = ""
    decided_at: str = ""
    decision_comment: str = ""
    auto_approved: bool = False
    auto_approve_rule: str = ""    # Rule ID if auto-approved
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.request_id:
            self.request_id = f"APR-{uuid.uuid4().hex[:8].upper()}"
        now = datetime.now(timezone.utc)
        if not self.created_at:
            self.created_at = now.isoformat()
        if not self.updated_at:
            self.updated_at = now.isoformat()
        if not self.expires_at:
            timeout = self.priority.timeout_minutes
            self.expires_at = (now + timedelta(minutes=timeout)).isoformat()

    @property
    def is_pending(self) -> bool:
        return self.status == ApprovalStatus.PENDING

    @property
    def is_decided(self) -> bool:
        return self.status in (ApprovalStatus.APPROVED, ApprovalStatus.REJECTED)

    @property
    def is_expired(self) -> bool:
        if self.status != ApprovalStatus.PENDING:
            return False
        try:
            exp = datetime.fromisoformat(self.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return datetime.now(timezone.utc) >= exp
        except (ValueError, TypeError):
            return False

    @property
    def time_remaining_seconds(self) -> float:
        """Seconds until expiration. Negative means expired."""
        try:
            exp = datetime.fromisoformat(self.expires_at)
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            return (exp - datetime.now(timezone.utc)).total_seconds()
        except (ValueError, TypeError):
            return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "action_type": self.action_type,
            "action_params": self.action_params,
            "context": self.context,
            "requester": self.requester,
            "approver": self.approver,
            "delegated_from": self.delegated_from,
            "status": self.status.value,
            "priority": self.priority.value,
            "priority_label": self.priority.label,
            "escalation_level": self.escalation_level.value,
            "title": self.title,
            "description": self.description,
            "alert_id": self.alert_id,
            "case_id": self.case_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "decided_at": self.decided_at,
            "decision_comment": self.decision_comment,
            "auto_approved": self.auto_approved,
            "auto_approve_rule": self.auto_approve_rule,
            "tags": self.tags,
            "is_pending": self.is_pending,
            "is_expired": self.is_expired,
            "time_remaining_seconds": round(self.time_remaining_seconds, 1),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        status = data.get("status", "pending")
        if isinstance(status, str):
            status = ApprovalStatus(status)
        priority = data.get("priority", 3)
        if isinstance(priority, int):
            priority = ApprovalPriority(priority)
        elif isinstance(priority, str):
            priority = ApprovalPriority(int(priority))
        esc = data.get("escalation_level", 1)
        if isinstance(esc, int):
            esc = EscalationLevel(esc)
        tags = data.get("tags") or []
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (json.JSONDecodeError, TypeError):
                tags = []
        return cls(
            request_id=data.get("request_id", ""),
            action_type=data.get("action_type", ""),
            action_params=data.get("action_params") or {},
            context=data.get("context") or {},
            requester=data.get("requester", ""),
            approver=data.get("approver", ""),
            delegated_from=data.get("delegated_from", ""),
            status=status,
            priority=priority,
            escalation_level=esc,
            title=data.get("title", ""),
            description=data.get("description", ""),
            alert_id=data.get("alert_id", ""),
            case_id=data.get("case_id", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            expires_at=data.get("expires_at", ""),
            decided_at=data.get("decided_at", ""),
            decision_comment=data.get("decision_comment", ""),
            auto_approved=data.get("auto_approved", False),
            auto_approve_rule=data.get("auto_approve_rule", ""),
            tags=tags,
        )


# ============================================================================
# Approval Store (SQLite)
# ============================================================================

class ApprovalStore:
    """SQLite-backed persistent storage for approval requests and audit trail."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path(os.environ.get("TSUNAMI_DATA_DIR", "/tmp/tsunami"))
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / "approval_workflow.db")
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS approval_requests (
                        request_id TEXT PRIMARY KEY,
                        action_type TEXT NOT NULL,
                        action_params TEXT DEFAULT '{}',
                        context TEXT DEFAULT '{}',
                        requester TEXT DEFAULT '',
                        approver TEXT DEFAULT '',
                        delegated_from TEXT DEFAULT '',
                        status TEXT DEFAULT 'pending',
                        priority INTEGER DEFAULT 3,
                        escalation_level INTEGER DEFAULT 1,
                        title TEXT DEFAULT '',
                        description TEXT DEFAULT '',
                        alert_id TEXT DEFAULT '',
                        case_id TEXT DEFAULT '',
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        decided_at TEXT DEFAULT '',
                        decision_comment TEXT DEFAULT '',
                        auto_approved INTEGER DEFAULT 0,
                        auto_approve_rule TEXT DEFAULT '',
                        tags TEXT DEFAULT '[]'
                    );

                    CREATE INDEX IF NOT EXISTS idx_approval_status
                        ON approval_requests(status);
                    CREATE INDEX IF NOT EXISTS idx_approval_approver
                        ON approval_requests(approver);
                    CREATE INDEX IF NOT EXISTS idx_approval_priority
                        ON approval_requests(priority);
                    CREATE INDEX IF NOT EXISTS idx_approval_created
                        ON approval_requests(created_at);
                    CREATE INDEX IF NOT EXISTS idx_approval_alert
                        ON approval_requests(alert_id);

                    CREATE TABLE IF NOT EXISTS audit_trail (
                        entry_id TEXT PRIMARY KEY,
                        request_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        actor TEXT DEFAULT '',
                        timestamp TEXT NOT NULL,
                        details TEXT DEFAULT '{}',
                        comment TEXT DEFAULT '',
                        FOREIGN KEY (request_id) REFERENCES approval_requests(request_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_audit_request
                        ON audit_trail(request_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_action
                        ON audit_trail(action);

                    CREATE TABLE IF NOT EXISTS auto_approve_rules (
                        rule_id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT DEFAULT '',
                        action_type TEXT DEFAULT '',
                        conditions TEXT DEFAULT '{}',
                        enabled INTEGER DEFAULT 1,
                        max_priority INTEGER DEFAULT 4,
                        created_by TEXT DEFAULT '',
                        created_at TEXT NOT NULL
                    );
                """)
                conn.commit()
            finally:
                conn.close()

    def save_request(self, req: ApprovalRequest) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO approval_requests
                    (request_id, action_type, action_params, context, requester,
                     approver, delegated_from, status, priority, escalation_level,
                     title, description, alert_id, case_id, created_at, updated_at,
                     expires_at, decided_at, decision_comment, auto_approved,
                     auto_approve_rule, tags)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    req.request_id, req.action_type,
                    json.dumps(req.action_params), json.dumps(req.context),
                    req.requester, req.approver, req.delegated_from,
                    req.status.value, req.priority.value, req.escalation_level.value,
                    req.title, req.description, req.alert_id, req.case_id,
                    req.created_at, req.updated_at, req.expires_at,
                    req.decided_at, req.decision_comment,
                    1 if req.auto_approved else 0, req.auto_approve_rule,
                    json.dumps(req.tags),
                ))
                conn.commit()
            finally:
                conn.close()

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM approval_requests WHERE request_id = ?",
                    (request_id,)
                ).fetchone()
                if row is None:
                    return None
                return self._row_to_request(row)
            finally:
                conn.close()

    def list_requests(
        self,
        status: Optional[str] = None,
        approver: Optional[str] = None,
        priority: Optional[int] = None,
        action_type: Optional[str] = None,
        alert_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ApprovalRequest]:
        conditions = []
        params: list = []
        if status:
            conditions.append("status = ?")
            params.append(status)
        if approver:
            conditions.append("approver = ?")
            params.append(approver)
        if priority is not None:
            conditions.append("priority = ?")
            params.append(priority)
        if action_type:
            conditions.append("action_type = ?")
            params.append(action_type)
        if alert_id:
            conditions.append("alert_id = ?")
            params.append(alert_id)

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        query = f"SELECT * FROM approval_requests {where} ORDER BY priority ASC, created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(query, params).fetchall()
                return [self._row_to_request(r) for r in rows]
            finally:
                conn.close()

    def count_requests(self, status: Optional[str] = None) -> int:
        with self._lock:
            conn = self._get_conn()
            try:
                if status:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM approval_requests WHERE status = ?",
                        (status,)
                    ).fetchone()
                else:
                    row = conn.execute("SELECT COUNT(*) FROM approval_requests").fetchone()
                return row[0] if row else 0
            finally:
                conn.close()

    def get_pending_expired(self) -> List[ApprovalRequest]:
        """Get all pending requests that have expired."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM approval_requests WHERE status = 'pending' AND expires_at <= ?",
                    (now,)
                ).fetchall()
                return [self._row_to_request(r) for r in rows]
            finally:
                conn.close()

    def delete_request(self, request_id: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("DELETE FROM audit_trail WHERE request_id = ?", (request_id,))
                cursor = conn.execute(
                    "DELETE FROM approval_requests WHERE request_id = ?",
                    (request_id,)
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    # --- Audit ---

    def add_audit_entry(self, entry: AuditEntry) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT INTO audit_trail
                    (entry_id, request_id, action, actor, timestamp, details, comment)
                    VALUES (?,?,?,?,?,?,?)
                """, (
                    entry.entry_id, entry.request_id, entry.action,
                    entry.actor, entry.timestamp,
                    json.dumps(entry.details), entry.comment,
                ))
                conn.commit()
            finally:
                conn.close()

    def get_audit_trail(self, request_id: str) -> List[AuditEntry]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_trail WHERE request_id = ? ORDER BY timestamp ASC",
                    (request_id,)
                ).fetchall()
                return [self._row_to_audit(r) for r in rows]
            finally:
                conn.close()

    def get_recent_audit(self, limit: int = 50) -> List[AuditEntry]:
        with self._lock:
            conn = self._get_conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM audit_trail ORDER BY timestamp DESC LIMIT ?",
                    (limit,)
                ).fetchall()
                return [self._row_to_audit(r) for r in rows]
            finally:
                conn.close()

    # --- Auto-Approve Rules ---

    def save_rule(self, rule: AutoApproveRule) -> None:
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute("""
                    INSERT OR REPLACE INTO auto_approve_rules
                    (rule_id, name, description, action_type, conditions,
                     enabled, max_priority, created_by, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                """, (
                    rule.rule_id, rule.name, rule.description,
                    rule.action_type, json.dumps(rule.conditions),
                    1 if rule.enabled else 0, rule.max_priority,
                    rule.created_by, rule.created_at,
                ))
                conn.commit()
            finally:
                conn.close()

    def list_rules(self, enabled_only: bool = False) -> List[AutoApproveRule]:
        with self._lock:
            conn = self._get_conn()
            try:
                if enabled_only:
                    rows = conn.execute(
                        "SELECT * FROM auto_approve_rules WHERE enabled = 1"
                    ).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM auto_approve_rules").fetchall()
                return [self._row_to_rule(r) for r in rows]
            finally:
                conn.close()

    def get_rule(self, rule_id: str) -> Optional[AutoApproveRule]:
        with self._lock:
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM auto_approve_rules WHERE rule_id = ?",
                    (rule_id,)
                ).fetchone()
                return self._row_to_rule(row) if row else None
            finally:
                conn.close()

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                cursor = conn.execute(
                    "DELETE FROM auto_approve_rules WHERE rule_id = ?",
                    (rule_id,)
                )
                conn.commit()
                return cursor.rowcount > 0
            finally:
                conn.close()

    # --- Stats ---

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            conn = self._get_conn()
            try:
                stats: Dict[str, Any] = {}
                for status in ApprovalStatus:
                    row = conn.execute(
                        "SELECT COUNT(*) FROM approval_requests WHERE status = ?",
                        (status.value,)
                    ).fetchone()
                    stats[f"count_{status.value}"] = row[0] if row else 0
                row = conn.execute("SELECT COUNT(*) FROM approval_requests").fetchone()
                stats["total_requests"] = row[0] if row else 0
                row = conn.execute(
                    "SELECT COUNT(*) FROM approval_requests WHERE auto_approved = 1"
                ).fetchone()
                stats["auto_approved_total"] = row[0] if row else 0
                row = conn.execute("SELECT COUNT(*) FROM audit_trail").fetchone()
                stats["audit_entries"] = row[0] if row else 0
                row = conn.execute("SELECT COUNT(*) FROM auto_approve_rules WHERE enabled = 1").fetchone()
                stats["active_rules"] = row[0] if row else 0
                return stats
            finally:
                conn.close()

    # --- Helpers ---

    def _row_to_request(self, row: sqlite3.Row) -> ApprovalRequest:
        data = dict(row)
        try:
            data["action_params"] = json.loads(data.get("action_params", "{}"))
        except (json.JSONDecodeError, TypeError):
            data["action_params"] = {}
        try:
            data["context"] = json.loads(data.get("context", "{}"))
        except (json.JSONDecodeError, TypeError):
            data["context"] = {}
        try:
            data["tags"] = json.loads(data.get("tags", "[]"))
        except (json.JSONDecodeError, TypeError):
            data["tags"] = []
        data["auto_approved"] = bool(data.get("auto_approved", 0))
        return ApprovalRequest.from_dict(data)

    def _row_to_audit(self, row: sqlite3.Row) -> AuditEntry:
        data = dict(row)
        try:
            data["details"] = json.loads(data.get("details", "{}"))
        except (json.JSONDecodeError, TypeError):
            data["details"] = {}
        return AuditEntry.from_dict(data)

    def _row_to_rule(self, row: sqlite3.Row) -> AutoApproveRule:
        data = dict(row)
        try:
            data["conditions"] = json.loads(data.get("conditions", "{}"))
        except (json.JSONDecodeError, TypeError):
            data["conditions"] = {}
        data["enabled"] = bool(data.get("enabled", 1))
        return AutoApproveRule.from_dict(data)


# ============================================================================
# Approval Workflow Engine
# ============================================================================

class ApprovalWorkflowEngine:
    """
    Main approval workflow engine.

    Manages the lifecycle of approval requests including:
    - Submission with auto-approve rule evaluation
    - Manual approve/reject with audit trail
    - Escalation on timeout
    - Delegation to other approvers
    - Bulk operations
    - Callback notifications
    """

    def __init__(
        self,
        store: Optional[ApprovalStore] = None,
        db_path: Optional[str] = None,
        escalation_chain: Optional[Dict[int, str]] = None,
        on_approved: Optional[Callable[[ApprovalRequest], None]] = None,
        on_rejected: Optional[Callable[[ApprovalRequest], None]] = None,
        on_escalated: Optional[Callable[[ApprovalRequest], None]] = None,
        on_expired: Optional[Callable[[ApprovalRequest], None]] = None,
    ):
        self.store = store or ApprovalStore(db_path=db_path)
        self.escalation_chain = escalation_chain or {}
        self._callbacks: Dict[str, Optional[Callable]] = {
            "on_approved": on_approved,
            "on_rejected": on_rejected,
            "on_escalated": on_escalated,
            "on_expired": on_expired,
        }
        self._lock = threading.Lock()
        self._stats = {
            "submitted": 0,
            "approved": 0,
            "rejected": 0,
            "auto_approved": 0,
            "escalated": 0,
            "expired": 0,
            "delegated": 0,
            "cancelled": 0,
        }
        logger.info("ApprovalWorkflowEngine initialized")

    # --- Submit ---

    def submit(
        self,
        action_type: str,
        requester: str,
        title: str = "",
        description: str = "",
        action_params: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        approver: str = "",
        priority: ApprovalPriority = ApprovalPriority.P3_MEDIUM,
        alert_id: str = "",
        case_id: str = "",
        tags: Optional[List[str]] = None,
    ) -> ApprovalRequest:
        """
        Submit a new approval request.

        Evaluates auto-approve rules first. If no rule matches,
        creates a pending request for manual approval.
        """
        req = ApprovalRequest(
            action_type=action_type,
            action_params=action_params or {},
            context=context or {},
            requester=requester,
            approver=approver,
            priority=priority,
            title=title or f"{action_type} approval request",
            description=description,
            alert_id=alert_id,
            case_id=case_id,
            tags=tags or [],
        )

        # Check auto-approve rules
        matching_rule = self._check_auto_approve(req)
        if matching_rule:
            req.status = ApprovalStatus.APPROVED
            req.auto_approved = True
            req.auto_approve_rule = matching_rule.rule_id
            req.decided_at = datetime.now(timezone.utc).isoformat()
            req.updated_at = req.decided_at
            self.store.save_request(req)
            self._add_audit(
                req.request_id, AuditAction.AUTO_APPROVED, "system",
                details={"rule_id": matching_rule.rule_id, "rule_name": matching_rule.name},
                comment=f"Auto-approved by rule: {matching_rule.name}",
            )
            self._stats["auto_approved"] += 1
            self._stats["submitted"] += 1
            self._fire_callback("on_approved", req)
            logger.info(
                "Request %s auto-approved by rule %s",
                req.request_id, matching_rule.rule_id,
            )
            return req

        # Manual approval needed
        self.store.save_request(req)
        self._add_audit(
            req.request_id, AuditAction.CREATED, requester,
            details={"action_type": action_type, "priority": priority.label},
        )
        self._stats["submitted"] += 1
        logger.info(
            "Request %s submitted for approval (priority=%s, approver=%s)",
            req.request_id, priority.label, approver or "unassigned",
        )
        return req

    # --- Approve / Reject ---

    def approve(
        self,
        request_id: str,
        approver: str,
        comment: str = "",
    ) -> ApprovalRequest:
        """Approve a pending request."""
        req = self._get_pending(request_id)
        now = datetime.now(timezone.utc).isoformat()
        req.status = ApprovalStatus.APPROVED
        req.decided_at = now
        req.updated_at = now
        req.decision_comment = comment
        if not req.approver:
            req.approver = approver
        self.store.save_request(req)
        self._add_audit(
            request_id, AuditAction.APPROVED, approver,
            comment=comment,
        )
        self._stats["approved"] += 1
        self._fire_callback("on_approved", req)
        logger.info("Request %s approved by %s", request_id, approver)
        return req

    def reject(
        self,
        request_id: str,
        approver: str,
        comment: str = "",
    ) -> ApprovalRequest:
        """Reject a pending request."""
        req = self._get_pending(request_id)
        now = datetime.now(timezone.utc).isoformat()
        req.status = ApprovalStatus.REJECTED
        req.decided_at = now
        req.updated_at = now
        req.decision_comment = comment
        if not req.approver:
            req.approver = approver
        self.store.save_request(req)
        self._add_audit(
            request_id, AuditAction.REJECTED, approver,
            comment=comment,
        )
        self._stats["rejected"] += 1
        self._fire_callback("on_rejected", req)
        logger.info("Request %s rejected by %s", request_id, approver)
        return req

    # --- Cancel ---

    def cancel(
        self,
        request_id: str,
        actor: str,
        comment: str = "",
    ) -> ApprovalRequest:
        """Cancel a pending request."""
        req = self._get_pending(request_id)
        now = datetime.now(timezone.utc).isoformat()
        req.status = ApprovalStatus.CANCELLED
        req.updated_at = now
        req.decision_comment = comment
        self.store.save_request(req)
        self._add_audit(
            request_id, AuditAction.CANCELLED, actor,
            comment=comment,
        )
        self._stats["cancelled"] += 1
        logger.info("Request %s cancelled by %s", request_id, actor)
        return req

    # --- Delegate ---

    def delegate(
        self,
        request_id: str,
        from_approver: str,
        to_approver: str,
        comment: str = "",
    ) -> ApprovalRequest:
        """Delegate a pending request to a different approver."""
        req = self._get_pending(request_id)
        old_approver = req.approver
        req.delegated_from = old_approver or from_approver
        req.approver = to_approver
        req.updated_at = datetime.now(timezone.utc).isoformat()
        self.store.save_request(req)
        self._add_audit(
            request_id, AuditAction.DELEGATED, from_approver,
            details={"from": old_approver or from_approver, "to": to_approver},
            comment=comment,
        )
        self._stats["delegated"] += 1
        logger.info(
            "Request %s delegated from %s to %s",
            request_id, from_approver, to_approver,
        )
        return req

    # --- Escalation ---

    def escalate(
        self,
        request_id: str,
        actor: str = "system",
        comment: str = "",
    ) -> ApprovalRequest:
        """Escalate a request to the next level in the chain."""
        req = self._get_pending(request_id)
        current_level = req.escalation_level.value
        next_level = current_level + 1

        # Check if next level exists
        try:
            new_esc = EscalationLevel(next_level)
        except ValueError:
            # Already at max level, mark as expired
            return self.expire(request_id, actor, comment="Max escalation reached")

        old_approver = req.approver
        req.escalation_level = new_esc
        req.status = ApprovalStatus.ESCALATED

        # Assign new approver from chain
        new_approver = self.escalation_chain.get(next_level, "")
        if new_approver:
            req.approver = new_approver

        # Reset expiration
        timeout = req.priority.timeout_minutes
        req.expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=timeout)
        ).isoformat()

        # Back to pending (escalated is transitional)
        req.status = ApprovalStatus.PENDING
        req.updated_at = datetime.now(timezone.utc).isoformat()

        self.store.save_request(req)
        self._add_audit(
            request_id, AuditAction.ESCALATED, actor,
            details={
                "from_level": current_level,
                "to_level": next_level,
                "old_approver": old_approver,
                "new_approver": new_approver,
            },
            comment=comment or f"Escalated to L{next_level}",
        )
        self._stats["escalated"] += 1
        self._fire_callback("on_escalated", req)
        logger.info(
            "Request %s escalated from L%d to L%d",
            request_id, current_level, next_level,
        )
        return req

    def expire(
        self,
        request_id: str,
        actor: str = "system",
        comment: str = "",
    ) -> ApprovalRequest:
        """Mark a request as expired."""
        req = self._get_pending(request_id)
        now = datetime.now(timezone.utc).isoformat()
        req.status = ApprovalStatus.EXPIRED
        req.updated_at = now
        req.decision_comment = comment or "Request expired"
        self.store.save_request(req)
        self._add_audit(
            request_id, AuditAction.EXPIRED, actor,
            comment=comment or "Request expired",
        )
        self._stats["expired"] += 1
        self._fire_callback("on_expired", req)
        logger.info("Request %s expired", request_id)
        return req

    # --- Process Expired ---

    def process_expired(self, escalate: bool = True) -> List[ApprovalRequest]:
        """
        Find and process all expired pending requests.

        If escalate=True, attempts to escalate before expiring.
        Returns list of processed requests.
        """
        expired = self.store.get_pending_expired()
        processed = []
        for req in expired:
            if escalate and req.escalation_level.value < EscalationLevel.L5_DIRECTOR.value:
                result = self.escalate(req.request_id)
            else:
                result = self.expire(req.request_id)
            processed.append(result)
        return processed

    # --- Bulk Operations ---

    def bulk_approve(
        self,
        request_ids: List[str],
        approver: str,
        comment: str = "",
    ) -> Dict[str, Any]:
        """Approve multiple requests at once."""
        results: Dict[str, Any] = {"approved": [], "errors": []}
        for rid in request_ids:
            try:
                req = self.approve(rid, approver, comment)
                results["approved"].append(req.request_id)
            except (ValueError, KeyError) as e:
                results["errors"].append({"request_id": rid, "error": str(e)})
        return results

    def bulk_reject(
        self,
        request_ids: List[str],
        approver: str,
        comment: str = "",
    ) -> Dict[str, Any]:
        """Reject multiple requests at once."""
        results: Dict[str, Any] = {"rejected": [], "errors": []}
        for rid in request_ids:
            try:
                req = self.reject(rid, approver, comment)
                results["rejected"].append(req.request_id)
            except (ValueError, KeyError) as e:
                results["errors"].append({"request_id": rid, "error": str(e)})
        return results

    # --- Add Comment ---

    def add_comment(
        self,
        request_id: str,
        actor: str,
        comment: str,
    ) -> AuditEntry:
        """Add a comment to a request's audit trail."""
        # Verify request exists
        req = self.store.get_request(request_id)
        if req is None:
            raise KeyError(f"Request {request_id} not found")
        entry = self._add_audit(
            request_id, AuditAction.COMMENT_ADDED, actor,
            comment=comment,
        )
        return entry

    # --- Query ---

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        return self.store.get_request(request_id)

    def list_pending(
        self,
        approver: Optional[str] = None,
        priority: Optional[int] = None,
        limit: int = 100,
    ) -> List[ApprovalRequest]:
        return self.store.list_requests(
            status="pending", approver=approver,
            priority=priority, limit=limit,
        )

    def list_requests(
        self,
        status: Optional[str] = None,
        approver: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ApprovalRequest]:
        return self.store.list_requests(
            status=status, approver=approver,
            limit=limit, offset=offset,
        )

    def get_audit_trail(self, request_id: str) -> List[AuditEntry]:
        return self.store.get_audit_trail(request_id)

    def get_recent_activity(self, limit: int = 50) -> List[AuditEntry]:
        return self.store.get_recent_audit(limit)

    # --- Auto-Approve Rules ---

    def add_rule(self, rule: AutoApproveRule) -> AutoApproveRule:
        self.store.save_rule(rule)
        logger.info("Auto-approve rule added: %s (%s)", rule.rule_id, rule.name)
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        return self.store.delete_rule(rule_id)

    def list_rules(self, enabled_only: bool = False) -> List[AutoApproveRule]:
        return self.store.list_rules(enabled_only=enabled_only)

    def get_rule(self, rule_id: str) -> Optional[AutoApproveRule]:
        return self.store.get_rule(rule_id)

    # --- Stats ---

    def get_stats(self) -> Dict[str, Any]:
        db_stats = self.store.get_stats()
        return {
            "session": dict(self._stats),
            "database": db_stats,
        }

    def reset_stats(self) -> None:
        for key in self._stats:
            self._stats[key] = 0

    # --- Internal ---

    def _get_pending(self, request_id: str) -> ApprovalRequest:
        """Get a request and verify it's still pending."""
        req = self.store.get_request(request_id)
        if req is None:
            raise KeyError(f"Request {request_id} not found")
        if not req.is_pending:
            raise ValueError(
                f"Request {request_id} is not pending (status={req.status.value})"
            )
        return req

    def _check_auto_approve(self, req: ApprovalRequest) -> Optional[AutoApproveRule]:
        """Evaluate auto-approve rules against a request."""
        rules = self.store.list_rules(enabled_only=True)
        for rule in rules:
            if rule.matches(req):
                return rule
        return None

    def _add_audit(
        self,
        request_id: str,
        action: AuditAction,
        actor: str,
        details: Optional[Dict[str, Any]] = None,
        comment: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            request_id=request_id,
            action=action.value,
            actor=actor,
            details=details or {},
            comment=comment,
        )
        self.store.add_audit_entry(entry)
        return entry

    def _fire_callback(self, name: str, req: ApprovalRequest) -> None:
        cb = self._callbacks.get(name)
        if cb:
            try:
                cb(req)
            except Exception as e:
                logger.error("Callback %s failed: %s", name, e)


# ============================================================================
# Flask Blueprint (REST API)
# ============================================================================

def create_approval_blueprint(engine: Optional[ApprovalWorkflowEngine] = None):
    """Create Flask Blueprint for Approval Workflow API."""
    try:
        from flask import Blueprint, jsonify, request as flask_request
    except ImportError:
        logger.warning("Flask not available, blueprint not created")
        return None

    bp = Blueprint("approval_workflow", __name__, url_prefix="/api/v1/soc/approval")
    _engine = engine

    def _get_engine() -> ApprovalWorkflowEngine:
        nonlocal _engine
        if _engine is None:
            _engine = get_approval_engine()
        return _engine

    @bp.route("/submit", methods=["POST"])
    def submit_request():
        data = flask_request.get_json(silent=True) or {}
        action_type = data.get("action_type", "")
        requester = data.get("requester", "")
        if not action_type or not requester:
            return jsonify({"error": "action_type and requester required"}), 400
        priority_val = data.get("priority", 3)
        try:
            priority = ApprovalPriority(int(priority_val))
        except (ValueError, TypeError):
            priority = ApprovalPriority.P3_MEDIUM
        try:
            req = _get_engine().submit(
                action_type=action_type,
                requester=requester,
                title=data.get("title", ""),
                description=data.get("description", ""),
                action_params=data.get("action_params"),
                context=data.get("context"),
                approver=data.get("approver", ""),
                priority=priority,
                alert_id=data.get("alert_id", ""),
                case_id=data.get("case_id", ""),
                tags=data.get("tags"),
            )
            return jsonify({"request": req.to_dict()}), 201
        except Exception as e:
            logger.error("Submit error: %s", e)
            return jsonify({"error": "Submission failed"}), 500

    @bp.route("/pending", methods=["GET"])
    def list_pending():
        approver = flask_request.args.get("approver")
        priority = flask_request.args.get("priority")
        limit = int(flask_request.args.get("limit", 100))
        p = int(priority) if priority else None
        reqs = _get_engine().list_pending(approver=approver, priority=p, limit=limit)
        return jsonify({"requests": [r.to_dict() for r in reqs], "count": len(reqs)})

    @bp.route("/list", methods=["GET"])
    def list_all():
        status = flask_request.args.get("status")
        approver = flask_request.args.get("approver")
        limit = int(flask_request.args.get("limit", 100))
        offset = int(flask_request.args.get("offset", 0))
        reqs = _get_engine().list_requests(
            status=status, approver=approver, limit=limit, offset=offset,
        )
        return jsonify({"requests": [r.to_dict() for r in reqs], "count": len(reqs)})

    @bp.route("/request/<request_id>", methods=["GET"])
    def get_request(request_id):
        req = _get_engine().get_request(request_id)
        if req is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"request": req.to_dict()})

    @bp.route("/request/<request_id>", methods=["DELETE"])
    def delete_request(request_id):
        deleted = _get_engine().store.delete_request(request_id)
        if not deleted:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"deleted": True})

    @bp.route("/approve/<request_id>", methods=["POST"])
    def approve_request(request_id):
        data = flask_request.get_json(silent=True) or {}
        approver = data.get("approver", "")
        if not approver:
            return jsonify({"error": "approver required"}), 400
        try:
            req = _get_engine().approve(
                request_id, approver, comment=data.get("comment", ""),
            )
            return jsonify({"request": req.to_dict()})
        except KeyError:
            return jsonify({"error": "Not found"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

    @bp.route("/reject/<request_id>", methods=["POST"])
    def reject_request(request_id):
        data = flask_request.get_json(silent=True) or {}
        approver = data.get("approver", "")
        if not approver:
            return jsonify({"error": "approver required"}), 400
        try:
            req = _get_engine().reject(
                request_id, approver, comment=data.get("comment", ""),
            )
            return jsonify({"request": req.to_dict()})
        except KeyError:
            return jsonify({"error": "Not found"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

    @bp.route("/cancel/<request_id>", methods=["POST"])
    def cancel_request(request_id):
        data = flask_request.get_json(silent=True) or {}
        actor = data.get("actor", "")
        if not actor:
            return jsonify({"error": "actor required"}), 400
        try:
            req = _get_engine().cancel(
                request_id, actor, comment=data.get("comment", ""),
            )
            return jsonify({"request": req.to_dict()})
        except KeyError:
            return jsonify({"error": "Not found"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

    @bp.route("/delegate/<request_id>", methods=["POST"])
    def delegate_request(request_id):
        data = flask_request.get_json(silent=True) or {}
        from_approver = data.get("from_approver", "")
        to_approver = data.get("to_approver", "")
        if not from_approver or not to_approver:
            return jsonify({"error": "from_approver and to_approver required"}), 400
        try:
            req = _get_engine().delegate(
                request_id, from_approver, to_approver,
                comment=data.get("comment", ""),
            )
            return jsonify({"request": req.to_dict()})
        except KeyError:
            return jsonify({"error": "Not found"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

    @bp.route("/escalate/<request_id>", methods=["POST"])
    def escalate_request(request_id):
        data = flask_request.get_json(silent=True) or {}
        actor = data.get("actor", "system")
        try:
            req = _get_engine().escalate(
                request_id, actor, comment=data.get("comment", ""),
            )
            return jsonify({"request": req.to_dict()})
        except KeyError:
            return jsonify({"error": "Not found"}), 404
        except ValueError as e:
            return jsonify({"error": str(e)}), 409

    @bp.route("/bulk/approve", methods=["POST"])
    def bulk_approve():
        data = flask_request.get_json(silent=True) or {}
        ids = data.get("request_ids", [])
        approver = data.get("approver", "")
        if not ids or not approver:
            return jsonify({"error": "request_ids and approver required"}), 400
        result = _get_engine().bulk_approve(ids, approver, data.get("comment", ""))
        return jsonify(result)

    @bp.route("/bulk/reject", methods=["POST"])
    def bulk_reject():
        data = flask_request.get_json(silent=True) or {}
        ids = data.get("request_ids", [])
        approver = data.get("approver", "")
        if not ids or not approver:
            return jsonify({"error": "request_ids and approver required"}), 400
        result = _get_engine().bulk_reject(ids, approver, data.get("comment", ""))
        return jsonify(result)

    @bp.route("/comment/<request_id>", methods=["POST"])
    def add_comment(request_id):
        data = flask_request.get_json(silent=True) or {}
        actor = data.get("actor", "")
        comment_text = data.get("comment", "")
        if not actor or not comment_text:
            return jsonify({"error": "actor and comment required"}), 400
        try:
            entry = _get_engine().add_comment(request_id, actor, comment_text)
            return jsonify({"entry": entry.to_dict()})
        except KeyError:
            return jsonify({"error": "Not found"}), 404

    @bp.route("/audit/<request_id>", methods=["GET"])
    def get_audit(request_id):
        entries = _get_engine().get_audit_trail(request_id)
        return jsonify({"entries": [e.to_dict() for e in entries], "count": len(entries)})

    @bp.route("/activity", methods=["GET"])
    def recent_activity():
        limit = int(flask_request.args.get("limit", 50))
        entries = _get_engine().get_recent_activity(limit)
        return jsonify({"entries": [e.to_dict() for e in entries], "count": len(entries)})

    @bp.route("/rules", methods=["GET"])
    def list_rules():
        enabled_only = flask_request.args.get("enabled_only", "").lower() == "true"
        rules = _get_engine().list_rules(enabled_only=enabled_only)
        return jsonify({"rules": [r.to_dict() for r in rules], "count": len(rules)})

    @bp.route("/rules", methods=["POST"])
    def add_rule():
        data = flask_request.get_json(silent=True) or {}
        name = data.get("name", "")
        action_type = data.get("action_type", "")
        if not name:
            return jsonify({"error": "name required"}), 400
        rule = AutoApproveRule(
            name=name,
            description=data.get("description", ""),
            action_type=action_type,
            conditions=data.get("conditions") or {},
            enabled=data.get("enabled", True),
            max_priority=data.get("max_priority", 4),
            created_by=data.get("created_by", ""),
        )
        _get_engine().add_rule(rule)
        return jsonify({"rule": rule.to_dict()}), 201

    @bp.route("/rules/<rule_id>", methods=["GET"])
    def get_rule(rule_id):
        rule = _get_engine().get_rule(rule_id)
        if rule is None:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"rule": rule.to_dict()})

    @bp.route("/rules/<rule_id>", methods=["DELETE"])
    def delete_rule(rule_id):
        deleted = _get_engine().remove_rule(rule_id)
        if not deleted:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"deleted": True})

    @bp.route("/process-expired", methods=["POST"])
    def process_expired():
        data = flask_request.get_json(silent=True) or {}
        escalate = data.get("escalate", True)
        results = _get_engine().process_expired(escalate=escalate)
        return jsonify({
            "processed": [r.to_dict() for r in results],
            "count": len(results),
        })

    @bp.route("/stats", methods=["GET"])
    def get_stats():
        return jsonify(_get_engine().get_stats())

    return bp


# ============================================================================
# Global Singleton
# ============================================================================

_global_engine: Optional[ApprovalWorkflowEngine] = None
_engine_lock = threading.Lock()


def get_approval_engine(**kwargs) -> ApprovalWorkflowEngine:
    """Get or create the global ApprovalWorkflowEngine instance."""
    global _global_engine
    if _global_engine is None:
        with _engine_lock:
            if _global_engine is None:
                _global_engine = ApprovalWorkflowEngine(**kwargs)
    return _global_engine


def reset_global_engine() -> None:
    """Reset the global engine (for testing)."""
    global _global_engine
    _global_engine = None
