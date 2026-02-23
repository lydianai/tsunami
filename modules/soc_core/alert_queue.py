#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Alert Queue & Prioritization Engine
    Production-Grade Alert Management System
================================================================================

    Features:
    - Priority queue with Redis sorted set backend + in-memory fallback
    - CVSS + context-based severity scoring
    - Fuzzy deduplication engine (similar alert merging)
    - SLA timer with escalation (P1:15m, P2:1h, P3:4h, P4:24h)
    - Alert lifecycle: NEW → TRIAGED → ASSIGNED → INVESTIGATING → RESOLVED/FALSE_POSITIVE
    - MITRE ATT&CK technique tagging
    - Thread-safe operations
    - Persistent SQLite storage for durability

================================================================================
"""

import hashlib
import json
import logging
import math
import os
import re
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("soc.alert_queue")


# ============================================================================
# Enums
# ============================================================================

class AlertSeverity(Enum):
    """Alert severity levels (P1-P5)."""
    CRITICAL = 1    # P1 - Immediate response
    HIGH = 2        # P2 - Urgent
    MEDIUM = 3      # P3 - Standard
    LOW = 4         # P4 - Low priority
    INFO = 5        # P5 - Informational

    @property
    def sla_minutes(self) -> int:
        return {1: 15, 2: 60, 3: 240, 4: 1440, 5: 0}[self.value]

    @property
    def label(self) -> str:
        return {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW", 5: "INFO"}[self.value]


class AlertStatus(Enum):
    """Alert lifecycle status."""
    NEW = "new"
    TRIAGED = "triaged"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    MERGED = "merged"
    EXPIRED = "expired"


class AlertSource(Enum):
    """Alert source types."""
    WAZUH = "wazuh"
    SURICATA = "suricata"
    SYSLOG = "syslog"
    SIGMA = "sigma"
    CUSTOM = "custom"
    INTERNAL = "internal"
    THREAT_INTEL = "threat_intel"
    ML_ANOMALY = "ml_anomaly"


# ============================================================================
# Alert Model
# ============================================================================

@dataclass
class Alert:
    """A security alert in the SOC queue."""
    alert_id: str
    title: str
    description: str
    severity: AlertSeverity
    source: AlertSource
    status: AlertStatus = AlertStatus.NEW

    # Classification
    category: str = ""           # e.g., "intrusion", "malware", "policy_violation"
    mitre_tactics: List[str] = field(default_factory=list)    # TA0001, TA0002...
    mitre_techniques: List[str] = field(default_factory=list)  # T1566, T1059...
    tags: List[str] = field(default_factory=list)

    # Source context
    source_id: str = ""          # Original alert ID from source
    source_rule: str = ""        # Rule that generated the alert
    source_raw: Dict[str, Any] = field(default_factory=dict)

    # Affected assets
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    hostname: str = ""
    username: str = ""
    asset_id: str = ""

    # Scoring
    cvss_score: float = 0.0
    confidence: float = 0.0      # 0.0-1.0
    priority_score: float = 0.0  # Calculated composite score

    # SLA
    sla_deadline: Optional[datetime] = None
    sla_breached: bool = False

    # Assignment
    assigned_to: str = ""
    assigned_at: Optional[datetime] = None

    # Related
    incident_id: str = ""
    parent_alert_id: str = ""    # If merged into another
    child_alert_ids: List[str] = field(default_factory=list)
    enrichment_data: Dict[str, Any] = field(default_factory=dict)

    # IOCs
    iocs: List[Dict[str, str]] = field(default_factory=list)  # [{"type":"ip","value":"1.2.3.4"}]

    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    triaged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

    # Dedup
    dedup_hash: str = ""
    occurrence_count: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.label,
            'severity_value': self.severity.value,
            'source': self.source.value,
            'status': self.status.value,
            'category': self.category,
            'mitre_tactics': self.mitre_tactics,
            'mitre_techniques': self.mitre_techniques,
            'tags': self.tags,
            'source_id': self.source_id,
            'source_rule': self.source_rule,
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'src_port': self.src_port,
            'dst_port': self.dst_port,
            'hostname': self.hostname,
            'username': self.username,
            'asset_id': self.asset_id,
            'cvss_score': self.cvss_score,
            'confidence': self.confidence,
            'priority_score': self.priority_score,
            'sla_deadline': self.sla_deadline.isoformat() if self.sla_deadline else None,
            'sla_breached': self.sla_breached,
            'assigned_to': self.assigned_to,
            'assigned_at': self.assigned_at.isoformat() if self.assigned_at else None,
            'incident_id': self.incident_id,
            'parent_alert_id': self.parent_alert_id,
            'child_alert_ids': self.child_alert_ids,
            'enrichment_data': self.enrichment_data,
            'iocs': self.iocs,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'triaged_at': self.triaged_at.isoformat() if self.triaged_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'dedup_hash': self.dedup_hash,
            'occurrence_count': self.occurrence_count,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'Alert':
        severity = d.get('severity', 'MEDIUM')
        if isinstance(severity, str):
            severity = AlertSeverity[severity] if severity in AlertSeverity.__members__ else AlertSeverity.MEDIUM
        elif isinstance(severity, int):
            severity = AlertSeverity(severity)

        source = d.get('source', 'custom')
        if isinstance(source, str):
            try:
                source = AlertSource(source)
            except ValueError:
                source = AlertSource.CUSTOM

        status = d.get('status', 'new')
        if isinstance(status, str):
            try:
                status = AlertStatus(status)
            except ValueError:
                status = AlertStatus.NEW

        def _parse_dt(val):
            if val is None:
                return None
            if isinstance(val, datetime):
                return val
            try:
                return datetime.fromisoformat(val)
            except (ValueError, TypeError):
                return None

        return cls(
            alert_id=d.get('alert_id', f"alert_{uuid.uuid4().hex[:16]}"),
            title=d.get('title', ''),
            description=d.get('description', ''),
            severity=severity,
            source=source,
            status=status,
            category=d.get('category', ''),
            mitre_tactics=d.get('mitre_tactics', []),
            mitre_techniques=d.get('mitre_techniques', []),
            tags=d.get('tags', []),
            source_id=d.get('source_id', ''),
            source_rule=d.get('source_rule', ''),
            source_raw=d.get('source_raw', {}),
            src_ip=d.get('src_ip', ''),
            dst_ip=d.get('dst_ip', ''),
            src_port=int(d.get('src_port', 0)),
            dst_port=int(d.get('dst_port', 0)),
            hostname=d.get('hostname', ''),
            username=d.get('username', ''),
            asset_id=d.get('asset_id', ''),
            cvss_score=float(d.get('cvss_score', 0.0)),
            confidence=float(d.get('confidence', 0.0)),
            priority_score=float(d.get('priority_score', 0.0)),
            sla_deadline=_parse_dt(d.get('sla_deadline')),
            sla_breached=bool(d.get('sla_breached', False)),
            assigned_to=d.get('assigned_to', ''),
            assigned_at=_parse_dt(d.get('assigned_at')),
            incident_id=d.get('incident_id', ''),
            parent_alert_id=d.get('parent_alert_id', ''),
            child_alert_ids=d.get('child_alert_ids', []),
            enrichment_data=d.get('enrichment_data', {}),
            iocs=d.get('iocs', []),
            created_at=_parse_dt(d.get('created_at')) or datetime.utcnow(),
            updated_at=_parse_dt(d.get('updated_at')) or datetime.utcnow(),
            triaged_at=_parse_dt(d.get('triaged_at')),
            resolved_at=_parse_dt(d.get('resolved_at')),
            dedup_hash=d.get('dedup_hash', ''),
            occurrence_count=int(d.get('occurrence_count', 1)),
        )


# ============================================================================
# Severity Scoring Engine
# ============================================================================

class SeverityScorer:
    """Calculate composite priority score from multiple factors."""

    # Context weights
    WEIGHTS = {
        'cvss': 0.30,
        'confidence': 0.15,
        'asset_criticality': 0.20,
        'threat_intel_match': 0.15,
        'recurrence': 0.10,
        'time_decay': 0.10,
    }

    # Critical asset patterns
    CRITICAL_ASSETS = {
        'dc', 'ad', 'domain', 'dns', 'firewall', 'fw', 'vpn',
        'db', 'database', 'sql', 'oracle', 'prod', 'production',
        'ceo', 'cfo', 'exec', 'admin', 'root',
    }

    @classmethod
    def calculate_priority(cls, alert: Alert,
                           threat_intel_match: bool = False,
                           asset_criticality: float = 0.5) -> float:
        """
        Calculate composite priority score (0-100, higher = more urgent).
        """
        scores = {}

        # CVSS component (0-10 → 0-100)
        scores['cvss'] = (alert.cvss_score / 10.0) * 100

        # Confidence (0-1 → 0-100)
        scores['confidence'] = alert.confidence * 100

        # Asset criticality
        asset_score = asset_criticality * 100
        hostname_lower = alert.hostname.lower()
        if any(pattern in hostname_lower for pattern in cls.CRITICAL_ASSETS):
            asset_score = max(asset_score, 90)
        scores['asset_criticality'] = asset_score

        # Threat intel match
        scores['threat_intel_match'] = 100 if threat_intel_match else 0

        # Recurrence (log scale, capped)
        recurrence_score = min(100, math.log2(max(1, alert.occurrence_count)) * 20)
        scores['recurrence'] = recurrence_score

        # Time decay (newer = higher priority)
        age_hours = (datetime.utcnow() - alert.created_at).total_seconds() / 3600
        time_score = max(0, 100 - (age_hours * 2))  # Decays ~50pts per day
        scores['time_decay'] = time_score

        # Weighted sum
        total = sum(scores[k] * cls.WEIGHTS[k] for k in cls.WEIGHTS)

        # Severity floor: ensure critical alerts never score below 70
        severity_floors = {
            AlertSeverity.CRITICAL: 70,
            AlertSeverity.HIGH: 50,
            AlertSeverity.MEDIUM: 30,
            AlertSeverity.LOW: 10,
            AlertSeverity.INFO: 0,
        }
        floor = severity_floors.get(alert.severity, 0)
        total = max(total, floor)

        return round(min(100, total), 2)

    @classmethod
    def auto_severity(cls, cvss_score: float, confidence: float = 0.5,
                      threat_intel_match: bool = False) -> AlertSeverity:
        """Auto-assign severity based on CVSS + context."""
        if cvss_score >= 9.0 or (cvss_score >= 7.0 and threat_intel_match):
            return AlertSeverity.CRITICAL
        elif cvss_score >= 7.0 or (cvss_score >= 5.0 and threat_intel_match):
            return AlertSeverity.HIGH
        elif cvss_score >= 4.0:
            return AlertSeverity.MEDIUM
        elif cvss_score >= 1.0:
            return AlertSeverity.LOW
        else:
            return AlertSeverity.INFO


# ============================================================================
# Deduplication Engine
# ============================================================================

class DedupEngine:
    """Detect and merge similar/duplicate alerts."""

    # Fields used for dedup fingerprint
    DEDUP_FIELDS = ['source_rule', 'src_ip', 'dst_ip', 'dst_port', 'category']

    # Time window for dedup (same alert within this window = duplicate)
    DEDUP_WINDOW_MINUTES = 30

    @classmethod
    def compute_hash(cls, alert: Alert) -> str:
        """Compute dedup fingerprint hash."""
        parts = []
        for f in cls.DEDUP_FIELDS:
            val = getattr(alert, f, '')
            if val:
                parts.append(f"{f}={val}")

        # Also include title normalization
        normalized_title = re.sub(r'\d+', 'N', alert.title.lower().strip())
        parts.append(f"title={normalized_title}")

        fingerprint = "|".join(sorted(parts))
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]

    @classmethod
    def is_duplicate(cls, new_alert: Alert, existing_alert: Alert) -> bool:
        """Check if two alerts are duplicates."""
        if new_alert.dedup_hash != existing_alert.dedup_hash:
            return False

        # Must be within time window
        time_diff = abs((new_alert.created_at - existing_alert.created_at).total_seconds())
        if time_diff > cls.DEDUP_WINDOW_MINUTES * 60:
            return False

        # Must be from same source type
        if new_alert.source != existing_alert.source:
            return False

        return True

    @classmethod
    def similarity_score(cls, a: Alert, b: Alert) -> float:
        """Calculate similarity between two alerts (0-1)."""
        score = 0.0
        checks = 0

        # Same source rule
        if a.source_rule and b.source_rule:
            checks += 1
            if a.source_rule == b.source_rule:
                score += 1.0

        # Same source/dest IPs
        if a.src_ip and b.src_ip:
            checks += 1
            if a.src_ip == b.src_ip:
                score += 1.0
        if a.dst_ip and b.dst_ip:
            checks += 1
            if a.dst_ip == b.dst_ip:
                score += 1.0

        # Same category
        if a.category and b.category:
            checks += 1
            if a.category == b.category:
                score += 1.0

        # Same MITRE techniques
        if a.mitre_techniques and b.mitre_techniques:
            checks += 1
            common = set(a.mitre_techniques) & set(b.mitre_techniques)
            if common:
                score += len(common) / max(len(a.mitre_techniques), len(b.mitre_techniques))

        return score / max(checks, 1)


# ============================================================================
# Alert Queue (SQLite backend + in-memory index)
# ============================================================================

class AlertQueue:
    """
    Production alert queue with SQLite persistence,
    priority scoring, dedup, and SLA tracking.
    """

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path.home() / '.dalga'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'soc_alerts.db')

        self.db_path = db_path
        self._lock = threading.Lock()
        self._scorer = SeverityScorer()
        self._dedup = DedupEngine()

        # Callbacks
        self._on_new_alert: List[Callable[[Alert], None]] = []
        self._on_sla_breach: List[Callable[[Alert], None]] = []
        self._on_status_change: List[Callable[[Alert, AlertStatus, AlertStatus], None]] = []

        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id TEXT PRIMARY KEY,
                        data TEXT NOT NULL,
                        priority_score REAL DEFAULT 0,
                        severity INTEGER DEFAULT 3,
                        status TEXT DEFAULT 'new',
                        dedup_hash TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        sla_deadline TEXT,
                        sla_breached INTEGER DEFAULT 0,
                        assigned_to TEXT DEFAULT '',
                        incident_id TEXT DEFAULT '',
                        occurrence_count INTEGER DEFAULT 1
                    );

                    CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
                    CREATE INDEX IF NOT EXISTS idx_alert_priority ON alerts(priority_score DESC);
                    CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);
                    CREATE INDEX IF NOT EXISTS idx_alert_dedup ON alerts(dedup_hash);
                    CREATE INDEX IF NOT EXISTS idx_alert_created ON alerts(created_at);
                    CREATE INDEX IF NOT EXISTS idx_alert_sla ON alerts(sla_deadline);
                    CREATE INDEX IF NOT EXISTS idx_alert_assigned ON alerts(assigned_to);
                """)
                conn.commit()
            finally:
                conn.close()

    # --- Event Callbacks ---

    def on_new_alert(self, callback: Callable[[Alert], None]):
        self._on_new_alert.append(callback)

    def on_sla_breach(self, callback: Callable[[Alert], None]):
        self._on_sla_breach.append(callback)

    def on_status_change(self, callback: Callable[[Alert, AlertStatus, AlertStatus], None]):
        self._on_status_change.append(callback)

    def _fire_callbacks(self, callbacks: list, *args):
        for cb in callbacks:
            try:
                cb(*args)
            except Exception as e:
                logger.error(f"[ALERT_QUEUE] Callback error: {e}")

    # --- Core Operations ---

    def ingest(self, alert: Alert, auto_score: bool = True,
               auto_dedup: bool = True) -> Tuple[Alert, bool]:
        """
        Ingest an alert into the queue.
        Returns (alert, is_new) - is_new=False if merged with existing.
        """
        # Compute dedup hash
        if not alert.dedup_hash:
            alert.dedup_hash = self._dedup.compute_hash(alert)

        # Check for duplicates
        if auto_dedup:
            existing = self._find_duplicate(alert)
            if existing:
                # Merge: increment count, update timestamps
                existing.occurrence_count += 1
                existing.updated_at = datetime.utcnow()

                # Upgrade severity if new occurrence has higher severity
                if alert.severity.value < existing.severity.value:
                    existing.severity = alert.severity

                # Re-score
                if auto_score:
                    existing.priority_score = self._scorer.calculate_priority(existing)

                self._save_alert(existing)
                logger.info(
                    f"[ALERT_QUEUE] Merged duplicate: {existing.alert_id} "
                    f"(count={existing.occurrence_count})"
                )
                return existing, False

        # New alert
        if not alert.alert_id:
            alert.alert_id = f"alert_{uuid.uuid4().hex[:16]}"

        # Auto-score
        if auto_score:
            alert.priority_score = self._scorer.calculate_priority(alert)

        # Set SLA deadline
        if alert.sla_deadline is None and alert.severity.sla_minutes > 0:
            alert.sla_deadline = alert.created_at + timedelta(minutes=alert.severity.sla_minutes)

        self._save_alert(alert)

        logger.info(
            f"[ALERT_QUEUE] New alert: {alert.alert_id} | {alert.severity.label} | "
            f"score={alert.priority_score} | {alert.title[:60]}"
        )

        # Fire callbacks
        self._fire_callbacks(self._on_new_alert, alert)

        return alert, True

    def _find_duplicate(self, alert: Alert) -> Optional[Alert]:
        """Find existing duplicate alert."""
        conn = self._get_conn()
        try:
            # Look for alerts with same dedup_hash, in active status, within time window
            cutoff = (datetime.utcnow() - timedelta(minutes=DedupEngine.DEDUP_WINDOW_MINUTES)).isoformat()
            rows = conn.execute(
                """SELECT data FROM alerts
                   WHERE dedup_hash = ? AND status IN ('new', 'triaged', 'assigned', 'investigating')
                   AND created_at >= ?
                   ORDER BY created_at DESC LIMIT 1""",
                (alert.dedup_hash, cutoff)
            ).fetchall()

            for row in rows:
                existing = Alert.from_dict(json.loads(row['data']))
                if self._dedup.is_duplicate(alert, existing):
                    return existing
            return None
        finally:
            conn.close()

    def _save_alert(self, alert: Alert):
        """Save or update alert in database."""
        alert.updated_at = datetime.utcnow()
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO alerts
                       (alert_id, data, priority_score, severity, status, dedup_hash,
                        created_at, updated_at, sla_deadline, sla_breached,
                        assigned_to, incident_id, occurrence_count)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (alert.alert_id, json.dumps(alert.to_dict()),
                     alert.priority_score, alert.severity.value, alert.status.value,
                     alert.dedup_hash, alert.created_at.isoformat(),
                     alert.updated_at.isoformat(),
                     alert.sla_deadline.isoformat() if alert.sla_deadline else None,
                     1 if alert.sla_breached else 0,
                     alert.assigned_to, alert.incident_id, alert.occurrence_count)
                )
                conn.commit()
            finally:
                conn.close()

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get a single alert by ID."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT data FROM alerts WHERE alert_id = ?", (alert_id,)
            ).fetchone()
            return Alert.from_dict(json.loads(row['data'])) if row else None
        finally:
            conn.close()

    def get_queue(self, status: Optional[AlertStatus] = None,
                  severity: Optional[AlertSeverity] = None,
                  assigned_to: Optional[str] = None,
                  limit: int = 100, offset: int = 0) -> List[Alert]:
        """Get alerts from queue, ordered by priority score descending."""
        conn = self._get_conn()
        try:
            query = "SELECT data FROM alerts WHERE 1=1"
            params: list = []

            if status:
                query += " AND status = ?"
                params.append(status.value)
            else:
                # Exclude resolved/false_positive/merged by default
                query += " AND status NOT IN ('resolved', 'false_positive', 'merged', 'expired')"

            if severity:
                query += " AND severity = ?"
                params.append(severity.value)

            if assigned_to:
                query += " AND assigned_to = ?"
                params.append(assigned_to)

            query += " ORDER BY priority_score DESC, created_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [Alert.from_dict(json.loads(r['data'])) for r in rows]
        finally:
            conn.close()

    def get_active_count(self) -> Dict[str, int]:
        """Get count of active alerts by severity."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt
                   FROM alerts
                   WHERE status NOT IN ('resolved', 'false_positive', 'merged', 'expired')
                   GROUP BY severity"""
            ).fetchall()

            counts = {s.label: 0 for s in AlertSeverity}
            for row in rows:
                try:
                    sev = AlertSeverity(row['severity'])
                    counts[sev.label] = row['cnt']
                except ValueError:
                    pass

            counts['total'] = sum(v for k, v in counts.items() if k != 'total')
            return counts
        finally:
            conn.close()

    # --- Status Transitions ---

    def triage(self, alert_id: str, severity: Optional[AlertSeverity] = None,
               analyst: str = "") -> Optional[Alert]:
        """Triage an alert: set status, optionally override severity."""
        alert = self.get_alert(alert_id)
        if not alert:
            return None

        old_status = alert.status
        alert.status = AlertStatus.TRIAGED
        alert.triaged_at = datetime.utcnow()
        if severity:
            alert.severity = severity
            if severity.sla_minutes > 0:
                alert.sla_deadline = alert.created_at + timedelta(minutes=severity.sla_minutes)

        alert.priority_score = self._scorer.calculate_priority(alert)
        self._save_alert(alert)

        self._fire_callbacks(self._on_status_change, alert, old_status, alert.status)
        logger.info(f"[ALERT_QUEUE] Triaged: {alert_id} → {alert.severity.label}")
        return alert

    def assign(self, alert_id: str, analyst: str) -> Optional[Alert]:
        """Assign alert to an analyst."""
        alert = self.get_alert(alert_id)
        if not alert:
            return None

        old_status = alert.status
        alert.status = AlertStatus.ASSIGNED
        alert.assigned_to = analyst
        alert.assigned_at = datetime.utcnow()
        self._save_alert(alert)

        self._fire_callbacks(self._on_status_change, alert, old_status, alert.status)
        logger.info(f"[ALERT_QUEUE] Assigned: {alert_id} → {analyst}")
        return alert

    def investigate(self, alert_id: str) -> Optional[Alert]:
        """Mark alert as under investigation."""
        alert = self.get_alert(alert_id)
        if not alert:
            return None

        old_status = alert.status
        alert.status = AlertStatus.INVESTIGATING
        self._save_alert(alert)

        self._fire_callbacks(self._on_status_change, alert, old_status, alert.status)
        return alert

    def resolve(self, alert_id: str, resolution: str = "",
                analyst: str = "") -> Optional[Alert]:
        """Resolve an alert."""
        alert = self.get_alert(alert_id)
        if not alert:
            return None

        old_status = alert.status
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.utcnow()
        if resolution:
            alert.enrichment_data['resolution'] = resolution
        self._save_alert(alert)

        self._fire_callbacks(self._on_status_change, alert, old_status, alert.status)
        logger.info(f"[ALERT_QUEUE] Resolved: {alert_id}")
        return alert

    def mark_false_positive(self, alert_id: str, reason: str = "",
                            analyst: str = "") -> Optional[Alert]:
        """Mark alert as false positive."""
        alert = self.get_alert(alert_id)
        if not alert:
            return None

        old_status = alert.status
        alert.status = AlertStatus.FALSE_POSITIVE
        alert.resolved_at = datetime.utcnow()
        alert.enrichment_data['fp_reason'] = reason
        self._save_alert(alert)

        self._fire_callbacks(self._on_status_change, alert, old_status, alert.status)
        logger.info(f"[ALERT_QUEUE] False Positive: {alert_id}")
        return alert

    # --- SLA Management ---

    def check_sla_breaches(self) -> List[Alert]:
        """Check for SLA breaches and fire callbacks. Called periodically."""
        conn = self._get_conn()
        breached = []
        try:
            now = datetime.utcnow().isoformat()
            rows = conn.execute(
                """SELECT data FROM alerts
                   WHERE sla_breached = 0 AND sla_deadline IS NOT NULL
                   AND sla_deadline < ?
                   AND status NOT IN ('resolved', 'false_positive', 'merged', 'expired')""",
                (now,)
            ).fetchall()

            for row in rows:
                alert = Alert.from_dict(json.loads(row['data']))
                alert.sla_breached = True
                self._save_alert(alert)
                breached.append(alert)
                self._fire_callbacks(self._on_sla_breach, alert)
                logger.warning(f"[SLA] BREACH: {alert.alert_id} ({alert.severity.label}) - {alert.title[:50]}")

        finally:
            conn.close()

        return breached

    # --- Statistics ---

    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        conn = self._get_conn()
        try:
            # Active counts
            active = self.get_active_count()

            # Resolution stats (last 24h)
            yesterday = (datetime.utcnow() - timedelta(hours=24)).isoformat()

            resolved_24h = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'resolved' AND updated_at >= ?",
                (yesterday,)
            ).fetchone()[0]

            fp_24h = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE status = 'false_positive' AND updated_at >= ?",
                (yesterday,)
            ).fetchone()[0]

            # SLA breach count
            sla_breached = conn.execute(
                """SELECT COUNT(*) FROM alerts
                   WHERE sla_breached = 1
                   AND status NOT IN ('resolved', 'false_positive', 'merged', 'expired')"""
            ).fetchone()[0]

            # MTTD (Mean Time To Detect → Triage)
            mttd_rows = conn.execute(
                """SELECT data FROM alerts
                   WHERE status != 'new' AND updated_at >= ?
                   LIMIT 100""",
                (yesterday,)
            ).fetchall()

            mttd_values = []
            mttr_values = []
            for row in mttd_rows:
                d = json.loads(row['data'])
                created = d.get('created_at')
                triaged = d.get('triaged_at')
                resolved = d.get('resolved_at')
                if created and triaged:
                    try:
                        dt_created = datetime.fromisoformat(created)
                        dt_triaged = datetime.fromisoformat(triaged)
                        mttd_values.append((dt_triaged - dt_created).total_seconds())
                    except (ValueError, TypeError):
                        pass
                if created and resolved:
                    try:
                        dt_created = datetime.fromisoformat(created)
                        dt_resolved = datetime.fromisoformat(resolved)
                        mttr_values.append((dt_resolved - dt_created).total_seconds())
                    except (ValueError, TypeError):
                        pass

            mttd_avg = sum(mttd_values) / len(mttd_values) if mttd_values else 0
            mttr_avg = sum(mttr_values) / len(mttr_values) if mttr_values else 0

            return {
                'active_alerts': active,
                'resolved_24h': resolved_24h,
                'false_positives_24h': fp_24h,
                'sla_breached_active': sla_breached,
                'mttd_seconds': round(mttd_avg, 1),
                'mttd_human': self._human_time(mttd_avg),
                'mttr_seconds': round(mttr_avg, 1),
                'mttr_human': self._human_time(mttr_avg),
            }
        finally:
            conn.close()

    @staticmethod
    def _human_time(seconds: float) -> str:
        if seconds <= 0:
            return "N/A"
        if seconds < 60:
            return f"{int(seconds)}s"
        if seconds < 3600:
            return f"{int(seconds/60)}m"
        return f"{seconds/3600:.1f}h"


# ============================================================================
# Global Instance
# ============================================================================

_alert_queue: Optional[AlertQueue] = None
_aq_lock = threading.Lock()


def get_alert_queue() -> AlertQueue:
    global _alert_queue
    if _alert_queue is None:
        with _aq_lock:
            if _alert_queue is None:
                _alert_queue = AlertQueue()
    return _alert_queue


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_alert_queue_blueprint(queue=None):
    """Create Flask Blueprint for Alert Queue API."""
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        return None

    if queue is None:
        queue = get_alert_queue()

    bp = Blueprint('soc_alert_queue', __name__, url_prefix='/api/v1/soc/alerts')

    @bp.route('/queue', methods=['GET'])
    def get_queue_api():
        """Alarm kuyrugundan liste getir."""
        try:
            status_param = request.args.get('status')
            severity_param = request.args.get('severity')
            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)

            # "open" = aktif alarmlar (resolved/merged hariç) → status=None
            if status_param and status_param.lower() == 'open':
                _status = None
            else:
                _status = AlertStatus(status_param) if status_param else None
            _severity = AlertSeverity[severity_param.upper()] if severity_param else None

            alerts = queue.get_queue(
                status=_status, severity=_severity,
                limit=min(limit, 200), offset=offset
            )
            return jsonify({
                'success': True,
                'alerts': [a.to_dict() for a in alerts],
                'count': len(alerts)
            })
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400

    @bp.route('/stats', methods=['GET'])
    def get_stats_api():
        """Alarm kuyrugu istatistikleri."""
        return jsonify({'success': True, 'data': queue.get_stats()})

    @bp.route('/counts', methods=['GET'])
    def get_counts_api():
        """Ciddiyet bazinda aktif alarm sayilari."""
        return jsonify({'success': True, 'data': queue.get_active_count()})

    @bp.route('/<alert_id>', methods=['GET'])
    def get_single_alert(alert_id):
        """Tekil alarm detayi."""
        alert = queue.get_alert(alert_id)
        if not alert:
            return jsonify({'success': False, 'error': 'Alarm bulunamadi'}), 404
        return jsonify({'success': True, 'data': alert.to_dict()})

    @bp.route('/<alert_id>/triage', methods=['POST'])
    def triage_alert(alert_id):
        """Alarm triage islemleri."""
        data = request.get_json(force=True)
        alert = queue.triage(alert_id, analyst=data.get('analyst', ''))
        if not alert:
            return jsonify({'success': False, 'error': 'Alarm bulunamadi'}), 404
        return jsonify({'success': True, 'data': alert.to_dict()})

    @bp.route('/<alert_id>/assign', methods=['POST'])
    def assign_alert(alert_id):
        """Alarm analist atama."""
        data = request.get_json(force=True)
        alert = queue.assign(alert_id, analyst=data.get('analyst', ''))
        if not alert:
            return jsonify({'success': False, 'error': 'Alarm bulunamadi'}), 404
        return jsonify({'success': True, 'data': alert.to_dict()})

    @bp.route('/<alert_id>/resolve', methods=['POST'])
    def resolve_alert(alert_id):
        """Alarm cozumleme."""
        data = request.get_json(force=True)
        alert = queue.resolve(alert_id, resolution=data.get('resolution', ''))
        if not alert:
            return jsonify({'success': False, 'error': 'Alarm bulunamadi'}), 404
        return jsonify({'success': True, 'data': alert.to_dict()})

    @bp.route('/sla-check', methods=['POST'])
    def check_sla():
        """SLA ihlali kontrolu."""
        breached = queue.check_sla_breaches()
        return jsonify({
            'success': True,
            'breached_count': len(breached),
            'breached': [a.to_dict() for a in breached]
        })

    return bp


__all__ = [
    'AlertSeverity', 'AlertStatus', 'AlertSource',
    'Alert', 'SeverityScorer', 'DedupEngine', 'AlertQueue',
    'get_alert_queue', 'create_alert_queue_blueprint',
]
