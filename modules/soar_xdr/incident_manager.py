#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOAR Incident Manager v5.0
    Incident Lifecycle Management System
================================================================================

    Features:
    - Create/update/close incidents
    - Severity classification
    - Auto-escalation rules
    - SLA tracking
    - Timeline construction
    - Evidence collection
    - Incident correlation

================================================================================
"""

import json
import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class IncidentStatus(Enum):
    """Incident status values."""
    NEW = "new"
    TRIAGING = "triaging"
    INVESTIGATING = "investigating"
    CONTAINING = "containing"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    CLOSED = "closed"
    REOPENED = "reopened"


class IncidentSeverity(Enum):
    """Incident severity levels."""
    CRITICAL = "critical"  # P1 - Business critical, immediate response
    HIGH = "high"          # P2 - Significant impact, urgent response
    MEDIUM = "medium"      # P3 - Moderate impact, standard response
    LOW = "low"            # P4 - Minor impact, scheduled response
    INFORMATIONAL = "informational"  # P5 - No impact, awareness only


@dataclass
class TimelineEvent:
    """A single event in the incident timeline."""
    id: str
    timestamp: datetime
    event_type: str
    description: str
    actor: str  # User or system that performed the action
    data: Dict[str, Any] = field(default_factory=dict)
    source: str = "manual"  # manual, automated, system

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type,
            'description': self.description,
            'actor': self.actor,
            'data': self.data,
            'source': self.source
        }


@dataclass
class Evidence:
    """Evidence associated with an incident."""
    id: str
    incident_id: str
    evidence_type: str  # file, log, screenshot, memory_dump, network_capture
    name: str
    description: str
    file_path: Optional[str]
    hash_md5: Optional[str]
    hash_sha256: Optional[str]
    collected_at: datetime
    collected_by: str
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'incident_id': self.incident_id,
            'evidence_type': self.evidence_type,
            'name': self.name,
            'description': self.description,
            'file_path': self.file_path,
            'hash_md5': self.hash_md5,
            'hash_sha256': self.hash_sha256,
            'collected_at': self.collected_at.isoformat(),
            'collected_by': self.collected_by,
            'chain_of_custody': self.chain_of_custody,
            'tags': self.tags,
            'metadata': self.metadata
        }


@dataclass
class IncidentTimeline:
    """Complete timeline for an incident."""
    incident_id: str
    events: List[TimelineEvent] = field(default_factory=list)

    def add_event(
        self,
        event_type: str,
        description: str,
        actor: str,
        data: Optional[Dict[str, Any]] = None,
        source: str = "manual"
    ) -> TimelineEvent:
        """Add an event to the timeline."""
        event = TimelineEvent(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            event_type=event_type,
            description=description,
            actor=actor,
            data=data or {},
            source=source
        )
        self.events.append(event)
        return event

    def get_events(
        self,
        event_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[TimelineEvent]:
        """Get filtered events."""
        events = self.events

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if start_time:
            events = [e for e in events if e.timestamp >= start_time]

        if end_time:
            events = [e for e in events if e.timestamp <= end_time]

        return sorted(events, key=lambda e: e.timestamp)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'incident_id': self.incident_id,
            'events': [e.to_dict() for e in sorted(self.events, key=lambda e: e.timestamp)]
        }


@dataclass
class EscalationRule:
    """Rule for automatic incident escalation."""
    id: str
    name: str
    condition_type: str  # time_based, severity_based, sla_breach, custom
    condition: Dict[str, Any]
    action: str  # escalate_severity, notify, assign, run_playbook
    action_params: Dict[str, Any]
    enabled: bool = True

    def evaluate(self, incident: 'Incident') -> bool:
        """Evaluate if this rule should trigger."""
        if not self.enabled:
            return False

        if self.condition_type == "time_based":
            # Check if incident has been in current status too long
            max_duration = self.condition.get('max_duration_minutes', 60)
            if incident.status_changed_at:
                elapsed = (datetime.utcnow() - incident.status_changed_at).total_seconds() / 60
                return elapsed > max_duration

        elif self.condition_type == "severity_based":
            # Check severity threshold
            severity_order = ['informational', 'low', 'medium', 'high', 'critical']
            min_severity = self.condition.get('min_severity', 'medium')
            return severity_order.index(incident.severity.value) >= severity_order.index(min_severity)

        elif self.condition_type == "sla_breach":
            # Check if SLA is breached
            if incident.sla_deadline:
                return datetime.utcnow() > incident.sla_deadline

        elif self.condition_type == "status":
            # Check if in specific status
            target_status = self.condition.get('status')
            return incident.status.value == target_status

        return False


@dataclass
class SLATracker:
    """Tracks SLA compliance for incidents."""
    incident_id: str
    severity: IncidentSeverity
    created_at: datetime
    response_deadline: datetime
    resolution_deadline: datetime
    response_time: Optional[datetime] = None
    resolution_time: Optional[datetime] = None

    # Default SLA times by severity (in minutes)
    DEFAULT_SLAS = {
        IncidentSeverity.CRITICAL: {'response': 15, 'resolution': 240},
        IncidentSeverity.HIGH: {'response': 30, 'resolution': 480},
        IncidentSeverity.MEDIUM: {'response': 120, 'resolution': 1440},
        IncidentSeverity.LOW: {'response': 480, 'resolution': 4320},
        IncidentSeverity.INFORMATIONAL: {'response': 1440, 'resolution': 10080}
    }

    @classmethod
    def create(
        cls,
        incident_id: str,
        severity: IncidentSeverity,
        created_at: Optional[datetime] = None,
        custom_sla: Optional[Dict[str, int]] = None
    ) -> 'SLATracker':
        """Create a new SLA tracker."""
        now = created_at or datetime.utcnow()
        sla = custom_sla or cls.DEFAULT_SLAS.get(severity, {'response': 120, 'resolution': 1440})

        return cls(
            incident_id=incident_id,
            severity=severity,
            created_at=now,
            response_deadline=now + timedelta(minutes=sla['response']),
            resolution_deadline=now + timedelta(minutes=sla['resolution'])
        )

    def record_response(self) -> None:
        """Record when the incident was responded to."""
        self.response_time = datetime.utcnow()

    def record_resolution(self) -> None:
        """Record when the incident was resolved."""
        self.resolution_time = datetime.utcnow()

    @property
    def response_breached(self) -> bool:
        """Check if response SLA is breached."""
        if self.response_time:
            return self.response_time > self.response_deadline
        return datetime.utcnow() > self.response_deadline

    @property
    def resolution_breached(self) -> bool:
        """Check if resolution SLA is breached."""
        if self.resolution_time:
            return self.resolution_time > self.resolution_deadline
        return datetime.utcnow() > self.resolution_deadline

    @property
    def response_remaining(self) -> Optional[timedelta]:
        """Get remaining time for response SLA."""
        if self.response_time:
            return None
        return self.response_deadline - datetime.utcnow()

    @property
    def resolution_remaining(self) -> Optional[timedelta]:
        """Get remaining time for resolution SLA."""
        if self.resolution_time:
            return None
        return self.resolution_deadline - datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'incident_id': self.incident_id,
            'severity': self.severity.value,
            'created_at': self.created_at.isoformat(),
            'response_deadline': self.response_deadline.isoformat(),
            'resolution_deadline': self.resolution_deadline.isoformat(),
            'response_time': self.response_time.isoformat() if self.response_time else None,
            'resolution_time': self.resolution_time.isoformat() if self.resolution_time else None,
            'response_breached': self.response_breached,
            'resolution_breached': self.resolution_breached
        }


@dataclass
class Incident:
    """Security incident record."""
    id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus
    category: str  # malware, phishing, dos, unauthorized_access, data_breach, etc.
    source: str  # alert, user_report, automated, threat_intel
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None
    status_changed_at: Optional[datetime] = None
    sla_deadline: Optional[datetime] = None

    # Assignment
    assignee: Optional[str] = None
    team: Optional[str] = None

    # Related data
    affected_assets: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    iocs: List[Dict[str, str]] = field(default_factory=list)  # [{type: ip, value: 1.2.3.4}]
    related_alerts: List[str] = field(default_factory=list)
    related_incidents: List[str] = field(default_factory=list)

    # Investigation
    root_cause: Optional[str] = None
    attack_vector: Optional[str] = None
    mitre_techniques: List[str] = field(default_factory=list)

    # Response
    containment_actions: List[str] = field(default_factory=list)
    eradication_actions: List[str] = field(default_factory=list)
    recovery_actions: List[str] = field(default_factory=list)
    lessons_learned: Optional[str] = None

    # Metadata
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    playbook_executions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value,
            'status': self.status.value,
            'category': self.category,
            'source': self.source,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'closed_at': self.closed_at.isoformat() if self.closed_at else None,
            'status_changed_at': self.status_changed_at.isoformat() if self.status_changed_at else None,
            'sla_deadline': self.sla_deadline.isoformat() if self.sla_deadline else None,
            'assignee': self.assignee,
            'team': self.team,
            'affected_assets': self.affected_assets,
            'affected_users': self.affected_users,
            'iocs': self.iocs,
            'related_alerts': self.related_alerts,
            'related_incidents': self.related_incidents,
            'root_cause': self.root_cause,
            'attack_vector': self.attack_vector,
            'mitre_techniques': self.mitre_techniques,
            'containment_actions': self.containment_actions,
            'eradication_actions': self.eradication_actions,
            'recovery_actions': self.recovery_actions,
            'lessons_learned': self.lessons_learned,
            'tags': self.tags,
            'custom_fields': self.custom_fields,
            'playbook_executions': self.playbook_executions
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Incident':
        return cls(
            id=data['id'],
            title=data['title'],
            description=data['description'],
            severity=IncidentSeverity(data['severity']),
            status=IncidentStatus(data['status']),
            category=data['category'],
            source=data.get('source', 'manual'),
            created_at=datetime.fromisoformat(data['created_at']),
            updated_at=datetime.fromisoformat(data['updated_at']),
            closed_at=datetime.fromisoformat(data['closed_at']) if data.get('closed_at') else None,
            status_changed_at=datetime.fromisoformat(data['status_changed_at']) if data.get('status_changed_at') else None,
            sla_deadline=datetime.fromisoformat(data['sla_deadline']) if data.get('sla_deadline') else None,
            assignee=data.get('assignee'),
            team=data.get('team'),
            affected_assets=data.get('affected_assets', []),
            affected_users=data.get('affected_users', []),
            iocs=data.get('iocs', []),
            related_alerts=data.get('related_alerts', []),
            related_incidents=data.get('related_incidents', []),
            root_cause=data.get('root_cause'),
            attack_vector=data.get('attack_vector'),
            mitre_techniques=data.get('mitre_techniques', []),
            containment_actions=data.get('containment_actions', []),
            eradication_actions=data.get('eradication_actions', []),
            recovery_actions=data.get('recovery_actions', []),
            lessons_learned=data.get('lessons_learned'),
            tags=data.get('tags', []),
            custom_fields=data.get('custom_fields', {}),
            playbook_executions=data.get('playbook_executions', [])
        )


class IncidentManager:
    """
    Incident lifecycle management system.

    Handles creation, updates, escalation, SLA tracking, and
    evidence collection for security incidents.
    """

    def __init__(
        self,
        storage_dir: str = "/var/lib/tsunami/incidents",
        escalation_check_interval: int = 60
    ):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self._incidents: Dict[str, Incident] = {}
        self._timelines: Dict[str, IncidentTimeline] = {}
        self._evidence: Dict[str, List[Evidence]] = {}
        self._sla_trackers: Dict[str, SLATracker] = {}
        self._escalation_rules: List[EscalationRule] = []

        self._lock = threading.Lock()
        self._escalation_callbacks: List[Callable] = []

        # Load existing incidents
        self._load_incidents()

        # Start escalation checker
        self._escalation_check_interval = escalation_check_interval
        self._escalation_thread = threading.Thread(target=self._escalation_checker, daemon=True)
        self._escalation_thread.start()

        logger.info(f"IncidentManager initialized with {len(self._incidents)} incidents")

    def _load_incidents(self) -> None:
        """Load incidents from storage."""
        for incident_file in self.storage_dir.glob("INC-*.json"):
            try:
                with open(incident_file, 'r') as f:
                    data = json.load(f)
                incident = Incident.from_dict(data['incident'])
                self._incidents[incident.id] = incident

                if 'timeline' in data:
                    timeline = IncidentTimeline(incident_id=incident.id)
                    for event_data in data['timeline']:
                        event = TimelineEvent(
                            id=event_data['id'],
                            timestamp=datetime.fromisoformat(event_data['timestamp']),
                            event_type=event_data['event_type'],
                            description=event_data['description'],
                            actor=event_data['actor'],
                            data=event_data.get('data', {}),
                            source=event_data.get('source', 'manual')
                        )
                        timeline.events.append(event)
                    self._timelines[incident.id] = timeline

                if 'sla' in data:
                    sla_data = data['sla']
                    sla = SLATracker(
                        incident_id=incident.id,
                        severity=IncidentSeverity(sla_data['severity']),
                        created_at=datetime.fromisoformat(sla_data['created_at']),
                        response_deadline=datetime.fromisoformat(sla_data['response_deadline']),
                        resolution_deadline=datetime.fromisoformat(sla_data['resolution_deadline']),
                        response_time=datetime.fromisoformat(sla_data['response_time']) if sla_data.get('response_time') else None,
                        resolution_time=datetime.fromisoformat(sla_data['resolution_time']) if sla_data.get('resolution_time') else None
                    )
                    self._sla_trackers[incident.id] = sla

            except Exception as e:
                logger.error(f"Failed to load incident {incident_file}: {e}")

    def _save_incident(self, incident: Incident) -> None:
        """Save incident to storage."""
        data = {
            'incident': incident.to_dict(),
            'timeline': self._timelines.get(incident.id, IncidentTimeline(incident.id)).to_dict()['events'],
            'sla': self._sla_trackers[incident.id].to_dict() if incident.id in self._sla_trackers else None
        }

        filepath = self.storage_dir / f"{incident.id}.json"
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)

    def create_incident(
        self,
        title: str,
        description: str,
        severity: str,
        category: str,
        source: str = "manual",
        assignee: Optional[str] = None,
        team: Optional[str] = None,
        affected_assets: Optional[List[str]] = None,
        affected_users: Optional[List[str]] = None,
        iocs: Optional[List[Dict[str, str]]] = None,
        related_alerts: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        custom_sla: Optional[Dict[str, int]] = None
    ) -> Incident:
        """Create a new incident."""
        with self._lock:
            incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
            now = datetime.utcnow()

            severity_enum = IncidentSeverity(severity)

            incident = Incident(
                id=incident_id,
                title=title,
                description=description,
                severity=severity_enum,
                status=IncidentStatus.NEW,
                category=category,
                source=source,
                created_at=now,
                updated_at=now,
                status_changed_at=now,
                assignee=assignee,
                team=team,
                affected_assets=affected_assets or [],
                affected_users=affected_users or [],
                iocs=iocs or [],
                related_alerts=related_alerts or [],
                tags=tags or [],
                custom_fields=custom_fields or {}
            )

            # Create SLA tracker
            sla = SLATracker.create(incident_id, severity_enum, now, custom_sla)
            self._sla_trackers[incident_id] = sla
            incident.sla_deadline = sla.resolution_deadline

            # Create timeline
            timeline = IncidentTimeline(incident_id=incident_id)
            timeline.add_event(
                event_type="created",
                description=f"Incident created: {title}",
                actor="system",
                data={'severity': severity, 'category': category},
                source="system"
            )

            self._incidents[incident_id] = incident
            self._timelines[incident_id] = timeline
            self._evidence[incident_id] = []

            self._save_incident(incident)

        logger.info(f"Created incident: {incident_id} - {title}")
        return incident

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get an incident by ID."""
        return self._incidents.get(incident_id)

    def update_incident(
        self,
        incident_id: str,
        actor: str,
        **updates
    ) -> Optional[Incident]:
        """Update an incident."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            changes = []
            for key, value in updates.items():
                if hasattr(incident, key):
                    old_value = getattr(incident, key)
                    if old_value != value:
                        setattr(incident, key, value)
                        changes.append(f"{key}: {old_value} -> {value}")

            if changes:
                incident.updated_at = datetime.utcnow()

                # Add timeline event
                timeline = self._timelines.get(incident_id)
                if timeline:
                    timeline.add_event(
                        event_type="updated",
                        description=f"Incident updated: {', '.join(changes)}",
                        actor=actor,
                        data={'changes': updates},
                        source="manual"
                    )

                self._save_incident(incident)

            return incident

    def update_status(
        self,
        incident_id: str,
        new_status: str,
        actor: str,
        comment: Optional[str] = None
    ) -> Optional[Incident]:
        """Update incident status."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            old_status = incident.status
            incident.status = IncidentStatus(new_status)
            incident.status_changed_at = datetime.utcnow()
            incident.updated_at = datetime.utcnow()

            # Handle SLA tracking
            sla = self._sla_trackers.get(incident_id)
            if sla:
                if new_status == IncidentStatus.INVESTIGATING.value and not sla.response_time:
                    sla.record_response()

                if new_status == IncidentStatus.CLOSED.value:
                    sla.record_resolution()
                    incident.closed_at = datetime.utcnow()

            # Add timeline event
            timeline = self._timelines.get(incident_id)
            if timeline:
                timeline.add_event(
                    event_type="status_change",
                    description=f"Status changed from {old_status.value} to {new_status}",
                    actor=actor,
                    data={'old_status': old_status.value, 'new_status': new_status, 'comment': comment},
                    source="manual"
                )

            self._save_incident(incident)

        logger.info(f"Incident {incident_id} status changed: {old_status.value} -> {new_status}")
        return incident

    def assign_incident(
        self,
        incident_id: str,
        assignee: str,
        actor: str,
        team: Optional[str] = None
    ) -> Optional[Incident]:
        """Assign incident to a user/team."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            old_assignee = incident.assignee
            incident.assignee = assignee
            if team:
                incident.team = team
            incident.updated_at = datetime.utcnow()

            timeline = self._timelines.get(incident_id)
            if timeline:
                timeline.add_event(
                    event_type="assignment",
                    description=f"Assigned to {assignee}" + (f" (Team: {team})" if team else ""),
                    actor=actor,
                    data={'old_assignee': old_assignee, 'new_assignee': assignee, 'team': team},
                    source="manual"
                )

            self._save_incident(incident)

        return incident

    def escalate_incident(
        self,
        incident_id: str,
        new_severity: str,
        reason: str,
        actor: str
    ) -> Optional[Incident]:
        """Escalate incident severity."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            old_severity = incident.severity
            incident.severity = IncidentSeverity(new_severity)
            incident.updated_at = datetime.utcnow()

            # Update SLA
            sla = SLATracker.create(
                incident_id,
                incident.severity,
                datetime.utcnow()
            )
            self._sla_trackers[incident_id] = sla
            incident.sla_deadline = sla.resolution_deadline

            timeline = self._timelines.get(incident_id)
            if timeline:
                timeline.add_event(
                    event_type="escalation",
                    description=f"Escalated from {old_severity.value} to {new_severity}: {reason}",
                    actor=actor,
                    data={'old_severity': old_severity.value, 'new_severity': new_severity, 'reason': reason},
                    source="manual"
                )

            self._save_incident(incident)

        logger.info(f"Incident {incident_id} escalated: {old_severity.value} -> {new_severity}")
        return incident

    def close_incident(
        self,
        incident_id: str,
        resolution: str,
        lessons_learned: Optional[str],
        actor: str
    ) -> Optional[Incident]:
        """Close an incident."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            incident.status = IncidentStatus.CLOSED
            incident.closed_at = datetime.utcnow()
            incident.updated_at = datetime.utcnow()
            incident.lessons_learned = lessons_learned

            sla = self._sla_trackers.get(incident_id)
            if sla:
                sla.record_resolution()

            timeline = self._timelines.get(incident_id)
            if timeline:
                timeline.add_event(
                    event_type="closed",
                    description=f"Incident closed: {resolution}",
                    actor=actor,
                    data={'resolution': resolution, 'lessons_learned': lessons_learned},
                    source="manual"
                )

            self._save_incident(incident)

        logger.info(f"Incident {incident_id} closed")
        return incident

    def reopen_incident(
        self,
        incident_id: str,
        reason: str,
        actor: str
    ) -> Optional[Incident]:
        """Reopen a closed incident."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            incident.status = IncidentStatus.REOPENED
            incident.closed_at = None
            incident.updated_at = datetime.utcnow()
            incident.status_changed_at = datetime.utcnow()

            timeline = self._timelines.get(incident_id)
            if timeline:
                timeline.add_event(
                    event_type="reopened",
                    description=f"Incident reopened: {reason}",
                    actor=actor,
                    data={'reason': reason},
                    source="manual"
                )

            self._save_incident(incident)

        logger.info(f"Incident {incident_id} reopened")
        return incident

    def add_ioc(
        self,
        incident_id: str,
        ioc_type: str,
        value: str,
        actor: str,
        description: Optional[str] = None
    ) -> Optional[Incident]:
        """Add an IOC to an incident."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            ioc = {'type': ioc_type, 'value': value, 'description': description}
            incident.iocs.append(ioc)
            incident.updated_at = datetime.utcnow()

            timeline = self._timelines.get(incident_id)
            if timeline:
                timeline.add_event(
                    event_type="ioc_added",
                    description=f"IOC added: {ioc_type}={value}",
                    actor=actor,
                    data=ioc,
                    source="manual"
                )

            self._save_incident(incident)

        return incident

    def add_evidence(
        self,
        incident_id: str,
        evidence_type: str,
        name: str,
        description: str,
        collector: str,
        file_path: Optional[str] = None,
        hash_md5: Optional[str] = None,
        hash_sha256: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[Evidence]:
        """Add evidence to an incident."""
        with self._lock:
            incident = self._incidents.get(incident_id)
            if not incident:
                return None

            evidence_id = str(uuid.uuid4())
            evidence = Evidence(
                id=evidence_id,
                incident_id=incident_id,
                evidence_type=evidence_type,
                name=name,
                description=description,
                file_path=file_path,
                hash_md5=hash_md5,
                hash_sha256=hash_sha256,
                collected_at=datetime.utcnow(),
                collected_by=collector,
                chain_of_custody=[{
                    'action': 'collected',
                    'actor': collector,
                    'timestamp': datetime.utcnow().isoformat()
                }],
                tags=tags or [],
                metadata=metadata or {}
            )

            if incident_id not in self._evidence:
                self._evidence[incident_id] = []
            self._evidence[incident_id].append(evidence)

            timeline = self._timelines.get(incident_id)
            if timeline:
                timeline.add_event(
                    event_type="evidence_collected",
                    description=f"Evidence collected: {name}",
                    actor=collector,
                    data={'evidence_id': evidence_id, 'type': evidence_type},
                    source="manual"
                )

        logger.info(f"Evidence {evidence_id} added to incident {incident_id}")
        return evidence

    def get_timeline(self, incident_id: str) -> Optional[IncidentTimeline]:
        """Get the timeline for an incident."""
        return self._timelines.get(incident_id)

    def get_evidence(self, incident_id: str) -> List[Evidence]:
        """Get evidence for an incident."""
        return self._evidence.get(incident_id, [])

    def get_sla(self, incident_id: str) -> Optional[SLATracker]:
        """Get SLA tracker for an incident."""
        return self._sla_trackers.get(incident_id)

    def list_incidents(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        assignee: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100
    ) -> List[Incident]:
        """List incidents with filtering."""
        incidents = list(self._incidents.values())

        if status:
            incidents = [i for i in incidents if i.status.value == status]

        if severity:
            incidents = [i for i in incidents if i.severity.value == severity]

        if category:
            incidents = [i for i in incidents if i.category == category]

        if assignee:
            incidents = [i for i in incidents if i.assignee == assignee]

        if start_date:
            incidents = [i for i in incidents if i.created_at >= start_date]

        if end_date:
            incidents = [i for i in incidents if i.created_at <= end_date]

        # Sort by severity then created_at
        severity_order = {
            IncidentSeverity.CRITICAL: 0,
            IncidentSeverity.HIGH: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.LOW: 3,
            IncidentSeverity.INFORMATIONAL: 4
        }
        incidents.sort(key=lambda i: (severity_order[i.severity], -i.created_at.timestamp()))

        return incidents[:limit]

    def add_escalation_rule(self, rule: EscalationRule) -> None:
        """Add an escalation rule."""
        self._escalation_rules.append(rule)

    def register_escalation_callback(self, callback: Callable) -> None:
        """Register a callback for escalation events."""
        self._escalation_callbacks.append(callback)

    def _escalation_checker(self) -> None:
        """Background thread to check escalation rules."""
        import time
        while True:
            try:
                time.sleep(self._escalation_check_interval)

                for incident in list(self._incidents.values()):
                    if incident.status == IncidentStatus.CLOSED:
                        continue

                    for rule in self._escalation_rules:
                        if rule.evaluate(incident):
                            self._trigger_escalation(incident, rule)

            except Exception as e:
                logger.error(f"Escalation checker error: {e}")

    def _trigger_escalation(self, incident: Incident, rule: EscalationRule) -> None:
        """Trigger an escalation action."""
        logger.info(f"Escalation rule {rule.name} triggered for incident {incident.id}")

        for callback in self._escalation_callbacks:
            try:
                callback(incident, rule)
            except Exception as e:
                logger.error(f"Escalation callback error: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get incident statistics."""
        incidents = list(self._incidents.values())

        by_status = {}
        by_severity = {}
        by_category = {}

        for incident in incidents:
            by_status[incident.status.value] = by_status.get(incident.status.value, 0) + 1
            by_severity[incident.severity.value] = by_severity.get(incident.severity.value, 0) + 1
            by_category[incident.category] = by_category.get(incident.category, 0) + 1

        open_incidents = [i for i in incidents if i.status != IncidentStatus.CLOSED]
        sla_breached = sum(1 for i in open_incidents if self._sla_trackers.get(i.id, SLATracker.create(i.id, i.severity)).resolution_breached)

        return {
            'total': len(incidents),
            'open': len(open_incidents),
            'closed': len(incidents) - len(open_incidents),
            'sla_breached': sla_breached,
            'by_status': by_status,
            'by_severity': by_severity,
            'by_category': by_category
        }


# Singleton instance
_incident_manager: Optional[IncidentManager] = None


def get_incident_manager(**kwargs) -> IncidentManager:
    """Get or create the incident manager singleton."""
    global _incident_manager
    if _incident_manager is None:
        _incident_manager = IncidentManager(**kwargs)
    return _incident_manager
