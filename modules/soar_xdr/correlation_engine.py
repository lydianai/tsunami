#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI XDR Correlation Engine v5.0
    Extended Detection and Response Event Correlation
================================================================================

    Features:
    - Correlate events from multiple sources
    - Group related alerts
    - Reduce alert fatigue
    - Root cause analysis
    - Attack chain reconstruction
    - MITRE ATT&CK mapping

================================================================================
"""

import hashlib
import json
import logging
import re
import threading
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class CorrelationMethod(Enum):
    """Methods for correlating events."""
    FIELD_MATCH = "field_match"       # Match on specific fields
    TIME_WINDOW = "time_window"       # Events within time window
    SEQUENCE = "sequence"             # Ordered sequence of events
    THRESHOLD = "threshold"           # Count threshold
    STATISTICAL = "statistical"       # Statistical anomaly
    GRAPH = "graph"                   # Graph-based correlation
    MITRE = "mitre"                   # MITRE ATT&CK based


@dataclass
class CorrelatedEvent:
    """An event in the correlation system."""
    id: str
    timestamp: datetime
    source: str  # endpoint, network, cloud, identity, email
    event_type: str
    severity: str
    raw_data: Dict[str, Any]
    normalized_data: Dict[str, Any]
    iocs: List[Dict[str, str]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    entity_id: Optional[str] = None  # Host, user, or IP
    cluster_id: Optional[str] = None
    correlation_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'event_type': self.event_type,
            'severity': self.severity,
            'raw_data': self.raw_data,
            'normalized_data': self.normalized_data,
            'iocs': self.iocs,
            'mitre_techniques': self.mitre_techniques,
            'entity_id': self.entity_id,
            'cluster_id': self.cluster_id,
            'correlation_score': self.correlation_score
        }


@dataclass
class EventCluster:
    """A cluster of correlated events."""
    id: str
    created_at: datetime
    updated_at: datetime
    events: List[str]  # Event IDs
    entities: Set[str]
    iocs: Set[str]
    mitre_techniques: Set[str]
    severity: str
    confidence: float
    correlation_methods: List[str]
    summary: str
    root_event_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'events': self.events,
            'entities': list(self.entities),
            'iocs': list(self.iocs),
            'mitre_techniques': list(self.mitre_techniques),
            'severity': self.severity,
            'confidence': self.confidence,
            'correlation_methods': self.correlation_methods,
            'summary': self.summary,
            'root_event_id': self.root_event_id
        }


@dataclass
class AlertGroup:
    """A group of related alerts (reduced from many to one)."""
    id: str
    name: str
    description: str
    severity: str
    alert_count: int
    first_seen: datetime
    last_seen: datetime
    alerts: List[str]
    common_fields: Dict[str, Any]
    unique_values: Dict[str, Set[str]]
    suppression_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'severity': self.severity,
            'alert_count': self.alert_count,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'alerts': self.alerts,
            'common_fields': self.common_fields,
            'unique_values': {k: list(v) for k, v in self.unique_values.items()},
            'suppression_count': self.suppression_count
        }


@dataclass
class AttackStage:
    """A stage in an attack chain."""
    technique_id: str
    technique_name: str
    tactic: str
    timestamp: datetime
    events: List[str]
    confidence: float
    indicators: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'tactic': self.tactic,
            'timestamp': self.timestamp.isoformat(),
            'events': self.events,
            'confidence': self.confidence,
            'indicators': self.indicators
        }


@dataclass
class AttackChain:
    """A reconstructed attack chain."""
    id: str
    name: str
    description: str
    created_at: datetime
    severity: str
    stages: List[AttackStage]
    entities: Set[str]
    total_events: int
    confidence: float
    kill_chain_phase: str  # reconnaissance, weaponization, delivery, etc.

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'severity': self.severity,
            'stages': [s.to_dict() for s in self.stages],
            'entities': list(self.entities),
            'total_events': self.total_events,
            'confidence': self.confidence,
            'kill_chain_phase': self.kill_chain_phase
        }


@dataclass
class RootCauseAnalysis:
    """Root cause analysis result."""
    id: str
    cluster_id: str
    analysis_time: datetime
    root_cause_event: str
    root_cause_entity: str
    root_cause_type: str  # malware, credential_compromise, misconfiguration, etc.
    confidence: float
    evidence: List[Dict[str, Any]]
    attack_narrative: str
    recommended_actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'cluster_id': self.cluster_id,
            'analysis_time': self.analysis_time.isoformat(),
            'root_cause_event': self.root_cause_event,
            'root_cause_entity': self.root_cause_entity,
            'root_cause_type': self.root_cause_type,
            'confidence': self.confidence,
            'evidence': self.evidence,
            'attack_narrative': self.attack_narrative,
            'recommended_actions': self.recommended_actions
        }


@dataclass
class CorrelationRule:
    """A rule for correlating events."""
    id: str
    name: str
    description: str
    method: CorrelationMethod
    conditions: Dict[str, Any]
    time_window: int  # seconds
    threshold: int
    severity: str
    enabled: bool = True
    mitre_mapping: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'method': self.method.value,
            'conditions': self.conditions,
            'time_window': self.time_window,
            'threshold': self.threshold,
            'severity': self.severity,
            'enabled': self.enabled,
            'mitre_mapping': self.mitre_mapping
        }


class CorrelationEngine:
    """
    XDR Event Correlation Engine.

    Correlates security events from multiple sources to detect
    complex attacks and reduce alert fatigue.
    """

    # MITRE ATT&CK Tactics in kill chain order
    MITRE_TACTICS = [
        'reconnaissance', 'resource-development', 'initial-access',
        'execution', 'persistence', 'privilege-escalation',
        'defense-evasion', 'credential-access', 'discovery',
        'lateral-movement', 'collection', 'command-and-control',
        'exfiltration', 'impact'
    ]

    # Common technique to tactic mapping
    TECHNIQUE_TACTICS = {
        'T1566': 'initial-access',      # Phishing
        'T1059': 'execution',           # Command and Scripting Interpreter
        'T1053': 'execution',           # Scheduled Task/Job
        'T1547': 'persistence',         # Boot or Logon Autostart
        'T1078': 'initial-access',      # Valid Accounts
        'T1110': 'credential-access',   # Brute Force
        'T1003': 'credential-access',   # OS Credential Dumping
        'T1021': 'lateral-movement',    # Remote Services
        'T1071': 'command-and-control', # Application Layer Protocol
        'T1048': 'exfiltration',        # Exfiltration Over Alternative Protocol
        'T1486': 'impact',              # Data Encrypted for Impact
        'T1489': 'impact',              # Service Stop
    }

    def __init__(
        self,
        time_window: int = 3600,  # Default 1 hour correlation window
        min_cluster_size: int = 2,
        auto_correlate: bool = True
    ):
        self.time_window = time_window
        self.min_cluster_size = min_cluster_size
        self.auto_correlate = auto_correlate

        self._events: Dict[str, CorrelatedEvent] = {}
        self._clusters: Dict[str, EventCluster] = {}
        self._alert_groups: Dict[str, AlertGroup] = {}
        self._attack_chains: Dict[str, AttackChain] = {}
        self._root_cause_analyses: Dict[str, RootCauseAnalysis] = {}
        self._rules: List[CorrelationRule] = []

        # Indexes for fast lookup
        self._entity_events: Dict[str, List[str]] = defaultdict(list)
        self._ioc_events: Dict[str, List[str]] = defaultdict(list)
        self._time_index: List[Tuple[datetime, str]] = []

        self._lock = threading.Lock()
        self._callbacks: List[Callable] = []

        # Load default rules
        self._load_default_rules()

        logger.info("CorrelationEngine initialized")

    def _load_default_rules(self) -> None:
        """Load default correlation rules."""
        default_rules = [
            CorrelationRule(
                id="rule-brute-force",
                name="Brute Force Detection",
                description="Multiple failed authentication attempts",
                method=CorrelationMethod.THRESHOLD,
                conditions={
                    'event_type': 'authentication_failure',
                    'group_by': ['entity_id', 'source_ip']
                },
                time_window=300,  # 5 minutes
                threshold=5,
                severity='high',
                mitre_mapping=['T1110']
            ),
            CorrelationRule(
                id="rule-lateral-movement",
                name="Lateral Movement Detection",
                description="Authentication from new source following compromise",
                method=CorrelationMethod.SEQUENCE,
                conditions={
                    'sequence': [
                        {'event_type': 'malware_detected'},
                        {'event_type': 'authentication_success', 'delay_max': 3600}
                    ]
                },
                time_window=3600,
                threshold=1,
                severity='critical',
                mitre_mapping=['T1021']
            ),
            CorrelationRule(
                id="rule-data-exfil",
                name="Data Exfiltration Indicators",
                description="Large data transfer following suspicious activity",
                method=CorrelationMethod.SEQUENCE,
                conditions={
                    'sequence': [
                        {'event_type': ['command_execution', 'file_access']},
                        {'event_type': 'network_upload', 'data_size_min': 10000000}
                    ]
                },
                time_window=7200,
                threshold=1,
                severity='critical',
                mitre_mapping=['T1048']
            ),
            CorrelationRule(
                id="rule-ransomware",
                name="Ransomware Behavior",
                description="Multiple file encryption events",
                method=CorrelationMethod.THRESHOLD,
                conditions={
                    'event_type': 'file_encrypted',
                    'group_by': ['entity_id']
                },
                time_window=60,
                threshold=10,
                severity='critical',
                mitre_mapping=['T1486']
            ),
            CorrelationRule(
                id="rule-multi-stage",
                name="Multi-Stage Attack",
                description="Events spanning multiple MITRE tactics",
                method=CorrelationMethod.MITRE,
                conditions={
                    'min_tactics': 3,
                    'tactic_order': True
                },
                time_window=86400,  # 24 hours
                threshold=1,
                severity='critical',
                mitre_mapping=[]
            )
        ]

        self._rules.extend(default_rules)

    def add_rule(self, rule: CorrelationRule) -> None:
        """Add a correlation rule."""
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a correlation rule."""
        for i, rule in enumerate(self._rules):
            if rule.id == rule_id:
                del self._rules[i]
                return True
        return False

    def get_rules(self) -> List[CorrelationRule]:
        """Get all correlation rules."""
        return self._rules.copy()

    def ingest_event(
        self,
        source: str,
        event_type: str,
        severity: str,
        raw_data: Dict[str, Any],
        timestamp: Optional[datetime] = None,
        entity_id: Optional[str] = None
    ) -> CorrelatedEvent:
        """Ingest and normalize an event."""
        event_id = str(uuid.uuid4())
        timestamp = timestamp or datetime.utcnow()

        # Normalize event data
        normalized = self._normalize_event(source, event_type, raw_data)

        # Extract IOCs
        iocs = self._extract_iocs(raw_data)

        # Map to MITRE techniques
        mitre_techniques = self._map_to_mitre(event_type, raw_data)

        # Determine entity
        if not entity_id:
            entity_id = self._determine_entity(normalized)

        event = CorrelatedEvent(
            id=event_id,
            timestamp=timestamp,
            source=source,
            event_type=event_type,
            severity=severity,
            raw_data=raw_data,
            normalized_data=normalized,
            iocs=iocs,
            mitre_techniques=mitre_techniques,
            entity_id=entity_id
        )

        with self._lock:
            self._events[event_id] = event

            # Update indexes
            if entity_id:
                self._entity_events[entity_id].append(event_id)

            for ioc in iocs:
                ioc_key = f"{ioc['type']}:{ioc['value']}"
                self._ioc_events[ioc_key].append(event_id)

            self._time_index.append((timestamp, event_id))
            self._time_index.sort(key=lambda x: x[0])

            # Keep only recent events in memory
            self._cleanup_old_events()

        # Auto-correlate if enabled
        if self.auto_correlate:
            self._correlate_event(event)

        return event

    def _normalize_event(
        self,
        source: str,
        event_type: str,
        raw_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Normalize event data to common schema."""
        normalized = {
            'source': source,
            'event_type': event_type,
            'timestamp': raw_data.get('timestamp'),
        }

        # Common field mappings
        field_mappings = {
            'src_ip': ['source_ip', 'src', 'src_addr', 'client_ip', 'ip'],
            'dst_ip': ['dest_ip', 'dst', 'dst_addr', 'destination_ip', 'server_ip'],
            'src_port': ['source_port', 'sport'],
            'dst_port': ['dest_port', 'dport', 'destination_port'],
            'user': ['username', 'user_name', 'account', 'login'],
            'hostname': ['host', 'computer_name', 'machine', 'device'],
            'process': ['process_name', 'proc', 'image'],
            'pid': ['process_id'],
            'command': ['command_line', 'cmdline', 'cmd'],
            'file_path': ['path', 'filename', 'file'],
            'hash_md5': ['md5', 'md5_hash'],
            'hash_sha256': ['sha256', 'sha256_hash'],
            'url': ['request_url', 'uri'],
            'domain': ['host', 'fqdn', 'dns_name']
        }

        for norm_field, raw_fields in field_mappings.items():
            for raw_field in raw_fields:
                if raw_field in raw_data and raw_data[raw_field]:
                    normalized[norm_field] = raw_data[raw_field]
                    break

        return normalized

    def _extract_iocs(self, data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract IOCs from event data."""
        iocs = []
        data_str = json.dumps(data)

        # IP addresses
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for ip in re.findall(ip_pattern, data_str):
            if not ip.startswith(('10.', '172.', '192.168.', '127.')):
                iocs.append({'type': 'ip', 'value': ip})

        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        for domain in re.findall(domain_pattern, data_str):
            if domain not in ['microsoft.com', 'google.com', 'windows.com']:
                iocs.append({'type': 'domain', 'value': domain.lower()})

        # MD5 hashes
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        for md5 in re.findall(md5_pattern, data_str):
            iocs.append({'type': 'md5', 'value': md5.lower()})

        # SHA256 hashes
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for sha256 in re.findall(sha256_pattern, data_str):
            iocs.append({'type': 'sha256', 'value': sha256.lower()})

        # URLs
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        for url in re.findall(url_pattern, data_str):
            iocs.append({'type': 'url', 'value': url})

        return iocs

    def _map_to_mitre(self, event_type: str, data: Dict[str, Any]) -> List[str]:
        """Map event to MITRE ATT&CK techniques."""
        techniques = []

        # Event type to technique mapping
        type_mapping = {
            'authentication_failure': ['T1110'],
            'authentication_success': ['T1078'],
            'command_execution': ['T1059'],
            'process_creation': ['T1059'],
            'file_created': ['T1105'],
            'file_modified': ['T1565'],
            'file_encrypted': ['T1486'],
            'registry_modified': ['T1547'],
            'scheduled_task_created': ['T1053'],
            'network_connection': ['T1071'],
            'dns_query': ['T1071.004'],
            'email_received': ['T1566'],
            'service_created': ['T1543'],
            'credential_access': ['T1003'],
        }

        if event_type in type_mapping:
            techniques.extend(type_mapping[event_type])

        # Check for specific indicators in data
        command = str(data.get('command', '')).lower()
        if 'powershell' in command:
            techniques.append('T1059.001')
        if 'mimikatz' in command or 'sekurlsa' in command:
            techniques.append('T1003.001')
        if 'psexec' in command:
            techniques.append('T1569.002')

        return list(set(techniques))

    def _determine_entity(self, normalized: Dict[str, Any]) -> Optional[str]:
        """Determine the primary entity for an event."""
        # Priority: hostname > user > src_ip
        for field in ['hostname', 'user', 'src_ip']:
            if field in normalized and normalized[field]:
                return f"{field}:{normalized[field]}"
        return None

    def _correlate_event(self, event: CorrelatedEvent) -> None:
        """Correlate a new event against existing events."""
        for rule in self._rules:
            if not rule.enabled:
                continue

            if rule.method == CorrelationMethod.FIELD_MATCH:
                self._correlate_field_match(event, rule)
            elif rule.method == CorrelationMethod.TIME_WINDOW:
                self._correlate_time_window(event, rule)
            elif rule.method == CorrelationMethod.THRESHOLD:
                self._correlate_threshold(event, rule)
            elif rule.method == CorrelationMethod.SEQUENCE:
                self._correlate_sequence(event, rule)
            elif rule.method == CorrelationMethod.MITRE:
                self._correlate_mitre(event, rule)

    def _correlate_field_match(
        self,
        event: CorrelatedEvent,
        rule: CorrelationRule
    ) -> Optional[EventCluster]:
        """Correlate based on matching field values."""
        match_fields = rule.conditions.get('match_fields', [])
        if not match_fields:
            return None

        # Find events with matching fields
        matching_events = []
        cutoff = event.timestamp - timedelta(seconds=rule.time_window)

        for eid, e in self._events.items():
            if e.timestamp < cutoff or e.id == event.id:
                continue

            matches = True
            for field in match_fields:
                if event.normalized_data.get(field) != e.normalized_data.get(field):
                    matches = False
                    break

            if matches:
                matching_events.append(eid)

        if len(matching_events) >= rule.threshold:
            return self._create_cluster(
                [event.id] + matching_events,
                rule,
                f"Field match on {match_fields}"
            )

        return None

    def _correlate_time_window(
        self,
        event: CorrelatedEvent,
        rule: CorrelationRule
    ) -> Optional[EventCluster]:
        """Correlate events within a time window."""
        entity_events = self._entity_events.get(event.entity_id, [])
        cutoff = event.timestamp - timedelta(seconds=rule.time_window)

        related = []
        for eid in entity_events:
            e = self._events.get(eid)
            if e and e.timestamp >= cutoff and e.id != event.id:
                related.append(eid)

        if len(related) >= rule.threshold:
            return self._create_cluster(
                [event.id] + related,
                rule,
                f"Time window correlation for {event.entity_id}"
            )

        return None

    def _correlate_threshold(
        self,
        event: CorrelatedEvent,
        rule: CorrelationRule
    ) -> Optional[EventCluster]:
        """Correlate based on event count threshold."""
        event_type = rule.conditions.get('event_type')
        if event.event_type != event_type:
            return None

        group_by = rule.conditions.get('group_by', ['entity_id'])
        cutoff = event.timestamp - timedelta(seconds=rule.time_window)

        # Group events
        group_key_parts = []
        for field in group_by:
            if field == 'entity_id':
                group_key_parts.append(event.entity_id or '')
            else:
                group_key_parts.append(str(event.normalized_data.get(field, '')))

        group_key = '|'.join(group_key_parts)

        # Count matching events
        matching = [event.id]
        for eid, e in self._events.items():
            if e.timestamp < cutoff or e.id == event.id:
                continue
            if e.event_type != event_type:
                continue

            e_key_parts = []
            for field in group_by:
                if field == 'entity_id':
                    e_key_parts.append(e.entity_id or '')
                else:
                    e_key_parts.append(str(e.normalized_data.get(field, '')))

            if '|'.join(e_key_parts) == group_key:
                matching.append(eid)

        if len(matching) >= rule.threshold:
            return self._create_cluster(
                matching,
                rule,
                f"Threshold exceeded: {len(matching)} {event_type} events"
            )

        return None

    def _correlate_sequence(
        self,
        event: CorrelatedEvent,
        rule: CorrelationRule
    ) -> Optional[EventCluster]:
        """Correlate based on event sequence."""
        sequence = rule.conditions.get('sequence', [])
        if not sequence:
            return None

        # Check if this event matches any step in the sequence
        for i, step in enumerate(sequence):
            step_types = step.get('event_type')
            if isinstance(step_types, str):
                step_types = [step_types]

            if event.event_type in step_types:
                # Check for preceding/following events
                if i == 0:
                    # First in sequence - look for following events
                    following = self._find_sequence_events(
                        event, sequence[1:], forward=True
                    )
                    if following:
                        return self._create_cluster(
                            [event.id] + following,
                            rule,
                            f"Sequence detected starting with {event.event_type}"
                        )
                else:
                    # Not first - look for preceding events
                    preceding = self._find_sequence_events(
                        event, sequence[:i], forward=False
                    )
                    if preceding:
                        return self._create_cluster(
                            preceding + [event.id],
                            rule,
                            f"Sequence detected ending with {event.event_type}"
                        )

        return None

    def _find_sequence_events(
        self,
        start_event: CorrelatedEvent,
        steps: List[Dict],
        forward: bool
    ) -> List[str]:
        """Find events matching sequence steps."""
        results = []
        current_time = start_event.timestamp
        entity = start_event.entity_id

        for step in (steps if forward else reversed(steps)):
            step_types = step.get('event_type')
            if isinstance(step_types, str):
                step_types = [step_types]

            delay_max = step.get('delay_max', self.time_window)

            if forward:
                window_start = current_time
                window_end = current_time + timedelta(seconds=delay_max)
            else:
                window_end = current_time
                window_start = current_time - timedelta(seconds=delay_max)

            found = None
            for eid, e in self._events.items():
                if e.entity_id != entity:
                    continue
                if e.event_type not in step_types:
                    continue
                if not (window_start <= e.timestamp <= window_end):
                    continue

                found = e
                break

            if found:
                results.append(found.id)
                current_time = found.timestamp
            else:
                return []  # Sequence broken

        return results

    def _correlate_mitre(
        self,
        event: CorrelatedEvent,
        rule: CorrelationRule
    ) -> Optional[EventCluster]:
        """Correlate based on MITRE ATT&CK coverage."""
        if not event.mitre_techniques:
            return None

        min_tactics = rule.conditions.get('min_tactics', 3)
        tactic_order = rule.conditions.get('tactic_order', False)
        cutoff = event.timestamp - timedelta(seconds=rule.time_window)

        # Collect events for entity
        entity_events = [
            self._events[eid]
            for eid in self._entity_events.get(event.entity_id, [])
            if self._events.get(eid) and self._events[eid].timestamp >= cutoff
        ]

        if event not in entity_events:
            entity_events.append(event)

        # Map to tactics
        tactic_events: Dict[str, List[CorrelatedEvent]] = defaultdict(list)
        for e in entity_events:
            for tech in e.mitre_techniques:
                tech_base = tech.split('.')[0]
                tactic = self.TECHNIQUE_TACTICS.get(tech_base)
                if tactic:
                    tactic_events[tactic].append(e)

        if len(tactic_events) >= min_tactics:
            if tactic_order:
                # Check if tactics follow kill chain order
                found_tactics = list(tactic_events.keys())
                indices = [self.MITRE_TACTICS.index(t) for t in found_tactics if t in self.MITRE_TACTICS]
                if indices != sorted(indices):
                    return None

            all_events = []
            for events in tactic_events.values():
                all_events.extend([e.id for e in events])

            return self._create_cluster(
                list(set(all_events)),
                rule,
                f"Multi-tactic attack: {list(tactic_events.keys())}"
            )

        return None

    def _create_cluster(
        self,
        event_ids: List[str],
        rule: CorrelationRule,
        summary: str
    ) -> EventCluster:
        """Create an event cluster."""
        events = [self._events[eid] for eid in event_ids if eid in self._events]

        entities = set()
        iocs = set()
        techniques = set()

        for event in events:
            if event.entity_id:
                entities.add(event.entity_id)
            for ioc in event.iocs:
                iocs.add(f"{ioc['type']}:{ioc['value']}")
            techniques.update(event.mitre_techniques)

        # Determine root event (earliest)
        events.sort(key=lambda e: e.timestamp)
        root_event = events[0] if events else None

        cluster = EventCluster(
            id=str(uuid.uuid4()),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            events=event_ids,
            entities=entities,
            iocs=iocs,
            mitre_techniques=techniques,
            severity=rule.severity,
            confidence=0.8,
            correlation_methods=[rule.method.value],
            summary=summary,
            root_event_id=root_event.id if root_event else None
        )

        with self._lock:
            self._clusters[cluster.id] = cluster

            # Update event cluster assignments
            for eid in event_ids:
                if eid in self._events:
                    self._events[eid].cluster_id = cluster.id

        # Trigger callbacks
        for callback in self._callbacks:
            try:
                callback(cluster)
            except Exception as e:
                logger.error(f"Cluster callback error: {e}")

        logger.info(f"Created cluster {cluster.id}: {summary}")
        return cluster

    def correlate_events(
        self,
        event_ids: Optional[List[str]] = None,
        entity_id: Optional[str] = None,
        time_range: Optional[Tuple[datetime, datetime]] = None
    ) -> List[EventCluster]:
        """Manually trigger correlation on a set of events."""
        events = []

        if event_ids:
            events = [self._events[eid] for eid in event_ids if eid in self._events]
        elif entity_id:
            events = [
                self._events[eid]
                for eid in self._entity_events.get(entity_id, [])
                if eid in self._events
            ]
        elif time_range:
            start, end = time_range
            events = [
                e for e in self._events.values()
                if start <= e.timestamp <= end
            ]

        clusters = []
        for event in events:
            for rule in self._rules:
                if not rule.enabled:
                    continue

                cluster = None
                if rule.method == CorrelationMethod.THRESHOLD:
                    cluster = self._correlate_threshold(event, rule)
                elif rule.method == CorrelationMethod.SEQUENCE:
                    cluster = self._correlate_sequence(event, rule)
                elif rule.method == CorrelationMethod.MITRE:
                    cluster = self._correlate_mitre(event, rule)

                if cluster and cluster.id not in [c.id for c in clusters]:
                    clusters.append(cluster)

        return clusters

    def group_alerts(
        self,
        group_by: List[str] = ['event_type', 'entity_id'],
        time_window: int = 3600
    ) -> List[AlertGroup]:
        """Group similar alerts to reduce fatigue."""
        cutoff = datetime.utcnow() - timedelta(seconds=time_window)

        groups: Dict[str, List[CorrelatedEvent]] = defaultdict(list)

        for event in self._events.values():
            if event.timestamp < cutoff:
                continue

            key_parts = []
            for field in group_by:
                if field == 'entity_id':
                    key_parts.append(event.entity_id or '')
                else:
                    key_parts.append(str(event.normalized_data.get(field, '')))

            key = '|'.join(key_parts)
            groups[key].append(event)

        alert_groups = []
        for key, events in groups.items():
            if len(events) < 2:
                continue

            events.sort(key=lambda e: e.timestamp)

            # Find common fields
            common_fields = {}
            all_fields = set()
            for e in events:
                all_fields.update(e.normalized_data.keys())

            for field in all_fields:
                values = set(e.normalized_data.get(field) for e in events)
                if len(values) == 1:
                    common_fields[field] = list(values)[0]

            # Find unique values per field
            unique_values: Dict[str, Set[str]] = defaultdict(set)
            for e in events:
                for field, value in e.normalized_data.items():
                    if field not in common_fields and value:
                        unique_values[field].add(str(value))

            # Determine highest severity
            severity_order = ['informational', 'low', 'medium', 'high', 'critical']
            max_severity = max(events, key=lambda e: severity_order.index(e.severity)).severity

            group = AlertGroup(
                id=str(uuid.uuid4()),
                name=f"Grouped: {events[0].event_type}",
                description=f"{len(events)} similar alerts",
                severity=max_severity,
                alert_count=len(events),
                first_seen=events[0].timestamp,
                last_seen=events[-1].timestamp,
                alerts=[e.id for e in events],
                common_fields=common_fields,
                unique_values=dict(unique_values),
                suppression_count=len(events) - 1
            )

            alert_groups.append(group)
            with self._lock:
                self._alert_groups[group.id] = group

        return alert_groups

    def build_attack_chain(self, cluster_id: str) -> Optional[AttackChain]:
        """Build an attack chain from a cluster."""
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None

        events = [
            self._events[eid]
            for eid in cluster.events
            if eid in self._events
        ]

        if not events:
            return None

        # Group by tactic
        tactic_stages: Dict[str, List[CorrelatedEvent]] = defaultdict(list)
        for event in events:
            for tech in event.mitre_techniques:
                tech_base = tech.split('.')[0]
                tactic = self.TECHNIQUE_TACTICS.get(tech_base, 'unknown')
                tactic_stages[tactic].append(event)

        # Build stages in kill chain order
        stages = []
        for tactic in self.MITRE_TACTICS:
            if tactic not in tactic_stages:
                continue

            tactic_events = tactic_stages[tactic]
            tactic_events.sort(key=lambda e: e.timestamp)

            techniques = set()
            for e in tactic_events:
                techniques.update(e.mitre_techniques)

            indicators = []
            for e in tactic_events:
                indicators.extend(e.iocs)

            stage = AttackStage(
                technique_id=list(techniques)[0] if techniques else '',
                technique_name=', '.join(techniques),
                tactic=tactic,
                timestamp=tactic_events[0].timestamp,
                events=[e.id for e in tactic_events],
                confidence=0.8,
                indicators=indicators[:10]
            )
            stages.append(stage)

        if not stages:
            return None

        # Determine kill chain phase
        first_tactic = stages[0].tactic
        phase_mapping = {
            'reconnaissance': 'reconnaissance',
            'resource-development': 'weaponization',
            'initial-access': 'delivery',
            'execution': 'exploitation',
            'persistence': 'installation',
            'command-and-control': 'command-and-control',
            'exfiltration': 'actions-on-objectives',
            'impact': 'actions-on-objectives'
        }
        kill_chain_phase = phase_mapping.get(first_tactic, 'unknown')

        chain = AttackChain(
            id=str(uuid.uuid4()),
            name=f"Attack Chain: {cluster.summary}",
            description=f"{len(stages)} stage attack across {', '.join(s.tactic for s in stages)}",
            created_at=datetime.utcnow(),
            severity=cluster.severity,
            stages=stages,
            entities=cluster.entities,
            total_events=len(events),
            confidence=cluster.confidence,
            kill_chain_phase=kill_chain_phase
        )

        with self._lock:
            self._attack_chains[chain.id] = chain

        logger.info(f"Built attack chain {chain.id} with {len(stages)} stages")
        return chain

    def analyze_root_cause(self, cluster_id: str) -> Optional[RootCauseAnalysis]:
        """Perform root cause analysis on a cluster."""
        cluster = self._clusters.get(cluster_id)
        if not cluster:
            return None

        events = [
            self._events[eid]
            for eid in cluster.events
            if eid in self._events
        ]

        if not events:
            return None

        # Sort by timestamp to find earliest
        events.sort(key=lambda e: e.timestamp)
        root_event = events[0]

        # Determine root cause type
        root_cause_types = {
            'authentication_failure': 'credential_attack',
            'malware_detected': 'malware',
            'email_received': 'phishing',
            'file_encrypted': 'ransomware',
            'command_execution': 'code_execution',
            'service_created': 'persistence'
        }
        root_cause_type = root_cause_types.get(root_event.event_type, 'unknown')

        # Collect evidence
        evidence = []
        for event in events[:10]:
            evidence.append({
                'event_id': event.id,
                'event_type': event.event_type,
                'timestamp': event.timestamp.isoformat(),
                'entity': event.entity_id,
                'iocs': event.iocs[:5]
            })

        # Generate attack narrative
        narrative_parts = [
            f"The attack began at {root_event.timestamp.isoformat()} on {root_event.entity_id}.",
            f"Initial event type: {root_event.event_type}.",
            f"The attack involved {len(cluster.entities)} entities and {len(events)} events.",
        ]

        if cluster.mitre_techniques:
            narrative_parts.append(
                f"MITRE ATT&CK techniques observed: {', '.join(list(cluster.mitre_techniques)[:5])}."
            )

        # Recommended actions
        actions = [
            f"Isolate affected entity: {root_event.entity_id}",
            "Review and block associated IOCs",
            "Examine logs for lateral movement",
            "Reset credentials for affected users",
            "Run malware scan on affected systems"
        ]

        analysis = RootCauseAnalysis(
            id=str(uuid.uuid4()),
            cluster_id=cluster_id,
            analysis_time=datetime.utcnow(),
            root_cause_event=root_event.id,
            root_cause_entity=root_event.entity_id or 'unknown',
            root_cause_type=root_cause_type,
            confidence=0.75,
            evidence=evidence,
            attack_narrative=' '.join(narrative_parts),
            recommended_actions=actions
        )

        with self._lock:
            self._root_cause_analyses[analysis.id] = analysis

        logger.info(f"Root cause analysis completed: {analysis.id}")
        return analysis

    def get_timeline(
        self,
        entity_id: Optional[str] = None,
        cluster_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Get a timeline of events."""
        events = []

        if cluster_id:
            cluster = self._clusters.get(cluster_id)
            if cluster:
                events = [
                    self._events[eid]
                    for eid in cluster.events
                    if eid in self._events
                ]
        elif entity_id:
            events = [
                self._events[eid]
                for eid in self._entity_events.get(entity_id, [])
                if eid in self._events
            ]
        else:
            events = list(self._events.values())

        if start_time:
            events = [e for e in events if e.timestamp >= start_time]
        if end_time:
            events = [e for e in events if e.timestamp <= end_time]

        events.sort(key=lambda e: e.timestamp)

        return [
            {
                'timestamp': e.timestamp.isoformat(),
                'event_id': e.id,
                'source': e.source,
                'event_type': e.event_type,
                'severity': e.severity,
                'entity': e.entity_id,
                'mitre': e.mitre_techniques,
                'summary': self._event_summary(e)
            }
            for e in events
        ]

    def _event_summary(self, event: CorrelatedEvent) -> str:
        """Generate a summary for an event."""
        n = event.normalized_data
        parts = [event.event_type]

        if n.get('user'):
            parts.append(f"user={n['user']}")
        if n.get('src_ip'):
            parts.append(f"src={n['src_ip']}")
        if n.get('dst_ip'):
            parts.append(f"dst={n['dst_ip']}")
        if n.get('process'):
            parts.append(f"process={n['process']}")

        return ' | '.join(parts)

    def _cleanup_old_events(self) -> None:
        """Remove old events from memory."""
        cutoff = datetime.utcnow() - timedelta(seconds=self.time_window * 2)

        old_events = [
            eid for eid, e in self._events.items()
            if e.timestamp < cutoff
        ]

        for eid in old_events:
            del self._events[eid]

        self._time_index = [
            (t, eid) for t, eid in self._time_index
            if t >= cutoff
        ]

    def register_callback(self, callback: Callable) -> None:
        """Register a callback for new clusters."""
        self._callbacks.append(callback)

    def get_cluster(self, cluster_id: str) -> Optional[EventCluster]:
        """Get a cluster by ID."""
        return self._clusters.get(cluster_id)

    def get_attack_chain(self, chain_id: str) -> Optional[AttackChain]:
        """Get an attack chain by ID."""
        return self._attack_chains.get(chain_id)

    def get_statistics(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        return {
            'total_events': len(self._events),
            'total_clusters': len(self._clusters),
            'total_attack_chains': len(self._attack_chains),
            'total_alert_groups': len(self._alert_groups),
            'active_rules': sum(1 for r in self._rules if r.enabled),
            'entities_tracked': len(self._entity_events),
            'iocs_tracked': len(self._ioc_events)
        }


# Singleton instance
_correlation_engine: Optional[CorrelationEngine] = None


def get_correlation_engine(**kwargs) -> CorrelationEngine:
    """Get or create the correlation engine singleton."""
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine(**kwargs)
    return _correlation_engine
