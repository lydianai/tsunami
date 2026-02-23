#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Alert Normalization Pipeline
    Unified Alert Schema with Multi-Source Adapters
================================================================================

    Features:
    - Unified TSUNAMI Alert Format (TAF) dataclass
    - Source adapters: Wazuh, Suricata, Syslog, Generic
    - Custom source adapter registration framework
    - Field mapping + validation
    - IOC auto-extraction (IP, domain, hash, URL, email)
    - Enrichment hooks (pre/post normalization)
    - Deduplication with configurable time window
    - Alert correlation hints (same src/dst, same SID, MITRE overlap)
    - Severity override rules
    - Pipeline statistics and audit trail
    - Thread-safe with SQLite persistence
    - Flask Blueprint for pipeline management API

================================================================================
"""

import hashlib
import json
import logging
import os
import re
import sqlite3
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type

logger = logging.getLogger("soc.normalizer")


# ============================================================================
# Enums & Constants
# ============================================================================

class TAFSeverity(Enum):
    """TSUNAMI Alert Format severity levels."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5

    @classmethod
    def from_string(cls, s: str) -> 'TAFSeverity':
        """Parse severity from string, case-insensitive."""
        mapping = {
            'critical': cls.CRITICAL,
            'high': cls.HIGH,
            'medium': cls.MEDIUM,
            'low': cls.LOW,
            'info': cls.INFO,
            'informational': cls.INFO,
        }
        return mapping.get(s.strip().lower(), cls.INFO)

    @property
    def sla_minutes(self) -> int:
        return {1: 15, 2: 60, 3: 240, 4: 1440, 5: 0}[self.value]


class TAFSource(Enum):
    """Alert source identifiers."""
    WAZUH = "wazuh"
    SURICATA = "suricata"
    SYSLOG = "syslog"
    SIGMA = "sigma"
    CUSTOM = "custom"
    INTERNAL = "internal"
    THREAT_INTEL = "threat_intel"
    ML_ANOMALY = "ml_anomaly"
    SNORT = "snort"
    ZEEK = "zeek"
    OSQUERY = "osquery"
    ELASTIC = "elastic"

    @classmethod
    def from_string(cls, s: str) -> 'TAFSource':
        for member in cls:
            if member.value == s.strip().lower():
                return member
        return cls.CUSTOM


class TAFStatus(Enum):
    """Alert lifecycle status."""
    NEW = "new"
    NORMALIZED = "normalized"
    ENRICHED = "enriched"
    DEDUPLICATED = "deduplicated"
    DISPATCHED = "dispatched"
    DROPPED = "dropped"


# IOC patterns for auto-extraction
IOC_PATTERNS = {
    'ipv4': re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    ),
    'ipv6': re.compile(
        r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    ),
    'domain': re.compile(
        r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}\b'
    ),
    'md5': re.compile(r'\b[0-9a-fA-F]{32}\b'),
    'sha1': re.compile(r'\b[0-9a-fA-F]{40}\b'),
    'sha256': re.compile(r'\b[0-9a-fA-F]{64}\b'),
    'url': re.compile(
        r'https?://[^\s<>"\']+',
        re.IGNORECASE,
    ),
    'email': re.compile(
        r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
    ),
    'cve': re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE),
}

# IPs to exclude from IOC extraction (private, loopback, etc.)
PRIVATE_IP_PREFIXES = (
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.', '192.168.', '127.', '0.', '169.254.',
)


# ============================================================================
# TSUNAMI Alert Format (TAF) Dataclass
# ============================================================================

@dataclass
class TAFAlert:
    """
    Unified TSUNAMI Alert Format.
    All source-specific alerts are normalized to this format before dispatch.
    """
    # Identity
    alert_id: str = ""
    title: str = ""
    description: str = ""

    # Classification
    severity: TAFSeverity = TAFSeverity.INFO
    source: TAFSource = TAFSource.CUSTOM
    category: str = "general"
    status: TAFStatus = TAFStatus.NEW

    # MITRE ATT&CK
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    # Source context
    source_id: str = ""
    source_rule: str = ""
    source_raw: Dict[str, Any] = field(default_factory=dict)

    # Network / Asset
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    hostname: str = ""
    username: str = ""
    protocol: str = ""
    action: str = ""
    flow_id: str = ""

    # Scoring
    cvss_score: float = 0.0
    confidence: float = 0.8
    priority_score: float = 0.0

    # IOCs (auto-extracted)
    iocs: List[Dict[str, str]] = field(default_factory=list)

    # Enrichment (added by pipeline hooks)
    enrichment: Dict[str, Any] = field(default_factory=dict)

    # Dedup
    dedup_hash: str = ""
    is_duplicate: bool = False

    # Correlation hints
    correlation_keys: List[str] = field(default_factory=list)

    # Timestamps
    event_timestamp: str = ""
    normalized_at: str = ""

    def __post_init__(self):
        if not self.alert_id:
            self.alert_id = f"taf_{uuid.uuid4().hex[:16]}"
        if not self.normalized_at:
            self.normalized_at = datetime.now(timezone.utc).isoformat()
        if not self.event_timestamp:
            self.event_timestamp = self.normalized_at
        if self.priority_score == 0.0:
            self._compute_priority()

    def _compute_priority(self):
        """Compute composite priority score (0-100)."""
        # Base from severity
        sev_score = {1: 90, 2: 70, 3: 50, 4: 30, 5: 10}.get(self.severity.value, 10)
        # CVSS boost
        cvss_boost = min(10, self.cvss_score)
        # MITRE coverage boost
        mitre_boost = min(10, len(self.mitre_techniques) * 2)
        # Confidence factor
        conf_factor = self.confidence

        self.priority_score = round(
            (sev_score + cvss_boost + mitre_boost) * conf_factor, 1
        )

    def compute_dedup_hash(self) -> str:
        """Generate dedup hash from key fields."""
        dedup_str = (
            f"{self.source.value}|{self.source_rule}|{self.src_ip}|"
            f"{self.dst_ip}|{self.category}"
        )
        self.dedup_hash = hashlib.sha256(dedup_str.encode()).hexdigest()[:32]
        return self.dedup_hash

    def compute_correlation_keys(self) -> List[str]:
        """Generate keys for correlation with other alerts."""
        keys = []
        if self.src_ip:
            keys.append(f"src:{self.src_ip}")
        if self.dst_ip:
            keys.append(f"dst:{self.dst_ip}")
        if self.source_rule:
            keys.append(f"rule:{self.source.value}:{self.source_rule}")
        for tactic in self.mitre_tactics:
            keys.append(f"mitre:{tactic}")
        if self.hostname:
            keys.append(f"host:{self.hostname}")
        if self.username:
            keys.append(f"user:{self.username}")
        self.correlation_keys = keys
        return keys

    def to_dict(self) -> Dict[str, Any]:
        """Convert to serializable dict."""
        d = {}
        for k, v in asdict(self).items():
            if isinstance(v, Enum):
                d[k] = v.value
            elif k == 'severity':
                d[k] = self.severity.name
            elif k == 'source':
                d[k] = self.source.value
            elif k == 'status':
                d[k] = self.status.value
            else:
                d[k] = v
        # Fix enums that asdict converts
        d['severity'] = self.severity.name
        d['source'] = self.source.value
        d['status'] = self.status.value
        return d


# ============================================================================
# IOC Extractor
# ============================================================================

class IOCExtractor:
    """Extract Indicators of Compromise from alert text fields."""

    @staticmethod
    def extract(alert: TAFAlert, include_private_ips: bool = False) -> List[Dict[str, str]]:
        """
        Extract IOCs from alert title, description, and raw data.
        Returns list of {type, value} dicts.
        """
        # Combine text fields for scanning
        text = f"{alert.title}\n{alert.description}"
        if alert.source_raw:
            text += "\n" + json.dumps(alert.source_raw, default=str)

        iocs = []
        seen: Set[str] = set()

        for ioc_type, pattern in IOC_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group()

                # Skip private IPs unless requested
                if ioc_type == 'ipv4' and not include_private_ips:
                    if any(value.startswith(p) for p in PRIVATE_IP_PREFIXES):
                        continue

                # Skip common false positives
                if ioc_type == 'domain':
                    if value.endswith('.local') or value.endswith('.internal'):
                        continue

                key = f"{ioc_type}:{value}"
                if key not in seen:
                    seen.add(key)
                    iocs.append({'type': ioc_type, 'value': value})

        # Add explicit IPs from alert fields
        for ip_field in [alert.src_ip, alert.dst_ip]:
            if ip_field and f"ipv4:{ip_field}" not in seen:
                if include_private_ips or not any(ip_field.startswith(p) for p in PRIVATE_IP_PREFIXES):
                    seen.add(f"ipv4:{ip_field}")
                    iocs.append({'type': 'ipv4', 'value': ip_field})

        return iocs


# ============================================================================
# Source Adapter (Abstract Base)
# ============================================================================

class SourceAdapter(ABC):
    """Abstract base class for alert source adapters."""

    @property
    @abstractmethod
    def source_type(self) -> TAFSource:
        """The source type this adapter handles."""
        ...

    @abstractmethod
    def normalize(self, raw_data: Dict[str, Any]) -> Optional[TAFAlert]:
        """
        Convert source-specific alert data to TAFAlert.
        Returns None if the data cannot be normalized.
        """
        ...

    @property
    def name(self) -> str:
        return self.__class__.__name__


# ============================================================================
# Wazuh Adapter
# ============================================================================

class WazuhAdapter(SourceAdapter):
    """Convert Wazuh raw alerts to TAFAlert."""

    SEVERITY_MAP = {
        (0, 3): TAFSeverity.INFO,
        (4, 7): TAFSeverity.LOW,
        (8, 10): TAFSeverity.MEDIUM,
        (11, 13): TAFSeverity.HIGH,
        (14, 16): TAFSeverity.CRITICAL,
    }

    MITRE_MAP = {
        'authentication_failed': (['TA0006'], ['T1110']),
        'authentication_success': (['TA0001'], ['T1078']),
        'web_attack': (['TA0001'], ['T1190']),
        'rootkit': (['TA0003'], ['T1014']),
        'syscheck': (['TA0007'], ['T1083']),
        'vulnerability-detector': (['TA0001'], ['T1190']),
        'ids': (['TA0001'], ['T1190']),
    }

    @property
    def source_type(self) -> TAFSource:
        return TAFSource.WAZUH

    def normalize(self, raw: Dict[str, Any]) -> Optional[TAFAlert]:
        """Normalize a Wazuh raw alert dict."""
        rule = raw.get('rule', {})
        agent = raw.get('agent', {})
        data = raw.get('data', {})
        predecoder = raw.get('predecoder', {})
        decoder = raw.get('decoder', {})

        if not rule:
            return None

        rule_level = int(rule.get('level', 0))
        severity = self._map_severity(rule_level)
        rule_groups = rule.get('groups', [])

        # MITRE
        mitre_tactics, mitre_techniques = self._extract_mitre(rule, rule_groups)

        # Category
        category = self._map_category(rule_groups)

        # Network
        src_ip = (data.get('srcip', '') or data.get('src_ip', '')
                  or raw.get('srcip', '') or predecoder.get('srcip', ''))
        dst_ip = (data.get('dstip', '') or data.get('dst_ip', '')
                  or raw.get('dstip', '') or predecoder.get('dstip', ''))
        src_port = int(data.get('srcport', 0) or data.get('src_port', 0) or 0)
        dst_port = int(data.get('dstport', 0) or data.get('dst_port', 0) or 0)

        rule_desc = rule.get('description', 'Wazuh Alert')
        hostname = agent.get('name', '') or data.get('hostname', '')
        timestamp = raw.get('timestamp', datetime.now(timezone.utc).isoformat())

        cvss = min(10.0, round(rule_level * 0.625, 1))

        return TAFAlert(
            alert_id=f"wazuh_{raw.get('id', uuid.uuid4().hex[:12])}",
            title=f"[Wazuh:{rule.get('id', '?')}] {rule_desc}"[:256],
            description=(
                f"{rule_desc}\n"
                f"Agent: {hostname} ({agent.get('id', 'N/A')})\n"
                f"Rule: {rule.get('id', 'N/A')} (Level {rule_level})\n"
                f"Groups: {', '.join(rule_groups)}\n"
                f"Decoder: {decoder.get('name', 'N/A')}"
            ),
            severity=severity,
            source=TAFSource.WAZUH,
            category=category,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            tags=rule_groups,
            source_id=str(raw.get('id', '')),
            source_rule=str(rule.get('id', '')),
            source_raw=raw,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            hostname=hostname,
            username=data.get('srcuser', '') or data.get('dstuser', ''),
            cvss_score=cvss,
            event_timestamp=timestamp,
        )

    def _map_severity(self, level: int) -> TAFSeverity:
        for (lo, hi), sev in self.SEVERITY_MAP.items():
            if lo <= level <= hi:
                return sev
        return TAFSeverity.INFO

    def _extract_mitre(self, rule: Dict, groups: List[str]) -> Tuple[List[str], List[str]]:
        tactics, techniques = [], []

        mitre = rule.get('mitre', {})
        if mitre:
            tactics = mitre.get('tactic', [])
            techniques = [
                t.get('id', '') for t in mitre.get('technique', [])
                if isinstance(t, dict)
            ]
            if not techniques:
                techniques = mitre.get('id', [])

        if not tactics:
            for group in groups:
                gl = group.lower()
                if gl in self.MITRE_MAP:
                    t, tech = self.MITRE_MAP[gl]
                    tactics.extend(t)
                    techniques.extend(tech)

        return list(dict.fromkeys(tactics)), list(dict.fromkeys(techniques))

    def _map_category(self, groups: List[str]) -> str:
        for group in groups:
            gl = group.lower()
            if 'authentication' in gl:
                return 'authentication'
            elif 'web' in gl:
                return 'web_attack'
            elif 'malware' in gl or 'rootkit' in gl:
                return 'malware'
            elif 'ids' in gl or 'attack' in gl:
                return 'intrusion'
            elif 'syscheck' in gl or 'fim' in gl:
                return 'file_integrity'
            elif 'vulnerability' in gl:
                return 'vulnerability'
            elif 'policy' in gl or 'sca' in gl:
                return 'policy_violation'
        return 'general'


# ============================================================================
# Suricata Adapter
# ============================================================================

class SuricataAdapter(SourceAdapter):
    """Convert Suricata EVE JSON alerts to TAFAlert."""

    SEVERITY_MAP = {
        1: TAFSeverity.CRITICAL,
        2: TAFSeverity.HIGH,
        3: TAFSeverity.MEDIUM,
        4: TAFSeverity.LOW,
        255: TAFSeverity.INFO,
    }

    MITRE_MAP = {
        'trojan-activity': (['TA0011'], ['T1071']),
        'attempted-admin': (['TA0004'], ['T1068']),
        'attempted-user': (['TA0006'], ['T1110']),
        'web-application-attack': (['TA0001'], ['T1190']),
        'web-application-activity': (['TA0001'], ['T1190']),
        'attempted-dos': (['TA0040'], ['T1499']),
        'attempted-recon': (['TA0043'], ['T1595']),
        'successful-recon-limited': (['TA0007'], ['T1082']),
        'successful-recon-largescale': (['TA0007'], ['T1046']),
        'misc-attack': (['TA0002'], ['T1059']),
        'shellcode-detect': (['TA0002'], ['T1059']),
        'policy-violation': (['TA0005'], ['T1562']),
        'network-scan': (['TA0043'], ['T1595']),
        'denial-of-service': (['TA0040'], ['T1498']),
        'exploit-kit': (['TA0001'], ['T1189']),
        'domain-c2': (['TA0011'], ['T1071.001']),
        'default-login-attempt': (['TA0006'], ['T1110.001']),
        'credential-theft': (['TA0006'], ['T1003']),
        'malware-cnc': (['TA0011'], ['T1071']),
    }

    CATEGORY_MAP = {
        'ET MALWARE': 'malware',
        'ET TROJAN': 'malware',
        'ET CNC': 'command_and_control',
        'ET EXPLOIT': 'exploit',
        'ET WEB_SERVER': 'web_attack',
        'ET WEB_CLIENT': 'web_attack',
        'ET SCAN': 'reconnaissance',
        'ET DOS': 'denial_of_service',
        'ET POLICY': 'policy_violation',
        'ET INFO': 'informational',
        'ET DNS': 'dns_anomaly',
        'ET HUNTING': 'threat_hunting',
        'ET TOR': 'anonymization',
        'ET CURRENT_EVENTS': 'current_threat',
        'GPL': 'general',
        'SURICATA': 'protocol_anomaly',
    }

    @property
    def source_type(self) -> TAFSource:
        return TAFSource.SURICATA

    def normalize(self, raw: Dict[str, Any]) -> Optional[TAFAlert]:
        """Normalize a Suricata EVE JSON alert."""
        if raw.get('event_type') != 'alert':
            return None

        alert = raw.get('alert', {})
        if not alert:
            return None

        severity_id = int(alert.get('severity', 4))
        severity = self.SEVERITY_MAP.get(severity_id, TAFSeverity.LOW)

        classtype = alert.get('category', '').lower().replace(' ', '-')
        mitre_tactics, mitre_techniques = self._extract_mitre(classtype, alert)

        sig_msg = alert.get('signature', '')
        category = self._map_category(sig_msg)

        sid = str(alert.get('signature_id', ''))
        gid = str(alert.get('gid', 1))
        rev = str(alert.get('rev', 0))

        src_ip = raw.get('src_ip', '')
        dst_ip = raw.get('dest_ip', '')
        action = alert.get('action', 'allowed')

        if severity_id <= 1:
            cvss = 9.5
        elif severity_id == 2:
            cvss = 7.5
        elif severity_id == 3:
            cvss = 5.0
        else:
            cvss = 2.5

        hostname = raw.get('host', '') or raw.get('in_iface', '')
        timestamp = raw.get('timestamp', datetime.now(timezone.utc).isoformat())

        return TAFAlert(
            alert_id=f"suricata_{sid}_{hashlib.md5(f'{src_ip}{dst_ip}{timestamp}'.encode()).hexdigest()[:8]}",
            title=f"[Suricata:{gid}:{sid}:{rev}] {sig_msg}"[:256],
            description=(
                f"{sig_msg}\n"
                f"SID: {gid}:{sid}:{rev}\n"
                f"Category: {alert.get('category', 'N/A')}\n"
                f"Action: {action}\n"
                f"Protocol: {raw.get('proto', '')}\n"
                f"Interface: {raw.get('in_iface', 'N/A')}\n"
                f"Flow ID: {raw.get('flow_id', 'N/A')}"
            ),
            severity=severity,
            source=TAFSource.SURICATA,
            category=category,
            mitre_tactics=mitre_tactics,
            mitre_techniques=mitre_techniques,
            tags=[f"sid:{sid}", f"classtype:{classtype}", f"action:{action}"],
            source_id=f"{gid}:{sid}:{rev}",
            source_rule=sid,
            source_raw=raw,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(raw.get('src_port', 0)),
            dst_port=int(raw.get('dest_port', 0)),
            hostname=hostname,
            protocol=raw.get('proto', '').upper(),
            action=action,
            flow_id=str(raw.get('flow_id', '')),
            cvss_score=cvss,
            event_timestamp=timestamp,
        )

    def _extract_mitre(self, classtype: str, alert: Dict) -> Tuple[List[str], List[str]]:
        tactics, techniques = [], []
        if classtype in self.MITRE_MAP:
            tactics, techniques = self.MITRE_MAP[classtype]
            tactics = list(tactics)
            techniques = list(techniques)

        metadata = alert.get('metadata', {})
        if metadata:
            for key, vals in metadata.items():
                kl = key.lower()
                if 'mitre_tactic' in kl:
                    tactics.extend(vals if isinstance(vals, list) else [vals])
                elif 'mitre_technique' in kl:
                    techniques.extend(vals if isinstance(vals, list) else [vals])

        return list(dict.fromkeys(tactics)), list(dict.fromkeys(techniques))

    def _map_category(self, sig_msg: str) -> str:
        for prefix, cat in self.CATEGORY_MAP.items():
            if sig_msg.upper().startswith(prefix):
                return cat
        return 'general'


# ============================================================================
# Syslog Adapter
# ============================================================================

class SyslogAdapter(SourceAdapter):
    """Convert raw syslog lines/parsed dicts to TAFAlert."""

    # Common syslog severity (RFC 5424)
    SYSLOG_SEVERITY = {
        0: TAFSeverity.CRITICAL,   # Emergency
        1: TAFSeverity.CRITICAL,   # Alert
        2: TAFSeverity.CRITICAL,   # Critical
        3: TAFSeverity.HIGH,       # Error
        4: TAFSeverity.MEDIUM,     # Warning
        5: TAFSeverity.LOW,        # Notice
        6: TAFSeverity.INFO,       # Informational
        7: TAFSeverity.INFO,       # Debug
    }

    SYSLOG_LINE_RE = re.compile(
        r'^<(\d+)>'                        # Priority
        r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+' # Timestamp
        r'(\S+)\s+'                         # Hostname
        r'(\S+?)(?:\[(\d+)\])?\s*:\s*'     # Program[PID]
        r'(.*)$'                            # Message
    )

    @property
    def source_type(self) -> TAFSource:
        return TAFSource.SYSLOG

    def normalize(self, raw: Dict[str, Any]) -> Optional[TAFAlert]:
        """Normalize syslog data. Accepts dict with parsed fields or 'raw_line'."""
        # If raw_line is provided, parse it first
        if 'raw_line' in raw:
            parsed = self._parse_syslog_line(raw['raw_line'])
            if not parsed:
                return None
            raw = {**parsed, **raw}

        message = raw.get('message', '')
        if not message:
            return None

        facility = raw.get('facility', 0)
        sev_num = raw.get('severity_num', 6)
        severity = self.SYSLOG_SEVERITY.get(sev_num, TAFSeverity.INFO)

        hostname = raw.get('hostname', '')
        program = raw.get('program', '')
        pid = raw.get('pid', '')
        timestamp = raw.get('timestamp', datetime.now(timezone.utc).isoformat())

        # Try to extract IPs from message
        ips = IOC_PATTERNS['ipv4'].findall(message)
        src_ip = ips[0] if len(ips) > 0 else ''
        dst_ip = ips[1] if len(ips) > 1 else ''

        # Category hints from program/message
        category = self._guess_category(program, message)

        return TAFAlert(
            alert_id=f"syslog_{uuid.uuid4().hex[:12]}",
            title=f"[Syslog:{hostname}:{program}] {message[:120]}"[:256],
            description=(
                f"Message: {message}\n"
                f"Host: {hostname}\n"
                f"Program: {program} (PID: {pid})\n"
                f"Facility: {facility}, Severity: {sev_num}"
            ),
            severity=severity,
            source=TAFSource.SYSLOG,
            category=category,
            source_raw=raw,
            src_ip=src_ip,
            dst_ip=dst_ip,
            hostname=hostname,
            event_timestamp=timestamp,
        )

    def _parse_syslog_line(self, line: str) -> Optional[Dict]:
        m = self.SYSLOG_LINE_RE.match(line)
        if not m:
            return None

        priority = int(m.group(1))
        facility = priority >> 3
        severity_num = priority & 0x07

        return {
            'facility': facility,
            'severity_num': severity_num,
            'timestamp': m.group(2),
            'hostname': m.group(3),
            'program': m.group(4),
            'pid': m.group(5) or '',
            'message': m.group(6),
        }

    def _guess_category(self, program: str, message: str) -> str:
        prog_lower = program.lower()
        msg_lower = message.lower()
        combined = f"{prog_lower} {msg_lower}"

        if any(k in combined for k in ['sshd', 'login', 'auth', 'pam']):
            return 'authentication'
        elif any(k in combined for k in ['firewall', 'iptables', 'nftables', 'ufw']):
            return 'firewall'
        elif any(k in combined for k in ['apache', 'nginx', 'httpd']):
            return 'web_server'
        elif any(k in combined for k in ['sudo', 'su:', 'privilege']):
            return 'privilege_escalation'
        elif any(k in combined for k in ['malware', 'virus', 'trojan']):
            return 'malware'
        return 'general'


# ============================================================================
# Generic / Passthrough Adapter
# ============================================================================

class GenericAdapter(SourceAdapter):
    """
    Generic adapter that accepts pre-formatted dicts.
    Expects dict with at least: title, severity (string), source (string).
    """

    @property
    def source_type(self) -> TAFSource:
        return TAFSource.CUSTOM

    def normalize(self, raw: Dict[str, Any]) -> Optional[TAFAlert]:
        if 'title' not in raw:
            return None

        return TAFAlert(
            alert_id=raw.get('alert_id', f"custom_{uuid.uuid4().hex[:12]}"),
            title=raw.get('title', '')[:256],
            description=raw.get('description', ''),
            severity=TAFSeverity.from_string(raw.get('severity', 'INFO')),
            source=TAFSource.from_string(raw.get('source', 'custom')),
            category=raw.get('category', 'general'),
            mitre_tactics=raw.get('mitre_tactics', []),
            mitre_techniques=raw.get('mitre_techniques', []),
            tags=raw.get('tags', []),
            source_id=raw.get('source_id', ''),
            source_rule=raw.get('source_rule', ''),
            source_raw=raw,
            src_ip=raw.get('src_ip', ''),
            dst_ip=raw.get('dst_ip', ''),
            src_port=int(raw.get('src_port', 0)),
            dst_port=int(raw.get('dst_port', 0)),
            hostname=raw.get('hostname', ''),
            username=raw.get('username', ''),
            cvss_score=float(raw.get('cvss_score', 0.0)),
            confidence=float(raw.get('confidence', 0.8)),
            event_timestamp=raw.get('timestamp', ''),
        )


# ============================================================================
# Severity Override Rules
# ============================================================================

@dataclass
class SeverityOverride:
    """Rule to override alert severity based on conditions."""
    name: str
    condition: Callable[[TAFAlert], bool]
    new_severity: TAFSeverity

    def apply(self, alert: TAFAlert) -> bool:
        if self.condition(alert):
            alert.severity = self.new_severity
            alert._compute_priority()
            return True
        return False


# ============================================================================
# Alert Normalization Pipeline
# ============================================================================

class AlertNormalizationPipeline:
    """
    Central pipeline that normalizes alerts from multiple sources,
    applies enrichment, deduplication, and dispatches to subscribers.
    """

    def __init__(self, db_path: Optional[str] = None,
                 dedup_window_minutes: int = 60):
        if db_path is None:
            db_dir = Path.home() / '.dalga'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'soc_normalizer.db')

        self.db_path = db_path
        self.dedup_window = dedup_window_minutes

        # Adapters
        self._adapters: Dict[str, SourceAdapter] = {}
        self._default_adapters()

        # Hooks
        self._pre_hooks: List[Callable[[TAFAlert], Optional[TAFAlert]]] = []
        self._post_hooks: List[Callable[[TAFAlert], Optional[TAFAlert]]] = []

        # Severity overrides
        self._severity_overrides: List[SeverityOverride] = []

        # Subscribers
        self._subscribers: List[Callable[[TAFAlert], None]] = []

        # State
        self._lock = threading.Lock()
        self._stats = {
            'received': 0,
            'normalized': 0,
            'dropped': 0,
            'duplicates': 0,
            'dispatched': 0,
            'errors': 0,
            'by_source': {},
            'by_severity': {},
        }

        self._init_db()

    def _default_adapters(self):
        """Register built-in adapters."""
        for adapter in [WazuhAdapter(), SuricataAdapter(), SyslogAdapter(), GenericAdapter()]:
            self._adapters[adapter.source_type.value] = adapter

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS normalized_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_id TEXT UNIQUE NOT NULL,
                    title TEXT,
                    severity TEXT,
                    source TEXT,
                    category TEXT,
                    status TEXT DEFAULT 'normalized',
                    src_ip TEXT,
                    dst_ip TEXT,
                    dedup_hash TEXT,
                    priority_score REAL,
                    event_timestamp TEXT,
                    normalized_at TEXT,
                    data_json TEXT
                );

                CREATE TABLE IF NOT EXISTS dedup_cache (
                    hash TEXT PRIMARY KEY,
                    first_seen TEXT,
                    last_seen TEXT,
                    count INTEGER DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_norm_ts
                    ON normalized_alerts(normalized_at);
                CREATE INDEX IF NOT EXISTS idx_norm_severity
                    ON normalized_alerts(severity);
                CREATE INDEX IF NOT EXISTS idx_norm_source
                    ON normalized_alerts(source);
                CREATE INDEX IF NOT EXISTS idx_dedup_last
                    ON dedup_cache(last_seen);
            """)
            conn.commit()
        finally:
            conn.close()

    # ---- Adapter Management ----

    def register_adapter(self, source_name: str, adapter: SourceAdapter):
        """Register a custom source adapter."""
        self._adapters[source_name] = adapter
        logger.info(f"[NORMALIZER] Registered adapter: {source_name} ({adapter.name})")

    def get_adapter(self, source_name: str) -> Optional[SourceAdapter]:
        return self._adapters.get(source_name)

    @property
    def adapters(self) -> Dict[str, str]:
        """List registered adapters."""
        return {k: v.name for k, v in self._adapters.items()}

    # ---- Hook Management ----

    def add_pre_hook(self, hook: Callable[[TAFAlert], Optional[TAFAlert]]):
        """Add pre-normalization hook. Return None to drop the alert."""
        self._pre_hooks.append(hook)

    def add_post_hook(self, hook: Callable[[TAFAlert], Optional[TAFAlert]]):
        """Add post-normalization hook. Return None to drop the alert."""
        self._post_hooks.append(hook)

    def add_severity_override(self, override: SeverityOverride):
        """Add a severity override rule."""
        self._severity_overrides.append(override)

    # ---- Subscriber Management ----

    def subscribe(self, callback: Callable[[TAFAlert], None]):
        """Register a subscriber for normalized alerts."""
        self._subscribers.append(callback)

    # ---- Main Pipeline ----

    def ingest(self, raw_data: Dict[str, Any], source: str = "custom") -> Optional[TAFAlert]:
        """
        Main entry point: ingest raw alert data and push through pipeline.

        Pipeline stages:
        1. Adapter selection & normalization
        2. Pre-hooks
        3. IOC extraction
        4. Severity overrides
        5. Dedup hash + check
        6. Correlation keys
        7. Post-hooks
        8. Persistence
        9. Dispatch to subscribers

        Returns the TAFAlert if dispatched, None if dropped/deduplicated.
        """
        with self._lock:
            self._stats['received'] += 1
            self._stats['by_source'][source] = self._stats['by_source'].get(source, 0) + 1

        # 1. Select adapter and normalize
        adapter = self._adapters.get(source)
        if not adapter:
            adapter = self._adapters.get('custom')

        try:
            alert = adapter.normalize(raw_data)
        except Exception as e:
            logger.error(f"[NORMALIZER] Adapter '{source}' error: {e}")
            with self._lock:
                self._stats['errors'] += 1
            return None

        if alert is None:
            with self._lock:
                self._stats['dropped'] += 1
            return None

        alert.status = TAFStatus.NORMALIZED

        # 2. Pre-hooks
        for hook in self._pre_hooks:
            try:
                result = hook(alert)
                if result is None:
                    with self._lock:
                        self._stats['dropped'] += 1
                    return None
                alert = result
            except Exception as e:
                logger.debug(f"[NORMALIZER] Pre-hook error: {e}")

        # 3. IOC extraction
        alert.iocs = IOCExtractor.extract(alert)

        # 4. Severity overrides
        for override in self._severity_overrides:
            try:
                override.apply(alert)
            except Exception:
                pass

        # 5. Dedup
        alert.compute_dedup_hash()
        if self._check_dedup(alert):
            alert.is_duplicate = True
            alert.status = TAFStatus.DEDUPLICATED
            with self._lock:
                self._stats['duplicates'] += 1
            return None

        # 6. Correlation keys
        alert.compute_correlation_keys()

        # 7. Post-hooks (enrichment etc.)
        alert.status = TAFStatus.ENRICHED
        for hook in self._post_hooks:
            try:
                result = hook(alert)
                if result is None:
                    with self._lock:
                        self._stats['dropped'] += 1
                    return None
                alert = result
            except Exception as e:
                logger.debug(f"[NORMALIZER] Post-hook error: {e}")

        # 8. Persist
        self._persist_alert(alert)

        with self._lock:
            self._stats['normalized'] += 1
            sev_name = alert.severity.name
            self._stats['by_severity'][sev_name] = (
                self._stats['by_severity'].get(sev_name, 0) + 1
            )

        # 9. Dispatch
        alert.status = TAFStatus.DISPATCHED
        for sub in self._subscribers:
            try:
                sub(alert)
            except Exception as e:
                logger.error(f"[NORMALIZER] Subscriber error: {e}")

        with self._lock:
            self._stats['dispatched'] += 1

        return alert

    def _check_dedup(self, alert: TAFAlert) -> bool:
        """Check if alert is a duplicate within the dedup window."""
        if not alert.dedup_hash:
            return False

        conn = self._get_conn()
        now = datetime.now(timezone.utc)
        cutoff = (now - timedelta(minutes=self.dedup_window)).isoformat()

        try:
            row = conn.execute(
                "SELECT count, last_seen FROM dedup_cache WHERE hash = ?",
                (alert.dedup_hash,)
            ).fetchone()

            if row and row['last_seen'] >= cutoff:
                # Duplicate within window - update count
                conn.execute(
                    "UPDATE dedup_cache SET count = count + 1, last_seen = ? WHERE hash = ?",
                    (now.isoformat(), alert.dedup_hash)
                )
                conn.commit()
                return True

            # Not a dupe (or outside window) - insert/update
            conn.execute("""
                INSERT INTO dedup_cache (hash, first_seen, last_seen, count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(hash) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    count = 1
            """, (alert.dedup_hash, now.isoformat(), now.isoformat()))
            conn.commit()
            return False
        finally:
            conn.close()

    def _persist_alert(self, alert: TAFAlert):
        """Store normalized alert in DB."""
        conn = self._get_conn()
        try:
            conn.execute("""
                INSERT OR IGNORE INTO normalized_alerts
                (alert_id, title, severity, source, category, status,
                 src_ip, dst_ip, dedup_hash, priority_score,
                 event_timestamp, normalized_at, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id,
                alert.title,
                alert.severity.name,
                alert.source.value,
                alert.category,
                alert.status.value,
                alert.src_ip,
                alert.dst_ip,
                alert.dedup_hash,
                alert.priority_score,
                alert.event_timestamp,
                alert.normalized_at,
                json.dumps(alert.to_dict(), default=str),
            ))
            conn.commit()
        except Exception as e:
            logger.error(f"[NORMALIZER] Persist error: {e}")
        finally:
            conn.close()

    # ---- Queries ----

    def get_recent_alerts(self, hours: int = 24, limit: int = 50) -> List[Dict]:
        """Get recent normalized alerts."""
        try:
            conn = self._get_conn()
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            rows = conn.execute("""
                SELECT alert_id, title, severity, source, category,
                       src_ip, dst_ip, priority_score, normalized_at
                FROM normalized_alerts
                WHERE normalized_at >= ?
                ORDER BY priority_score DESC
                LIMIT ?
            """, (since, limit)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            return []

    def get_source_distribution(self) -> Dict[str, int]:
        """Get count of alerts by source."""
        try:
            conn = self._get_conn()
            rows = conn.execute("""
                SELECT source, COUNT(*) as cnt
                FROM normalized_alerts
                GROUP BY source
            """).fetchall()
            conn.close()
            return {r['source']: r['cnt'] for r in rows}
        except sqlite3.OperationalError:
            return {}

    def get_severity_distribution(self) -> Dict[str, int]:
        """Get count of alerts by severity."""
        try:
            conn = self._get_conn()
            rows = conn.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM normalized_alerts
                GROUP BY severity
            """).fetchall()
            conn.close()
            return {r['severity']: r['cnt'] for r in rows}
        except sqlite3.OperationalError:
            return {}

    def cleanup_dedup_cache(self, older_than_hours: int = 24):
        """Remove expired entries from dedup cache."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=older_than_hours)).isoformat()
        conn = self._get_conn()
        try:
            deleted = conn.execute(
                "DELETE FROM dedup_cache WHERE last_seen < ?", (cutoff,)
            ).rowcount
            conn.commit()
            return deleted
        finally:
            conn.close()

    # ---- Stats ----

    @property
    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_normalizer_blueprint(pipeline: Optional[AlertNormalizationPipeline] = None):
    """Create Flask Blueprint for Normalization Pipeline API."""
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        return None

    if pipeline is None:
        pipeline = AlertNormalizationPipeline()

    bp = Blueprint('soc_normalizer', __name__, url_prefix='/api/v1/soc/normalizer')

    @bp.route('/status', methods=['GET'])
    def status():
        return jsonify({
            'success': True,
            'data': {
                'stats': pipeline.stats,
                'adapters': pipeline.adapters,
                'dedup_window_minutes': pipeline.dedup_window,
            }
        })

    @bp.route('/ingest', methods=['POST'])
    def ingest_alert():
        data = request.get_json(silent=True)
        if not data:
            return jsonify({'success': False, 'error': 'JSON body required'}), 400

        source = data.pop('_source', 'custom')
        alert = pipeline.ingest(data, source=source)

        if alert:
            return jsonify({
                'success': True,
                'data': {
                    'alert_id': alert.alert_id,
                    'severity': alert.severity.name,
                    'priority': alert.priority_score,
                    'status': alert.status.value,
                }
            })
        return jsonify({
            'success': True,
            'data': {'status': 'dropped_or_deduplicated'}
        })

    @bp.route('/alerts', methods=['GET'])
    def recent_alerts():
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 50, type=int)
        return jsonify({
            'success': True,
            'data': pipeline.get_recent_alerts(hours, limit),
        })

    @bp.route('/distribution/source', methods=['GET'])
    def source_dist():
        return jsonify({
            'success': True,
            'data': pipeline.get_source_distribution(),
        })

    @bp.route('/distribution/severity', methods=['GET'])
    def severity_dist():
        return jsonify({
            'success': True,
            'data': pipeline.get_severity_distribution(),
        })

    @bp.route('/adapters', methods=['GET'])
    def list_adapters():
        return jsonify({
            'success': True,
            'data': pipeline.adapters,
        })

    @bp.route('/dedup/cleanup', methods=['POST'])
    def cleanup_dedup():
        hours = request.args.get('hours', 24, type=int)
        deleted = pipeline.cleanup_dedup_cache(hours)
        return jsonify({
            'success': True,
            'data': {'deleted': deleted},
        })

    return bp


# ============================================================================
# Global Instance
# ============================================================================

_pipeline: Optional[AlertNormalizationPipeline] = None
_pl_lock = threading.Lock()


def get_normalization_pipeline() -> AlertNormalizationPipeline:
    global _pipeline
    if _pipeline is None:
        with _pl_lock:
            if _pipeline is None:
                _pipeline = AlertNormalizationPipeline()
    return _pipeline


__all__ = [
    'TAFSeverity', 'TAFSource', 'TAFStatus', 'TAFAlert',
    'IOCExtractor', 'IOC_PATTERNS',
    'SourceAdapter', 'WazuhAdapter', 'SuricataAdapter', 'SyslogAdapter', 'GenericAdapter',
    'SeverityOverride', 'AlertNormalizationPipeline',
    'create_normalizer_blueprint', 'get_normalization_pipeline',
]
