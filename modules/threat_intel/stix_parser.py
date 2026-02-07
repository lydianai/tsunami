#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI STIX 2.1 Parser v5.0
    Parse STIX Bundles and Extract Threat Intelligence
================================================================================

    Features:
    - Parse STIX 2.1 bundles (JSON)
    - Extract indicators (IPs, domains, hashes, URLs)
    - Extract malware information
    - Extract attack patterns
    - Map to MITRE ATT&CK framework

================================================================================
"""

import re
import json
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

# Optional STIX2 library
try:
    import stix2
    from stix2 import (
        Bundle, Indicator, Malware, AttackPattern,
        ThreatActor, Campaign, IntrusionSet,
        Relationship, Tool, Vulnerability
    )
    from stix2.parsing import parse as stix_parse
    STIX2_AVAILABLE = True
except ImportError:
    STIX2_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class IndicatorType(Enum):
    """Types of indicators"""
    IPV4 = "ipv4-addr"
    IPV6 = "ipv6-addr"
    DOMAIN = "domain-name"
    URL = "url"
    EMAIL = "email-addr"
    HASH_MD5 = "file:hashes.MD5"
    HASH_SHA1 = "file:hashes.SHA-1"
    HASH_SHA256 = "file:hashes.SHA-256"
    FILE_NAME = "file:name"
    REGISTRY_KEY = "windows-registry-key:key"
    PROCESS_NAME = "process:name"
    USER_AGENT = "network-traffic:extensions.'http-request-ext'.request_header.'User-Agent'"
    X509_SERIAL = "x509-certificate:serial_number"
    MUTEX = "mutex:name"
    CVE = "vulnerability:name"


@dataclass
class ParsedIndicator:
    """Parsed indicator from STIX"""
    id: str
    type: str
    value: str
    pattern: str = ""
    pattern_type: str = "stix"
    name: str = ""
    description: str = ""
    confidence: int = 0
    valid_from: Optional[str] = None
    valid_until: Optional[str] = None
    kill_chain_phases: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    external_references: List[dict] = field(default_factory=list)
    created: Optional[str] = None
    modified: Optional[str] = None
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParsedMalware:
    """Parsed malware from STIX"""
    id: str
    name: str
    malware_types: List[str] = field(default_factory=list)
    is_family: bool = False
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    kill_chain_phases: List[str] = field(default_factory=list)
    capabilities: List[str] = field(default_factory=list)
    sample_refs: List[str] = field(default_factory=list)
    operating_system_refs: List[str] = field(default_factory=list)
    architecture_execution_envs: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    external_references: List[dict] = field(default_factory=list)
    created: Optional[str] = None
    modified: Optional[str] = None
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParsedAttackPattern:
    """Parsed attack pattern (MITRE ATT&CK technique)"""
    id: str
    name: str
    description: str = ""
    aliases: List[str] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    external_references: List[dict] = field(default_factory=list)
    mitre_id: str = ""  # e.g., T1566
    mitre_name: str = ""
    tactic: str = ""
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection: str = ""
    created: Optional[str] = None
    modified: Optional[str] = None
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ParsedThreatActor:
    """Parsed threat actor"""
    id: str
    name: str
    threat_actor_types: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    sophistication: str = ""
    resource_level: str = ""
    primary_motivation: str = ""
    secondary_motivations: List[str] = field(default_factory=list)
    personal_motivations: List[str] = field(default_factory=list)
    goals: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    labels: List[str] = field(default_factory=list)
    external_references: List[dict] = field(default_factory=list)
    created: Optional[str] = None
    modified: Optional[str] = None
    source: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class MITREMapper:
    """Map indicators and patterns to MITRE ATT&CK framework"""

    # MITRE ATT&CK Tactics mapping
    TACTICS = {
        'reconnaissance': 'TA0043',
        'resource-development': 'TA0042',
        'initial-access': 'TA0001',
        'execution': 'TA0002',
        'persistence': 'TA0003',
        'privilege-escalation': 'TA0004',
        'defense-evasion': 'TA0005',
        'credential-access': 'TA0006',
        'discovery': 'TA0007',
        'lateral-movement': 'TA0008',
        'collection': 'TA0009',
        'command-and-control': 'TA0011',
        'exfiltration': 'TA0010',
        'impact': 'TA0040'
    }

    # Common techniques by indicator type
    INDICATOR_TECHNIQUES = {
        'ipv4-addr': ['T1071', 'T1095', 'T1573'],  # Application Layer Protocol, C2
        'domain-name': ['T1071', 'T1568', 'T1583'],  # Application Layer Protocol, Dynamic Resolution
        'url': ['T1071.001', 'T1102', 'T1566.002'],  # Web Protocols, Web Service
        'file:hashes': ['T1027', 'T1036', 'T1059'],  # Obfuscation, Masquerading
        'email-addr': ['T1566.001', 'T1598'],  # Spearphishing Attachment
        'windows-registry-key': ['T1547.001', 'T1112'],  # Registry Run Keys
        'process': ['T1055', 'T1106'],  # Process Injection
    }

    # Malware type to technique mapping
    MALWARE_TECHNIQUES = {
        'backdoor': ['T1059', 'T1071', 'T1095', 'T1543'],
        'bot': ['T1071', 'T1095', 'T1219'],
        'ddos': ['T1498', 'T1499'],
        'downloader': ['T1105', 'T1129'],
        'dropper': ['T1204', 'T1059'],
        'exploit-kit': ['T1189', 'T1190', 'T1203'],
        'keylogger': ['T1056.001'],
        'ransomware': ['T1486', 'T1490', 'T1489'],
        'remote-access-trojan': ['T1219', 'T1071', 'T1059'],
        'rootkit': ['T1014', 'T1564'],
        'screen-capture': ['T1113'],
        'spyware': ['T1056', 'T1113', 'T1125'],
        'trojan': ['T1204', 'T1059', 'T1071'],
        'virus': ['T1091'],
        'webshell': ['T1505.003'],
        'wiper': ['T1485', 'T1561'],
        'worm': ['T1091', 'T1080'],
        'adware': ['T1176'],
        'cryptominer': ['T1496']
    }

    @classmethod
    def get_techniques_for_indicator(cls, indicator_type: str) -> List[str]:
        """Get likely MITRE techniques for indicator type"""
        for key, techniques in cls.INDICATOR_TECHNIQUES.items():
            if key in indicator_type.lower():
                return techniques
        return []

    @classmethod
    def get_techniques_for_malware(cls, malware_types: List[str]) -> List[str]:
        """Get likely MITRE techniques for malware types"""
        techniques = set()
        for mtype in malware_types:
            mtype_lower = mtype.lower().replace('_', '-')
            if mtype_lower in cls.MALWARE_TECHNIQUES:
                techniques.update(cls.MALWARE_TECHNIQUES[mtype_lower])
        return list(techniques)

    @classmethod
    def get_tactic_id(cls, tactic_name: str) -> Optional[str]:
        """Get MITRE tactic ID from name"""
        return cls.TACTICS.get(tactic_name.lower().replace(' ', '-'))

    @classmethod
    def extract_mitre_id(cls, external_references: List[dict]) -> Optional[str]:
        """Extract MITRE ATT&CK ID from external references"""
        for ref in external_references:
            if ref.get('source_name') == 'mitre-attack':
                ext_id = ref.get('external_id', '')
                if ext_id.startswith('T') or ext_id.startswith('TA'):
                    return ext_id
        return None


class STIXParser:
    """
    STIX 2.1 Bundle Parser

    Parses STIX bundles and extracts:
    - Indicators (IPs, domains, hashes, URLs)
    - Malware information
    - Attack patterns (MITRE ATT&CK techniques)
    - Threat actors
    - Relationships
    """

    # STIX pattern regex patterns
    PATTERN_REGEXES = {
        'ipv4': re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
        'ipv6': re.compile(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]"),
        'domain': re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]"),
        'url': re.compile(r"\[url:value\s*=\s*'([^']+)'\]"),
        'email': re.compile(r"\[email-addr:value\s*=\s*'([^']+)'\]"),
        'md5': re.compile(r"\[file:hashes\.'MD5'\s*=\s*'([^']+)'\]"),
        'sha1': re.compile(r"\[file:hashes\.'SHA-1'\s*=\s*'([^']+)'\]"),
        'sha256': re.compile(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]"),
        'sha512': re.compile(r"\[file:hashes\.'SHA-512'\s*=\s*'([^']+)'\]"),
        'file_name': re.compile(r"\[file:name\s*=\s*'([^']+)'\]"),
        'registry': re.compile(r"\[windows-registry-key:key\s*=\s*'([^']+)'\]"),
        'mutex': re.compile(r"\[mutex:name\s*=\s*'([^']+)'\]"),
    }

    # Simple IP/Domain extraction patterns (for non-STIX data)
    SIMPLE_PATTERNS = {
        'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
        'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'cve': re.compile(r'\bCVE-\d{4}-\d{4,}\b'),
    }

    def __init__(self):
        self.indicators: List[ParsedIndicator] = []
        self.malware: List[ParsedMalware] = []
        self.attack_patterns: List[ParsedAttackPattern] = []
        self.threat_actors: List[ParsedThreatActor] = []
        self.relationships: List[dict] = []
        self.mitre_mapper = MITREMapper()

    def parse_bundle(self, bundle_data: Any, source: str = "unknown") -> dict:
        """
        Parse a STIX 2.1 bundle

        Args:
            bundle_data: STIX bundle (dict, JSON string, or stix2 Bundle object)
            source: Source identifier

        Returns:
            Parsed results with indicators, malware, attack patterns
        """
        # Clear previous results
        self.indicators = []
        self.malware = []
        self.attack_patterns = []
        self.threat_actors = []
        self.relationships = []

        # Convert to dict if needed
        if isinstance(bundle_data, str):
            bundle_data = json.loads(bundle_data)

        if STIX2_AVAILABLE and hasattr(bundle_data, 'objects'):
            # stix2 Bundle object
            objects = bundle_data.objects
        elif isinstance(bundle_data, dict):
            objects = bundle_data.get('objects', [])
        else:
            objects = []

        # Parse each object
        for obj in objects:
            obj_type = obj.get('type', '') if isinstance(obj, dict) else getattr(obj, 'type', '')

            if obj_type == 'indicator':
                self._parse_indicator(obj, source)
            elif obj_type == 'malware':
                self._parse_malware(obj, source)
            elif obj_type == 'attack-pattern':
                self._parse_attack_pattern(obj, source)
            elif obj_type == 'threat-actor':
                self._parse_threat_actor(obj, source)
            elif obj_type == 'relationship':
                self._parse_relationship(obj, source)

        return {
            'indicators': [i.to_dict() for i in self.indicators],
            'malware': [m.to_dict() for m in self.malware],
            'attack_patterns': [a.to_dict() for a in self.attack_patterns],
            'threat_actors': [t.to_dict() for t in self.threat_actors],
            'relationships': self.relationships,
            'statistics': {
                'total_objects': len(objects),
                'indicators_count': len(self.indicators),
                'malware_count': len(self.malware),
                'attack_patterns_count': len(self.attack_patterns),
                'threat_actors_count': len(self.threat_actors),
                'relationships_count': len(self.relationships)
            }
        }

    def _parse_indicator(self, obj: Any, source: str) -> None:
        """Parse STIX indicator object"""
        if isinstance(obj, dict):
            pattern = obj.get('pattern', '')
            pattern_type = obj.get('pattern_type', 'stix')

            # Extract indicator type and value from pattern
            ind_type, ind_value = self._extract_from_pattern(pattern)

            indicator = ParsedIndicator(
                id=obj.get('id', ''),
                type=ind_type,
                value=ind_value,
                pattern=pattern,
                pattern_type=pattern_type,
                name=obj.get('name', ''),
                description=obj.get('description', ''),
                confidence=obj.get('confidence', 0),
                valid_from=obj.get('valid_from'),
                valid_until=obj.get('valid_until'),
                kill_chain_phases=self._extract_kill_chain(obj.get('kill_chain_phases', [])),
                labels=obj.get('labels', []),
                external_references=obj.get('external_references', []),
                created=obj.get('created'),
                modified=obj.get('modified'),
                source=source
            )

            self.indicators.append(indicator)
        else:
            # stix2 object
            pattern = getattr(obj, 'pattern', '')
            ind_type, ind_value = self._extract_from_pattern(pattern)

            indicator = ParsedIndicator(
                id=str(obj.id),
                type=ind_type,
                value=ind_value,
                pattern=pattern,
                pattern_type=getattr(obj, 'pattern_type', 'stix'),
                name=getattr(obj, 'name', ''),
                description=getattr(obj, 'description', ''),
                confidence=getattr(obj, 'confidence', 0),
                valid_from=str(obj.valid_from) if hasattr(obj, 'valid_from') else None,
                valid_until=str(obj.valid_until) if hasattr(obj, 'valid_until') else None,
                kill_chain_phases=self._extract_kill_chain(getattr(obj, 'kill_chain_phases', [])),
                labels=list(getattr(obj, 'labels', [])),
                external_references=[dict(ref) for ref in getattr(obj, 'external_references', [])],
                created=str(obj.created) if hasattr(obj, 'created') else None,
                modified=str(obj.modified) if hasattr(obj, 'modified') else None,
                source=source
            )

            self.indicators.append(indicator)

    def _parse_malware(self, obj: Any, source: str) -> None:
        """Parse STIX malware object"""
        if isinstance(obj, dict):
            malware = ParsedMalware(
                id=obj.get('id', ''),
                name=obj.get('name', ''),
                malware_types=obj.get('malware_types', []),
                is_family=obj.get('is_family', False),
                aliases=obj.get('aliases', []),
                description=obj.get('description', ''),
                first_seen=obj.get('first_seen'),
                last_seen=obj.get('last_seen'),
                kill_chain_phases=self._extract_kill_chain(obj.get('kill_chain_phases', [])),
                capabilities=obj.get('capabilities', []),
                sample_refs=obj.get('sample_refs', []),
                operating_system_refs=obj.get('operating_system_refs', []),
                architecture_execution_envs=obj.get('architecture_execution_envs', []),
                labels=obj.get('labels', []),
                external_references=obj.get('external_references', []),
                created=obj.get('created'),
                modified=obj.get('modified'),
                source=source
            )
        else:
            malware = ParsedMalware(
                id=str(obj.id),
                name=getattr(obj, 'name', ''),
                malware_types=list(getattr(obj, 'malware_types', [])),
                is_family=getattr(obj, 'is_family', False),
                aliases=list(getattr(obj, 'aliases', [])),
                description=getattr(obj, 'description', ''),
                first_seen=str(obj.first_seen) if hasattr(obj, 'first_seen') and obj.first_seen else None,
                last_seen=str(obj.last_seen) if hasattr(obj, 'last_seen') and obj.last_seen else None,
                kill_chain_phases=self._extract_kill_chain(getattr(obj, 'kill_chain_phases', [])),
                capabilities=list(getattr(obj, 'capabilities', [])),
                labels=list(getattr(obj, 'labels', [])),
                external_references=[dict(ref) for ref in getattr(obj, 'external_references', [])],
                created=str(obj.created) if hasattr(obj, 'created') else None,
                modified=str(obj.modified) if hasattr(obj, 'modified') else None,
                source=source
            )

        self.malware.append(malware)

    def _parse_attack_pattern(self, obj: Any, source: str) -> None:
        """Parse STIX attack pattern object"""
        if isinstance(obj, dict):
            ext_refs = obj.get('external_references', [])
            mitre_id = MITREMapper.extract_mitre_id(ext_refs)

            attack_pattern = ParsedAttackPattern(
                id=obj.get('id', ''),
                name=obj.get('name', ''),
                description=obj.get('description', ''),
                aliases=obj.get('aliases', []),
                kill_chain_phases=self._extract_kill_chain(obj.get('kill_chain_phases', [])),
                external_references=ext_refs,
                mitre_id=mitre_id or '',
                mitre_name=obj.get('name', ''),
                tactic=self._extract_tactic(obj.get('kill_chain_phases', [])),
                platforms=obj.get('x_mitre_platforms', []),
                permissions_required=obj.get('x_mitre_permissions_required', []),
                data_sources=obj.get('x_mitre_data_sources', []),
                detection=obj.get('x_mitre_detection', ''),
                created=obj.get('created'),
                modified=obj.get('modified'),
                source=source
            )
        else:
            ext_refs = [dict(ref) for ref in getattr(obj, 'external_references', [])]
            mitre_id = MITREMapper.extract_mitre_id(ext_refs)

            attack_pattern = ParsedAttackPattern(
                id=str(obj.id),
                name=getattr(obj, 'name', ''),
                description=getattr(obj, 'description', ''),
                aliases=list(getattr(obj, 'aliases', [])),
                kill_chain_phases=self._extract_kill_chain(getattr(obj, 'kill_chain_phases', [])),
                external_references=ext_refs,
                mitre_id=mitre_id or '',
                mitre_name=getattr(obj, 'name', ''),
                tactic=self._extract_tactic(getattr(obj, 'kill_chain_phases', [])),
                platforms=list(getattr(obj, 'x_mitre_platforms', [])),
                created=str(obj.created) if hasattr(obj, 'created') else None,
                modified=str(obj.modified) if hasattr(obj, 'modified') else None,
                source=source
            )

        self.attack_patterns.append(attack_pattern)

    def _parse_threat_actor(self, obj: Any, source: str) -> None:
        """Parse STIX threat actor object"""
        if isinstance(obj, dict):
            threat_actor = ParsedThreatActor(
                id=obj.get('id', ''),
                name=obj.get('name', ''),
                threat_actor_types=obj.get('threat_actor_types', []),
                aliases=obj.get('aliases', []),
                description=obj.get('description', ''),
                sophistication=obj.get('sophistication', ''),
                resource_level=obj.get('resource_level', ''),
                primary_motivation=obj.get('primary_motivation', ''),
                secondary_motivations=obj.get('secondary_motivations', []),
                personal_motivations=obj.get('personal_motivations', []),
                goals=obj.get('goals', []),
                roles=obj.get('roles', []),
                first_seen=obj.get('first_seen'),
                last_seen=obj.get('last_seen'),
                labels=obj.get('labels', []),
                external_references=obj.get('external_references', []),
                created=obj.get('created'),
                modified=obj.get('modified'),
                source=source
            )
        else:
            threat_actor = ParsedThreatActor(
                id=str(obj.id),
                name=getattr(obj, 'name', ''),
                threat_actor_types=list(getattr(obj, 'threat_actor_types', [])),
                aliases=list(getattr(obj, 'aliases', [])),
                description=getattr(obj, 'description', ''),
                sophistication=getattr(obj, 'sophistication', ''),
                resource_level=getattr(obj, 'resource_level', ''),
                primary_motivation=getattr(obj, 'primary_motivation', ''),
                labels=list(getattr(obj, 'labels', [])),
                external_references=[dict(ref) for ref in getattr(obj, 'external_references', [])],
                created=str(obj.created) if hasattr(obj, 'created') else None,
                modified=str(obj.modified) if hasattr(obj, 'modified') else None,
                source=source
            )

        self.threat_actors.append(threat_actor)

    def _parse_relationship(self, obj: Any, source: str) -> None:
        """Parse STIX relationship object"""
        if isinstance(obj, dict):
            rel = {
                'id': obj.get('id', ''),
                'relationship_type': obj.get('relationship_type', ''),
                'source_ref': obj.get('source_ref', ''),
                'target_ref': obj.get('target_ref', ''),
                'description': obj.get('description', ''),
                'source': source
            }
        else:
            rel = {
                'id': str(obj.id),
                'relationship_type': getattr(obj, 'relationship_type', ''),
                'source_ref': str(obj.source_ref) if hasattr(obj, 'source_ref') else '',
                'target_ref': str(obj.target_ref) if hasattr(obj, 'target_ref') else '',
                'description': getattr(obj, 'description', ''),
                'source': source
            }

        self.relationships.append(rel)

    def _extract_from_pattern(self, pattern: str) -> Tuple[str, str]:
        """Extract indicator type and value from STIX pattern"""
        if not pattern:
            return ('unknown', '')

        for ind_type, regex in self.PATTERN_REGEXES.items():
            match = regex.search(pattern)
            if match:
                return (ind_type, match.group(1))

        return ('unknown', pattern)

    def _extract_kill_chain(self, kill_chain_phases: List[Any]) -> List[str]:
        """Extract kill chain phase names"""
        phases = []
        for phase in kill_chain_phases:
            if isinstance(phase, dict):
                phases.append(phase.get('phase_name', ''))
            elif hasattr(phase, 'phase_name'):
                phases.append(phase.phase_name)
        return [p for p in phases if p]

    def _extract_tactic(self, kill_chain_phases: List[Any]) -> str:
        """Extract primary MITRE ATT&CK tactic"""
        for phase in kill_chain_phases:
            if isinstance(phase, dict):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    return phase.get('phase_name', '')
            elif hasattr(phase, 'kill_chain_name'):
                if phase.kill_chain_name == 'mitre-attack':
                    return getattr(phase, 'phase_name', '')
        return ''

    def extract_indicators_from_text(self, text: str, source: str = "text") -> List[ParsedIndicator]:
        """
        Extract indicators from plain text (non-STIX format)

        Args:
            text: Text containing indicators
            source: Source identifier

        Returns:
            List of parsed indicators
        """
        indicators = []
        seen = set()

        for ind_type, regex in self.SIMPLE_PATTERNS.items():
            for match in regex.finditer(text):
                value = match.group()

                # Skip duplicates
                key = f"{ind_type}:{value}"
                if key in seen:
                    continue
                seen.add(key)

                # Skip common false positives
                if ind_type == 'domain':
                    if value.endswith('.png') or value.endswith('.jpg'):
                        continue
                    if value in ['example.com', 'localhost']:
                        continue

                indicator = ParsedIndicator(
                    id=f"indicator--{hashlib.md5(key.encode()).hexdigest()}",
                    type=ind_type,
                    value=value,
                    source=source
                )

                indicators.append(indicator)

        return indicators

    def parse_raw_indicators(self, data: List[dict], source: str = "unknown") -> List[ParsedIndicator]:
        """
        Parse raw indicator data from threat feeds

        Args:
            data: List of indicator dicts from feeds
            source: Source identifier

        Returns:
            List of parsed indicators
        """
        indicators = []

        for item in data:
            ind_type = item.get('type', 'unknown')
            value = item.get('value', '')

            if not value:
                continue

            indicator = ParsedIndicator(
                id=item.get('id', f"indicator--{hashlib.md5(f'{ind_type}:{value}'.encode()).hexdigest()}"),
                type=ind_type,
                value=value,
                name=item.get('name', ''),
                description=item.get('description', ''),
                confidence=item.get('confidence', 0),
                labels=item.get('tags', item.get('labels', [])),
                created=item.get('first_seen', item.get('created', '')),
                modified=item.get('last_seen', item.get('modified', '')),
                source=item.get('source', source)
            )

            indicators.append(indicator)

        return indicators

    def get_mitre_techniques(self) -> List[str]:
        """Get all MITRE technique IDs from parsed data"""
        techniques = set()

        for ap in self.attack_patterns:
            if ap.mitre_id:
                techniques.add(ap.mitre_id)

        for ind in self.indicators:
            ind_techniques = MITREMapper.get_techniques_for_indicator(ind.type)
            techniques.update(ind_techniques)

        for mal in self.malware:
            mal_techniques = MITREMapper.get_techniques_for_malware(mal.malware_types)
            techniques.update(mal_techniques)

        return sorted(list(techniques))

    def get_statistics(self) -> dict:
        """Get parsing statistics"""
        return {
            'indicators': {
                'total': len(self.indicators),
                'by_type': self._count_by_type(self.indicators)
            },
            'malware': {
                'total': len(self.malware),
                'by_type': self._count_malware_types()
            },
            'attack_patterns': {
                'total': len(self.attack_patterns),
                'by_tactic': self._count_by_tactic()
            },
            'threat_actors': {
                'total': len(self.threat_actors)
            },
            'relationships': {
                'total': len(self.relationships)
            },
            'mitre_techniques': len(self.get_mitre_techniques())
        }

    def _count_by_type(self, indicators: List[ParsedIndicator]) -> dict:
        """Count indicators by type"""
        counts = {}
        for ind in indicators:
            counts[ind.type] = counts.get(ind.type, 0) + 1
        return counts

    def _count_malware_types(self) -> dict:
        """Count malware by type"""
        counts = {}
        for mal in self.malware:
            for mtype in mal.malware_types:
                counts[mtype] = counts.get(mtype, 0) + 1
        return counts

    def _count_by_tactic(self) -> dict:
        """Count attack patterns by tactic"""
        counts = {}
        for ap in self.attack_patterns:
            if ap.tactic:
                counts[ap.tactic] = counts.get(ap.tactic, 0) + 1
        return counts


# Export functions for easy access
def parse_stix_bundle(bundle_data: Any, source: str = "unknown") -> dict:
    """Parse STIX bundle and return results"""
    parser = STIXParser()
    return parser.parse_bundle(bundle_data, source)


def extract_indicators_from_text(text: str, source: str = "text") -> List[ParsedIndicator]:
    """Extract indicators from plain text"""
    parser = STIXParser()
    return parser.extract_indicators_from_text(text, source)
