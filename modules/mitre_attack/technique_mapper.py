#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    MITRE ATT&CK Technique Mapper
    Map Security Events to ATT&CK Techniques
================================================================================

    Features:
    - Log pattern to technique mapping
    - CVE to technique correlation
    - STIX pattern to technique mapping
    - Event-based technique detection
    - Coverage report generation

================================================================================
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Set, Any, Tuple, Pattern
from dataclasses import dataclass, field
from enum import Enum
import threading

from .attack_data import MITREAttackData, Technique, get_attack_data

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EventType(Enum):
    """Security event types"""
    PROCESS_CREATE = "process_creation"
    PROCESS_TERMINATE = "process_termination"
    FILE_CREATE = "file_creation"
    FILE_MODIFY = "file_modification"
    FILE_DELETE = "file_deletion"
    REGISTRY_CREATE = "registry_creation"
    REGISTRY_MODIFY = "registry_modification"
    REGISTRY_DELETE = "registry_deletion"
    NETWORK_CONNECT = "network_connection"
    NETWORK_LISTEN = "network_listen"
    DNS_QUERY = "dns_query"
    IMAGE_LOAD = "image_load"
    DRIVER_LOAD = "driver_load"
    SERVICE_CREATE = "service_creation"
    SERVICE_MODIFY = "service_modification"
    SCHEDULED_TASK = "scheduled_task"
    WMI_EVENT = "wmi_event"
    POWERSHELL = "powershell_execution"
    AUTH_SUCCESS = "authentication_success"
    AUTH_FAILURE = "authentication_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"


class ConfidenceLevel(Enum):
    """Mapping confidence levels"""
    HIGH = "high"      # 0.8-1.0 - Strong indicator
    MEDIUM = "medium"  # 0.5-0.79 - Moderate indicator
    LOW = "low"        # 0.2-0.49 - Weak indicator
    INFO = "info"      # 0.0-0.19 - Informational only


@dataclass
class TechniqueMatch:
    """A matched technique with confidence score"""
    technique_id: str
    technique_name: str
    confidence: float  # 0.0 - 1.0
    confidence_level: ConfidenceLevel
    matched_patterns: List[str] = field(default_factory=list)
    matched_indicators: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'confidence': self.confidence,
            'confidence_level': self.confidence_level.value,
            'matched_patterns': self.matched_patterns,
            'matched_indicators': self.matched_indicators,
            'tactics': self.tactics,
            'platforms': self.platforms,
            'evidence': self.evidence
        }


@dataclass
class EventMapping:
    """Mapping of an event to ATT&CK techniques"""
    event_id: str
    event_type: EventType
    timestamp: datetime
    source: str
    matches: List[TechniqueMatch] = field(default_factory=list)
    raw_event: Dict = field(default_factory=dict)
    metadata: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'matches': [m.to_dict() for m in self.matches],
            'raw_event': self.raw_event,
            'metadata': self.metadata
        }


@dataclass
class MappingRule:
    """Rule for mapping events to techniques"""
    rule_id: str
    name: str
    description: str
    technique_ids: List[str]
    event_types: List[EventType]
    patterns: List[Pattern]  # Compiled regex patterns
    indicators: Dict[str, List[str]]  # Field -> values to match
    weight: float = 1.0  # Contribution to confidence
    enabled: bool = True


class TechniqueMapper:
    """
    Maps security events to MITRE ATT&CK techniques

    Uses pattern matching, heuristics, and indicator correlation
    to identify potential ATT&CK techniques from security events.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> 'TechniqueMapper':
        """Get singleton instance"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._attack_data: Optional[MITREAttackData] = None
        self._rules: Dict[str, MappingRule] = {}
        self._cve_technique_map: Dict[str, List[str]] = {}  # CVE -> [technique_ids]
        self._process_indicators: Dict[str, List[str]] = {}  # process_name -> [technique_ids]
        self._file_indicators: Dict[str, List[str]] = {}  # file_path_pattern -> [technique_ids]
        self._registry_indicators: Dict[str, List[str]] = {}  # registry_key -> [technique_ids]
        self._network_indicators: Dict[str, List[str]] = {}  # port/protocol -> [technique_ids]

        self._initialize_rules()
        logger.info("[TECHNIQUE-MAPPER] Mapper initialized")

    def _initialize_rules(self):
        """Initialize detection rules based on ATT&CK techniques"""
        # Load rules from embedded knowledge
        self._load_process_rules()
        self._load_file_rules()
        self._load_registry_rules()
        self._load_network_rules()
        self._load_persistence_rules()
        self._load_credential_rules()
        self._load_discovery_rules()
        self._load_lateral_movement_rules()
        self._load_cve_mappings()

    def _load_process_rules(self):
        """Load process-based detection rules"""
        # T1059 - Command and Scripting Interpreter
        self._process_indicators['powershell.exe'] = ['T1059.001']
        self._process_indicators['pwsh.exe'] = ['T1059.001']
        self._process_indicators['cmd.exe'] = ['T1059.003']
        self._process_indicators['bash'] = ['T1059.004']
        self._process_indicators['sh'] = ['T1059.004']
        self._process_indicators['python'] = ['T1059.006']
        self._process_indicators['python3'] = ['T1059.006']
        self._process_indicators['wscript.exe'] = ['T1059.005']
        self._process_indicators['cscript.exe'] = ['T1059.005']
        self._process_indicators['mshta.exe'] = ['T1218.005']

        # T1053 - Scheduled Task/Job
        self._process_indicators['schtasks.exe'] = ['T1053.005']
        self._process_indicators['at.exe'] = ['T1053.002']
        self._process_indicators['crontab'] = ['T1053.003']

        # T1055 - Process Injection
        self._process_indicators['rundll32.exe'] = ['T1218.011', 'T1055']

        # T1003 - OS Credential Dumping
        self._process_indicators['mimikatz'] = ['T1003.001']
        self._process_indicators['procdump.exe'] = ['T1003.001']
        self._process_indicators['lsass.exe'] = ['T1003.001']

        # T1021 - Remote Services
        self._process_indicators['psexec.exe'] = ['T1021.002', 'T1569.002']
        self._process_indicators['winrs.exe'] = ['T1021.006']
        self._process_indicators['ssh'] = ['T1021.004']

        # T1047 - Windows Management Instrumentation
        self._process_indicators['wmic.exe'] = ['T1047']
        self._process_indicators['wmiprvse.exe'] = ['T1047']

        # T1105 - Ingress Tool Transfer
        self._process_indicators['certutil.exe'] = ['T1105', 'T1140']
        self._process_indicators['bitsadmin.exe'] = ['T1105', 'T1197']
        self._process_indicators['curl'] = ['T1105']
        self._process_indicators['wget'] = ['T1105']

        # T1218 - System Binary Proxy Execution
        self._process_indicators['regsvr32.exe'] = ['T1218.010']
        self._process_indicators['msiexec.exe'] = ['T1218.007']
        self._process_indicators['cmstp.exe'] = ['T1218.003']
        self._process_indicators['installutil.exe'] = ['T1218.004']

        # T1070 - Indicator Removal
        self._process_indicators['wevtutil.exe'] = ['T1070.001']
        self._process_indicators['fsutil.exe'] = ['T1070.004']

        # T1027 - Obfuscated Files
        self._process_indicators['base64'] = ['T1027']
        self._process_indicators['certutil.exe'] = ['T1140']

    def _load_file_rules(self):
        """Load file-based detection rules"""
        # T1547 - Boot or Logon Autostart Execution
        self._file_indicators[r'.*\\Start Menu\\Programs\\Startup\\.*'] = ['T1547.001']
        self._file_indicators[r'.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\.*'] = ['T1547.001']

        # T1574 - Hijack Execution Flow
        self._file_indicators[r'.*\.dll$'] = ['T1574.001', 'T1574.002']

        # T1036 - Masquerading
        self._file_indicators[r'.*\\Windows\\Temp\\.*\.exe'] = ['T1036']
        self._file_indicators[r'.*\\Users\\Public\\.*\.exe'] = ['T1036']

        # T1505 - Server Software Component
        self._file_indicators[r'.*\\inetpub\\wwwroot\\.*\.aspx'] = ['T1505.003']
        self._file_indicators[r'.*\\wwwroot\\.*\.php'] = ['T1505.003']
        self._file_indicators[r'.*\\wwwroot\\.*\.jsp'] = ['T1505.003']

        # T1070 - Indicator Removal on Host
        self._file_indicators[r'.*\\Windows\\System32\\winevt\\Logs\\.*'] = ['T1070.001']

    def _load_registry_rules(self):
        """Load registry-based detection rules (Windows)"""
        # T1547.001 - Registry Run Keys
        self._registry_indicators[r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'] = ['T1547.001']
        self._registry_indicators[r'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'] = ['T1547.001']
        self._registry_indicators[r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'] = ['T1547.001']

        # T1546 - Event Triggered Execution
        self._registry_indicators[r'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'] = ['T1546.012']
        self._registry_indicators[r'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit'] = ['T1546.012']

        # T1112 - Modify Registry
        self._registry_indicators[r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders'] = ['T1112', 'T1556']
        self._registry_indicators[r'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa'] = ['T1112', 'T1003']

        # T1562 - Impair Defenses
        self._registry_indicators[r'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender'] = ['T1562.001']
        self._registry_indicators[r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\EnableLUA'] = ['T1548.002']

    def _load_network_rules(self):
        """Load network-based detection rules"""
        # T1071 - Application Layer Protocol
        self._network_indicators['tcp/80'] = ['T1071.001']
        self._network_indicators['tcp/443'] = ['T1071.001']
        self._network_indicators['tcp/53'] = ['T1071.004']
        self._network_indicators['udp/53'] = ['T1071.004']

        # T1021 - Remote Services
        self._network_indicators['tcp/22'] = ['T1021.004']
        self._network_indicators['tcp/3389'] = ['T1021.001']
        self._network_indicators['tcp/445'] = ['T1021.002']
        self._network_indicators['tcp/135'] = ['T1021.003']
        self._network_indicators['tcp/5985'] = ['T1021.006']
        self._network_indicators['tcp/5986'] = ['T1021.006']

        # T1572 - Protocol Tunneling
        self._network_indicators['tcp/8080'] = ['T1572']
        self._network_indicators['tcp/8443'] = ['T1572']

        # T1090 - Proxy
        self._network_indicators['tcp/1080'] = ['T1090']
        self._network_indicators['tcp/3128'] = ['T1090']
        self._network_indicators['tcp/9050'] = ['T1090.003']  # Tor

    def _load_persistence_rules(self):
        """Load persistence-specific detection rules"""
        self._rules['persistence_service'] = MappingRule(
            rule_id='persistence_service',
            name='Service Installation',
            description='Detect new service creation for persistence',
            technique_ids=['T1543.003'],
            event_types=[EventType.SERVICE_CREATE],
            patterns=[re.compile(r'.*new.*service.*', re.IGNORECASE)],
            indicators={'event_type': ['service_creation']},
            weight=0.8
        )

        self._rules['persistence_scheduled_task'] = MappingRule(
            rule_id='persistence_scheduled_task',
            name='Scheduled Task Creation',
            description='Detect scheduled task creation for persistence',
            technique_ids=['T1053.005'],
            event_types=[EventType.SCHEDULED_TASK],
            patterns=[re.compile(r'schtasks.*/(create|change)', re.IGNORECASE)],
            indicators={'process_name': ['schtasks.exe']},
            weight=0.8
        )

    def _load_credential_rules(self):
        """Load credential access detection rules"""
        self._rules['cred_lsass'] = MappingRule(
            rule_id='cred_lsass',
            name='LSASS Memory Access',
            description='Detect LSASS memory access for credential dumping',
            technique_ids=['T1003.001'],
            event_types=[EventType.PROCESS_CREATE, EventType.CREDENTIAL_ACCESS],
            patterns=[
                re.compile(r'.*lsass\.exe.*', re.IGNORECASE),
                re.compile(r'.*mimikatz.*', re.IGNORECASE),
                re.compile(r'.*procdump.*-ma.*lsass.*', re.IGNORECASE)
            ],
            indicators={'target_process': ['lsass.exe']},
            weight=0.9
        )

        self._rules['cred_sam'] = MappingRule(
            rule_id='cred_sam',
            name='SAM Registry Access',
            description='Detect SAM registry hive access',
            technique_ids=['T1003.002'],
            event_types=[EventType.REGISTRY_MODIFY],
            patterns=[re.compile(r'.*\\SAM\\.*', re.IGNORECASE)],
            indicators={'registry_key': ['HKLM\\SAM']},
            weight=0.9
        )

    def _load_discovery_rules(self):
        """Load discovery-specific detection rules"""
        self._rules['discovery_system'] = MappingRule(
            rule_id='discovery_system',
            name='System Information Discovery',
            description='Detect system information gathering',
            technique_ids=['T1082'],
            event_types=[EventType.PROCESS_CREATE],
            patterns=[
                re.compile(r'.*systeminfo.*', re.IGNORECASE),
                re.compile(r'.*uname.*-a.*', re.IGNORECASE),
                re.compile(r'.*hostname.*', re.IGNORECASE)
            ],
            indicators={'process_name': ['systeminfo.exe', 'hostname.exe']},
            weight=0.6
        )

        self._rules['discovery_network'] = MappingRule(
            rule_id='discovery_network',
            name='Network Discovery',
            description='Detect network configuration discovery',
            technique_ids=['T1016'],
            event_types=[EventType.PROCESS_CREATE],
            patterns=[
                re.compile(r'.*ipconfig.*', re.IGNORECASE),
                re.compile(r'.*ifconfig.*', re.IGNORECASE),
                re.compile(r'.*netstat.*', re.IGNORECASE),
                re.compile(r'.*arp.*-a.*', re.IGNORECASE)
            ],
            indicators={'process_name': ['ipconfig.exe', 'netstat.exe', 'arp.exe']},
            weight=0.5
        )

        self._rules['discovery_account'] = MappingRule(
            rule_id='discovery_account',
            name='Account Discovery',
            description='Detect account enumeration',
            technique_ids=['T1087'],
            event_types=[EventType.PROCESS_CREATE],
            patterns=[
                re.compile(r'.*net\s+user.*', re.IGNORECASE),
                re.compile(r'.*net\s+localgroup.*', re.IGNORECASE),
                re.compile(r'.*whoami.*', re.IGNORECASE),
                re.compile(r'.*id\s*$', re.IGNORECASE)
            ],
            indicators={'process_name': ['net.exe', 'whoami.exe']},
            weight=0.5
        )

    def _load_lateral_movement_rules(self):
        """Load lateral movement detection rules"""
        self._rules['lateral_psexec'] = MappingRule(
            rule_id='lateral_psexec',
            name='PsExec Usage',
            description='Detect PsExec for lateral movement',
            technique_ids=['T1021.002', 'T1569.002'],
            event_types=[EventType.PROCESS_CREATE, EventType.LATERAL_MOVEMENT],
            patterns=[
                re.compile(r'.*psexec.*', re.IGNORECASE),
                re.compile(r'.*\\ADMIN\$\\.*', re.IGNORECASE)
            ],
            indicators={'process_name': ['psexec.exe', 'psexesvc.exe']},
            weight=0.9
        )

        self._rules['lateral_wmi'] = MappingRule(
            rule_id='lateral_wmi',
            name='WMI Lateral Movement',
            description='Detect WMI for remote execution',
            technique_ids=['T1047'],
            event_types=[EventType.PROCESS_CREATE, EventType.WMI_EVENT],
            patterns=[
                re.compile(r'.*wmic.*process.*call.*create.*', re.IGNORECASE),
                re.compile(r'.*wmic.*/node:.*', re.IGNORECASE)
            ],
            indicators={'process_name': ['wmic.exe']},
            weight=0.8
        )

    def _load_cve_mappings(self):
        """Load CVE to ATT&CK technique mappings"""
        # Major CVEs mapped to ATT&CK techniques
        # Source: MITRE CVE-ATT&CK mappings

        # Initial Access
        self._cve_technique_map['CVE-2021-44228'] = ['T1190', 'T1059']  # Log4Shell
        self._cve_technique_map['CVE-2021-34527'] = ['T1547.012', 'T1574.010']  # PrintNightmare
        self._cve_technique_map['CVE-2021-26855'] = ['T1190']  # ProxyLogon
        self._cve_technique_map['CVE-2021-27065'] = ['T1505.003']  # ProxyLogon webshell
        self._cve_technique_map['CVE-2020-1472'] = ['T1068', 'T1557']  # Zerologon
        self._cve_technique_map['CVE-2019-0708'] = ['T1210']  # BlueKeep
        self._cve_technique_map['CVE-2017-0144'] = ['T1210']  # EternalBlue
        self._cve_technique_map['CVE-2017-11882'] = ['T1203']  # Office Equation Editor

        # Privilege Escalation
        self._cve_technique_map['CVE-2021-1732'] = ['T1068']  # Win32k Elevation
        self._cve_technique_map['CVE-2020-0787'] = ['T1574.002']  # BITS Elevation
        self._cve_technique_map['CVE-2016-0167'] = ['T1068']  # Win32k

        # Defense Evasion
        self._cve_technique_map['CVE-2021-21551'] = ['T1211']  # Dell driver bypass

        # Code Execution
        self._cve_technique_map['CVE-2022-30190'] = ['T1203', 'T1059']  # Follina
        self._cve_technique_map['CVE-2023-23397'] = ['T1187']  # Outlook NTLM relay
        self._cve_technique_map['CVE-2023-36884'] = ['T1203']  # Office RCE
        self._cve_technique_map['CVE-2024-21762'] = ['T1190']  # FortiOS RCE

    def set_attack_data(self, attack_data: MITREAttackData):
        """Set the ATT&CK data source"""
        self._attack_data = attack_data

    def map_event(self, event: Dict) -> EventMapping:
        """
        Map a security event to ATT&CK techniques

        Args:
            event: Security event dict with fields like:
                - event_id: Unique identifier
                - event_type: Type of event
                - timestamp: Event time
                - source: Event source (e.g., sysmon, auditd)
                - process_name: Process name if applicable
                - command_line: Command line if applicable
                - file_path: File path if applicable
                - registry_key: Registry key if applicable
                - network_dest: Network destination if applicable
                - network_port: Network port if applicable

        Returns:
            EventMapping with matched techniques
        """
        event_id = event.get('event_id', str(id(event)))
        event_type_str = event.get('event_type', 'unknown')
        timestamp = event.get('timestamp', datetime.now())

        # Parse timestamp if string
        if isinstance(timestamp, str):
            try:
                timestamp = datetime.fromisoformat(timestamp)
            except Exception:
                timestamp = datetime.now()

        # Determine event type
        try:
            event_type = EventType(event_type_str)
        except ValueError:
            event_type = EventType.PROCESS_CREATE  # Default

        mapping = EventMapping(
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            source=event.get('source', 'unknown'),
            raw_event=event
        )

        matches: List[TechniqueMatch] = []

        # Check process indicators
        process_name = event.get('process_name', '').lower()
        if process_name:
            process_base = process_name.split('/')[-1].split('\\')[-1]
            if process_base in self._process_indicators:
                for tech_id in self._process_indicators[process_base]:
                    match = self._create_match(tech_id, 0.7, [f"process:{process_base}"])
                    if match:
                        matches.append(match)

        # Check command line patterns
        command_line = event.get('command_line', '')
        if command_line:
            for rule in self._rules.values():
                if not rule.enabled:
                    continue
                for pattern in rule.patterns:
                    if pattern.search(command_line):
                        for tech_id in rule.technique_ids:
                            match = self._create_match(
                                tech_id,
                                rule.weight,
                                [f"pattern:{pattern.pattern[:50]}"],
                                [command_line[:100]]
                            )
                            if match:
                                matches.append(match)

        # Check file indicators
        file_path = event.get('file_path', '')
        if file_path:
            for pattern_str, tech_ids in self._file_indicators.items():
                if re.match(pattern_str, file_path, re.IGNORECASE):
                    for tech_id in tech_ids:
                        match = self._create_match(tech_id, 0.6, [f"file:{pattern_str[:30]}"])
                        if match:
                            matches.append(match)

        # Check registry indicators
        registry_key = event.get('registry_key', '')
        if registry_key:
            for key_pattern, tech_ids in self._registry_indicators.items():
                if re.match(key_pattern, registry_key, re.IGNORECASE):
                    for tech_id in tech_ids:
                        match = self._create_match(tech_id, 0.7, [f"registry:{key_pattern[:30]}"])
                        if match:
                            matches.append(match)

        # Check network indicators
        network_port = event.get('network_port')
        network_proto = event.get('network_proto', 'tcp').lower()
        if network_port:
            key = f"{network_proto}/{network_port}"
            if key in self._network_indicators:
                for tech_id in self._network_indicators[key]:
                    match = self._create_match(tech_id, 0.5, [f"network:{key}"])
                    if match:
                        matches.append(match)

        # Deduplicate and sort matches
        seen_ids = set()
        unique_matches = []
        for match in sorted(matches, key=lambda m: -m.confidence):
            if match.technique_id not in seen_ids:
                seen_ids.add(match.technique_id)
                unique_matches.append(match)

        mapping.matches = unique_matches
        return mapping

    def _create_match(self, technique_id: str, confidence: float,
                     patterns: List[str] = None,
                     indicators: List[str] = None) -> Optional[TechniqueMatch]:
        """Create a TechniqueMatch object"""
        if not self._attack_data:
            self._attack_data = get_attack_data()

        technique = self._attack_data.get_technique(technique_id)
        if not technique:
            return None

        # Determine confidence level
        if confidence >= 0.8:
            level = ConfidenceLevel.HIGH
        elif confidence >= 0.5:
            level = ConfidenceLevel.MEDIUM
        elif confidence >= 0.2:
            level = ConfidenceLevel.LOW
        else:
            level = ConfidenceLevel.INFO

        return TechniqueMatch(
            technique_id=technique_id,
            technique_name=technique.name,
            confidence=confidence,
            confidence_level=level,
            matched_patterns=patterns or [],
            matched_indicators=indicators or [],
            tactics=technique.tactics,
            platforms=technique.platforms
        )

    def map_cve(self, cve_id: str) -> List[TechniqueMatch]:
        """
        Map a CVE to ATT&CK techniques

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            List of matched techniques
        """
        cve_upper = cve_id.upper()
        if cve_upper not in self._cve_technique_map:
            return []

        matches = []
        for tech_id in self._cve_technique_map[cve_upper]:
            match = self._create_match(tech_id, 0.9, [f"cve:{cve_upper}"])
            if match:
                match.evidence['cve'] = cve_upper
                matches.append(match)

        return matches

    def map_stix_pattern(self, stix_pattern: str) -> List[TechniqueMatch]:
        """
        Map a STIX pattern to ATT&CK techniques

        Args:
            stix_pattern: STIX 2.1 pattern string

        Returns:
            List of matched techniques
        """
        matches = []

        # Extract indicators from STIX pattern
        # Basic parsing - full STIX parsing would use stix2 library

        # Process patterns
        process_match = re.search(r"process:name\s*=\s*'([^']+)'", stix_pattern, re.IGNORECASE)
        if process_match:
            process_name = process_match.group(1).lower()
            if process_name in self._process_indicators:
                for tech_id in self._process_indicators[process_name]:
                    match = self._create_match(tech_id, 0.7, [f"stix_process:{process_name}"])
                    if match:
                        matches.append(match)

        # File patterns
        file_match = re.search(r"file:name\s*=\s*'([^']+)'", stix_pattern, re.IGNORECASE)
        if file_match:
            file_name = file_match.group(1)
            for pattern_str, tech_ids in self._file_indicators.items():
                if re.match(pattern_str, file_name, re.IGNORECASE):
                    for tech_id in tech_ids:
                        match = self._create_match(tech_id, 0.6, [f"stix_file:{file_name[:30]}"])
                        if match:
                            matches.append(match)

        # Network patterns
        port_match = re.search(r"network-traffic:dst_port\s*=\s*(\d+)", stix_pattern, re.IGNORECASE)
        if port_match:
            port = port_match.group(1)
            key = f"tcp/{port}"
            if key in self._network_indicators:
                for tech_id in self._network_indicators[key]:
                    match = self._create_match(tech_id, 0.5, [f"stix_port:{port}"])
                    if match:
                        matches.append(match)

        return matches

    def generate_coverage_report(self, mappings: List[EventMapping]) -> Dict[str, Any]:
        """
        Generate a technique coverage report from event mappings

        Args:
            mappings: List of event mappings

        Returns:
            Coverage report with statistics
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        # Collect all detected techniques
        detected_techniques: Dict[str, Dict] = {}
        tactic_coverage: Dict[str, Set[str]] = {}
        platform_coverage: Dict[str, Set[str]] = {}

        for mapping in mappings:
            for match in mapping.matches:
                tech_id = match.technique_id
                if tech_id not in detected_techniques:
                    detected_techniques[tech_id] = {
                        'technique_id': tech_id,
                        'technique_name': match.technique_name,
                        'count': 0,
                        'max_confidence': 0,
                        'tactics': match.tactics,
                        'first_seen': mapping.timestamp,
                        'last_seen': mapping.timestamp
                    }

                detected_techniques[tech_id]['count'] += 1
                detected_techniques[tech_id]['max_confidence'] = max(
                    detected_techniques[tech_id]['max_confidence'],
                    match.confidence
                )
                if mapping.timestamp < detected_techniques[tech_id]['first_seen']:
                    detected_techniques[tech_id]['first_seen'] = mapping.timestamp
                if mapping.timestamp > detected_techniques[tech_id]['last_seen']:
                    detected_techniques[tech_id]['last_seen'] = mapping.timestamp

                # Track tactic coverage
                for tactic in match.tactics:
                    if tactic not in tactic_coverage:
                        tactic_coverage[tactic] = set()
                    tactic_coverage[tactic].add(tech_id)

                # Track platform coverage
                for platform in match.platforms:
                    if platform not in platform_coverage:
                        platform_coverage[platform] = set()
                    platform_coverage[platform].add(tech_id)

        # Calculate coverage percentages
        total_techniques = len(self._attack_data.list_techniques(include_subtechniques=False))
        detected_count = len(detected_techniques)

        # Build report
        report = {
            'generated_at': datetime.now().isoformat(),
            'total_events': len(mappings),
            'summary': {
                'techniques_detected': detected_count,
                'total_techniques': total_techniques,
                'coverage_percentage': round(detected_count / total_techniques * 100, 2) if total_techniques > 0 else 0
            },
            'tactic_coverage': {
                tactic: {
                    'count': len(techs),
                    'techniques': list(techs)
                }
                for tactic, techs in tactic_coverage.items()
            },
            'platform_coverage': {
                platform: {
                    'count': len(techs),
                    'techniques': list(techs)
                }
                for platform, techs in platform_coverage.items()
            },
            'detected_techniques': [
                {
                    **tech,
                    'first_seen': tech['first_seen'].isoformat(),
                    'last_seen': tech['last_seen'].isoformat()
                }
                for tech in sorted(
                    detected_techniques.values(),
                    key=lambda x: (-x['count'], x['technique_id'])
                )
            ],
            'high_confidence': [
                tech['technique_id']
                for tech in detected_techniques.values()
                if tech['max_confidence'] >= 0.8
            ],
            'mitre_matrix_coverage': self._build_matrix_coverage(detected_techniques)
        }

        return report

    def _build_matrix_coverage(self, detected_techniques: Dict[str, Dict]) -> Dict[str, List[Dict]]:
        """Build ATT&CK matrix coverage for visualization"""
        if not self._attack_data:
            return {}

        matrix = {}
        for tactic in self._attack_data.list_tactics():
            matrix[tactic.shortname] = []
            for tech in self._attack_data.get_techniques_by_tactic(tactic.shortname):
                if tech.is_subtechnique:
                    continue
                coverage = detected_techniques.get(tech.id, {})
                matrix[tactic.shortname].append({
                    'technique_id': tech.id,
                    'technique_name': tech.name,
                    'detected': tech.id in detected_techniques,
                    'count': coverage.get('count', 0),
                    'confidence': coverage.get('max_confidence', 0)
                })

        return matrix

    def add_cve_mapping(self, cve_id: str, technique_ids: List[str]):
        """Add a custom CVE to technique mapping"""
        self._cve_technique_map[cve_id.upper()] = technique_ids

    def get_statistics(self) -> Dict[str, Any]:
        """Get mapper statistics"""
        return {
            'total_rules': len(self._rules),
            'process_indicators': len(self._process_indicators),
            'file_indicators': len(self._file_indicators),
            'registry_indicators': len(self._registry_indicators),
            'network_indicators': len(self._network_indicators),
            'cve_mappings': len(self._cve_technique_map),
            'attack_data_loaded': self._attack_data.is_loaded() if self._attack_data else False
        }


# Singleton accessor
def get_technique_mapper() -> TechniqueMapper:
    """Get the global technique mapper instance"""
    mapper = TechniqueMapper.get_instance()
    if not mapper._attack_data:
        mapper.set_attack_data(get_attack_data())
    return mapper
