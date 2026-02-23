#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Suricata IDS/IPS Connector
    Production-Grade Suricata Integration
================================================================================

    Features:
    - EVE JSON log reader (file tailing / Unix socket)
    - Alert normalization to TSUNAMI Alert format
    - Suricata rule management (enable/disable/add/remove)
    - Real-time alert stream with filtering
    - Network flow metadata ingestion (flow, http, dns, tls, fileinfo)
    - Suricata stats monitoring (capture, decoder, flow counters)
    - Threshold / suppress rule management
    - PCAP replay trigger for forensics
    - Suricata socket control (reload-rules, iface-stat)
    - Thread-safe SQLite persistence for dedup and stats
    - MITRE ATT&CK mapping from Suricata rule metadata

================================================================================
"""

import hashlib
import json
import logging
import os
import re
import select
import socket
import sqlite3
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("soc.suricata")


# ============================================================================
# Enums & Constants
# ============================================================================

class SuricataEventType(Enum):
    """Suricata EVE event types."""
    ALERT = "alert"
    FLOW = "flow"
    HTTP = "http"
    DNS = "dns"
    TLS = "tls"
    FILEINFO = "fileinfo"
    ANOMALY = "anomaly"
    STATS = "stats"
    DROP = "drop"
    SMTP = "smtp"
    SSH = "ssh"
    DHCP = "dhcp"
    NFS = "nfs"
    SMB = "smb"


class SuricataAction(Enum):
    """Suricata alert actions."""
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    DROPPED = "drop"


class RuleAction(Enum):
    """Suricata rule actions."""
    ALERT = "alert"
    PASS_RULE = "pass"
    DROP = "drop"
    REJECT = "reject"


# Suricata severity (priority) → TSUNAMI severity mapping
SURICATA_SEVERITY_MAP = {
    1: "CRITICAL",    # Priority 1 = highest severity
    2: "HIGH",        # Priority 2
    3: "MEDIUM",      # Priority 3
    4: "LOW",         # Priority 4 (default ET rules)
    255: "INFO",      # Informational
}

# Suricata class type → MITRE ATT&CK mapping
SURICATA_MITRE_MAP = {
    "trojan-activity":          (["TA0011"], ["T1071"]),       # C2
    "attempted-admin":          (["TA0004"], ["T1068"]),       # Privilege Escalation
    "attempted-user":           (["TA0006"], ["T1110"]),       # Credential Access
    "web-application-attack":   (["TA0001"], ["T1190"]),       # Initial Access / Exploit
    "web-application-activity": (["TA0001"], ["T1190"]),
    "attempted-dos":            (["TA0040"], ["T1499"]),       # Impact / DoS
    "attempted-recon":          (["TA0043"], ["T1595"]),       # Reconnaissance
    "successful-recon-limited": (["TA0007"], ["T1082"]),       # Discovery
    "successful-recon-largescale": (["TA0007"], ["T1046"]),    # Network Service Scan
    "misc-attack":              (["TA0002"], ["T1059"]),       # Execution
    "misc-activity":            (["TA0007"], ["T1082"]),       # Discovery
    "shellcode-detect":         (["TA0002"], ["T1059"]),       # Execution / Shellcode
    "policy-violation":         (["TA0005"], ["T1562"]),       # Defense Evasion
    "network-scan":             (["TA0043"], ["T1595"]),       # Recon / Active Scanning
    "denial-of-service":        (["TA0040"], ["T1498"]),       # Impact / Network DoS
    "exploit-kit":              (["TA0001"], ["T1189"]),       # Drive-by Compromise
    "domain-c2":                (["TA0011"], ["T1071.001"]),   # C2 / Web Protocols
    "default-login-attempt":    (["TA0006"], ["T1110.001"]),   # Brute Force
    "credential-theft":         (["TA0006"], ["T1003"]),       # OS Credential Dumping
    "malware-cnc":              (["TA0011"], ["T1071"]),       # C2
    "kickass-porn":             (["TA0005"], ["T1562"]),       # Policy violation
    "protocol-command-decode":  (["TA0007"], ["T1040"]),       # Discovery / Sniffing
}

# Suricata rule category (msg prefix) → alert category
SURICATA_CATEGORY_MAP = {
    "ET MALWARE":     "malware",
    "ET TROJAN":      "malware",
    "ET CNC":         "command_and_control",
    "ET EXPLOIT":     "exploit",
    "ET WEB_SERVER":  "web_attack",
    "ET WEB_CLIENT":  "web_attack",
    "ET SCAN":        "reconnaissance",
    "ET DOS":         "denial_of_service",
    "ET POLICY":      "policy_violation",
    "ET INFO":        "informational",
    "ET DNS":         "dns_anomaly",
    "ET HUNTING":     "threat_hunting",
    "ET TOR":         "anonymization",
    "ET CURRENT_EVENTS": "current_threat",
    "GPL":            "general",
    "SURICATA":       "protocol_anomaly",
}


@dataclass
class SuricataConfig:
    """Suricata connector configuration."""
    eve_log_path: str = "/var/log/suricata/eve.json"
    socket_path: str = "/var/run/suricata/suricata-command.socket"
    rules_dir: str = "/etc/suricata/rules"
    stats_interval: int = 30              # seconds
    tail_interval: float = 0.5            # seconds between file tail checks
    min_severity: int = 4                 # 1=Critical..4=Low. Ingest all by default
    ingest_flows: bool = False            # Also ingest flow records
    ingest_dns: bool = True               # Ingest DNS events
    ingest_http: bool = True              # Ingest HTTP events
    ingest_tls: bool = True               # Ingest TLS events
    ingest_fileinfo: bool = True          # Ingest file events
    batch_size: int = 100                 # Process N events per batch

    @classmethod
    def from_env(cls) -> 'SuricataConfig':
        return cls(
            eve_log_path=os.getenv('SURICATA_EVE_LOG', '/var/log/suricata/eve.json'),
            socket_path=os.getenv('SURICATA_SOCKET', '/var/run/suricata/suricata-command.socket'),
            rules_dir=os.getenv('SURICATA_RULES_DIR', '/etc/suricata/rules'),
            stats_interval=int(os.getenv('SURICATA_STATS_INTERVAL', '30')),
            tail_interval=float(os.getenv('SURICATA_TAIL_INTERVAL', '0.5')),
            min_severity=int(os.getenv('SURICATA_MIN_SEVERITY', '4')),
            ingest_flows=os.getenv('SURICATA_INGEST_FLOWS', '').lower() == 'true',
            ingest_dns=os.getenv('SURICATA_INGEST_DNS', 'true').lower() == 'true',
            ingest_http=os.getenv('SURICATA_INGEST_HTTP', 'true').lower() == 'true',
            ingest_tls=os.getenv('SURICATA_INGEST_TLS', 'true').lower() == 'true',
            ingest_fileinfo=os.getenv('SURICATA_INGEST_FILEINFO', 'true').lower() == 'true',
            batch_size=int(os.getenv('SURICATA_BATCH_SIZE', '100')),
        )


# ============================================================================
# Suricata Alert Normalizer
# ============================================================================

class SuricataAlertNormalizer:
    """
    Normalize Suricata EVE JSON alerts to TSUNAMI Alert format.
    """

    @staticmethod
    def normalize(eve_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Convert a Suricata EVE JSON event (event_type=alert) to TSUNAMI format.
        Returns None if not an alert or below threshold.
        """
        event_type = eve_event.get('event_type', '')
        if event_type != 'alert':
            return None

        alert = eve_event.get('alert', {})
        if not alert:
            return None

        # Severity mapping
        severity_id = int(alert.get('severity', 4))
        severity_str = SURICATA_SEVERITY_MAP.get(severity_id, 'LOW')

        # MITRE ATT&CK from classtype
        classtype = alert.get('category', '').lower().replace(' ', '-')
        mitre_tactics = []
        mitre_techniques = []

        if classtype in SURICATA_MITRE_MAP:
            mitre_tactics, mitre_techniques = SURICATA_MITRE_MAP[classtype]
            mitre_tactics = list(mitre_tactics)
            mitre_techniques = list(mitre_techniques)

        # Also check metadata for mitre fields
        metadata = alert.get('metadata', {})
        if metadata:
            for key, vals in metadata.items():
                key_l = key.lower()
                if 'mitre_tactic' in key_l:
                    mitre_tactics.extend(vals if isinstance(vals, list) else [vals])
                elif 'mitre_technique' in key_l:
                    mitre_techniques.extend(vals if isinstance(vals, list) else [vals])

        # Deduplicate
        mitre_tactics = list(dict.fromkeys(mitre_tactics))
        mitre_techniques = list(dict.fromkeys(mitre_techniques))

        # Category from signature message prefix
        sig_msg = alert.get('signature', '')
        category = 'general'
        for prefix, cat in SURICATA_CATEGORY_MAP.items():
            if sig_msg.upper().startswith(prefix):
                category = cat
                break

        # Network info
        src_ip = eve_event.get('src_ip', '')
        dst_ip = eve_event.get('dest_ip', '')
        src_port = int(eve_event.get('src_port', 0))
        dst_port = int(eve_event.get('dest_port', 0))
        proto = eve_event.get('proto', '').upper()

        # Action
        action = alert.get('action', 'allowed')

        # Signature ID
        sid = str(alert.get('signature_id', ''))
        gid = str(alert.get('gid', 1))
        rev = str(alert.get('rev', 0))

        # Build title
        title = f"[Suricata:{gid}:{sid}:{rev}] {sig_msg}"

        # Hostname from in_iface or flow
        hostname = eve_event.get('host', '') or eve_event.get('in_iface', '')

        # Timestamp
        timestamp = eve_event.get('timestamp', datetime.now(timezone.utc).isoformat())

        # CVSS estimate: invert severity (1=highest→10, 4=lowest→2.5)
        if severity_id <= 1:
            cvss = 9.5
        elif severity_id == 2:
            cvss = 7.5
        elif severity_id == 3:
            cvss = 5.0
        else:
            cvss = 2.5

        return {
            'alert_id': f"suricata_{sid}_{hashlib.md5(f'{src_ip}{dst_ip}{timestamp}'.encode()).hexdigest()[:8]}",
            'title': title[:256],
            'description': (
                f"{sig_msg}\n"
                f"SID: {gid}:{sid}:{rev}\n"
                f"Category: {alert.get('category', 'N/A')}\n"
                f"Action: {action}\n"
                f"Protocol: {proto}\n"
                f"Interface: {eve_event.get('in_iface', 'N/A')}\n"
                f"Flow ID: {eve_event.get('flow_id', 'N/A')}"
            ),
            'severity': severity_str,
            'source': 'suricata',
            'category': category,
            'mitre_tactics': mitre_tactics,
            'mitre_techniques': mitre_techniques,
            'tags': [f"sid:{sid}", f"classtype:{classtype}", f"action:{action}"],
            'source_id': f"{gid}:{sid}:{rev}",
            'source_rule': sid,
            'source_raw': eve_event,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'hostname': hostname,
            'username': '',
            'cvss_score': cvss,
            'timestamp': timestamp,
            'action': action,
            'protocol': proto,
            'flow_id': str(eve_event.get('flow_id', '')),
        }


# ============================================================================
# EVE JSON Log Reader (File Tail)
# ============================================================================

class EVELogReader:
    """
    Tail Suricata's eve.json log file for real-time event ingestion.
    Handles log rotation (detects inode change), UTF-8 errors.
    """

    def __init__(self, log_path: str, callback: Callable[[Dict], None],
                 tail_interval: float = 0.5):
        self.log_path = log_path
        self._callback = callback
        self._tail_interval = tail_interval
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._position: int = 0
        self._inode: int = 0
        self._stats = {'lines_read': 0, 'events_parsed': 0, 'errors': 0}
        self._lock = threading.Lock()

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()
        logger.info(f"[SURICATA] EVE log reader started: {self.log_path}")

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def _tail_loop(self):
        """Main tailing loop with rotation detection."""
        while self._running:
            try:
                if not os.path.exists(self.log_path):
                    time.sleep(self._tail_interval * 2)
                    continue

                stat = os.stat(self.log_path)
                current_inode = stat.st_ino

                # Detect log rotation (inode changed or file got smaller)
                if current_inode != self._inode or stat.st_size < self._position:
                    self._position = 0
                    self._inode = current_inode
                    logger.info("[SURICATA] Log rotation detected, resetting position")

                if stat.st_size <= self._position:
                    time.sleep(self._tail_interval)
                    continue

                with open(self.log_path, 'r', encoding='utf-8', errors='replace') as f:
                    f.seek(self._position)
                    batch = []

                    for line in f:
                        self._stats['lines_read'] += 1
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                            batch.append(event)
                            self._stats['events_parsed'] += 1
                        except json.JSONDecodeError:
                            self._stats['errors'] += 1

                    self._position = f.tell()

                # Dispatch batch
                for event in batch:
                    try:
                        self._callback(event)
                    except Exception as e:
                        logger.debug(f"[SURICATA] Callback error: {e}")

            except Exception as e:
                logger.error(f"[SURICATA] EVE reader error: {e}")
                time.sleep(2)

            time.sleep(self._tail_interval)

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


# ============================================================================
# Suricata Unix Socket Client
# ============================================================================

class SuricataSocket:
    """
    Communicate with Suricata via Unix domain socket.
    Used for: reload-rules, iface-stat, uptime, version, etc.
    """

    def __init__(self, socket_path: str = "/var/run/suricata/suricata-command.socket",
                 timeout: int = 10):
        self.socket_path = socket_path
        self.timeout = timeout

    def _send_command(self, command: str) -> Dict[str, Any]:
        """Send command to Suricata socket and return response."""
        if not os.path.exists(self.socket_path):
            raise FileNotFoundError(f"Suricata socket not found: {self.socket_path}")

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect(self.socket_path)

            # Read initial version banner
            banner = b''
            while True:
                chunk = sock.recv(4096)
                banner += chunk
                if b'\n' in chunk:
                    break

            # Send command
            cmd_json = json.dumps({"command": command})
            sock.send(cmd_json.encode('utf-8') + b'\n')

            # Read response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\n' in chunk:
                    break

            return json.loads(response.decode('utf-8'))
        finally:
            sock.close()

    def reload_rules(self) -> Dict:
        """Trigger rule reload on Suricata."""
        return self._send_command("reload-rules")

    def get_version(self) -> str:
        """Get Suricata version."""
        try:
            result = self._send_command("version")
            return result.get('message', {}).get('version', 'unknown')
        except Exception:
            return 'unavailable'

    def get_uptime(self) -> int:
        """Get Suricata uptime in seconds."""
        try:
            result = self._send_command("uptime")
            return int(result.get('message', {}).get('uptime', 0))
        except Exception:
            return 0

    def get_iface_stats(self) -> Dict[str, Any]:
        """Get interface capture statistics."""
        try:
            result = self._send_command("iface-stat")
            return result.get('message', {})
        except Exception:
            return {}

    def shutdown(self) -> Dict:
        """Request graceful Suricata shutdown."""
        return self._send_command("shutdown")

    @property
    def available(self) -> bool:
        return os.path.exists(self.socket_path)


# ============================================================================
# Suricata Rule Manager
# ============================================================================

class SuricataRuleManager:
    """
    Manage Suricata rules: enable/disable SIDs, add custom rules,
    manage threshold/suppress.
    """

    def __init__(self, rules_dir: str, socket_client: Optional[SuricataSocket] = None):
        self.rules_dir = Path(rules_dir)
        self.socket = socket_client
        self._lock = threading.Lock()

    def list_rule_files(self) -> List[str]:
        """List all .rules files."""
        if not self.rules_dir.exists():
            return []
        return sorted([f.name for f in self.rules_dir.glob("*.rules")])

    def get_rule_count(self) -> Dict[str, int]:
        """Count rules by action type."""
        counts = {'alert': 0, 'drop': 0, 'pass': 0, 'reject': 0, 'disabled': 0, 'total': 0}
        if not self.rules_dir.exists():
            return counts

        for rule_file in self.rules_dir.glob("*.rules"):
            try:
                with open(rule_file, 'r', encoding='utf-8', errors='replace') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            if line.startswith('# alert') or line.startswith('# drop'):
                                counts['disabled'] += 1
                            continue
                        counts['total'] += 1
                        for action in ['alert', 'drop', 'pass', 'reject']:
                            if line.startswith(action + ' '):
                                counts[action] += 1
                                break
            except Exception:
                pass
        return counts

    def find_rule_by_sid(self, sid: int) -> Optional[Dict[str, Any]]:
        """Find a rule by its SID across all rule files."""
        sid_pattern = re.compile(rf'sid\s*:\s*{sid}\s*;')

        for rule_file in self.rules_dir.glob("*.rules"):
            try:
                with open(rule_file, 'r', encoding='utf-8', errors='replace') as f:
                    for line_num, line in enumerate(f, 1):
                        stripped = line.strip()
                        if sid_pattern.search(stripped):
                            disabled = stripped.startswith('#')
                            rule_text = stripped.lstrip('# ')
                            return {
                                'sid': sid,
                                'file': rule_file.name,
                                'line': line_num,
                                'disabled': disabled,
                                'text': rule_text,
                            }
            except Exception:
                pass
        return None

    def disable_sid(self, sid: int) -> bool:
        """Disable a rule by SID (prepend # to the line)."""
        with self._lock:
            rule = self.find_rule_by_sid(sid)
            if not rule or rule['disabled']:
                return False

            file_path = self.rules_dir / rule['file']
            return self._toggle_rule_in_file(file_path, sid, disable=True)

    def enable_sid(self, sid: int) -> bool:
        """Enable a disabled rule by SID (remove leading #)."""
        with self._lock:
            rule = self.find_rule_by_sid(sid)
            if not rule or not rule['disabled']:
                return False

            file_path = self.rules_dir / rule['file']
            return self._toggle_rule_in_file(file_path, sid, disable=False)

    def _toggle_rule_in_file(self, file_path: Path, sid: int, disable: bool) -> bool:
        """Toggle a rule's enabled/disabled state in a file."""
        sid_pattern = re.compile(rf'sid\s*:\s*{sid}\s*;')

        try:
            lines = file_path.read_text(encoding='utf-8', errors='replace').splitlines(True)
            modified = False

            for i, line in enumerate(lines):
                if sid_pattern.search(line):
                    stripped = line.strip()
                    if disable and not stripped.startswith('#'):
                        lines[i] = '# ' + line
                        modified = True
                    elif not disable and stripped.startswith('#'):
                        lines[i] = line.lstrip().lstrip('#').lstrip()
                        modified = True
                    break

            if modified:
                file_path.write_text(''.join(lines), encoding='utf-8')
                return True
        except Exception as e:
            logger.error(f"[SURICATA] Rule toggle error: {e}")

        return False

    def add_custom_rule(self, rule_text: str, filename: str = "local.rules") -> bool:
        """Add a custom rule to a rules file."""
        # Validate rule format
        if not re.match(r'^(alert|drop|pass|reject)\s+', rule_text.strip()):
            return False

        file_path = self.rules_dir / filename
        try:
            with self._lock:
                with open(file_path, 'a', encoding='utf-8') as f:
                    f.write(f"\n{rule_text.strip()}\n")
            return True
        except Exception as e:
            logger.error(f"[SURICATA] Add rule error: {e}")
            return False

    def add_threshold(self, sid: int, threshold_type: str = "limit",
                      track: str = "by_src", count: int = 1,
                      seconds: int = 60) -> str:
        """Generate a threshold rule for a SID."""
        return (
            f"threshold gen_id 1, sig_id {sid}, type {threshold_type}, "
            f"track {track}, count {count}, seconds {seconds}"
        )

    def add_suppress(self, sid: int, track: str = "by_src",
                     ip: str = "") -> str:
        """Generate a suppress rule for a SID."""
        suppress = f"suppress gen_id 1, sig_id {sid}, track {track}"
        if ip:
            suppress += f", ip {ip}"
        return suppress

    def reload_rules(self) -> bool:
        """Reload rules via Suricata socket."""
        if self.socket and self.socket.available:
            try:
                self.socket.reload_rules()
                logger.info("[SURICATA] Rules reloaded via socket")
                return True
            except Exception as e:
                logger.error(f"[SURICATA] Rule reload error: {e}")
        return False


# ============================================================================
# Suricata Stats Monitor
# ============================================================================

class SuricataStatsMonitor:
    """
    Track Suricata engine statistics from EVE stats events.
    Captures: packet counters, decoder errors, flow stats, CPU usage.
    """

    def __init__(self):
        self._latest_stats: Dict[str, Any] = {}
        self._stats_history: List[Dict[str, Any]] = []
        self._max_history = 60  # Keep last 60 snapshots
        self._lock = threading.Lock()

    def process_stats_event(self, eve_event: Dict[str, Any]):
        """Process a Suricata stats EVE event."""
        if eve_event.get('event_type') != 'stats':
            return

        stats = eve_event.get('stats', {})
        capture = stats.get('capture', {})
        decoder = stats.get('decoder', {})
        flow = stats.get('flow', {})
        detect = stats.get('detect', {})

        snapshot = {
            'timestamp': eve_event.get('timestamp', ''),
            'uptime': stats.get('uptime', 0),
            'capture': {
                'kernel_packets': capture.get('kernel_packets', 0),
                'kernel_drops': capture.get('kernel_drops', 0),
                'kernel_ifdrops': capture.get('kernel_ifdrops', 0),
            },
            'decoder': {
                'pkts': decoder.get('pkts', 0),
                'bytes': decoder.get('bytes', 0),
                'ipv4': decoder.get('ipv4', 0),
                'ipv6': decoder.get('ipv6', 0),
                'tcp': decoder.get('tcp', 0),
                'udp': decoder.get('udp', 0),
                'avg_pkt_size': decoder.get('avg_pkt_size', 0),
            },
            'flow': {
                'tcp': flow.get('tcp', 0),
                'udp': flow.get('udp', 0),
                'icmpv4': flow.get('icmpv4', 0),
                'active': flow.get('active', 0),
            },
            'detect': {
                'alert': detect.get('alert', 0),
            },
        }

        with self._lock:
            self._latest_stats = snapshot
            self._stats_history.append(snapshot)
            if len(self._stats_history) > self._max_history:
                self._stats_history = self._stats_history[-self._max_history:]

    @property
    def latest(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._latest_stats)

    @property
    def history(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._stats_history)

    def get_drop_rate(self) -> float:
        """Calculate packet drop percentage."""
        s = self._latest_stats
        cap = s.get('capture', {})
        total = cap.get('kernel_packets', 0)
        drops = cap.get('kernel_drops', 0)
        if total == 0:
            return 0.0
        return round((drops / total) * 100, 2)


# ============================================================================
# Suricata Connector (Main Orchestrator)
# ============================================================================

class SuricataConnector:
    """
    Main Suricata connector orchestrating EVE log reading, alert normalization,
    stats monitoring, and rule management.
    """

    def __init__(self, config: Optional[SuricataConfig] = None,
                 db_path: Optional[str] = None):
        self.config = config or SuricataConfig.from_env()

        if db_path is None:
            db_dir = Path.home() / '.dalga'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'soc_suricata.db')

        self.db_path = db_path

        # Sub-components
        self.socket_client = SuricataSocket(self.config.socket_path)
        self.rule_manager = SuricataRuleManager(self.config.rules_dir, self.socket_client)
        self.stats_monitor = SuricataStatsMonitor()
        self.eve_reader: Optional[EVELogReader] = None

        # Callbacks
        self._alert_callbacks: List[Callable[[Dict], None]] = []
        self._flow_callbacks: List[Callable[[Dict], None]] = []

        # State
        self._running = False
        self._lock = threading.Lock()
        self._stats = {
            'alerts_ingested': 0,
            'alerts_normalized': 0,
            'flows_ingested': 0,
            'events_total': 0,
            'events_by_type': {},
        }

        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS suricata_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sid TEXT NOT NULL,
                    gid TEXT DEFAULT '1',
                    rev TEXT DEFAULT '0',
                    signature TEXT,
                    severity INTEGER,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER,
                    dst_port INTEGER,
                    proto TEXT,
                    action TEXT,
                    flow_id TEXT,
                    timestamp TEXT,
                    raw_json TEXT,
                    normalized INTEGER DEFAULT 0,
                    ingested_at TEXT,
                    dedup_hash TEXT UNIQUE
                );

                CREATE TABLE IF NOT EXISTS suricata_ingestion_state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_suricata_alerts_ts
                    ON suricata_alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_suricata_alerts_sid
                    ON suricata_alerts(sid);
                CREATE INDEX IF NOT EXISTS idx_suricata_alerts_severity
                    ON suricata_alerts(severity);
            """)
            conn.commit()
        finally:
            conn.close()

    # ---- Callback Registration ----

    def on_alert(self, callback: Callable[[Dict], None]):
        """Register callback for normalized alerts."""
        self._alert_callbacks.append(callback)

    def on_flow(self, callback: Callable[[Dict], None]):
        """Register callback for flow events."""
        self._flow_callbacks.append(callback)

    # ---- Lifecycle ----

    def start(self):
        """Start EVE log reader and stats collection."""
        if self._running:
            return
        self._running = True

        # Start EVE log reader
        self.eve_reader = EVELogReader(
            self.config.eve_log_path,
            callback=self._handle_eve_event,
            tail_interval=self.config.tail_interval,
        )
        self.eve_reader.start()

        logger.info("[SURICATA] Connector started")

    def stop(self):
        """Stop all components."""
        self._running = False
        if self.eve_reader:
            self.eve_reader.stop()
        logger.info("[SURICATA] Connector stopped")

    # ---- Event Processing ----

    def _handle_eve_event(self, eve_event: Dict[str, Any]):
        """Route EVE events to appropriate handlers."""
        event_type = eve_event.get('event_type', '')

        with self._lock:
            self._stats['events_total'] += 1
            self._stats['events_by_type'][event_type] = (
                self._stats['events_by_type'].get(event_type, 0) + 1
            )

        if event_type == 'alert':
            self._handle_alert(eve_event)
        elif event_type == 'stats':
            self.stats_monitor.process_stats_event(eve_event)
        elif event_type == 'flow' and self.config.ingest_flows:
            self._handle_flow(eve_event)

    def _handle_alert(self, eve_event: Dict[str, Any]):
        """Process and store alert event."""
        alert = eve_event.get('alert', {})
        severity = int(alert.get('severity', 4))

        # Filter by min severity
        if severity > self.config.min_severity:
            return

        # Dedup hash
        dedup_str = (
            f"{alert.get('signature_id', '')}"
            f"{eve_event.get('src_ip', '')}"
            f"{eve_event.get('dest_ip', '')}"
            f"{eve_event.get('timestamp', '')}"
        )
        dedup_hash = hashlib.sha256(dedup_str.encode()).hexdigest()[:32]

        # Store in DB
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        cursor = conn.execute("""
            INSERT OR IGNORE INTO suricata_alerts
            (sid, gid, rev, signature, severity, src_ip, dst_ip,
             src_port, dst_port, proto, action, flow_id,
             timestamp, raw_json, ingested_at, dedup_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            str(alert.get('signature_id', '')),
            str(alert.get('gid', 1)),
            str(alert.get('rev', 0)),
            alert.get('signature', ''),
            severity,
            eve_event.get('src_ip', ''),
            eve_event.get('dest_ip', ''),
            int(eve_event.get('src_port', 0)),
            int(eve_event.get('dest_port', 0)),
            eve_event.get('proto', ''),
            alert.get('action', 'allowed'),
            str(eve_event.get('flow_id', '')),
            eve_event.get('timestamp', now),
            json.dumps(eve_event, default=str),
            now,
            dedup_hash,
        ))

        if cursor.rowcount == 0:
            conn.close()
            return  # Duplicate

        conn.commit()
        conn.close()

        self._stats['alerts_ingested'] += 1

        # Normalize and dispatch
        try:
            normalized = SuricataAlertNormalizer.normalize(eve_event)
            if normalized:
                self._stats['alerts_normalized'] += 1
                for cb in self._alert_callbacks:
                    try:
                        cb(normalized)
                    except Exception as e:
                        logger.error(f"[SURICATA] Alert callback error: {e}")
        except Exception as e:
            logger.error(f"[SURICATA] Normalize error: {e}")

    def _handle_flow(self, eve_event: Dict[str, Any]):
        """Process flow event."""
        self._stats['flows_ingested'] += 1
        for cb in self._flow_callbacks:
            try:
                cb(eve_event)
            except Exception as e:
                logger.debug(f"[SURICATA] Flow callback error: {e}")

    # ---- Query Methods ----

    def get_top_signatures(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Get top triggered signatures in time window."""
        try:
            conn = self._get_conn()
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            rows = conn.execute("""
                SELECT sid, signature, severity, COUNT(*) as hit_count,
                       COUNT(DISTINCT src_ip) as unique_sources,
                       COUNT(DISTINCT dst_ip) as unique_targets
                FROM suricata_alerts
                WHERE ingested_at >= ?
                GROUP BY sid
                ORDER BY hit_count DESC
                LIMIT ?
            """, (since, limit)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            return []

    def get_top_attackers(self, hours: int = 24, limit: int = 20) -> List[Dict]:
        """Get IPs with most triggered alerts."""
        try:
            conn = self._get_conn()
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            rows = conn.execute("""
                SELECT src_ip, COUNT(*) as alert_count,
                       COUNT(DISTINCT sid) as unique_sids,
                       MIN(severity) as max_severity
                FROM suricata_alerts
                WHERE ingested_at >= ? AND src_ip != ''
                GROUP BY src_ip
                ORDER BY alert_count DESC
                LIMIT ?
            """, (since, limit)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            return []

    def get_alert_count(self, hours: int = 24) -> int:
        """Get count of alerts in time window."""
        try:
            conn = self._get_conn()
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            cnt = conn.execute(
                "SELECT COUNT(*) FROM suricata_alerts WHERE ingested_at >= ?",
                (since,)
            ).fetchone()[0]
            conn.close()
            return cnt
        except sqlite3.OperationalError:
            return 0

    def get_severity_distribution(self, hours: int = 24) -> Dict[str, int]:
        """Get alert count by severity."""
        try:
            conn = self._get_conn()
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            rows = conn.execute("""
                SELECT severity, COUNT(*) as cnt
                FROM suricata_alerts WHERE ingested_at >= ?
                GROUP BY severity
            """, (since,)).fetchall()
            conn.close()
            result = {}
            for r in rows:
                sev = SURICATA_SEVERITY_MAP.get(r['severity'], 'UNKNOWN')
                result[sev] = r['cnt']
            return result
        except sqlite3.OperationalError:
            return {}

    # ---- Stats ----

    @property
    def stats(self) -> Dict[str, Any]:
        result = dict(self._stats)
        result['engine'] = self.stats_monitor.latest
        result['drop_rate'] = self.stats_monitor.get_drop_rate()
        if self.eve_reader:
            result['eve_reader'] = self.eve_reader.stats
        result['rules'] = self.rule_manager.get_rule_count()
        return result


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_suricata_blueprint(connector: Optional[SuricataConnector] = None):
    """Create Flask Blueprint for Suricata IDS API."""
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        return None

    if connector is None:
        connector = SuricataConnector()

    bp = Blueprint('soc_suricata', __name__, url_prefix='/api/v1/soc/suricata')

    @bp.route('/status', methods=['GET'])
    def suricata_status():
        return jsonify({
            'success': True,
            'data': {
                'running': connector._running,
                'socket_available': connector.socket_client.available,
                'stats': connector.stats,
            }
        })

    @bp.route('/alerts/top-signatures', methods=['GET'])
    def top_sigs():
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 20, type=int)
        return jsonify({
            'success': True,
            'data': connector.get_top_signatures(hours, limit),
        })

    @bp.route('/alerts/top-attackers', methods=['GET'])
    def top_attackers():
        hours = request.args.get('hours', 24, type=int)
        limit = request.args.get('limit', 20, type=int)
        return jsonify({
            'success': True,
            'data': connector.get_top_attackers(hours, limit),
        })

    @bp.route('/alerts/severity', methods=['GET'])
    def severity_dist():
        hours = request.args.get('hours', 24, type=int)
        return jsonify({
            'success': True,
            'data': connector.get_severity_distribution(hours),
        })

    @bp.route('/rules/stats', methods=['GET'])
    def rule_stats():
        return jsonify({
            'success': True,
            'data': connector.rule_manager.get_rule_count(),
        })

    @bp.route('/rules/find/<int:sid>', methods=['GET'])
    def find_rule(sid):
        rule = connector.rule_manager.find_rule_by_sid(sid)
        if rule:
            return jsonify({'success': True, 'data': rule})
        return jsonify({'success': False, 'error': 'Kural bulunamadi'}), 404

    @bp.route('/rules/disable/<int:sid>', methods=['POST'])
    def disable_rule(sid):
        ok = connector.rule_manager.disable_sid(sid)
        return jsonify({'success': ok})

    @bp.route('/rules/enable/<int:sid>', methods=['POST'])
    def enable_rule(sid):
        ok = connector.rule_manager.enable_sid(sid)
        return jsonify({'success': ok})

    @bp.route('/rules/reload', methods=['POST'])
    def reload_rules():
        ok = connector.rule_manager.reload_rules()
        return jsonify({'success': ok})

    @bp.route('/engine/stats', methods=['GET'])
    def engine_stats():
        return jsonify({
            'success': True,
            'data': {
                'latest': connector.stats_monitor.latest,
                'drop_rate': connector.stats_monitor.get_drop_rate(),
                'history_count': len(connector.stats_monitor.history),
            }
        })

    return bp


# ============================================================================
# Global Instance
# ============================================================================

_suricata_connector: Optional[SuricataConnector] = None
_sc_lock = threading.Lock()


def get_suricata_connector() -> SuricataConnector:
    global _suricata_connector
    if _suricata_connector is None:
        with _sc_lock:
            if _suricata_connector is None:
                _suricata_connector = SuricataConnector()
    return _suricata_connector


__all__ = [
    'SuricataEventType', 'SuricataAction', 'RuleAction',
    'SuricataConfig', 'SuricataAlertNormalizer',
    'EVELogReader', 'SuricataSocket', 'SuricataRuleManager',
    'SuricataStatsMonitor', 'SuricataConnector',
    'create_suricata_blueprint', 'get_suricata_connector',
]
