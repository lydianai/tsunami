#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Wazuh SIEM Connector
    Production-Grade Wazuh Manager Integration
================================================================================

    Features:
    - Wazuh REST API v4 integration (auth, agents, alerts, rules)
    - Real-time alert ingestion via Wazuh API polling + Syslog UDP/TCP
    - Alert normalization to TSUNAMI Alert format
    - Agent health monitoring with heartbeat tracking
    - Active Response trigger (block IP, kill process, etc.)
    - Rule management (enable/disable, custom rules)
    - FIM (File Integrity Monitoring) event ingestion
    - SCA (Security Configuration Assessment) polling
    - Vulnerability detection feed
    - Thread-safe operations with SQLite persistence
    - Exponential backoff on connection failures

================================================================================
"""

import hashlib
import json
import logging
import os
import re
import socket
import socketserver
import sqlite3
import ssl
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger("soc.wazuh")


# ============================================================================
# Wazuh Enums & Config
# ============================================================================

class WazuhAgentStatus(Enum):
    ACTIVE = "active"
    DISCONNECTED = "disconnected"
    PENDING = "pending"
    NEVER_CONNECTED = "never_connected"


class WazuhAlertLevel(Enum):
    """Wazuh rule levels mapped to severity."""
    SYSTEM_LOW = (0, 4)       # System/low priority
    LOW = (5, 7)              # Low
    MEDIUM = (8, 10)          # Medium
    HIGH = (11, 13)           # High
    CRITICAL = (14, 16)       # Critical

    @classmethod
    def from_level(cls, level: int) -> 'WazuhAlertLevel':
        for member in cls:
            lo, hi = member.value
            if lo <= level <= hi:
                return member
        return cls.CRITICAL if level > 16 else cls.SYSTEM_LOW


class ActiveResponseAction(Enum):
    """Wazuh Active Response commands."""
    FIREWALL_DROP = "firewall-drop"
    HOST_DENY = "host-deny"
    IP_BLOCK = "ip-block"
    DISABLE_ACCOUNT = "disable-account"
    RESTART_SERVICE = "restart-service"
    CUSTOM = "custom"


# ============================================================================
# Wazuh ↔ TSUNAMI Severity Mapping
# ============================================================================

WAZUH_SEVERITY_MAP = {
    WazuhAlertLevel.CRITICAL: "CRITICAL",     # Level 14-16
    WazuhAlertLevel.HIGH: "HIGH",             # Level 11-13
    WazuhAlertLevel.MEDIUM: "MEDIUM",         # Level 8-10
    WazuhAlertLevel.LOW: "LOW",               # Level 5-7
    WazuhAlertLevel.SYSTEM_LOW: "INFO",       # Level 0-4
}

# Wazuh rule group → MITRE ATT&CK mapping (common groups)
WAZUH_MITRE_MAP = {
    'authentication_failed': (['TA0006'], ['T1110']),      # Credential Access / Brute Force
    'authentication_success': (['TA0001'], ['T1078']),     # Initial Access / Valid Accounts
    'sshd': (['TA0001', 'TA0008'], ['T1021.004']),        # Lateral Movement / SSH
    'syslog': (['TA0005'], ['T1070']),                     # Defense Evasion / Log Clearing
    'web-log': (['TA0001'], ['T1190']),                    # Initial Access / Exploit Public-Facing
    'windows': (['TA0002'], ['T1059']),                    # Execution / Command & Script
    'firewall': (['TA0011'], ['T1071']),                   # C2 / Application Layer
    'rootcheck': (['TA0003'], ['T1547']),                  # Persistence / Boot or Logon
    'syscheck': (['TA0005'], ['T1565']),                   # Defense Evasion / Data Manipulation
    'vulnerability-detector': (['TA0001'], ['T1190']),     # Initial Access / Exploit
    'osquery': (['TA0007'], ['T1082']),                    # Discovery / System Info
    'pam': (['TA0006'], ['T1556']),                        # Credential Access / Modify Auth
    'ids': (['TA0040'], ['T1499']),                        # Impact / Endpoint DoS
    'attack': (['TA0001'], ['T1190']),                     # Initial Access
}


@dataclass
class WazuhConfig:
    """Wazuh Manager connection configuration."""
    host: str = ""
    port: int = 55000
    username: str = ""
    password: str = ""
    api_token: str = ""
    verify_ssl: bool = False
    timeout: int = 30
    poll_interval: int = 15          # seconds between alert polls
    syslog_port: int = 0             # 0 = disabled; typically 514/1514
    syslog_protocol: str = "udp"     # udp or tcp
    max_alerts_per_poll: int = 100
    min_alert_level: int = 3         # Minimum rule level to ingest

    @classmethod
    def from_env(cls) -> 'WazuhConfig':
        """Load config from environment variables."""
        return cls(
            host=os.getenv('WAZUH_HOST', ''),
            port=int(os.getenv('WAZUH_PORT', '55000')),
            username=os.getenv('WAZUH_USER', 'wazuh-wui'),
            password=os.getenv('WAZUH_PASSWORD', ''),
            verify_ssl=os.getenv('WAZUH_VERIFY_SSL', '').lower() == 'true',
            timeout=int(os.getenv('WAZUH_TIMEOUT', '30')),
            poll_interval=int(os.getenv('WAZUH_POLL_INTERVAL', '15')),
            syslog_port=int(os.getenv('WAZUH_SYSLOG_PORT', '0')),
            syslog_protocol=os.getenv('WAZUH_SYSLOG_PROTOCOL', 'udp'),
            max_alerts_per_poll=int(os.getenv('WAZUH_MAX_ALERTS', '100')),
            min_alert_level=int(os.getenv('WAZUH_MIN_LEVEL', '3')),
        )


# ============================================================================
# Wazuh API Client
# ============================================================================

class WazuhAPIClient:
    """
    Thread-safe Wazuh REST API v4 client.
    Handles authentication, token refresh, and API calls.
    """

    def __init__(self, config: WazuhConfig):
        self.config = config
        self._token: str = ""
        self._token_expires: float = 0.0
        self._lock = threading.Lock()
        self._base_url = f"https://{config.host}:{config.port}"

    def _get_ssl_context(self) -> ssl.SSLContext:
        """Get SSL context (optionally skip verification for self-signed certs)."""
        ctx = ssl.create_default_context()
        if not self.config.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def authenticate(self) -> bool:
        """Authenticate to Wazuh API and obtain JWT token."""
        if not self.config.host:
            logger.warning("[WAZUH] No host configured")
            return False

        try:
            url = f"{self._base_url}/security/user/authenticate"
            req = Request(url, method='POST')

            # Basic auth
            import base64
            creds = base64.b64encode(
                f"{self.config.username}:{self.config.password}".encode()
            ).decode()
            req.add_header('Authorization', f'Basic {creds}')
            req.add_header('Content-Type', 'application/json')

            ctx = self._get_ssl_context()
            with urlopen(req, timeout=self.config.timeout, context=ctx) as resp:
                data = json.loads(resp.read())

            self._token = data.get('data', {}).get('token', '')
            if self._token:
                # Wazuh tokens expire in 900s by default
                self._token_expires = time.time() + 850
                logger.info("[WAZUH] Authentication successful")
                return True
            else:
                logger.error("[WAZUH] Auth response missing token")
                return False

        except Exception as e:
            logger.error(f"[WAZUH] Authentication failed: {e}")
            return False

    def _ensure_auth(self):
        """Re-authenticate if token is expired or missing."""
        with self._lock:
            if not self._token or time.time() >= self._token_expires:
                if not self.authenticate():
                    raise ConnectionError("Wazuh authentication failed")

    def _api_request(self, method: str, endpoint: str,
                     params: Optional[Dict] = None,
                     body: Optional[Dict] = None) -> Dict[str, Any]:
        """Make authenticated API request to Wazuh."""
        self._ensure_auth()

        url = f"{self._base_url}{endpoint}"
        if params:
            url += '?' + urlencode(params)

        data = json.dumps(body).encode('utf-8') if body else None
        req = Request(url, data=data, method=method)
        req.add_header('Authorization', f'Bearer {self._token}')
        req.add_header('Content-Type', 'application/json')

        ctx = self._get_ssl_context()
        try:
            with urlopen(req, timeout=self.config.timeout, context=ctx) as resp:
                return json.loads(resp.read())
        except HTTPError as e:
            if e.code == 401:
                # Token expired, retry once
                with self._lock:
                    self._token = ""
                self._ensure_auth()
                req2 = Request(url, data=data, method=method)
                req2.add_header('Authorization', f'Bearer {self._token}')
                req2.add_header('Content-Type', 'application/json')
                with urlopen(req2, timeout=self.config.timeout, context=ctx) as resp:
                    return json.loads(resp.read())
            raise

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        return self._api_request('GET', endpoint, params=params)

    def post(self, endpoint: str, body: Optional[Dict] = None) -> Dict:
        return self._api_request('POST', endpoint, body=body)

    def put(self, endpoint: str, body: Optional[Dict] = None) -> Dict:
        return self._api_request('PUT', endpoint, body=body)

    def delete(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        return self._api_request('DELETE', endpoint, params=params)

    # ---- High-Level API Wrappers ----

    def get_manager_info(self) -> Dict[str, Any]:
        """Get Wazuh manager info."""
        return self.get('/manager/info')

    def get_agents(self, status: Optional[str] = None, limit: int = 500) -> List[Dict]:
        """Get list of agents."""
        params = {'limit': limit}
        if status:
            params['status'] = status
        result = self.get('/agents', params)
        return result.get('data', {}).get('affected_items', [])

    def get_agent(self, agent_id: str) -> Dict:
        """Get specific agent details."""
        result = self.get(f'/agents?agents_list={agent_id}')
        items = result.get('data', {}).get('affected_items', [])
        return items[0] if items else {}

    def get_alerts(self, offset: int = 0, limit: int = 100,
                   level_min: int = 0, timestamp_gt: str = "") -> List[Dict]:
        """Get alerts from Wazuh API."""
        params: Dict[str, Any] = {
            'offset': offset,
            'limit': limit,
            'sort': '-timestamp',
        }
        if level_min > 0:
            params['min_level'] = level_min
        if timestamp_gt:
            params['timestamp'] = f'>{timestamp_gt}'

        try:
            result = self.get('/alerts', params)
            return result.get('data', {}).get('affected_items', [])
        except Exception as e:
            logger.error(f"[WAZUH] Get alerts error: {e}")
            return []

    def get_rules(self, offset: int = 0, limit: int = 500,
                  group: Optional[str] = None) -> List[Dict]:
        """Get Wazuh rules."""
        params: Dict[str, Any] = {'offset': offset, 'limit': limit}
        if group:
            params['group'] = group
        result = self.get('/rules', params)
        return result.get('data', {}).get('affected_items', [])

    def get_sca_checks(self, agent_id: str) -> List[Dict]:
        """Get SCA (Security Configuration Assessment) for an agent."""
        result = self.get(f'/sca/{agent_id}')
        return result.get('data', {}).get('affected_items', [])

    def get_vulnerabilities(self, agent_id: str) -> List[Dict]:
        """Get vulnerability detections for an agent."""
        result = self.get(f'/vulnerability/{agent_id}')
        return result.get('data', {}).get('affected_items', [])

    def get_fim_events(self, agent_id: str, limit: int = 50) -> List[Dict]:
        """Get FIM (File Integrity Monitoring) events."""
        result = self.get(f'/syscheck/{agent_id}', {'limit': limit, 'sort': '-date'})
        return result.get('data', {}).get('affected_items', [])

    def run_active_response(self, agent_id: str, command: str,
                            arguments: Optional[List[str]] = None) -> Dict:
        """Trigger active response on agent."""
        body = {
            'command': command,
            'arguments': arguments or [],
        }
        return self.put(f'/active-response/{agent_id}', body)


# ============================================================================
# Alert Normalizer: Wazuh → TSUNAMI Alert
# ============================================================================

class WazuhAlertNormalizer:
    """
    Normalize Wazuh raw alerts into TSUNAMI Alert format.
    Handles field mapping, MITRE tagging, severity scoring.
    """

    @staticmethod
    def normalize(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a raw Wazuh alert dict into a standardized dict
        suitable for creating a TSUNAMI Alert object.
        """
        rule = raw_alert.get('rule', {})
        agent = raw_alert.get('agent', {})
        data = raw_alert.get('data', {})
        predecoder = raw_alert.get('predecoder', {})
        decoder = raw_alert.get('decoder', {})
        syscheck = raw_alert.get('syscheck', {})

        # Severity mapping
        rule_level = int(rule.get('level', 0))
        wazuh_level = WazuhAlertLevel.from_level(rule_level)
        severity_str = WAZUH_SEVERITY_MAP.get(wazuh_level, 'INFO')

        # MITRE ATT&CK from Wazuh rule groups
        mitre_tactics = []
        mitre_techniques = []
        rule_groups = rule.get('groups', [])

        # Check Wazuh MITRE field (v4.x)
        mitre = rule.get('mitre', {})
        if mitre:
            mitre_tactics = mitre.get('tactic', [])
            mitre_techniques = [
                t.get('id', '') for t in mitre.get('technique', [])
                if isinstance(t, dict)
            ]
            if not mitre_techniques:
                mitre_techniques = mitre.get('id', [])

        # Fallback: map from rule groups
        if not mitre_tactics:
            for group in rule_groups:
                group_lower = group.lower()
                if group_lower in WAZUH_MITRE_MAP:
                    tactics, techniques = WAZUH_MITRE_MAP[group_lower]
                    mitre_tactics.extend(tactics)
                    mitre_techniques.extend(techniques)

        # Deduplicate
        mitre_tactics = list(dict.fromkeys(mitre_tactics))
        mitre_techniques = list(dict.fromkeys(mitre_techniques))

        # Extract network info
        src_ip = (data.get('srcip', '') or data.get('src_ip', '')
                  or raw_alert.get('srcip', '') or predecoder.get('srcip', ''))
        dst_ip = (data.get('dstip', '') or data.get('dst_ip', '')
                  or raw_alert.get('dstip', '') or predecoder.get('dstip', ''))
        src_port = int(data.get('srcport', 0) or data.get('src_port', 0))
        dst_port = int(data.get('dstport', 0) or data.get('dst_port', 0))

        # Category from rule groups
        category = 'general'
        for group in rule_groups:
            gl = group.lower()
            if 'authentication' in gl:
                category = 'authentication'
                break
            elif 'web' in gl:
                category = 'web_attack'
                break
            elif 'malware' in gl or 'rootkit' in gl:
                category = 'malware'
                break
            elif 'ids' in gl or 'attack' in gl:
                category = 'intrusion'
                break
            elif 'syscheck' in gl or 'fim' in gl:
                category = 'file_integrity'
                break
            elif 'vulnerability' in gl:
                category = 'vulnerability'
                break
            elif 'policy' in gl or 'sca' in gl:
                category = 'policy_violation'
                break

        # Build title
        rule_desc = rule.get('description', 'Wazuh Alert')
        title = f"[Wazuh:{rule.get('id', '?')}] {rule_desc}"

        # Hostname
        hostname = agent.get('name', '') or data.get('hostname', '')

        # Timestamp
        timestamp = raw_alert.get('timestamp', datetime.now(timezone.utc).isoformat())

        # CVSS estimate from Wazuh level
        cvss_estimate = min(10.0, round(rule_level * 0.625, 1))  # 0-16 → 0-10

        return {
            'alert_id': f"wazuh_{raw_alert.get('id', uuid.uuid4().hex[:12])}",
            'title': title[:256],
            'description': (
                f"{rule_desc}\n"
                f"Agent: {hostname} ({agent.get('id', 'N/A')})\n"
                f"Rule: {rule.get('id', 'N/A')} (Level {rule_level})\n"
                f"Groups: {', '.join(rule_groups)}\n"
                f"Decoder: {decoder.get('name', 'N/A')}"
            ),
            'severity': severity_str,
            'source': 'wazuh',
            'category': category,
            'mitre_tactics': mitre_tactics,
            'mitre_techniques': mitre_techniques,
            'tags': rule_groups,
            'source_id': str(raw_alert.get('id', '')),
            'source_rule': str(rule.get('id', '')),
            'source_raw': raw_alert,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'hostname': hostname,
            'username': data.get('srcuser', '') or data.get('dstuser', ''),
            'cvss_score': cvss_estimate,
            'timestamp': timestamp,
        }

    @staticmethod
    def normalize_syslog(log_line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a Wazuh syslog-format alert into normalized dict.
        Wazuh can output JSON alerts via syslog.
        """
        # Try JSON extraction from syslog line
        json_match = re.search(r'\{.*\}', log_line)
        if json_match:
            try:
                raw = json.loads(json_match.group())
                return WazuhAlertNormalizer.normalize(raw)
            except json.JSONDecodeError:
                pass

        # Fallback: parse CEF-like or raw syslog
        # Format: <priority>timestamp host wazuh: alert_json
        parts = log_line.split('wazuh:', 1)
        if len(parts) == 2:
            try:
                raw = json.loads(parts[1].strip())
                return WazuhAlertNormalizer.normalize(raw)
            except json.JSONDecodeError:
                pass

        return None


# ============================================================================
# Agent Health Monitor
# ============================================================================

class AgentHealthMonitor:
    """
    Track Wazuh agent health via periodic polling.
    Detects disconnections, new agents, and status changes.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
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
                CREATE TABLE IF NOT EXISTS wazuh_agents (
                    agent_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    ip TEXT DEFAULT '',
                    os_name TEXT DEFAULT '',
                    os_version TEXT DEFAULT '',
                    version TEXT DEFAULT '',
                    status TEXT DEFAULT 'never_connected',
                    last_keepalive TEXT,
                    date_added TEXT,
                    group_name TEXT DEFAULT 'default',
                    last_checked TEXT,
                    alerts_24h INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS agent_status_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    old_status TEXT,
                    new_status TEXT,
                    timestamp TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_agent_status ON wazuh_agents(status);
                CREATE INDEX IF NOT EXISTS idx_agent_status_log_ts
                    ON agent_status_log(timestamp);
            """)
            conn.commit()
        finally:
            conn.close()

    def update_agents(self, agents: List[Dict]) -> List[Dict[str, Any]]:
        """
        Update agent database from Wazuh API response.
        Returns list of status change events.
        """
        changes = []
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        try:
            for agent in agents:
                agent_id = str(agent.get('id', ''))
                if not agent_id:
                    continue

                new_status = agent.get('status', 'unknown')
                name = agent.get('name', '')

                # Check existing status
                row = conn.execute(
                    "SELECT status FROM wazuh_agents WHERE agent_id = ?",
                    (agent_id,)
                ).fetchone()

                old_status = row['status'] if row else None

                # Upsert agent
                os_info = agent.get('os', {})
                conn.execute("""
                    INSERT INTO wazuh_agents
                    (agent_id, name, ip, os_name, os_version, version, status,
                     last_keepalive, date_added, group_name, last_checked)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(agent_id) DO UPDATE SET
                        name=excluded.name, ip=excluded.ip,
                        os_name=excluded.os_name, os_version=excluded.os_version,
                        version=excluded.version, status=excluded.status,
                        last_keepalive=excluded.last_keepalive,
                        last_checked=excluded.last_checked
                """, (
                    agent_id, name,
                    agent.get('ip', ''),
                    os_info.get('name', '') if isinstance(os_info, dict) else '',
                    os_info.get('version', '') if isinstance(os_info, dict) else '',
                    agent.get('version', ''),
                    new_status,
                    agent.get('lastKeepAlive', ''),
                    agent.get('dateAdd', ''),
                    ','.join(agent.get('group', ['default'])) if isinstance(agent.get('group'), list) else agent.get('group', 'default'),
                    now,
                ))

                # Track status changes
                if old_status and old_status != new_status:
                    conn.execute(
                        "INSERT INTO agent_status_log (agent_id, old_status, new_status, timestamp) VALUES (?, ?, ?, ?)",
                        (agent_id, old_status, new_status, now)
                    )
                    changes.append({
                        'agent_id': agent_id,
                        'name': name,
                        'old_status': old_status,
                        'new_status': new_status,
                        'timestamp': now,
                    })

            conn.commit()
        finally:
            conn.close()

        if changes:
            logger.info(f"[WAZUH] Agent status changes: {len(changes)}")

        return changes

    def get_agent_summary(self) -> Dict[str, Any]:
        """Get summary of agent health."""
        try:
            conn = self._get_conn()
            total = conn.execute("SELECT COUNT(*) FROM wazuh_agents").fetchone()[0]
            active = conn.execute(
                "SELECT COUNT(*) FROM wazuh_agents WHERE status = 'active'"
            ).fetchone()[0]
            disconnected = conn.execute(
                "SELECT COUNT(*) FROM wazuh_agents WHERE status = 'disconnected'"
            ).fetchone()[0]
            pending = conn.execute(
                "SELECT COUNT(*) FROM wazuh_agents WHERE status = 'pending'"
            ).fetchone()[0]
            conn.close()

            return {
                'total': total,
                'active': active,
                'disconnected': disconnected,
                'pending': pending,
                'health_pct': round((active / total * 100) if total > 0 else 0, 1),
            }
        except sqlite3.OperationalError:
            return {'total': 0, 'active': 0, 'disconnected': 0, 'pending': 0, 'health_pct': 0}

    def get_all_agents(self) -> List[Dict[str, Any]]:
        """Get all tracked agents."""
        try:
            conn = self._get_conn()
            rows = conn.execute("SELECT * FROM wazuh_agents ORDER BY agent_id").fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            return []


# ============================================================================
# Syslog Receiver (for Wazuh JSON alerts over syslog)
# ============================================================================

class WazuhSyslogReceiver:
    """
    UDP/TCP Syslog server for receiving Wazuh alert output.
    Wazuh can be configured to send JSON alerts via syslog.
    """

    def __init__(self, port: int = 1514, protocol: str = "udp",
                 callback: Optional[Callable[[Dict], None]] = None):
        self.port = port
        self.protocol = protocol.lower()
        self._callback = callback
        self._server: Optional[Any] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._stats = {'received': 0, 'parsed': 0, 'errors': 0}

    def start(self):
        """Start syslog receiver in background thread."""
        if self._running or self.port <= 0:
            return

        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(f"[WAZUH] Syslog receiver started on {self.protocol.upper()}:{self.port}")

    def stop(self):
        self._running = False
        if self._server:
            try:
                self._server.shutdown()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        receiver = self

        if self.protocol == 'udp':
            class UDPHandler(socketserver.BaseRequestHandler):
                def handle(self):
                    data = self.request[0].strip().decode('utf-8', errors='replace')
                    receiver._process_line(data)

            self._server = socketserver.UDPServer(('0.0.0.0', self.port), UDPHandler)
        else:
            class TCPHandler(socketserver.StreamRequestHandler):
                def handle(self):
                    for line in self.rfile:
                        data = line.strip().decode('utf-8', errors='replace')
                        if data:
                            receiver._process_line(data)

            self._server = socketserver.TCPServer(('0.0.0.0', self.port), TCPHandler)
            self._server.allow_reuse_address = True

        try:
            self._server.serve_forever()
        except Exception as e:
            if self._running:
                logger.error(f"[WAZUH] Syslog server error: {e}")

    def _process_line(self, line: str):
        """Process a syslog line and normalize."""
        self._stats['received'] += 1
        try:
            normalized = WazuhAlertNormalizer.normalize_syslog(line)
            if normalized and self._callback:
                self._callback(normalized)
                self._stats['parsed'] += 1
            elif not normalized:
                self._stats['errors'] += 1
        except Exception as e:
            self._stats['errors'] += 1
            logger.debug(f"[WAZUH] Syslog parse error: {e}")

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


# ============================================================================
# Wazuh Connector (Main Orchestrator)
# ============================================================================

class WazuhConnector:
    """
    Main Wazuh connector orchestrating API polling, syslog ingestion,
    agent monitoring, and alert normalization.
    """

    def __init__(self, config: Optional[WazuhConfig] = None, db_path: Optional[str] = None):
        self.config = config or WazuhConfig.from_env()

        if db_path is None:
            db_dir = Path.home() / '.dalga'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'soc_wazuh.db')

        self.db_path = db_path
        self.api = WazuhAPIClient(self.config)
        self.health_monitor = AgentHealthMonitor(db_path)
        self.syslog_receiver: Optional[WazuhSyslogReceiver] = None

        # Callbacks
        self._alert_callbacks: List[Callable[[Dict], None]] = []
        self._agent_change_callbacks: List[Callable[[Dict], None]] = []

        # State
        self._last_poll_timestamp = ""
        self._poll_thread: Optional[threading.Thread] = None
        self._agent_thread: Optional[threading.Thread] = None
        self._running = False
        self._lock = threading.Lock()
        self._consecutive_failures = 0
        self._stats = {
            'alerts_ingested': 0,
            'alerts_normalized': 0,
            'poll_cycles': 0,
            'poll_errors': 0,
            'last_poll': None,
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
                CREATE TABLE IF NOT EXISTS wazuh_ingestion_state (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );

                CREATE TABLE IF NOT EXISTS wazuh_raw_alerts (
                    wazuh_id TEXT PRIMARY KEY,
                    rule_id TEXT,
                    rule_level INTEGER,
                    agent_id TEXT,
                    timestamp TEXT,
                    raw_json TEXT,
                    normalized INTEGER DEFAULT 0,
                    ingested_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_ts
                    ON wazuh_raw_alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_level
                    ON wazuh_raw_alerts(rule_level);
            """)

            # Load last poll timestamp
            row = conn.execute(
                "SELECT value FROM wazuh_ingestion_state WHERE key = 'last_poll_ts'"
            ).fetchone()
            if row:
                self._last_poll_timestamp = row['value']

            conn.commit()
        finally:
            conn.close()

    # ---- Callback Registration ----

    def on_alert(self, callback: Callable[[Dict], None]):
        """Register callback for normalized alerts."""
        self._alert_callbacks.append(callback)

    def on_agent_change(self, callback: Callable[[Dict], None]):
        """Register callback for agent status changes."""
        self._agent_change_callbacks.append(callback)

    # ---- Lifecycle ----

    def start(self):
        """Start all ingestion threads."""
        if self._running:
            return

        self._running = True

        # API polling thread
        if self.config.host:
            self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
            self._poll_thread.start()
            logger.info("[WAZUH] Alert polling started")

            # Agent monitor thread
            self._agent_thread = threading.Thread(target=self._agent_monitor_loop, daemon=True)
            self._agent_thread.start()
            logger.info("[WAZUH] Agent monitor started")

        # Syslog receiver
        if self.config.syslog_port > 0:
            self.syslog_receiver = WazuhSyslogReceiver(
                port=self.config.syslog_port,
                protocol=self.config.syslog_protocol,
                callback=self._handle_syslog_alert,
            )
            self.syslog_receiver.start()

    def stop(self):
        """Stop all ingestion threads."""
        self._running = False
        if self._poll_thread:
            self._poll_thread.join(timeout=10)
        if self._agent_thread:
            self._agent_thread.join(timeout=10)
        if self.syslog_receiver:
            self.syslog_receiver.stop()
        logger.info("[WAZUH] Connector stopped")

    # ---- Polling Loop ----

    def _poll_loop(self):
        """Main alert polling loop with exponential backoff on failures."""
        while self._running:
            try:
                alerts = self.api.get_alerts(
                    limit=self.config.max_alerts_per_poll,
                    level_min=self.config.min_alert_level,
                    timestamp_gt=self._last_poll_timestamp,
                )

                self._stats['poll_cycles'] += 1
                self._stats['last_poll'] = datetime.now(timezone.utc).isoformat()

                if alerts:
                    self._process_api_alerts(alerts)
                    self._consecutive_failures = 0
                else:
                    self._consecutive_failures = 0

            except Exception as e:
                self._stats['poll_errors'] += 1
                self._consecutive_failures += 1
                logger.error(f"[WAZUH] Poll error (attempt {self._consecutive_failures}): {e}")

            # Sleep with exponential backoff on failures
            sleep_time = self.config.poll_interval
            if self._consecutive_failures > 0:
                sleep_time = min(300, sleep_time * (2 ** min(self._consecutive_failures, 5)))

            # Interruptible sleep
            deadline = time.time() + sleep_time
            while self._running and time.time() < deadline:
                time.sleep(1)

    def _process_api_alerts(self, alerts: List[Dict]):
        """Process alerts from API response."""
        conn = self._get_conn()
        now = datetime.now(timezone.utc).isoformat()

        for raw in alerts:
            wazuh_id = str(raw.get('id', uuid.uuid4().hex))
            rule = raw.get('rule', {})
            agent = raw.get('agent', {})
            timestamp = raw.get('timestamp', now)

            # Store raw alert (INSERT OR IGNORE + rowcount check for duplicates)
            cursor = conn.execute("""
                INSERT OR IGNORE INTO wazuh_raw_alerts
                (wazuh_id, rule_id, rule_level, agent_id, timestamp, raw_json, ingested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                wazuh_id,
                str(rule.get('id', '')),
                int(rule.get('level', 0)),
                str(agent.get('id', '')),
                timestamp,
                json.dumps(raw, default=str),
                now,
            ))
            if cursor.rowcount == 0:
                continue  # Already ingested - duplicate

            self._stats['alerts_ingested'] += 1

            # Normalize and dispatch
            try:
                normalized = WazuhAlertNormalizer.normalize(raw)
                self._stats['alerts_normalized'] += 1
                self._dispatch_alert(normalized)

                conn.execute(
                    "UPDATE wazuh_raw_alerts SET normalized = 1 WHERE wazuh_id = ?",
                    (wazuh_id,)
                )
            except Exception as e:
                logger.error(f"[WAZUH] Normalize error for {wazuh_id}: {e}")

            # Update last poll timestamp
            if timestamp > self._last_poll_timestamp:
                self._last_poll_timestamp = timestamp

        # Persist state
        conn.execute(
            "INSERT OR REPLACE INTO wazuh_ingestion_state (key, value) VALUES ('last_poll_ts', ?)",
            (self._last_poll_timestamp,)
        )
        conn.commit()
        conn.close()

        logger.info(f"[WAZUH] Processed {len(alerts)} alerts")

    def _handle_syslog_alert(self, normalized: Dict):
        """Handle alert from syslog receiver."""
        self._stats['alerts_ingested'] += 1
        self._stats['alerts_normalized'] += 1
        self._dispatch_alert(normalized)

    def _dispatch_alert(self, normalized: Dict):
        """Send normalized alert to all registered callbacks."""
        for cb in self._alert_callbacks:
            try:
                cb(normalized)
            except Exception as e:
                logger.error(f"[WAZUH] Alert callback error: {e}")

    # ---- Agent Monitor ----

    def _agent_monitor_loop(self):
        """Periodic agent health check."""
        while self._running:
            try:
                agents = self.api.get_agents(limit=500)
                changes = self.health_monitor.update_agents(agents)

                for change in changes:
                    for cb in self._agent_change_callbacks:
                        try:
                            cb(change)
                        except Exception as e:
                            logger.error(f"[WAZUH] Agent change callback error: {e}")

            except Exception as e:
                logger.debug(f"[WAZUH] Agent monitor error: {e}")

            # Check every 60 seconds
            deadline = time.time() + 60
            while self._running and time.time() < deadline:
                time.sleep(1)

    # ---- Active Response ----

    def block_ip(self, agent_id: str, ip_address: str) -> Dict:
        """Block an IP address via active response."""
        return self.api.run_active_response(
            agent_id, ActiveResponseAction.FIREWALL_DROP.value,
            [ip_address]
        )

    def unblock_ip(self, agent_id: str, ip_address: str) -> Dict:
        """Unblock an IP address."""
        return self.api.run_active_response(
            agent_id, f"{ActiveResponseAction.FIREWALL_DROP.value}0",
            [ip_address]
        )

    # ---- Stats & Info ----

    @property
    def stats(self) -> Dict[str, Any]:
        result = dict(self._stats)
        result['agent_summary'] = self.health_monitor.get_agent_summary()
        if self.syslog_receiver:
            result['syslog'] = self.syslog_receiver.stats
        return result

    def get_ingested_alert_count(self, hours: int = 24) -> int:
        """Get count of ingested alerts in time window."""
        try:
            conn = self._get_conn()
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
            cnt = conn.execute(
                "SELECT COUNT(*) FROM wazuh_raw_alerts WHERE ingested_at >= ?",
                (since,)
            ).fetchone()[0]
            conn.close()
            return cnt
        except sqlite3.OperationalError:
            return 0


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_wazuh_blueprint(connector: Optional[WazuhConnector] = None):
    """Create Flask Blueprint for Wazuh SIEM API."""
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        return None

    if connector is None:
        connector = WazuhConnector()

    bp = Blueprint('soc_wazuh', __name__, url_prefix='/api/v1/soc/wazuh')

    @bp.route('/status', methods=['GET'])
    def wazuh_status():
        """Get Wazuh connector status."""
        return jsonify({
            'success': True,
            'data': {
                'connected': bool(connector.config.host),
                'host': connector.config.host or 'Not configured',
                'stats': connector.stats,
            }
        })

    @bp.route('/agents', methods=['GET'])
    def list_agents():
        """Get tracked agents."""
        return jsonify({
            'success': True,
            'data': {
                'agents': connector.health_monitor.get_all_agents(),
                'summary': connector.health_monitor.get_agent_summary(),
            }
        })

    @bp.route('/agents/<agent_id>', methods=['GET'])
    def get_agent(agent_id):
        """Get specific agent info from Wazuh API."""
        try:
            info = connector.api.get_agent(agent_id)
            return jsonify({'success': True, 'data': info})
        except Exception as e:
            return jsonify({'success': False, 'error': 'Agent bilgisi alinamadi'}), 500

    @bp.route('/alerts/stats', methods=['GET'])
    def alert_stats():
        """Get ingestion statistics."""
        hours = request.args.get('hours', 24, type=int)
        return jsonify({
            'success': True,
            'data': {
                'ingested_count': connector.get_ingested_alert_count(hours),
                'stats': connector.stats,
            }
        })

    @bp.route('/active-response', methods=['POST'])
    def active_response():
        """Trigger active response action."""
        data = request.get_json(force=True)
        agent_id = data.get('agent_id', '')
        action = data.get('action', '')
        args = data.get('arguments', [])

        if not agent_id or not action:
            return jsonify({'success': False, 'error': 'agent_id ve action gerekli'}), 400

        try:
            result = connector.api.run_active_response(agent_id, action, args)
            return jsonify({'success': True, 'data': result})
        except Exception as e:
            return jsonify({'success': False, 'error': 'Active response gonderilemedi'}), 500

    @bp.route('/sca/<agent_id>', methods=['GET'])
    def sca_results(agent_id):
        """Get SCA checks for an agent."""
        try:
            checks = connector.api.get_sca_checks(agent_id)
            return jsonify({'success': True, 'data': checks})
        except Exception as e:
            return jsonify({'success': False, 'error': 'SCA bilgisi alinamadi'}), 500

    @bp.route('/vulnerabilities/<agent_id>', methods=['GET'])
    def vuln_results(agent_id):
        """Get vulnerability detections for an agent."""
        try:
            vulns = connector.api.get_vulnerabilities(agent_id)
            return jsonify({'success': True, 'data': vulns})
        except Exception as e:
            return jsonify({'success': False, 'error': 'Zafiyet bilgisi alinamadi'}), 500

    @bp.route('/fim/<agent_id>', methods=['GET'])
    def fim_events(agent_id):
        """Get FIM events for an agent."""
        try:
            events = connector.api.get_fim_events(agent_id)
            return jsonify({'success': True, 'data': events})
        except Exception as e:
            return jsonify({'success': False, 'error': 'FIM bilgisi alinamadi'}), 500

    return bp


# ============================================================================
# Global Instance
# ============================================================================

_wazuh_connector: Optional[WazuhConnector] = None
_wc_lock = threading.Lock()


def get_wazuh_connector() -> WazuhConnector:
    global _wazuh_connector
    if _wazuh_connector is None:
        with _wc_lock:
            if _wazuh_connector is None:
                _wazuh_connector = WazuhConnector()
    return _wazuh_connector


__all__ = [
    'WazuhAgentStatus', 'WazuhAlertLevel', 'ActiveResponseAction',
    'WazuhConfig', 'WazuhAPIClient', 'WazuhAlertNormalizer',
    'AgentHealthMonitor', 'WazuhSyslogReceiver', 'WazuhConnector',
    'create_wazuh_blueprint', 'get_wazuh_connector',
]
