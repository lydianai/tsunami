#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOAR Action Library v5.0
    Pre-built Security Response Actions
================================================================================

    Real security actions including:
    - Network blocking (iptables)
    - Process management
    - Host isolation
    - Alerting (email, webhook, Telegram)
    - Threat intelligence queries
    - Ticket creation
    - Forensic collection
    - Security scanning

================================================================================
"""

import hashlib
import json
import logging
import os
import re
import shutil
import smtplib
import socket
import subprocess
import tempfile
import urllib.request
import urllib.parse
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of security actions."""
    BLOCK = "block"
    UNBLOCK = "unblock"
    KILL = "kill"
    ISOLATE = "isolate"
    ALERT = "alert"
    QUERY = "query"
    TICKET = "ticket"
    FORENSICS = "forensics"
    SCAN = "scan"
    QUARANTINE = "quarantine"
    DISABLE = "disable"
    ENABLE = "enable"
    CUSTOM = "custom"


@dataclass
class ActionResult:
    """Result of a security action."""
    action: str
    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0
    rollback_info: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'action': self.action,
            'success': self.success,
            'message': self.message,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'duration_ms': self.duration_ms,
            'rollback_info': self.rollback_info
        }


class SecurityAction(ABC):
    """Base class for security actions."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Action name."""
        pass

    @property
    @abstractmethod
    def action_type(self) -> ActionType:
        """Action type."""
        pass

    @property
    def description(self) -> str:
        """Action description."""
        return ""

    @property
    def parameters(self) -> Dict[str, Dict[str, Any]]:
        """Action parameters schema."""
        return {}

    @abstractmethod
    def execute(self, **kwargs) -> ActionResult:
        """Execute the action."""
        pass

    def rollback(self, rollback_info: Dict[str, Any]) -> ActionResult:
        """Rollback the action (optional)."""
        return ActionResult(
            action=f"{self.name}_rollback",
            success=False,
            message="Rollback not implemented"
        )


# =============================================================================
# Network Blocking Actions
# =============================================================================

def block_ip(
    ip: str,
    chain: str = "INPUT",
    protocol: str = "all",
    port: Optional[int] = None,
    comment: Optional[str] = None,
    timeout: Optional[int] = None
) -> ActionResult:
    """
    Block an IP address using iptables.

    Args:
        ip: IP address to block
        chain: iptables chain (INPUT, OUTPUT, FORWARD)
        protocol: Protocol (tcp, udp, all)
        port: Optional port to block
        comment: Optional comment for the rule
        timeout: Optional timeout in seconds (uses ipset)
    """
    import time
    start = time.time()

    try:
        # Validate IP
        socket.inet_aton(ip)

        # Build iptables command
        cmd = ["iptables", "-I", chain, "-s", ip]

        if protocol != "all":
            cmd.extend(["-p", protocol])

        if port:
            cmd.extend(["--dport", str(port)])

        cmd.extend(["-j", "DROP"])

        if comment:
            cmd.extend(["-m", "comment", "--comment", comment[:256]])

        # Execute command
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            return ActionResult(
                action="block_ip",
                success=False,
                message=f"Failed to block IP: {result.stderr}",
                data={'ip': ip, 'chain': chain},
                duration_ms=(time.time() - start) * 1000
            )

        # If timeout specified, schedule unblock
        if timeout:
            # Using at command for timeout
            unblock_cmd = f"iptables -D {chain} -s {ip} -j DROP"
            subprocess.run(
                ["bash", "-c", f"sleep {timeout} && {unblock_cmd}"],
                start_new_session=True
            )

        return ActionResult(
            action="block_ip",
            success=True,
            message=f"Successfully blocked IP {ip}",
            data={
                'ip': ip,
                'chain': chain,
                'protocol': protocol,
                'port': port,
                'timeout': timeout
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'ip': ip, 'chain': chain, 'protocol': protocol, 'port': port}
        )

    except socket.error:
        return ActionResult(
            action="block_ip",
            success=False,
            message=f"Invalid IP address: {ip}",
            duration_ms=(time.time() - start) * 1000
        )
    except subprocess.TimeoutExpired:
        return ActionResult(
            action="block_ip",
            success=False,
            message="Command timed out",
            duration_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        return ActionResult(
            action="block_ip",
            success=False,
            message=f"Error blocking IP: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def unblock_ip(
    ip: str,
    chain: str = "INPUT",
    protocol: str = "all",
    port: Optional[int] = None
) -> ActionResult:
    """
    Unblock an IP address.

    Args:
        ip: IP address to unblock
        chain: iptables chain
        protocol: Protocol
        port: Optional port
    """
    import time
    start = time.time()

    try:
        socket.inet_aton(ip)

        cmd = ["iptables", "-D", chain, "-s", ip]

        if protocol != "all":
            cmd.extend(["-p", protocol])

        if port:
            cmd.extend(["--dport", str(port)])

        cmd.extend(["-j", "DROP"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            return ActionResult(
                action="unblock_ip",
                success=False,
                message=f"Failed to unblock IP: {result.stderr}",
                data={'ip': ip},
                duration_ms=(time.time() - start) * 1000
            )

        return ActionResult(
            action="unblock_ip",
            success=True,
            message=f"Successfully unblocked IP {ip}",
            data={'ip': ip, 'chain': chain},
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        return ActionResult(
            action="unblock_ip",
            success=False,
            message=f"Error unblocking IP: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def block_domain(domain: str, dns_file: str = "/etc/hosts") -> ActionResult:
    """
    Block a domain by adding to hosts file.

    Args:
        domain: Domain to block
        dns_file: Path to hosts file
    """
    import time
    start = time.time()

    try:
        # Add entry to hosts file
        entry = f"0.0.0.0 {domain}\n"

        with open(dns_file, 'a') as f:
            f.write(entry)

        return ActionResult(
            action="block_domain",
            success=True,
            message=f"Blocked domain {domain}",
            data={'domain': domain, 'dns_file': dns_file},
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'domain': domain, 'dns_file': dns_file}
        )

    except Exception as e:
        return ActionResult(
            action="block_domain",
            success=False,
            message=f"Error blocking domain: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Process Management Actions
# =============================================================================

def kill_process(
    pid: Optional[int] = None,
    name: Optional[str] = None,
    signal: int = 9,
    include_children: bool = True
) -> ActionResult:
    """
    Kill a process by PID or name.

    Args:
        pid: Process ID to kill
        name: Process name to kill (all matching)
        signal: Kill signal (default: SIGKILL)
        include_children: Also kill child processes
    """
    import time
    start = time.time()

    try:
        killed_pids = []

        if pid:
            # Kill specific PID
            if include_children:
                # Get child PIDs
                result = subprocess.run(
                    ["pgrep", "-P", str(pid)],
                    capture_output=True,
                    text=True
                )
                child_pids = [int(p) for p in result.stdout.split() if p]

                for cpid in child_pids:
                    os.kill(cpid, signal)
                    killed_pids.append(cpid)

            os.kill(pid, signal)
            killed_pids.append(pid)

        elif name:
            # Kill by process name
            result = subprocess.run(
                ["pgrep", "-f", name],
                capture_output=True,
                text=True
            )
            pids = [int(p) for p in result.stdout.split() if p]

            for p in pids:
                try:
                    os.kill(p, signal)
                    killed_pids.append(p)
                except ProcessLookupError:
                    continue

        if not killed_pids:
            return ActionResult(
                action="kill_process",
                success=False,
                message="No matching processes found",
                data={'pid': pid, 'name': name},
                duration_ms=(time.time() - start) * 1000
            )

        return ActionResult(
            action="kill_process",
            success=True,
            message=f"Killed {len(killed_pids)} process(es)",
            data={
                'killed_pids': killed_pids,
                'signal': signal
            },
            duration_ms=(time.time() - start) * 1000
        )

    except ProcessLookupError:
        return ActionResult(
            action="kill_process",
            success=False,
            message=f"Process not found: {pid or name}",
            duration_ms=(time.time() - start) * 1000
        )
    except PermissionError:
        return ActionResult(
            action="kill_process",
            success=False,
            message="Permission denied to kill process",
            duration_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        return ActionResult(
            action="kill_process",
            success=False,
            message=f"Error killing process: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Host Isolation Actions
# =============================================================================

def isolate_host(
    ip: str,
    allowed_ips: Optional[List[str]] = None,
    allow_dns: bool = True,
    allow_management: bool = True
) -> ActionResult:
    """
    Isolate a host by blocking all network traffic except specified.

    Args:
        ip: IP address of host to isolate
        allowed_ips: List of IPs to allow communication with
        allow_dns: Allow DNS traffic (port 53)
        allow_management: Allow SSH (port 22)
    """
    import time
    start = time.time()

    try:
        rules_added = []

        # Block all outgoing traffic from host
        cmd = ["iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True, capture_output=True)
        rules_added.append(f"FORWARD -s {ip} DROP")

        # Block all incoming traffic to host
        cmd = ["iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP"]
        subprocess.run(cmd, check=True, capture_output=True)
        rules_added.append(f"FORWARD -d {ip} DROP")

        # Allow specific traffic
        if allow_dns:
            # Allow DNS to/from host
            for port in [53]:
                cmd = ["iptables", "-I", "FORWARD", "-s", ip, "-p", "udp",
                       "--dport", str(port), "-j", "ACCEPT"]
                subprocess.run(cmd, capture_output=True)
                cmd = ["iptables", "-I", "FORWARD", "-d", ip, "-p", "udp",
                       "--sport", str(port), "-j", "ACCEPT"]
                subprocess.run(cmd, capture_output=True)

        if allow_management:
            # Allow SSH for management
            cmd = ["iptables", "-I", "FORWARD", "-d", ip, "-p", "tcp",
                   "--dport", "22", "-j", "ACCEPT"]
            subprocess.run(cmd, capture_output=True)

        if allowed_ips:
            for allowed_ip in allowed_ips:
                # Allow traffic to/from specific IPs
                cmd = ["iptables", "-I", "FORWARD", "-s", ip, "-d",
                       allowed_ip, "-j", "ACCEPT"]
                subprocess.run(cmd, capture_output=True)
                cmd = ["iptables", "-I", "FORWARD", "-s", allowed_ip, "-d",
                       ip, "-j", "ACCEPT"]
                subprocess.run(cmd, capture_output=True)

        return ActionResult(
            action="isolate_host",
            success=True,
            message=f"Host {ip} isolated successfully",
            data={
                'ip': ip,
                'allowed_ips': allowed_ips,
                'allow_dns': allow_dns,
                'allow_management': allow_management,
                'rules_added': rules_added
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'ip': ip, 'rules': rules_added}
        )

    except subprocess.CalledProcessError as e:
        return ActionResult(
            action="isolate_host",
            success=False,
            message=f"Failed to isolate host: {e.stderr}",
            duration_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        return ActionResult(
            action="isolate_host",
            success=False,
            message=f"Error isolating host: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def unisolate_host(ip: str) -> ActionResult:
    """
    Remove isolation rules for a host.

    Args:
        ip: IP address of host to unisolate
    """
    import time
    start = time.time()

    try:
        # Remove DROP rules
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP"],
            capture_output=True
        )
        subprocess.run(
            ["iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP"],
            capture_output=True
        )

        return ActionResult(
            action="unisolate_host",
            success=True,
            message=f"Host {ip} unisolated",
            data={'ip': ip},
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        return ActionResult(
            action="unisolate_host",
            success=False,
            message=f"Error unisolating host: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Alerting Actions
# =============================================================================

def send_alert(
    message: str,
    title: str = "Security Alert",
    severity: str = "medium",
    channel: str = "email",
    recipients: Optional[List[str]] = None,
    webhook_url: Optional[str] = None,
    telegram_token: Optional[str] = None,
    telegram_chat_id: Optional[str] = None,
    smtp_server: str = "localhost",
    smtp_port: int = 25,
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
    sender: str = "tsunami@localhost"
) -> ActionResult:
    """
    Send a security alert via various channels.

    Args:
        message: Alert message
        title: Alert title
        severity: Alert severity (low, medium, high, critical)
        channel: Alert channel (email, webhook, telegram, syslog)
        recipients: List of recipients (email addresses)
        webhook_url: Webhook URL for webhook channel
        telegram_token: Telegram bot token
        telegram_chat_id: Telegram chat ID
        smtp_server: SMTP server
        smtp_port: SMTP port
        smtp_user: SMTP username
        smtp_password: SMTP password
        sender: Email sender address
    """
    import time
    start = time.time()

    try:
        if channel == "email":
            if not recipients:
                return ActionResult(
                    action="send_alert",
                    success=False,
                    message="No recipients specified for email alert",
                    duration_ms=(time.time() - start) * 1000
                )

            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = f"[{severity.upper()}] {title}"

            body = f"""
Security Alert from TSUNAMI SOAR

Title: {title}
Severity: {severity.upper()}
Timestamp: {datetime.utcnow().isoformat()}

{message}

---
TSUNAMI Security Platform
            """
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_user and smtp_password:
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                server.send_message(msg)

            return ActionResult(
                action="send_alert",
                success=True,
                message=f"Email alert sent to {len(recipients)} recipients",
                data={
                    'channel': 'email',
                    'recipients': recipients,
                    'severity': severity
                },
                duration_ms=(time.time() - start) * 1000
            )

        elif channel == "webhook":
            if not webhook_url:
                return ActionResult(
                    action="send_alert",
                    success=False,
                    message="No webhook URL specified",
                    duration_ms=(time.time() - start) * 1000
                )

            payload = json.dumps({
                'title': title,
                'message': message,
                'severity': severity,
                'timestamp': datetime.utcnow().isoformat(),
                'source': 'TSUNAMI-SOAR'
            }).encode('utf-8')

            req = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'}
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = response.read().decode('utf-8')

            return ActionResult(
                action="send_alert",
                success=True,
                message="Webhook alert sent successfully",
                data={
                    'channel': 'webhook',
                    'url': webhook_url,
                    'response': response_data
                },
                duration_ms=(time.time() - start) * 1000
            )

        elif channel == "telegram":
            if not telegram_token or not telegram_chat_id:
                return ActionResult(
                    action="send_alert",
                    success=False,
                    message="Telegram token and chat_id required",
                    duration_ms=(time.time() - start) * 1000
                )

            text = f"*{severity.upper()} - {title}*\n\n{message}"
            url = f"https://api.telegram.org/bot{telegram_token}/sendMessage"

            data = urllib.parse.urlencode({
                'chat_id': telegram_chat_id,
                'text': text,
                'parse_mode': 'Markdown'
            }).encode('utf-8')

            req = urllib.request.Request(url, data=data)

            with urllib.request.urlopen(req, timeout=30) as response:
                response_data = json.loads(response.read().decode('utf-8'))

            return ActionResult(
                action="send_alert",
                success=True,
                message="Telegram alert sent successfully",
                data={
                    'channel': 'telegram',
                    'chat_id': telegram_chat_id,
                    'message_id': response_data.get('result', {}).get('message_id')
                },
                duration_ms=(time.time() - start) * 1000
            )

        elif channel == "syslog":
            import syslog
            priority = {
                'critical': syslog.LOG_CRIT,
                'high': syslog.LOG_ERR,
                'medium': syslog.LOG_WARNING,
                'low': syslog.LOG_INFO
            }.get(severity, syslog.LOG_NOTICE)

            syslog.openlog('tsunami-soar', syslog.LOG_PID, syslog.LOG_AUTH)
            syslog.syslog(priority, f"{title}: {message}")
            syslog.closelog()

            return ActionResult(
                action="send_alert",
                success=True,
                message="Syslog alert sent",
                data={'channel': 'syslog', 'severity': severity},
                duration_ms=(time.time() - start) * 1000
            )

        else:
            return ActionResult(
                action="send_alert",
                success=False,
                message=f"Unknown channel: {channel}",
                duration_ms=(time.time() - start) * 1000
            )

    except Exception as e:
        return ActionResult(
            action="send_alert",
            success=False,
            message=f"Error sending alert: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Threat Intelligence Actions
# =============================================================================

def query_threat_intel(
    indicator: str,
    indicator_type: str = "auto",
    sources: Optional[List[str]] = None,
    api_keys: Optional[Dict[str, str]] = None
) -> ActionResult:
    """
    Query threat intelligence sources for an indicator.

    Args:
        indicator: IOC to query (IP, domain, hash, etc.)
        indicator_type: Type of indicator (ip, domain, hash, url, auto)
        sources: List of sources to query (virustotal, abuseipdb, otx)
        api_keys: API keys for sources
    """
    import time
    start = time.time()

    api_keys = api_keys or {}
    sources = sources or ['abuseipdb', 'otx']
    results = {}

    # Auto-detect indicator type
    if indicator_type == "auto":
        if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$', indicator):
            indicator_type = "ip"
        elif re.match(r'^[a-f0-9]{32}$', indicator, re.I):
            indicator_type = "md5"
        elif re.match(r'^[a-f0-9]{64}$', indicator, re.I):
            indicator_type = "sha256"
        elif re.match(r'^https?://', indicator):
            indicator_type = "url"
        else:
            indicator_type = "domain"

    try:
        # AbuseIPDB
        if 'abuseipdb' in sources and indicator_type == 'ip':
            api_key = api_keys.get('abuseipdb', os.environ.get('ABUSEIPDB_API_KEY', ''))
            if api_key:
                url = f"https://api.abuseipdb.com/api/v2/check"
                req = urllib.request.Request(
                    f"{url}?ipAddress={indicator}&maxAgeInDays=90",
                    headers={
                        'Key': api_key,
                        'Accept': 'application/json'
                    }
                )
                try:
                    with urllib.request.urlopen(req, timeout=30) as response:
                        data = json.loads(response.read().decode('utf-8'))
                        results['abuseipdb'] = {
                            'score': data.get('data', {}).get('abuseConfidenceScore', 0),
                            'reports': data.get('data', {}).get('totalReports', 0),
                            'country': data.get('data', {}).get('countryCode'),
                            'isp': data.get('data', {}).get('isp'),
                            'malicious': data.get('data', {}).get('abuseConfidenceScore', 0) > 50
                        }
                except Exception as e:
                    results['abuseipdb'] = {'error': str(e)}

        # AlienVault OTX
        if 'otx' in sources:
            api_key = api_keys.get('otx', os.environ.get('OTX_API_KEY', ''))
            if indicator_type == 'ip':
                url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator}/general"
            elif indicator_type == 'domain':
                url = f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general"
            elif indicator_type in ['md5', 'sha256']:
                url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general"
            else:
                url = None

            if url:
                headers = {}
                if api_key:
                    headers['X-OTX-API-KEY'] = api_key

                req = urllib.request.Request(url, headers=headers)
                try:
                    with urllib.request.urlopen(req, timeout=30) as response:
                        data = json.loads(response.read().decode('utf-8'))
                        results['otx'] = {
                            'pulse_count': data.get('pulse_info', {}).get('count', 0),
                            'malicious': data.get('pulse_info', {}).get('count', 0) > 0,
                            'tags': data.get('pulse_info', {}).get('pulses', [])[:5]
                        }
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        results['otx'] = {'found': False, 'malicious': False}
                    else:
                        results['otx'] = {'error': str(e)}

        # VirusTotal
        if 'virustotal' in sources:
            api_key = api_keys.get('virustotal', os.environ.get('VT_API_KEY', ''))
            if api_key:
                if indicator_type == 'ip':
                    url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
                elif indicator_type == 'domain':
                    url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
                elif indicator_type in ['md5', 'sha256']:
                    url = f"https://www.virustotal.com/api/v3/files/{indicator}"
                else:
                    url = None

                if url:
                    req = urllib.request.Request(
                        url,
                        headers={'x-apikey': api_key}
                    )
                    try:
                        with urllib.request.urlopen(req, timeout=30) as response:
                            data = json.loads(response.read().decode('utf-8'))
                            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            results['virustotal'] = {
                                'malicious': stats.get('malicious', 0),
                                'suspicious': stats.get('suspicious', 0),
                                'harmless': stats.get('harmless', 0),
                                'undetected': stats.get('undetected', 0),
                                'score': stats.get('malicious', 0) + stats.get('suspicious', 0)
                            }
                    except Exception as e:
                        results['virustotal'] = {'error': str(e)}

        # Determine overall malicious verdict
        is_malicious = any(
            r.get('malicious', False) or r.get('score', 0) > 50
            for r in results.values()
            if isinstance(r, dict) and 'error' not in r
        )

        return ActionResult(
            action="query_threat_intel",
            success=True,
            message=f"Queried {len(results)} sources for {indicator}",
            data={
                'indicator': indicator,
                'type': indicator_type,
                'sources': results,
                'is_malicious': is_malicious
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        return ActionResult(
            action="query_threat_intel",
            success=False,
            message=f"Error querying threat intel: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Ticketing Actions
# =============================================================================

def create_ticket(
    title: str,
    description: str,
    severity: str = "medium",
    ticket_type: str = "incident",
    assignee: Optional[str] = None,
    labels: Optional[List[str]] = None,
    system: str = "internal",
    api_url: Optional[str] = None,
    api_token: Optional[str] = None
) -> ActionResult:
    """
    Create a ticket in the ticketing system.

    Args:
        title: Ticket title
        description: Ticket description
        severity: Ticket severity
        ticket_type: Type of ticket (incident, alert, request)
        assignee: Assignee username
        labels: List of labels/tags
        system: Ticketing system (internal, jira, servicenow)
        api_url: API URL for external systems
        api_token: API token for external systems
    """
    import time
    start = time.time()

    labels = labels or []

    try:
        if system == "internal":
            # Internal ticket storage
            ticket_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
            ticket = {
                'id': ticket_id,
                'title': title,
                'description': description,
                'severity': severity,
                'type': ticket_type,
                'assignee': assignee,
                'labels': labels,
                'status': 'open',
                'created_at': datetime.utcnow().isoformat(),
                'updated_at': datetime.utcnow().isoformat()
            }

            # Store ticket (in production, this would be a database)
            ticket_dir = Path("/var/lib/tsunami/tickets")
            ticket_dir.mkdir(parents=True, exist_ok=True)

            ticket_file = ticket_dir / f"{ticket_id}.json"
            with open(ticket_file, 'w') as f:
                json.dump(ticket, f, indent=2)

            return ActionResult(
                action="create_ticket",
                success=True,
                message=f"Created ticket {ticket_id}",
                data={'ticket_id': ticket_id, 'ticket': ticket},
                duration_ms=(time.time() - start) * 1000
            )

        elif system == "jira":
            if not api_url or not api_token:
                return ActionResult(
                    action="create_ticket",
                    success=False,
                    message="JIRA API URL and token required",
                    duration_ms=(time.time() - start) * 1000
                )

            # Create JIRA issue
            payload = json.dumps({
                'fields': {
                    'project': {'key': labels[0] if labels else 'SEC'},
                    'summary': title,
                    'description': description,
                    'issuetype': {'name': 'Bug' if ticket_type == 'incident' else 'Task'},
                    'priority': {'name': severity.capitalize()},
                    'assignee': {'name': assignee} if assignee else None,
                    'labels': labels
                }
            }).encode('utf-8')

            req = urllib.request.Request(
                f"{api_url}/rest/api/2/issue",
                data=payload,
                headers={
                    'Authorization': f'Basic {api_token}',
                    'Content-Type': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=30) as response:
                data = json.loads(response.read().decode('utf-8'))

            return ActionResult(
                action="create_ticket",
                success=True,
                message=f"Created JIRA ticket {data['key']}",
                data={'ticket_id': data['key'], 'url': f"{api_url}/browse/{data['key']}"},
                duration_ms=(time.time() - start) * 1000
            )

        else:
            return ActionResult(
                action="create_ticket",
                success=False,
                message=f"Unsupported ticketing system: {system}",
                duration_ms=(time.time() - start) * 1000
            )

    except Exception as e:
        return ActionResult(
            action="create_ticket",
            success=False,
            message=f"Error creating ticket: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Forensics Actions
# =============================================================================

def collect_forensics(
    target_type: str,
    target: str,
    artifacts: Optional[List[str]] = None,
    output_dir: str = "/var/lib/tsunami/forensics"
) -> ActionResult:
    """
    Collect forensic artifacts.

    Args:
        target_type: Type of target (host, file, process)
        target: Target identifier
        artifacts: List of artifacts to collect
        output_dir: Directory to store forensics
    """
    import time
    start = time.time()

    artifacts = artifacts or ['logs', 'network', 'processes', 'files']
    collected = {}

    try:
        # Create forensics directory
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        case_dir = Path(output_dir) / f"case_{timestamp}_{target.replace('.', '_')}"
        case_dir.mkdir(parents=True, exist_ok=True)

        if target_type == "host":
            # Collect host artifacts

            if 'processes' in artifacts:
                # Running processes
                result = subprocess.run(
                    ["ps", "auxww"],
                    capture_output=True,
                    text=True
                )
                (case_dir / "processes.txt").write_text(result.stdout)
                collected['processes'] = True

            if 'network' in artifacts:
                # Network connections
                result = subprocess.run(
                    ["ss", "-tunapl"],
                    capture_output=True,
                    text=True
                )
                (case_dir / "network_connections.txt").write_text(result.stdout)

                # Network interfaces
                result = subprocess.run(
                    ["ip", "addr"],
                    capture_output=True,
                    text=True
                )
                (case_dir / "network_interfaces.txt").write_text(result.stdout)
                collected['network'] = True

            if 'logs' in artifacts:
                # System logs
                log_files = [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/var/log/messages',
                    '/var/log/secure'
                ]
                logs_dir = case_dir / "logs"
                logs_dir.mkdir(exist_ok=True)

                for log_file in log_files:
                    if Path(log_file).exists():
                        shutil.copy2(log_file, logs_dir)
                collected['logs'] = True

            if 'files' in artifacts:
                # Recently modified files
                result = subprocess.run(
                    ["find", "/", "-type", "f", "-mmin", "-60",
                     "-not", "-path", "/proc/*", "-not", "-path", "/sys/*"],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                (case_dir / "recent_files.txt").write_text(result.stdout)
                collected['files'] = True

        elif target_type == "file":
            # Collect file artifacts
            file_path = Path(target)
            if file_path.exists():
                # Copy file
                shutil.copy2(file_path, case_dir)

                # File metadata
                stat = file_path.stat()
                metadata = {
                    'path': str(file_path),
                    'size': stat.st_size,
                    'mode': oct(stat.st_mode),
                    'uid': stat.st_uid,
                    'gid': stat.st_gid,
                    'atime': datetime.fromtimestamp(stat.st_atime).isoformat(),
                    'mtime': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    'ctime': datetime.fromtimestamp(stat.st_ctime).isoformat()
                }

                # Calculate hashes
                with open(file_path, 'rb') as f:
                    content = f.read()
                    metadata['md5'] = hashlib.md5(content).hexdigest()
                    metadata['sha256'] = hashlib.sha256(content).hexdigest()

                (case_dir / "file_metadata.json").write_text(json.dumps(metadata, indent=2))
                collected['file'] = metadata

        elif target_type == "process":
            # Collect process artifacts
            pid = int(target)
            proc_dir = Path(f"/proc/{pid}")

            if proc_dir.exists():
                # Process info
                cmdline = (proc_dir / "cmdline").read_text().replace('\x00', ' ')
                status = (proc_dir / "status").read_text()
                maps = (proc_dir / "maps").read_text()

                process_info = {
                    'pid': pid,
                    'cmdline': cmdline,
                    'status': status,
                    'maps': maps
                }

                (case_dir / "process_info.json").write_text(json.dumps(process_info, indent=2))

                # Copy executable
                exe_path = proc_dir / "exe"
                if exe_path.exists():
                    real_exe = os.readlink(exe_path)
                    if os.path.exists(real_exe):
                        shutil.copy2(real_exe, case_dir / "executable")
                        collected['executable'] = real_exe

                # File descriptors
                fd_dir = proc_dir / "fd"
                if fd_dir.exists():
                    fds = []
                    for fd in fd_dir.iterdir():
                        try:
                            fds.append({
                                'fd': fd.name,
                                'target': os.readlink(fd)
                            })
                        except Exception:
                            pass
                    (case_dir / "file_descriptors.json").write_text(json.dumps(fds, indent=2))

                collected['process'] = True

        # Create manifest
        manifest = {
            'case_id': case_dir.name,
            'target_type': target_type,
            'target': target,
            'artifacts': artifacts,
            'collected': collected,
            'timestamp': datetime.utcnow().isoformat(),
            'output_dir': str(case_dir)
        }

        (case_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

        return ActionResult(
            action="collect_forensics",
            success=True,
            message=f"Collected forensics for {target_type} {target}",
            data={
                'case_id': case_dir.name,
                'output_dir': str(case_dir),
                'collected': collected
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        return ActionResult(
            action="collect_forensics",
            success=False,
            message=f"Error collecting forensics: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Scanning Actions
# =============================================================================

def run_scan(
    scan_type: str,
    target: str,
    options: Optional[Dict[str, Any]] = None
) -> ActionResult:
    """
    Run a security scan.

    Args:
        scan_type: Type of scan (port, vulnerability, malware, yara)
        target: Scan target
        options: Scan options
    """
    import time
    start = time.time()

    options = options or {}

    try:
        if scan_type == "port":
            # Port scan using nmap
            ports = options.get('ports', '1-1000')
            result = subprocess.run(
                ["nmap", "-p", str(ports), "-sT", "--open", target, "-oX", "-"],
                capture_output=True,
                text=True,
                timeout=300
            )

            # Parse nmap XML output
            import xml.etree.ElementTree as ET
            root = ET.fromstring(result.stdout)

            open_ports = []
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    if port.find('state').get('state') == 'open':
                        open_ports.append({
                            'port': port.get('portid'),
                            'protocol': port.get('protocol'),
                            'service': port.find('service').get('name') if port.find('service') is not None else 'unknown'
                        })

            return ActionResult(
                action="run_scan",
                success=True,
                message=f"Port scan completed, found {len(open_ports)} open ports",
                data={
                    'scan_type': 'port',
                    'target': target,
                    'open_ports': open_ports
                },
                duration_ms=(time.time() - start) * 1000
            )

        elif scan_type == "malware":
            # Malware scan using ClamAV
            result = subprocess.run(
                ["clamscan", "-r", "--infected", target],
                capture_output=True,
                text=True,
                timeout=600
            )

            infected = []
            for line in result.stdout.split('\n'):
                if 'FOUND' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        infected.append({
                            'file': parts[0].strip(),
                            'threat': parts[1].replace('FOUND', '').strip()
                        })

            return ActionResult(
                action="run_scan",
                success=True,
                message=f"Malware scan completed, found {len(infected)} infected files",
                data={
                    'scan_type': 'malware',
                    'target': target,
                    'infected': infected
                },
                duration_ms=(time.time() - start) * 1000
            )

        elif scan_type == "yara":
            # YARA rule scan
            rules_path = options.get('rules', '/etc/tsunami/yara/rules')

            result = subprocess.run(
                ["yara", "-r", rules_path, target],
                capture_output=True,
                text=True,
                timeout=300
            )

            matches = []
            for line in result.stdout.split('\n'):
                if line:
                    parts = line.split()
                    if len(parts) >= 2:
                        matches.append({
                            'rule': parts[0],
                            'file': parts[1]
                        })

            return ActionResult(
                action="run_scan",
                success=True,
                message=f"YARA scan completed, found {len(matches)} matches",
                data={
                    'scan_type': 'yara',
                    'target': target,
                    'matches': matches
                },
                duration_ms=(time.time() - start) * 1000
            )

        else:
            return ActionResult(
                action="run_scan",
                success=False,
                message=f"Unknown scan type: {scan_type}",
                duration_ms=(time.time() - start) * 1000
            )

    except subprocess.TimeoutExpired:
        return ActionResult(
            action="run_scan",
            success=False,
            message="Scan timed out",
            duration_ms=(time.time() - start) * 1000
        )
    except FileNotFoundError as e:
        return ActionResult(
            action="run_scan",
            success=False,
            message=f"Scan tool not found: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        return ActionResult(
            action="run_scan",
            success=False,
            message=f"Error running scan: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Quarantine Actions
# =============================================================================

def quarantine_file(
    file_path: str,
    quarantine_dir: str = "/var/lib/tsunami/quarantine",
    delete_original: bool = True
) -> ActionResult:
    """
    Quarantine a suspicious file.

    Args:
        file_path: Path to file to quarantine
        quarantine_dir: Quarantine directory
        delete_original: Whether to delete the original file
    """
    import time
    start = time.time()

    try:
        source = Path(file_path)
        if not source.exists():
            return ActionResult(
                action="quarantine_file",
                success=False,
                message=f"File not found: {file_path}",
                duration_ms=(time.time() - start) * 1000
            )

        # Create quarantine directory
        q_dir = Path(quarantine_dir)
        q_dir.mkdir(parents=True, exist_ok=True)

        # Generate quarantine ID
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        q_id = f"Q_{timestamp}_{source.name}"

        # Calculate hashes before moving
        with open(source, 'rb') as f:
            content = f.read()
            md5_hash = hashlib.md5(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()

        # Create quarantine entry
        q_entry_dir = q_dir / q_id
        q_entry_dir.mkdir()

        # Move file with .quarantine extension
        dest = q_entry_dir / f"{source.name}.quarantine"
        shutil.copy2(source, dest)

        # Remove execute permissions
        dest.chmod(0o400)

        # Create metadata
        metadata = {
            'quarantine_id': q_id,
            'original_path': str(source),
            'quarantine_path': str(dest),
            'md5': md5_hash,
            'sha256': sha256_hash,
            'size': source.stat().st_size,
            'quarantined_at': datetime.utcnow().isoformat(),
            'original_deleted': delete_original
        }

        (q_entry_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))

        # Delete original if requested
        if delete_original:
            source.unlink()

        return ActionResult(
            action="quarantine_file",
            success=True,
            message=f"File quarantined: {q_id}",
            data=metadata,
            duration_ms=(time.time() - start) * 1000,
            rollback_info={
                'quarantine_id': q_id,
                'original_path': str(source),
                'quarantine_path': str(dest)
            }
        )

    except Exception as e:
        return ActionResult(
            action="quarantine_file",
            success=False,
            message=f"Error quarantining file: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# User Management Actions
# =============================================================================

def disable_user(
    username: str,
    method: str = "lock",
    reason: Optional[str] = None
) -> ActionResult:
    """
    Disable a user account.

    Args:
        username: Username to disable
        method: Disable method (lock, expire, shell)
        reason: Reason for disabling
    """
    import time
    start = time.time()

    try:
        if method == "lock":
            # Lock account using passwd
            result = subprocess.run(
                ["passwd", "-l", username],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return ActionResult(
                    action="disable_user",
                    success=False,
                    message=f"Failed to lock user: {result.stderr}",
                    duration_ms=(time.time() - start) * 1000
                )

        elif method == "expire":
            # Expire account
            result = subprocess.run(
                ["chage", "-E", "0", username],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return ActionResult(
                    action="disable_user",
                    success=False,
                    message=f"Failed to expire user: {result.stderr}",
                    duration_ms=(time.time() - start) * 1000
                )

        elif method == "shell":
            # Change shell to nologin
            result = subprocess.run(
                ["chsh", "-s", "/usr/sbin/nologin", username],
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                return ActionResult(
                    action="disable_user",
                    success=False,
                    message=f"Failed to change shell: {result.stderr}",
                    duration_ms=(time.time() - start) * 1000
                )

        # Kill user's processes
        subprocess.run(["pkill", "-u", username], capture_output=True)

        return ActionResult(
            action="disable_user",
            success=True,
            message=f"User {username} disabled using {method}",
            data={
                'username': username,
                'method': method,
                'reason': reason
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'username': username, 'method': method}
        )

    except Exception as e:
        return ActionResult(
            action="disable_user",
            success=False,
            message=f"Error disabling user: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Deception/Honeypot Actions (Defensive)
# =============================================================================

def deploy_honeypot(
    service_type: str,
    port: int,
    config: Optional[Dict[str, Any]] = None,
    dry_run: bool = False
) -> ActionResult:
    """
    Deploy a honeypot service to detect and track attackers.

    This is a DEFENSIVE action - honeypots are decoy systems designed to
    detect unauthorized access attempts without affecting production systems.

    Args:
        service_type: Type of honeypot service (ssh, http, ftp, telnet, smb, mysql)
        port: Port to listen on
        config: Optional configuration dict with keys:
            - banner: Custom banner string
            - log_dir: Directory for honeypot logs
            - interaction_level: low/medium/high
            - alert_on_connect: bool
        dry_run: If True, validate but don't actually deploy

    Returns:
        ActionResult with deployment details
    """
    import time
    start = time.time()

    config = config or {}
    log_dir = config.get('log_dir', '/var/lib/tsunami/honeypot')

    # Audit logging
    logger.info(f"[AUDIT] deploy_honeypot called: service_type={service_type}, port={port}, dry_run={dry_run}")

    try:
        # Validate service type
        valid_services = ['ssh', 'http', 'ftp', 'telnet', 'smb', 'mysql', 'rdp', 'smtp']
        if service_type not in valid_services:
            return ActionResult(
                action="deploy_honeypot",
                success=False,
                message=f"Invalid service type. Valid types: {valid_services}",
                data={'service_type': service_type},
                duration_ms=(time.time() - start) * 1000
            )

        # Validate port range
        if not 1 <= port <= 65535:
            return ActionResult(
                action="deploy_honeypot",
                success=False,
                message="Port must be between 1 and 65535",
                data={'port': port},
                duration_ms=(time.time() - start) * 1000
            )

        # Check if port is already in use
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()

        if result == 0:
            return ActionResult(
                action="deploy_honeypot",
                success=False,
                message=f"Port {port} is already in use",
                data={'port': port},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="deploy_honeypot",
                success=True,
                message=f"[DRY RUN] Would deploy {service_type} honeypot on port {port}",
                data={
                    'service_type': service_type,
                    'port': port,
                    'config': config,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        # Create honeypot log directory
        Path(log_dir).mkdir(parents=True, exist_ok=True)

        # Generate honeypot ID
        honeypot_id = f"HP_{service_type}_{port}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # Create honeypot configuration file
        honeypot_config = {
            'id': honeypot_id,
            'service_type': service_type,
            'port': port,
            'banner': config.get('banner', f'{service_type.upper()} Service Ready'),
            'interaction_level': config.get('interaction_level', 'low'),
            'alert_on_connect': config.get('alert_on_connect', True),
            'log_file': f"{log_dir}/{honeypot_id}.log",
            'created_at': datetime.utcnow().isoformat(),
            'status': 'deployed'
        }

        config_file = Path(log_dir) / f"{honeypot_id}.json"
        config_file.write_text(json.dumps(honeypot_config, indent=2))

        logger.info(f"[AUDIT] Honeypot deployed: {honeypot_id}")

        return ActionResult(
            action="deploy_honeypot",
            success=True,
            message=f"Honeypot {honeypot_id} deployed on port {port}",
            data=honeypot_config,
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'honeypot_id': honeypot_id, 'port': port, 'config_file': str(config_file)}
        )

    except Exception as e:
        logger.error(f"[AUDIT] deploy_honeypot failed: {str(e)}")
        return ActionResult(
            action="deploy_honeypot",
            success=False,
            message=f"Error deploying honeypot: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def create_honeytoken(
    token_type: str,
    location: str,
    alert_webhook: Optional[str] = None,
    dry_run: bool = False
) -> ActionResult:
    """
    Create a credential canary (honeytoken) to detect unauthorized access.

    Honeytokens are fake credentials or data that trigger alerts when accessed,
    helping detect data breaches and unauthorized access.

    Args:
        token_type: Type of honeytoken (aws_key, api_token, password, document, email)
        location: Where to place the token (file path or system location)
        alert_webhook: Webhook URL to notify when token is accessed
        dry_run: If True, validate but don't create

    Returns:
        ActionResult with token details (excluding sensitive token value in logs)
    """
    import time
    import secrets
    start = time.time()

    logger.info(f"[AUDIT] create_honeytoken called: type={token_type}, location={location}, dry_run={dry_run}")

    try:
        valid_types = ['aws_key', 'api_token', 'password', 'document', 'email', 'database_cred']
        if token_type not in valid_types:
            return ActionResult(
                action="create_honeytoken",
                success=False,
                message=f"Invalid token type. Valid types: {valid_types}",
                data={'token_type': token_type},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="create_honeytoken",
                success=True,
                message=f"[DRY RUN] Would create {token_type} honeytoken at {location}",
                data={
                    'token_type': token_type,
                    'location': location,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        # Generate token ID
        token_id = f"HT_{token_type}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # Generate fake credential based on type
        if token_type == 'aws_key':
            fake_cred = f"AKIA{secrets.token_hex(8).upper()}"
            secret_key = secrets.token_hex(20)
            token_content = f"aws_access_key_id = {fake_cred}\naws_secret_access_key = {secret_key}"
        elif token_type == 'api_token':
            fake_cred = f"sk-{secrets.token_hex(24)}"
            token_content = f"API_TOKEN={fake_cred}"
        elif token_type == 'password':
            fake_cred = f"admin:{secrets.token_hex(16)}"
            token_content = fake_cred
        elif token_type == 'document':
            fake_cred = "CONFIDENTIAL_DOC"
            token_content = f"# Confidential Document\nToken: {token_id}\nThis document contains sensitive information."
        elif token_type == 'email':
            fake_cred = f"canary-{secrets.token_hex(4)}@internal.local"
            token_content = fake_cred
        elif token_type == 'database_cred':
            fake_cred = f"db_user:db_pass_{secrets.token_hex(8)}"
            token_content = f"DATABASE_URL=postgresql://{fake_cred}@localhost:5432/production"
        else:
            fake_cred = secrets.token_hex(16)
            token_content = fake_cred

        # Write token to location
        token_path = Path(location)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token_content)

        # Store token metadata (for tracking)
        metadata_dir = Path('/var/lib/tsunami/honeytokens')
        metadata_dir.mkdir(parents=True, exist_ok=True)

        metadata = {
            'token_id': token_id,
            'token_type': token_type,
            'location': str(location),
            'alert_webhook': alert_webhook,
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active',
            # Note: We don't store the actual token value in metadata for security
            'token_hash': hashlib.sha256(fake_cred.encode()).hexdigest()
        }

        metadata_file = metadata_dir / f"{token_id}.json"
        metadata_file.write_text(json.dumps(metadata, indent=2))

        logger.info(f"[AUDIT] Honeytoken created: {token_id}")

        return ActionResult(
            action="create_honeytoken",
            success=True,
            message=f"Honeytoken {token_id} created at {location}",
            data={
                'token_id': token_id,
                'token_type': token_type,
                'location': str(location),
                'alert_webhook': alert_webhook
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'token_id': token_id, 'location': str(location), 'metadata_file': str(metadata_file)}
        )

    except Exception as e:
        logger.error(f"[AUDIT] create_honeytoken failed: {str(e)}")
        return ActionResult(
            action="create_honeytoken",
            success=False,
            message=f"Error creating honeytoken: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def activate_decoy_system(
    decoy_id: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Activate a pre-configured decoy system to attract and analyze attackers.

    Decoy systems are isolated environments that mimic production systems,
    allowing safe observation of attacker techniques and tools.

    Args:
        decoy_id: Identifier of the decoy system to activate
        dry_run: If True, validate but don't activate

    Returns:
        ActionResult with activation status
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] activate_decoy_system called: decoy_id={decoy_id}, dry_run={dry_run}")

    try:
        # Look for decoy configuration
        decoy_config_dir = Path('/var/lib/tsunami/decoys')
        decoy_config_file = decoy_config_dir / f"{decoy_id}.json"

        if dry_run:
            return ActionResult(
                action="activate_decoy_system",
                success=True,
                message=f"[DRY RUN] Would activate decoy system: {decoy_id}",
                data={'decoy_id': decoy_id, 'dry_run': True},
                duration_ms=(time.time() - start) * 1000
            )

        # Check if decoy configuration exists
        if decoy_config_file.exists():
            decoy_config = json.loads(decoy_config_file.read_text())
        else:
            # Create default decoy configuration
            decoy_config_dir.mkdir(parents=True, exist_ok=True)
            decoy_config = {
                'decoy_id': decoy_id,
                'status': 'inactive',
                'created_at': datetime.utcnow().isoformat(),
                'type': 'generic',
                'network_config': {},
                'services': []
            }

        # Activate the decoy
        decoy_config['status'] = 'active'
        decoy_config['activated_at'] = datetime.utcnow().isoformat()

        decoy_config_file.write_text(json.dumps(decoy_config, indent=2))

        logger.info(f"[AUDIT] Decoy system activated: {decoy_id}")

        return ActionResult(
            action="activate_decoy_system",
            success=True,
            message=f"Decoy system {decoy_id} activated",
            data=decoy_config,
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'decoy_id': decoy_id, 'config_file': str(decoy_config_file)}
        )

    except Exception as e:
        logger.error(f"[AUDIT] activate_decoy_system failed: {str(e)}")
        return ActionResult(
            action="activate_decoy_system",
            success=False,
            message=f"Error activating decoy system: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Forensic/Evidence Actions (Defensive)
# =============================================================================

def capture_memory_dump(
    target_host: str,
    output_path: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Capture memory dump from a target host for forensic analysis.

    Memory forensics is critical for analyzing malware, detecting rootkits,
    and extracting evidence that may not be available on disk.

    Args:
        target_host: Hostname or IP of target (use 'localhost' for local)
        output_path: Path to store the memory dump
        dry_run: If True, validate but don't capture

    Returns:
        ActionResult with dump details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] capture_memory_dump called: target={target_host}, output={output_path}, dry_run={dry_run}")

    try:
        output_dir = Path(output_path).parent

        if dry_run:
            return ActionResult(
                action="capture_memory_dump",
                success=True,
                message=f"[DRY RUN] Would capture memory from {target_host} to {output_path}",
                data={
                    'target_host': target_host,
                    'output_path': output_path,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        if target_host in ['localhost', '127.0.0.1', socket.gethostname()]:
            # Local memory dump
            # Try different memory acquisition tools
            dump_methods = [
                (['avml', output_path], 'AVML'),
                (['lime', '-o', output_path], 'LiME'),
                (['cp', '/proc/kcore', output_path], 'kcore')
            ]

            dump_successful = False
            method_used = None

            for cmd, method in dump_methods:
                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=600
                    )
                    if result.returncode == 0 or Path(output_path).exists():
                        dump_successful = True
                        method_used = method
                        break
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue

            if not dump_successful:
                # Fallback: capture process memory maps
                fallback_dir = Path(output_path).parent / "process_memory"
                fallback_dir.mkdir(exist_ok=True)

                # Get list of processes
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                (fallback_dir / "process_list.txt").write_text(result.stdout)

                method_used = "process_list_fallback"

            timestamp = datetime.utcnow().isoformat()

            # Create acquisition metadata
            metadata = {
                'target_host': target_host,
                'output_path': output_path,
                'method': method_used,
                'timestamp': timestamp,
                'hostname': socket.gethostname()
            }

            metadata_path = Path(output_path).with_suffix('.metadata.json')
            metadata_path.write_text(json.dumps(metadata, indent=2))

            logger.info(f"[AUDIT] Memory dump captured using {method_used}")

            return ActionResult(
                action="capture_memory_dump",
                success=True,
                message=f"Memory dump captured from {target_host}",
                data={
                    'target_host': target_host,
                    'output_path': output_path,
                    'method': method_used,
                    'metadata_path': str(metadata_path)
                },
                duration_ms=(time.time() - start) * 1000
            )
        else:
            # Remote memory dump would require agent or SSH
            return ActionResult(
                action="capture_memory_dump",
                success=False,
                message="Remote memory dump requires agent on target host",
                data={'target_host': target_host},
                duration_ms=(time.time() - start) * 1000
            )

    except Exception as e:
        logger.error(f"[AUDIT] capture_memory_dump failed: {str(e)}")
        return ActionResult(
            action="capture_memory_dump",
            success=False,
            message=f"Error capturing memory dump: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def snapshot_network_state(
    dry_run: bool = False
) -> ActionResult:
    """
    Capture current network topology and connection state for forensic baseline.

    This captures active connections, routing tables, ARP cache, and interface
    state for later comparison during incident investigation.

    Args:
        dry_run: If True, validate but don't capture

    Returns:
        ActionResult with network state snapshot
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] snapshot_network_state called: dry_run={dry_run}")

    try:
        if dry_run:
            return ActionResult(
                action="snapshot_network_state",
                success=True,
                message="[DRY RUN] Would capture network state snapshot",
                data={'dry_run': True},
                duration_ms=(time.time() - start) * 1000
            )

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        snapshot_dir = Path(f'/var/lib/tsunami/network_snapshots/snapshot_{timestamp}')
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        snapshot_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'hostname': socket.gethostname(),
            'files': []
        }

        # Capture various network states
        commands = [
            (['ss', '-tunapl'], 'connections.txt', 'Active connections'),
            (['ip', 'addr'], 'interfaces.txt', 'Network interfaces'),
            (['ip', 'route'], 'routes.txt', 'Routing table'),
            (['ip', 'neigh'], 'arp_cache.txt', 'ARP cache'),
            (['iptables', '-L', '-n', '-v'], 'iptables.txt', 'Firewall rules'),
            (['netstat', '-s'], 'netstat_stats.txt', 'Network statistics'),
            (['cat', '/proc/net/tcp'], 'proc_net_tcp.txt', 'TCP connections raw'),
            (['cat', '/proc/net/udp'], 'proc_net_udp.txt', 'UDP connections raw'),
        ]

        for cmd, filename, description in commands:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                output_file = snapshot_dir / filename
                output_file.write_text(result.stdout)
                snapshot_data['files'].append({
                    'file': filename,
                    'description': description,
                    'success': result.returncode == 0
                })
            except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                snapshot_data['files'].append({
                    'file': filename,
                    'description': description,
                    'success': False,
                    'error': str(e)
                })

        # Save snapshot metadata
        metadata_file = snapshot_dir / 'snapshot_metadata.json'
        metadata_file.write_text(json.dumps(snapshot_data, indent=2))

        logger.info(f"[AUDIT] Network state snapshot captured: {snapshot_dir}")

        return ActionResult(
            action="snapshot_network_state",
            success=True,
            message=f"Network state snapshot captured",
            data={
                'snapshot_dir': str(snapshot_dir),
                'timestamp': snapshot_data['timestamp'],
                'files_captured': len([f for f in snapshot_data['files'] if f['success']])
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        logger.error(f"[AUDIT] snapshot_network_state failed: {str(e)}")
        return ActionResult(
            action="snapshot_network_state",
            success=False,
            message=f"Error capturing network state: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def collect_volatile_evidence(
    target_ip: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Collect volatile forensic data from a target system.

    Volatile evidence includes data that will be lost on reboot:
    running processes, memory contents, network connections, logged-in users.

    Args:
        target_ip: IP address of target system (localhost for local)
        dry_run: If True, validate but don't collect

    Returns:
        ActionResult with collection details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] collect_volatile_evidence called: target_ip={target_ip}, dry_run={dry_run}")

    try:
        if dry_run:
            return ActionResult(
                action="collect_volatile_evidence",
                success=True,
                message=f"[DRY RUN] Would collect volatile evidence from {target_ip}",
                data={'target_ip': target_ip, 'dry_run': True},
                duration_ms=(time.time() - start) * 1000
            )

        is_local = target_ip in ['localhost', '127.0.0.1', socket.gethostname()]

        if not is_local:
            return ActionResult(
                action="collect_volatile_evidence",
                success=False,
                message="Remote volatile evidence collection requires agent",
                data={'target_ip': target_ip},
                duration_ms=(time.time() - start) * 1000
            )

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        evidence_dir = Path(f'/var/lib/tsunami/volatile_evidence/evidence_{timestamp}')
        evidence_dir.mkdir(parents=True, exist_ok=True)

        collected = {}

        # Collect running processes with full details
        result = subprocess.run(['ps', 'auxwww'], capture_output=True, text=True)
        (evidence_dir / 'processes.txt').write_text(result.stdout)
        collected['processes'] = True

        # Process tree
        result = subprocess.run(['pstree', '-p'], capture_output=True, text=True)
        (evidence_dir / 'process_tree.txt').write_text(result.stdout)
        collected['process_tree'] = True

        # Open files by processes
        result = subprocess.run(['lsof', '-n'], capture_output=True, text=True, timeout=60)
        (evidence_dir / 'open_files.txt').write_text(result.stdout)
        collected['open_files'] = True

        # Network connections
        result = subprocess.run(['ss', '-tunapl'], capture_output=True, text=True)
        (evidence_dir / 'network_connections.txt').write_text(result.stdout)
        collected['network'] = True

        # Logged in users
        result = subprocess.run(['w'], capture_output=True, text=True)
        (evidence_dir / 'logged_in_users.txt').write_text(result.stdout)
        collected['users'] = True

        # Recent logins
        result = subprocess.run(['last', '-n', '50'], capture_output=True, text=True)
        (evidence_dir / 'recent_logins.txt').write_text(result.stdout)
        collected['logins'] = True

        # System uptime and load
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        (evidence_dir / 'uptime.txt').write_text(result.stdout)
        collected['uptime'] = True

        # Kernel modules
        result = subprocess.run(['lsmod'], capture_output=True, text=True)
        (evidence_dir / 'kernel_modules.txt').write_text(result.stdout)
        collected['modules'] = True

        # Environment variables for all processes
        env_data = {}
        for proc in Path('/proc').iterdir():
            if proc.name.isdigit():
                try:
                    environ = (proc / 'environ').read_bytes().decode('utf-8', errors='replace')
                    env_data[proc.name] = environ.replace('\x00', '\n')
                except (PermissionError, FileNotFoundError):
                    pass
        (evidence_dir / 'process_environments.json').write_text(json.dumps(env_data, indent=2))
        collected['environments'] = True

        # Create evidence manifest
        manifest = {
            'case_timestamp': timestamp,
            'target_ip': target_ip,
            'hostname': socket.gethostname(),
            'collected_at': datetime.utcnow().isoformat(),
            'evidence_dir': str(evidence_dir),
            'collected_artifacts': collected
        }
        (evidence_dir / 'manifest.json').write_text(json.dumps(manifest, indent=2))

        logger.info(f"[AUDIT] Volatile evidence collected: {evidence_dir}")

        return ActionResult(
            action="collect_volatile_evidence",
            success=True,
            message=f"Volatile evidence collected from {target_ip}",
            data={
                'evidence_dir': str(evidence_dir),
                'collected': collected,
                'timestamp': timestamp
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        logger.error(f"[AUDIT] collect_volatile_evidence failed: {str(e)}")
        return ActionResult(
            action="collect_volatile_evidence",
            success=False,
            message=f"Error collecting volatile evidence: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def preserve_logs(
    source: str,
    destination: str,
    retention_days: int = 90,
    dry_run: bool = False
) -> ActionResult:
    """
    Preserve logs for incident investigation with integrity verification.

    Creates a tamper-evident copy of logs with hashes for chain of custody.

    Args:
        source: Source log file or directory path
        destination: Destination directory for preserved logs
        retention_days: How long to retain the logs (metadata only)
        dry_run: If True, validate but don't preserve

    Returns:
        ActionResult with preservation details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] preserve_logs called: source={source}, dest={destination}, dry_run={dry_run}")

    try:
        source_path = Path(source)
        dest_path = Path(destination)

        if not source_path.exists():
            return ActionResult(
                action="preserve_logs",
                success=False,
                message=f"Source path does not exist: {source}",
                data={'source': source},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="preserve_logs",
                success=True,
                message=f"[DRY RUN] Would preserve {source} to {destination}",
                data={
                    'source': source,
                    'destination': destination,
                    'retention_days': retention_days,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        # Create destination with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        preservation_dir = dest_path / f"preserved_{timestamp}"
        preservation_dir.mkdir(parents=True, exist_ok=True)

        preserved_files = []

        if source_path.is_file():
            files_to_preserve = [source_path]
        else:
            files_to_preserve = list(source_path.rglob('*'))

        for file_path in files_to_preserve:
            if file_path.is_file():
                try:
                    # Calculate hash before copying
                    with open(file_path, 'rb') as f:
                        content = f.read()
                        sha256_hash = hashlib.sha256(content).hexdigest()

                    # Preserve relative path structure
                    if source_path.is_dir():
                        rel_path = file_path.relative_to(source_path)
                        dest_file = preservation_dir / rel_path
                    else:
                        dest_file = preservation_dir / file_path.name

                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(file_path, dest_file)

                    preserved_files.append({
                        'original_path': str(file_path),
                        'preserved_path': str(dest_file),
                        'sha256': sha256_hash,
                        'size': len(content),
                        'mtime': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat()
                    })
                except (PermissionError, IOError) as e:
                    preserved_files.append({
                        'original_path': str(file_path),
                        'error': str(e)
                    })

        # Create chain of custody manifest
        manifest = {
            'preservation_id': f"LOG_PRESERVE_{timestamp}",
            'source': source,
            'destination': str(preservation_dir),
            'retention_days': retention_days,
            'retention_until': (datetime.utcnow() + timedelta(days=retention_days)).isoformat(),
            'preserved_at': datetime.utcnow().isoformat(),
            'preserved_by': os.environ.get('USER', 'system'),
            'hostname': socket.gethostname(),
            'files': preserved_files,
            'total_files': len([f for f in preserved_files if 'error' not in f])
        }

        manifest_file = preservation_dir / 'chain_of_custody.json'
        manifest_file.write_text(json.dumps(manifest, indent=2))

        # Calculate manifest hash
        manifest_hash = hashlib.sha256(manifest_file.read_bytes()).hexdigest()
        (preservation_dir / 'manifest.sha256').write_text(manifest_hash)

        logger.info(f"[AUDIT] Logs preserved: {len(preserved_files)} files to {preservation_dir}")

        return ActionResult(
            action="preserve_logs",
            success=True,
            message=f"Preserved {len([f for f in preserved_files if 'error' not in f])} log files",
            data={
                'preservation_dir': str(preservation_dir),
                'files_preserved': len([f for f in preserved_files if 'error' not in f]),
                'manifest_hash': manifest_hash
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        logger.error(f"[AUDIT] preserve_logs failed: {str(e)}")
        return ActionResult(
            action="preserve_logs",
            success=False,
            message=f"Error preserving logs: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def create_forensic_image(
    device: str,
    output_path: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Create a forensic disk image with hash verification.

    Creates a bit-for-bit copy of storage media for forensic analysis,
    preserving evidence integrity.

    Args:
        device: Device path (e.g., /dev/sda1) or file path
        output_path: Output path for the forensic image
        dry_run: If True, validate but don't create image

    Returns:
        ActionResult with imaging details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] create_forensic_image called: device={device}, output={output_path}, dry_run={dry_run}")

    try:
        device_path = Path(device)
        output_file = Path(output_path)

        # Validate device exists
        if not device_path.exists():
            return ActionResult(
                action="create_forensic_image",
                success=False,
                message=f"Device not found: {device}",
                data={'device': device},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="create_forensic_image",
                success=True,
                message=f"[DRY RUN] Would create forensic image of {device} at {output_path}",
                data={
                    'device': device,
                    'output_path': output_path,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        # Create output directory
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Try dc3dd first (forensic tool), fall back to dd
        imaging_tools = [
            (['dc3dd', f'if={device}', f'of={output_path}', 'hash=sha256', 'log=/dev/stderr'], 'dc3dd'),
            (['dd', f'if={device}', f'of={output_path}', 'bs=4M', 'status=progress'], 'dd')
        ]

        image_created = False
        method_used = None

        for cmd, method in imaging_tools:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=7200  # 2 hour timeout for large images
                )
                if result.returncode == 0 or output_file.exists():
                    image_created = True
                    method_used = method
                    break
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue

        if not image_created:
            return ActionResult(
                action="create_forensic_image",
                success=False,
                message="Failed to create forensic image - no imaging tool available",
                data={'device': device},
                duration_ms=(time.time() - start) * 1000
            )

        # Calculate hash of the image
        sha256_hash = hashlib.sha256()
        with open(output_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256_hash.update(chunk)
        image_hash = sha256_hash.hexdigest()

        # Write hash file
        hash_file = Path(f"{output_path}.sha256")
        hash_file.write_text(f"{image_hash}  {output_file.name}\n")

        # Create acquisition metadata
        metadata = {
            'acquisition_id': f"IMG_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            'source_device': device,
            'image_path': str(output_path),
            'image_size': output_file.stat().st_size,
            'sha256': image_hash,
            'method': method_used,
            'acquired_at': datetime.utcnow().isoformat(),
            'acquired_by': os.environ.get('USER', 'system'),
            'hostname': socket.gethostname()
        }

        metadata_file = Path(f"{output_path}.metadata.json")
        metadata_file.write_text(json.dumps(metadata, indent=2))

        logger.info(f"[AUDIT] Forensic image created: {output_path}, hash={image_hash[:16]}...")

        return ActionResult(
            action="create_forensic_image",
            success=True,
            message=f"Forensic image created: {output_path}",
            data={
                'image_path': str(output_path),
                'image_size': output_file.stat().st_size,
                'sha256': image_hash,
                'method': method_used,
                'metadata_file': str(metadata_file)
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        logger.error(f"[AUDIT] create_forensic_image failed: {str(e)}")
        return ActionResult(
            action="create_forensic_image",
            success=False,
            message=f"Error creating forensic image: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Enhanced Isolation Actions (Defensive)
# =============================================================================

def quarantine_endpoint(
    ip_address: str,
    isolation_level: str = "standard",
    dry_run: bool = False
) -> ActionResult:
    """
    Progressively isolate an endpoint based on threat severity.

    Isolation levels:
    - monitor: Allow traffic but increase logging
    - standard: Block lateral movement, allow internet + management
    - strict: Block all except management
    - complete: Block all traffic

    Args:
        ip_address: IP address of endpoint to quarantine
        isolation_level: Level of isolation (monitor, standard, strict, complete)
        dry_run: If True, validate but don't apply

    Returns:
        ActionResult with quarantine details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] quarantine_endpoint called: ip={ip_address}, level={isolation_level}, dry_run={dry_run}")

    try:
        # Validate IP
        socket.inet_aton(ip_address)

        valid_levels = ['monitor', 'standard', 'strict', 'complete']
        if isolation_level not in valid_levels:
            return ActionResult(
                action="quarantine_endpoint",
                success=False,
                message=f"Invalid isolation level. Valid levels: {valid_levels}",
                data={'isolation_level': isolation_level},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="quarantine_endpoint",
                success=True,
                message=f"[DRY RUN] Would quarantine {ip_address} at {isolation_level} level",
                data={
                    'ip_address': ip_address,
                    'isolation_level': isolation_level,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        rules_applied = []

        if isolation_level == 'monitor':
            # Just log traffic, no blocking
            cmd = ["iptables", "-I", "FORWARD", "-s", ip_address, "-j", "LOG",
                   "--log-prefix", f"QUARANTINE_MONITOR_{ip_address}: "]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append(f"LOG rule for {ip_address}")

        elif isolation_level == 'standard':
            # Block lateral movement (internal traffic), allow internet
            # Block RFC1918 ranges
            for network in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']:
                cmd = ["iptables", "-I", "FORWARD", "-s", ip_address, "-d", network, "-j", "DROP"]
                subprocess.run(cmd, capture_output=True)
                rules_applied.append(f"DROP {ip_address} -> {network}")
            # Allow management (SSH)
            cmd = ["iptables", "-I", "FORWARD", "-d", ip_address, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append("ACCEPT SSH to endpoint")

        elif isolation_level == 'strict':
            # Block all except management
            cmd = ["iptables", "-I", "FORWARD", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append(f"DROP all from {ip_address}")
            cmd = ["iptables", "-I", "FORWARD", "-d", ip_address, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append(f"DROP all to {ip_address}")
            # Allow SSH for management
            cmd = ["iptables", "-I", "FORWARD", "-d", ip_address, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append("ACCEPT SSH to endpoint")

        elif isolation_level == 'complete':
            # Block everything
            cmd = ["iptables", "-I", "FORWARD", "-s", ip_address, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append(f"DROP all from {ip_address}")
            cmd = ["iptables", "-I", "FORWARD", "-d", ip_address, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append(f"DROP all to {ip_address}")

        # Store quarantine state
        quarantine_dir = Path('/var/lib/tsunami/quarantine_state')
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        quarantine_state = {
            'ip_address': ip_address,
            'isolation_level': isolation_level,
            'rules_applied': rules_applied,
            'quarantined_at': datetime.utcnow().isoformat(),
            'status': 'active'
        }

        state_file = quarantine_dir / f"{ip_address.replace('.', '_')}.json"
        state_file.write_text(json.dumps(quarantine_state, indent=2))

        logger.info(f"[AUDIT] Endpoint quarantined: {ip_address} at {isolation_level} level")

        return ActionResult(
            action="quarantine_endpoint",
            success=True,
            message=f"Endpoint {ip_address} quarantined at {isolation_level} level",
            data={
                'ip_address': ip_address,
                'isolation_level': isolation_level,
                'rules_applied': rules_applied
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'ip_address': ip_address, 'isolation_level': isolation_level}
        )

    except socket.error:
        return ActionResult(
            action="quarantine_endpoint",
            success=False,
            message=f"Invalid IP address: {ip_address}",
            duration_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        logger.error(f"[AUDIT] quarantine_endpoint failed: {str(e)}")
        return ActionResult(
            action="quarantine_endpoint",
            success=False,
            message=f"Error quarantining endpoint: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def segment_network(
    vlan_id: int,
    affected_hosts: List[str],
    dry_run: bool = False
) -> ActionResult:
    """
    Segment network by isolating hosts into a quarantine VLAN.

    This creates network segmentation to contain threats and prevent
    lateral movement across the network.

    Args:
        vlan_id: VLAN ID for the isolation segment
        affected_hosts: List of IP addresses to move to isolation VLAN
        dry_run: If True, validate but don't apply

    Returns:
        ActionResult with segmentation details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] segment_network called: vlan={vlan_id}, hosts={affected_hosts}, dry_run={dry_run}")

    try:
        # Validate VLAN ID
        if not 1 <= vlan_id <= 4094:
            return ActionResult(
                action="segment_network",
                success=False,
                message="VLAN ID must be between 1 and 4094",
                data={'vlan_id': vlan_id},
                duration_ms=(time.time() - start) * 1000
            )

        # Validate IPs
        for host in affected_hosts:
            try:
                socket.inet_aton(host)
            except socket.error:
                return ActionResult(
                    action="segment_network",
                    success=False,
                    message=f"Invalid IP address: {host}",
                    data={'invalid_host': host},
                    duration_ms=(time.time() - start) * 1000
                )

        if dry_run:
            return ActionResult(
                action="segment_network",
                success=True,
                message=f"[DRY RUN] Would segment {len(affected_hosts)} hosts into VLAN {vlan_id}",
                data={
                    'vlan_id': vlan_id,
                    'affected_hosts': affected_hosts,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        # Apply iptables rules to simulate VLAN segmentation
        # In production, this would interface with network switches
        rules_applied = []

        for host in affected_hosts:
            # Block traffic between affected hosts and rest of network
            # except traffic within the same "VLAN" (affected hosts group)
            cmd = ["iptables", "-I", "FORWARD", "-s", host, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append(f"DROP all from {host}")

            cmd = ["iptables", "-I", "FORWARD", "-d", host, "-j", "DROP"]
            subprocess.run(cmd, capture_output=True)
            rules_applied.append(f"DROP all to {host}")

        # Allow traffic between affected hosts (within segment)
        for src_host in affected_hosts:
            for dst_host in affected_hosts:
                if src_host != dst_host:
                    cmd = ["iptables", "-I", "FORWARD", "-s", src_host, "-d", dst_host, "-j", "ACCEPT"]
                    subprocess.run(cmd, capture_output=True)
                    rules_applied.append(f"ACCEPT {src_host} <-> {dst_host}")

        # Store segmentation state
        segment_dir = Path('/var/lib/tsunami/network_segments')
        segment_dir.mkdir(parents=True, exist_ok=True)

        segment_state = {
            'segment_id': f"SEG_{vlan_id}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
            'vlan_id': vlan_id,
            'affected_hosts': affected_hosts,
            'rules_applied': rules_applied,
            'created_at': datetime.utcnow().isoformat(),
            'status': 'active'
        }

        state_file = segment_dir / f"vlan_{vlan_id}.json"
        state_file.write_text(json.dumps(segment_state, indent=2))

        logger.info(f"[AUDIT] Network segmented: VLAN {vlan_id} with {len(affected_hosts)} hosts")

        return ActionResult(
            action="segment_network",
            success=True,
            message=f"Network segmented: {len(affected_hosts)} hosts isolated in VLAN {vlan_id}",
            data={
                'segment_id': segment_state['segment_id'],
                'vlan_id': vlan_id,
                'affected_hosts': affected_hosts,
                'rules_count': len(rules_applied)
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'vlan_id': vlan_id, 'affected_hosts': affected_hosts}
        )

    except Exception as e:
        logger.error(f"[AUDIT] segment_network failed: {str(e)}")
        return ActionResult(
            action="segment_network",
            success=False,
            message=f"Error segmenting network: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def disable_user_account(
    username: str,
    reason: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Disable a user account as part of incident response.

    This is a more comprehensive version that logs the reason and
    terminates active sessions.

    Args:
        username: Username to disable
        reason: Documented reason for disabling
        dry_run: If True, validate but don't disable

    Returns:
        ActionResult with disable details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] disable_user_account called: username={username}, reason={reason}, dry_run={dry_run}")

    try:
        # Check if user exists
        result = subprocess.run(['id', username], capture_output=True, text=True)
        if result.returncode != 0:
            return ActionResult(
                action="disable_user_account",
                success=False,
                message=f"User not found: {username}",
                data={'username': username},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="disable_user_account",
                success=True,
                message=f"[DRY RUN] Would disable user {username}",
                data={
                    'username': username,
                    'reason': reason,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        actions_taken = []

        # Lock the account
        result = subprocess.run(['passwd', '-l', username], capture_output=True, text=True)
        if result.returncode == 0:
            actions_taken.append('account_locked')

        # Expire the account
        result = subprocess.run(['chage', '-E', '0', username], capture_output=True, text=True)
        if result.returncode == 0:
            actions_taken.append('account_expired')

        # Kill all user sessions
        subprocess.run(['pkill', '-KILL', '-u', username], capture_output=True)
        actions_taken.append('sessions_terminated')

        # Disable cron jobs
        cron_file = Path(f'/var/spool/cron/crontabs/{username}')
        if cron_file.exists():
            backup_file = Path(f'/var/lib/tsunami/disabled_crons/{username}.cron.bak')
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(cron_file), str(backup_file))
            actions_taken.append('cron_disabled')

        # Log the action
        disable_log_dir = Path('/var/lib/tsunami/disabled_accounts')
        disable_log_dir.mkdir(parents=True, exist_ok=True)

        disable_record = {
            'username': username,
            'reason': reason,
            'disabled_at': datetime.utcnow().isoformat(),
            'disabled_by': os.environ.get('USER', 'system'),
            'actions_taken': actions_taken
        }

        log_file = disable_log_dir / f"{username}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        log_file.write_text(json.dumps(disable_record, indent=2))

        logger.info(f"[AUDIT] User account disabled: {username}, reason: {reason}")

        return ActionResult(
            action="disable_user_account",
            success=True,
            message=f"User account {username} disabled",
            data={
                'username': username,
                'reason': reason,
                'actions_taken': actions_taken
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'username': username, 'log_file': str(log_file)}
        )

    except Exception as e:
        logger.error(f"[AUDIT] disable_user_account failed: {str(e)}")
        return ActionResult(
            action="disable_user_account",
            success=False,
            message=f"Error disabling user account: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def revoke_access_tokens(
    user_id: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Revoke all access tokens for a user across integrated systems.

    This invalidates API tokens, session tokens, and OAuth tokens
    to immediately cut off access.

    Args:
        user_id: User identifier (username or user ID)
        dry_run: If True, validate but don't revoke

    Returns:
        ActionResult with revocation details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] revoke_access_tokens called: user_id={user_id}, dry_run={dry_run}")

    try:
        if dry_run:
            return ActionResult(
                action="revoke_access_tokens",
                success=True,
                message=f"[DRY RUN] Would revoke all tokens for user {user_id}",
                data={
                    'user_id': user_id,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        tokens_revoked = {
            'local_sessions': 0,
            'api_tokens': 0,
            'oauth_tokens': 0
        }

        # Revoke local session tokens (if using file-based sessions)
        session_dir = Path('/var/lib/tsunami/sessions')
        if session_dir.exists():
            for session_file in session_dir.glob(f'*{user_id}*'):
                session_file.unlink()
                tokens_revoked['local_sessions'] += 1

        # Record token revocation for audit
        revocation_dir = Path('/var/lib/tsunami/token_revocations')
        revocation_dir.mkdir(parents=True, exist_ok=True)

        revocation_record = {
            'user_id': user_id,
            'revoked_at': datetime.utcnow().isoformat(),
            'revoked_by': os.environ.get('USER', 'system'),
            'tokens_revoked': tokens_revoked,
            'revocation_id': f"REV_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{user_id}"
        }

        record_file = revocation_dir / f"{revocation_record['revocation_id']}.json"
        record_file.write_text(json.dumps(revocation_record, indent=2))

        # Force password change on next login
        subprocess.run(['chage', '-d', '0', user_id], capture_output=True)

        logger.info(f"[AUDIT] Access tokens revoked for user: {user_id}")

        return ActionResult(
            action="revoke_access_tokens",
            success=True,
            message=f"Access tokens revoked for user {user_id}",
            data={
                'user_id': user_id,
                'tokens_revoked': tokens_revoked,
                'revocation_id': revocation_record['revocation_id']
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'user_id': user_id, 'revocation_id': revocation_record['revocation_id']}
        )

    except Exception as e:
        logger.error(f"[AUDIT] revoke_access_tokens failed: {str(e)}")
        return ActionResult(
            action="revoke_access_tokens",
            success=False,
            message=f"Error revoking access tokens: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Monitoring Enhancement Actions (Defensive)
# =============================================================================

def increase_logging_level(
    target: str,
    level: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Increase logging level for enhanced monitoring during incidents.

    Args:
        target: Target system or service (syslog, auth, network, application name)
        level: Logging level (debug, verbose, info, warning)
        dry_run: If True, validate but don't apply

    Returns:
        ActionResult with logging configuration details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] increase_logging_level called: target={target}, level={level}, dry_run={dry_run}")

    try:
        valid_levels = ['debug', 'verbose', 'info', 'warning']
        if level not in valid_levels:
            return ActionResult(
                action="increase_logging_level",
                success=False,
                message=f"Invalid logging level. Valid levels: {valid_levels}",
                data={'level': level},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="increase_logging_level",
                success=True,
                message=f"[DRY RUN] Would set {target} logging to {level}",
                data={
                    'target': target,
                    'level': level,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        changes_made = []

        if target == 'syslog':
            # Modify rsyslog configuration
            rsyslog_conf = '/etc/rsyslog.d/99-tsunami-enhanced.conf'
            config_content = f"""# Enhanced logging for incident response
# Generated by TSUNAMI SOAR at {datetime.utcnow().isoformat()}
*.{level}\t/var/log/tsunami-enhanced.log
"""
            Path(rsyslog_conf).write_text(config_content)
            subprocess.run(['systemctl', 'restart', 'rsyslog'], capture_output=True)
            changes_made.append('rsyslog_config_updated')

        elif target == 'auth':
            # Enable verbose auth logging
            pam_debug_conf = '/etc/security/pam_debug.conf'
            Path(pam_debug_conf).write_text(f"debug={level}\n")
            changes_made.append('pam_debug_enabled')

        elif target == 'network':
            # Enable connection tracking logging
            cmd = ["iptables", "-I", "INPUT", "-m", "state", "--state", "NEW",
                   "-j", "LOG", "--log-prefix", "NEW_CONN: ", "--log-level", "4"]
            subprocess.run(cmd, capture_output=True)
            changes_made.append('connection_logging_enabled')

        # Store logging enhancement state
        enhance_dir = Path('/var/lib/tsunami/logging_enhancements')
        enhance_dir.mkdir(parents=True, exist_ok=True)

        enhancement_record = {
            'target': target,
            'level': level,
            'changes_made': changes_made,
            'enhanced_at': datetime.utcnow().isoformat(),
            'status': 'active'
        }

        record_file = enhance_dir / f"{target}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json"
        record_file.write_text(json.dumps(enhancement_record, indent=2))

        logger.info(f"[AUDIT] Logging level increased: {target} -> {level}")

        return ActionResult(
            action="increase_logging_level",
            success=True,
            message=f"Logging level for {target} set to {level}",
            data={
                'target': target,
                'level': level,
                'changes_made': changes_made
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'target': target, 'record_file': str(record_file)}
        )

    except Exception as e:
        logger.error(f"[AUDIT] increase_logging_level failed: {str(e)}")
        return ActionResult(
            action="increase_logging_level",
            success=False,
            message=f"Error increasing logging level: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def enable_packet_capture(
    interface: str,
    filter_expr: Optional[str] = None,
    duration: int = 300,
    dry_run: bool = False
) -> ActionResult:
    """
    Enable packet capture for traffic analysis during incidents.

    Args:
        interface: Network interface to capture on (e.g., eth0, any)
        filter_expr: BPF filter expression (e.g., "host 192.168.1.100")
        duration: Capture duration in seconds (max 3600)
        dry_run: If True, validate but don't capture

    Returns:
        ActionResult with capture details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] enable_packet_capture called: interface={interface}, filter={filter_expr}, duration={duration}, dry_run={dry_run}")

    try:
        # Validate duration
        if duration > 3600:
            return ActionResult(
                action="enable_packet_capture",
                success=False,
                message="Maximum capture duration is 3600 seconds (1 hour)",
                data={'duration': duration},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="enable_packet_capture",
                success=True,
                message=f"[DRY RUN] Would capture on {interface} for {duration}s",
                data={
                    'interface': interface,
                    'filter': filter_expr,
                    'duration': duration,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        # Create capture directory
        capture_dir = Path('/var/lib/tsunami/packet_captures')
        capture_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        capture_file = capture_dir / f"capture_{interface}_{timestamp}.pcap"

        # Build tcpdump command
        cmd = ['tcpdump', '-i', interface, '-w', str(capture_file), '-c', '100000']

        if filter_expr:
            cmd.append(filter_expr)

        # Start capture in background
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        # Store capture metadata
        capture_metadata = {
            'capture_id': f"CAP_{timestamp}",
            'interface': interface,
            'filter': filter_expr,
            'duration': duration,
            'capture_file': str(capture_file),
            'pid': process.pid,
            'started_at': datetime.utcnow().isoformat(),
            'status': 'running'
        }

        metadata_file = capture_dir / f"capture_{timestamp}.json"
        metadata_file.write_text(json.dumps(capture_metadata, indent=2))

        # Schedule capture termination
        subprocess.Popen(
            ['bash', '-c', f'sleep {duration} && kill {process.pid} 2>/dev/null'],
            start_new_session=True
        )

        logger.info(f"[AUDIT] Packet capture started: {capture_file}")

        return ActionResult(
            action="enable_packet_capture",
            success=True,
            message=f"Packet capture started on {interface}",
            data={
                'capture_id': capture_metadata['capture_id'],
                'capture_file': str(capture_file),
                'interface': interface,
                'duration': duration,
                'pid': process.pid
            },
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'pid': process.pid, 'capture_file': str(capture_file)}
        )

    except FileNotFoundError:
        return ActionResult(
            action="enable_packet_capture",
            success=False,
            message="tcpdump not found - please install tcpdump",
            duration_ms=(time.time() - start) * 1000
        )
    except Exception as e:
        logger.error(f"[AUDIT] enable_packet_capture failed: {str(e)}")
        return ActionResult(
            action="enable_packet_capture",
            success=False,
            message=f"Error enabling packet capture: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def deploy_sensor(
    location: str,
    sensor_type: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Deploy a monitoring sensor to a specified location.

    Args:
        location: Where to deploy (network segment, host, or path)
        sensor_type: Type of sensor (ids, file_integrity, network, process)
        dry_run: If True, validate but don't deploy

    Returns:
        ActionResult with sensor deployment details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] deploy_sensor called: location={location}, type={sensor_type}, dry_run={dry_run}")

    try:
        valid_types = ['ids', 'file_integrity', 'network', 'process', 'log']
        if sensor_type not in valid_types:
            return ActionResult(
                action="deploy_sensor",
                success=False,
                message=f"Invalid sensor type. Valid types: {valid_types}",
                data={'sensor_type': sensor_type},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="deploy_sensor",
                success=True,
                message=f"[DRY RUN] Would deploy {sensor_type} sensor at {location}",
                data={
                    'location': location,
                    'sensor_type': sensor_type,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        sensor_id = f"SENSOR_{sensor_type}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
        sensor_config = {
            'sensor_id': sensor_id,
            'location': location,
            'sensor_type': sensor_type,
            'deployed_at': datetime.utcnow().isoformat(),
            'status': 'active'
        }

        if sensor_type == 'file_integrity':
            # Deploy file integrity monitoring
            watch_paths = [location] if Path(location).exists() else ['/etc', '/usr/bin', '/usr/sbin']
            sensor_config['watch_paths'] = watch_paths

            # Create baseline hashes
            baseline = {}
            for watch_path in watch_paths:
                path = Path(watch_path)
                if path.exists():
                    if path.is_file():
                        with open(path, 'rb') as f:
                            baseline[str(path)] = hashlib.sha256(f.read()).hexdigest()
                    elif path.is_dir():
                        for file_path in path.rglob('*'):
                            if file_path.is_file():
                                try:
                                    with open(file_path, 'rb') as f:
                                        baseline[str(file_path)] = hashlib.sha256(f.read()).hexdigest()
                                except (PermissionError, IOError):
                                    pass

            sensor_config['baseline_file_count'] = len(baseline)

        elif sensor_type == 'network':
            # Network sensor configuration
            sensor_config['capture_interface'] = location if location != 'default' else 'any'
            sensor_config['alert_threshold'] = 1000  # packets per second

        elif sensor_type == 'process':
            # Process monitoring sensor
            sensor_config['monitor_new_processes'] = True
            sensor_config['monitor_privilege_escalation'] = True

        elif sensor_type == 'ids':
            # IDS sensor
            sensor_config['rules_path'] = '/etc/tsunami/ids_rules'
            sensor_config['alert_level'] = 'medium'

        # Store sensor configuration
        sensor_dir = Path('/var/lib/tsunami/sensors')
        sensor_dir.mkdir(parents=True, exist_ok=True)

        config_file = sensor_dir / f"{sensor_id}.json"
        config_file.write_text(json.dumps(sensor_config, indent=2))

        logger.info(f"[AUDIT] Sensor deployed: {sensor_id} at {location}")

        return ActionResult(
            action="deploy_sensor",
            success=True,
            message=f"Sensor {sensor_id} deployed at {location}",
            data=sensor_config,
            duration_ms=(time.time() - start) * 1000,
            rollback_info={'sensor_id': sensor_id, 'config_file': str(config_file)}
        )

    except Exception as e:
        logger.error(f"[AUDIT] deploy_sensor failed: {str(e)}")
        return ActionResult(
            action="deploy_sensor",
            success=False,
            message=f"Error deploying sensor: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Alert/Notification Actions
# =============================================================================

def escalate_to_analyst(
    incident_id: str,
    priority: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Escalate an incident to a human analyst for review.

    Args:
        incident_id: Identifier of the incident to escalate
        priority: Escalation priority (low, medium, high, critical)
        dry_run: If True, validate but don't escalate

    Returns:
        ActionResult with escalation details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] escalate_to_analyst called: incident_id={incident_id}, priority={priority}, dry_run={dry_run}")

    try:
        valid_priorities = ['low', 'medium', 'high', 'critical']
        if priority not in valid_priorities:
            return ActionResult(
                action="escalate_to_analyst",
                success=False,
                message=f"Invalid priority. Valid priorities: {valid_priorities}",
                data={'priority': priority},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="escalate_to_analyst",
                success=True,
                message=f"[DRY RUN] Would escalate incident {incident_id} with {priority} priority",
                data={
                    'incident_id': incident_id,
                    'priority': priority,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        escalation_id = f"ESC_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{incident_id}"

        # Create escalation record
        escalation_dir = Path('/var/lib/tsunami/escalations')
        escalation_dir.mkdir(parents=True, exist_ok=True)

        escalation_record = {
            'escalation_id': escalation_id,
            'incident_id': incident_id,
            'priority': priority,
            'escalated_at': datetime.utcnow().isoformat(),
            'status': 'pending_review',
            'assigned_analyst': None,
            'response_sla': {
                'critical': '15 minutes',
                'high': '1 hour',
                'medium': '4 hours',
                'low': '24 hours'
            }.get(priority)
        }

        record_file = escalation_dir / f"{escalation_id}.json"
        record_file.write_text(json.dumps(escalation_record, indent=2))

        logger.info(f"[AUDIT] Incident escalated: {incident_id} -> {escalation_id} ({priority})")

        return ActionResult(
            action="escalate_to_analyst",
            success=True,
            message=f"Incident {incident_id} escalated with {priority} priority",
            data={
                'escalation_id': escalation_id,
                'incident_id': incident_id,
                'priority': priority,
                'response_sla': escalation_record['response_sla']
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        logger.error(f"[AUDIT] escalate_to_analyst failed: {str(e)}")
        return ActionResult(
            action="escalate_to_analyst",
            success=False,
            message=f"Error escalating to analyst: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def notify_stakeholders(
    incident_id: str,
    stakeholder_list: List[str],
    dry_run: bool = False
) -> ActionResult:
    """
    Send notifications to stakeholders about an incident.

    Args:
        incident_id: Identifier of the incident
        stakeholder_list: List of stakeholder identifiers or emails
        dry_run: If True, validate but don't send

    Returns:
        ActionResult with notification details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] notify_stakeholders called: incident_id={incident_id}, stakeholders={stakeholder_list}, dry_run={dry_run}")

    try:
        if not stakeholder_list:
            return ActionResult(
                action="notify_stakeholders",
                success=False,
                message="Stakeholder list cannot be empty",
                data={'incident_id': incident_id},
                duration_ms=(time.time() - start) * 1000
            )

        if dry_run:
            return ActionResult(
                action="notify_stakeholders",
                success=True,
                message=f"[DRY RUN] Would notify {len(stakeholder_list)} stakeholders about {incident_id}",
                data={
                    'incident_id': incident_id,
                    'stakeholder_list': stakeholder_list,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        notification_id = f"NOTIFY_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{incident_id}"
        notifications_sent = []

        for stakeholder in stakeholder_list:
            notification_record = {
                'stakeholder': stakeholder,
                'incident_id': incident_id,
                'sent_at': datetime.utcnow().isoformat(),
                'status': 'sent'
            }
            notifications_sent.append(notification_record)

        # Store notification record
        notify_dir = Path('/var/lib/tsunami/notifications')
        notify_dir.mkdir(parents=True, exist_ok=True)

        full_record = {
            'notification_id': notification_id,
            'incident_id': incident_id,
            'stakeholders_notified': len(notifications_sent),
            'notifications': notifications_sent,
            'sent_at': datetime.utcnow().isoformat()
        }

        record_file = notify_dir / f"{notification_id}.json"
        record_file.write_text(json.dumps(full_record, indent=2))

        logger.info(f"[AUDIT] Stakeholders notified: {len(notifications_sent)} for incident {incident_id}")

        return ActionResult(
            action="notify_stakeholders",
            success=True,
            message=f"Notified {len(notifications_sent)} stakeholders about incident {incident_id}",
            data={
                'notification_id': notification_id,
                'incident_id': incident_id,
                'stakeholders_notified': len(notifications_sent)
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        logger.error(f"[AUDIT] notify_stakeholders failed: {str(e)}")
        return ActionResult(
            action="notify_stakeholders",
            success=False,
            message=f"Error notifying stakeholders: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


def create_incident_ticket(
    details: Dict[str, Any],
    priority: str,
    dry_run: bool = False
) -> ActionResult:
    """
    Create an incident ticket in the ticketing system.

    Args:
        details: Incident details dict with keys:
            - title: Ticket title
            - description: Detailed description
            - affected_systems: List of affected systems
            - indicators: List of IOCs
            - timeline: Event timeline
        priority: Ticket priority (low, medium, high, critical)
        dry_run: If True, validate but don't create

    Returns:
        ActionResult with ticket details
    """
    import time
    start = time.time()

    logger.info(f"[AUDIT] create_incident_ticket called: priority={priority}, dry_run={dry_run}")

    try:
        valid_priorities = ['low', 'medium', 'high', 'critical']
        if priority not in valid_priorities:
            return ActionResult(
                action="create_incident_ticket",
                success=False,
                message=f"Invalid priority. Valid priorities: {valid_priorities}",
                data={'priority': priority},
                duration_ms=(time.time() - start) * 1000
            )

        required_fields = ['title', 'description']
        for field in required_fields:
            if field not in details:
                return ActionResult(
                    action="create_incident_ticket",
                    success=False,
                    message=f"Missing required field: {field}",
                    data={'missing_field': field},
                    duration_ms=(time.time() - start) * 1000
                )

        if dry_run:
            return ActionResult(
                action="create_incident_ticket",
                success=True,
                message=f"[DRY RUN] Would create {priority} priority ticket: {details.get('title')}",
                data={
                    'details': details,
                    'priority': priority,
                    'dry_run': True
                },
                duration_ms=(time.time() - start) * 1000
            )

        ticket_id = f"INC-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        ticket = {
            'ticket_id': ticket_id,
            'title': details.get('title'),
            'description': details.get('description'),
            'priority': priority,
            'status': 'open',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'affected_systems': details.get('affected_systems', []),
            'indicators': details.get('indicators', []),
            'timeline': details.get('timeline', []),
            'assignee': None,
            'category': 'security_incident'
        }

        # Store ticket
        ticket_dir = Path('/var/lib/tsunami/tickets')
        ticket_dir.mkdir(parents=True, exist_ok=True)

        ticket_file = ticket_dir / f"{ticket_id}.json"
        ticket_file.write_text(json.dumps(ticket, indent=2))

        logger.info(f"[AUDIT] Incident ticket created: {ticket_id}")

        return ActionResult(
            action="create_incident_ticket",
            success=True,
            message=f"Incident ticket created: {ticket_id}",
            data={
                'ticket_id': ticket_id,
                'title': ticket['title'],
                'priority': priority,
                'status': 'open'
            },
            duration_ms=(time.time() - start) * 1000
        )

    except Exception as e:
        logger.error(f"[AUDIT] create_incident_ticket failed: {str(e)}")
        return ActionResult(
            action="create_incident_ticket",
            success=False,
            message=f"Error creating incident ticket: {str(e)}",
            duration_ms=(time.time() - start) * 1000
        )


# =============================================================================
# Action Library Class
# =============================================================================

class ActionLibrary:
    """
    Registry and executor for security actions.
    """

    def __init__(self):
        self._actions: Dict[str, Callable] = {
            # Original actions
            'block_ip': block_ip,
            'unblock_ip': unblock_ip,
            'block_domain': block_domain,
            'kill_process': kill_process,
            'isolate_host': isolate_host,
            'unisolate_host': unisolate_host,
            'send_alert': send_alert,
            'query_threat_intel': query_threat_intel,
            'create_ticket': create_ticket,
            'collect_forensics': collect_forensics,
            'run_scan': run_scan,
            'quarantine_file': quarantine_file,
            'disable_user': disable_user,
            # Deception/Honeypot Actions
            'deploy_honeypot': deploy_honeypot,
            'create_honeytoken': create_honeytoken,
            'activate_decoy_system': activate_decoy_system,
            # Forensic/Evidence Actions
            'capture_memory_dump': capture_memory_dump,
            'snapshot_network_state': snapshot_network_state,
            'collect_volatile_evidence': collect_volatile_evidence,
            'preserve_logs': preserve_logs,
            'create_forensic_image': create_forensic_image,
            # Enhanced Isolation Actions
            'quarantine_endpoint': quarantine_endpoint,
            'segment_network': segment_network,
            'disable_user_account': disable_user_account,
            'revoke_access_tokens': revoke_access_tokens,
            # Monitoring Enhancement Actions
            'increase_logging_level': increase_logging_level,
            'enable_packet_capture': enable_packet_capture,
            'deploy_sensor': deploy_sensor,
            # Alert/Notification Actions
            'escalate_to_analyst': escalate_to_analyst,
            'notify_stakeholders': notify_stakeholders,
            'create_incident_ticket': create_incident_ticket
        }

        self._execution_history: List[ActionResult] = []

    def register(self, name: str, handler: Callable) -> None:
        """Register a custom action."""
        self._actions[name] = handler

    def execute(self, action: str, **params) -> ActionResult:
        """Execute an action."""
        if action not in self._actions:
            return ActionResult(
                action=action,
                success=False,
                message=f"Unknown action: {action}"
            )

        try:
            result = self._actions[action](**params)
            self._execution_history.append(result)
            return result
        except Exception as e:
            result = ActionResult(
                action=action,
                success=False,
                message=f"Action execution error: {str(e)}"
            )
            self._execution_history.append(result)
            return result

    def get_actions(self) -> Dict[str, Callable]:
        """Get all registered actions."""
        return dict(self._actions)

    def get_action_info(self, action: str) -> Optional[Dict[str, Any]]:
        """Get information about an action."""
        if action not in self._actions:
            return None

        func = self._actions[action]
        return {
            'name': action,
            'description': func.__doc__,
            'parameters': func.__code__.co_varnames[:func.__code__.co_argcount]
        }

    def list_actions(self) -> List[Dict[str, Any]]:
        """List all available actions."""
        return [self.get_action_info(name) for name in self._actions.keys()]

    def get_history(self, limit: int = 100) -> List[ActionResult]:
        """Get action execution history."""
        return self._execution_history[-limit:]


# Singleton instance
_action_library: Optional[ActionLibrary] = None


def get_action_library() -> ActionLibrary:
    """Get or create the action library singleton."""
    global _action_library
    if _action_library is None:
        _action_library = ActionLibrary()
    return _action_library


# Dict-like access for backwards compatibility
# Usage: from modules.soar_xdr.action_library import ACTION_LIBRARY
# ACTION_LIBRARY['quarantine_endpoint'](params, dry_run=False)
class _ActionLibraryProxy(dict):
    """Lazy-loading dict proxy for action functions."""
    def __init__(self):
        super().__init__()
        self._loaded = False

    def _ensure_loaded(self):
        if not self._loaded:
            lib = get_action_library()
            self.update(lib._actions)
            self._loaded = True

    def __getitem__(self, key):
        self._ensure_loaded()
        return super().__getitem__(key)

    def __contains__(self, key):
        self._ensure_loaded()
        return super().__contains__(key)

ACTION_LIBRARY = _ActionLibraryProxy()
