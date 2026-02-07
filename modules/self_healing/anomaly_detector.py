#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI ANOMALY DETECTOR v5.0
    Network Anomaly Detection Engine
================================================================================

    Features:
    - Unusual port activity detection
    - Suspicious outbound connection detection
    - Traffic spike detection
    - Known bad IP detection (threat intelligence)
    - Protocol anomaly detection
    - Behavioral baseline analysis
    - Real-time alerting

================================================================================
"""

import os
import re
import time
import socket
import logging
import threading
import ipaddress
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Callable
from collections import defaultdict
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of network anomalies"""
    UNUSUAL_PORT = "unusual_port"
    SUSPICIOUS_OUTBOUND = "suspicious_outbound"
    TRAFFIC_SPIKE = "traffic_spike"
    KNOWN_BAD_IP = "known_bad_ip"
    PORT_SCAN = "port_scan"
    PROTOCOL_ANOMALY = "protocol_anomaly"
    EXCESSIVE_CONNECTIONS = "excessive_connections"
    DNS_TUNNEL = "dns_tunnel"
    DATA_EXFILTRATION = "data_exfiltration"
    CRYPTO_MINING = "crypto_mining"
    UNAUTHORIZED_SERVICE = "unauthorized_service"
    BRUTE_FORCE = "brute_force"


class Severity(Enum):
    """Anomaly severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Anomaly:
    """Detected network anomaly"""
    id: str
    type: AnomalyType
    severity: Severity
    title: str
    description: str
    source_ip: Optional[str]
    source_port: Optional[int]
    dest_ip: Optional[str]
    dest_port: Optional[int]
    process_id: Optional[int]
    process_name: Optional[str]
    evidence: Dict = field(default_factory=dict)
    recommended_action: str = ""
    is_active: bool = True
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())
    resolved_at: Optional[str] = None

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['type'] = self.type.value
        result['severity'] = self.severity.value
        return result


@dataclass
class BaselineStats:
    """Baseline statistics for anomaly detection"""
    avg_connections: float
    std_connections: float
    avg_bandwidth_recv: float
    std_bandwidth_recv: float
    avg_bandwidth_sent: float
    std_bandwidth_sent: float
    common_ports: Set[int]
    common_destinations: Set[str]
    normal_processes: Set[str]
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())


class ThreatIntelligence:
    """Threat intelligence data for known bad IPs and patterns"""

    # Known malicious IP ranges (examples - in production, load from threat feeds)
    KNOWN_BAD_RANGES = [
        # Example known bad ranges (NOT real threat intel - for demo)
        '185.220.101.0/24',  # Tor exit nodes (example)
        '192.42.116.0/24',   # Tor exit nodes (example)
    ]

    # Suspicious destination ports
    SUSPICIOUS_PORTS = {
        4444: 'Metasploit default',
        5555: 'Android ADB',
        6666: 'IRC (often C2)',
        6667: 'IRC (often C2)',
        8080: 'Common proxy/malware',
        1337: 'Common backdoor',
        31337: 'Elite/Back Orifice',
        12345: 'NetBus',
        27374: 'SubSeven',
        65534: 'Common backdoor',
    }

    # Known crypto mining pool ports
    MINING_PORTS = {
        3333, 3334, 3335, 3336,  # Common Stratum ports
        4444, 5555, 7777, 8888,  # Alternative mining ports
        9999, 14444, 14433,
    }

    # Suspicious process patterns (regex)
    SUSPICIOUS_PROCESSES = [
        r'xmrig',  # Crypto miner
        r'minerd',  # Crypto miner
        r'cpuminer',  # Crypto miner
        r'nc\.exe',  # Netcat
        r'ncat',  # Netcat
        r'socat',  # Socket proxy
        r'reverse.*shell',
        r'powershell.*hidden',
        r'cmd\.exe.*encoded',
    ]

    def __init__(self):
        self._bad_networks = [ipaddress.ip_network(r, strict=False) for r in self.KNOWN_BAD_RANGES]
        self._custom_bad_ips: Set[str] = set()
        self._whitelist_ips: Set[str] = set()

    def is_bad_ip(self, ip: str) -> Tuple[bool, Optional[str]]:
        """Check if IP is known bad"""
        if ip in self._whitelist_ips:
            return False, None

        if ip in self._custom_bad_ips:
            return True, "Custom blacklist"

        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self._bad_networks:
                if ip_obj in network:
                    return True, f"Known bad range: {network}"
        except ValueError:
            pass

        return False, None

    def is_suspicious_port(self, port: int) -> Tuple[bool, Optional[str]]:
        """Check if port is suspicious"""
        if port in self.SUSPICIOUS_PORTS:
            return True, self.SUSPICIOUS_PORTS[port]
        if port in self.MINING_PORTS:
            return True, "Crypto mining pool port"
        return False, None

    def is_suspicious_process(self, name: str) -> bool:
        """Check if process name matches suspicious patterns"""
        for pattern in self.SUSPICIOUS_PROCESSES:
            if re.search(pattern, name, re.IGNORECASE):
                return True
        return False

    def add_bad_ip(self, ip: str):
        """Add IP to custom blacklist"""
        self._custom_bad_ips.add(ip)

    def add_whitelist_ip(self, ip: str):
        """Add IP to whitelist"""
        self._whitelist_ips.add(ip)


class AnomalyDetector:
    """
    Network anomaly detection engine.
    Uses baseline analysis and threat intelligence to detect anomalies.
    """

    def __init__(self, network_monitor=None, baseline_hours: int = 24):
        """
        Initialize anomaly detector.

        Args:
            network_monitor: NetworkMonitor instance (optional)
            baseline_hours: Hours of data to use for baseline calculation
        """
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil is required for anomaly detection")

        self.network_monitor = network_monitor
        self.baseline_hours = baseline_hours

        # Threat intelligence
        self.threat_intel = ThreatIntelligence()

        # Detection state
        self._baseline: Optional[BaselineStats] = None
        self._anomalies: List[Anomaly] = []
        self._active_anomalies: Dict[str, Anomaly] = {}
        self._lock = threading.RLock()

        # Detection thresholds
        self.thresholds = {
            'connection_spike_std_multiplier': 3.0,
            'bandwidth_spike_std_multiplier': 5.0,
            'port_scan_threshold': 10,  # Connections to unique ports in 60s
            'brute_force_threshold': 10,  # Failed connections in 60s
            'excessive_connections_per_process': 100,
            'max_outbound_per_minute': 50,
        }

        # Tracking state
        self._connection_history: Dict[str, List[Dict]] = defaultdict(list)
        self._port_access_history: Dict[str, Set[int]] = defaultdict(set)
        self._alert_callbacks: List[Callable[[Anomaly], None]] = []

        # Counter for anomaly IDs
        self._anomaly_counter = 0

        logger.info("[ANOMALY_DETECTOR] Initialized")

    def _generate_anomaly_id(self) -> str:
        """Generate unique anomaly ID"""
        self._anomaly_counter += 1
        return f"ANM-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._anomaly_counter:04d}"

    def register_alert_callback(self, callback: Callable[[Anomaly], None]):
        """Register callback for anomaly alerts"""
        self._alert_callbacks.append(callback)

    def _emit_alert(self, anomaly: Anomaly):
        """Emit alert to all registered callbacks"""
        for callback in self._alert_callbacks:
            try:
                callback(anomaly)
            except Exception as e:
                logger.error("[ANOMALY_DETECTOR] Alert callback error: %s", e)

    def _record_anomaly(self, anomaly: Anomaly):
        """Record a detected anomaly"""
        with self._lock:
            self._anomalies.append(anomaly)
            self._active_anomalies[anomaly.id] = anomaly

            # Trim history
            if len(self._anomalies) > 10000:
                self._anomalies = self._anomalies[-10000:]

        logger.warning("[ANOMALY_DETECTOR] %s: %s (Severity: %s)",
                      anomaly.type.value, anomaly.title, anomaly.severity.value)

        self._emit_alert(anomaly)

    def detect_unusual_ports(self, connections: List[Dict]) -> List[Anomaly]:
        """Detect connections to unusual/suspicious ports"""
        anomalies = []

        for conn in connections:
            remote_port = conn.get('remote_port', 0)
            if remote_port == 0:
                continue

            is_suspicious, reason = self.threat_intel.is_suspicious_port(remote_port)
            if is_suspicious:
                anomaly = Anomaly(
                    id=self._generate_anomaly_id(),
                    type=AnomalyType.UNUSUAL_PORT,
                    severity=Severity.HIGH,
                    title=f"Connection to suspicious port {remote_port}",
                    description=f"Process connected to port {remote_port}: {reason}",
                    source_ip=conn.get('local_address'),
                    source_port=conn.get('local_port'),
                    dest_ip=conn.get('remote_address'),
                    dest_port=remote_port,
                    process_id=conn.get('pid'),
                    process_name=conn.get('process_name'),
                    evidence={'reason': reason, 'connection': conn},
                    recommended_action=f"Investigate process and block port {remote_port}"
                )
                anomalies.append(anomaly)
                self._record_anomaly(anomaly)

        return anomalies

    def detect_suspicious_outbound(self, connections: List[Dict]) -> List[Anomaly]:
        """Detect suspicious outbound connections"""
        anomalies = []

        for conn in connections:
            remote_ip = conn.get('remote_address', '')
            if not remote_ip or conn.get('state') != 'ESTABLISHED':
                continue

            # Check against threat intelligence
            is_bad, reason = self.threat_intel.is_bad_ip(remote_ip)
            if is_bad:
                anomaly = Anomaly(
                    id=self._generate_anomaly_id(),
                    type=AnomalyType.KNOWN_BAD_IP,
                    severity=Severity.CRITICAL,
                    title=f"Connection to known malicious IP: {remote_ip}",
                    description=f"Outbound connection to known bad IP. {reason}",
                    source_ip=conn.get('local_address'),
                    source_port=conn.get('local_port'),
                    dest_ip=remote_ip,
                    dest_port=conn.get('remote_port'),
                    process_id=conn.get('pid'),
                    process_name=conn.get('process_name'),
                    evidence={'reason': reason, 'connection': conn},
                    recommended_action=f"Block IP {remote_ip} and investigate process"
                )
                anomalies.append(anomaly)
                self._record_anomaly(anomaly)

        return anomalies

    def detect_port_scan(self, connections: List[Dict], window_seconds: int = 60) -> List[Anomaly]:
        """Detect port scanning activity"""
        anomalies = []
        now = datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)

        # Group by source IP
        by_source: Dict[str, Set[Tuple[str, int]]] = defaultdict(set)

        for conn in connections:
            remote_ip = conn.get('remote_address', '')
            remote_port = conn.get('remote_port', 0)
            local_ip = conn.get('local_address', '')

            if remote_ip and remote_port:
                by_source[local_ip].add((remote_ip, remote_port))

        # Check for port scan patterns
        for source_ip, destinations in by_source.items():
            # Group by destination IP
            ports_per_dest: Dict[str, Set[int]] = defaultdict(set)
            for dest_ip, dest_port in destinations:
                ports_per_dest[dest_ip].add(dest_port)

            for dest_ip, ports in ports_per_dest.items():
                if len(ports) >= self.thresholds['port_scan_threshold']:
                    anomaly = Anomaly(
                        id=self._generate_anomaly_id(),
                        type=AnomalyType.PORT_SCAN,
                        severity=Severity.HIGH,
                        title=f"Port scan detected from {source_ip}",
                        description=f"Host scanning {len(ports)} ports on {dest_ip}",
                        source_ip=source_ip,
                        source_port=None,
                        dest_ip=dest_ip,
                        dest_port=None,
                        process_id=None,
                        process_name=None,
                        evidence={'ports_scanned': list(ports), 'count': len(ports)},
                        recommended_action=f"Block source IP {source_ip}"
                    )
                    anomalies.append(anomaly)
                    self._record_anomaly(anomaly)

        return anomalies

    def detect_excessive_connections(self, connections: List[Dict]) -> List[Anomaly]:
        """Detect processes with excessive network connections"""
        anomalies = []

        # Count connections per process
        by_process: Dict[Tuple[int, str], int] = defaultdict(int)
        for conn in connections:
            pid = conn.get('pid')
            name = conn.get('process_name', 'unknown')
            if pid:
                by_process[(pid, name)] += 1

        threshold = self.thresholds['excessive_connections_per_process']

        for (pid, name), count in by_process.items():
            if count >= threshold:
                anomaly = Anomaly(
                    id=self._generate_anomaly_id(),
                    type=AnomalyType.EXCESSIVE_CONNECTIONS,
                    severity=Severity.MEDIUM,
                    title=f"Process {name} has {count} connections",
                    description=f"Process {name} (PID {pid}) has excessive connections",
                    source_ip=None,
                    source_port=None,
                    dest_ip=None,
                    dest_port=None,
                    process_id=pid,
                    process_name=name,
                    evidence={'connection_count': count, 'threshold': threshold},
                    recommended_action=f"Investigate process {name} (PID {pid})"
                )
                anomalies.append(anomaly)
                self._record_anomaly(anomaly)

        return anomalies

    def detect_crypto_mining(self, connections: List[Dict]) -> List[Anomaly]:
        """Detect potential crypto mining activity"""
        anomalies = []

        for conn in connections:
            remote_port = conn.get('remote_port', 0)
            process_name = conn.get('process_name', '')

            # Check for mining pool ports
            if remote_port in ThreatIntelligence.MINING_PORTS:
                anomaly = Anomaly(
                    id=self._generate_anomaly_id(),
                    type=AnomalyType.CRYPTO_MINING,
                    severity=Severity.HIGH,
                    title="Potential crypto mining detected",
                    description=f"Connection to mining pool port {remote_port}",
                    source_ip=conn.get('local_address'),
                    source_port=conn.get('local_port'),
                    dest_ip=conn.get('remote_address'),
                    dest_port=remote_port,
                    process_id=conn.get('pid'),
                    process_name=process_name,
                    evidence={'mining_port': remote_port, 'connection': conn},
                    recommended_action="Kill process and investigate"
                )
                anomalies.append(anomaly)
                self._record_anomaly(anomaly)
                continue

            # Check for mining process names
            if process_name and self.threat_intel.is_suspicious_process(process_name):
                anomaly = Anomaly(
                    id=self._generate_anomaly_id(),
                    type=AnomalyType.CRYPTO_MINING,
                    severity=Severity.CRITICAL,
                    title=f"Suspicious mining process: {process_name}",
                    description=f"Process name matches known crypto miner pattern",
                    source_ip=conn.get('local_address'),
                    source_port=conn.get('local_port'),
                    dest_ip=conn.get('remote_address'),
                    dest_port=remote_port,
                    process_id=conn.get('pid'),
                    process_name=process_name,
                    evidence={'process': process_name, 'connection': conn},
                    recommended_action="Kill process immediately"
                )
                anomalies.append(anomaly)
                self._record_anomaly(anomaly)

        return anomalies

    def detect_traffic_spike(self, current_bandwidth: Dict,
                            baseline: Optional[BaselineStats] = None) -> List[Anomaly]:
        """Detect abnormal traffic spikes"""
        anomalies = []

        if not baseline:
            baseline = self._baseline

        if not baseline:
            return anomalies  # No baseline yet

        multiplier = self.thresholds['bandwidth_spike_std_multiplier']

        for interface, bw in current_bandwidth.items():
            # Check receive spike
            if hasattr(bw, 'bytes_recv_per_sec'):
                recv_threshold = baseline.avg_bandwidth_recv + (baseline.std_bandwidth_recv * multiplier)
                if bw.bytes_recv_per_sec > recv_threshold and recv_threshold > 0:
                    anomaly = Anomaly(
                        id=self._generate_anomaly_id(),
                        type=AnomalyType.TRAFFIC_SPIKE,
                        severity=Severity.MEDIUM,
                        title=f"Inbound traffic spike on {interface}",
                        description=f"Receiving {bw.bytes_recv_per_sec/1024:.1f} KB/s (baseline: {baseline.avg_bandwidth_recv/1024:.1f} KB/s)",
                        source_ip=None,
                        source_port=None,
                        dest_ip=None,
                        dest_port=None,
                        process_id=None,
                        process_name=None,
                        evidence={
                            'interface': interface,
                            'current_bps': bw.bytes_recv_per_sec,
                            'baseline_avg': baseline.avg_bandwidth_recv,
                            'threshold': recv_threshold
                        },
                        recommended_action="Investigate traffic source"
                    )
                    anomalies.append(anomaly)
                    self._record_anomaly(anomaly)

            # Check send spike
            if hasattr(bw, 'bytes_sent_per_sec'):
                sent_threshold = baseline.avg_bandwidth_sent + (baseline.std_bandwidth_sent * multiplier)
                if bw.bytes_sent_per_sec > sent_threshold and sent_threshold > 0:
                    anomaly = Anomaly(
                        id=self._generate_anomaly_id(),
                        type=AnomalyType.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        title=f"Outbound traffic spike on {interface}",
                        description=f"Sending {bw.bytes_sent_per_sec/1024:.1f} KB/s (baseline: {baseline.avg_bandwidth_sent/1024:.1f} KB/s)",
                        source_ip=None,
                        source_port=None,
                        dest_ip=None,
                        dest_port=None,
                        process_id=None,
                        process_name=None,
                        evidence={
                            'interface': interface,
                            'current_bps': bw.bytes_sent_per_sec,
                            'baseline_avg': baseline.avg_bandwidth_sent,
                            'threshold': sent_threshold
                        },
                        recommended_action="Investigate for data exfiltration"
                    )
                    anomalies.append(anomaly)
                    self._record_anomaly(anomaly)

        return anomalies

    def run_detection(self, connections: List[Dict] = None,
                     bandwidth: Dict = None) -> List[Anomaly]:
        """
        Run all anomaly detection checks.

        Args:
            connections: List of connection dicts (or fetch from monitor)
            bandwidth: Bandwidth data dict (or fetch from monitor)

        Returns:
            List of detected anomalies
        """
        all_anomalies = []

        # Get data if not provided
        if connections is None and self.network_monitor:
            raw_connections = self.network_monitor.get_all_connections()
            connections = [c.to_dict() for c in raw_connections]
        elif connections is None:
            connections = self._get_connections_psutil()

        if bandwidth is None and self.network_monitor:
            bandwidth = self.network_monitor.get_bandwidth_usage()

        # Run detection checks
        all_anomalies.extend(self.detect_unusual_ports(connections))
        all_anomalies.extend(self.detect_suspicious_outbound(connections))
        all_anomalies.extend(self.detect_port_scan(connections))
        all_anomalies.extend(self.detect_excessive_connections(connections))
        all_anomalies.extend(self.detect_crypto_mining(connections))

        if bandwidth:
            all_anomalies.extend(self.detect_traffic_spike(bandwidth))

        return all_anomalies

    def _get_connections_psutil(self) -> List[Dict]:
        """Get connections directly via psutil"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                process_name = None
                if conn.pid:
                    try:
                        process_name = psutil.Process(conn.pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                connections.append({
                    'local_address': conn.laddr.ip if conn.laddr else '',
                    'local_port': conn.laddr.port if conn.laddr else 0,
                    'remote_address': conn.raddr.ip if conn.raddr else '',
                    'remote_port': conn.raddr.port if conn.raddr else 0,
                    'state': conn.status,
                    'pid': conn.pid,
                    'process_name': process_name
                })
        except psutil.AccessDenied:
            logger.warning("[ANOMALY_DETECTOR] Access denied for connection info")
        except Exception as e:
            logger.error("[ANOMALY_DETECTOR] Error getting connections: %s", e)

        return connections

    def resolve_anomaly(self, anomaly_id: str, resolution_note: str = ""):
        """Mark an anomaly as resolved"""
        with self._lock:
            if anomaly_id in self._active_anomalies:
                anomaly = self._active_anomalies[anomaly_id]
                anomaly.is_active = False
                anomaly.resolved_at = datetime.now().isoformat()
                anomaly.evidence['resolution_note'] = resolution_note
                del self._active_anomalies[anomaly_id]
                logger.info("[ANOMALY_DETECTOR] Resolved anomaly %s", anomaly_id)

    def get_active_anomalies(self) -> List[Anomaly]:
        """Get all active (unresolved) anomalies"""
        with self._lock:
            return list(self._active_anomalies.values())

    def get_anomaly_history(self, hours: int = 24,
                           anomaly_type: AnomalyType = None,
                           severity: Severity = None) -> List[Anomaly]:
        """Get anomaly history with optional filters"""
        cutoff = datetime.now() - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()

        with self._lock:
            results = []
            for anomaly in self._anomalies:
                if anomaly.detected_at < cutoff_str:
                    continue
                if anomaly_type and anomaly.type != anomaly_type:
                    continue
                if severity and anomaly.severity != severity:
                    continue
                results.append(anomaly)
            return results

    def get_summary(self) -> Dict:
        """Get anomaly detection summary"""
        with self._lock:
            active = list(self._active_anomalies.values())

            by_type = defaultdict(int)
            by_severity = defaultdict(int)

            for anomaly in active:
                by_type[anomaly.type.value] += 1
                by_severity[anomaly.severity.value] += 1

            return {
                'timestamp': datetime.now().isoformat(),
                'active_anomalies': len(active),
                'total_detected': len(self._anomalies),
                'by_type': dict(by_type),
                'by_severity': dict(by_severity),
                'recent_anomalies': [a.to_dict() for a in active[:10]]
            }


# Singleton instance
_anomaly_detector: Optional[AnomalyDetector] = None

def get_anomaly_detector(network_monitor=None) -> AnomalyDetector:
    """Get or create anomaly detector singleton"""
    global _anomaly_detector
    if _anomaly_detector is None:
        _anomaly_detector = AnomalyDetector(network_monitor=network_monitor)
    return _anomaly_detector
