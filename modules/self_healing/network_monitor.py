#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI NETWORK MONITOR v5.0
    Real-time Network Interface and Connection Monitoring
================================================================================

    Features:
    - Monitor all network interfaces (psutil)
    - Track active connections with process info
    - Bandwidth usage monitoring
    - Connection state tracking
    - Process network activity correlation
    - Historical data collection

================================================================================
"""

import os
import time
import socket
import logging
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict
from enum import Enum

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """TCP connection states"""
    ESTABLISHED = "ESTABLISHED"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    TIME_WAIT = "TIME_WAIT"
    CLOSE = "CLOSE"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    LISTEN = "LISTEN"
    CLOSING = "CLOSING"
    NONE = "NONE"


@dataclass
class ConnectionInfo:
    """Detailed connection information"""
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    pid: Optional[int]
    process_name: Optional[str]
    family: str  # IPv4/IPv6
    protocol: str  # TCP/UDP
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class InterfaceStats:
    """Network interface statistics"""
    name: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    errors_in: int
    errors_out: int
    drop_in: int
    drop_out: int
    is_up: bool
    speed_mbps: int
    mtu: int
    addresses: List[Dict]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class BandwidthSample:
    """Bandwidth measurement sample"""
    interface: str
    bytes_sent_per_sec: float
    bytes_recv_per_sec: float
    packets_sent_per_sec: float
    packets_recv_per_sec: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ProcessNetworkActivity:
    """Network activity for a specific process"""
    pid: int
    name: str
    connections: List[ConnectionInfo]
    bytes_sent: int
    bytes_recv: int
    open_files: int
    cpu_percent: float
    memory_percent: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return {
            'pid': self.pid,
            'name': self.name,
            'connections': [c.to_dict() for c in self.connections],
            'bytes_sent': self.bytes_sent,
            'bytes_recv': self.bytes_recv,
            'open_files': self.open_files,
            'cpu_percent': self.cpu_percent,
            'memory_percent': self.memory_percent,
            'timestamp': self.timestamp
        }


class NetworkMonitor:
    """
    Real-time network monitoring system using psutil.
    Tracks interfaces, connections, bandwidth, and process activity.
    """

    def __init__(self, sample_interval: float = 1.0, history_size: int = 3600):
        """
        Initialize network monitor.

        Args:
            sample_interval: Seconds between samples (default 1.0)
            history_size: Number of samples to keep in history (default 3600 = 1 hour)
        """
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil is required for network monitoring. Install with: pip install psutil")

        self.sample_interval = sample_interval
        self.history_size = history_size

        # Data stores
        self._interface_stats: Dict[str, InterfaceStats] = {}
        self._connections: List[ConnectionInfo] = []
        self._bandwidth_history: Dict[str, List[BandwidthSample]] = defaultdict(list)
        self._connection_history: List[Dict] = []
        self._process_activity: Dict[int, ProcessNetworkActivity] = {}

        # Previous counters for bandwidth calculation
        self._prev_counters: Dict[str, Dict] = {}
        self._prev_time: float = 0

        # Monitoring state
        self._running = False
        self._monitor_thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Known local IPs
        self._local_ips: Set[str] = set()
        self._update_local_ips()

        logger.info("[NETWORK_MONITOR] Initialized with interval=%.1fs, history=%d samples",
                   sample_interval, history_size)

    def _update_local_ips(self):
        """Update set of local IP addresses"""
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        self._local_ips.add(addr.address)
                    elif addr.family == socket.AF_INET6:
                        self._local_ips.add(addr.address)
            self._local_ips.add('127.0.0.1')
            self._local_ips.add('::1')
        except Exception as e:
            logger.error("[NETWORK_MONITOR] Failed to get local IPs: %s", e)

    def get_all_interfaces(self) -> List[InterfaceStats]:
        """Get statistics for all network interfaces"""
        interfaces = []

        try:
            # Get interface counters
            counters = psutil.net_io_counters(pernic=True)
            # Get interface addresses
            addrs = psutil.net_if_addrs()
            # Get interface status
            stats = psutil.net_if_stats()

            for name, counter in counters.items():
                iface_addrs = []
                if name in addrs:
                    for addr in addrs[name]:
                        iface_addrs.append({
                            'family': 'IPv4' if addr.family == socket.AF_INET else
                                     'IPv6' if addr.family == socket.AF_INET6 else 'MAC',
                            'address': addr.address,
                            'netmask': addr.netmask,
                            'broadcast': addr.broadcast
                        })

                iface_stat = stats.get(name)

                interface = InterfaceStats(
                    name=name,
                    bytes_sent=counter.bytes_sent,
                    bytes_recv=counter.bytes_recv,
                    packets_sent=counter.packets_sent,
                    packets_recv=counter.packets_recv,
                    errors_in=counter.errin,
                    errors_out=counter.errout,
                    drop_in=counter.dropin,
                    drop_out=counter.dropout,
                    is_up=iface_stat.isup if iface_stat else False,
                    speed_mbps=iface_stat.speed if iface_stat else 0,
                    mtu=iface_stat.mtu if iface_stat else 0,
                    addresses=iface_addrs
                )
                interfaces.append(interface)

                with self._lock:
                    self._interface_stats[name] = interface

        except Exception as e:
            logger.error("[NETWORK_MONITOR] Failed to get interface stats: %s", e)

        return interfaces

    def get_all_connections(self, include_listen: bool = True) -> List[ConnectionInfo]:
        """
        Get all active network connections with process info.

        Args:
            include_listen: Include LISTEN state connections
        """
        connections = []

        try:
            for conn in psutil.net_connections(kind='all'):
                # Skip if no listen and state is LISTEN
                if not include_listen and conn.status == 'LISTEN':
                    continue

                # Get process info
                process_name = None
                if conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_name = proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                # Parse addresses (handle both tuples and addr objects)
                if conn.laddr:
                    if hasattr(conn.laddr, 'ip'):
                        local_addr = conn.laddr.ip
                        local_port = conn.laddr.port
                    elif isinstance(conn.laddr, tuple) and len(conn.laddr) >= 2:
                        local_addr = conn.laddr[0]
                        local_port = conn.laddr[1]
                    else:
                        local_addr = str(conn.laddr)
                        local_port = 0
                else:
                    local_addr = ''
                    local_port = 0

                if conn.raddr:
                    if hasattr(conn.raddr, 'ip'):
                        remote_addr = conn.raddr.ip
                        remote_port = conn.raddr.port
                    elif isinstance(conn.raddr, tuple) and len(conn.raddr) >= 2:
                        remote_addr = conn.raddr[0]
                        remote_port = conn.raddr[1]
                    else:
                        remote_addr = str(conn.raddr)
                        remote_port = 0
                else:
                    remote_addr = ''
                    remote_port = 0

                # Determine protocol and family
                if conn.type == socket.SOCK_STREAM:
                    protocol = 'TCP'
                elif conn.type == socket.SOCK_DGRAM:
                    protocol = 'UDP'
                else:
                    protocol = 'OTHER'

                family = 'IPv4' if conn.family == socket.AF_INET else 'IPv6'

                connection = ConnectionInfo(
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    state=conn.status,
                    pid=conn.pid,
                    process_name=process_name,
                    family=family,
                    protocol=protocol
                )
                connections.append(connection)

            with self._lock:
                self._connections = connections

        except psutil.AccessDenied:
            logger.warning("[NETWORK_MONITOR] Access denied for connection info (try running as root)")
        except Exception as e:
            logger.error("[NETWORK_MONITOR] Failed to get connections: %s", e)

        return connections

    def get_connections_by_state(self, state: str) -> List[ConnectionInfo]:
        """Get connections filtered by state"""
        with self._lock:
            return [c for c in self._connections if c.state == state]

    def get_connections_by_port(self, port: int, local: bool = True) -> List[ConnectionInfo]:
        """Get connections filtered by port"""
        with self._lock:
            if local:
                return [c for c in self._connections if c.local_port == port]
            else:
                return [c for c in self._connections if c.remote_port == port]

    def get_connections_by_process(self, pid: int = None, name: str = None) -> List[ConnectionInfo]:
        """Get connections filtered by process PID or name"""
        with self._lock:
            results = []
            for conn in self._connections:
                if pid and conn.pid == pid:
                    results.append(conn)
                elif name and conn.process_name and name.lower() in conn.process_name.lower():
                    results.append(conn)
            return results

    def get_outbound_connections(self) -> List[ConnectionInfo]:
        """Get all outbound (non-local remote) connections"""
        with self._lock:
            return [c for c in self._connections
                   if c.remote_address and c.remote_address not in self._local_ips
                   and c.state == 'ESTABLISHED']

    def get_bandwidth_usage(self) -> Dict[str, BandwidthSample]:
        """Calculate current bandwidth usage per interface"""
        bandwidth = {}
        current_time = time.time()

        try:
            counters = psutil.net_io_counters(pernic=True)

            for name, counter in counters.items():
                if name in self._prev_counters and self._prev_time > 0:
                    time_diff = current_time - self._prev_time
                    if time_diff > 0:
                        prev = self._prev_counters[name]

                        sample = BandwidthSample(
                            interface=name,
                            bytes_sent_per_sec=(counter.bytes_sent - prev['bytes_sent']) / time_diff,
                            bytes_recv_per_sec=(counter.bytes_recv - prev['bytes_recv']) / time_diff,
                            packets_sent_per_sec=(counter.packets_sent - prev['packets_sent']) / time_diff,
                            packets_recv_per_sec=(counter.packets_recv - prev['packets_recv']) / time_diff
                        )
                        bandwidth[name] = sample

                        # Store in history
                        with self._lock:
                            self._bandwidth_history[name].append(sample)
                            # Trim history
                            if len(self._bandwidth_history[name]) > self.history_size:
                                self._bandwidth_history[name] = self._bandwidth_history[name][-self.history_size:]

                # Update previous counters
                self._prev_counters[name] = {
                    'bytes_sent': counter.bytes_sent,
                    'bytes_recv': counter.bytes_recv,
                    'packets_sent': counter.packets_sent,
                    'packets_recv': counter.packets_recv
                }

            self._prev_time = current_time

        except Exception as e:
            logger.error("[NETWORK_MONITOR] Failed to calculate bandwidth: %s", e)

        return bandwidth

    def get_bandwidth_history(self, interface: str = None,
                             minutes: int = 60) -> Dict[str, List[BandwidthSample]]:
        """Get bandwidth history for specified duration"""
        with self._lock:
            cutoff = datetime.now() - timedelta(minutes=minutes)
            cutoff_str = cutoff.isoformat()

            if interface:
                samples = [s for s in self._bandwidth_history.get(interface, [])
                          if s.timestamp >= cutoff_str]
                return {interface: samples}
            else:
                result = {}
                for iface, samples in self._bandwidth_history.items():
                    result[iface] = [s for s in samples if s.timestamp >= cutoff_str]
                return result

    def get_process_network_activity(self) -> Dict[int, ProcessNetworkActivity]:
        """Get network activity grouped by process"""
        activity = {}

        try:
            # Group connections by PID
            connections_by_pid: Dict[int, List[ConnectionInfo]] = defaultdict(list)
            for conn in self.get_all_connections():
                if conn.pid:
                    connections_by_pid[conn.pid].append(conn)

            # Get process info
            for pid, conns in connections_by_pid.items():
                try:
                    proc = psutil.Process(pid)

                    # Get I/O counters if available
                    try:
                        io_counters = proc.io_counters()
                        bytes_sent = io_counters.write_bytes
                        bytes_recv = io_counters.read_bytes
                    except (psutil.AccessDenied, AttributeError):
                        bytes_sent = 0
                        bytes_recv = 0

                    # Get open files count
                    try:
                        open_files = len(proc.open_files())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        open_files = 0

                    proc_activity = ProcessNetworkActivity(
                        pid=pid,
                        name=proc.name(),
                        connections=conns,
                        bytes_sent=bytes_sent,
                        bytes_recv=bytes_recv,
                        open_files=open_files,
                        cpu_percent=proc.cpu_percent(),
                        memory_percent=proc.memory_percent()
                    )
                    activity[pid] = proc_activity

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            with self._lock:
                self._process_activity = activity

        except Exception as e:
            logger.error("[NETWORK_MONITOR] Failed to get process activity: %s", e)

        return activity

    def get_listening_ports(self) -> List[Dict]:
        """Get all listening ports with service info"""
        ports = []

        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    process_name = None
                    if conn.pid:
                        try:
                            process_name = psutil.Process(conn.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

                    ports.append({
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'protocol': 'TCP',
                        'pid': conn.pid,
                        'process': process_name,
                        'family': 'IPv4' if conn.family == socket.AF_INET else 'IPv6'
                    })
        except psutil.AccessDenied:
            logger.warning("[NETWORK_MONITOR] Access denied for listening ports (try running as root)")
        except Exception as e:
            logger.error("[NETWORK_MONITOR] Failed to get listening ports: %s", e)

        return ports

    def get_connection_count_by_state(self) -> Dict[str, int]:
        """Get connection count grouped by state"""
        counts: Dict[str, int] = defaultdict(int)
        with self._lock:
            for conn in self._connections:
                counts[conn.state] += 1
        return dict(counts)

    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Get top processes by connection count"""
        with self._lock:
            process_counts: Dict[Tuple[int, str], int] = defaultdict(int)

            for conn in self._connections:
                if conn.pid and conn.process_name:
                    process_counts[(conn.pid, conn.process_name)] += 1

            sorted_procs = sorted(process_counts.items(), key=lambda x: x[1], reverse=True)

            return [
                {'pid': pid, 'process': name, 'connection_count': count}
                for (pid, name), count in sorted_procs[:limit]
            ]

    def start_monitoring(self):
        """Start background monitoring thread"""
        if self._running:
            logger.warning("[NETWORK_MONITOR] Already running")
            return

        self._running = True
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        logger.info("[NETWORK_MONITOR] Background monitoring started")

    def stop_monitoring(self):
        """Stop background monitoring"""
        self._running = False
        if self._monitor_thread:
            self._monitor_thread.join(timeout=5.0)
        logger.info("[NETWORK_MONITOR] Background monitoring stopped")

    def _monitor_loop(self):
        """Background monitoring loop"""
        while self._running:
            try:
                self.get_all_interfaces()
                self.get_all_connections()
                self.get_bandwidth_usage()

                # Store connection snapshot
                with self._lock:
                    snapshot = {
                        'timestamp': datetime.now().isoformat(),
                        'total_connections': len(self._connections),
                        'states': self.get_connection_count_by_state()
                    }
                    self._connection_history.append(snapshot)

                    # Trim history
                    if len(self._connection_history) > self.history_size:
                        self._connection_history = self._connection_history[-self.history_size:]

            except Exception as e:
                logger.error("[NETWORK_MONITOR] Monitor loop error: %s", e)

            time.sleep(self.sample_interval)

    def get_summary(self) -> Dict:
        """Get overall network monitoring summary"""
        self.get_all_interfaces()
        self.get_all_connections()
        bandwidth = self.get_bandwidth_usage()

        total_bytes_recv = sum(s.bytes_recv_per_sec for s in bandwidth.values())
        total_bytes_sent = sum(s.bytes_sent_per_sec for s in bandwidth.values())

        with self._lock:
            return {
                'timestamp': datetime.now().isoformat(),
                'interfaces': {
                    'count': len(self._interface_stats),
                    'active': sum(1 for i in self._interface_stats.values() if i.is_up)
                },
                'connections': {
                    'total': len(self._connections),
                    'established': len([c for c in self._connections if c.state == 'ESTABLISHED']),
                    'listening': len([c for c in self._connections if c.state == 'LISTEN']),
                    'by_state': self.get_connection_count_by_state()
                },
                'bandwidth': {
                    'total_recv_bytes_sec': total_bytes_recv,
                    'total_sent_bytes_sec': total_bytes_sent,
                    'total_recv_mbps': (total_bytes_recv * 8) / 1_000_000,
                    'total_sent_mbps': (total_bytes_sent * 8) / 1_000_000
                },
                'outbound_connections': len(self.get_outbound_connections()),
                'listening_ports': len(self.get_listening_ports()),
                'top_talkers': self.get_top_talkers(5)
            }


# Singleton instance
_network_monitor: Optional[NetworkMonitor] = None

def get_network_monitor() -> NetworkMonitor:
    """Get or create network monitor singleton"""
    global _network_monitor
    if _network_monitor is None:
        _network_monitor = NetworkMonitor()
    return _network_monitor
