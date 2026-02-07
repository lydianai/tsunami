#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI HEALTH CHECKER v5.0
    System Health Monitoring Module
================================================================================

    Features:
    - CPU, memory, disk monitoring (psutil)
    - Service status checks (systemctl, process)
    - Port availability checks
    - SSL certificate monitoring
    - DNS resolution checks
    - Custom health check plugins

================================================================================
"""

import os
import ssl
import socket
import logging
import threading
import subprocess
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HealthStatus(Enum):
    """Health check status"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    CRITICAL = "critical"


@dataclass
class ServiceCheck:
    """Service health check result"""
    name: str
    status: HealthStatus
    message: str
    response_time_ms: float
    details: Dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['status'] = self.status.value
        return result


@dataclass
class ResourceMetrics:
    """System resource metrics"""
    cpu_percent: float
    cpu_count: int
    cpu_freq_mhz: float
    memory_total_gb: float
    memory_used_gb: float
    memory_percent: float
    swap_total_gb: float
    swap_used_gb: float
    swap_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_percent: float
    disk_read_bytes: int
    disk_write_bytes: int
    load_avg_1m: float
    load_avg_5m: float
    load_avg_15m: float
    boot_time: str
    uptime_hours: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SSLCertInfo:
    """SSL certificate information"""
    host: str
    port: int
    subject: str
    issuer: str
    not_before: str
    not_after: str
    days_until_expiry: int
    is_expired: bool
    is_valid: bool
    serial_number: str
    version: int
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class PortCheck:
    """Port availability check result"""
    host: str
    port: int
    is_open: bool
    response_time_ms: float
    banner: Optional[str] = None
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DNSCheck:
    """DNS resolution check result"""
    hostname: str
    resolved_ips: List[str]
    resolution_time_ms: float
    nameserver: Optional[str] = None
    is_successful: bool = True
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        return asdict(self)


class HealthChecker:
    """
    Comprehensive system health checker.
    Monitors resources, services, ports, SSL certificates, and DNS.
    """

    # Default thresholds
    DEFAULT_THRESHOLDS = {
        'cpu_warning': 70.0,
        'cpu_critical': 90.0,
        'memory_warning': 75.0,
        'memory_critical': 90.0,
        'disk_warning': 80.0,
        'disk_critical': 95.0,
        'ssl_expiry_warning_days': 30,
        'ssl_expiry_critical_days': 7,
        'load_warning_multiplier': 2.0,  # Multiplier of CPU count
        'load_critical_multiplier': 4.0,
    }

    def __init__(self, thresholds: Dict = None):
        """Initialize health checker with custom thresholds"""
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil is required for health checking. Install with: pip install psutil")

        self.thresholds = {**self.DEFAULT_THRESHOLDS, **(thresholds or {})}
        self._check_history: List[Dict] = []
        self._service_statuses: Dict[str, ServiceCheck] = {}
        self._custom_checks: Dict[str, Callable] = {}
        self._lock = threading.RLock()

        logger.info("[HEALTH_CHECKER] Initialized with thresholds: %s", self.thresholds)

    def get_resource_metrics(self) -> ResourceMetrics:
        """Collect all system resource metrics"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.5)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()

            # Memory
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Disk (root partition)
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()

            # Load average (Unix only)
            try:
                load_avg = os.getloadavg()
            except (OSError, AttributeError):
                load_avg = (0.0, 0.0, 0.0)

            # Boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time

            return ResourceMetrics(
                cpu_percent=cpu_percent,
                cpu_count=cpu_count,
                cpu_freq_mhz=cpu_freq.current if cpu_freq else 0,
                memory_total_gb=memory.total / (1024**3),
                memory_used_gb=memory.used / (1024**3),
                memory_percent=memory.percent,
                swap_total_gb=swap.total / (1024**3),
                swap_used_gb=swap.used / (1024**3),
                swap_percent=swap.percent,
                disk_total_gb=disk.total / (1024**3),
                disk_used_gb=disk.used / (1024**3),
                disk_percent=disk.percent,
                disk_read_bytes=disk_io.read_bytes if disk_io else 0,
                disk_write_bytes=disk_io.write_bytes if disk_io else 0,
                load_avg_1m=load_avg[0],
                load_avg_5m=load_avg[1],
                load_avg_15m=load_avg[2],
                boot_time=boot_time.isoformat(),
                uptime_hours=uptime.total_seconds() / 3600
            )
        except Exception as e:
            logger.error("[HEALTH_CHECKER] Failed to get resource metrics: %s", e)
            raise

    def check_resource_health(self) -> ServiceCheck:
        """Check overall resource health against thresholds"""
        start_time = time.time()
        try:
            metrics = self.get_resource_metrics()
            issues = []
            status = HealthStatus.HEALTHY

            # CPU checks
            if metrics.cpu_percent >= self.thresholds['cpu_critical']:
                issues.append(f"CPU critical: {metrics.cpu_percent:.1f}%")
                status = HealthStatus.CRITICAL
            elif metrics.cpu_percent >= self.thresholds['cpu_warning']:
                issues.append(f"CPU warning: {metrics.cpu_percent:.1f}%")
                if status != HealthStatus.CRITICAL:
                    status = HealthStatus.DEGRADED

            # Memory checks
            if metrics.memory_percent >= self.thresholds['memory_critical']:
                issues.append(f"Memory critical: {metrics.memory_percent:.1f}%")
                status = HealthStatus.CRITICAL
            elif metrics.memory_percent >= self.thresholds['memory_warning']:
                issues.append(f"Memory warning: {metrics.memory_percent:.1f}%")
                if status != HealthStatus.CRITICAL:
                    status = HealthStatus.DEGRADED

            # Disk checks
            if metrics.disk_percent >= self.thresholds['disk_critical']:
                issues.append(f"Disk critical: {metrics.disk_percent:.1f}%")
                status = HealthStatus.CRITICAL
            elif metrics.disk_percent >= self.thresholds['disk_warning']:
                issues.append(f"Disk warning: {metrics.disk_percent:.1f}%")
                if status != HealthStatus.CRITICAL:
                    status = HealthStatus.DEGRADED

            # Load average checks
            load_warning = metrics.cpu_count * self.thresholds['load_warning_multiplier']
            load_critical = metrics.cpu_count * self.thresholds['load_critical_multiplier']

            if metrics.load_avg_1m >= load_critical:
                issues.append(f"Load critical: {metrics.load_avg_1m:.2f}")
                status = HealthStatus.CRITICAL
            elif metrics.load_avg_1m >= load_warning:
                issues.append(f"Load warning: {metrics.load_avg_1m:.2f}")
                if status != HealthStatus.CRITICAL:
                    status = HealthStatus.DEGRADED

            response_time = (time.time() - start_time) * 1000
            message = "; ".join(issues) if issues else "All resources healthy"

            return ServiceCheck(
                name="system_resources",
                status=status,
                message=message,
                response_time_ms=response_time,
                details=metrics.to_dict()
            )
        except Exception as e:
            return ServiceCheck(
                name="system_resources",
                status=HealthStatus.UNKNOWN,
                message=f"Failed to check resources: {e}",
                response_time_ms=(time.time() - start_time) * 1000
            )

    def check_service_systemctl(self, service_name: str) -> ServiceCheck:
        """Check service status using systemctl"""
        start_time = time.time()

        try:
            # Check if service is active
            result = subprocess.run(
                ['systemctl', 'is-active', service_name],
                capture_output=True,
                text=True,
                timeout=10
            )
            is_active = result.stdout.strip() == 'active'

            # Get more details
            status_result = subprocess.run(
                ['systemctl', 'show', service_name,
                 '--property=ActiveState,SubState,MainPID,MemoryCurrent,CPUUsageNSec'],
                capture_output=True,
                text=True,
                timeout=10
            )

            details = {}
            for line in status_result.stdout.strip().split('\n'):
                if '=' in line:
                    key, value = line.split('=', 1)
                    details[key] = value

            response_time = (time.time() - start_time) * 1000

            if is_active:
                return ServiceCheck(
                    name=service_name,
                    status=HealthStatus.HEALTHY,
                    message=f"Service {service_name} is active",
                    response_time_ms=response_time,
                    details=details
                )
            else:
                return ServiceCheck(
                    name=service_name,
                    status=HealthStatus.UNHEALTHY,
                    message=f"Service {service_name} is not active: {result.stdout.strip()}",
                    response_time_ms=response_time,
                    details=details
                )

        except subprocess.TimeoutExpired:
            return ServiceCheck(
                name=service_name,
                status=HealthStatus.UNKNOWN,
                message=f"Timeout checking service {service_name}",
                response_time_ms=(time.time() - start_time) * 1000
            )
        except FileNotFoundError:
            return ServiceCheck(
                name=service_name,
                status=HealthStatus.UNKNOWN,
                message="systemctl not found (not a systemd system)",
                response_time_ms=(time.time() - start_time) * 1000
            )
        except Exception as e:
            return ServiceCheck(
                name=service_name,
                status=HealthStatus.UNKNOWN,
                message=f"Error checking service: {e}",
                response_time_ms=(time.time() - start_time) * 1000
            )

    def check_service_process(self, process_name: str,
                              min_instances: int = 1) -> ServiceCheck:
        """Check if a process is running by name"""
        start_time = time.time()

        try:
            found_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_percent']):
                try:
                    if process_name.lower() in proc.info['name'].lower():
                        found_processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'status': proc.info['status'],
                            'cpu_percent': proc.info['cpu_percent'],
                            'memory_percent': proc.info['memory_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            response_time = (time.time() - start_time) * 1000
            count = len(found_processes)

            if count >= min_instances:
                return ServiceCheck(
                    name=f"process:{process_name}",
                    status=HealthStatus.HEALTHY,
                    message=f"Found {count} instance(s) of {process_name}",
                    response_time_ms=response_time,
                    details={'instances': found_processes}
                )
            elif count > 0:
                return ServiceCheck(
                    name=f"process:{process_name}",
                    status=HealthStatus.DEGRADED,
                    message=f"Found {count}/{min_instances} instances of {process_name}",
                    response_time_ms=response_time,
                    details={'instances': found_processes}
                )
            else:
                return ServiceCheck(
                    name=f"process:{process_name}",
                    status=HealthStatus.UNHEALTHY,
                    message=f"Process {process_name} not running",
                    response_time_ms=response_time
                )
        except Exception as e:
            return ServiceCheck(
                name=f"process:{process_name}",
                status=HealthStatus.UNKNOWN,
                message=f"Error checking process: {e}",
                response_time_ms=(time.time() - start_time) * 1000
            )

    def check_port(self, host: str, port: int, timeout: float = 5.0) -> PortCheck:
        """Check if a TCP port is open and responding"""
        start_time = time.time()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)

            result = sock.connect_ex((host, port))
            response_time = (time.time() - start_time) * 1000

            if result == 0:
                # Try to grab banner
                banner = None
                try:
                    sock.settimeout(2.0)
                    sock.send(b'\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                except:
                    pass

                sock.close()
                return PortCheck(
                    host=host,
                    port=port,
                    is_open=True,
                    response_time_ms=response_time,
                    banner=banner
                )
            else:
                sock.close()
                return PortCheck(
                    host=host,
                    port=port,
                    is_open=False,
                    response_time_ms=response_time,
                    error=f"Connection refused (errno: {result})"
                )

        except socket.timeout:
            return PortCheck(
                host=host,
                port=port,
                is_open=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error="Connection timeout"
            )
        except Exception as e:
            return PortCheck(
                host=host,
                port=port,
                is_open=False,
                response_time_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )

    def check_ssl_certificate(self, host: str, port: int = 443) -> SSLCertInfo:
        """Check SSL certificate validity and expiration"""
        try:
            context = ssl.create_default_context()

            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()

                    # Parse dates
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.now()

                    days_until_expiry = (not_after - now).days
                    is_expired = now > not_after
                    is_valid = not_before <= now <= not_after

                    # Extract subject and issuer
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))

                    return SSLCertInfo(
                        host=host,
                        port=port,
                        subject=subject.get('commonName', 'Unknown'),
                        issuer=issuer.get('organizationName', 'Unknown'),
                        not_before=not_before.isoformat(),
                        not_after=not_after.isoformat(),
                        days_until_expiry=days_until_expiry,
                        is_expired=is_expired,
                        is_valid=is_valid,
                        serial_number=cert.get('serialNumber', ''),
                        version=cert.get('version', 0)
                    )

        except ssl.SSLCertVerificationError as e:
            return SSLCertInfo(
                host=host,
                port=port,
                subject='',
                issuer='',
                not_before='',
                not_after='',
                days_until_expiry=0,
                is_expired=True,
                is_valid=False,
                serial_number='',
                version=0,
                error=f"SSL verification failed: {e}"
            )
        except Exception as e:
            return SSLCertInfo(
                host=host,
                port=port,
                subject='',
                issuer='',
                not_before='',
                not_after='',
                days_until_expiry=0,
                is_expired=False,
                is_valid=False,
                serial_number='',
                version=0,
                error=f"SSL check failed: {e}"
            )

    def check_ssl_health(self, host: str, port: int = 443) -> ServiceCheck:
        """Check SSL certificate health against thresholds"""
        start_time = time.time()
        cert_info = self.check_ssl_certificate(host, port)
        response_time = (time.time() - start_time) * 1000

        if cert_info.error:
            return ServiceCheck(
                name=f"ssl:{host}:{port}",
                status=HealthStatus.UNHEALTHY,
                message=cert_info.error,
                response_time_ms=response_time,
                details=cert_info.to_dict()
            )

        if cert_info.is_expired:
            return ServiceCheck(
                name=f"ssl:{host}:{port}",
                status=HealthStatus.CRITICAL,
                message=f"SSL certificate is EXPIRED",
                response_time_ms=response_time,
                details=cert_info.to_dict()
            )

        if cert_info.days_until_expiry <= self.thresholds['ssl_expiry_critical_days']:
            return ServiceCheck(
                name=f"ssl:{host}:{port}",
                status=HealthStatus.CRITICAL,
                message=f"SSL certificate expires in {cert_info.days_until_expiry} days",
                response_time_ms=response_time,
                details=cert_info.to_dict()
            )

        if cert_info.days_until_expiry <= self.thresholds['ssl_expiry_warning_days']:
            return ServiceCheck(
                name=f"ssl:{host}:{port}",
                status=HealthStatus.DEGRADED,
                message=f"SSL certificate expires in {cert_info.days_until_expiry} days",
                response_time_ms=response_time,
                details=cert_info.to_dict()
            )

        return ServiceCheck(
            name=f"ssl:{host}:{port}",
            status=HealthStatus.HEALTHY,
            message=f"SSL certificate valid for {cert_info.days_until_expiry} days",
            response_time_ms=response_time,
            details=cert_info.to_dict()
        )

    def check_dns(self, hostname: str, expected_ips: List[str] = None) -> DNSCheck:
        """Check DNS resolution for a hostname"""
        start_time = time.time()

        try:
            # Resolve hostname
            result = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
            resolved_ips = list(set(addr[4][0] for addr in result))
            resolution_time = (time.time() - start_time) * 1000

            # Check if expected IPs match
            is_successful = True
            if expected_ips:
                is_successful = any(ip in resolved_ips for ip in expected_ips)

            return DNSCheck(
                hostname=hostname,
                resolved_ips=resolved_ips,
                resolution_time_ms=resolution_time,
                is_successful=is_successful
            )

        except socket.gaierror as e:
            return DNSCheck(
                hostname=hostname,
                resolved_ips=[],
                resolution_time_ms=(time.time() - start_time) * 1000,
                is_successful=False,
                error=f"DNS resolution failed: {e}"
            )
        except Exception as e:
            return DNSCheck(
                hostname=hostname,
                resolved_ips=[],
                resolution_time_ms=(time.time() - start_time) * 1000,
                is_successful=False,
                error=str(e)
            )

    def register_custom_check(self, name: str, check_fn: Callable[[], ServiceCheck]):
        """Register a custom health check function"""
        self._custom_checks[name] = check_fn
        logger.info("[HEALTH_CHECKER] Registered custom check: %s", name)

    def run_custom_checks(self) -> List[ServiceCheck]:
        """Run all registered custom health checks"""
        results = []
        for name, check_fn in self._custom_checks.items():
            try:
                result = check_fn()
                results.append(result)
            except Exception as e:
                results.append(ServiceCheck(
                    name=name,
                    status=HealthStatus.UNKNOWN,
                    message=f"Custom check error: {e}",
                    response_time_ms=0
                ))
        return results

    def run_all_checks(self,
                       services: List[str] = None,
                       processes: List[str] = None,
                       ports: List[Dict] = None,
                       ssl_hosts: List[Dict] = None,
                       dns_hosts: List[str] = None) -> Dict:
        """
        Run comprehensive health check.

        Args:
            services: List of systemd service names
            processes: List of process names to check
            ports: List of {'host': str, 'port': int} dicts
            ssl_hosts: List of {'host': str, 'port': int} dicts
            dns_hosts: List of hostnames to resolve
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'overall_status': HealthStatus.HEALTHY.value,
            'checks': {}
        }

        all_checks = []

        # Resource check
        resource_check = self.check_resource_health()
        all_checks.append(resource_check)
        results['checks']['resources'] = resource_check.to_dict()

        # Service checks
        if services:
            service_results = []
            for service in services:
                check = self.check_service_systemctl(service)
                service_results.append(check.to_dict())
                all_checks.append(check)
            results['checks']['services'] = service_results

        # Process checks
        if processes:
            process_results = []
            for process in processes:
                check = self.check_service_process(process)
                process_results.append(check.to_dict())
                all_checks.append(check)
            results['checks']['processes'] = process_results

        # Port checks
        if ports:
            port_results = []
            for port_info in ports:
                check_result = self.check_port(port_info['host'], port_info['port'])
                port_results.append(check_result.to_dict())
            results['checks']['ports'] = port_results

        # SSL checks
        if ssl_hosts:
            ssl_results = []
            for ssl_info in ssl_hosts:
                check = self.check_ssl_health(ssl_info['host'], ssl_info.get('port', 443))
                ssl_results.append(check.to_dict())
                all_checks.append(check)
            results['checks']['ssl'] = ssl_results

        # DNS checks
        if dns_hosts:
            dns_results = []
            for hostname in dns_hosts:
                check_result = self.check_dns(hostname)
                dns_results.append(check_result.to_dict())
            results['checks']['dns'] = dns_results

        # Custom checks
        custom_results = self.run_custom_checks()
        if custom_results:
            results['checks']['custom'] = [c.to_dict() for c in custom_results]
            all_checks.extend(custom_results)

        # Determine overall status
        statuses = [c.status for c in all_checks]
        if HealthStatus.CRITICAL in statuses:
            results['overall_status'] = HealthStatus.CRITICAL.value
        elif HealthStatus.UNHEALTHY in statuses:
            results['overall_status'] = HealthStatus.UNHEALTHY.value
        elif HealthStatus.DEGRADED in statuses:
            results['overall_status'] = HealthStatus.DEGRADED.value
        elif HealthStatus.UNKNOWN in statuses:
            results['overall_status'] = HealthStatus.UNKNOWN.value

        # Store in history
        with self._lock:
            self._check_history.append(results)
            if len(self._check_history) > 1000:
                self._check_history = self._check_history[-1000:]

        return results

    def get_check_history(self, minutes: int = 60) -> List[Dict]:
        """Get health check history for specified duration"""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        cutoff_str = cutoff.isoformat()

        with self._lock:
            return [h for h in self._check_history if h['timestamp'] >= cutoff_str]


# Singleton instance
_health_checker: Optional[HealthChecker] = None

def get_health_checker() -> HealthChecker:
    """Get or create health checker singleton"""
    global _health_checker
    if _health_checker is None:
        _health_checker = HealthChecker()
    return _health_checker
