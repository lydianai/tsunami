# Cybersecurity Autonomous Agent - Core Implementation
# Demonstrates event-driven scanning with pattern matching

import asyncio
import json
import logging
from datetime import datetime
from enum import Enum
from typing import Dict, List, Any
import uuid
import re
import socket
import ssl
import time
from dataclasses import dataclass, asdict, field

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============== THREAT SIGNATURES ==============

@dataclass
class ThreatSignature:
    """Pattern-based threat detection model"""
    id: str
    name: str
    severity: str  # critical, high, medium, low
    pattern: str  # Regex pattern
    description: str
    remediation: str
    cwe: List[str] = field(default_factory=list)

# Comprehensive threat database
THREAT_SIGNATURES = [
    ThreatSignature(
        id='ssl_expired',
        name='Expired SSL Certificate',
        severity='critical',
        pattern=r'notAfter.*\d{4}-\d{2}-\d{2}.*(?:19\d{2}|20(?:0[0-9]|1[0-9]|2[0-4]))',
        description='SSL/TLS certificate has expired',
        remediation='Renew SSL certificate from Certificate Authority immediately',
        cwe=['CWE-295']
    ),
    ThreatSignature(
        id='weak_ssl_cipher',
        name='Weak SSL/TLS Cipher Suite',
        severity='high',
        pattern=r'(DES|RC4|MD5|NULL|EXPORT|anon|aNULL|eNULL)',
        description='Server supports deprecated cipher suites vulnerable to cryptanalysis',
        remediation='Update OpenSSL/TLS version, disable weak ciphers in server config',
        cwe=['CWE-326', 'CWE-327']
    ),
    ThreatSignature(
        id='ssh_weak_key_exchange',
        name='SSH Weak Key Exchange Algorithm',
        severity='high',
        pattern=r'diffie-hellman-group1-sha1',
        description='SSH uses weak Diffie-Hellman groups vulnerable to discrete log attacks',
        remediation='Enable diffie-hellman-group14-sha256 or stronger algorithms',
        cwe=['CWE-326']
    ),
    ThreatSignature(
        id='default_credentials',
        name='Default Credentials Detected',
        severity='critical',
        pattern=r'(admin|root|test|guest):(admin|root|test|guest|password|123456)',
        description='Service responds with default username/password combinations',
        remediation='Change all default credentials immediately',
        cwe=['CWE-798']
    ),
    ThreatSignature(
        id='sql_injection_vulnerable',
        name='SQL Injection Vulnerability',
        severity='critical',
        pattern=r"(\' OR '1'='1|DROP TABLE|UNION SELECT|;DELETE)",
        description='Application appears vulnerable to SQL injection attacks',
        remediation='Use parameterized queries, input validation, WAF',
        cwe=['CWE-89']
    ),
    ThreatSignature(
        id='header_injection',
        name='Header Injection Vulnerability',
        severity='high',
        pattern=r'(Content-Type|Location|Set-Cookie).*\r\n',
        description='Response headers contain injection vulnerabilities',
        remediation='Sanitize all user input before adding to headers',
        cwe=['CWE-113']
    ),
    ThreatSignature(
        id='open_debug_interface',
        name='Open Debug Interface',
        severity='high',
        pattern=r'(debug=true|DEBUG|debugmode|debug_mode=1)',
        description='Debug interface is enabled and accessible',
        remediation='Disable debug mode in production',
        cwe=['CWE-215']
    ),
]

# ============== SCAN TYPES ==============

class ScanType(Enum):
    PORT_SCAN = "port_scan"
    SSL_CHECK = "ssl_check"
    VULNERABILITY_SCAN = "vuln_scan"
    HEADER_ANALYSIS = "header_analysis"
    CREDENTIAL_TEST = "credential_test"

@dataclass
class ScanTask:
    """Task definition for scanning"""
    id: str
    type: ScanType
    target: str
    ports: List[int] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class Finding:
    """Individual finding from scan"""
    type: str
    severity: str
    description: str
    data: Dict[str, Any]
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ThreatDetection:
    """Detected security threat"""
    threat_id: str
    name: str
    severity: str
    finding_match: str
    remediation: str
    cwe: List[str]
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanResult:
    """Complete scan results"""
    scan_id: str
    target: str
    scan_type: str
    status: str
    findings: List[Finding]
    threats: List[ThreatDetection]
    duration_seconds: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self):
        return {
            'scan_id': self.scan_id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'findings': [asdict(f) for f in self.findings],
            'threats': [asdict(t) for t in self.threats],
            'duration_seconds': self.duration_seconds,
            'timestamp': self.timestamp
        }

# ============== SCANNER IMPLEMENTATIONS ==============

class PortScanner:
    """Asynchronous port scanner"""

    @staticmethod
    async def scan(target: str, ports: List[int], timeout: float = 2.0) -> List[Finding]:
        """Scan target ports concurrently"""
        findings = []

        async def check_port(port):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=timeout
                )
                writer.close()
                await writer.wait_closed()

                return Finding(
                    type='open_port',
                    severity='info',
                    description=f'Port {port} is open',
                    data={'port': port, 'status': 'open'}
                )
            except (asyncio.TimeoutError, OSError):
                return Finding(
                    type='port_status',
                    severity='info',
                    description=f'Port {port} is closed or filtered',
                    data={'port': port, 'status': 'closed'}
                )
            except Exception as e:
                return Finding(
                    type='port_error',
                    severity='info',
                    description=str(e),
                    data={'port': port, 'error': str(e)}
                )

        # Run port checks concurrently
        tasks = [check_port(port) for port in ports]
        findings = await asyncio.gather(*tasks)

        return findings

class SSLChecker:
    """SSL/TLS certificate analyzer"""

    @staticmethod
    async def check(target: str, port: int = 443) -> List[Finding]:
        """Analyze SSL certificate and cipher suites"""
        findings = []

        def get_cert_info():
            try:
                context = ssl.create_default_context()
                with socket.create_connection((target, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()

                        # Certificate info
                        findings.append(Finding(
                            type='ssl_certificate',
                            severity='info',
                            description='SSL certificate info',
                            data={
                                'subject': dict(x[0] for x in cert.get('subject', [])),
                                'issuer': dict(x[0] for x in cert.get('issuer', [])),
                                'version': cert.get('version'),
                                'notBefore': cert.get('notBefore'),
                                'notAfter': cert.get('notAfter'),
                                'serialNumber': cert.get('serialNumber')
                            }
                        ))

                        # Cipher suite
                        findings.append(Finding(
                            type='ssl_cipher',
                            severity='info',
                            description='SSL cipher suite in use',
                            data={
                                'cipher': cipher[0],
                                'protocol': cipher[1],
                                'bits': cipher[2]
                            }
                        ))

                        # Get supported protocols
                        protocols = SSLChecker._get_supported_protocols(target, port)
                        findings.append(Finding(
                            type='ssl_protocols',
                            severity='info',
                            description='Supported SSL/TLS protocols',
                            data={'protocols': protocols}
                        ))

                        return findings
            except Exception as e:
                findings.append(Finding(
                    type='ssl_error',
                    severity='high',
                    description=f'SSL check failed: {str(e)}',
                    data={'error': str(e)}
                ))
                return findings

        return await asyncio.to_thread(get_cert_info)

    @staticmethod
    def _get_supported_protocols(target: str, port: int) -> List[str]:
        """Check which SSL/TLS protocols are supported"""
        protocols = []
        for protocol, method in [
            ('TLS 1.3', ssl.TLSVersion.TLSv1_3),
            ('TLS 1.2', ssl.TLSVersion.TLSv1_2),
            ('TLS 1.1', ssl.TLSVersion.TLSv1_1),
            ('TLS 1.0', ssl.TLSVersion.TLSv1_0),
        ]:
            try:
                context = ssl.SSLContext(method)
                with socket.create_connection((target, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=target):
                        protocols.append(protocol)
            except:
                pass
        return protocols

class HeaderAnalyzer:
    """HTTP header security analysis"""

    SECURITY_HEADERS = {
        'Strict-Transport-Security': 'HSTS enforces HTTPS',
        'X-Frame-Options': 'Prevents clickjacking',
        'X-Content-Type-Options': 'Prevents MIME sniffing',
        'Content-Security-Policy': 'XSS and injection protection',
        'X-XSS-Protection': 'Legacy XSS protection',
    }

    @staticmethod
    async def analyze(target: str, port: int = 443) -> List[Finding]:
        """Analyze HTTP response headers"""
        findings = []

        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                scheme = 'https' if port == 443 else 'http'
                url = f'{scheme}://{target}:{port}/'

                async with session.get(url, ssl=False, timeout=5) as response:
                    headers = response.headers

                    # Check for security headers
                    for header, description in HeaderAnalyzer.SECURITY_HEADERS.items():
                        if header in headers:
                            findings.append(Finding(
                                type='security_header_present',
                                severity='info',
                                description=f'{header}: {description}',
                                data={'header': header, 'value': headers[header]}
                            ))
                        else:
                            findings.append(Finding(
                                type='missing_security_header',
                                severity='medium',
                                description=f'Missing {header}',
                                data={'header': header}
                            ))

                    # Check for server info leakage
                    if 'Server' in headers:
                        findings.append(Finding(
                            type='server_info_leakage',
                            severity='low',
                            description='Server version information disclosed',
                            data={'server': headers['Server']}
                        ))

                    return findings
        except Exception as e:
            findings.append(Finding(
                type='header_analysis_error',
                severity='info',
                description=str(e),
                data={'error': str(e)}
            ))
            return findings

# ============== THREAT DETECTION ENGINE ==============

class ThreatDetectionEngine:
    """Pattern-based threat detection"""

    @staticmethod
    def detect_threats(findings: List[Finding]) -> List[ThreatDetection]:
        """Match findings against threat signatures"""
        threats = []
        findings_str = json.dumps([asdict(f) for f in findings])

        for signature in THREAT_SIGNATURES:
            if re.search(signature.pattern, findings_str, re.IGNORECASE):
                threat = ThreatDetection(
                    threat_id=signature.id,
                    name=signature.name,
                    severity=signature.severity,
                    finding_match=findings_str[:200],
                    remediation=signature.remediation,
                    cwe=signature.cwe
                )
                threats.append(threat)
                logger.warning(f"Threat detected: {signature.name} ({signature.severity})")

        return threats

# ============== AGENT EXECUTOR ==============

class ScanExecutor:
    """Executes scanning tasks"""

    @staticmethod
    async def execute(task: ScanTask) -> ScanResult:
        """Execute a single scan task"""
        start_time = time.time()
        findings = []
        status = 'success'

        try:
            logger.info(f"Executing scan: {task.id} ({task.type.value})")

            if task.type == ScanType.PORT_SCAN:
                ports = task.ports or [22, 80, 443, 8080, 3306, 5432]
                findings = await PortScanner.scan(task.target, ports)

            elif task.type == ScanType.SSL_CHECK:
                findings = await SSLChecker.check(task.target)

            elif task.type == ScanType.HEADER_ANALYSIS:
                findings = await HeaderAnalyzer.analyze(task.target)

        except Exception as e:
            logger.error(f"Scan error: {e}")
            status = 'failed'
            findings = [Finding(
                type='scan_error',
                severity='high',
                description=str(e),
                data={'error': str(e)}
            )]

        duration = time.time() - start_time

        # Detect threats from findings
        threats = ThreatDetectionEngine.detect_threats(findings)

        result = ScanResult(
            scan_id=task.id,
            target=task.target,
            scan_type=task.type.value,
            status=status,
            findings=findings,
            threats=threats,
            duration_seconds=duration
        )

        return result

# ============== EXAMPLE USAGE ==============

async def main():
    """Demonstrate scanning operations"""

    # Create scan tasks
    tasks = [
        ScanTask(
            id=str(uuid.uuid4()),
            type=ScanType.PORT_SCAN,
            target='scanme.nmap.org',
            ports=[22, 80, 443]
        ),
        ScanTask(
            id=str(uuid.uuid4()),
            type=ScanType.SSL_CHECK,
            target='scanme.nmap.org'
        ),
    ]

    # Execute scans
    for task in tasks:
        result = await ScanExecutor.execute(task)
        print(json.dumps(result.to_dict(), indent=2))

        # Show threats
        for threat in result.threats:
            print(f"\n[THREAT] {threat.name} ({threat.severity})")
            print(f"Remediation: {threat.remediation}")

if __name__ == '__main__':
    asyncio.run(main())
