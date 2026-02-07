"""
Shannon Report Parser
=====================
Parses Shannon AI Pentester markdown reports into structured data.
Extracts vulnerabilities, severity, exploitation steps, and proof-of-impact.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_string(cls, value: str) -> 'Severity':
        """Parse severity from string"""
        value = value.lower().strip()
        for severity in cls:
            if severity.value in value:
                return severity
        return cls.MEDIUM  # Default


class VulnType(Enum):
    """Vulnerability types supported by Shannon"""
    INJECTION = "injection"
    XSS = "xss"
    SSRF = "ssrf"
    AUTH = "auth"
    AUTHZ = "authz"
    IDOR = "idor"
    FILE_INCLUSION = "file_inclusion"
    PATH_TRAVERSAL = "path_traversal"
    CSRF = "csrf"
    SENSITIVE_DATA = "sensitive_data"
    SECURITY_MISCONFIG = "misconfig"
    OTHER = "other"


@dataclass
class ShannonFinding:
    """Shannon vulnerability finding"""
    id: str
    title: str
    vulnerability_type: str
    severity: Severity
    location: str
    method: str = "GET"
    summary: str = ""
    impact: str = ""
    exploitation_steps: List[str] = field(default_factory=list)
    proof_of_impact: str = ""
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    remediation: str = ""
    raw_section: str = ""
    geo_data: Optional[Dict] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity.value,
            'location': self.location,
            'method': self.method,
            'summary': self.summary,
            'impact': self.impact,
            'exploitation_steps': self.exploitation_steps,
            'proof_of_impact': self.proof_of_impact,
            'cvss_score': self.cvss_score,
            'cwe_id': self.cwe_id,
            'remediation': self.remediation,
            'exploited': True  # Shannon only reports verified exploits
        }


def parse_shannon_report(markdown_content: str) -> List[ShannonFinding]:
    """
    Parse Shannon markdown report into structured findings

    Shannon reports follow this format:
    ### VULN-001: SQL Injection in Login Form
    **Summary:**
    - **Vulnerable location:** POST /api/auth/login
    - **Severity:** Critical
    ...
    """
    findings = []

    if not markdown_content:
        return findings

    # Split by vulnerability sections
    # Shannon uses: ### VULN-XXX: Title or ### APP-VULN-XXX: Title
    vuln_pattern = r'###\s+(?:[A-Z]+-)?VULN-(\d+):\s*(.+?)(?=\n)'

    sections = re.split(r'(?=###\s+(?:[A-Z]+-)?VULN-\d+:)', markdown_content)

    for section in sections:
        if not section.strip():
            continue

        # Extract vulnerability header
        header_match = re.match(vuln_pattern, section)
        if not header_match:
            continue

        vuln_num = header_match.group(1)
        title = header_match.group(2).strip()

        finding = ShannonFinding(
            id=f"SHAN-{vuln_num.zfill(3)}",
            title=title,
            vulnerability_type=_detect_vuln_type(section),
            severity=_extract_severity(section),
            location=_extract_location(section),
            method=_extract_method(section),
            summary=_extract_field(section, "Summary|Overview"),
            impact=_extract_field(section, "Impact"),
            exploitation_steps=_extract_steps(section),
            proof_of_impact=_extract_proof(section),
            cvss_score=_extract_cvss(section),
            cwe_id=_extract_cwe(section),
            remediation=_extract_field(section, "Remediation|Recommendation|Fix"),
            raw_section=section
        )

        findings.append(finding)
        logger.debug(f"[SHANNON] Parsed finding: {finding.id} - {finding.title}")

    logger.info(f"[SHANNON] Parsed {len(findings)} findings from report")
    return findings


def _detect_vuln_type(section: str) -> str:
    """Detect vulnerability type from content"""
    section_lower = section.lower()

    type_patterns = [
        (r'sql\s*injection|sqli', 'injection'),
        (r'command\s*injection|os\s*injection|rce', 'injection'),
        (r'xss|cross-site\s*scripting', 'xss'),
        (r'ssrf|server-side\s*request', 'ssrf'),
        (r'authentication|login\s*bypass|auth\s*bypass', 'auth'),
        (r'authorization|privilege|idor|access\s*control', 'authz'),
        (r'file\s*inclusion|lfi|rfi', 'file_inclusion'),
        (r'path\s*traversal|directory\s*traversal', 'path_traversal'),
        (r'csrf|cross-site\s*request', 'csrf'),
        (r'sensitive\s*data|information\s*disclosure|leak', 'sensitive_data'),
        (r'misconfiguration|security\s*header', 'misconfig'),
    ]

    for pattern, vuln_type in type_patterns:
        if re.search(pattern, section_lower):
            return vuln_type

    return 'other'


def _extract_severity(section: str) -> Severity:
    """Extract severity from section"""
    # Look for explicit severity field
    severity_match = re.search(
        r'\*\*Severity:?\*\*[:\s]*([A-Za-z]+)',
        section,
        re.IGNORECASE
    )

    if severity_match:
        return Severity.from_string(severity_match.group(1))

    # Look for CVSS-based severity
    cvss = _extract_cvss(section)
    if cvss:
        if cvss >= 9.0:
            return Severity.CRITICAL
        elif cvss >= 7.0:
            return Severity.HIGH
        elif cvss >= 4.0:
            return Severity.MEDIUM
        else:
            return Severity.LOW

    # Infer from vulnerability type
    section_lower = section.lower()
    if any(x in section_lower for x in ['sql injection', 'rce', 'command injection']):
        return Severity.CRITICAL
    elif any(x in section_lower for x in ['xss', 'ssrf', 'auth bypass']):
        return Severity.HIGH
    elif any(x in section_lower for x in ['csrf', 'idor']):
        return Severity.MEDIUM

    return Severity.HIGH  # Shannon's "No Exploit, No Report" means verified issues


def _extract_location(section: str) -> str:
    """Extract vulnerable endpoint location"""
    patterns = [
        r'\*\*Vulnerable\s*location:?\*\*[:\s]*(.+?)(?:\n|$)',
        r'\*\*Endpoint:?\*\*[:\s]*(.+?)(?:\n|$)',
        r'\*\*URL:?\*\*[:\s]*(.+?)(?:\n|$)',
        r'\*\*Location:?\*\*[:\s]*(.+?)(?:\n|$)',
        r'((?:GET|POST|PUT|DELETE|PATCH)\s+/[^\s]+)',
    ]

    for pattern in patterns:
        match = re.search(pattern, section, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return "Unknown"


def _extract_method(section: str) -> str:
    """Extract HTTP method"""
    method_match = re.search(
        r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b',
        section
    )
    return method_match.group(1) if method_match else "GET"


def _extract_field(section: str, field_name: str) -> str:
    """Extract a field value from section"""
    pattern = rf'\*\*(?:{field_name}):?\*\*[:\s]*(.+?)(?=\n\*\*|\n###|\n\n|\Z)'
    match = re.search(pattern, section, re.IGNORECASE | re.DOTALL)

    if match:
        value = match.group(1).strip()
        # Clean up bullet points
        value = re.sub(r'^[\-\*]\s+', '', value, flags=re.MULTILINE)
        return value

    return ""


def _extract_steps(section: str) -> List[str]:
    """Extract exploitation steps"""
    steps = []

    # Look for steps section
    steps_match = re.search(
        r'\*\*(?:Exploitation\s*Steps?|Steps\s*to\s*Reproduce|PoC):?\*\*\s*\n((?:[\d\.\-\*]\s*.+?\n?)+)',
        section,
        re.IGNORECASE
    )

    if steps_match:
        steps_text = steps_match.group(1)
        for line in steps_text.split('\n'):
            line = line.strip()
            if line and re.match(r'^[\d\.\-\*]', line):
                # Remove bullet/number prefix
                step = re.sub(r'^[\d\.\-\*\s]+', '', line).strip()
                if step:
                    steps.append(step)

    # Also extract code blocks as steps
    code_blocks = re.findall(r'```[^\n]*\n(.*?)```', section, re.DOTALL)
    for i, code in enumerate(code_blocks):
        if code.strip():
            steps.append(f"Execute: {code.strip()[:200]}...")

    return steps


def _extract_proof(section: str) -> str:
    """Extract proof of impact/exploitation"""
    patterns = [
        r'\*\*Proof\s*(?:of\s*)?(?:Impact|Concept|Exploitation)?:?\*\*\s*\n?(.*?)(?=\n\*\*|\n###|\Z)',
        r'\*\*Evidence:?\*\*\s*\n?(.*?)(?=\n\*\*|\n###|\Z)',
        r'\*\*Result:?\*\*\s*\n?(.*?)(?=\n\*\*|\n###|\Z)',
    ]

    for pattern in patterns:
        match = re.search(pattern, section, re.IGNORECASE | re.DOTALL)
        if match:
            proof = match.group(1).strip()
            # Include any code blocks
            if proof:
                return proof[:1000]  # Limit length

    return ""


def _extract_cvss(section: str) -> Optional[float]:
    """Extract CVSS score"""
    cvss_match = re.search(r'CVSS[:\s]*(\d+\.?\d*)', section, re.IGNORECASE)
    if cvss_match:
        try:
            return float(cvss_match.group(1))
        except ValueError:
            pass
    return None


def _extract_cwe(section: str) -> Optional[str]:
    """Extract CWE ID"""
    cwe_match = re.search(r'CWE-(\d+)', section, re.IGNORECASE)
    return f"CWE-{cwe_match.group(1)}" if cwe_match else None


# Utility functions for aggregation

def findings_by_severity(findings: List[ShannonFinding]) -> Dict[str, List[ShannonFinding]]:
    """Group findings by severity"""
    result = {s.value: [] for s in Severity}
    for finding in findings:
        result[finding.severity.value].append(finding)
    return result


def findings_by_type(findings: List[ShannonFinding]) -> Dict[str, List[ShannonFinding]]:
    """Group findings by vulnerability type"""
    result = {}
    for finding in findings:
        if finding.vulnerability_type not in result:
            result[finding.vulnerability_type] = []
        result[finding.vulnerability_type].append(finding)
    return result


def generate_summary(findings: List[ShannonFinding]) -> Dict[str, Any]:
    """Generate summary statistics"""
    by_severity = findings_by_severity(findings)
    by_type = findings_by_type(findings)

    return {
        'total': len(findings),
        'by_severity': {k: len(v) for k, v in by_severity.items()},
        'by_type': {k: len(v) for k, v in by_type.items()},
        'critical_count': len(by_severity.get('critical', [])),
        'high_count': len(by_severity.get('high', [])),
        'exploitable': len(findings),  # All Shannon findings are exploitable
        'most_common_type': max(by_type.keys(), key=lambda k: len(by_type[k])) if by_type else None
    }
