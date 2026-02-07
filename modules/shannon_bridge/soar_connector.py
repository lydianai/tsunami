"""
Shannon SOAR Connector
======================
Connects Shannon findings to TSUNAMI SOAR for automated incident response.
Creates incidents from verified vulnerabilities and triggers appropriate playbooks.
"""

import logging
from typing import List, Dict, Optional, Any
from datetime import datetime

from .result_parser import ShannonFinding, Severity

logger = logging.getLogger(__name__)


class ShannonSOARConnector:
    """Connects Shannon findings to SOAR incident management"""

    # Severity mapping to SOAR format
    SEVERITY_MAP = {
        Severity.CRITICAL: 'critical',
        Severity.HIGH: 'high',
        Severity.MEDIUM: 'medium',
        Severity.LOW: 'low',
        Severity.INFO: 'info'
    }

    # Playbook mapping by vulnerability type
    PLAYBOOK_MAP = {
        'injection': 'shannon_injection_response',
        'xss': 'shannon_xss_response',
        'ssrf': 'shannon_ssrf_response',
        'auth': 'shannon_auth_bypass_response',
        'authz': 'shannon_authz_response',
        'idor': 'shannon_authz_response',
        'file_inclusion': 'shannon_file_inclusion_response',
        'path_traversal': 'shannon_file_inclusion_response',
        'csrf': 'shannon_csrf_response',
        'sensitive_data': 'shannon_data_exposure_response',
        'misconfig': 'shannon_misconfig_response'
    }

    # MITRE ATT&CK mapping
    MITRE_MAP = {
        'injection': 'T1190',  # Exploit Public-Facing Application
        'xss': 'T1189',  # Drive-by Compromise
        'ssrf': 'T1199',  # Trusted Relationship
        'auth': 'T1078',  # Valid Accounts
        'authz': 'T1078',  # Valid Accounts
        'sensitive_data': 'T1552'  # Unsecured Credentials
    }

    def __init__(self):
        self._incident_manager = None
        self._playbook_engine = None
        self._soar_available = self._init_soar()
        self._created_incidents = []

    def _init_soar(self) -> bool:
        """Initialize SOAR modules"""
        try:
            from modules.soar_xdr.incident_manager import IncidentManager
            from modules.soar_xdr.playbook_engine import PlaybookEngine
            self._incident_manager = IncidentManager()
            self._playbook_engine = PlaybookEngine()
            logger.info("[SHANNON→SOAR] SOAR modules loaded successfully")
            return True
        except ImportError as e:
            logger.warning(f"[SHANNON→SOAR] SOAR modules not available: {e}")
            return False
        except Exception as e:
            logger.error(f"[SHANNON→SOAR] Failed to initialize SOAR: {e}")
            return False

    def is_available(self) -> bool:
        """Check if SOAR integration is available"""
        return self._soar_available

    def process_findings(
        self,
        findings: List[ShannonFinding],
        session_id: str,
        auto_playbook: bool = True
    ) -> List[Dict]:
        """
        Process all findings from a Shannon session

        Args:
            findings: List of parsed findings
            session_id: Shannon session ID
            auto_playbook: Whether to auto-trigger playbooks for critical/high

        Returns:
            List of created incidents
        """
        if not findings:
            logger.info("[SHANNON→SOAR] No findings to process")
            return []

        incidents = []

        for finding in findings:
            incident = self.create_incident(finding, session_id)
            if incident:
                incidents.append(incident)

                # Auto-trigger playbook for critical/high findings
                if auto_playbook and finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                    self.trigger_playbook(finding, incident.get('id'))

        self._created_incidents.extend(incidents)
        logger.info(f"[SHANNON→SOAR] Created {len(incidents)} incidents from session {session_id}")

        return incidents

    def create_incident(self, finding: ShannonFinding, session_id: str) -> Optional[Dict]:
        """Create SOAR incident from Shannon finding"""

        incident_data = {
            'title': f"[SHANNON] {finding.title}",
            'description': self._build_description(finding),
            'severity': self.SEVERITY_MAP.get(finding.severity, 'medium'),
            'category': 'vulnerability',
            'subcategory': finding.vulnerability_type,
            'source': 'shannon_ai_pentester',
            'source_ref': f"{session_id}/{finding.id}",
            'status': 'new',
            'priority': self._calculate_priority(finding),
            'details': {
                'vulnerability_type': finding.vulnerability_type,
                'location': finding.location,
                'method': finding.method,
                'impact': finding.impact,
                'exploitation_steps': finding.exploitation_steps,
                'proof_of_impact': finding.proof_of_impact,
                'cvss_score': finding.cvss_score,
                'cwe_id': finding.cwe_id,
                'remediation': finding.remediation,
                'exploited': True,  # Shannon only reports verified exploits
                'verified_by': 'Shannon AI Pentester',
                'verification_method': 'automated_exploitation'
            },
            'tags': self._build_tags(finding),
            'mitre_technique': self.MITRE_MAP.get(finding.vulnerability_type),
            'created_at': datetime.now().isoformat(),
            'assigned_team': self._determine_team(finding)
        }

        if self._incident_manager:
            try:
                result = self._incident_manager.create_incident(**incident_data)
                logger.info(f"[SHANNON→SOAR] Created incident for {finding.id}")
                return result
            except Exception as e:
                logger.error(f"[SHANNON→SOAR] Failed to create incident: {e}")

        # Fallback: return data as-is for logging/display
        incident_data['id'] = f"SHAN-INC-{finding.id}"
        return incident_data

    def trigger_playbook(self, finding: ShannonFinding, incident_id: Optional[str] = None):
        """Trigger appropriate response playbook"""
        playbook_id = self.PLAYBOOK_MAP.get(finding.vulnerability_type, 'shannon_generic_response')

        if not self._playbook_engine:
            logger.warning("[SHANNON→SOAR] Playbook engine not available")
            return None

        event_data = {
            'finding_id': finding.id,
            'incident_id': incident_id,
            'severity': finding.severity.value,
            'location': finding.location,
            'vuln_type': finding.vulnerability_type,
            'method': finding.method,
            'title': finding.title,
            'cwe_id': finding.cwe_id,
            'triggered_at': datetime.now().isoformat()
        }

        try:
            result = self._playbook_engine.execute_playbook(
                playbook_id=playbook_id,
                event_data=event_data
            )
            logger.info(f"[SHANNON→SOAR] Triggered playbook: {playbook_id}")
            return result
        except Exception as e:
            logger.error(f"[SHANNON→SOAR] Failed to trigger playbook: {e}")
            return None

    def _build_description(self, finding: ShannonFinding) -> str:
        """Build rich incident description"""
        desc = f"""## Shannon AI Pentester Finding

**Vulnerability:** {finding.title}
**Type:** {finding.vulnerability_type.upper()}
**Severity:** {finding.severity.value.upper()}
**Location:** `{finding.method} {finding.location}`

### Summary
{finding.summary or 'Automated security testing identified a verified vulnerability.'}

### Impact
{finding.impact or 'This vulnerability has been confirmed exploitable.'}

### Proof of Exploitation
{finding.proof_of_impact or 'Exploitation confirmed by Shannon AI Pentester.'}

### Remediation
{finding.remediation or 'Refer to security best practices for this vulnerability type.'}

---
*This incident was automatically created by Shannon AI Pentester integration.*
*Finding ID: {finding.id}*
"""
        return desc

    def _build_tags(self, finding: ShannonFinding) -> List[str]:
        """Build tag list for incident"""
        tags = [
            'shannon',
            'ai-pentest',
            'verified-exploit',
            finding.vulnerability_type,
            finding.severity.value
        ]

        if finding.cwe_id:
            tags.append(finding.cwe_id.lower())

        if finding.cvss_score:
            if finding.cvss_score >= 9.0:
                tags.append('cvss-critical')
            elif finding.cvss_score >= 7.0:
                tags.append('cvss-high')

        return tags

    def _calculate_priority(self, finding: ShannonFinding) -> int:
        """Calculate incident priority (1-5, 1 is highest)"""
        if finding.severity == Severity.CRITICAL:
            return 1
        elif finding.severity == Severity.HIGH:
            return 2
        elif finding.severity == Severity.MEDIUM:
            return 3
        elif finding.severity == Severity.LOW:
            return 4
        return 5

    def _determine_team(self, finding: ShannonFinding) -> str:
        """Determine responsible team based on vulnerability"""
        team_map = {
            'injection': 'security-critical',
            'auth': 'security-critical',
            'authz': 'security-ops',
            'xss': 'security-ops',
            'ssrf': 'security-critical',
            'sensitive_data': 'security-compliance',
            'misconfig': 'infrastructure'
        }
        return team_map.get(finding.vulnerability_type, 'security-ops')

    def get_statistics(self) -> Dict[str, Any]:
        """Get SOAR connector statistics"""
        return {
            'available': self._soar_available,
            'total_incidents_created': len(self._created_incidents),
            'by_severity': self._count_by_severity(),
            'by_type': self._count_by_type(),
            'playbooks_available': list(self.PLAYBOOK_MAP.values())
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Count incidents by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for inc in self._created_incidents:
            sev = inc.get('severity', 'medium')
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_by_type(self) -> Dict[str, int]:
        """Count incidents by vulnerability type"""
        counts = {}
        for inc in self._created_incidents:
            vtype = inc.get('details', {}).get('vulnerability_type', 'other')
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts
