"""
Cryptographic Auditing and Compliance

Provides comprehensive auditing for cryptographic operations:
- Track all crypto operations with timestamps
- Detect weak or deprecated algorithms
- Migration readiness assessment for PQC
- Compliance reporting (NIST, FIPS, etc.)
"""

import json
import hashlib
import threading
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from pathlib import Path

from .pqc_algorithms import SecurityLevel


class AuditEventType(Enum):
    """Types of cryptographic audit events."""
    KEY_GENERATION = "key_generation"
    KEY_ROTATION = "key_rotation"
    KEY_REVOCATION = "key_revocation"
    KEY_BACKUP = "key_backup"
    KEY_RESTORE = "key_restore"
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    SIGNING = "signing"
    VERIFICATION = "verification"
    CHANNEL_ESTABLISHED = "channel_established"
    CHANNEL_CLOSED = "channel_closed"
    ALGORITHM_WARNING = "algorithm_warning"
    POLICY_VIOLATION = "policy_violation"
    AUTHENTICATION_FAILURE = "authentication_failure"
    INTEGRITY_FAILURE = "integrity_failure"


class AlgorithmStatus(Enum):
    """Status of cryptographic algorithms."""
    RECOMMENDED = "recommended"      # Current best practice
    ACCEPTABLE = "acceptable"        # Still secure, not optimal
    DEPRECATED = "deprecated"        # Should not be used for new keys
    PROHIBITED = "prohibited"        # Must not be used
    QUANTUM_SAFE = "quantum_safe"    # Post-quantum secure


class ComplianceStandard(Enum):
    """Compliance standards for cryptographic operations."""
    NIST_PQC = "NIST-PQC"           # NIST Post-Quantum Cryptography
    FIPS_140_3 = "FIPS-140-3"       # FIPS 140-3
    NSA_CNSA_2 = "NSA-CNSA-2.0"     # NSA CNSA 2.0 Suite
    TSUNAMI_INTERNAL = "TSUNAMI"    # Internal TSUNAMI standards


@dataclass
class AuditEvent:
    """A single audit event."""
    event_id: str
    event_type: AuditEventType
    timestamp: datetime
    algorithm: Optional[str] = None
    key_id: Optional[str] = None
    security_level: Optional[int] = None
    success: bool = True
    error_message: Optional[str] = None
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "security_level": self.security_level,
            "success": self.success,
            "error_message": self.error_message,
            "user_id": self.user_id,
            "source_ip": self.source_ip,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEvent":
        return cls(
            event_id=data["event_id"],
            event_type=AuditEventType(data["event_type"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            algorithm=data.get("algorithm"),
            key_id=data.get("key_id"),
            security_level=data.get("security_level"),
            success=data.get("success", True),
            error_message=data.get("error_message"),
            user_id=data.get("user_id"),
            source_ip=data.get("source_ip"),
            metadata=data.get("metadata", {}),
        )


@dataclass
class AlgorithmAssessment:
    """Assessment of an algorithm's security status."""
    algorithm: str
    status: AlgorithmStatus
    quantum_safe: bool
    recommended_replacement: Optional[str] = None
    deprecation_date: Optional[datetime] = None
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "status": self.status.value,
            "quantum_safe": self.quantum_safe,
            "recommended_replacement": self.recommended_replacement,
            "deprecation_date": self.deprecation_date.isoformat() if self.deprecation_date else None,
            "notes": self.notes,
        }


@dataclass
class ComplianceReport:
    """Compliance assessment report."""
    report_id: str
    generated_at: datetime
    standard: ComplianceStandard
    compliant: bool
    score: float  # 0.0 to 100.0
    findings: List[Dict[str, Any]]
    recommendations: List[str]
    algorithm_inventory: List[AlgorithmAssessment]
    key_inventory_summary: Dict[str, Any]
    migration_readiness: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "standard": self.standard.value,
            "compliant": self.compliant,
            "score": self.score,
            "findings": self.findings,
            "recommendations": self.recommendations,
            "algorithm_inventory": [a.to_dict() for a in self.algorithm_inventory],
            "key_inventory_summary": self.key_inventory_summary,
            "migration_readiness": self.migration_readiness,
        }


class CryptoAudit:
    """
    Cryptographic Audit System

    Provides comprehensive monitoring and assessment of cryptographic operations:
    - Event logging with full audit trail
    - Algorithm security assessment
    - PQC migration readiness
    - Compliance reporting
    """

    # Algorithm security database
    ALGORITHM_DATABASE = {
        # Post-Quantum (Recommended)
        "ML-KEM-512": AlgorithmAssessment(
            algorithm="ML-KEM-512",
            status=AlgorithmStatus.QUANTUM_SAFE,
            quantum_safe=True,
            notes="NIST Level 1 PQC. Suitable for general use."
        ),
        "ML-KEM-768": AlgorithmAssessment(
            algorithm="ML-KEM-768",
            status=AlgorithmStatus.QUANTUM_SAFE,
            quantum_safe=True,
            notes="NIST Level 3 PQC. Recommended for most applications."
        ),
        "ML-KEM-1024": AlgorithmAssessment(
            algorithm="ML-KEM-1024",
            status=AlgorithmStatus.QUANTUM_SAFE,
            quantum_safe=True,
            notes="NIST Level 5 PQC. Maximum security."
        ),
        "ML-DSA-44": AlgorithmAssessment(
            algorithm="ML-DSA-44",
            status=AlgorithmStatus.QUANTUM_SAFE,
            quantum_safe=True,
            notes="NIST Level 2 PQC signatures."
        ),
        "ML-DSA-65": AlgorithmAssessment(
            algorithm="ML-DSA-65",
            status=AlgorithmStatus.QUANTUM_SAFE,
            quantum_safe=True,
            notes="NIST Level 3 PQC signatures. Recommended."
        ),
        "ML-DSA-87": AlgorithmAssessment(
            algorithm="ML-DSA-87",
            status=AlgorithmStatus.QUANTUM_SAFE,
            quantum_safe=True,
            notes="NIST Level 5 PQC signatures."
        ),

        # Classical (Acceptable for hybrid, deprecated alone)
        "X25519": AlgorithmAssessment(
            algorithm="X25519",
            status=AlgorithmStatus.ACCEPTABLE,
            quantum_safe=False,
            recommended_replacement="ML-KEM-768",
            deprecation_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
            notes="Secure against classical attacks. Use in hybrid mode with PQC."
        ),
        "Ed25519": AlgorithmAssessment(
            algorithm="Ed25519",
            status=AlgorithmStatus.ACCEPTABLE,
            quantum_safe=False,
            recommended_replacement="ML-DSA-65",
            deprecation_date=datetime(2030, 1, 1, tzinfo=timezone.utc),
            notes="Secure against classical attacks. Use in hybrid mode with PQC."
        ),

        # Symmetric (Quantum-resistant with sufficient key size)
        "AES-256-GCM": AlgorithmAssessment(
            algorithm="AES-256-GCM",
            status=AlgorithmStatus.RECOMMENDED,
            quantum_safe=True,  # 128-bit security against Grover's
            notes="Quantum-resistant with 256-bit keys."
        ),
        "ChaCha20-Poly1305": AlgorithmAssessment(
            algorithm="ChaCha20-Poly1305",
            status=AlgorithmStatus.RECOMMENDED,
            quantum_safe=True,  # 128-bit security against Grover's
            notes="Quantum-resistant, excellent for software implementations."
        ),

        # Deprecated/Prohibited
        "RSA-2048": AlgorithmAssessment(
            algorithm="RSA-2048",
            status=AlgorithmStatus.DEPRECATED,
            quantum_safe=False,
            recommended_replacement="ML-KEM-768+X25519",
            deprecation_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            notes="Vulnerable to quantum attacks. Migrate to PQC."
        ),
        "ECDSA-P256": AlgorithmAssessment(
            algorithm="ECDSA-P256",
            status=AlgorithmStatus.DEPRECATED,
            quantum_safe=False,
            recommended_replacement="ML-DSA-65+Ed25519",
            deprecation_date=datetime(2025, 1, 1, tzinfo=timezone.utc),
            notes="Vulnerable to quantum attacks. Migrate to PQC."
        ),
        "3DES": AlgorithmAssessment(
            algorithm="3DES",
            status=AlgorithmStatus.PROHIBITED,
            quantum_safe=False,
            recommended_replacement="AES-256-GCM",
            notes="Prohibited. Insufficient security."
        ),
    }

    def __init__(
        self,
        storage_path: Optional[str] = None,
        max_events: int = 100000,
        alert_callback: Optional[Callable[[AuditEvent], None]] = None
    ):
        """
        Initialize the audit system.

        Args:
            storage_path: Path for persistent audit log storage
            max_events: Maximum events to keep in memory
            alert_callback: Callback for critical audit events
        """
        self.storage_path = Path(storage_path) if storage_path else None
        self.max_events = max_events
        self.alert_callback = alert_callback

        self._events: List[AuditEvent] = []
        self._events_lock = threading.Lock()
        self._event_counter = 0

        # Statistics
        self._stats = defaultdict(int)
        self._algorithm_usage = defaultdict(int)
        self._key_usage = defaultdict(int)

        # Load existing events
        if self.storage_path:
            self._load_from_storage()

    def _generate_event_id(self) -> str:
        """Generate a unique event identifier."""
        self._event_counter += 1
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return f"EVT-{timestamp}-{self._event_counter:06d}"

    # ==================== EVENT LOGGING ====================

    def log_event(
        self,
        event_type: AuditEventType,
        algorithm: Optional[str] = None,
        key_id: Optional[str] = None,
        security_level: Optional[int] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> AuditEvent:
        """
        Log an audit event.

        Args:
            event_type: Type of cryptographic event
            algorithm: Algorithm used
            key_id: Key identifier involved
            security_level: NIST security level
            success: Whether operation succeeded
            error_message: Error message if failed
            user_id: User who initiated the operation
            source_ip: Source IP address
            metadata: Additional metadata

        Returns:
            The created AuditEvent
        """
        event = AuditEvent(
            event_id=self._generate_event_id(),
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            algorithm=algorithm,
            key_id=key_id,
            security_level=security_level,
            success=success,
            error_message=error_message,
            user_id=user_id,
            source_ip=source_ip,
            metadata=metadata or {},
        )

        with self._events_lock:
            self._events.append(event)

            # Trim if over limit
            if len(self._events) > self.max_events:
                self._events = self._events[-self.max_events:]

            # Update statistics
            self._stats[event_type.value] += 1
            if algorithm:
                self._algorithm_usage[algorithm] += 1
            if key_id:
                self._key_usage[key_id] += 1

        # Check for algorithm warnings
        if algorithm:
            self._check_algorithm_security(event)

        # Trigger alerts for critical events
        if not success or event_type in [
            AuditEventType.POLICY_VIOLATION,
            AuditEventType.AUTHENTICATION_FAILURE,
            AuditEventType.INTEGRITY_FAILURE,
        ]:
            if self.alert_callback:
                self.alert_callback(event)

        # Persist to storage
        if self.storage_path:
            self._append_to_storage(event)

        return event

    def _check_algorithm_security(self, event: AuditEvent) -> None:
        """Check if the algorithm triggers any security warnings."""
        assessment = self.ALGORITHM_DATABASE.get(event.algorithm)
        if not assessment:
            return

        if assessment.status in [AlgorithmStatus.DEPRECATED, AlgorithmStatus.PROHIBITED]:
            warning_event = AuditEvent(
                event_id=self._generate_event_id(),
                event_type=AuditEventType.ALGORITHM_WARNING,
                timestamp=datetime.now(timezone.utc),
                algorithm=event.algorithm,
                key_id=event.key_id,
                success=True,
                metadata={
                    "original_event_id": event.event_id,
                    "algorithm_status": assessment.status.value,
                    "recommended_replacement": assessment.recommended_replacement,
                    "warning": f"Algorithm {event.algorithm} is {assessment.status.value}",
                },
            )

            with self._events_lock:
                self._events.append(warning_event)

            if self.alert_callback:
                self.alert_callback(warning_event)

    # ==================== QUERIES ====================

    def get_events(
        self,
        event_type: Optional[AuditEventType] = None,
        algorithm: Optional[str] = None,
        key_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        success_only: bool = False,
        limit: int = 1000
    ) -> List[AuditEvent]:
        """
        Query audit events.

        Args:
            event_type: Filter by event type
            algorithm: Filter by algorithm
            key_id: Filter by key ID
            start_time: Filter events after this time
            end_time: Filter events before this time
            success_only: Only return successful events
            limit: Maximum events to return

        Returns:
            List of matching AuditEvents
        """
        results = []

        with self._events_lock:
            for event in reversed(self._events):
                if event_type and event.event_type != event_type:
                    continue
                if algorithm and event.algorithm != algorithm:
                    continue
                if key_id and event.key_id != key_id:
                    continue
                if start_time and event.timestamp < start_time:
                    continue
                if end_time and event.timestamp > end_time:
                    continue
                if success_only and not event.success:
                    continue

                results.append(event)
                if len(results) >= limit:
                    break

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get audit statistics."""
        with self._events_lock:
            return {
                "total_events": len(self._events),
                "event_counts": dict(self._stats),
                "algorithm_usage": dict(self._algorithm_usage),
                "key_usage_count": len(self._key_usage),
                "first_event": self._events[0].timestamp.isoformat() if self._events else None,
                "last_event": self._events[-1].timestamp.isoformat() if self._events else None,
            }

    # ==================== ALGORITHM ASSESSMENT ====================

    def assess_algorithm(self, algorithm: str) -> AlgorithmAssessment:
        """
        Assess an algorithm's security status.

        Args:
            algorithm: Algorithm name to assess

        Returns:
            AlgorithmAssessment with status and recommendations
        """
        if algorithm in self.ALGORITHM_DATABASE:
            return self.ALGORITHM_DATABASE[algorithm]

        # Unknown algorithm - conservative assessment
        return AlgorithmAssessment(
            algorithm=algorithm,
            status=AlgorithmStatus.DEPRECATED,
            quantum_safe=False,
            notes="Unknown algorithm. Assume vulnerable until verified."
        )

    def detect_weak_algorithms(self) -> List[Dict[str, Any]]:
        """
        Detect weak algorithms currently in use.

        Returns:
            List of weak algorithm findings
        """
        findings = []

        with self._events_lock:
            algorithms_in_use = set(self._algorithm_usage.keys())

        for algo in algorithms_in_use:
            assessment = self.assess_algorithm(algo)
            if assessment.status in [AlgorithmStatus.DEPRECATED, AlgorithmStatus.PROHIBITED]:
                findings.append({
                    "algorithm": algo,
                    "status": assessment.status.value,
                    "usage_count": self._algorithm_usage.get(algo, 0),
                    "quantum_safe": assessment.quantum_safe,
                    "recommended_replacement": assessment.recommended_replacement,
                    "severity": "critical" if assessment.status == AlgorithmStatus.PROHIBITED else "high",
                })
            elif not assessment.quantum_safe:
                findings.append({
                    "algorithm": algo,
                    "status": assessment.status.value,
                    "usage_count": self._algorithm_usage.get(algo, 0),
                    "quantum_safe": False,
                    "recommended_replacement": assessment.recommended_replacement,
                    "severity": "medium",
                })

        return sorted(findings, key=lambda x: {"critical": 0, "high": 1, "medium": 2}.get(x["severity"], 3))

    # ==================== MIGRATION READINESS ====================

    def assess_pqc_migration_readiness(
        self,
        key_inventory: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Assess readiness for post-quantum cryptography migration.

        Args:
            key_inventory: Optional key inventory from KeyManager

        Returns:
            Migration readiness assessment
        """
        with self._events_lock:
            algorithms_in_use = dict(self._algorithm_usage)

        # Categorize algorithms
        pqc_algorithms = []
        hybrid_algorithms = []
        classical_only = []
        deprecated_algorithms = []

        for algo, count in algorithms_in_use.items():
            assessment = self.assess_algorithm(algo)

            if "+" in algo:  # Hybrid indicator
                hybrid_algorithms.append({"algorithm": algo, "usage": count})
            elif assessment.quantum_safe and assessment.status == AlgorithmStatus.QUANTUM_SAFE:
                pqc_algorithms.append({"algorithm": algo, "usage": count})
            elif assessment.status in [AlgorithmStatus.DEPRECATED, AlgorithmStatus.PROHIBITED]:
                deprecated_algorithms.append({
                    "algorithm": algo,
                    "usage": count,
                    "replacement": assessment.recommended_replacement,
                })
            else:
                classical_only.append({
                    "algorithm": algo,
                    "usage": count,
                    "replacement": assessment.recommended_replacement,
                })

        # Calculate readiness score
        total_usage = sum(algorithms_in_use.values()) or 1
        pqc_usage = sum(a["usage"] for a in pqc_algorithms)
        hybrid_usage = sum(a["usage"] for a in hybrid_algorithms)
        deprecated_usage = sum(a["usage"] for a in deprecated_algorithms)

        # Score: 100 = all PQC, 50 = all hybrid, 0 = deprecated/classical
        score = (
            (pqc_usage / total_usage) * 100 +
            (hybrid_usage / total_usage) * 50 -
            (deprecated_usage / total_usage) * 50
        )
        score = max(0, min(100, score))

        # Determine readiness level
        if score >= 80:
            readiness_level = "READY"
        elif score >= 50:
            readiness_level = "PARTIAL"
        elif score >= 20:
            readiness_level = "IN_PROGRESS"
        else:
            readiness_level = "NOT_STARTED"

        return {
            "readiness_level": readiness_level,
            "readiness_score": round(score, 2),
            "pqc_algorithms": pqc_algorithms,
            "hybrid_algorithms": hybrid_algorithms,
            "classical_algorithms": classical_only,
            "deprecated_algorithms": deprecated_algorithms,
            "recommendations": self._generate_migration_recommendations(
                pqc_algorithms, hybrid_algorithms, classical_only, deprecated_algorithms
            ),
        }

    def _generate_migration_recommendations(
        self,
        pqc: List,
        hybrid: List,
        classical: List,
        deprecated: List
    ) -> List[str]:
        """Generate migration recommendations."""
        recommendations = []

        if deprecated:
            recommendations.append(
                f"CRITICAL: {len(deprecated)} deprecated algorithm(s) in use. "
                "Migrate immediately to prevent security vulnerabilities."
            )
            for algo in deprecated:
                recommendations.append(
                    f"  - Replace {algo['algorithm']} with {algo['replacement']}"
                )

        if classical and not hybrid:
            recommendations.append(
                "HIGH: Classical-only algorithms detected. "
                "Enable hybrid mode to prepare for quantum threats."
            )

        if not pqc and not hybrid:
            recommendations.append(
                "HIGH: No post-quantum algorithms in use. "
                "Begin migration to ML-KEM and ML-DSA."
            )

        if hybrid and not pqc:
            recommendations.append(
                "MEDIUM: Using hybrid mode. Consider testing PQC-only "
                "mode for applications not requiring backward compatibility."
            )

        if pqc and (classical or hybrid):
            recommendations.append(
                "INFO: Migration in progress. Continue transitioning "
                "remaining workloads to PQC-only mode."
            )

        if pqc and not classical and not deprecated:
            recommendations.append(
                "INFO: Excellent! All cryptographic operations are "
                "post-quantum secure. Continue monitoring for updates."
            )

        return recommendations

    # ==================== COMPLIANCE REPORTING ====================

    def generate_compliance_report(
        self,
        standard: ComplianceStandard = ComplianceStandard.NIST_PQC,
        key_inventory: Optional[Dict[str, Any]] = None
    ) -> ComplianceReport:
        """
        Generate a compliance report for a specific standard.

        Args:
            standard: Compliance standard to assess against
            key_inventory: Optional key inventory from KeyManager

        Returns:
            ComplianceReport with findings and recommendations
        """
        import secrets as py_secrets

        findings = []
        recommendations = []

        # Get algorithm inventory
        algorithm_inventory = []
        with self._events_lock:
            for algo in self._algorithm_usage.keys():
                algorithm_inventory.append(self.assess_algorithm(algo))

        # Get weak algorithms
        weak_algos = self.detect_weak_algorithms()
        for weak in weak_algos:
            findings.append({
                "severity": weak["severity"],
                "finding": f"Weak algorithm in use: {weak['algorithm']}",
                "recommendation": f"Migrate to {weak['recommended_replacement']}",
            })

        # Get migration readiness
        migration = self.assess_pqc_migration_readiness(key_inventory)
        recommendations.extend(migration.get("recommendations", []))

        # Calculate compliance score
        score = migration.get("readiness_score", 0)

        # Adjust score based on findings
        for finding in findings:
            if finding["severity"] == "critical":
                score -= 20
            elif finding["severity"] == "high":
                score -= 10
            elif finding["severity"] == "medium":
                score -= 5
        score = max(0, min(100, score))

        # Determine compliance
        if standard == ComplianceStandard.NIST_PQC:
            compliant = score >= 80 and not any(f["severity"] == "critical" for f in findings)
        elif standard == ComplianceStandard.NSA_CNSA_2:
            compliant = score >= 90 and not weak_algos
        else:
            compliant = score >= 70

        # Key inventory summary
        key_summary = {}
        if key_inventory:
            key_summary = {
                "total_keys": len(key_inventory),
                "pqc_keys": sum(1 for k in key_inventory.values() if "ML-" in k.get("algorithm", "")),
                "hybrid_keys": sum(1 for k in key_inventory.values() if "+" in k.get("algorithm", "")),
            }

        return ComplianceReport(
            report_id=f"RPT-{py_secrets.token_hex(8)}",
            generated_at=datetime.now(timezone.utc),
            standard=standard,
            compliant=compliant,
            score=round(score, 2),
            findings=findings,
            recommendations=recommendations,
            algorithm_inventory=algorithm_inventory,
            key_inventory_summary=key_summary,
            migration_readiness=migration,
        )

    # ==================== STORAGE ====================

    def _append_to_storage(self, event: AuditEvent) -> None:
        """Append an event to persistent storage."""
        if not self.storage_path:
            return

        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Use date-based log files
        log_date = event.timestamp.strftime("%Y-%m-%d")
        log_file = self.storage_path / f"audit_{log_date}.jsonl"

        with open(log_file, "a") as f:
            f.write(json.dumps(event.to_dict()) + "\n")

    def _load_from_storage(self) -> None:
        """Load events from persistent storage."""
        if not self.storage_path or not self.storage_path.exists():
            return

        try:
            # Load recent log files
            log_files = sorted(self.storage_path.glob("audit_*.jsonl"))[-30:]  # Last 30 days

            for log_file in log_files:
                with open(log_file, "r") as f:
                    for line in f:
                        try:
                            event = AuditEvent.from_dict(json.loads(line.strip()))
                            self._events.append(event)
                            self._stats[event.event_type.value] += 1
                            if event.algorithm:
                                self._algorithm_usage[event.algorithm] += 1
                            if event.key_id:
                                self._key_usage[event.key_id] += 1
                        except Exception:
                            continue

            # Trim to max events
            if len(self._events) > self.max_events:
                self._events = self._events[-self.max_events:]

        except Exception:
            pass

    def export_audit_log(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None
    ) -> List[Dict[str, Any]]:
        """Export audit log for external analysis."""
        events = self.get_events(start_time=start_time, end_time=end_time, limit=self.max_events)
        return [e.to_dict() for e in events]
