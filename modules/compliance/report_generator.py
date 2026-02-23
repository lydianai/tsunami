#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Compliance Report Generator
    NIST SP 800-61 / ISO 27001 Annex A / KVKK-GDPR Reporting Engine
================================================================================

    Features:
    - NIST SP 800-61 incident response lifecycle mapping
    - ISO 27001 Annex A control mapping (14 domains, 114 controls)
    - KVKK (Turkish GDPR) / EU-GDPR breach notification report
    - PDF report generation via ReportLab
    - Periodic report scheduling (daily, weekly, monthly)
    - Executive summary dashboard data
    - Compliance score calculation per framework
    - Control gap analysis
    - Evidence collection and linking
    - Historical trend tracking (SQLite)
    - Thread-safe operations
    - Flask Blueprint REST API

================================================================================
"""

import json
import logging
import os
import sqlite3
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from io import BytesIO
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("tsunami.compliance.report_generator")

# =============================================================================
#   ENUMS
# =============================================================================


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    NIST_800_61 = "nist_800_61"
    ISO_27001 = "iso_27001"
    KVKK = "kvkk"
    GDPR = "gdpr"


class ReportType(str, Enum):
    """Report types."""
    INCIDENT = "incident"
    COMPLIANCE_AUDIT = "compliance_audit"
    BREACH_NOTIFICATION = "breach_notification"
    EXECUTIVE_SUMMARY = "executive_summary"
    PERIODIC = "periodic"
    GAP_ANALYSIS = "gap_analysis"


class ReportFormat(str, Enum):
    """Output formats."""
    PDF = "pdf"
    JSON = "json"
    HTML = "html"


class ReportPeriod(str, Enum):
    """Periodic report intervals."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    ANNUAL = "annual"


class ControlStatus(str, Enum):
    """Control implementation status."""
    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    PLANNED = "planned"
    NOT_IMPLEMENTED = "not_implemented"
    NOT_APPLICABLE = "not_applicable"


class NISTPhase(str, Enum):
    """NIST SP 800-61 incident response phases."""
    PREPARATION = "preparation"
    DETECTION_ANALYSIS = "detection_analysis"
    CONTAINMENT_ERADICATION_RECOVERY = "containment_eradication_recovery"
    POST_INCIDENT = "post_incident"


class SeverityLevel(str, Enum):
    """Incident severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# =============================================================================
#   NIST SP 800-61 MAPPING
# =============================================================================

NIST_800_61_PHASES: Dict[str, Dict[str, Any]] = {
    NISTPhase.PREPARATION.value: {
        "title": "Preparation",
        "title_tr": "Hazırlık",
        "description": "Establishing an incident response capability",
        "controls": [
            {"id": "PR-1", "name": "Incident Response Plan", "name_tr": "Olay Müdahale Planı",
             "description": "Documented incident response procedures"},
            {"id": "PR-2", "name": "Communication Plan", "name_tr": "İletişim Planı",
             "description": "Internal and external communication procedures"},
            {"id": "PR-3", "name": "Team Training", "name_tr": "Ekip Eğitimi",
             "description": "Regular training and exercises for IR team"},
            {"id": "PR-4", "name": "Tools & Resources", "name_tr": "Araçlar ve Kaynaklar",
             "description": "Hardware, software, and documentation for IR"},
            {"id": "PR-5", "name": "Threat Intelligence", "name_tr": "Tehdit İstihbaratı",
             "description": "Threat intelligence feeds and sharing"},
        ],
    },
    NISTPhase.DETECTION_ANALYSIS.value: {
        "title": "Detection & Analysis",
        "title_tr": "Tespit ve Analiz",
        "description": "Detecting and analyzing potential incidents",
        "controls": [
            {"id": "DA-1", "name": "Log Collection", "name_tr": "Log Toplama",
             "description": "Centralized log collection and retention"},
            {"id": "DA-2", "name": "SIEM Integration", "name_tr": "SIEM Entegrasyonu",
             "description": "SIEM correlation and alerting"},
            {"id": "DA-3", "name": "IDS/IPS", "name_tr": "IDS/IPS",
             "description": "Network and host-based intrusion detection"},
            {"id": "DA-4", "name": "Alert Triage", "name_tr": "Alarm Önceliklendirme",
             "description": "Alert prioritization and triage process"},
            {"id": "DA-5", "name": "Incident Classification", "name_tr": "Olay Sınıflandırma",
             "description": "Taxonomy-based incident categorization"},
            {"id": "DA-6", "name": "IOC Analysis", "name_tr": "IOC Analizi",
             "description": "Indicator of compromise enrichment"},
        ],
    },
    NISTPhase.CONTAINMENT_ERADICATION_RECOVERY.value: {
        "title": "Containment, Eradication & Recovery",
        "title_tr": "Sınırlama, Temizleme ve Kurtarma",
        "description": "Containing, eradicating, and recovering from incidents",
        "controls": [
            {"id": "CER-1", "name": "Containment Strategy", "name_tr": "Sınırlama Stratejisi",
             "description": "Short-term and long-term containment strategies"},
            {"id": "CER-2", "name": "Evidence Collection", "name_tr": "Delil Toplama",
             "description": "Forensic evidence preservation"},
            {"id": "CER-3", "name": "Eradication", "name_tr": "Temizleme",
             "description": "Eliminating root cause of incident"},
            {"id": "CER-4", "name": "Recovery", "name_tr": "Kurtarma",
             "description": "System restoration and validation"},
            {"id": "CER-5", "name": "Automated Response", "name_tr": "Otomatik Müdahale",
             "description": "Automated containment and response actions"},
        ],
    },
    NISTPhase.POST_INCIDENT.value: {
        "title": "Post-Incident Activity",
        "title_tr": "Olay Sonrası Faaliyet",
        "description": "Learning from and improving after incidents",
        "controls": [
            {"id": "PI-1", "name": "Lessons Learned", "name_tr": "Alınan Dersler",
             "description": "Post-incident review meetings"},
            {"id": "PI-2", "name": "Metrics Collection", "name_tr": "Metrik Toplama",
             "description": "MTTD, MTTR, incident count tracking"},
            {"id": "PI-3", "name": "Process Improvement", "name_tr": "Süreç İyileştirme",
             "description": "Updating procedures based on lessons learned"},
            {"id": "PI-4", "name": "Reporting", "name_tr": "Raporlama",
             "description": "Compliance and management reporting"},
        ],
    },
}

# =============================================================================
#   ISO 27001 ANNEX A MAPPING (2022 revision - 4 themes, 93 controls)
# =============================================================================

ISO_27001_DOMAINS: Dict[str, Dict[str, Any]] = {
    "A5": {
        "title": "Organizational Controls",
        "title_tr": "Organizasyonel Kontroller",
        "control_count": 37,
        "controls": [
            {"id": "A.5.1", "name": "Policies for information security",
             "name_tr": "Bilgi güvenliği politikaları"},
            {"id": "A.5.2", "name": "Information security roles and responsibilities",
             "name_tr": "Bilgi güvenliği rolleri ve sorumlulukları"},
            {"id": "A.5.3", "name": "Segregation of duties", "name_tr": "Görevler ayrılığı"},
            {"id": "A.5.4", "name": "Management responsibilities", "name_tr": "Yönetim sorumlulukları"},
            {"id": "A.5.5", "name": "Contact with authorities", "name_tr": "Yetkililerle iletişim"},
            {"id": "A.5.6", "name": "Contact with special interest groups",
             "name_tr": "Özel ilgi gruplarıyla iletişim"},
            {"id": "A.5.7", "name": "Threat intelligence", "name_tr": "Tehdit istihbaratı"},
            {"id": "A.5.8", "name": "Information security in project management",
             "name_tr": "Proje yönetiminde bilgi güvenliği"},
            {"id": "A.5.24", "name": "Information security incident management planning",
             "name_tr": "Bilgi güvenliği olay yönetimi planlama"},
            {"id": "A.5.25", "name": "Assessment and decision on information security events",
             "name_tr": "Bilgi güvenliği olaylarının değerlendirilmesi"},
            {"id": "A.5.26", "name": "Response to information security incidents",
             "name_tr": "Bilgi güvenliği olaylarına müdahale"},
            {"id": "A.5.27", "name": "Learning from information security incidents",
             "name_tr": "Bilgi güvenliği olaylarından öğrenme"},
            {"id": "A.5.28", "name": "Collection of evidence", "name_tr": "Delil toplama"},
        ],
    },
    "A6": {
        "title": "People Controls",
        "title_tr": "İnsan Kontrolleri",
        "control_count": 8,
        "controls": [
            {"id": "A.6.1", "name": "Screening", "name_tr": "Tarama"},
            {"id": "A.6.2", "name": "Terms and conditions of employment",
             "name_tr": "İstihdam şartları"},
            {"id": "A.6.3", "name": "Information security awareness, education and training",
             "name_tr": "Bilgi güvenliği farkındalığı ve eğitimi"},
            {"id": "A.6.4", "name": "Disciplinary process", "name_tr": "Disiplin süreci"},
            {"id": "A.6.5", "name": "Responsibilities after termination or change of employment",
             "name_tr": "İstihdam sonrası sorumluluklar"},
        ],
    },
    "A7": {
        "title": "Physical Controls",
        "title_tr": "Fiziksel Kontroller",
        "control_count": 14,
        "controls": [
            {"id": "A.7.1", "name": "Physical security perimeters",
             "name_tr": "Fiziksel güvenlik çevreleri"},
            {"id": "A.7.2", "name": "Physical entry", "name_tr": "Fiziksel giriş"},
            {"id": "A.7.4", "name": "Physical security monitoring",
             "name_tr": "Fiziksel güvenlik izleme"},
        ],
    },
    "A8": {
        "title": "Technological Controls",
        "title_tr": "Teknolojik Kontroller",
        "control_count": 34,
        "controls": [
            {"id": "A.8.1", "name": "User endpoint devices",
             "name_tr": "Kullanıcı uç cihazları"},
            {"id": "A.8.2", "name": "Privileged access rights",
             "name_tr": "Ayrıcalıklı erişim hakları"},
            {"id": "A.8.5", "name": "Secure authentication",
             "name_tr": "Güvenli kimlik doğrulama"},
            {"id": "A.8.7", "name": "Protection against malware",
             "name_tr": "Zararlı yazılımlara karşı koruma"},
            {"id": "A.8.8", "name": "Management of technical vulnerabilities",
             "name_tr": "Teknik zafiyet yönetimi"},
            {"id": "A.8.15", "name": "Logging", "name_tr": "Kayıt tutma"},
            {"id": "A.8.16", "name": "Monitoring activities",
             "name_tr": "İzleme faaliyetleri"},
            {"id": "A.8.20", "name": "Networks security",
             "name_tr": "Ağ güvenliği"},
            {"id": "A.8.22", "name": "Web filtering", "name_tr": "Web filtreleme"},
            {"id": "A.8.23", "name": "Information security for use of cloud services",
             "name_tr": "Bulut hizmetlerinde bilgi güvenliği"},
            {"id": "A.8.24", "name": "Use of cryptography",
             "name_tr": "Kriptografi kullanımı"},
            {"id": "A.8.28", "name": "Secure coding", "name_tr": "Güvenli kodlama"},
        ],
    },
}

# =============================================================================
#   KVKK / GDPR BREACH NOTIFICATION FIELDS
# =============================================================================

KVKK_NOTIFICATION_FIELDS: List[Dict[str, str]] = [
    {"id": "KV-1", "field": "breach_date", "label": "İhlalin gerçekleştiği tarih",
     "label_en": "Date of breach occurrence"},
    {"id": "KV-2", "field": "discovery_date", "label": "İhlalin tespit edildiği tarih",
     "label_en": "Date of breach discovery"},
    {"id": "KV-3", "field": "notification_date", "label": "Bildirim tarihi",
     "label_en": "Notification date"},
    {"id": "KV-4", "field": "breach_description", "label": "İhlalin niteliği ve kapsamı",
     "label_en": "Nature and scope of the breach"},
    {"id": "KV-5", "field": "data_categories", "label": "Etkilenen kişisel veri kategorileri",
     "label_en": "Categories of personal data affected"},
    {"id": "KV-6", "field": "affected_count", "label": "Etkilenen kişi sayısı",
     "label_en": "Number of affected individuals"},
    {"id": "KV-7", "field": "consequences", "label": "Muhtemel sonuçlar",
     "label_en": "Likely consequences of the breach"},
    {"id": "KV-8", "field": "measures_taken", "label": "Alınan ve alınacak önlemler",
     "label_en": "Measures taken and to be taken"},
    {"id": "KV-9", "field": "dpo_contact", "label": "Veri Koruma Görevlisi iletişim bilgileri",
     "label_en": "DPO contact information"},
    {"id": "KV-10", "field": "data_subjects_notified", "label": "İlgili kişilere bildirim durumu",
     "label_en": "Whether data subjects have been notified"},
    {"id": "KV-11", "field": "cross_border", "label": "Sınır ötesi veri aktarımı olup olmadığı",
     "label_en": "Whether cross-border data transfer is involved"},
    {"id": "KV-12", "field": "legal_basis", "label": "Veri işleme hukuki dayanağı",
     "label_en": "Legal basis for data processing"},
]

# =============================================================================
#   DATA CLASSES
# =============================================================================


@dataclass
class ControlAssessment:
    """Single control assessment result."""
    control_id: str
    control_name: str = ""
    framework: str = ""
    status: str = ControlStatus.NOT_IMPLEMENTED.value
    score: float = 0.0  # 0.0 to 1.0
    evidence: str = ""
    notes: str = ""
    assessor: str = ""
    assessed_at: str = ""
    id: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.assessed_at:
            self.assessed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ControlAssessment":
        valid = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid})


@dataclass
class IncidentRecord:
    """Incident record for compliance reporting."""
    incident_id: str
    title: str = ""
    severity: str = SeverityLevel.MEDIUM.value
    status: str = "open"
    detected_at: str = ""
    contained_at: str = ""
    resolved_at: str = ""
    nist_phase: str = NISTPhase.DETECTION_ANALYSIS.value
    category: str = ""
    source: str = ""
    affected_assets: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    lessons_learned: str = ""
    analyst: str = ""
    id: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.detected_at:
            self.detected_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IncidentRecord":
        valid = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid})


@dataclass
class BreachNotification:
    """KVKK/GDPR breach notification record."""
    breach_id: str
    breach_date: str = ""
    discovery_date: str = ""
    notification_date: str = ""
    breach_description: str = ""
    data_categories: List[str] = field(default_factory=list)
    affected_count: int = 0
    consequences: str = ""
    measures_taken: str = ""
    dpo_contact: str = ""
    data_subjects_notified: bool = False
    cross_border: bool = False
    legal_basis: str = ""
    severity: str = SeverityLevel.HIGH.value
    framework: str = ComplianceFramework.KVKK.value
    status: str = "draft"
    id: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.discovery_date:
            self.discovery_date = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "BreachNotification":
        valid = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid})


@dataclass
class ComplianceReport:
    """Generated compliance report metadata."""
    report_id: str
    title: str = ""
    report_type: str = ReportType.COMPLIANCE_AUDIT.value
    framework: str = ComplianceFramework.NIST_800_61.value
    period: str = ReportPeriod.MONTHLY.value
    generated_at: str = ""
    generated_by: str = "TSUNAMI SOC"
    period_start: str = ""
    period_end: str = ""
    total_score: float = 0.0
    control_count: int = 0
    implemented_count: int = 0
    gap_count: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    data: Dict[str, Any] = field(default_factory=dict)
    format: str = ReportFormat.JSON.value
    file_path: str = ""
    id: str = ""

    def __post_init__(self):
        if not self.id:
            self.id = str(uuid.uuid4())
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()
        if not self.report_id:
            self.report_id = self.id

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceReport":
        valid = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in data.items() if k in valid})


# =============================================================================
#   COMPLIANCE STORE (SQLite)
# =============================================================================


class ComplianceStore:
    """SQLite-backed storage for compliance data."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_path = os.path.join(os.path.dirname(__file__), "compliance.db")
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS control_assessments (
                    id TEXT PRIMARY KEY,
                    control_id TEXT NOT NULL,
                    control_name TEXT DEFAULT '',
                    framework TEXT DEFAULT '',
                    status TEXT DEFAULT 'not_implemented',
                    score REAL DEFAULT 0.0,
                    evidence TEXT DEFAULT '',
                    notes TEXT DEFAULT '',
                    assessor TEXT DEFAULT '',
                    assessed_at TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    title TEXT DEFAULT '',
                    severity TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'open',
                    detected_at TEXT DEFAULT '',
                    contained_at TEXT DEFAULT '',
                    resolved_at TEXT DEFAULT '',
                    nist_phase TEXT DEFAULT 'detection_analysis',
                    category TEXT DEFAULT '',
                    source TEXT DEFAULT '',
                    affected_assets TEXT DEFAULT '[]',
                    iocs TEXT DEFAULT '[]',
                    actions_taken TEXT DEFAULT '[]',
                    lessons_learned TEXT DEFAULT '',
                    analyst TEXT DEFAULT ''
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS breach_notifications (
                    id TEXT PRIMARY KEY,
                    breach_id TEXT NOT NULL,
                    breach_date TEXT DEFAULT '',
                    discovery_date TEXT DEFAULT '',
                    notification_date TEXT DEFAULT '',
                    breach_description TEXT DEFAULT '',
                    data_categories TEXT DEFAULT '[]',
                    affected_count INTEGER DEFAULT 0,
                    consequences TEXT DEFAULT '',
                    measures_taken TEXT DEFAULT '',
                    dpo_contact TEXT DEFAULT '',
                    data_subjects_notified INTEGER DEFAULT 0,
                    cross_border INTEGER DEFAULT 0,
                    legal_basis TEXT DEFAULT '',
                    severity TEXT DEFAULT 'high',
                    framework TEXT DEFAULT 'kvkk',
                    status TEXT DEFAULT 'draft'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id TEXT PRIMARY KEY,
                    report_id TEXT NOT NULL,
                    title TEXT DEFAULT '',
                    report_type TEXT DEFAULT 'compliance_audit',
                    framework TEXT DEFAULT 'nist_800_61',
                    period TEXT DEFAULT 'monthly',
                    generated_at TEXT DEFAULT '',
                    generated_by TEXT DEFAULT 'TSUNAMI SOC',
                    period_start TEXT DEFAULT '',
                    period_end TEXT DEFAULT '',
                    total_score REAL DEFAULT 0.0,
                    control_count INTEGER DEFAULT 0,
                    implemented_count INTEGER DEFAULT 0,
                    gap_count INTEGER DEFAULT 0,
                    findings TEXT DEFAULT '[]',
                    data TEXT DEFAULT '{}',
                    format TEXT DEFAULT 'json',
                    file_path TEXT DEFAULT ''
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ca_framework ON control_assessments(framework)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ca_control_id ON control_assessments(control_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_severity ON incidents(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_status ON incidents(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_inc_detected ON incidents(detected_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_bn_framework ON breach_notifications(framework)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rep_type ON reports(report_type)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_rep_framework ON reports(framework)")
            conn.commit()
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    # -- Control Assessments --

    def save_assessment(self, assessment: ControlAssessment) -> ControlAssessment:
        with self._lock:
            conn = self._conn()
            d = assessment.to_dict()
            conn.execute("""
                INSERT OR REPLACE INTO control_assessments
                (id, control_id, control_name, framework, status, score, evidence, notes, assessor, assessed_at)
                VALUES (:id, :control_id, :control_name, :framework, :status, :score, :evidence, :notes, :assessor, :assessed_at)
            """, d)
            conn.commit()
            conn.close()
        return assessment

    def get_assessment(self, assessment_id: str) -> Optional[ControlAssessment]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM control_assessments WHERE id = ?", (assessment_id,)).fetchone()
        conn.close()
        if row:
            return ControlAssessment.from_dict(dict(row))
        return None

    def list_assessments(
        self, framework: Optional[str] = None, status: Optional[str] = None,
        limit: int = 100, offset: int = 0
    ) -> List[ControlAssessment]:
        conn = self._conn()
        query = "SELECT * FROM control_assessments WHERE 1=1"
        params: List[Any] = []
        if framework:
            query += " AND framework = ?"
            params.append(framework)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY assessed_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        conn.close()
        return [ControlAssessment.from_dict(dict(r)) for r in rows]

    def get_framework_score(self, framework: str) -> Dict[str, Any]:
        conn = self._conn()
        rows = conn.execute(
            "SELECT status, COUNT(*) as cnt, AVG(score) as avg_score FROM control_assessments WHERE framework = ? GROUP BY status",
            (framework,),
        ).fetchall()
        conn.close()
        result: Dict[str, Any] = {"framework": framework, "statuses": {}, "total": 0, "average_score": 0.0}
        total = 0
        weighted_sum = 0.0
        for r in rows:
            d = dict(r)
            result["statuses"][d["status"]] = {"count": d["cnt"], "average_score": d["avg_score"]}
            total += d["cnt"]
            weighted_sum += d["avg_score"] * d["cnt"]
        result["total"] = total
        result["average_score"] = (weighted_sum / total) if total > 0 else 0.0
        return result

    # -- Incidents --

    def save_incident(self, incident: IncidentRecord) -> IncidentRecord:
        with self._lock:
            conn = self._conn()
            d = incident.to_dict()
            d["affected_assets"] = json.dumps(d.get("affected_assets", []))
            d["iocs"] = json.dumps(d.get("iocs", []))
            d["actions_taken"] = json.dumps(d.get("actions_taken", []))
            conn.execute("""
                INSERT OR REPLACE INTO incidents
                (id, incident_id, title, severity, status, detected_at, contained_at, resolved_at,
                 nist_phase, category, source, affected_assets, iocs, actions_taken, lessons_learned, analyst)
                VALUES (:id, :incident_id, :title, :severity, :status, :detected_at, :contained_at, :resolved_at,
                 :nist_phase, :category, :source, :affected_assets, :iocs, :actions_taken, :lessons_learned, :analyst)
            """, d)
            conn.commit()
            conn.close()
        return incident

    def get_incident(self, incident_id: str) -> Optional[IncidentRecord]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM incidents WHERE id = ? OR incident_id = ?",
                           (incident_id, incident_id)).fetchone()
        conn.close()
        if row:
            d = dict(row)
            d["affected_assets"] = json.loads(d.get("affected_assets", "[]"))
            d["iocs"] = json.loads(d.get("iocs", "[]"))
            d["actions_taken"] = json.loads(d.get("actions_taken", "[]"))
            return IncidentRecord.from_dict(d)
        return None

    def list_incidents(
        self, severity: Optional[str] = None, status: Optional[str] = None,
        start_date: Optional[str] = None, end_date: Optional[str] = None,
        limit: int = 100, offset: int = 0
    ) -> List[IncidentRecord]:
        conn = self._conn()
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if start_date:
            query += " AND detected_at >= ?"
            params.append(start_date)
        if end_date:
            query += " AND detected_at <= ?"
            params.append(end_date)
        query += " ORDER BY detected_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["affected_assets"] = json.loads(d.get("affected_assets", "[]"))
            d["iocs"] = json.loads(d.get("iocs", "[]"))
            d["actions_taken"] = json.loads(d.get("actions_taken", "[]"))
            results.append(IncidentRecord.from_dict(d))
        return results

    def get_incident_stats(
        self, start_date: Optional[str] = None, end_date: Optional[str] = None
    ) -> Dict[str, Any]:
        conn = self._conn()
        base = "FROM incidents WHERE 1=1"
        params: List[Any] = []
        if start_date:
            base += " AND detected_at >= ?"
            params.append(start_date)
        if end_date:
            base += " AND detected_at <= ?"
            params.append(end_date)
        total = conn.execute(f"SELECT COUNT(*) as cnt {base}", params).fetchone()["cnt"]
        severity_rows = conn.execute(
            f"SELECT severity, COUNT(*) as cnt {base} GROUP BY severity", params
        ).fetchall()
        status_rows = conn.execute(
            f"SELECT status, COUNT(*) as cnt {base} GROUP BY status", params
        ).fetchall()
        phase_rows = conn.execute(
            f"SELECT nist_phase, COUNT(*) as cnt {base} GROUP BY nist_phase", params
        ).fetchall()
        conn.close()
        return {
            "total": total,
            "by_severity": {r["severity"]: r["cnt"] for r in severity_rows},
            "by_status": {r["status"]: r["cnt"] for r in status_rows},
            "by_nist_phase": {r["nist_phase"]: r["cnt"] for r in phase_rows},
        }

    # -- Breach Notifications --

    def save_breach(self, breach: BreachNotification) -> BreachNotification:
        with self._lock:
            conn = self._conn()
            d = breach.to_dict()
            d["data_categories"] = json.dumps(d.get("data_categories", []))
            d["data_subjects_notified"] = 1 if d.get("data_subjects_notified") else 0
            d["cross_border"] = 1 if d.get("cross_border") else 0
            conn.execute("""
                INSERT OR REPLACE INTO breach_notifications
                (id, breach_id, breach_date, discovery_date, notification_date, breach_description,
                 data_categories, affected_count, consequences, measures_taken, dpo_contact,
                 data_subjects_notified, cross_border, legal_basis, severity, framework, status)
                VALUES (:id, :breach_id, :breach_date, :discovery_date, :notification_date, :breach_description,
                 :data_categories, :affected_count, :consequences, :measures_taken, :dpo_contact,
                 :data_subjects_notified, :cross_border, :legal_basis, :severity, :framework, :status)
            """, d)
            conn.commit()
            conn.close()
        return breach

    def get_breach(self, breach_id: str) -> Optional[BreachNotification]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM breach_notifications WHERE id = ? OR breach_id = ?",
                           (breach_id, breach_id)).fetchone()
        conn.close()
        if row:
            d = dict(row)
            d["data_categories"] = json.loads(d.get("data_categories", "[]"))
            d["data_subjects_notified"] = bool(d.get("data_subjects_notified", 0))
            d["cross_border"] = bool(d.get("cross_border", 0))
            return BreachNotification.from_dict(d)
        return None

    def list_breaches(
        self, framework: Optional[str] = None, status: Optional[str] = None,
        limit: int = 100, offset: int = 0
    ) -> List[BreachNotification]:
        conn = self._conn()
        query = "SELECT * FROM breach_notifications WHERE 1=1"
        params: List[Any] = []
        if framework:
            query += " AND framework = ?"
            params.append(framework)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY discovery_date DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["data_categories"] = json.loads(d.get("data_categories", "[]"))
            d["data_subjects_notified"] = bool(d.get("data_subjects_notified", 0))
            d["cross_border"] = bool(d.get("cross_border", 0))
            results.append(BreachNotification.from_dict(d))
        return results

    # -- Reports --

    def save_report(self, report: ComplianceReport) -> ComplianceReport:
        with self._lock:
            conn = self._conn()
            d = report.to_dict()
            d["findings"] = json.dumps(d.get("findings", []))
            d["data"] = json.dumps(d.get("data", {}))
            conn.execute("""
                INSERT OR REPLACE INTO reports
                (id, report_id, title, report_type, framework, period, generated_at, generated_by,
                 period_start, period_end, total_score, control_count, implemented_count, gap_count,
                 findings, data, format, file_path)
                VALUES (:id, :report_id, :title, :report_type, :framework, :period, :generated_at, :generated_by,
                 :period_start, :period_end, :total_score, :control_count, :implemented_count, :gap_count,
                 :findings, :data, :format, :file_path)
            """, d)
            conn.commit()
            conn.close()
        return report

    def get_report(self, report_id: str) -> Optional[ComplianceReport]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM reports WHERE id = ? OR report_id = ?",
                           (report_id, report_id)).fetchone()
        conn.close()
        if row:
            d = dict(row)
            d["findings"] = json.loads(d.get("findings", "[]"))
            d["data"] = json.loads(d.get("data", "{}"))
            return ComplianceReport.from_dict(d)
        return None

    def list_reports(
        self, report_type: Optional[str] = None, framework: Optional[str] = None,
        limit: int = 100, offset: int = 0
    ) -> List[ComplianceReport]:
        conn = self._conn()
        query = "SELECT * FROM reports WHERE 1=1"
        params: List[Any] = []
        if report_type:
            query += " AND report_type = ?"
            params.append(report_type)
        if framework:
            query += " AND framework = ?"
            params.append(framework)
        query += " ORDER BY generated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        rows = conn.execute(query, params).fetchall()
        conn.close()
        results = []
        for r in rows:
            d = dict(r)
            d["findings"] = json.loads(d.get("findings", "[]"))
            d["data"] = json.loads(d.get("data", "{}"))
            results.append(ComplianceReport.from_dict(d))
        return results


# =============================================================================
#   PDF REPORT GENERATOR
# =============================================================================


class PDFReportGenerator:
    """Generates compliance reports as PDF using ReportLab."""

    def __init__(self):
        self._reportlab_available = False
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.units import cm
            self._reportlab_available = True
        except ImportError:
            logger.warning("ReportLab not available; PDF generation disabled")

    @property
    def available(self) -> bool:
        return self._reportlab_available

    def generate_nist_report(
        self, title: str, incidents: List[IncidentRecord],
        assessments: List[ControlAssessment], period_start: str, period_end: str,
        organization: str = "TSUNAMI SOC"
    ) -> Optional[bytes]:
        if not self._reportlab_available:
            return None
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CustomTitle", parent=styles["Title"], fontSize=18, alignment=TA_CENTER)
        heading_style = ParagraphStyle("CustomHeading", parent=styles["Heading2"], fontSize=14)
        normal_style = styles["Normal"]

        elements = []

        # Title
        elements.append(Paragraph(title, title_style))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(f"Organization: {organization}", normal_style))
        elements.append(Paragraph(f"Period: {period_start} to {period_end}", normal_style))
        elements.append(Paragraph(f"Framework: NIST SP 800-61", normal_style))
        elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", normal_style))
        elements.append(Spacer(1, 1 * cm))

        # Executive Summary
        elements.append(Paragraph("Executive Summary", heading_style))
        severity_counts = {}
        for inc in incidents:
            severity_counts[inc.severity] = severity_counts.get(inc.severity, 0) + 1
        elements.append(Paragraph(f"Total Incidents: {len(incidents)}", normal_style))
        for sev, cnt in sorted(severity_counts.items()):
            elements.append(Paragraph(f"  {sev.upper()}: {cnt}", normal_style))
        elements.append(Spacer(1, 0.5 * cm))

        # Control Assessment Summary
        elements.append(Paragraph("Control Assessment Summary", heading_style))
        if assessments:
            table_data = [["Control ID", "Name", "Status", "Score"]]
            for a in assessments:
                table_data.append([a.control_id, a.control_name[:30], a.status, f"{a.score:.0%}"])
            t = Table(table_data, colWidths=[3 * cm, 6 * cm, 4 * cm, 3 * cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ecf0f1")]),
            ]))
            elements.append(t)
        else:
            elements.append(Paragraph("No control assessments recorded.", normal_style))
        elements.append(Spacer(1, 0.5 * cm))

        # NIST Phase Mapping
        elements.append(Paragraph("NIST SP 800-61 Phase Distribution", heading_style))
        phase_counts = {}
        for inc in incidents:
            phase_counts[inc.nist_phase] = phase_counts.get(inc.nist_phase, 0) + 1
        if phase_counts:
            phase_data = [["Phase", "Incident Count"]]
            for phase, cnt in phase_counts.items():
                phase_info = NIST_800_61_PHASES.get(phase, {})
                label = phase_info.get("title", phase)
                phase_data.append([label, str(cnt)])
            pt = Table(phase_data, colWidths=[8 * cm, 4 * cm])
            pt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(pt)
        elements.append(Spacer(1, 0.5 * cm))

        # Incident Details
        elements.append(Paragraph("Incident Details", heading_style))
        for inc in incidents[:20]:  # cap at 20 for readability
            elements.append(Paragraph(
                f"<b>[{inc.severity.upper()}]</b> {inc.title} — {inc.status} (ID: {inc.incident_id})",
                normal_style
            ))
        if len(incidents) > 20:
            elements.append(Paragraph(f"... and {len(incidents) - 20} more incidents", normal_style))

        doc.build(elements)
        return buf.getvalue()

    def generate_iso27001_report(
        self, title: str, assessments: List[ControlAssessment],
        period_start: str, period_end: str, organization: str = "TSUNAMI SOC"
    ) -> Optional[bytes]:
        if not self._reportlab_available:
            return None
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CustomTitle", parent=styles["Title"], fontSize=18, alignment=TA_CENTER)
        heading_style = ParagraphStyle("CustomHeading", parent=styles["Heading2"], fontSize=14)
        normal_style = styles["Normal"]

        elements = []

        elements.append(Paragraph(title, title_style))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(f"Organization: {organization}", normal_style))
        elements.append(Paragraph(f"Period: {period_start} to {period_end}", normal_style))
        elements.append(Paragraph(f"Framework: ISO 27001:2022 Annex A", normal_style))
        elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", normal_style))
        elements.append(Spacer(1, 1 * cm))

        # Score summary
        total = len(assessments)
        implemented = sum(1 for a in assessments if a.status == ControlStatus.IMPLEMENTED.value)
        partial = sum(1 for a in assessments if a.status == ControlStatus.PARTIALLY_IMPLEMENTED.value)
        not_impl = sum(1 for a in assessments if a.status == ControlStatus.NOT_IMPLEMENTED.value)
        avg_score = (sum(a.score for a in assessments) / total) if total > 0 else 0.0

        elements.append(Paragraph("Executive Summary", heading_style))
        elements.append(Paragraph(f"Total Controls Assessed: {total}", normal_style))
        elements.append(Paragraph(f"Implemented: {implemented}", normal_style))
        elements.append(Paragraph(f"Partially Implemented: {partial}", normal_style))
        elements.append(Paragraph(f"Not Implemented: {not_impl}", normal_style))
        elements.append(Paragraph(f"Average Score: {avg_score:.0%}", normal_style))
        elements.append(Spacer(1, 0.5 * cm))

        # Domain breakdown
        elements.append(Paragraph("Domain Breakdown", heading_style))
        domain_stats: Dict[str, List[ControlAssessment]] = {}
        for a in assessments:
            domain_key = a.control_id.split(".")[0] if "." in a.control_id else a.control_id[:2]
            domain_key = domain_key.replace("A", "A")
            domain_stats.setdefault(domain_key, []).append(a)

        if domain_stats:
            dom_data = [["Domain", "Controls", "Avg Score"]]
            for dk, alist in sorted(domain_stats.items()):
                davg = sum(a.score for a in alist) / len(alist) if alist else 0
                dom_data.append([dk, str(len(alist)), f"{davg:.0%}"])
            dt = Table(dom_data, colWidths=[4 * cm, 4 * cm, 4 * cm])
            dt.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(dt)
        elements.append(Spacer(1, 0.5 * cm))

        # Control details
        elements.append(Paragraph("Control Assessment Details", heading_style))
        if assessments:
            ctrl_data = [["Control", "Name", "Status", "Score"]]
            for a in assessments:
                ctrl_data.append([a.control_id, a.control_name[:30], a.status, f"{a.score:.0%}"])
            ct = Table(ctrl_data, colWidths=[3 * cm, 6 * cm, 4 * cm, 3 * cm])
            ct.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#ecf0f1")]),
            ]))
            elements.append(ct)

        doc.build(elements)
        return buf.getvalue()

    def generate_breach_report(
        self, title: str, breach: BreachNotification,
        organization: str = "TSUNAMI SOC"
    ) -> Optional[bytes]:
        if not self._reportlab_available:
            return None
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CustomTitle", parent=styles["Title"], fontSize=18, alignment=TA_CENTER)
        heading_style = ParagraphStyle("CustomHeading", parent=styles["Heading2"], fontSize=14)
        normal_style = styles["Normal"]

        elements = []

        fw_label = "KVKK" if breach.framework == ComplianceFramework.KVKK.value else "GDPR"
        elements.append(Paragraph(title, title_style))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(f"Organization: {organization}", normal_style))
        elements.append(Paragraph(f"Framework: {fw_label}", normal_style))
        elements.append(Paragraph(f"Breach ID: {breach.breach_id}", normal_style))
        elements.append(Paragraph(f"Severity: {breach.severity.upper()}", normal_style))
        elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", normal_style))
        elements.append(Spacer(1, 1 * cm))

        # Notification details table
        elements.append(Paragraph("Breach Notification Details", heading_style))
        detail_data = [
            ["Field", "Value"],
            ["Breach Date", breach.breach_date or "N/A"],
            ["Discovery Date", breach.discovery_date or "N/A"],
            ["Notification Date", breach.notification_date or "N/A"],
            ["Description", breach.breach_description[:80] or "N/A"],
            ["Data Categories", ", ".join(breach.data_categories) or "N/A"],
            ["Affected Count", str(breach.affected_count)],
            ["Consequences", breach.consequences[:80] or "N/A"],
            ["Measures Taken", breach.measures_taken[:80] or "N/A"],
            ["DPO Contact", breach.dpo_contact or "N/A"],
            ["Subjects Notified", "Yes" if breach.data_subjects_notified else "No"],
            ["Cross-Border", "Yes" if breach.cross_border else "No"],
            ["Legal Basis", breach.legal_basis or "N/A"],
        ]
        dt = Table(detail_data, colWidths=[5 * cm, 11 * cm])
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#c0392b")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#ecf0f1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        elements.append(dt)
        elements.append(Spacer(1, 0.5 * cm))

        # KVKK required fields checklist
        elements.append(Paragraph(f"{fw_label} Required Fields Checklist", heading_style))
        for fld in KVKK_NOTIFICATION_FIELDS:
            val = getattr(breach, fld["field"], None)
            has_value = bool(val) if not isinstance(val, bool) else True
            marker = "OK" if has_value else "MISSING"
            elements.append(Paragraph(f"[{marker}] {fld['label']} ({fld['label_en']})", normal_style))

        doc.build(elements)
        return buf.getvalue()

    def generate_executive_summary(
        self, title: str, incident_stats: Dict[str, Any],
        framework_scores: Dict[str, Dict[str, Any]],
        breach_count: int, period_start: str, period_end: str,
        organization: str = "TSUNAMI SOC"
    ) -> Optional[bytes]:
        if not self._reportlab_available:
            return None
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_CENTER

        buf = BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2 * cm, bottomMargin=2 * cm)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("CustomTitle", parent=styles["Title"], fontSize=20, alignment=TA_CENTER)
        heading_style = ParagraphStyle("CustomHeading", parent=styles["Heading2"], fontSize=14)
        normal_style = styles["Normal"]

        elements = []

        elements.append(Paragraph(title, title_style))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(f"Organization: {organization}", normal_style))
        elements.append(Paragraph(f"Period: {period_start} to {period_end}", normal_style))
        elements.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}", normal_style))
        elements.append(Spacer(1, 1 * cm))

        # KPI Summary
        elements.append(Paragraph("Key Performance Indicators", heading_style))
        kpi_data = [
            ["Metric", "Value"],
            ["Total Incidents", str(incident_stats.get("total", 0))],
            ["Critical Incidents", str(incident_stats.get("by_severity", {}).get("critical", 0))],
            ["High Incidents", str(incident_stats.get("by_severity", {}).get("high", 0))],
            ["Open Incidents", str(incident_stats.get("by_status", {}).get("open", 0))],
            ["Resolved Incidents", str(incident_stats.get("by_status", {}).get("resolved", 0))],
            ["Breach Notifications", str(breach_count)],
        ]
        kt = Table(kpi_data, colWidths=[8 * cm, 4 * cm])
        kt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ]))
        elements.append(kt)
        elements.append(Spacer(1, 0.5 * cm))

        # Framework scores
        elements.append(Paragraph("Compliance Framework Scores", heading_style))
        if framework_scores:
            fw_data = [["Framework", "Controls", "Avg Score"]]
            for fw_name, fw_info in framework_scores.items():
                fw_data.append([
                    fw_name,
                    str(fw_info.get("total", 0)),
                    f"{fw_info.get('average_score', 0):.0%}",
                ])
            ft = Table(fw_data, colWidths=[6 * cm, 3 * cm, 3 * cm])
            ft.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            elements.append(ft)

        doc.build(elements)
        return buf.getvalue()


# =============================================================================
#   COMPLIANCE REPORT ENGINE
# =============================================================================


class ComplianceReportEngine:
    """Main compliance reporting orchestrator."""

    def __init__(
        self,
        store: Optional[ComplianceStore] = None,
        pdf_generator: Optional[PDFReportGenerator] = None,
        output_dir: Optional[str] = None,
    ):
        self.store = store or ComplianceStore()
        self.pdf = pdf_generator or PDFReportGenerator()
        self.output_dir = output_dir or os.path.join(os.path.dirname(__file__), "reports")
        os.makedirs(self.output_dir, exist_ok=True)
        self._callbacks: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()

    def register_callback(self, event: str, callback: Callable) -> None:
        with self._lock:
            self._callbacks.setdefault(event, []).append(callback)

    def _fire(self, event: str, data: Any = None) -> None:
        for cb in self._callbacks.get(event, []):
            try:
                cb(event, data)
            except Exception as e:
                logger.error("Callback error for %s: %s", event, e)

    # -- NIST 800-61 --

    def get_nist_controls(self) -> Dict[str, Any]:
        return NIST_800_61_PHASES

    def assess_nist_control(
        self, control_id: str, status: str, score: float,
        evidence: str = "", notes: str = "", assessor: str = ""
    ) -> ControlAssessment:
        # Find control name from mapping
        control_name = ""
        for phase_data in NIST_800_61_PHASES.values():
            for ctrl in phase_data.get("controls", []):
                if ctrl["id"] == control_id:
                    control_name = ctrl["name"]
                    break
        assessment = ControlAssessment(
            control_id=control_id,
            control_name=control_name,
            framework=ComplianceFramework.NIST_800_61.value,
            status=status,
            score=max(0.0, min(1.0, score)),
            evidence=evidence,
            notes=notes,
            assessor=assessor,
        )
        self.store.save_assessment(assessment)
        self._fire("assessment_saved", assessment.to_dict())
        return assessment

    def generate_nist_report(
        self, period_start: str, period_end: str,
        output_format: str = ReportFormat.JSON.value,
        organization: str = "TSUNAMI SOC"
    ) -> ComplianceReport:
        assessments = self.store.list_assessments(
            framework=ComplianceFramework.NIST_800_61.value, limit=500
        )
        incidents = self.store.list_incidents(
            start_date=period_start, end_date=period_end, limit=500
        )
        total = len(assessments)
        implemented = sum(1 for a in assessments if a.status == ControlStatus.IMPLEMENTED.value)
        gaps = sum(1 for a in assessments if a.status in (
            ControlStatus.NOT_IMPLEMENTED.value, ControlStatus.PLANNED.value
        ))
        avg_score = (sum(a.score for a in assessments) / total) if total > 0 else 0.0

        findings = []
        for a in assessments:
            if a.status in (ControlStatus.NOT_IMPLEMENTED.value, ControlStatus.PLANNED.value):
                findings.append({
                    "control_id": a.control_id,
                    "control_name": a.control_name,
                    "status": a.status,
                    "score": a.score,
                    "recommendation": f"Implement control {a.control_id}: {a.control_name}",
                })

        report = ComplianceReport(
            report_id=str(uuid.uuid4()),
            title=f"NIST SP 800-61 Compliance Report ({period_start} to {period_end})",
            report_type=ReportType.COMPLIANCE_AUDIT.value,
            framework=ComplianceFramework.NIST_800_61.value,
            period_start=period_start,
            period_end=period_end,
            total_score=avg_score,
            control_count=total,
            implemented_count=implemented,
            gap_count=gaps,
            findings=findings,
            format=output_format,
            data={
                "incident_count": len(incidents),
                "severity_distribution": {},
                "phase_distribution": {},
            },
        )
        # Incident stats
        for inc in incidents:
            report.data["severity_distribution"][inc.severity] = \
                report.data["severity_distribution"].get(inc.severity, 0) + 1
            report.data["phase_distribution"][inc.nist_phase] = \
                report.data["phase_distribution"].get(inc.nist_phase, 0) + 1

        # Generate PDF if requested
        if output_format == ReportFormat.PDF.value:
            pdf_bytes = self.pdf.generate_nist_report(
                report.title, incidents, assessments, period_start, period_end, organization
            )
            if pdf_bytes:
                fname = f"nist_800_61_{period_start}_{period_end}.pdf".replace("-", "")
                fpath = os.path.join(self.output_dir, fname)
                with open(fpath, "wb") as f:
                    f.write(pdf_bytes)
                report.file_path = fpath

        self.store.save_report(report)
        self._fire("report_generated", report.to_dict())
        return report

    # -- ISO 27001 --

    def get_iso27001_controls(self) -> Dict[str, Any]:
        return ISO_27001_DOMAINS

    def assess_iso27001_control(
        self, control_id: str, status: str, score: float,
        evidence: str = "", notes: str = "", assessor: str = ""
    ) -> ControlAssessment:
        control_name = ""
        for domain_data in ISO_27001_DOMAINS.values():
            for ctrl in domain_data.get("controls", []):
                if ctrl["id"] == control_id:
                    control_name = ctrl["name"]
                    break
        assessment = ControlAssessment(
            control_id=control_id,
            control_name=control_name,
            framework=ComplianceFramework.ISO_27001.value,
            status=status,
            score=max(0.0, min(1.0, score)),
            evidence=evidence,
            notes=notes,
            assessor=assessor,
        )
        self.store.save_assessment(assessment)
        self._fire("assessment_saved", assessment.to_dict())
        return assessment

    def generate_iso27001_report(
        self, period_start: str, period_end: str,
        output_format: str = ReportFormat.JSON.value,
        organization: str = "TSUNAMI SOC"
    ) -> ComplianceReport:
        assessments = self.store.list_assessments(
            framework=ComplianceFramework.ISO_27001.value, limit=500
        )
        total = len(assessments)
        implemented = sum(1 for a in assessments if a.status == ControlStatus.IMPLEMENTED.value)
        gaps = sum(1 for a in assessments if a.status in (
            ControlStatus.NOT_IMPLEMENTED.value, ControlStatus.PLANNED.value
        ))
        avg_score = (sum(a.score for a in assessments) / total) if total > 0 else 0.0

        findings = []
        for a in assessments:
            if a.status in (ControlStatus.NOT_IMPLEMENTED.value, ControlStatus.PLANNED.value):
                findings.append({
                    "control_id": a.control_id,
                    "control_name": a.control_name,
                    "status": a.status,
                    "score": a.score,
                    "recommendation": f"Implement control {a.control_id}: {a.control_name}",
                })

        report = ComplianceReport(
            report_id=str(uuid.uuid4()),
            title=f"ISO 27001 Compliance Report ({period_start} to {period_end})",
            report_type=ReportType.COMPLIANCE_AUDIT.value,
            framework=ComplianceFramework.ISO_27001.value,
            period_start=period_start,
            period_end=period_end,
            total_score=avg_score,
            control_count=total,
            implemented_count=implemented,
            gap_count=gaps,
            findings=findings,
            format=output_format,
        )

        if output_format == ReportFormat.PDF.value:
            pdf_bytes = self.pdf.generate_iso27001_report(
                report.title, assessments, period_start, period_end, organization
            )
            if pdf_bytes:
                fname = f"iso27001_{period_start}_{period_end}.pdf".replace("-", "")
                fpath = os.path.join(self.output_dir, fname)
                with open(fpath, "wb") as f:
                    f.write(pdf_bytes)
                report.file_path = fpath

        self.store.save_report(report)
        self._fire("report_generated", report.to_dict())
        return report

    # -- KVKK / GDPR --

    def create_breach_notification(self, **kwargs) -> BreachNotification:
        breach_id = kwargs.pop("breach_id", str(uuid.uuid4()))
        breach = BreachNotification(breach_id=breach_id, **kwargs)
        self.store.save_breach(breach)
        self._fire("breach_created", breach.to_dict())
        return breach

    def update_breach_notification(self, breach_id: str, **kwargs) -> Optional[BreachNotification]:
        breach = self.store.get_breach(breach_id)
        if not breach:
            return None
        for k, v in kwargs.items():
            if hasattr(breach, k):
                setattr(breach, k, v)
        self.store.save_breach(breach)
        self._fire("breach_updated", breach.to_dict())
        return breach

    def generate_breach_report(
        self, breach_id: str,
        output_format: str = ReportFormat.JSON.value,
        organization: str = "TSUNAMI SOC"
    ) -> Optional[ComplianceReport]:
        breach = self.store.get_breach(breach_id)
        if not breach:
            return None
        fw_label = "KVKK" if breach.framework == ComplianceFramework.KVKK.value else "GDPR"
        report = ComplianceReport(
            report_id=str(uuid.uuid4()),
            title=f"{fw_label} Breach Notification Report — {breach.breach_id}",
            report_type=ReportType.BREACH_NOTIFICATION.value,
            framework=breach.framework,
            total_score=0.0,
            data=breach.to_dict(),
            format=output_format,
        )

        if output_format == ReportFormat.PDF.value:
            pdf_bytes = self.pdf.generate_breach_report(report.title, breach, organization)
            if pdf_bytes:
                fname = f"breach_{breach.breach_id}.pdf".replace("-", "")
                fpath = os.path.join(self.output_dir, fname)
                with open(fpath, "wb") as f:
                    f.write(pdf_bytes)
                report.file_path = fpath

        self.store.save_report(report)
        self._fire("report_generated", report.to_dict())
        return report

    def get_kvkk_notification_fields(self) -> List[Dict[str, str]]:
        return KVKK_NOTIFICATION_FIELDS

    # -- Executive Summary --

    def generate_executive_summary(
        self, period_start: str, period_end: str,
        output_format: str = ReportFormat.JSON.value,
        organization: str = "TSUNAMI SOC"
    ) -> ComplianceReport:
        incident_stats = self.store.get_incident_stats(start_date=period_start, end_date=period_end)
        breaches = self.store.list_breaches(limit=500)
        period_breaches = [b for b in breaches if b.discovery_date >= period_start and b.discovery_date <= period_end] if period_start else breaches

        framework_scores = {}
        for fw in ComplianceFramework:
            score_data = self.store.get_framework_score(fw.value)
            if score_data.get("total", 0) > 0:
                framework_scores[fw.value] = score_data

        report = ComplianceReport(
            report_id=str(uuid.uuid4()),
            title=f"Executive Compliance Summary ({period_start} to {period_end})",
            report_type=ReportType.EXECUTIVE_SUMMARY.value,
            period_start=period_start,
            period_end=period_end,
            data={
                "incident_stats": incident_stats,
                "framework_scores": framework_scores,
                "breach_count": len(period_breaches),
            },
            format=output_format,
        )

        if output_format == ReportFormat.PDF.value:
            pdf_bytes = self.pdf.generate_executive_summary(
                report.title, incident_stats, framework_scores,
                len(period_breaches), period_start, period_end, organization
            )
            if pdf_bytes:
                fname = f"executive_summary_{period_start}_{period_end}.pdf".replace("-", "")
                fpath = os.path.join(self.output_dir, fname)
                with open(fpath, "wb") as f:
                    f.write(pdf_bytes)
                report.file_path = fpath

        self.store.save_report(report)
        self._fire("report_generated", report.to_dict())
        return report

    # -- Gap Analysis --

    def generate_gap_analysis(self, framework: str) -> Dict[str, Any]:
        assessments = self.store.list_assessments(framework=framework, limit=500)
        assessed_ids = {a.control_id for a in assessments}

        # Get all expected controls
        all_controls: List[Dict[str, str]] = []
        if framework == ComplianceFramework.NIST_800_61.value:
            for phase_data in NIST_800_61_PHASES.values():
                all_controls.extend(phase_data.get("controls", []))
        elif framework == ComplianceFramework.ISO_27001.value:
            for domain_data in ISO_27001_DOMAINS.values():
                all_controls.extend(domain_data.get("controls", []))

        expected_ids = {c["id"] for c in all_controls}
        missing = expected_ids - assessed_ids
        gaps = [a for a in assessments if a.status in (
            ControlStatus.NOT_IMPLEMENTED.value, ControlStatus.PLANNED.value
        )]

        return {
            "framework": framework,
            "total_expected": len(expected_ids),
            "total_assessed": len(assessed_ids),
            "missing_assessments": sorted(missing),
            "gap_count": len(gaps),
            "gaps": [{"control_id": g.control_id, "control_name": g.control_name,
                       "status": g.status, "score": g.score} for g in gaps],
            "coverage_pct": (len(assessed_ids) / len(expected_ids) * 100) if expected_ids else 0,
        }

    # -- Periodic Reports --

    def get_period_range(self, period: str, reference_date: Optional[datetime] = None) -> Tuple[str, str]:
        ref = reference_date or datetime.now(timezone.utc)
        if period == ReportPeriod.DAILY.value:
            start = ref.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1) - timedelta(seconds=1)
        elif period == ReportPeriod.WEEKLY.value:
            start = ref - timedelta(days=ref.weekday())
            start = start.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=7) - timedelta(seconds=1)
        elif period == ReportPeriod.MONTHLY.value:
            start = ref.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            if ref.month == 12:
                end = start.replace(year=ref.year + 1, month=1) - timedelta(seconds=1)
            else:
                end = start.replace(month=ref.month + 1) - timedelta(seconds=1)
        elif period == ReportPeriod.QUARTERLY.value:
            q = (ref.month - 1) // 3
            start = ref.replace(month=q * 3 + 1, day=1, hour=0, minute=0, second=0, microsecond=0)
            end_month = q * 3 + 4
            if end_month > 12:
                end = start.replace(year=ref.year + 1, month=end_month - 12) - timedelta(seconds=1)
            else:
                end = start.replace(month=end_month) - timedelta(seconds=1)
        elif period == ReportPeriod.ANNUAL.value:
            start = ref.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
            end = start.replace(year=ref.year + 1) - timedelta(seconds=1)
        else:
            start = ref.replace(hour=0, minute=0, second=0, microsecond=0)
            end = start + timedelta(days=1) - timedelta(seconds=1)
        return start.isoformat(), end.isoformat()

    def generate_periodic_report(
        self, period: str, framework: Optional[str] = None,
        output_format: str = ReportFormat.JSON.value,
        organization: str = "TSUNAMI SOC"
    ) -> ComplianceReport:
        period_start, period_end = self.get_period_range(period)
        if framework == ComplianceFramework.NIST_800_61.value:
            return self.generate_nist_report(period_start, period_end, output_format, organization)
        elif framework == ComplianceFramework.ISO_27001.value:
            return self.generate_iso27001_report(period_start, period_end, output_format, organization)
        else:
            return self.generate_executive_summary(period_start, period_end, output_format, organization)

    # -- Incidents --

    def record_incident(self, **kwargs) -> IncidentRecord:
        incident_id = kwargs.pop("incident_id", str(uuid.uuid4()))
        incident = IncidentRecord(incident_id=incident_id, **kwargs)
        self.store.save_incident(incident)
        self._fire("incident_recorded", incident.to_dict())
        return incident

    def update_incident(self, incident_id: str, **kwargs) -> Optional[IncidentRecord]:
        incident = self.store.get_incident(incident_id)
        if not incident:
            return None
        for k, v in kwargs.items():
            if hasattr(incident, k):
                setattr(incident, k, v)
        self.store.save_incident(incident)
        self._fire("incident_updated", incident.to_dict())
        return incident

    def get_dashboard_data(
        self, period_start: Optional[str] = None, period_end: Optional[str] = None
    ) -> Dict[str, Any]:
        if not period_start:
            now = datetime.now(timezone.utc)
            period_start = (now - timedelta(days=30)).isoformat()
            period_end = now.isoformat()
        incident_stats = self.store.get_incident_stats(start_date=period_start, end_date=period_end)
        framework_scores = {}
        for fw in ComplianceFramework:
            s = self.store.get_framework_score(fw.value)
            if s.get("total", 0) > 0:
                framework_scores[fw.value] = s
        breaches = self.store.list_breaches(limit=500)
        recent_reports = self.store.list_reports(limit=10)
        return {
            "period_start": period_start,
            "period_end": period_end,
            "incident_stats": incident_stats,
            "framework_scores": framework_scores,
            "breach_count": len(breaches),
            "recent_reports": [r.to_dict() for r in recent_reports],
        }


# =============================================================================
#   FLASK BLUEPRINT
# =============================================================================


def create_compliance_blueprint():
    try:
        from flask import Blueprint, request, jsonify, send_file
    except ImportError:
        logger.warning("Flask not available; blueprint disabled")
        return None

    bp = Blueprint("compliance", __name__, url_prefix="/api/v1/soc/compliance")
    _engine: Optional[ComplianceReportEngine] = None

    def _get_engine() -> ComplianceReportEngine:
        nonlocal _engine
        if _engine is None:
            _engine = get_compliance_engine()
        return _engine

    # -- Framework Controls --

    @bp.route("/frameworks/nist/controls", methods=["GET"])
    def nist_controls():
        return jsonify({"success": True, "data": _get_engine().get_nist_controls()})

    @bp.route("/frameworks/iso27001/controls", methods=["GET"])
    def iso_controls():
        return jsonify({"success": True, "data": _get_engine().get_iso27001_controls()})

    @bp.route("/frameworks/kvkk/fields", methods=["GET"])
    def kvkk_fields():
        return jsonify({"success": True, "data": _get_engine().get_kvkk_notification_fields()})

    # -- Assessments --

    @bp.route("/assessments", methods=["POST"])
    def create_assessment():
        data = request.get_json(force=True)
        control_id = data.get("control_id")
        framework = data.get("framework")
        if not control_id or not framework:
            return jsonify({"success": False, "error": "control_id and framework required"}), 400
        engine = _get_engine()
        if framework == ComplianceFramework.NIST_800_61.value:
            a = engine.assess_nist_control(
                control_id=control_id,
                status=data.get("status", ControlStatus.NOT_IMPLEMENTED.value),
                score=float(data.get("score", 0)),
                evidence=data.get("evidence", ""),
                notes=data.get("notes", ""),
                assessor=data.get("assessor", ""),
            )
        elif framework == ComplianceFramework.ISO_27001.value:
            a = engine.assess_iso27001_control(
                control_id=control_id,
                status=data.get("status", ControlStatus.NOT_IMPLEMENTED.value),
                score=float(data.get("score", 0)),
                evidence=data.get("evidence", ""),
                notes=data.get("notes", ""),
                assessor=data.get("assessor", ""),
            )
        else:
            return jsonify({"success": False, "error": f"Unsupported framework: {framework}"}), 400
        return jsonify({"success": True, "data": a.to_dict()}), 201

    @bp.route("/assessments", methods=["GET"])
    def list_assessments():
        framework = request.args.get("framework")
        status = request.args.get("status")
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        results = _get_engine().store.list_assessments(
            framework=framework, status=status, limit=limit, offset=offset
        )
        return jsonify({"success": True, "data": [a.to_dict() for a in results]})

    @bp.route("/assessments/<assessment_id>", methods=["GET"])
    def get_assessment(assessment_id):
        a = _get_engine().store.get_assessment(assessment_id)
        if not a:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "data": a.to_dict()})

    # -- Incidents --

    @bp.route("/incidents", methods=["POST"])
    def create_incident():
        data = request.get_json(force=True)
        inc = _get_engine().record_incident(**data)
        return jsonify({"success": True, "data": inc.to_dict()}), 201

    @bp.route("/incidents", methods=["GET"])
    def list_incidents():
        severity = request.args.get("severity")
        status = request.args.get("status")
        start = request.args.get("start_date")
        end = request.args.get("end_date")
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        results = _get_engine().store.list_incidents(
            severity=severity, status=status, start_date=start, end_date=end,
            limit=limit, offset=offset
        )
        return jsonify({"success": True, "data": [i.to_dict() for i in results]})

    @bp.route("/incidents/<incident_id>", methods=["GET"])
    def get_incident(incident_id):
        inc = _get_engine().store.get_incident(incident_id)
        if not inc:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "data": inc.to_dict()})

    @bp.route("/incidents/<incident_id>", methods=["PUT"])
    def update_incident(incident_id):
        data = request.get_json(force=True)
        inc = _get_engine().update_incident(incident_id, **data)
        if not inc:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "data": inc.to_dict()})

    @bp.route("/incidents/stats", methods=["GET"])
    def incident_stats():
        start = request.args.get("start_date")
        end = request.args.get("end_date")
        stats = _get_engine().store.get_incident_stats(start_date=start, end_date=end)
        return jsonify({"success": True, "data": stats})

    # -- Breaches --

    @bp.route("/breaches", methods=["POST"])
    def create_breach():
        data = request.get_json(force=True)
        b = _get_engine().create_breach_notification(**data)
        return jsonify({"success": True, "data": b.to_dict()}), 201

    @bp.route("/breaches", methods=["GET"])
    def list_breaches():
        framework = request.args.get("framework")
        status = request.args.get("status")
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        results = _get_engine().store.list_breaches(
            framework=framework, status=status, limit=limit, offset=offset
        )
        return jsonify({"success": True, "data": [b.to_dict() for b in results]})

    @bp.route("/breaches/<breach_id>", methods=["GET"])
    def get_breach(breach_id):
        b = _get_engine().store.get_breach(breach_id)
        if not b:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "data": b.to_dict()})

    @bp.route("/breaches/<breach_id>", methods=["PUT"])
    def update_breach(breach_id):
        data = request.get_json(force=True)
        b = _get_engine().update_breach_notification(breach_id, **data)
        if not b:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "data": b.to_dict()})

    # -- Reports --

    @bp.route("/reports/nist", methods=["POST"])
    def generate_nist_report():
        data = request.get_json(force=True)
        ps = data.get("period_start", "")
        pe = data.get("period_end", "")
        if not ps or not pe:
            return jsonify({"success": False, "error": "period_start and period_end required"}), 400
        fmt = data.get("format", ReportFormat.JSON.value)
        org = data.get("organization", "TSUNAMI SOC")
        report = _get_engine().generate_nist_report(ps, pe, fmt, org)
        return jsonify({"success": True, "data": report.to_dict()}), 201

    @bp.route("/reports/iso27001", methods=["POST"])
    def generate_iso_report():
        data = request.get_json(force=True)
        ps = data.get("period_start", "")
        pe = data.get("period_end", "")
        if not ps or not pe:
            return jsonify({"success": False, "error": "period_start and period_end required"}), 400
        fmt = data.get("format", ReportFormat.JSON.value)
        org = data.get("organization", "TSUNAMI SOC")
        report = _get_engine().generate_iso27001_report(ps, pe, fmt, org)
        return jsonify({"success": True, "data": report.to_dict()}), 201

    @bp.route("/reports/breach/<breach_id>", methods=["POST"])
    def generate_breach_report(breach_id):
        data = request.get_json(force=True) if request.is_json else {}
        fmt = data.get("format", ReportFormat.JSON.value)
        org = data.get("organization", "TSUNAMI SOC")
        report = _get_engine().generate_breach_report(breach_id, fmt, org)
        if not report:
            return jsonify({"success": False, "error": "Breach not found"}), 404
        return jsonify({"success": True, "data": report.to_dict()}), 201

    @bp.route("/reports/executive", methods=["POST"])
    def generate_executive():
        data = request.get_json(force=True)
        ps = data.get("period_start", "")
        pe = data.get("period_end", "")
        if not ps or not pe:
            return jsonify({"success": False, "error": "period_start and period_end required"}), 400
        fmt = data.get("format", ReportFormat.JSON.value)
        org = data.get("organization", "TSUNAMI SOC")
        report = _get_engine().generate_executive_summary(ps, pe, fmt, org)
        return jsonify({"success": True, "data": report.to_dict()}), 201

    @bp.route("/reports/periodic", methods=["POST"])
    def generate_periodic():
        data = request.get_json(force=True)
        period = data.get("period", ReportPeriod.MONTHLY.value)
        framework = data.get("framework")
        fmt = data.get("format", ReportFormat.JSON.value)
        org = data.get("organization", "TSUNAMI SOC")
        report = _get_engine().generate_periodic_report(period, framework, fmt, org)
        return jsonify({"success": True, "data": report.to_dict()}), 201

    @bp.route("/reports", methods=["GET"])
    def list_reports():
        rt = request.args.get("report_type")
        fw = request.args.get("framework")
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        results = _get_engine().store.list_reports(
            report_type=rt, framework=fw, limit=limit, offset=offset
        )
        return jsonify({"success": True, "data": [r.to_dict() for r in results]})

    @bp.route("/reports/<report_id>", methods=["GET"])
    def get_report(report_id):
        r = _get_engine().store.get_report(report_id)
        if not r:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "data": r.to_dict()})

    @bp.route("/reports/<report_id>/download", methods=["GET"])
    def download_report(report_id):
        r = _get_engine().store.get_report(report_id)
        if not r:
            return jsonify({"success": False, "error": "Not found"}), 404
        if not r.file_path or not os.path.exists(r.file_path):
            return jsonify({"success": False, "error": "PDF file not available"}), 404
        return send_file(r.file_path, mimetype="application/pdf", as_attachment=True,
                         download_name=os.path.basename(r.file_path))

    # -- Gap Analysis --

    @bp.route("/gap-analysis/<framework>", methods=["GET"])
    def gap_analysis(framework):
        result = _get_engine().generate_gap_analysis(framework)
        return jsonify({"success": True, "data": result})

    # -- Dashboard --

    @bp.route("/dashboard", methods=["GET"])
    def dashboard():
        start = request.args.get("period_start")
        end = request.args.get("period_end")
        data = _get_engine().get_dashboard_data(period_start=start, period_end=end)
        return jsonify({"success": True, "data": data})

    # -- Framework Scores --

    @bp.route("/scores/<framework>", methods=["GET"])
    def framework_score(framework):
        score = _get_engine().store.get_framework_score(framework)
        return jsonify({"success": True, "data": score})

    return bp


# =============================================================================
#   GLOBAL SINGLETON
# =============================================================================

_global_engine: Optional[ComplianceReportEngine] = None
_global_lock = threading.Lock()


def get_compliance_engine(**kwargs) -> ComplianceReportEngine:
    global _global_engine
    if _global_engine is None:
        with _global_lock:
            if _global_engine is None:
                _global_engine = ComplianceReportEngine(**kwargs)
    return _global_engine


def reset_global_engine() -> None:
    global _global_engine
    with _global_lock:
        _global_engine = None
