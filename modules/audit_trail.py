#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI AUDIT TRAIL MODULE v1.0
    Beyaz Şapka Kuralları - Denetim ve İzleme Sistemi
================================================================================

Bu modül TSUNAMI platformundaki tüm faaliyetleri kayıt altına alır,
denetim izi oluşturur ve uyumluluk raporlaması yapar.

KVKK, 7469 Sayılı Siber Güvenlik Yasası ve ilgili mevzuata uygun olarak
tüm operasyonlar loglanır ve saklanır.

Fonksiyonlar:
- log_access: Kullanıcı erişim kaydı
- log_export: Veri ihracı kaydı
- log_admin_action: Yönetici işlem kaydı
- log_security_event: Güvenlik olayı kaydı
- get_user_history: Kullanıcı geçmişi sorgulama
- get_audit_stats: Denetim istatistikleri
- export_audit_log: Log ihracı
- check_compliance: Uyumluluk kontrolü

Author: TSUNAMI Security Team
Version: 1.0.0
Date: 2026-02-20
================================================================================
"""

import os
import sys
import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
from pathlib import Path

# TSUNAMI yolu
TSUNAMI_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_DB_PATH = os.path.join(TSUNAMI_ROOT, 'tsunami_audit.db')

# Loglama yapılandırması
logger = logging.getLogger('tsunami.audit')


class LogLevel(Enum):
    """Log seviyeleri"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class EventType(Enum):
    """Olay türleri"""
    # Kullanıcı işlemleri
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    PASSWORD_CHANGE = "password_change"

    # Veri işlemleri
    DATA_VIEW = "data_view"
    DATA_EXPORT = "data_export"
    DATA_DELETE = "data_delete"
    DATA_MODIFY = "data_modify"

    # Operasyon işlemleri
    OPERATION_START = "operation_start"
    OPERATION_STOP = "operation_stop"
    OPERATION_PAUSE = "operation_pause"

    # Yönetim işlemleri
    USER_CREATE = "user_create"
    USER_DELETE = "user_delete"
    USER_MODIFY = "user_modify"
    ROLE_CHANGE = "role_change"
    PERMISSION_CHANGE = "permission_change"

    # Sistem işlemleri
    SYSTEM_START = "system_start"
    SYSTEM_STOP = "system_stop"
    CONFIG_CHANGE = "config_change"
    SYSTEM_ERROR = "system_error"

    # Güvenlik olayları
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    BRUTE_FORCE = "brute_force"
    INJECTION_ATTEMPT = "injection_attempt"
    DATA_BREACH = "data_breach"
    MALWARE_DETECTED = "malware_detected"

    # İhlal bildirimleri
    VIOLATION_REPORTED = "violation_reported"
    COMPLIANCE_CHECK = "compliance_check"
    AUDIT_PERFORMED = "audit_performed"


class Severity(Enum):
    """Olay şiddet seviyeleri"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class AuditLog:
    """Denetim kaydı veri yapısı"""
    timestamp: str
    level: str
    event_type: str
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str
    details: Dict[str, Any]
    status: str
    severity: int
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class AuditDatabase:
    """Denetim veritabanı yöneticisi"""

    def __init__(self, db_path: str = AUDIT_DB_PATH):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Veritabanını başlat"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Ana audit tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user_id TEXT NOT NULL,
                session_id TEXT,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                status TEXT,
                severity INTEGER,
                duration_ms INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                signature TEXT
            )
        ''')

        # Kullanıcı oturum tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                session_id TEXT UNIQUE NOT NULL,
                login_time TEXT NOT NULL,
                logout_time TEXT,
                ip_address TEXT,
                user_agent TEXT,
                status TEXT DEFAULT 'active',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Veri ihracı tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_exports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                export_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                data_type TEXT,
                record_count INTEGER,
                format TEXT,
                file_path TEXT,
                purpose TEXT,
                approval_status TEXT,
                approved_by TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME
            )
        ''')

        # Güvenlik olayları tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_type TEXT NOT NULL,
                severity INTEGER,
                source TEXT,
                target TEXT,
                description TEXT,
                details TEXT,
                status TEXT DEFAULT 'open',
                resolved_by TEXT,
                resolved_at TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # İhlal raporları tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS violation_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT UNIQUE NOT NULL,
                reporter_id TEXT,
                reporter_type TEXT,
                violation_type TEXT,
                description TEXT,
                severity INTEGER,
                status TEXT DEFAULT 'pending',
                assigned_to TEXT,
                resolution TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                resolved_at DATETIME
            )
        ''')

        # Uyumluluk kontrolleri tablosu
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                check_id TEXT UNIQUE NOT NULL,
                check_type TEXT,
                status TEXT,
                findings INTEGER,
                passed INTEGER,
                failed INTEGER,
                score REAL,
                details TEXT,
                performed_by TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Index'ler
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_event ON audit_logs(event_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_session_user ON user_sessions(user_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_export_user ON data_exports(user_id)')

        conn.commit()
        conn.close()

        logger.info("Audit database initialized")

    def insert_log(self, log: AuditLog) -> int:
        """Log kaydı ekle"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # İmza oluştur (bütünlük için)
        log_data = log.to_json()
        signature = hashlib.sha256(log_data.encode()).hexdigest()[:32]

        cursor.execute('''
            INSERT INTO audit_logs
            (timestamp, level, event_type, user_id, session_id, ip_address,
             user_agent, details, status, severity, duration_ms, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log.timestamp,
            log.level,
            log.event_type,
            log.user_id,
            log.session_id,
            log.ip_address,
            log.user_agent,
            json.dumps(log.details, ensure_ascii=False),
            log.status,
            log.severity,
            log.duration_ms,
            signature
        ))

        log_id = cursor.lastrowid
        conn.commit()
        conn.close()

        return log_id

    def get_logs(self, filters: Optional[Dict] = None, limit: int = 1000,
                 offset: int = 0) -> List[Dict]:
        """Logları getir"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []

        if filters:
            if filters.get('user_id'):
                query += " AND user_id = ?"
                params.append(filters['user_id'])
            if filters.get('event_type'):
                query += " AND event_type = ?"
                params.append(filters['event_type'])
            if filters.get('level'):
                query += " AND level = ?"
                params.append(filters['level'])
            if filters.get('start_date'):
                query += " AND timestamp >= ?"
                params.append(filters['start_date'])
            if filters.get('end_date'):
                query += " AND timestamp <= ?"
                params.append(filters['end_date'])

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        rows = cursor.fetchall()

        logs = []
        for row in rows:
            log_dict = dict(row)
            log_dict['details'] = json.loads(log_dict['details']) if log_dict['details'] else {}
            logs.append(log_dict)

        conn.close()
        return logs

    def get_stats(self, date_range: Optional[str] = None) -> Dict:
        """İstatistikleri getir"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Toplam log sayısı
        cursor.execute("SELECT COUNT(*) FROM audit_logs")
        total_logs = cursor.fetchone()[0]

        # Son 24 saat
        cursor.execute('''
            SELECT COUNT(*) FROM audit_logs
            WHERE timestamp >= datetime('now', '-1 day')
        ''')
        last_24h = cursor.fetchone()[0]

        # Olay tipi dağılımı
        cursor.execute('''
            SELECT event_type, COUNT(*) as count
            FROM audit_logs
            GROUP BY event_type
            ORDER BY count DESC
            LIMIT 10
        ''')
        event_distribution = dict(cursor.fetchall())

        # En aktif kullanıcılar
        cursor.execute('''
            SELECT user_id, COUNT(*) as count
            FROM audit_logs
            GROUP BY user_id
            ORDER BY count DESC
            LIMIT 10
        ''')
        top_users = dict(cursor.fetchall())

        # Başarısız işlemler
        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE status = 'failed'")
        failed_ops = cursor.fetchone()[0]

        # Kritik olaylar
        cursor.execute("SELECT COUNT(*) FROM audit_logs WHERE severity >= 4")
        critical_events = cursor.fetchone()[0]

        conn.close()

        return {
            'total_logs': total_logs,
            'last_24h': last_24h,
            'event_distribution': event_distribution,
            'top_users': top_users,
            'failed_operations': failed_ops,
            'critical_events': critical_events,
            'generated_at': datetime.now().isoformat()
        }

    def cleanup_old_logs(self, retention_days: int = 365):
        """Eski logları temizle"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            DELETE FROM audit_logs
            WHERE timestamp < datetime('now', '-' || ? || ' days')
        ''', (retention_days,))

        deleted = cursor.rowcount
        conn.commit()
        conn.close()

        logger.info(f"Cleaned up {deleted} old audit logs (older than {retention_days} days)")
        return deleted


class AuditLogger:
    """Ana denetim günlükleyici sınıfı"""

    def __init__(self, db_path: str = AUDIT_DB_PATH):
        self.db = AuditDatabase(db_path)
        self.logger = logger

    def _create_log(self,
                    level: LogLevel,
                    event_type: EventType,
                    user_id: str,
                    details: Dict[str, Any],
                    status: str = "success",
                    severity: int = Severity.LOW.value,
                    session_id: Optional[str] = None,
                    ip_address: Optional[str] = None,
                    user_agent: Optional[str] = None,
                    duration_ms: Optional[int] = None) -> int:
        """Log kaydı oluştur"""

        log = AuditLog(
            timestamp=datetime.now().isoformat(),
            level=level.value,
            event_type=event_type.value,
            user_id=user_id,
            session_id=session_id or "unknown",
            ip_address=ip_address or "0.0.0.0",
            user_agent=user_agent or "unknown",
            details=details,
            status=status,
            severity=severity,
            duration_ms=duration_ms
        )

        log_id = self.db.insert_log(log)

        # Terminal log
        log_msg = f"[{event_type.value}] {user_id}: {details.get('description', 'No description')}"

        if level == LogLevel.DEBUG:
            self.logger.debug(log_msg)
        elif level == LogLevel.INFO:
            self.logger.info(log_msg)
        elif level == LogLevel.WARNING:
            self.logger.warning(log_msg)
        elif level == LogLevel.ERROR:
            self.logger.error(log_msg)
        elif level == LogLevel.CRITICAL:
            self.logger.critical(log_msg)

        return log_id

    def log_access(self,
                   user_id: str,
                   resource: str,
                   action: str,
                   success: bool = True,
                   details: Optional[Dict] = None,
                   **kwargs) -> int:
        """
        Kullanıcı erişim kaydı

        Parametreler:
            user_id: Kullanıcı ID
            resource: Erişilen kaynak (örn: 'dashboard', 'api/endopint')
            action: Yapılan işlem (örn: 'view', 'create', 'update')
            success: Başarılı mı
            details: Ek detaylar
        """
        log_details = details or {}
        log_details.update({
            'resource': resource,
            'action': action,
            'description': f"Access to {resource} - {action}"
        })

        return self._create_log(
            level=LogLevel.INFO if success else LogLevel.WARNING,
            event_type=EventType.DATA_VIEW,
            user_id=user_id,
            details=log_details,
            status="success" if success else "failed",
            severity=Severity.LOW.value,
            **kwargs
        )

    def log_export(self,
                   user_id: str,
                   data_type: str,
                   record_count: int,
                   format_type: str,
                   purpose: str,
                   approved_by: Optional[str] = None,
                   file_path: Optional[str] = None,
                   **kwargs) -> int:
        """
        Veri ihracı kaydı

        Parametreler:
            user_id: İhracı yapan kullanıcı
            data_type: Veri türü (örn: 'audit_logs', 'findings')
            record_count: Kayıt sayısı
            format_type: Format (örn: 'json', 'csv')
            purpose: İhracat amacı
            approved_by: Onaylayan (opsiyonel)
            file_path: Dosya yolu (opsiyonel)
        """
        log_details = {
            'data_type': data_type,
            'record_count': record_count,
            'format': format_type,
            'purpose': purpose,
            'approved_by': approved_by,
            'file_path': file_path,
            'description': f"Data export: {record_count} {data_type} records as {format_type}"
        }

        # Veritabanına da kaydet
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        export_id = f"EXP-{datetime.now().strftime('%Y%m%d%H%M%S')}-{user_id}"

        cursor.execute('''
            INSERT INTO data_exports
            (export_id, user_id, data_type, record_count, format, file_path,
             purpose, approval_status, approved_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            export_id,
            user_id,
            data_type,
            record_count,
            format_type,
            file_path,
            purpose,
            'approved' if approved_by else 'pending',
            approved_by
        ))

        conn.commit()
        conn.close()

        return self._create_log(
            level=LogLevel.INFO,
            event_type=EventType.DATA_EXPORT,
            user_id=user_id,
            details=log_details,
            status="success",
            severity=Severity.MEDIUM.value if not approved_by else Severity.LOW.value,
            **kwargs
        )

    def log_admin_action(self,
                         user_id: str,
                         action: str,
                         target_type: str,
                         target_id: str,
                         details: Optional[Dict] = None,
                         **kwargs) -> int:
        """
        Yönetici işlem kaydı

        Parametreler:
            user_id: Yönetici ID
            action: İşlem tipi (örn: 'user_create', 'role_change')
            target_type: Hedef tipi (örn: 'user', 'role', 'permission')
            target_id: Hedef ID
            details: Ek detaylar
        """
        log_details = details or {}
        log_details.update({
            'action': action,
            'target_type': target_type,
            'target_id': target_id,
            'description': f"Admin action: {action} on {target_type}/{target_id}"
        })

        # Olay tipi belirle
        event_map = {
            'user_create': EventType.USER_CREATE,
            'user_delete': EventType.USER_DELETE,
            'user_modify': EventType.USER_MODIFY,
            'role_change': EventType.ROLE_CHANGE,
            'permission_change': EventType.PERMISSION_CHANGE,
        }
        event_type = event_map.get(action, EventType.USER_MODIFY)

        return self._create_log(
            level=LogLevel.INFO,
            event_type=event_type,
            user_id=user_id,
            details=log_details,
            status="success",
            severity=Severity.MEDIUM.value,
            **kwargs
        )

    def log_security_event(self,
                           event_type: EventType,
                           severity: Severity,
                           source: str,
                           description: str,
                           details: Optional[Dict] = None,
                           target: Optional[str] = None,
                           **kwargs) -> int:
        """
        Güvenlik olayı kaydı

        Parametreler:
            event_type: Olay tipi
            severity: Şiddet seviyesi
            source: Kaynak (IP, user ID vb.)
            description: Açıklama
            details: Ek detaylar
            target: Hedef (opsiyonel)
        """
        log_details = details or {}
        log_details.update({
            'source': source,
            'description': description,
            'target': target
        })

        # Veritabanına kaydet
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        event_id = f"SEC-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        cursor.execute('''
            INSERT INTO security_events
            (event_id, event_type, severity, source, target, description, details)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            event_id,
            event_type.value,
            severity.value,
            source,
            target,
            description,
            json.dumps(log_details, ensure_ascii=False)
        ))

        conn.commit()
        conn.close()

        return self._create_log(
            level=LogLevel.WARNING if severity.value < 4 else LogLevel.CRITICAL,
            event_type=event_type,
            user_id=source,  # Source as user_id
            details=log_details,
            status="detected",
            severity=severity.value,
            **kwargs
        )

    def get_user_history(self,
                         user_id: str,
                         date_range: Optional[int] = None) -> List[Dict]:
        """
        Kullanıcı geçmişini getir

        Parametreler:
            user_id: Kullanıcı ID
            date_range: Gün sayısı (opsiyonel)

        Returns:
            Log listesi
        """
        filters = {'user_id': user_id}

        if date_range:
            start_date = (datetime.now() - timedelta(days=date_range)).isoformat()
            filters['start_date'] = start_date

        return self.db.get_logs(filters=filters, limit=10000)

    def get_audit_stats(self, date_range: Optional[int] = None) -> Dict:
        """
        Denetim istatistikleri

        Parametreler:
            date_range: Gün sayısı (opsiyonel)

        Returns:
            İstatistik sözlüğü
        """
        return self.db.get_stats(date_range)

    def export_audit_log(self,
                         start_date: str,
                         end_date: str,
                         format_type: str = 'json',
                         filters: Optional[Dict] = None) -> str:
        """
        Audit log ihracı

        Parametreler:
            start_date: Başlangıç tarihi (ISO format)
            end_date: Bitiş tarihi (ISO format)
            format_type: Format ('json' veya 'csv')
            filters: Ek filtreler (opsiyonel)

        Returns:
            İhraç edilen dosya yolu
        """
        import csv

        if filters is None:
            filters = {}

        filters['start_date'] = start_date
        filters['end_date'] = end_date

        logs = self.db.get_logs(filters=filters, limit=1000000)

        # Dışa aktarma dizini
        export_dir = os.path.join(TSUNAMI_ROOT, 'audit_exports')
        os.makedirs(export_dir, exist_ok=True)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"audit_export_{timestamp}.{format_type}"
        filepath = os.path.join(export_dir, filename)

        if format_type == 'json':
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(logs, f, ensure_ascii=False, indent=2)
        elif format_type == 'csv':
            with open(filepath, 'w', encoding='utf-8', newline='') as f:
                if logs:
                    writer = csv.DictWriter(f, fieldnames=logs[0].keys())
                    writer.writeheader()
                    writer.writerows(logs)

        self.logger.info(f"Exported {len(logs)} audit logs to {filepath}")

        return filepath

    def check_compliance(self) -> Dict:
        """
        Uyumluluk kontrolü

        KVKK, 7469 Sayılı Kanun vb. için uyumluluk kontrolü

        Returns:
            Uyumluluk raporu
        """
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()

        findings = []
        passed = 0
        failed = 0

        # Kontrol 1: Log saklama süresi
        cursor.execute('''
            SELECT COUNT(*) FROM audit_logs
            WHERE timestamp < datetime('now', '-365 days')
        ''')
        old_logs = cursor.fetchone()[0]

        if old_logs > 0:
            findings.append({
                'check': 'Log Retention',
                'status': 'WARNING',
                'message': f'{old_logs} logs older than 365 days found',
                'severity': 'MEDIUM'
            })
            failed += 1
        else:
            passed += 1

        # Kontrol 2: Kritik olayların bildirimi
        cursor.execute('''
            SELECT COUNT(*) FROM audit_logs
            WHERE severity >= 4 AND timestamp >= datetime('now', '-24 hours')
        ''')
        critical_last_24h = cursor.fetchone()[0]

        if critical_last_24h > 0:
            findings.append({
                'check': 'Critical Events',
                'status': 'WARNING',
                'message': f'{critical_last_24h} critical events in last 24 hours',
                'severity': 'HIGH'
            })
            failed += 1
        else:
            passed += 1

        # Kontrol 3: Başarısız giriş denemeleri
        cursor.execute('''
            SELECT COUNT(*) FROM audit_logs
            WHERE event_type = 'login_failed'
            AND timestamp >= datetime('now', '-1 hour')
        ''')
        failed_logins = cursor.fetchone()[0]

        if failed_logins > 10:
            findings.append({
                'check': 'Failed Login Attempts',
                'status': 'CRITICAL',
                'message': f'{failed_logins} failed login attempts in last hour',
                'severity': 'CRITICAL'
            })
            failed += 1
        else:
            passed += 1

        # Kontrol 4: Veri ihracı onayları
        cursor.execute('''
            SELECT COUNT(*) FROM data_exports
            WHERE approval_status = 'pending'
            AND created_at >= datetime('now', '-7 days')
        ''')
        pending_exports = cursor.fetchone()[0]

        if pending_exports > 0:
            findings.append({
                'check': 'Pending Export Approvals',
                'status': 'WARNING',
                'message': f'{pending_exports} exports pending approval',
                'severity': 'MEDIUM'
            })
            failed += 1
        else:
            passed += 1

        conn.close()

        # Skor hesapla
        total_checks = passed + failed
        score = (passed / total_checks * 100) if total_checks > 0 else 100

        # Veritabanına kaydet
        conn = sqlite3.connect(self.db.db_path)
        cursor = conn.cursor()
        check_id = f"COMP-{datetime.now().strftime('%Y%m%d%H%M%S')}"

        cursor.execute('''
            INSERT INTO compliance_checks
            (check_id, check_type, status, findings, passed, failed, score, details, performed_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            check_id,
            'routine',
            'passed' if score >= 80 else 'failed',
            len(findings),
            passed,
            failed,
            score,
            json.dumps(findings, ensure_ascii=False),
            'system'
        ))

        conn.commit()
        conn.close()

        return {
            'check_id': check_id,
            'timestamp': datetime.now().isoformat(),
            'score': round(score, 2),
            'status': 'PASSED' if score >= 80 else 'FAILED',
            'passed': passed,
            'failed': failed,
            'total_checks': total_checks,
            'findings': findings
        }


# Global instance
_audit_logger = None

def get_audit_logger() -> AuditLogger:
    """Global audit logger instance'ı al"""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger()
    return _audit_logger


# Convenience fonksiyonları
def log_access(user_id: str, resource: str, action: str, **kwargs) -> int:
    """Kullanıcı erişimini logla"""
    return get_audit_logger().log_access(user_id, resource, action, **kwargs)


def log_export(user_id: str, data_type: str, record_count: int, **kwargs) -> int:
    """Veri ihracını logla"""
    return get_audit_logger().log_export(user_id, data_type, record_count, **kwargs)


def log_admin_action(user_id: str, action: str, target_type: str, target_id: str, **kwargs) -> int:
    """Yönetici işlemini logla"""
    return get_audit_logger().log_admin_action(user_id, action, target_type, target_id, **kwargs)


def log_security_event(event_type: EventType, severity: Severity, source: str,
                       description: str, **kwargs) -> int:
    """Güvenlik olayını logla"""
    return get_audit_logger().log_security_event(event_type, severity, source, description, **kwargs)


def get_user_history(user_id: str, days: int = 30) -> List[Dict]:
    """Kullanıcı geçmişini al"""
    return get_audit_logger().get_user_history(user_id, days)


def get_audit_stats() -> Dict:
    """Denetim istatistiklerini al"""
    return get_audit_logger().get_audit_stats()


if __name__ == '__main__':
    # Test
    logger = get_audit_logger()

    # Örnek loglar
    logger.log_access(
        user_id='admin',
        resource='/dashboard',
        action='view',
        success=True
    )

    logger.log_export(
        user_id='analyst',
        data_type='findings',
        record_count=150,
        format_type='json',
        purpose='analysis_report',
        approved_by='manager'
    )

    logger.log_admin_action(
        user_id='admin',
        action='user_create',
        target_type='user',
        target_id='new_user',
        details={'email': 'new@example.com'}
    )

    logger.log_security_event(
        event_type=EventType.UNAUTHORIZED_ACCESS,
        severity=Severity.HIGH,
        source='192.168.1.100',
        description='Failed login attempt',
        details={'attempts': 5}
    )

    # İstatistikler
    stats = logger.get_audit_stats()
    print(json.dumps(stats, indent=2, ensure_ascii=False))

    # Uyumluluk kontrolü
    compliance = logger.check_compliance()
    print(json.dumps(compliance, indent=2, ensure_ascii=False))
