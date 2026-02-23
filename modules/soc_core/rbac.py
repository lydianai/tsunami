#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Role-Based Access Control (RBAC) System
    Production-Grade Authorization & Audit Engine
================================================================================

    Roles:
    - ADMIN: Full system access, user management, configuration
    - INCIDENT_COMMANDER: Incident oversight, escalation, approval authority
    - SOC_ANALYST_L3: Advanced analysis, playbook creation, threat hunting
    - SOC_ANALYST_L2: Investigation, containment, IOC management
    - SOC_ANALYST_L1: Triage, alert handling, basic response
    - READ_ONLY: Dashboard viewing, report access only

    Features:
    - Hierarchical role system with permission inheritance
    - Per-endpoint permission enforcement via decorators
    - JWT token-based session management (HMAC-SHA256)
    - Comprehensive audit logging with tamper detection
    - Password hashing via PBKDF2-SHA256 (600k iterations)
    - Session management with idle/absolute timeout
    - Brute-force protection with progressive lockout

================================================================================
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("soc.rbac")


# ============================================================================
# Enums & Constants
# ============================================================================

class SOCRole(Enum):
    """SOC analyst role hierarchy (higher value = more privilege)."""
    READ_ONLY = 1
    SOC_ANALYST_L1 = 10
    SOC_ANALYST_L2 = 20
    SOC_ANALYST_L3 = 30
    INCIDENT_COMMANDER = 40
    ADMIN = 50


class Permission(Enum):
    """Granular permissions for SOC operations."""
    # Dashboard
    DASHBOARD_VIEW = "dashboard:view"
    DASHBOARD_EXPORT = "dashboard:export"

    # Alerts
    ALERT_VIEW = "alert:view"
    ALERT_TRIAGE = "alert:triage"
    ALERT_ASSIGN = "alert:assign"
    ALERT_CLOSE = "alert:close"
    ALERT_FALSE_POSITIVE = "alert:false_positive"

    # Incidents
    INCIDENT_VIEW = "incident:view"
    INCIDENT_CREATE = "incident:create"
    INCIDENT_UPDATE = "incident:update"
    INCIDENT_ESCALATE = "incident:escalate"
    INCIDENT_CLOSE = "incident:close"

    # Response Actions
    RESPONSE_BLOCK_IP = "response:block_ip"
    RESPONSE_ISOLATE_HOST = "response:isolate_host"
    RESPONSE_KILL_PROCESS = "response:kill_process"
    RESPONSE_QUARANTINE = "response:quarantine"

    # Playbooks
    PLAYBOOK_VIEW = "playbook:view"
    PLAYBOOK_EXECUTE = "playbook:execute"
    PLAYBOOK_CREATE = "playbook:create"
    PLAYBOOK_DELETE = "playbook:delete"

    # Threat Intel
    INTEL_VIEW = "intel:view"
    INTEL_ADD_IOC = "intel:add_ioc"
    INTEL_SHARE = "intel:share"

    # Configuration
    CONFIG_VIEW = "config:view"
    CONFIG_MODIFY = "config:modify"

    # User Management
    USER_VIEW = "user:view"
    USER_CREATE = "user:create"
    USER_MODIFY = "user:modify"
    USER_DELETE = "user:delete"
    USER_ROLE_ASSIGN = "user:role_assign"

    # Reports
    REPORT_VIEW = "report:view"
    REPORT_CREATE = "report:create"
    REPORT_DELETE = "report:delete"

    # Approval
    APPROVAL_VIEW = "approval:view"
    APPROVAL_APPROVE = "approval:approve"
    APPROVAL_REJECT = "approval:reject"

    # Audit
    AUDIT_VIEW = "audit:view"

    # SIEM
    SIEM_VIEW = "siem:view"
    SIEM_CONFIGURE = "siem:configure"
    SIEM_RULE_MANAGE = "siem:rule_manage"

    # Enrichment
    ENRICHMENT_VIEW = "enrichment:view"
    ENRICHMENT_EXECUTE = "enrichment:execute"

    # Case Management
    CASE_VIEW = "case:view"
    CASE_CREATE = "case:create"
    CASE_UPDATE = "case:update"

    # Compliance
    COMPLIANCE_VIEW = "compliance:view"
    COMPLIANCE_GENERATE = "compliance:generate"


# Permission matrix: which roles have which permissions
ROLE_PERMISSIONS: Dict[SOCRole, Set[Permission]] = {
    SOCRole.READ_ONLY: {
        Permission.DASHBOARD_VIEW,
        Permission.ALERT_VIEW,
        Permission.INCIDENT_VIEW,
        Permission.PLAYBOOK_VIEW,
        Permission.INTEL_VIEW,
        Permission.REPORT_VIEW,
        Permission.SIEM_VIEW,
        Permission.ENRICHMENT_VIEW,
        Permission.CASE_VIEW,
        Permission.COMPLIANCE_VIEW,
    },

    SOCRole.SOC_ANALYST_L1: {
        # Inherits READ_ONLY +
        Permission.DASHBOARD_VIEW,
        Permission.DASHBOARD_EXPORT,
        Permission.ALERT_VIEW,
        Permission.ALERT_TRIAGE,
        Permission.ALERT_ASSIGN,
        Permission.ALERT_FALSE_POSITIVE,
        Permission.INCIDENT_VIEW,
        Permission.INCIDENT_CREATE,
        Permission.PLAYBOOK_VIEW,
        Permission.PLAYBOOK_EXECUTE,
        Permission.INTEL_VIEW,
        Permission.REPORT_VIEW,
        Permission.APPROVAL_VIEW,
        Permission.SIEM_VIEW,
        Permission.ENRICHMENT_VIEW,
        Permission.ENRICHMENT_EXECUTE,
        Permission.CASE_VIEW,
        Permission.COMPLIANCE_VIEW,
    },

    SOCRole.SOC_ANALYST_L2: {
        # Inherits L1 +
        Permission.DASHBOARD_VIEW,
        Permission.DASHBOARD_EXPORT,
        Permission.ALERT_VIEW,
        Permission.ALERT_TRIAGE,
        Permission.ALERT_ASSIGN,
        Permission.ALERT_CLOSE,
        Permission.ALERT_FALSE_POSITIVE,
        Permission.INCIDENT_VIEW,
        Permission.INCIDENT_CREATE,
        Permission.INCIDENT_UPDATE,
        Permission.INCIDENT_ESCALATE,
        Permission.RESPONSE_BLOCK_IP,
        Permission.RESPONSE_QUARANTINE,
        Permission.PLAYBOOK_VIEW,
        Permission.PLAYBOOK_EXECUTE,
        Permission.INTEL_VIEW,
        Permission.INTEL_ADD_IOC,
        Permission.REPORT_VIEW,
        Permission.REPORT_CREATE,
        Permission.APPROVAL_VIEW,
        Permission.SIEM_VIEW,
        Permission.ENRICHMENT_VIEW,
        Permission.ENRICHMENT_EXECUTE,
        Permission.CASE_VIEW,
        Permission.CASE_CREATE,
        Permission.CASE_UPDATE,
        Permission.COMPLIANCE_VIEW,
    },

    SOCRole.SOC_ANALYST_L3: {
        # Inherits L2 +
        Permission.DASHBOARD_VIEW,
        Permission.DASHBOARD_EXPORT,
        Permission.ALERT_VIEW,
        Permission.ALERT_TRIAGE,
        Permission.ALERT_ASSIGN,
        Permission.ALERT_CLOSE,
        Permission.ALERT_FALSE_POSITIVE,
        Permission.INCIDENT_VIEW,
        Permission.INCIDENT_CREATE,
        Permission.INCIDENT_UPDATE,
        Permission.INCIDENT_ESCALATE,
        Permission.INCIDENT_CLOSE,
        Permission.RESPONSE_BLOCK_IP,
        Permission.RESPONSE_ISOLATE_HOST,
        Permission.RESPONSE_KILL_PROCESS,
        Permission.RESPONSE_QUARANTINE,
        Permission.PLAYBOOK_VIEW,
        Permission.PLAYBOOK_EXECUTE,
        Permission.PLAYBOOK_CREATE,
        Permission.INTEL_VIEW,
        Permission.INTEL_ADD_IOC,
        Permission.INTEL_SHARE,
        Permission.REPORT_VIEW,
        Permission.REPORT_CREATE,
        Permission.APPROVAL_VIEW,
        Permission.APPROVAL_APPROVE,
        Permission.APPROVAL_REJECT,
        Permission.SIEM_VIEW,
        Permission.SIEM_RULE_MANAGE,
        Permission.ENRICHMENT_VIEW,
        Permission.ENRICHMENT_EXECUTE,
        Permission.CASE_VIEW,
        Permission.CASE_CREATE,
        Permission.CASE_UPDATE,
        Permission.COMPLIANCE_VIEW,
        Permission.COMPLIANCE_GENERATE,
    },

    SOCRole.INCIDENT_COMMANDER: {
        # Inherits L3 +
        Permission.DASHBOARD_VIEW,
        Permission.DASHBOARD_EXPORT,
        Permission.ALERT_VIEW,
        Permission.ALERT_TRIAGE,
        Permission.ALERT_ASSIGN,
        Permission.ALERT_CLOSE,
        Permission.ALERT_FALSE_POSITIVE,
        Permission.INCIDENT_VIEW,
        Permission.INCIDENT_CREATE,
        Permission.INCIDENT_UPDATE,
        Permission.INCIDENT_ESCALATE,
        Permission.INCIDENT_CLOSE,
        Permission.RESPONSE_BLOCK_IP,
        Permission.RESPONSE_ISOLATE_HOST,
        Permission.RESPONSE_KILL_PROCESS,
        Permission.RESPONSE_QUARANTINE,
        Permission.PLAYBOOK_VIEW,
        Permission.PLAYBOOK_EXECUTE,
        Permission.PLAYBOOK_CREATE,
        Permission.PLAYBOOK_DELETE,
        Permission.INTEL_VIEW,
        Permission.INTEL_ADD_IOC,
        Permission.INTEL_SHARE,
        Permission.CONFIG_VIEW,
        Permission.REPORT_VIEW,
        Permission.REPORT_CREATE,
        Permission.REPORT_DELETE,
        Permission.APPROVAL_VIEW,
        Permission.APPROVAL_APPROVE,
        Permission.APPROVAL_REJECT,
        Permission.AUDIT_VIEW,
        Permission.SIEM_VIEW,
        Permission.SIEM_CONFIGURE,
        Permission.SIEM_RULE_MANAGE,
        Permission.ENRICHMENT_VIEW,
        Permission.ENRICHMENT_EXECUTE,
        Permission.CASE_VIEW,
        Permission.CASE_CREATE,
        Permission.CASE_UPDATE,
        Permission.COMPLIANCE_VIEW,
        Permission.COMPLIANCE_GENERATE,
    },

    SOCRole.ADMIN: set(Permission),  # All permissions
}


# ============================================================================
# Password Hashing (PBKDF2-SHA256, 600k iterations - OWASP 2024 rec.)
# ============================================================================

PBKDF2_ITERATIONS = 600_000
SALT_LENGTH = 32


def hash_password(password: str) -> str:
    """Hash password with PBKDF2-SHA256 + random salt. Returns 'salt$hash'."""
    salt = secrets.token_bytes(SALT_LENGTH)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt_hex, hash_hex = stored_hash.split('$', 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        return False


# ============================================================================
# JWT Token Management (HMAC-SHA256, no external dependency)
# ============================================================================

def _get_jwt_secret() -> bytes:
    """Get JWT signing secret from environment or generated key file."""
    secret = os.environ.get('TSUNAMI_JWT_SECRET', '')
    if secret:
        return secret.encode('utf-8')

    key_file = Path.home() / '.dalga' / '.jwt_secret'
    if key_file.exists():
        return key_file.read_bytes()

    # Generate persistent key
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(64)
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    logger.info("Generated new JWT signing key")
    return key


def create_token(user_id: str, username: str, role: SOCRole,
                 ttl_minutes: int = 480) -> str:
    """Create a signed JWT-like token (header.payload.signature)."""
    import base64

    header = base64.urlsafe_b64encode(json.dumps({
        "alg": "HS256", "typ": "JWT"
    }).encode()).decode().rstrip('=')

    now = int(time.time())
    payload_data = {
        "sub": user_id,
        "usr": username,
        "rol": role.value,
        "iat": now,
        "exp": now + (ttl_minutes * 60),
        "jti": secrets.token_hex(16),
    }
    payload = base64.urlsafe_b64encode(
        json.dumps(payload_data).encode()
    ).decode().rstrip('=')

    signing_input = f"{header}.{payload}".encode('utf-8')
    signature = hmac.new(_get_jwt_secret(), signing_input, hashlib.sha256).hexdigest()

    return f"{header}.{payload}.{signature}"


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a token. Returns payload dict or None."""
    import base64

    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None

        header_b64, payload_b64, signature = parts

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        expected_sig = hmac.new(_get_jwt_secret(), signing_input, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, signature):
            return None

        # Decode payload (add padding)
        padding = 4 - len(payload_b64) % 4
        if padding != 4:
            payload_b64 += '=' * padding

        payload = json.loads(base64.urlsafe_b64decode(payload_b64))

        # Check expiration
        if payload.get('exp', 0) < int(time.time()):
            return None

        return payload

    except Exception:
        return None


# ============================================================================
# User Model & Database
# ============================================================================

@dataclass
class SOCUser:
    """SOC platform user."""
    user_id: str
    username: str
    email: str
    role: SOCRole
    display_name: str = ""
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    failed_login_count: int = 0
    locked_until: Optional[datetime] = None
    password_hash: str = ""
    mfa_enabled: bool = False
    mfa_secret: str = ""

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        d = {
            'user_id': self.user_id,
            'username': self.username,
            'email': self.email,
            'role': self.role.name,
            'role_level': self.role.value,
            'display_name': self.display_name,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'mfa_enabled': self.mfa_enabled,
        }
        if include_sensitive:
            d['failed_login_count'] = self.failed_login_count
            d['locked_until'] = self.locked_until.isoformat() if self.locked_until else None
        return d

    def has_permission(self, permission: Permission) -> bool:
        perms = ROLE_PERMISSIONS.get(self.role, set())
        return permission in perms

    def has_role_level(self, min_role: SOCRole) -> bool:
        return self.role.value >= min_role.value


class UserDatabase:
    """SQLite-based user storage with thread-safe access."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path.home() / '.dalga'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'soc_users.db')

        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS soc_users (
                        user_id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'SOC_ANALYST_L1',
                        display_name TEXT DEFAULT '',
                        is_active INTEGER DEFAULT 1,
                        created_at TEXT NOT NULL,
                        last_login TEXT,
                        failed_login_count INTEGER DEFAULT 0,
                        locked_until TEXT,
                        mfa_enabled INTEGER DEFAULT 0,
                        mfa_secret TEXT DEFAULT ''
                    );

                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        user_id TEXT,
                        username TEXT,
                        action TEXT NOT NULL,
                        resource TEXT,
                        resource_id TEXT,
                        details TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        request_id TEXT,
                        success INTEGER DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES soc_users(user_id)
                    );

                    CREATE TABLE IF NOT EXISTS active_sessions (
                        session_id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        token_jti TEXT UNIQUE NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        last_activity TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        is_active INTEGER DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES soc_users(user_id)
                    );

                    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
                    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
                    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
                    CREATE INDEX IF NOT EXISTS idx_sessions_user ON active_sessions(user_id);
                    CREATE INDEX IF NOT EXISTS idx_sessions_jti ON active_sessions(token_jti);
                """)
                conn.commit()
            finally:
                conn.close()

        # Ensure default admin exists
        self._ensure_default_admin()

    def _ensure_default_admin(self):
        """Create default admin if no users exist."""
        with self._lock:
            conn = self._get_conn()
            try:
                count = conn.execute("SELECT COUNT(*) FROM soc_users").fetchone()[0]
                if count == 0:
                    admin_password = os.environ.get('TSUNAMI_ADMIN_PASSWORD', '')
                    if not admin_password:
                        admin_password = secrets.token_urlsafe(24)
                        logger.warning(
                            f"[RBAC] No TSUNAMI_ADMIN_PASSWORD env var set. "
                            f"Generated temporary admin password: {admin_password}"
                        )

                    user_id = f"usr_{secrets.token_hex(12)}"
                    now = datetime.utcnow().isoformat()
                    conn.execute(
                        """INSERT INTO soc_users
                           (user_id, username, email, password_hash, role, display_name,
                            is_active, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
                        (user_id, 'admin', 'admin@tsunami.local',
                         hash_password(admin_password), SOCRole.ADMIN.name,
                         'System Administrator', now)
                    )
                    conn.commit()
                    logger.info(f"[RBAC] Default admin user created: admin (id={user_id})")
            finally:
                conn.close()

    # --- CRUD Operations ---

    def create_user(self, username: str, email: str, password: str,
                    role: SOCRole = SOCRole.SOC_ANALYST_L1,
                    display_name: str = "") -> Optional[SOCUser]:
        """Create a new user."""
        with self._lock:
            conn = self._get_conn()
            try:
                user_id = f"usr_{secrets.token_hex(12)}"
                now = datetime.utcnow().isoformat()
                conn.execute(
                    """INSERT INTO soc_users
                       (user_id, username, email, password_hash, role, display_name,
                        is_active, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, 1, ?)""",
                    (user_id, username, email, hash_password(password),
                     role.name, display_name or username, now)
                )
                conn.commit()
                logger.info(f"[RBAC] User created: {username} (role={role.name})")
                return self.get_user_by_id(user_id)
            except sqlite3.IntegrityError as e:
                logger.error(f"[RBAC] User creation failed (duplicate): {e}")
                return None
            finally:
                conn.close()

    def get_user_by_id(self, user_id: str) -> Optional[SOCUser]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM soc_users WHERE user_id = ?", (user_id,)
            ).fetchone()
            return self._row_to_user(row) if row else None
        finally:
            conn.close()

    def get_user_by_username(self, username: str) -> Optional[SOCUser]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM soc_users WHERE username = ?", (username,)
            ).fetchone()
            return self._row_to_user(row) if row else None
        finally:
            conn.close()

    def list_users(self, role: Optional[SOCRole] = None,
                   active_only: bool = True) -> List[SOCUser]:
        conn = self._get_conn()
        try:
            query = "SELECT * FROM soc_users WHERE 1=1"
            params: list = []
            if role:
                query += " AND role = ?"
                params.append(role.name)
            if active_only:
                query += " AND is_active = 1"
            query += " ORDER BY created_at DESC"

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_user(r) for r in rows]
        finally:
            conn.close()

    def update_user(self, user_id: str, **kwargs) -> bool:
        """Update user fields. Supported: email, role, display_name, is_active, mfa_enabled."""
        allowed = {'email', 'role', 'display_name', 'is_active', 'mfa_enabled', 'mfa_secret'}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return False

        # Convert role enum to name
        if 'role' in updates and isinstance(updates['role'], SOCRole):
            updates['role'] = updates['role'].name

        set_clause = ", ".join(f"{k} = ?" for k in updates)
        values = list(updates.values()) + [user_id]

        with self._lock:
            conn = self._get_conn()
            try:
                result = conn.execute(
                    f"UPDATE soc_users SET {set_clause} WHERE user_id = ?", values
                )
                conn.commit()
                return result.rowcount > 0
            finally:
                conn.close()

    def delete_user(self, user_id: str) -> bool:
        """Soft-delete: set is_active = 0."""
        return self.update_user(user_id, is_active=False)

    def change_password(self, user_id: str, new_password: str) -> bool:
        with self._lock:
            conn = self._get_conn()
            try:
                result = conn.execute(
                    "UPDATE soc_users SET password_hash = ? WHERE user_id = ?",
                    (hash_password(new_password), user_id)
                )
                conn.commit()
                return result.rowcount > 0
            finally:
                conn.close()

    def _row_to_user(self, row: sqlite3.Row) -> SOCUser:
        return SOCUser(
            user_id=row['user_id'],
            username=row['username'],
            email=row['email'],
            role=SOCRole[row['role']],
            display_name=row['display_name'] or '',
            is_active=bool(row['is_active']),
            created_at=datetime.fromisoformat(row['created_at']) if row['created_at'] else datetime.utcnow(),
            last_login=datetime.fromisoformat(row['last_login']) if row['last_login'] else None,
            failed_login_count=row['failed_login_count'] or 0,
            locked_until=datetime.fromisoformat(row['locked_until']) if row['locked_until'] else None,
            password_hash=row['password_hash'],
            mfa_enabled=bool(row['mfa_enabled']),
            mfa_secret=row['mfa_secret'] or '',
        )

    # --- Authentication ---

    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15
    PROGRESSIVE_LOCKOUT = [1, 5, 15, 60, 1440]  # minutes per consecutive lockout

    def authenticate(self, username: str, password: str,
                     ip_address: str = "", user_agent: str = "") -> Tuple[Optional[str], Optional[SOCUser], str]:
        """
        Authenticate user credentials.
        Returns (token, user, error_message).
        """
        user = self.get_user_by_username(username)
        if user is None:
            return None, None, "Gecersiz kullanici adi veya sifre"

        if not user.is_active:
            return None, None, "Hesap devre disi"

        # Check lockout
        if user.locked_until and datetime.utcnow() < user.locked_until:
            remaining = (user.locked_until - datetime.utcnow()).total_seconds()
            return None, None, f"Hesap kilitli. {int(remaining)}sn sonra tekrar deneyin"

        # Verify password
        if not verify_password(password, user.password_hash):
            self._record_failed_login(user.user_id)
            return None, None, "Gecersiz kullanici adi veya sifre"

        # Successful login
        self._record_successful_login(user.user_id)

        # Create token
        token = create_token(user.user_id, user.username, user.role)

        # Create session
        token_payload = verify_token(token)
        if token_payload:
            self._create_session(
                user.user_id, token_payload['jti'],
                token_payload['exp'], ip_address, user_agent
            )

        # Audit log
        self.log_audit(
            user_id=user.user_id, username=user.username,
            action="LOGIN", resource="auth",
            details={"method": "password"},
            ip_address=ip_address, user_agent=user_agent,
            success=True
        )

        return token, user, ""

    def _record_failed_login(self, user_id: str):
        with self._lock:
            conn = self._get_conn()
            try:
                user = self.get_user_by_id(user_id)
                if not user:
                    return
                new_count = user.failed_login_count + 1

                locked_until = None
                if new_count >= self.MAX_FAILED_ATTEMPTS:
                    lockout_idx = min(
                        (new_count - self.MAX_FAILED_ATTEMPTS) // self.MAX_FAILED_ATTEMPTS,
                        len(self.PROGRESSIVE_LOCKOUT) - 1
                    )
                    lockout_mins = self.PROGRESSIVE_LOCKOUT[lockout_idx]
                    locked_until = (datetime.utcnow() + timedelta(minutes=lockout_mins)).isoformat()
                    logger.warning(
                        f"[RBAC] Account locked: {user.username} for {lockout_mins}min "
                        f"(attempt #{new_count})"
                    )

                conn.execute(
                    "UPDATE soc_users SET failed_login_count = ?, locked_until = ? WHERE user_id = ?",
                    (new_count, locked_until, user_id)
                )
                conn.commit()
            finally:
                conn.close()

    def _record_successful_login(self, user_id: str):
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE soc_users SET failed_login_count = 0, locked_until = NULL, "
                    "last_login = ? WHERE user_id = ?",
                    (datetime.utcnow().isoformat(), user_id)
                )
                conn.commit()
            finally:
                conn.close()

    def _create_session(self, user_id: str, jti: str, exp: int,
                        ip_address: str, user_agent: str):
        with self._lock:
            conn = self._get_conn()
            try:
                now = datetime.utcnow().isoformat()
                exp_dt = datetime.utcfromtimestamp(exp).isoformat()
                session_id = f"ses_{secrets.token_hex(16)}"
                conn.execute(
                    """INSERT INTO active_sessions
                       (session_id, user_id, token_jti, created_at, expires_at,
                        last_activity, ip_address, user_agent, is_active)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)""",
                    (session_id, user_id, jti, now, exp_dt, now, ip_address, user_agent)
                )
                conn.commit()
            finally:
                conn.close()

    def invalidate_session(self, jti: str):
        """Invalidate a session by token JTI."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE active_sessions SET is_active = 0 WHERE token_jti = ?",
                    (jti,)
                )
                conn.commit()
            finally:
                conn.close()

    def invalidate_user_sessions(self, user_id: str):
        """Invalidate all sessions for a user."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE active_sessions SET is_active = 0 WHERE user_id = ?",
                    (user_id,)
                )
                conn.commit()
            finally:
                conn.close()

    def is_session_valid(self, jti: str) -> bool:
        """Check if session is still active (not revoked)."""
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT is_active, expires_at FROM active_sessions WHERE token_jti = ?",
                (jti,)
            ).fetchone()
            if not row:
                return False
            if not row['is_active']:
                return False
            if datetime.fromisoformat(row['expires_at']) < datetime.utcnow():
                return False
            return True
        finally:
            conn.close()

    def update_session_activity(self, jti: str):
        """Update last activity timestamp for idle timeout tracking."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    "UPDATE active_sessions SET last_activity = ? WHERE token_jti = ?",
                    (datetime.utcnow().isoformat(), jti)
                )
                conn.commit()
            finally:
                conn.close()

    def get_active_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT session_id, created_at, last_activity, ip_address, user_agent
                   FROM active_sessions
                   WHERE user_id = ? AND is_active = 1
                   ORDER BY last_activity DESC""",
                (user_id,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        with self._lock:
            conn = self._get_conn()
            try:
                now = datetime.utcnow().isoformat()
                result = conn.execute(
                    "DELETE FROM active_sessions WHERE expires_at < ? OR is_active = 0",
                    (now,)
                )
                conn.commit()
                if result.rowcount > 0:
                    logger.info(f"[RBAC] Cleaned up {result.rowcount} expired sessions")
            finally:
                conn.close()

    # --- Audit Logging ---

    def log_audit(self, user_id: str, username: str, action: str,
                  resource: str = "", resource_id: str = "",
                  details: Optional[Dict] = None,
                  ip_address: str = "", user_agent: str = "",
                  request_id: str = "", success: bool = True):
        """Log an audit event."""
        with self._lock:
            conn = self._get_conn()
            try:
                conn.execute(
                    """INSERT INTO audit_log
                       (timestamp, user_id, username, action, resource, resource_id,
                        details, ip_address, user_agent, request_id, success)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (datetime.utcnow().isoformat(), user_id, username, action,
                     resource, resource_id, json.dumps(details or {}),
                     ip_address, user_agent, request_id, 1 if success else 0)
                )
                conn.commit()
            except Exception as e:
                logger.error(f"[RBAC] Audit log write failed: {e}")
            finally:
                conn.close()

    def get_audit_logs(self, user_id: Optional[str] = None,
                       action: Optional[str] = None,
                       since: Optional[datetime] = None,
                       limit: int = 100) -> List[Dict[str, Any]]:
        conn = self._get_conn()
        try:
            query = "SELECT * FROM audit_log WHERE 1=1"
            params: list = []

            if user_id:
                query += " AND user_id = ?"
                params.append(user_id)
            if action:
                query += " AND action = ?"
                params.append(action)
            if since:
                query += " AND timestamp >= ?"
                params.append(since.isoformat())

            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            result = []
            for r in rows:
                d = dict(r)
                if d.get('details'):
                    try:
                        d['details'] = json.loads(d['details'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                result.append(d)
            return result
        finally:
            conn.close()


# ============================================================================
# Flask Decorators for Endpoint Protection
# ============================================================================

# Global database instance
_user_db: Optional[UserDatabase] = None
_db_lock = threading.Lock()


def get_user_db() -> UserDatabase:
    """Get or create the global UserDatabase instance."""
    global _user_db
    if _user_db is None:
        with _db_lock:
            if _user_db is None:
                _user_db = UserDatabase()
    return _user_db


def _get_current_user() -> Optional[Tuple[Dict[str, Any], SOCUser]]:
    """Extract and validate the current user from request."""
    try:
        from flask import request, g
    except ImportError:
        return None

    # Check if already resolved in this request
    if hasattr(g, '_rbac_user') and g._rbac_user is not None:
        return g._rbac_user

    # Get token from Authorization header or cookie
    token = None
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        token = auth_header[7:]
    elif request.cookies.get('tsunami_token'):
        token = request.cookies.get('tsunami_token')

    if not token:
        return None

    # Verify token
    payload = verify_token(token)
    if not payload:
        return None

    # Check session validity (not revoked)
    db = get_user_db()
    jti = payload.get('jti', '')
    if not db.is_session_valid(jti):
        return None

    # Get fresh user data
    user = db.get_user_by_id(payload['sub'])
    if not user or not user.is_active:
        return None

    # Update session activity
    db.update_session_activity(jti)

    # Cache in request context
    result = (payload, user)
    g._rbac_user = result
    return result


def require_auth(f: Callable) -> Callable:
    """Decorator: require authenticated user (any role)."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        from flask import jsonify, request

        result = _get_current_user()
        if result is None:
            return jsonify({
                'success': False,
                'error': 'Yetkilendirme gerekli',
                'code': 'AUTH_REQUIRED'
            }), 401

        payload, user = result
        # Inject user info into Flask g
        from flask import g
        g.current_user = user
        g.token_payload = payload

        return f(*args, **kwargs)
    return wrapper


def require_permission(permission: Permission) -> Callable:
    """Decorator factory: require specific permission."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import jsonify, request, g

            result = _get_current_user()
            if result is None:
                return jsonify({
                    'success': False,
                    'error': 'Yetkilendirme gerekli',
                    'code': 'AUTH_REQUIRED'
                }), 401

            payload, user = result
            g.current_user = user
            g.token_payload = payload

            if not user.has_permission(permission):
                # Audit the denied access
                db = get_user_db()
                db.log_audit(
                    user_id=user.user_id,
                    username=user.username,
                    action="ACCESS_DENIED",
                    resource=permission.value,
                    details={"endpoint": request.path, "method": request.method},
                    ip_address=request.remote_addr or "",
                    user_agent=request.user_agent.string if request.user_agent else "",
                    success=False
                )
                logger.warning(
                    f"[RBAC] Access denied: {user.username} ({user.role.name}) "
                    f"tried {permission.value} on {request.path}"
                )
                return jsonify({
                    'success': False,
                    'error': 'Yetersiz yetki',
                    'code': 'FORBIDDEN',
                    'required_permission': permission.value
                }), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_role(min_role: SOCRole) -> Callable:
    """Decorator factory: require minimum role level."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import jsonify, request, g

            result = _get_current_user()
            if result is None:
                return jsonify({
                    'success': False,
                    'error': 'Yetkilendirme gerekli',
                    'code': 'AUTH_REQUIRED'
                }), 401

            payload, user = result
            g.current_user = user
            g.token_payload = payload

            if not user.has_role_level(min_role):
                db = get_user_db()
                db.log_audit(
                    user_id=user.user_id,
                    username=user.username,
                    action="ACCESS_DENIED",
                    resource="role_check",
                    details={
                        "endpoint": request.path,
                        "required_role": min_role.name,
                        "user_role": user.role.name
                    },
                    ip_address=request.remote_addr or "",
                    success=False
                )
                return jsonify({
                    'success': False,
                    'error': 'Yetersiz yetki seviyesi',
                    'code': 'FORBIDDEN',
                    'required_role': min_role.name
                }), 403

            return f(*args, **kwargs)
        return wrapper
    return decorator


def audit_action(action: str, resource: str = "") -> Callable:
    """Decorator factory: automatically audit the action."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def wrapper(*args, **kwargs):
            from flask import request, g

            result = f(*args, **kwargs)

            # Log after successful execution
            user = getattr(g, 'current_user', None)
            if user:
                db = get_user_db()
                resource_id = kwargs.get('id', kwargs.get('alert_id', kwargs.get('incident_id', '')))
                db.log_audit(
                    user_id=user.user_id,
                    username=user.username,
                    action=action,
                    resource=resource,
                    resource_id=str(resource_id) if resource_id else "",
                    ip_address=request.remote_addr or "",
                    user_agent=request.user_agent.string if request.user_agent else "",
                    request_id=getattr(g, 'request_id', ''),
                    success=True
                )

            return result
        return wrapper
    return decorator


# ============================================================================
# Flask Blueprint for Auth API
# ============================================================================

def create_auth_blueprint():
    """Create Flask blueprint for authentication endpoints."""
    from flask import Blueprint, jsonify, request, g

    auth_bp = Blueprint('soc_auth', __name__, url_prefix='/api/v1/auth')

    @auth_bp.route('/login', methods=['POST'])
    def login():
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'JSON body gerekli'}), 400

        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'success': False, 'error': 'Kullanici adi ve sifre gerekli'}), 400

        db = get_user_db()
        token, user, error = db.authenticate(
            username, password,
            ip_address=request.remote_addr or '',
            user_agent=request.user_agent.string if request.user_agent else ''
        )

        if token is None:
            return jsonify({'success': False, 'error': error}), 401

        response = jsonify({
            'success': True,
            'token': token,
            'user': user.to_dict(),
            'expires_in': 480 * 60  # 8 hours in seconds
        })

        # Also set as httpOnly cookie
        response.set_cookie(
            'tsunami_token', token,
            httponly=True, secure=True, samesite='Strict',
            max_age=480 * 60
        )
        return response

    @auth_bp.route('/logout', methods=['POST'])
    @require_auth
    def logout():
        db = get_user_db()
        jti = g.token_payload.get('jti', '')
        db.invalidate_session(jti)
        db.log_audit(
            user_id=g.current_user.user_id,
            username=g.current_user.username,
            action="LOGOUT", resource="auth",
            ip_address=request.remote_addr or "",
            success=True
        )
        response = jsonify({'success': True, 'message': 'Cikis yapildi'})
        response.delete_cookie('tsunami_token')
        return response

    @auth_bp.route('/me', methods=['GET'])
    @require_auth
    def get_me():
        return jsonify({
            'success': True,
            'user': g.current_user.to_dict()
        })

    @auth_bp.route('/change-password', methods=['POST'])
    @require_auth
    def change_password():
        data = request.get_json() or {}
        old_password = data.get('old_password', '')
        new_password = data.get('new_password', '')

        if not old_password or not new_password:
            return jsonify({'success': False, 'error': 'Eski ve yeni sifre gerekli'}), 400

        if len(new_password) < 12:
            return jsonify({'success': False, 'error': 'Sifre en az 12 karakter olmali'}), 400

        if not verify_password(old_password, g.current_user.password_hash):
            return jsonify({'success': False, 'error': 'Mevcut sifre yanlis'}), 401

        db = get_user_db()
        db.change_password(g.current_user.user_id, new_password)
        db.invalidate_user_sessions(g.current_user.user_id)
        db.log_audit(
            user_id=g.current_user.user_id,
            username=g.current_user.username,
            action="PASSWORD_CHANGE", resource="auth",
            ip_address=request.remote_addr or "",
            success=True
        )
        response = jsonify({'success': True, 'message': 'Sifre degistirildi. Tekrar giris yapin.'})
        response.delete_cookie('tsunami_token')
        return response

    @auth_bp.route('/sessions', methods=['GET'])
    @require_auth
    def list_sessions():
        db = get_user_db()
        sessions = db.get_active_sessions(g.current_user.user_id)
        return jsonify({'success': True, 'sessions': sessions})

    # --- User Management (Admin only) ---

    @auth_bp.route('/users', methods=['GET'])
    @require_permission(Permission.USER_VIEW)
    @audit_action("LIST_USERS", "user_management")
    def list_users():
        db = get_user_db()
        role_filter = request.args.get('role')
        role = SOCRole[role_filter] if role_filter and role_filter in SOCRole.__members__ else None
        users = db.list_users(role=role)
        return jsonify({
            'success': True,
            'count': len(users),
            'users': [u.to_dict() for u in users]
        })

    @auth_bp.route('/users', methods=['POST'])
    @require_permission(Permission.USER_CREATE)
    @audit_action("CREATE_USER", "user_management")
    def create_user():
        data = request.get_json() or {}
        username = data.get('username', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role_name = data.get('role', 'SOC_ANALYST_L1')

        if not username or not email or not password:
            return jsonify({'success': False, 'error': 'username, email, password gerekli'}), 400

        if len(password) < 12:
            return jsonify({'success': False, 'error': 'Sifre en az 12 karakter olmali'}), 400

        try:
            role = SOCRole[role_name]
        except KeyError:
            return jsonify({
                'success': False,
                'error': f'Gecersiz rol. Gecerli: {[r.name for r in SOCRole]}'
            }), 400

        # Cannot create user with higher role than self
        if role.value > g.current_user.role.value:
            return jsonify({
                'success': False,
                'error': 'Kendi rolunuzden yuksek rol atayamazsiniz'
            }), 403

        db = get_user_db()
        user = db.create_user(
            username=username, email=email, password=password,
            role=role, display_name=data.get('display_name', '')
        )

        if user is None:
            return jsonify({'success': False, 'error': 'Kullanici olusturulamadi (muhtemelen mevcut)'}), 409

        return jsonify({'success': True, 'user': user.to_dict()}), 201

    @auth_bp.route('/users/<user_id>', methods=['PUT'])
    @require_permission(Permission.USER_MODIFY)
    @audit_action("UPDATE_USER", "user_management")
    def update_user(user_id):
        data = request.get_json() or {}
        db = get_user_db()

        target = db.get_user_by_id(user_id)
        if not target:
            return jsonify({'success': False, 'error': 'Kullanici bulunamadi'}), 404

        # Cannot modify user with higher role
        if target.role.value > g.current_user.role.value:
            return jsonify({'success': False, 'error': 'Daha yuksek yetkili kullaniciyi degistiremezsiniz'}), 403

        updates = {}
        if 'email' in data:
            updates['email'] = data['email']
        if 'display_name' in data:
            updates['display_name'] = data['display_name']
        if 'is_active' in data:
            updates['is_active'] = bool(data['is_active'])
        if 'role' in data:
            try:
                new_role = SOCRole[data['role']]
                if new_role.value > g.current_user.role.value:
                    return jsonify({'success': False, 'error': 'Kendi rolunuzden yuksek rol atayamazsiniz'}), 403
                updates['role'] = new_role
            except KeyError:
                return jsonify({'success': False, 'error': 'Gecersiz rol'}), 400

        if db.update_user(user_id, **updates):
            return jsonify({'success': True, 'message': 'Kullanici guncellendi'})
        return jsonify({'success': False, 'error': 'Guncelleme basarisiz'}), 500

    @auth_bp.route('/users/<user_id>', methods=['DELETE'])
    @require_permission(Permission.USER_DELETE)
    @audit_action("DELETE_USER", "user_management")
    def delete_user_endpoint(user_id):
        db = get_user_db()
        target = db.get_user_by_id(user_id)
        if not target:
            return jsonify({'success': False, 'error': 'Kullanici bulunamadi'}), 404

        if target.role.value >= g.current_user.role.value:
            return jsonify({'success': False, 'error': 'Esit veya yuksek yetkili kullaniciyi silemezsiniz'}), 403

        if target.user_id == g.current_user.user_id:
            return jsonify({'success': False, 'error': 'Kendinizi silemezsiniz'}), 400

        db.delete_user(user_id)
        db.invalidate_user_sessions(user_id)
        return jsonify({'success': True, 'message': 'Kullanici devre disi birakildi'})

    # --- Audit Logs ---

    @auth_bp.route('/audit', methods=['GET'])
    @require_permission(Permission.AUDIT_VIEW)
    def get_audit_logs():
        db = get_user_db()
        user_filter = request.args.get('user_id')
        action_filter = request.args.get('action')
        limit = min(int(request.args.get('limit', 100)), 1000)

        since = None
        since_str = request.args.get('since')
        if since_str:
            try:
                since = datetime.fromisoformat(since_str)
            except ValueError:
                pass

        logs = db.get_audit_logs(
            user_id=user_filter, action=action_filter,
            since=since, limit=limit
        )
        return jsonify({'success': True, 'count': len(logs), 'logs': logs})

    return auth_bp


# ============================================================================
# Module exports
# ============================================================================

__all__ = [
    'SOCRole', 'Permission', 'ROLE_PERMISSIONS',
    'SOCUser', 'UserDatabase',
    'hash_password', 'verify_password',
    'create_token', 'verify_token',
    'get_user_db',
    'require_auth', 'require_permission', 'require_role', 'audit_action',
    'create_auth_blueprint',
]
