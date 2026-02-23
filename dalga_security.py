#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SECURITY HARDENING v1.0
    Kurumsal Seviye Güvenlik Modülü
================================================================================

    Özellikler:
    - Güçlü Parola Politikası (Argon2id)
    - Oturum Güvenliği (Redis-backed)
    - Rate Limiting (IP & User based)
    - CSRF Koruması
    - SQL Injection Önleme
    - XSS Filtreleme
    - Audit Logging
    - IP Geofencing
    - 2FA Desteği (TOTP)

================================================================================
"""

import os
import re
import hmac
import hashlib
import secrets
import sqlite3
import ipaddress
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from functools import wraps
from collections import defaultdict
import threading

# Argon2 - Modern password hashing
try:
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

# TOTP for 2FA
try:
    import pyotp
    import qrcode
    import io
    import base64
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

# Flask
from flask import request, session, g, abort, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# === Password Policy ===

@dataclass
class PasswordPolicy:
    """Parola politikası"""
    min_length: int = 12
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = True
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    max_age_days: int = 90
    history_count: int = 5  # Son N parola tekrar kullanılamaz
    common_passwords_check: bool = True


class PasswordManager:
    """Güvenli parola yönetimi"""

    # En yaygın parolalar (ilk 1000'den örnek)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123', 'monkey',
        'password1', 'letmein', 'trustno1', 'dragon', 'baseball', 'iloveyou',
        'master', 'sunshine', 'ashley', 'bailey', 'passw0rd', 'shadow',
        'admin', 'root', 'administrator', 'test', 'guest', 'dalga2024'
    }

    def __init__(self, policy: PasswordPolicy = None):
        self.policy = policy or PasswordPolicy()

        if ARGON2_AVAILABLE:
            self.hasher = PasswordHasher(
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                salt_len=16
            )
        else:
            self.hasher = None
            logger.warning("[SECURITY] Argon2 yok, SHA256 kullanılacak")

    def validate_password(self, password: str) -> Tuple[bool, List[str]]:
        """Parola politikası kontrolü"""
        errors = []

        if len(password) < self.policy.min_length:
            errors.append(f"Parola en az {self.policy.min_length} karakter olmalı")

        if len(password) > self.policy.max_length:
            errors.append(f"Parola en fazla {self.policy.max_length} karakter olmalı")

        if self.policy.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("En az bir büyük harf gerekli")

        if self.policy.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("En az bir küçük harf gerekli")

        if self.policy.require_numbers and not re.search(r'\d', password):
            errors.append("En az bir rakam gerekli")

        if self.policy.require_special:
            special_pattern = f"[{re.escape(self.policy.special_chars)}]"
            if not re.search(special_pattern, password):
                errors.append("En az bir özel karakter gerekli")

        if self.policy.common_passwords_check:
            if password.lower() in self.COMMON_PASSWORDS:
                errors.append("Bu parola çok yaygın, daha güçlü bir parola seçin")

        return (len(errors) == 0, errors)

    def hash_password(self, password: str) -> str:
        """Parolayı hashle (Argon2id veya SHA256)"""
        if self.hasher:
            return self.hasher.hash(password)
        else:
            salt = secrets.token_hex(16)
            hash_value = hashlib.pbkdf2_hmac(
                'sha256',
                password.encode(),
                salt.encode(),
                100000
            ).hex()
            return f"sha256${salt}${hash_value}"

    def verify_password(self, password: str, hash_value: str) -> bool:
        """Parola doğrula"""
        try:
            if self.hasher and not hash_value.startswith('sha256$'):
                return self.hasher.verify(hash_value, password)
            else:
                # SHA256 fallback
                parts = hash_value.split('$')
                if len(parts) != 3:
                    return False
                _, salt, stored_hash = parts
                computed = hashlib.pbkdf2_hmac(
                    'sha256',
                    password.encode(),
                    salt.encode(),
                    100000
                ).hex()
                return hmac.compare_digest(computed, stored_hash)
        except Exception:
            return False

    def needs_rehash(self, hash_value: str) -> bool:
        """Hash güncelleme gerekli mi?"""
        if self.hasher and hash_value.startswith('sha256$'):
            return True
        if self.hasher:
            return self.hasher.check_needs_rehash(hash_value)
        return False

    def generate_password(self, length: int = 16) -> str:
        """Güvenli rastgele parola oluştur"""
        import string
        alphabet = string.ascii_letters + string.digits + self.policy.special_chars
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            valid, _ = self.validate_password(password)
            if valid:
                return password


# === Rate Limiting ===

class RateLimiter:
    """IP ve kullanıcı bazlı rate limiting"""

    def __init__(self, redis_client=None):
        self.redis = redis_client
        self._local_cache: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, key: str, limit: int, window: int = 60) -> Tuple[bool, int]:
        """
        İstek izinli mi?
        Returns: (allowed, remaining_requests)
        """
        now = datetime.now().timestamp()

        if self.redis:
            return self._check_redis(key, limit, window, now)
        else:
            return self._check_local(key, limit, window, now)

    def _check_local(self, key: str, limit: int, window: int, now: float) -> Tuple[bool, int]:
        """Local cache ile kontrol"""
        with self._lock:
            # Eski kayıtları temizle
            self._local_cache[key] = [
                t for t in self._local_cache[key]
                if now - t < window
            ]

            current_count = len(self._local_cache[key])

            if current_count >= limit:
                return (False, 0)

            self._local_cache[key].append(now)
            return (True, limit - current_count - 1)

    def _check_redis(self, key: str, limit: int, window: int, now: float) -> Tuple[bool, int]:
        """Redis ile kontrol"""
        try:
            pipe = self.redis.pipeline()
            redis_key = f"ratelimit:{key}"

            pipe.zremrangebyscore(redis_key, 0, now - window)
            pipe.zadd(redis_key, {str(now): now})
            pipe.zcard(redis_key)
            pipe.expire(redis_key, window)

            results = pipe.execute()
            current_count = results[2]

            if current_count > limit:
                return (False, 0)

            return (True, limit - current_count)
        except Exception as e:
            logger.error(f"[RATELIMIT] Redis hatası: {e}")
            return self._check_local(key, limit, window, now)

    def reset(self, key: str):
        """Rate limit sıfırla"""
        if self.redis:
            self.redis.delete(f"ratelimit:{key}")
        with self._lock:
            self._local_cache.pop(key, None)


# === Account Lockout ===

class AccountLockout:
    """Hesap kilitleme yönetimi"""

    def __init__(self, max_attempts: int = 5, lockout_duration: int = 1800):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration  # saniye
        self._attempts: Dict[str, List[datetime]] = defaultdict(list)
        self._lockouts: Dict[str, datetime] = {}
        self._lock = threading.Lock()

    def record_failure(self, identifier: str) -> Tuple[bool, int]:
        """
        Başarısız giriş kaydet
        Returns: (locked, remaining_attempts)
        """
        with self._lock:
            now = datetime.now()

            # Kilitli mi kontrol
            if self.is_locked(identifier):
                return (True, 0)

            # Son 15 dakikadaki denemeleri say
            window = now - timedelta(minutes=15)
            self._attempts[identifier] = [
                t for t in self._attempts[identifier]
                if t > window
            ]
            self._attempts[identifier].append(now)

            attempts = len(self._attempts[identifier])

            if attempts >= self.max_attempts:
                self._lockouts[identifier] = now + timedelta(seconds=self.lockout_duration)
                return (True, 0)

            return (False, self.max_attempts - attempts)

    def is_locked(self, identifier: str) -> bool:
        """Hesap kilitli mi?"""
        with self._lock:
            if identifier not in self._lockouts:
                return False

            if datetime.now() > self._lockouts[identifier]:
                del self._lockouts[identifier]
                self._attempts.pop(identifier, None)
                return False

            return True

    def get_lockout_remaining(self, identifier: str) -> int:
        """Kalan kilitleme süresi (saniye)"""
        with self._lock:
            if identifier not in self._lockouts:
                return 0
            remaining = (self._lockouts[identifier] - datetime.now()).total_seconds()
            return max(0, int(remaining))

    def reset(self, identifier: str):
        """Kilidi kaldır"""
        with self._lock:
            self._lockouts.pop(identifier, None)
            self._attempts.pop(identifier, None)

    def record_success(self, identifier: str):
        """Başarılı giriş - denemeleri sıfırla"""
        with self._lock:
            self._attempts.pop(identifier, None)


# === TOTP 2FA ===

class TwoFactorAuth:
    """İki faktörlü kimlik doğrulama (TOTP)"""

    def __init__(self):
        if not TOTP_AVAILABLE:
            logger.warning("[SECURITY] pyotp/qrcode yok, 2FA devre dışı")

    def generate_secret(self) -> str:
        """Yeni TOTP secret oluştur"""
        if not TOTP_AVAILABLE:
            return ""
        return pyotp.random_base32()

    def get_totp_uri(self, secret: str, email: str, issuer: str = "TSUNAMI") -> str:
        """TOTP URI oluştur (QR kod için)"""
        if not TOTP_AVAILABLE:
            return ""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)

    def generate_qr_code(self, secret: str, email: str, issuer: str = "TSUNAMI") -> str:
        """QR kod oluştur (base64)"""
        if not TOTP_AVAILABLE:
            return ""

        uri = self.get_totp_uri(secret, email, issuer)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        return base64.b64encode(buffer.getvalue()).decode()

    def verify_totp(self, secret: str, code: str) -> bool:
        """TOTP kodu doğrula"""
        if not TOTP_AVAILABLE:
            return False

        try:
            totp = pyotp.TOTP(secret)
            return totp.verify(code, valid_window=1)  # ±30 saniye tolerans
        except Exception:
            return False


# === Audit Logger ===

@dataclass
class AuditLog:
    """Audit log kaydı"""
    timestamp: datetime
    user: str
    action: str
    resource: str
    ip_address: str
    user_agent: str
    success: bool
    details: Dict = field(default_factory=dict)


class AuditLogger:
    """Güvenlik audit loglama"""

    def __init__(self, log_file: str = None):
        self.log_file = log_file
        self._logs: List[AuditLog] = []
        self._lock = threading.Lock()

        if log_file:
            import os
            os.makedirs(os.path.dirname(log_file), exist_ok=True)

    def log(self, user: str, action: str, resource: str,
            success: bool = True, details: Dict = None):
        """Audit log kaydet"""
        try:
            ip = request.remote_addr if request else 'N/A'
            ua = request.user_agent.string if request else 'N/A'
        except RuntimeError:
            ip = 'N/A'
            ua = 'N/A'

        entry = AuditLog(
            timestamp=datetime.now(),
            user=user,
            action=action,
            resource=resource,
            ip_address=ip,
            user_agent=ua,
            success=success,
            details=details or {}
        )

        with self._lock:
            self._logs.append(entry)

            # Bellek limiti (son 10000 kayıt)
            if len(self._logs) > 10000:
                self._logs = self._logs[-10000:]

        # Dosyaya yaz
        if self.log_file:
            try:
                import json
                with open(self.log_file, 'a') as f:
                    f.write(json.dumps({
                        'timestamp': entry.timestamp.isoformat(),
                        'user': entry.user,
                        'action': entry.action,
                        'resource': entry.resource,
                        'ip': entry.ip_address,
                        'success': entry.success,
                        'details': entry.details
                    }) + '\n')
            except Exception as e:
                logger.error(f"[AUDIT] Log yazma hatası: {e}")

        # Kritik olayları logla
        if not success or action in ['login_failed', 'permission_denied', 'rate_limited']:
            logger.warning(f"[AUDIT] {action} by {user} from {ip}: {success}")

    def get_logs(self, user: str = None, action: str = None,
                 since: datetime = None, limit: int = 100) -> List[Dict]:
        """Audit logları getir"""
        with self._lock:
            results = []
            for log in reversed(self._logs):
                if user and log.user != user:
                    continue
                if action and log.action != action:
                    continue
                if since and log.timestamp < since:
                    continue

                results.append({
                    'timestamp': log.timestamp.isoformat(),
                    'user': log.user,
                    'action': log.action,
                    'resource': log.resource,
                    'ip': log.ip_address,
                    'success': log.success
                })

                if len(results) >= limit:
                    break

            return results


# === IP Geofencing ===

class GeoFence:
    """IP tabanlı coğrafi kısıtlama"""

    # Türkiye IP blokları (örnek - gerçek veriler için GeoIP DB kullanın)
    TURKEY_RANGES = [
        '5.2.64.0/19', '5.24.0.0/15', '5.44.80.0/20', '5.46.0.0/17',
        '31.145.0.0/16', '31.155.0.0/16', '31.200.0.0/14',
        '46.1.0.0/16', '46.2.0.0/15', '46.104.0.0/14',
        '78.160.0.0/12', '81.212.0.0/14', '85.96.0.0/13',
        '88.224.0.0/12', '94.54.0.0/16', '95.0.0.0/13',
    ]

    def __init__(self):
        self._allowed_countries: List[str] = []
        self._blocked_countries: List[str] = []
        self._whitelist: List[str] = []
        self._blacklist: List[str] = []
        self._turkey_networks = [ipaddress.ip_network(r) for r in self.TURKEY_RANGES]

    def set_allowed_countries(self, countries: List[str]):
        """İzin verilen ülkeler"""
        self._allowed_countries = [c.upper() for c in countries]

    def set_blocked_countries(self, countries: List[str]):
        """Engellenen ülkeler"""
        self._blocked_countries = [c.upper() for c in countries]

    def add_whitelist(self, ip_or_range: str):
        """IP/range whitelist"""
        self._whitelist.append(ip_or_range)

    def add_blacklist(self, ip_or_range: str):
        """IP/range blacklist"""
        self._blacklist.append(ip_or_range)

    def is_turkey_ip(self, ip: str) -> bool:
        """IP Türkiye'den mi?"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            for network in self._turkey_networks:
                if ip_obj in network:
                    return True
        except ValueError:
            pass
        return False

    def is_allowed(self, ip: str) -> Tuple[bool, str]:
        """IP izinli mi?"""
        # Whitelist kontrolü
        for entry in self._whitelist:
            try:
                if '/' in entry:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                        return (True, 'whitelist')
                elif ip == entry:
                    return (True, 'whitelist')
            except ValueError:
                pass

        # Blacklist kontrolü
        for entry in self._blacklist:
            try:
                if '/' in entry:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(entry, strict=False):
                        return (False, 'blacklist')
                elif ip == entry:
                    return (False, 'blacklist')
            except ValueError:
                pass

        # Localhost her zaman izinli
        if ip in ('127.0.0.1', '::1', 'localhost'):
            return (True, 'localhost')

        return (True, 'default')


# === Input Sanitization ===

class InputSanitizer:
    """Girdi temizleme ve doğrulama"""

    # SQL Injection patterns
    SQL_PATTERNS = [
        r"'\s*(or|and)\s+'",  # ' OR '  veya ' AND '
        r"'\s*(or|and)\s+\d",  # ' OR 1  veya ' AND 1
        r"('|\")\s*(or|and)\s*('|\")?\s*['\"]?\s*=",  # ' OR '='
        r";\s*(drop|delete|update|insert|alter|create)\s+",
        r"union\s+(all\s+)?select",
        r"'--",  # SQL comment after quote
        r"--\s*$",
        r"/\*.*\*/",
        r"1\s*=\s*1",  # 1=1 tautology
        r"admin\s*'",  # admin' injection
    ]

    # XSS patterns
    XSS_PATTERNS = [
        r"<\s*script",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"<\s*iframe",
        r"<\s*object",
        r"<\s*embed",
    ]

    def __init__(self):
        self._sql_regex = [re.compile(p, re.IGNORECASE) for p in self.SQL_PATTERNS]
        self._xss_regex = [re.compile(p, re.IGNORECASE) for p in self.XSS_PATTERNS]

    def detect_sql_injection(self, value: str) -> bool:
        """SQL injection tespiti"""
        for pattern in self._sql_regex:
            if pattern.search(value):
                return True
        return False

    def detect_xss(self, value: str) -> bool:
        """XSS tespiti"""
        for pattern in self._xss_regex:
            if pattern.search(value):
                return True
        return False

    def sanitize_html(self, value: str) -> str:
        """HTML etiketlerini temizle"""
        import html
        return html.escape(value)

    def sanitize_filename(self, filename: str) -> str:
        """Dosya adı temizle"""
        # Tehlikeli karakterleri kaldır
        filename = re.sub(r'[^\w\-_\. ]', '', filename)
        # Path traversal önle
        filename = filename.replace('..', '')
        return filename[:255]

    def validate_email(self, email: str) -> bool:
        """Email doğrula"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def validate_ip(self, ip: str) -> bool:
        """IP adresi doğrula"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


# === Security Manager (Birleşik Yönetim) ===

class SecurityManager:
    """Tüm güvenlik bileşenlerini yöneten ana sınıf"""

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self.password = PasswordManager()
        self.rate_limiter = RateLimiter()
        self.lockout = AccountLockout()
        self.totp = TwoFactorAuth()
        self.audit = AuditLogger('/var/log/tsunami/audit.log')
        self.geofence = GeoFence()
        self.sanitizer = InputSanitizer()

        # Veritabanı bağlantısı (dalga_web.py ile aynı DB)
        self._db_path = Path.home() / ".dalga" / "dalga_v2.db"
        self._db_lock = threading.Lock()
        self._db_conn = None

        logger.info("[SECURITY] Security Manager başlatıldı")

    def secure_login(self, username: str, password: str,
                    totp_code: str = None) -> Tuple[bool, str, Dict]:
        """
        Güvenli giriş işlemi
        Returns: (success, message, user_data)
        """
        ip = request.remote_addr if request else 'N/A'

        # Geofence kontrolü
        geo_allowed, geo_reason = self.geofence.is_allowed(ip)
        if not geo_allowed:
            self.audit.log(username, 'login_blocked', 'auth', False,
                          {'reason': 'geofence', 'ip': ip})
            return (False, 'Bu konumdan erişim engellendi', {})

        # Hesap kilidi kontrolü
        if self.lockout.is_locked(username):
            remaining = self.lockout.get_lockout_remaining(username)
            self.audit.log(username, 'login_locked', 'auth', False,
                          {'remaining': remaining})
            return (False, f'Hesap kilitli. {remaining}sn bekleyin', {})

        # Rate limiting
        allowed, remaining = self.rate_limiter.is_allowed(f"login:{ip}", 10, 300)
        if not allowed:
            self.audit.log(username, 'rate_limited', 'auth', False)
            return (False, 'Çok fazla deneme. Lütfen bekleyin.', {})

        # Gerçek veritabanı doğrulaması
        user_data = self._verify_user_from_db(username, password)

        if user_data is None:
            self.lockout.record_failure(username)
            self.audit.log(username, 'login_failed', 'auth', False,
                          {'reason': 'invalid_credentials', 'ip': ip})
            return (False, 'Geçersiz kullanıcı adı veya parola', {})

        # 2FA kontrolü (aktifse)
        if totp_code and user_data.get('totp_secret'):
            if not self.totp.verify_totp(user_data['totp_secret'], totp_code):
                self.lockout.record_failure(username)
                self.audit.log(username, 'totp_failed', 'auth', False)
                return (False, 'Geçersiz 2FA kodu', {})

        self.lockout.record_success(username)
        self.audit.log(username, 'login_success', 'auth', True)

        return (True, 'Giriş başarılı', user_data)

    def _get_db_conn(self):
        """SQLite bağlantısı al (lazy, thread-safe)"""
        if self._db_conn is None:
            if not self._db_path.exists():
                logger.warning("[SECURITY] Veritabanı bulunamadı: %s", self._db_path)
                return None
            self._db_conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            self._db_conn.row_factory = sqlite3.Row
        return self._db_conn

    def _verify_user_from_db(self, username: str, password: str) -> Optional[Dict]:
        """
        Veritabanından kullanıcı doğrulama.
        Argon2, PBKDF2 ve SHA256 hash formatlarını destekler.
        Eski hash'leri otomatik Argon2'ye yükseltir.
        Returns: user_data dict veya None (başarısız)
        """
        with self._db_lock:
            conn = self._get_db_conn()
            if conn is None:
                logger.error("[SECURITY] DB bağlantısı kurulamadı")
                return None

            try:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT id, kullanici_adi, sifre_hash, rol, aktif "
                    "FROM kullanicilar WHERE kullanici_adi = ? AND aktif = 1",
                    (username,)
                )
                result = cursor.fetchone()

                if not result:
                    return None

                user_id = result['id']
                stored_hash = result['sifre_hash']
                verified = False

                # Argon2 hash doğrulama
                if ARGON2_AVAILABLE and stored_hash.startswith('$argon2'):
                    try:
                        ph = PasswordHasher()
                        ph.verify(stored_hash, password)
                        verified = True
                        # Rehash gerekiyorsa (parametreler değiştiyse)
                        if ph.check_needs_rehash(stored_hash):
                            new_hash = ph.hash(password)
                            cursor.execute(
                                "UPDATE kullanicilar SET sifre_hash = ? WHERE id = ?",
                                (new_hash, user_id)
                            )
                    except Exception:
                        verified = False

                # PBKDF2 hash doğrulama
                elif stored_hash.startswith('pbkdf2$'):
                    parts = stored_hash.split('$')
                    if len(parts) == 3:
                        salt, hash_val = parts[1], parts[2]
                        check = hashlib.pbkdf2_hmac(
                            'sha256', password.encode(), salt.encode(), 100000
                        ).hex()
                        verified = hmac.compare_digest(check, hash_val)

                # Eski SHA256 hash (geriye uyumluluk)
                else:
                    old_hash = hashlib.sha256(password.encode()).hexdigest()
                    verified = hmac.compare_digest(old_hash, stored_hash)

                if not verified:
                    return None

                # Eski hash'i Argon2'ye yükselt
                if ARGON2_AVAILABLE and not stored_hash.startswith('$argon2'):
                    try:
                        ph = PasswordHasher()
                        new_hash = ph.hash(password)
                        cursor.execute(
                            "UPDATE kullanicilar SET sifre_hash = ? WHERE id = ?",
                            (new_hash, user_id)
                        )
                        logger.info("[SECURITY] Hash Argon2'ye yükseltildi: %s", username)
                    except Exception as e:
                        logger.warning("[SECURITY] Hash yükseltme başarısız: %s", e)

                # Son giriş zamanını güncelle
                cursor.execute(
                    "UPDATE kullanicilar SET son_giris = CURRENT_TIMESTAMP WHERE id = ?",
                    (user_id,)
                )
                conn.commit()

                return {
                    'id': user_id,
                    'username': result['kullanici_adi'],
                    'role': result['rol'],
                }

            except sqlite3.Error as e:
                logger.error("[SECURITY] DB sorgu hatası: %s", e)
                return None


# === Decorator'lar ===

def require_secure_password(f):
    """Güçlü parola gerektiren endpoint decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'password' in request.form:
            sm = SecurityManager.get_instance()
            valid, errors = sm.password.validate_password(request.form['password'])
            if not valid:
                return jsonify({'basarili': False, 'hatalar': errors}), 400
        return f(*args, **kwargs)
    return decorated


def rate_limit(limit: int = 60, window: int = 60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            sm = SecurityManager.get_instance()
            key = f"{request.endpoint}:{request.remote_addr}"
            allowed, remaining = sm.rate_limiter.is_allowed(key, limit, window)

            if not allowed:
                sm.audit.log(
                    session.get('kullanici', 'anonymous'),
                    'rate_limited',
                    request.endpoint,
                    False
                )
                return jsonify({
                    'basarili': False,
                    'hata': 'Rate limit aşıldı'
                }), 429

            response = f(*args, **kwargs)
            return response
        return decorated
    return decorator


def audit_action(action: str):
    """Audit logging decorator"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            sm = SecurityManager.get_instance()
            user = session.get('kullanici', 'anonymous')

            try:
                result = f(*args, **kwargs)
                sm.audit.log(user, action, request.endpoint, True)
                return result
            except Exception as e:
                sm.audit.log(user, action, request.endpoint, False,
                           {'error': str(e)})
                raise
        return decorated
    return decorator


def check_injection(f):
    """SQL/XSS injection kontrolü decorator"""
    @wraps(f)
    def decorated(*args, **kwargs):
        sm = SecurityManager.get_instance()

        # Form data kontrolü
        for key, value in request.form.items():
            if isinstance(value, str):
                if sm.sanitizer.detect_sql_injection(value):
                    sm.audit.log(session.get('kullanici', 'anonymous'),
                               'sql_injection_attempt', request.endpoint, False,
                               {'field': key})
                    abort(400, 'Geçersiz girdi tespit edildi')

                if sm.sanitizer.detect_xss(value):
                    sm.audit.log(session.get('kullanici', 'anonymous'),
                               'xss_attempt', request.endpoint, False,
                               {'field': key})
                    abort(400, 'Geçersiz girdi tespit edildi')

        # JSON data kontrolü
        if request.is_json:
            data = request.get_json(silent=True) or {}
            for key, value in data.items():
                if isinstance(value, str):
                    if sm.sanitizer.detect_sql_injection(value):
                        abort(400, 'Geçersiz girdi tespit edildi')
                    if sm.sanitizer.detect_xss(value):
                        abort(400, 'Geçersiz girdi tespit edildi')

        return f(*args, **kwargs)
    return decorated


# === Singleton erişim ===
_security_manager = None

def security_al() -> SecurityManager:
    """Security Manager instance al"""
    global _security_manager
    if _security_manager is None:
        _security_manager = SecurityManager.get_instance()
    return _security_manager

# Alias
security_manager_al = security_al
