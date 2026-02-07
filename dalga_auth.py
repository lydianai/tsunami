#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Authentication & Security v1.0
======================================

Kimlik doğrulama ve güvenlik modülü.
- CSRF token koruması
- Rate limiting
- 2FA/TOTP desteği
- Session güvenliği
- Brute-force koruması

KULLANIM:
    from dalga_auth import (
        csrf_protect, rate_limit, require_2fa,
        generate_totp_secret, verify_totp
    )
"""

import os
import hmac
import hashlib
import secrets
import logging
import time
from typing import Optional, Callable, Dict, Any
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict

from flask import (
    request, session, jsonify, g, current_app,
    make_response, abort
)

logger = logging.getLogger(__name__)


# ============================================================
# CSRF Protection
# ============================================================

class CSRFProtection:
    """
    CSRF token koruması.

    Kullanım:
        csrf = CSRFProtection(app)

        @app.route('/api/action', methods=['POST'])
        @csrf.protect
        def action():
            ...
    """

    TOKEN_LENGTH = 32
    TOKEN_HEADER = 'X-CSRF-Token'
    TOKEN_FORM_FIELD = 'csrf_token'
    SESSION_KEY = '_csrf_token'

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Flask app'e bağla"""
        app.config.setdefault('CSRF_ENABLED', True)
        app.config.setdefault('CSRF_TIME_LIMIT', 3600)  # 1 saat

        # Her response'a CSRF token ekle
        @app.after_request
        def add_csrf_token(response):
            if 'text/html' in response.content_type:
                token = self.generate_token()
                response.set_cookie(
                    'csrf_token',
                    token,
                    httponly=False,  # JavaScript erişimi için
                    secure=app.config.get('SESSION_COOKIE_SECURE', False),
                    samesite='Strict'
                )
            return response

    def generate_token(self) -> str:
        """Yeni CSRF token oluştur"""
        if self.SESSION_KEY not in session:
            session[self.SESSION_KEY] = secrets.token_hex(self.TOKEN_LENGTH)
        return session[self.SESSION_KEY]

    def validate_token(self, token: str) -> bool:
        """Token'ı doğrula"""
        expected = session.get(self.SESSION_KEY)
        if not expected or not token:
            return False

        # Timing-safe karşılaştırma
        return hmac.compare_digest(expected, token)

    def get_token_from_request(self) -> Optional[str]:
        """Request'ten token al"""
        # Header'dan dene
        token = request.headers.get(self.TOKEN_HEADER)
        if token:
            return token

        # Form data'dan dene
        token = request.form.get(self.TOKEN_FORM_FIELD)
        if token:
            return token

        # JSON body'den dene
        if request.is_json:
            data = request.get_json(silent=True) or {}
            token = data.get(self.TOKEN_FORM_FIELD)
            if token:
                return token

        # Cookie'den dene
        token = request.cookies.get('csrf_token')
        return token

    def protect(self, f: Callable):
        """CSRF koruması decorator"""
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not current_app.config.get('CSRF_ENABLED', True):
                return f(*args, **kwargs)

            # GET, HEAD, OPTIONS metodları CSRF'den muaf
            if request.method in ('GET', 'HEAD', 'OPTIONS'):
                return f(*args, **kwargs)

            token = self.get_token_from_request()

            if not self.validate_token(token):
                logger.warning(f"[CSRF] Token doğrulama başarısız: {request.path}")
                return jsonify({
                    'success': False,
                    'error': 'CSRF token geçersiz'
                }), 403

            return f(*args, **kwargs)

        return wrapper


# Global CSRF instance
csrf = CSRFProtection()


def csrf_protect(f: Callable):
    """CSRF koruması decorator (kısa yol)"""
    return csrf.protect(f)


# ============================================================
# Rate Limiting
# ============================================================

class RateLimiter:
    """
    In-memory rate limiter.

    Production'da Redis kullanın.
    """

    def __init__(self):
        self._requests: Dict[str, list] = defaultdict(list)
        self._blocked: Dict[str, float] = {}

    def _get_key(self, identifier: str, endpoint: str = "") -> str:
        """Rate limit key oluştur"""
        return f"{identifier}:{endpoint}"

    def _clean_old_requests(self, key: str, window: int):
        """Eski request'leri temizle"""
        now = time.time()
        self._requests[key] = [
            t for t in self._requests[key]
            if now - t < window
        ]

    def is_allowed(self, identifier: str, limit: int, window: int,
                   endpoint: str = "") -> tuple[bool, int]:
        """
        İstek izin veriliyor mu?

        Args:
            identifier: IP adresi veya user ID
            limit: Maksimum istek sayısı
            window: Zaman penceresi (saniye)
            endpoint: Endpoint adı (opsiyonel)

        Returns:
            (izin_var_mı, kalan_istek_sayısı)
        """
        key = self._get_key(identifier, endpoint)
        now = time.time()

        # Block kontrolü
        if key in self._blocked:
            if now < self._blocked[key]:
                return False, 0
            del self._blocked[key]

        # Eski request'leri temizle
        self._clean_old_requests(key, window)

        # Limit kontrolü
        current_count = len(self._requests[key])

        if current_count >= limit:
            return False, 0

        # Request'i kaydet
        self._requests[key].append(now)

        return True, limit - current_count - 1

    def block(self, identifier: str, duration: int, endpoint: str = ""):
        """Identifier'ı belirli süre blokla"""
        key = self._get_key(identifier, endpoint)
        self._blocked[key] = time.time() + duration
        logger.warning(f"[RATE_LIMIT] Bloklandı: {key} ({duration}s)")


# Global rate limiter
rate_limiter = RateLimiter()


def rate_limit(limit: int = 100, window: int = 60, per_endpoint: bool = True):
    """
    Rate limiting decorator.

    Kullanım:
        @app.route('/api/action')
        @rate_limit(limit=10, window=60)  # 60 saniyede 10 istek
        def action():
            ...
    """
    def decorator(f: Callable):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # IP adresi al
            identifier = request.headers.get('X-Forwarded-For', request.remote_addr)
            if identifier:
                identifier = identifier.split(',')[0].strip()

            endpoint = request.endpoint if per_endpoint else ""

            allowed, remaining = rate_limiter.is_allowed(
                identifier, limit, window, endpoint
            )

            # Rate limit header'ları ekle
            g.rate_limit_remaining = remaining

            if not allowed:
                logger.warning(f"[RATE_LIMIT] Limit aşıldı: {identifier} - {request.path}")
                response = jsonify({
                    'success': False,
                    'error': 'Rate limit aşıldı',
                    'retry_after': window
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(window)
                return response

            return f(*args, **kwargs)

        return wrapper
    return decorator


# ============================================================
# Brute-Force Protection
# ============================================================

class BruteForceProtection:
    """
    Brute-force saldırı koruması.

    - Başarısız giriş denemelerini takip et
    - Exponential backoff uygula
    - Belirli süre sonra blokla
    """

    MAX_ATTEMPTS = 5
    BLOCK_DURATION = 300  # 5 dakika
    BACKOFF_MULTIPLIER = 2

    def __init__(self):
        self._attempts: Dict[str, list] = defaultdict(list)
        self._blocked: Dict[str, tuple] = {}  # (unblock_time, attempt_count)

    def record_attempt(self, identifier: str, success: bool):
        """Giriş denemesini kaydet"""
        now = time.time()

        if success:
            # Başarılı giriş - geçmişi temizle
            self._attempts.pop(identifier, None)
            self._blocked.pop(identifier, None)
            logger.info(f"[AUTH] Başarılı giriş: {identifier}")
            return

        # Başarısız deneme
        self._attempts[identifier].append(now)

        # Son 10 dakikadaki denemeleri say
        recent = [t for t in self._attempts[identifier] if now - t < 600]
        self._attempts[identifier] = recent

        if len(recent) >= self.MAX_ATTEMPTS:
            # Blokla
            attempt_count = len(recent)
            block_duration = self.BLOCK_DURATION * (self.BACKOFF_MULTIPLIER ** (attempt_count - self.MAX_ATTEMPTS))
            block_duration = min(block_duration, 3600)  # Max 1 saat

            self._blocked[identifier] = (now + block_duration, attempt_count)
            logger.warning(f"[AUTH] Bloklandı: {identifier} ({block_duration}s)")

    def is_blocked(self, identifier: str) -> tuple[bool, int]:
        """
        Identifier bloklanmış mı?

        Returns:
            (bloklanmış_mı, kalan_süre)
        """
        if identifier not in self._blocked:
            return False, 0

        unblock_time, _ = self._blocked[identifier]
        now = time.time()

        if now >= unblock_time:
            del self._blocked[identifier]
            return False, 0

        return True, int(unblock_time - now)

    def get_remaining_attempts(self, identifier: str) -> int:
        """Kalan deneme hakkı"""
        now = time.time()
        recent = [t for t in self._attempts.get(identifier, []) if now - t < 600]
        return max(0, self.MAX_ATTEMPTS - len(recent))


# Global instance
brute_force = BruteForceProtection()


# ============================================================
# 2FA / TOTP
# ============================================================

try:
    import pyotp
    import qrcode
    import qrcode.image.svg
    from io import BytesIO
    import base64
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False
    logger.warning("[2FA] pyotp veya qrcode yüklü değil. 2FA devre dışı.")


class TOTPManager:
    """
    TOTP (Time-based One-Time Password) yönetimi.

    Google Authenticator, Authy vb. ile uyumlu.
    """

    ISSUER = "TSUNAMI"
    DIGITS = 6
    INTERVAL = 30

    def __init__(self):
        if not TOTP_AVAILABLE:
            raise RuntimeError("2FA için pyotp ve qrcode gerekli: pip install pyotp qrcode")

    def generate_secret(self) -> str:
        """Yeni TOTP secret oluştur"""
        return pyotp.random_base32()

    def get_totp(self, secret: str) -> "pyotp.TOTP":
        """TOTP objesi al"""
        return pyotp.TOTP(secret, digits=self.DIGITS, interval=self.INTERVAL)

    def verify(self, secret: str, code: str, valid_window: int = 1) -> bool:
        """
        TOTP kodunu doğrula.

        Args:
            secret: TOTP secret
            code: Kullanıcıdan gelen kod
            valid_window: Kaç periyod tolerans (önce/sonra)

        Returns:
            Doğru mu?
        """
        try:
            totp = self.get_totp(secret)
            return totp.verify(code, valid_window=valid_window)
        except Exception as e:
            logger.error(f"[2FA] Doğrulama hatası: {e}")
            return False

    def get_current_code(self, secret: str) -> str:
        """Şu anki TOTP kodunu al (test için)"""
        totp = self.get_totp(secret)
        return totp.now()

    def get_provisioning_uri(self, secret: str, username: str) -> str:
        """QR kod için URI oluştur"""
        totp = self.get_totp(secret)
        return totp.provisioning_uri(name=username, issuer_name=self.ISSUER)

    def generate_qr_code(self, secret: str, username: str) -> str:
        """
        QR kod oluştur (base64 SVG).

        Returns:
            Base64 encoded SVG
        """
        uri = self.get_provisioning_uri(secret, username)

        # QR kod oluştur
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        # SVG olarak kaydet
        img = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        buffer = BytesIO()
        img.save(buffer)
        buffer.seek(0)

        # Base64 encode
        svg_data = buffer.getvalue().decode('utf-8')
        b64 = base64.b64encode(svg_data.encode()).decode()

        return f"data:image/svg+xml;base64,{b64}"


# Global instance (lazy init)
_totp_manager: Optional[TOTPManager] = None


def get_totp_manager() -> TOTPManager:
    """TOTP manager al"""
    global _totp_manager
    if _totp_manager is None and TOTP_AVAILABLE:
        _totp_manager = TOTPManager()
    return _totp_manager


def generate_totp_secret() -> str:
    """Yeni TOTP secret oluştur"""
    manager = get_totp_manager()
    if manager:
        return manager.generate_secret()
    raise RuntimeError("2FA kullanılamıyor")


def verify_totp(secret: str, code: str) -> bool:
    """TOTP kodunu doğrula"""
    manager = get_totp_manager()
    if manager:
        return manager.verify(secret, code)
    return False


def require_2fa(f: Callable):
    """
    2FA zorunlu decorator.

    Session'da 2fa_verified=True olmalı.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('2fa_verified'):
            return jsonify({
                'success': False,
                'error': '2FA doğrulaması gerekli',
                'require_2fa': True
            }), 401

        return f(*args, **kwargs)

    return wrapper


# ============================================================
# Session Security
# ============================================================

def secure_session_config(app):
    """Flask session güvenlik ayarları"""
    app.config.update(
        SESSION_COOKIE_SECURE=True,  # HTTPS only
        SESSION_COOKIE_HTTPONLY=True,  # JavaScript erişimi yok
        SESSION_COOKIE_SAMESITE='Lax',  # CSRF koruması
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # Session timeout
        SESSION_REFRESH_EACH_REQUEST=True,  # Her istekte yenile
    )


def regenerate_session():
    """Session ID'yi yenile (session fixation koruması)"""
    old_session = dict(session)
    session.clear()
    session.update(old_session)
    session.modified = True


class SessionSecurityManager:
    """
    Session güvenlik yöneticisi.

    Kullanım:
        session_mgr = SessionSecurityManager()
        session_mgr.regenerate_session()
        session_mgr.clear_session()
    """

    def __init__(self, app=None):
        self.app = app

    def regenerate_session(self):
        """Session ID'yi yenile (session fixation koruması)"""
        regenerate_session()

    def clear_session(self):
        """Session'ı temizle"""
        session.clear()

    def set_user(self, username: str, **kwargs):
        """Kullanıcı session bilgilerini ayarla"""
        self.regenerate_session()
        session['user'] = username
        session['login_time'] = datetime.now().isoformat()
        session['login_ip'] = request.remote_addr if request else None
        for key, value in kwargs.items():
            session[key] = value

    def get_user(self) -> Optional[str]:
        """Mevcut kullanıcıyı al"""
        return session.get('user')

    def is_authenticated(self) -> bool:
        """Kullanıcı giriş yapmış mı?"""
        return session.get('user') is not None


# ============================================================
# Security Headers Middleware
# ============================================================

def add_security_headers(response):
    """Güvenlik header'larını ekle"""
    headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
        'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
    }

    for key, value in headers.items():
        response.headers[key] = value

    return response


# ============================================================
# Login/Logout Helpers
# ============================================================

def login_user(user_id: str, username: str, role: str = 'user',
               remember: bool = False, totp_secret: Optional[str] = None):
    """
    Kullanıcı girişi yap.

    Args:
        user_id: Kullanıcı ID
        username: Kullanıcı adı
        role: Rol (user, admin, vb.)
        remember: Beni hatırla
        totp_secret: 2FA secret (varsa)
    """
    # Session fixation koruması
    regenerate_session()

    # Session bilgilerini ayarla
    session['user'] = {
        'id': user_id,
        'username': username,
        'role': role,
        'login_time': datetime.now().isoformat(),
        'ip': request.remote_addr
    }

    # 2FA kontrolü
    if totp_secret:
        session['2fa_required'] = True
        session['2fa_verified'] = False
        session['totp_secret'] = totp_secret
    else:
        session['2fa_required'] = False
        session['2fa_verified'] = True

    # Remember me
    if remember:
        session.permanent = True
    else:
        session.permanent = False

    logger.info(f"[AUTH] Giriş: {username} ({request.remote_addr})")


def logout_user():
    """Kullanıcı çıkışı yap"""
    username = session.get('user', {}).get('username', 'unknown')
    session.clear()
    logger.info(f"[AUTH] Çıkış: {username}")


def get_current_user() -> Optional[Dict[str, Any]]:
    """Mevcut kullanıcıyı al"""
    return session.get('user')


def is_authenticated() -> bool:
    """Kullanıcı giriş yapmış mı?"""
    user = get_current_user()
    if not user:
        return False

    # 2FA kontrolü
    if session.get('2fa_required') and not session.get('2fa_verified'):
        return False

    return True


def login_required(f: Callable):
    """Login zorunlu decorator"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not is_authenticated():
            if request.is_json:
                return jsonify({
                    'success': False,
                    'error': 'Oturum gerekli'
                }), 401
            return abort(401)

        return f(*args, **kwargs)

    return wrapper


def admin_required(f: Callable):
    """Admin yetkisi zorunlu decorator"""
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        user = get_current_user()
        if not user or user.get('role') != 'admin':
            return jsonify({
                'success': False,
                'error': 'Admin yetkisi gerekli'
            }), 403

        return f(*args, **kwargs)

    return wrapper


# ============================================================
# Flask App Integration
# ============================================================

def init_security(app):
    """
    Flask app'e güvenlik özelliklerini ekle.

    Kullanım:
        from dalga_auth import init_security
        init_security(app)
    """
    # CSRF koruması
    csrf.init_app(app)

    # Session güvenliği
    secure_session_config(app)

    # Güvenlik header'ları
    @app.after_request
    def security_headers(response):
        return add_security_headers(response)

    # Rate limit header'ları
    @app.after_request
    def rate_limit_headers(response):
        if hasattr(g, 'rate_limit_remaining'):
            response.headers['X-RateLimit-Remaining'] = str(g.rate_limit_remaining)
        return response

    logger.info("[AUTH] Güvenlik modülü başlatıldı")


# ============================================================
# Test
# ============================================================

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    print("=== Authentication Module Tests ===\n")

    # Rate limiter test
    print("Rate Limiter:")
    for i in range(12):
        allowed, remaining = rate_limiter.is_allowed("test_ip", 10, 60)
        print(f"  Request {i+1}: allowed={allowed}, remaining={remaining}")

    # Brute force test
    print("\nBrute Force Protection:")
    for i in range(7):
        brute_force.record_attempt("test_user", success=False)
        blocked, remaining = brute_force.is_blocked("test_user")
        attempts = brute_force.get_remaining_attempts("test_user")
        print(f"  Attempt {i+1}: blocked={blocked}, remaining_attempts={attempts}")

    # TOTP test
    if TOTP_AVAILABLE:
        print("\nTOTP (2FA):")
        manager = TOTPManager()
        secret = manager.generate_secret()
        code = manager.get_current_code(secret)
        verified = manager.verify(secret, code)
        print(f"  Secret: {secret}")
        print(f"  Current code: {code}")
        print(f"  Verified: {verified}")
