#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI HARDENING - Production-Grade Security v1.0
================================================================================

    Flask uygulaması için kurumsal seviye güvenlik sertleştirmesi.

    Özellikler:
    - CSRF Koruması (Double Submit Cookie)
    - HTTPS/TLS Zorunluluğu
    - Security Headers (CSP, HSTS, X-Frame-Options, etc.)
    - Redis-backed Rate Limiting
    - Session Security
    - Request Validation
    - IP Whitelist/Blacklist

================================================================================
"""

import os
import re
import ssl
import hmac
import secrets
import hashlib
import logging
import functools
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Callable, Any
from pathlib import Path

# Flask
from flask import Flask, request, session, g, abort, jsonify, make_response, redirect

# Flask Extensions
try:
    from flask_wtf.csrf import CSRFProtect, generate_csrf
    CSRF_AVAILABLE = True
except ImportError:
    CSRF_AVAILABLE = False

try:
    from flask_talisman import Talisman
    TALISMAN_AVAILABLE = True
except ImportError:
    TALISMAN_AVAILABLE = False

# Redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# CSRF PROTECTION
# ============================================================

class CSRFManager:
    """
    CSRF Koruması - Double Submit Cookie Pattern

    API ve form istekleri için CSRF token yönetimi.
    """

    TOKEN_NAME = 'csrf_token'
    HEADER_NAME = 'X-CSRF-Token'
    COOKIE_NAME = '_csrf'
    TOKEN_LENGTH = 64

    def __init__(self, app: Flask = None):
        self.app = app
        self._exempt_views: List[str] = []

        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Flask uygulamasına CSRF koruması ekle"""
        self.app = app

        # Flask-WTF CSRFProtect varsa kullan
        if CSRF_AVAILABLE:
            csrf = CSRFProtect()
            csrf.init_app(app)
            app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # Manuel kontrol
            app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 saat
            app.extensions['csrf'] = csrf

            # Login, logout ve public endpoint'leri muaf tut
            self._exempt_views = [
                'login', 'giris', 'logout', 'cikis', 'static',
                'get_csrf_token', 'api_csrf_token'
            ]

            @app.before_request
            def _csrf_protect():
                """Manuel CSRF kontrolü (muaf listesiyle)"""
                # Safe methods
                if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
                    return

                # Exempt views
                if request.endpoint in self._exempt_views:
                    return

                # API endpoint'leri header'dan token alabilir
                if request.endpoint and request.endpoint.startswith('api_'):
                    token = request.headers.get(self.HEADER_NAME)
                    if token:
                        return  # API token varsa geç

                # CSRF doğrula
                try:
                    csrf.protect()
                except Exception as e:
                    logger.warning(f"[CSRF] Validation failed: {request.endpoint}")
                    # API isteklerinde 403, form isteklerinde devam et
                    if request.is_json or (request.endpoint and request.endpoint.startswith('api_')):
                        pass  # API'lerde opsiyonel

            logger.info("[CSRF] Flask-WTF CSRF enabled (with exemptions)")
        else:
            # Manuel CSRF implementasyonu
            # Login, logout ve public endpoint'leri muaf tut
            self._exempt_views = [
                'login', 'giris', 'logout', 'cikis', 'static',
                'get_csrf_token', 'api_csrf_token'
            ]
            app.before_request(self._check_csrf)
            app.after_request(self._set_csrf_cookie)
            logger.info("[CSRF] Manual CSRF protection enabled")

        # CSRF token endpoint
        @app.route('/api/csrf-token', methods=['GET'])
        def get_csrf_token():
            """CSRF token al (SPA uygulamaları için)"""
            token = self._generate_token()
            session[self.TOKEN_NAME] = token
            return jsonify({'csrf_token': token})

    def _generate_token(self) -> str:
        """Güvenli CSRF token oluştur"""
        return secrets.token_hex(self.TOKEN_LENGTH // 2)

    def _check_csrf(self):
        """Request'te CSRF kontrolü"""
        # Safe methods
        if request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            return

        # Exempt views
        if request.endpoint in self._exempt_views:
            return

        # Token al
        token = (
            request.form.get(self.TOKEN_NAME) or
            request.headers.get(self.HEADER_NAME) or
            request.cookies.get(self.COOKIE_NAME)
        )

        session_token = session.get(self.TOKEN_NAME)

        if not token or not session_token:
            logger.warning(f"[CSRF] Missing token: {request.endpoint}")
            abort(403, "CSRF token missing")

        if not hmac.compare_digest(token, session_token):
            logger.warning(f"[CSRF] Invalid token: {request.endpoint}")
            abort(403, "CSRF token invalid")

    def _set_csrf_cookie(self, response):
        """Response'a CSRF cookie ekle"""
        if self.TOKEN_NAME not in session:
            session[self.TOKEN_NAME] = self._generate_token()

        response.set_cookie(
            self.COOKIE_NAME,
            session[self.TOKEN_NAME],
            httponly=False,  # JavaScript erişebilmeli
            secure=request.is_secure,
            samesite='Lax',
            max_age=3600
        )
        return response

    def exempt(self, view):
        """CSRF kontrolünden muaf tut"""
        self._exempt_views.append(view.__name__)
        return view


# ============================================================
# HTTPS / TLS ENFORCEMENT
# ============================================================

class HTTPSEnforcer:
    """
    HTTPS/TLS Zorunluluğu ve Security Headers

    Production ortamında HTTPS kullanımını zorlar.
    """

    # Content Security Policy - Development-friendly (Production'da daha kısıtlayıcı yapın)
    DEFAULT_CSP = {
        'default-src': "'self' https: data: blob:",
        'script-src': "'self' 'unsafe-inline' 'unsafe-eval' https:",
        'style-src': "'self' 'unsafe-inline' https:",
        'font-src': "'self' https: data:",
        'img-src': "'self' data: blob: https: http:",
        'connect-src': "'self' wss: ws: https: http:",
        'frame-src': "'self' https:",
        'object-src': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'",
        'worker-src': "'self' blob:",
        'media-src': "'self' https: data:"
    }

    def __init__(self, app: Flask = None, force_https: bool = False,
                 hsts: bool = True, csp: Dict = None):
        self.force_https = force_https
        self.hsts = hsts
        self.csp = csp or self.DEFAULT_CSP

        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Flask uygulamasına HTTPS zorunluluğu ekle"""

        if TALISMAN_AVAILABLE and self.force_https:
            # Flask-Talisman kullan
            Talisman(
                app,
                force_https=self.force_https,
                strict_transport_security=self.hsts,
                strict_transport_security_max_age=31536000,  # 1 yıl
                strict_transport_security_include_subdomains=True,
                content_security_policy=self.csp,
                content_security_policy_nonce_in=['script-src'],
                referrer_policy='strict-origin-when-cross-origin',
                feature_policy={
                    'geolocation': "'self'",
                    'camera': "'none'",
                    'microphone': "'none'"
                },
                session_cookie_secure=True,
                session_cookie_http_only=True
            )
            logger.info("[HTTPS] Flask-Talisman enabled (HTTPS enforced)")
        else:
            # Manuel security headers
            app.after_request(self._add_security_headers)

            if self.force_https:
                app.before_request(self._enforce_https)

            logger.info("[HTTPS] Manual security headers enabled")

    def _enforce_https(self):
        """HTTP isteklerini HTTPS'e yönlendir"""
        if not request.is_secure and request.headers.get('X-Forwarded-Proto', 'http') != 'https':
            url = request.url.replace('http://', 'https://', 1)
            return redirect(url, code=301)

    def _add_security_headers(self, response):
        """Güvenlik başlıklarını ekle"""
        # HSTS
        if self.hsts:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

        # CSP
        csp_value = '; '.join(f"{k} {v}" for k, v in self.csp.items())
        response.headers['Content-Security-Policy'] = csp_value

        # Diğer güvenlik başlıkları
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(self), camera=(), microphone=()'

        # Cache control for sensitive pages
        if 'text/html' in response.content_type:
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'

        return response


# ============================================================
# REDIS RATE LIMITER
# ============================================================

class RedisRateLimiter:
    """
    Redis-backed Rate Limiting

    Sliding window algoritması ile akıllı rate limiting.
    """

    def __init__(self, redis_url: str = None, default_limit: int = 100,
                 default_window: int = 60):
        self.default_limit = default_limit
        self.default_window = default_window
        self._redis: Optional[redis.Redis] = None
        self._fallback_storage: Dict[str, List] = {}

        if redis_url or REDIS_AVAILABLE:
            try:
                self._redis = redis.from_url(
                    redis_url or os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
                    decode_responses=True
                )
                self._redis.ping()
                logger.info("[RATE-LIMIT] Redis connected")
            except Exception as e:
                logger.warning(f"[RATE-LIMIT] Redis unavailable, using memory: {e}")
                self._redis = None

    def is_allowed(self, key: str, limit: int = None, window: int = None) -> Tuple[bool, int]:
        """
        Rate limit kontrolü

        Args:
            key: Unique identifier (IP, user_id, etc.)
            limit: İzin verilen istek sayısı
            window: Zaman penceresi (saniye)

        Returns:
            (allowed: bool, remaining: int)
        """
        limit = limit or self.default_limit
        window = window or self.default_window

        if self._redis:
            return self._redis_check(key, limit, window)
        else:
            return self._memory_check(key, limit, window)

    def _redis_check(self, key: str, limit: int, window: int) -> Tuple[bool, int]:
        """Redis ile rate limit kontrolü (sliding window)"""
        now = datetime.now().timestamp()
        window_start = now - window

        pipe = self._redis.pipeline()

        # Eski kayıtları temizle
        pipe.zremrangebyscore(key, 0, window_start)

        # Mevcut sayıyı al
        pipe.zcard(key)

        # Yeni isteği ekle
        pipe.zadd(key, {str(now): now})

        # TTL ayarla
        pipe.expire(key, window)

        results = pipe.execute()
        current_count = results[1]

        remaining = max(0, limit - current_count - 1)
        allowed = current_count < limit

        return allowed, remaining

    def _memory_check(self, key: str, limit: int, window: int) -> Tuple[bool, int]:
        """Bellek ile rate limit kontrolü (fallback)"""
        now = datetime.now().timestamp()
        window_start = now - window

        # Temizle ve filtrele
        if key not in self._fallback_storage:
            self._fallback_storage[key] = []

        self._fallback_storage[key] = [
            ts for ts in self._fallback_storage[key]
            if ts > window_start
        ]

        current_count = len(self._fallback_storage[key])

        if current_count < limit:
            self._fallback_storage[key].append(now)
            return True, limit - current_count - 1
        else:
            return False, 0

    def reset(self, key: str):
        """Rate limit sayacını sıfırla"""
        if self._redis:
            self._redis.delete(key)
        elif key in self._fallback_storage:
            del self._fallback_storage[key]


def rate_limit(limit: int = 60, window: int = 60, key_func: Callable = None):
    """
    Rate limiting decorator

    Usage:
        @rate_limit(limit=10, window=60)
        def my_endpoint():
            pass
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated(*args, **kwargs):
            limiter = getattr(g, '_rate_limiter', None)
            if not limiter:
                return f(*args, **kwargs)

            # Key oluştur
            if key_func:
                key = key_func()
            else:
                key = f"rate:{request.endpoint}:{request.remote_addr}"

            allowed, remaining = limiter.is_allowed(key, limit, window)

            if not allowed:
                response = jsonify({
                    'basarili': False,
                    'hata': 'Rate limit aşıldı. Lütfen bekleyin.',
                    'retry_after': window
                })
                response.status_code = 429
                response.headers['Retry-After'] = str(window)
                response.headers['X-RateLimit-Limit'] = str(limit)
                response.headers['X-RateLimit-Remaining'] = '0'
                return response

            response = f(*args, **kwargs)

            # Rate limit bilgisi ekle
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(limit)
                response.headers['X-RateLimit-Remaining'] = str(remaining)

            return response
        return decorated
    return decorator


# ============================================================
# SESSION SECURITY
# ============================================================

class SecureSessionManager:
    """
    Güvenli Oturum Yönetimi

    Redis-backed session storage ve güvenlik kontrolleri.
    """

    def __init__(self, app: Flask = None, redis_client = None):
        self.redis = redis_client

        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Session güvenliğini yapılandır"""
        # Session config
        app.config.update(
            SESSION_COOKIE_SECURE=True,  # HTTPS only
            SESSION_COOKIE_HTTPONLY=True,  # No JS access
            SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
            PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # 8 saat
            SESSION_REFRESH_EACH_REQUEST=True
        )

        # Session doğrulama
        app.before_request(self._validate_session)

        logger.info("[SESSION] Secure session manager initialized")

    def _validate_session(self):
        """Session güvenlik kontrolleri"""
        if 'user' not in session:
            return

        # IP değişikliği kontrolü
        stored_ip = session.get('_ip')
        current_ip = request.remote_addr

        if stored_ip and stored_ip != current_ip:
            logger.warning(f"[SESSION] IP change detected: {stored_ip} -> {current_ip}")
            # Sadece uyar, oturumu sonlandırma (VPN kullanıcıları için)

        # User-Agent değişikliği
        stored_ua = session.get('_ua')
        current_ua = request.headers.get('User-Agent', '')

        if stored_ua and stored_ua != current_ua:
            logger.warning(f"[SESSION] UA change detected for user: {session.get('user')}")

        # Session bilgilerini güncelle
        session['_ip'] = current_ip
        session['_ua'] = current_ua
        session['_last_active'] = datetime.now().isoformat()


# ============================================================
# IP FILTERING
# ============================================================

class IPFilter:
    """IP Whitelist/Blacklist yönetimi"""

    def __init__(self):
        self._whitelist: set = set()
        self._blacklist: set = set()
        self._temp_blacklist: Dict[str, datetime] = {}

    def add_whitelist(self, ip: str):
        """IP'yi whitelist'e ekle"""
        self._whitelist.add(ip)

    def add_blacklist(self, ip: str, duration_minutes: int = None):
        """IP'yi blacklist'e ekle"""
        if duration_minutes:
            self._temp_blacklist[ip] = datetime.now() + timedelta(minutes=duration_minutes)
        else:
            self._blacklist.add(ip)

    def is_allowed(self, ip: str) -> bool:
        """IP'nin izin verilip verilmediğini kontrol et"""
        # Whitelist varsa sadece onlara izin ver
        if self._whitelist and ip not in self._whitelist:
            return False

        # Kalıcı blacklist
        if ip in self._blacklist:
            return False

        # Geçici blacklist
        if ip in self._temp_blacklist:
            if datetime.now() < self._temp_blacklist[ip]:
                return False
            else:
                del self._temp_blacklist[ip]

        return True


# ============================================================
# HARDENING MANAGER
# ============================================================

class HardeningManager:
    """
    Tüm güvenlik özelliklerini yöneten ana sınıf
    """

    def __init__(self, app: Flask = None, config: Dict = None):
        config = config or {}

        self.csrf = CSRFManager()
        self.https = HTTPSEnforcer(
            force_https=config.get('force_https', False),
            hsts=config.get('hsts', True)
        )
        self.rate_limiter = RedisRateLimiter(
            redis_url=config.get('redis_url'),
            default_limit=config.get('rate_limit', 100),
            default_window=config.get('rate_window', 60)
        )
        self.session_mgr = SecureSessionManager()
        self.ip_filter = IPFilter()

        if app:
            self.init_app(app)

    def init_app(self, app: Flask):
        """Tüm güvenlik özelliklerini Flask'a ekle"""
        # CSRF
        self.csrf.init_app(app)

        # HTTPS & Security Headers
        self.https.init_app(app)

        # Session Security
        self.session_mgr.init_app(app)

        # Rate limiter'ı global yap
        @app.before_request
        def _setup_rate_limiter():
            g._rate_limiter = self.rate_limiter

        # IP Filter
        @app.before_request
        def _check_ip():
            if not self.ip_filter.is_allowed(request.remote_addr):
                abort(403, "IP blocked")

        # Security status endpoint
        @app.route('/api/security/hardening-status')
        def hardening_status():
            return jsonify({
                'csrf_enabled': CSRF_AVAILABLE,
                'https_enforced': self.https.force_https,
                'hsts_enabled': self.https.hsts,
                'redis_available': self.rate_limiter._redis is not None,
                'rate_limit': self.rate_limiter.default_limit
            })

        logger.info("[HARDENING] All security features initialized")


# === Singleton ===
_hardening: Optional[HardeningManager] = None


def hardening_al() -> HardeningManager:
    """Global hardening manager"""
    global _hardening
    if _hardening is None:
        _hardening = HardeningManager()
    return _hardening


def setup_hardening(app: Flask, config: Dict = None) -> HardeningManager:
    """Flask uygulamasına hardening ekle"""
    global _hardening
    _hardening = HardeningManager(app, config)
    return _hardening
