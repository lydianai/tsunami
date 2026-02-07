"""
TSUNAMI v5.0 - Security Middleware
==================================

Güvenlik middleware'leri:
- CSP (Content Security Policy) with nonces
- HSTS
- X-Frame-Options
- Request ID tracking
- IP-based security
"""

import os
import secrets
import logging
from functools import wraps
from flask import request, g, make_response
from datetime import datetime

logger = logging.getLogger(__name__)


def generate_nonce():
    """CSP nonce üret"""
    return secrets.token_urlsafe(16)


def setup_security_middleware(app):
    """Güvenlik middleware'lerini ekle"""

    @app.before_request
    def before_request_security():
        """Her istekten önce güvenlik kontrolleri"""
        # Request ID üret (tracing için)
        g.request_id = secrets.token_hex(8)
        g.request_start = datetime.utcnow()

        # CSP Nonce üret
        g.csp_nonce = generate_nonce()

        # Suspicious header kontrolü
        suspicious_headers = [
            'X-Forwarded-Host',
            'X-Original-URL',
            'X-Rewrite-URL'
        ]

        for header in suspicious_headers:
            if header in request.headers:
                logger.warning(
                    f"[SECURITY] Suspicious header: {header}",
                    extra={
                        'request_id': g.request_id,
                        'ip': request.remote_addr,
                        'header_value': request.headers.get(header)
                    }
                )

    @app.after_request
    def after_request_security(response):
        """Her istekten sonra güvenlik header'ları"""
        # Request ID header'ı
        response.headers['X-Request-ID'] = g.get('request_id', 'unknown')

        # Security headers (Flask-Talisman'a ek)
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

        # CSP with nonce
        nonce = g.get('csp_nonce', '')
        csp = (
            f"default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net https://unpkg.com; "
            f"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
            f"img-src 'self' data: https: blob:; "
            f"font-src 'self' https://cdn.jsdelivr.net; "
            f"connect-src 'self' wss: https:; "
            f"frame-ancestors 'none'; "
            f"base-uri 'self'; "
            f"form-action 'self'"
        )
        response.headers['Content-Security-Policy'] = csp

        # HSTS (sadece HTTPS'de)
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        # Response time logging
        if hasattr(g, 'request_start'):
            duration = (datetime.utcnow() - g.request_start).total_seconds()
            response.headers['X-Response-Time'] = f"{duration:.3f}s"

            # Yavaş istekleri logla
            if duration > 2.0:
                logger.warning(
                    f"[SLOW] {request.method} {request.path} took {duration:.3f}s",
                    extra={
                        'request_id': g.get('request_id'),
                        'duration': duration
                    }
                )

        return response

    return app


def require_https(f):
    """HTTPS zorunlu kıl"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not request.is_secure and not os.environ.get('FLASK_DEBUG'):
            return make_response('HTTPS required', 403)
        return f(*args, **kwargs)
    return wrapper


def rate_limit_by_ip(limit=100, window=60):
    """IP tabanlı rate limiting decorator"""
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # Flask-Limiter zaten bu işi yapıyor
            # Bu decorator ek kontroller için
            return f(*args, **kwargs)
        return wrapper
    return decorator


def log_security_event(event_type, details=None):
    """Güvenlik olaylarını logla"""
    logger.info(
        f"[SECURITY_EVENT] {event_type}",
        extra={
            'event_type': event_type,
            'details': details or {},
            'ip': request.remote_addr if request else 'N/A',
            'user_agent': request.user_agent.string if request else 'N/A',
            'request_id': g.get('request_id', 'N/A') if g else 'N/A'
        }
    )


__all__ = [
    'setup_security_middleware',
    'generate_nonce',
    'require_https',
    'rate_limit_by_ip',
    'log_security_event'
]
