"""
TSUNAMI v5.0 - Centralized Error Handler
========================================

Merkezi hata yönetimi:
- Güvenli hata mesajları (stack trace gizleme)
- Structured logging
- Sentry entegrasyonu
- JSON error responses
"""

import logging
import traceback
from functools import wraps
from flask import jsonify, request, current_app
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)


class TsunamiError(Exception):
    """Base exception for TSUNAMI"""
    def __init__(self, message, status_code=500, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['success'] = False
        rv['error'] = self.message
        rv['status_code'] = self.status_code
        return rv


class ValidationError(TsunamiError):
    """Input validation error"""
    def __init__(self, message, payload=None):
        super().__init__(message, status_code=400, payload=payload)


class AuthenticationError(TsunamiError):
    """Authentication failed"""
    def __init__(self, message="Kimlik dogrulama basarisiz", payload=None):
        super().__init__(message, status_code=401, payload=payload)


class AuthorizationError(TsunamiError):
    """Permission denied"""
    def __init__(self, message="Yetki yetersiz", payload=None):
        super().__init__(message, status_code=403, payload=payload)


class NotFoundError(TsunamiError):
    """Resource not found"""
    def __init__(self, message="Kaynak bulunamadi", payload=None):
        super().__init__(message, status_code=404, payload=payload)


class RateLimitError(TsunamiError):
    """Rate limit exceeded"""
    def __init__(self, message="Istek limiti asildi", payload=None):
        super().__init__(message, status_code=429, payload=payload)


def setup_error_handlers(app):
    """Flask app'e error handler'ları ekle"""

    @app.errorhandler(TsunamiError)
    def handle_tsunami_error(error):
        """TSUNAMI özel hataları"""
        response = jsonify(error.to_dict())
        response.status_code = error.status_code

        logger.warning(
            f"[ERROR] {error.__class__.__name__}: {error.message}",
            extra={
                'status_code': error.status_code,
                'path': request.path,
                'method': request.method,
                'ip': request.remote_addr
            }
        )

        return response

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        """Werkzeug HTTP exceptions"""
        response = jsonify({
            'success': False,
            'error': error.description,
            'status_code': error.code
        })
        response.status_code = error.code

        logger.warning(
            f"[HTTP] {error.code}: {error.description}",
            extra={
                'path': request.path,
                'method': request.method,
                'ip': request.remote_addr
            }
        )

        return response

    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            'success': False,
            'error': 'Gecersiz istek',
            'status_code': 400
        }), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            'success': False,
            'error': 'Kimlik dogrulama gerekli',
            'status_code': 401
        }), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            'success': False,
            'error': 'Erisim engellendi',
            'status_code': 403
        }), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'Sayfa bulunamadi',
            'status_code': 404
        }), 404

    @app.errorhandler(429)
    def rate_limited(error):
        return jsonify({
            'success': False,
            'error': 'Istek limiti asildi. Lutfen bekleyin.',
            'status_code': 429
        }), 429

    @app.errorhandler(500)
    def internal_error(error):
        """Internal server error - stack trace gizle"""
        # Production'da detay gosterme
        if not current_app.debug:
            logger.error(
                f"[CRITICAL] Internal error: {str(error)}",
                extra={
                    'traceback': traceback.format_exc(),
                    'path': request.path,
                    'method': request.method,
                    'ip': request.remote_addr
                }
            )

            return jsonify({
                'success': False,
                'error': 'Sunucu hatasi olustu',
                'status_code': 500
            }), 500

        # Debug modunda detay goster
        return jsonify({
            'success': False,
            'error': str(error),
            'traceback': traceback.format_exc(),
            'status_code': 500
        }), 500

    @app.errorhandler(Exception)
    def handle_generic_exception(error):
        """Yakalanmamis tum hatalar"""
        logger.error(
            f"[UNHANDLED] {error.__class__.__name__}: {str(error)}",
            extra={
                'traceback': traceback.format_exc(),
                'path': request.path,
                'method': request.method,
                'ip': request.remote_addr
            }
        )

        # Sentry'ye gonder (opsiyonel)
        try:
            import sentry_sdk
            sentry_sdk.capture_exception(error)
        except ImportError:
            pass

        if not current_app.debug:
            return jsonify({
                'success': False,
                'error': 'Beklenmeyen bir hata olustu',
                'status_code': 500
            }), 500

        return jsonify({
            'success': False,
            'error': str(error),
            'type': error.__class__.__name__,
            'traceback': traceback.format_exc(),
            'status_code': 500
        }), 500

    return app


def safe_endpoint(f):
    """
    Route decorator for safe error handling.

    Usage:
        @app.route('/api/scan')
        @safe_endpoint
        def scan():
            ...
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except TsunamiError:
            raise
        except Exception as e:
            logger.error(f"[ENDPOINT] {f.__name__}: {str(e)}", exc_info=True)
            raise TsunamiError(
                message="Islem sirasinda hata olustu",
                status_code=500
            )
    return wrapper


__all__ = [
    'TsunamiError', 'ValidationError', 'AuthenticationError',
    'AuthorizationError', 'NotFoundError', 'RateLimitError',
    'setup_error_handlers', 'safe_endpoint'
]
