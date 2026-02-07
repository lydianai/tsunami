"""
TSUNAMI v5.0 - Logging Middleware
=================================

Structured JSON logging:
- Request/Response logging
- Performance metrics
- Audit trail
- Prometheus integration
"""

import time
import logging
import json
from functools import wraps
from flask import request, g
from datetime import datetime

try:
    from prometheus_client import Counter, Histogram, Gauge
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False

logger = logging.getLogger(__name__)


# Prometheus metrics
if PROMETHEUS_AVAILABLE:
    REQUEST_COUNT = Counter(
        'tsunami_http_requests_total',
        'Total HTTP requests',
        ['method', 'endpoint', 'status']
    )

    REQUEST_LATENCY = Histogram(
        'tsunami_http_request_duration_seconds',
        'HTTP request latency',
        ['method', 'endpoint']
    )

    ACTIVE_REQUESTS = Gauge(
        'tsunami_active_requests',
        'Active HTTP requests'
    )

    ERROR_COUNT = Counter(
        'tsunami_errors_total',
        'Total errors',
        ['type', 'endpoint']
    )

    OSINT_QUERIES = Counter(
        'tsunami_osint_queries_total',
        'OSINT queries performed',
        ['query_type']
    )

    SIGINT_SCANS = Counter(
        'tsunami_sigint_scans_total',
        'SIGINT scans performed',
        ['scan_type']
    )


class StructuredLogger:
    """Structured JSON logging"""

    @staticmethod
    def log_request(response):
        """Request/Response logging"""
        duration = time.time() - g.get('start_time', time.time())

        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'request_id': g.get('request_id', 'unknown'),
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'duration_ms': round(duration * 1000, 2),
            'ip': request.remote_addr,
            'user_agent': request.user_agent.string,
            'content_length': response.content_length,
            'user': g.get('current_user', 'anonymous')
        }

        # Response code'a göre log level
        if response.status_code >= 500:
            logger.error(json.dumps(log_data))
        elif response.status_code >= 400:
            logger.warning(json.dumps(log_data))
        else:
            logger.info(json.dumps(log_data))

        return log_data

    @staticmethod
    def log_osint_query(query_type, target, success=True, duration=0):
        """OSINT query logging"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'osint_query',
            'query_type': query_type,
            'target': target[:50],  # Truncate for privacy
            'success': success,
            'duration_ms': round(duration * 1000, 2),
            'request_id': g.get('request_id', 'unknown')
        }

        logger.info(json.dumps(log_data))

        if PROMETHEUS_AVAILABLE:
            OSINT_QUERIES.labels(query_type=query_type).inc()

        return log_data

    @staticmethod
    def log_sigint_scan(scan_type, target_count, devices_found, duration=0):
        """SIGINT scan logging"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'sigint_scan',
            'scan_type': scan_type,
            'target_count': target_count,
            'devices_found': devices_found,
            'duration_ms': round(duration * 1000, 2),
            'request_id': g.get('request_id', 'unknown')
        }

        logger.info(json.dumps(log_data))

        if PROMETHEUS_AVAILABLE:
            SIGINT_SCANS.labels(scan_type=scan_type).inc()

        return log_data

    @staticmethod
    def log_security_event(event_type, severity, details=None):
        """Security event logging"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'event': 'security',
            'event_type': event_type,
            'severity': severity,
            'details': details or {},
            'ip': request.remote_addr if request else 'N/A',
            'request_id': g.get('request_id', 'unknown') if g else 'N/A'
        }

        if severity in ['high', 'critical']:
            logger.error(json.dumps(log_data))
        elif severity == 'medium':
            logger.warning(json.dumps(log_data))
        else:
            logger.info(json.dumps(log_data))

        if PROMETHEUS_AVAILABLE:
            ERROR_COUNT.labels(type=event_type, endpoint=request.path if request else 'N/A').inc()

        return log_data


def setup_logging_middleware(app):
    """Logging middleware'lerini ekle"""

    @app.before_request
    def before_request_logging():
        """Request başlangıç zamanını kaydet"""
        g.start_time = time.time()

        if PROMETHEUS_AVAILABLE:
            ACTIVE_REQUESTS.inc()

    @app.after_request
    def after_request_logging(response):
        """Request/Response loglama"""
        # Log the request
        StructuredLogger.log_request(response)

        # Prometheus metrics
        if PROMETHEUS_AVAILABLE:
            ACTIVE_REQUESTS.dec()

            duration = time.time() - g.get('start_time', time.time())
            endpoint = request.endpoint or 'unknown'

            REQUEST_COUNT.labels(
                method=request.method,
                endpoint=endpoint,
                status=response.status_code
            ).inc()

            REQUEST_LATENCY.labels(
                method=request.method,
                endpoint=endpoint
            ).observe(duration)

        return response

    return app


def log_function_call(func_name=None):
    """Function call logging decorator"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            name = func_name or f.__name__
            start = time.time()

            try:
                result = f(*args, **kwargs)
                duration = time.time() - start

                logger.debug(
                    f"[FUNC] {name} completed in {duration*1000:.2f}ms"
                )

                return result
            except Exception as e:
                duration = time.time() - start

                logger.error(
                    f"[FUNC] {name} failed after {duration*1000:.2f}ms: {str(e)}"
                )
                raise
        return wrapper
    return decorator


__all__ = [
    'StructuredLogger',
    'setup_logging_middleware',
    'log_function_call'
]
