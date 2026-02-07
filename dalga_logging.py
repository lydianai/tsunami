#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Structured Logging & Metrics v1.0
=========================================

Yapılandırılmış loglama ve Prometheus metrikleri.
- JSON formatında loglar
- Request/Response logging
- Error tracking
- Prometheus metrikleri
- Performance monitoring

KULLANIM:
    from dalga_logging import setup_logging, get_logger, metrics

    logger = get_logger(__name__)
    logger.info("Mesaj", extra={"user": "admin", "action": "login"})
"""

import os
import sys
import json
import time
import logging
import traceback
from typing import Optional, Dict, Any, Callable
from datetime import datetime
from functools import wraps
from collections import defaultdict
import threading

from flask import request, g, Response


# ============================================================
# JSON Formatter
# ============================================================

class JSONFormatter(logging.Formatter):
    """
    JSON formatında log çıktısı.

    Örnek çıktı:
    {"timestamp": "2024-01-15T10:30:00", "level": "INFO", "message": "User login", ...}
    """

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Extra fields
        if hasattr(record, 'extra_fields'):
            log_data.update(record.extra_fields)

        # Exception info
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'traceback': traceback.format_exception(*record.exc_info) if record.exc_info[0] else None
            }

        # Request context (Flask)
        try:
            if request:
                log_data['request'] = {
                    'method': request.method,
                    'path': request.path,
                    'remote_addr': request.remote_addr,
                    'user_agent': str(request.user_agent)[:100]
                }
        except RuntimeError:
            pass  # Outside request context

        return json.dumps(log_data, ensure_ascii=False, default=str)


class StructuredLogAdapter(logging.LoggerAdapter):
    """
    Yapılandırılmış log adapter.

    Kullanım:
        logger.info("Message", user="admin", action="login")
    """

    def process(self, msg, kwargs):
        extra = kwargs.get('extra', {})

        # Extra fields'i ayır
        extra_fields = {}
        for key in list(kwargs.keys()):
            if key not in ('exc_info', 'stack_info', 'stacklevel', 'extra'):
                extra_fields[key] = kwargs.pop(key)

        if extra_fields:
            extra['extra_fields'] = extra_fields

        kwargs['extra'] = extra
        return msg, kwargs


# ============================================================
# Prometheus Metrics (In-Memory)
# ============================================================

class PrometheusMetrics:
    """
    In-memory Prometheus metrikleri.

    Production'da prometheus_client kullanın.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, int] = defaultdict(int)
        self._gauges: Dict[str, float] = defaultdict(float)
        self._histograms: Dict[str, list] = defaultdict(list)
        self._summaries: Dict[str, list] = defaultdict(list)

        # Histogram buckets
        self._histogram_buckets = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]

    def inc(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        """Counter artır"""
        key = self._make_key(name, labels)
        with self._lock:
            self._counters[key] += value

    def dec(self, name: str, value: int = 1, labels: Dict[str, str] = None):
        """Counter azalt (gauge için)"""
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] -= value

    def set(self, name: str, value: float, labels: Dict[str, str] = None):
        """Gauge değeri ayarla"""
        key = self._make_key(name, labels)
        with self._lock:
            self._gauges[key] = value

    def observe(self, name: str, value: float, labels: Dict[str, str] = None):
        """Histogram/Summary gözlemi"""
        key = self._make_key(name, labels)
        with self._lock:
            self._histograms[key].append(value)
            # Son 1000 değeri tut
            if len(self._histograms[key]) > 1000:
                self._histograms[key] = self._histograms[key][-1000:]

    def _make_key(self, name: str, labels: Dict[str, str] = None) -> str:
        """Metrik anahtarı oluştur"""
        if not labels:
            return name
        label_str = ','.join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f'{name}{{{label_str}}}'

    def get_counter(self, name: str, labels: Dict[str, str] = None) -> int:
        """Counter değerini al"""
        key = self._make_key(name, labels)
        return self._counters.get(key, 0)

    def get_gauge(self, name: str, labels: Dict[str, str] = None) -> float:
        """Gauge değerini al"""
        key = self._make_key(name, labels)
        return self._gauges.get(key, 0.0)

    def get_histogram_stats(self, name: str, labels: Dict[str, str] = None) -> Dict[str, float]:
        """Histogram istatistikleri"""
        key = self._make_key(name, labels)
        values = self._histograms.get(key, [])

        if not values:
            return {'count': 0, 'sum': 0, 'avg': 0, 'min': 0, 'max': 0, 'p50': 0, 'p95': 0, 'p99': 0}

        sorted_values = sorted(values)
        count = len(sorted_values)

        return {
            'count': count,
            'sum': sum(sorted_values),
            'avg': sum(sorted_values) / count,
            'min': sorted_values[0],
            'max': sorted_values[-1],
            'p50': sorted_values[int(count * 0.5)] if count > 0 else 0,
            'p95': sorted_values[int(count * 0.95)] if count > 0 else 0,
            'p99': sorted_values[int(count * 0.99)] if count > 0 else 0,
        }

    def export_prometheus(self) -> str:
        """Prometheus formatında export"""
        lines = []

        # Counters
        for key, value in self._counters.items():
            lines.append(f'# TYPE {key.split("{")[0]} counter')
            lines.append(f'{key} {value}')

        # Gauges
        for key, value in self._gauges.items():
            lines.append(f'# TYPE {key.split("{")[0]} gauge')
            lines.append(f'{key} {value}')

        # Histograms
        for key, values in self._histograms.items():
            base_name = key.split("{")[0]
            labels = key[len(base_name):] if '{' in key else ''

            lines.append(f'# TYPE {base_name} histogram')

            sorted_values = sorted(values)
            count = len(sorted_values)
            total = sum(sorted_values)

            # Buckets
            for bucket in self._histogram_buckets:
                bucket_count = sum(1 for v in sorted_values if v <= bucket)
                bucket_labels = labels.rstrip('}') + f',le="{bucket}"}}' if labels else f'{{le="{bucket}"}}'
                lines.append(f'{base_name}_bucket{bucket_labels} {bucket_count}')

            # +Inf bucket
            inf_labels = labels.rstrip('}') + ',le="+Inf"}' if labels else '{le="+Inf"}'
            lines.append(f'{base_name}_bucket{inf_labels} {count}')

            # Sum and count
            lines.append(f'{base_name}_sum{labels} {total}')
            lines.append(f'{base_name}_count{labels} {count}')

        return '\n'.join(lines)

    def get_all_metrics(self) -> Dict[str, Any]:
        """Tüm metrikleri dict olarak al"""
        return {
            'counters': dict(self._counters),
            'gauges': dict(self._gauges),
            'histograms': {k: self.get_histogram_stats(k) for k in self._histograms.keys()}
        }


# Global instances
_metrics = PrometheusMetrics()
_loggers: Dict[str, StructuredLogAdapter] = {}


def get_metrics() -> PrometheusMetrics:
    """Global metrics instance"""
    return _metrics


# ============================================================
# Pre-defined Metrics
# ============================================================

# Request metrikleri
REQUEST_COUNT = 'http_requests_total'
REQUEST_LATENCY = 'http_request_duration_seconds'
REQUEST_IN_PROGRESS = 'http_requests_in_progress'

# Error metrikleri
ERROR_COUNT = 'errors_total'

# Business metrikleri
SCAN_COUNT = 'scans_total'
THREAT_COUNT = 'threats_detected_total'
LOGIN_COUNT = 'logins_total'
API_CALL_COUNT = 'api_calls_total'


# ============================================================
# Flask Middleware
# ============================================================

def setup_request_logging(app):
    """
    Flask request/response logging middleware.

    Kullanım:
        from dalga_logging import setup_request_logging
        setup_request_logging(app)
    """

    @app.before_request
    def before_request():
        g.start_time = time.time()
        g.request_id = os.urandom(8).hex()

        # In-progress counter
        _metrics.inc(REQUEST_IN_PROGRESS, labels={'method': request.method})

    @app.after_request
    def after_request(response: Response) -> Response:
        # Latency
        latency = time.time() - getattr(g, 'start_time', time.time())

        # Labels
        labels = {
            'method': request.method,
            'endpoint': request.endpoint or 'unknown',
            'status': str(response.status_code)
        }

        # Metrikleri kaydet
        _metrics.inc(REQUEST_COUNT, labels=labels)
        _metrics.observe(REQUEST_LATENCY, latency, labels={'method': request.method, 'endpoint': request.endpoint or 'unknown'})
        _metrics.dec(REQUEST_IN_PROGRESS, labels={'method': request.method})

        # Log
        logger = get_logger('request')
        log_data = {
            'request_id': getattr(g, 'request_id', None),
            'method': request.method,
            'path': request.path,
            'status': response.status_code,
            'latency_ms': round(latency * 1000, 2),
            'content_length': response.content_length,
            'remote_addr': request.remote_addr
        }

        if response.status_code >= 500:
            logger.error("Request failed", **log_data)
        elif response.status_code >= 400:
            logger.warning("Request error", **log_data)
        else:
            logger.info("Request completed", **log_data)

        # Add request ID header
        response.headers['X-Request-ID'] = getattr(g, 'request_id', '')

        return response

    @app.errorhandler(Exception)
    def handle_exception(e):
        logger = get_logger('error')
        logger.exception("Unhandled exception",
                        error_type=type(e).__name__,
                        error_message=str(e))

        _metrics.inc(ERROR_COUNT, labels={'type': type(e).__name__})

        return {'error': 'Internal server error'}, 500


# ============================================================
# Decorators
# ============================================================

def log_execution(logger_name: str = None, level: int = logging.INFO):
    """
    Fonksiyon çalışmasını logla.

    Kullanım:
        @log_execution('scanner')
        def scan_network():
            ...
    """
    def decorator(f: Callable):
        @wraps(f)
        def wrapper(*args, **kwargs):
            _logger = get_logger(logger_name or f.__module__)

            start = time.time()
            _logger.log(level, f"Starting {f.__name__}", function=f.__name__)

            try:
                result = f(*args, **kwargs)
                elapsed = time.time() - start
                _logger.log(level, f"Completed {f.__name__}",
                           function=f.__name__,
                           elapsed_ms=round(elapsed * 1000, 2))
                return result
            except Exception as e:
                elapsed = time.time() - start
                _logger.exception(f"Failed {f.__name__}",
                                 function=f.__name__,
                                 elapsed_ms=round(elapsed * 1000, 2),
                                 error=str(e))
                raise

        return wrapper
    return decorator


def track_metric(metric_name: str, labels: Dict[str, str] = None):
    """
    Fonksiyon çağrısını metrik olarak izle.

    Kullanım:
        @track_metric('api_calls_total', {'endpoint': 'scan'})
        def api_scan():
            ...
    """
    def decorator(f: Callable):
        @wraps(f)
        def wrapper(*args, **kwargs):
            _metrics.inc(metric_name, labels=labels)

            start = time.time()
            try:
                result = f(*args, **kwargs)
                elapsed = time.time() - start

                # Duration histogram
                _metrics.observe(f'{metric_name}_duration_seconds', elapsed, labels=labels)

                return result
            except Exception:
                _metrics.inc(f'{metric_name}_errors', labels=labels)
                raise

        return wrapper
    return decorator


# ============================================================
# Setup Functions
# ============================================================

def setup_logging(app=None, level: int = logging.INFO, json_format: bool = True):
    """
    Logging sistemini yapılandır.

    Args:
        app: Flask app (opsiyonel)
        level: Log seviyesi
        json_format: JSON formatı kullan
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Mevcut handler'ları kaldır
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)

    if json_format:
        console_handler.setFormatter(JSONFormatter())
    else:
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))

    root_logger.addHandler(console_handler)

    # Flask app middleware
    if app:
        setup_request_logging(app)

    return root_logger


def get_logger(name: str) -> StructuredLogAdapter:
    """
    Yapılandırılmış logger al.

    Args:
        name: Logger adı

    Returns:
        StructuredLogAdapter instance
    """
    if name not in _loggers:
        base_logger = logging.getLogger(name)
        _loggers[name] = StructuredLogAdapter(base_logger, {})

    return _loggers[name]


# ============================================================
# Flask Blueprint for Metrics
# ============================================================

def create_metrics_blueprint():
    """Prometheus metrikleri için Flask Blueprint"""
    from flask import Blueprint

    metrics_bp = Blueprint('metrics', __name__)

    @metrics_bp.route('/metrics')
    def prometheus_metrics():
        """Prometheus formatında metrikler"""
        return Response(
            _metrics.export_prometheus(),
            mimetype='text/plain; charset=utf-8'
        )

    @metrics_bp.route('/metrics/json')
    def json_metrics():
        """JSON formatında metrikler"""
        return _metrics.get_all_metrics()

    @metrics_bp.route('/health/metrics')
    def health_metrics():
        """Sağlık metrikleri"""
        all_metrics = _metrics.get_all_metrics()

        # Request latency özeti
        latency_stats = {}
        for key, stats in all_metrics.get('histograms', {}).items():
            if REQUEST_LATENCY in key:
                latency_stats[key] = stats

        return {
            'status': 'healthy',
            'request_count': sum(v for k, v in all_metrics.get('counters', {}).items() if REQUEST_COUNT in k),
            'error_count': sum(v for k, v in all_metrics.get('counters', {}).items() if ERROR_COUNT in k),
            'latency': latency_stats
        }

    return metrics_bp


# ============================================================
# Convenience Functions
# ============================================================

def log_scan(scan_type: str, target: str, success: bool, **extra):
    """Tarama logla"""
    logger = get_logger('scan')
    _metrics.inc(SCAN_COUNT, labels={'type': scan_type, 'success': str(success).lower()})

    logger.info(f"Scan completed: {scan_type}",
               scan_type=scan_type,
               target=target,
               success=success,
               **extra)


def log_threat(threat_type: str, severity: str, source: str, **extra):
    """Tehdit logla"""
    logger = get_logger('threat')
    _metrics.inc(THREAT_COUNT, labels={'type': threat_type, 'severity': severity})

    logger.warning(f"Threat detected: {threat_type}",
                  threat_type=threat_type,
                  severity=severity,
                  source=source,
                  **extra)


def log_login(username: str, success: bool, **extra):
    """Login logla"""
    logger = get_logger('auth')
    _metrics.inc(LOGIN_COUNT, labels={'success': str(success).lower()})

    if success:
        logger.info(f"Login successful: {username}", username=username, **extra)
    else:
        logger.warning(f"Login failed: {username}", username=username, **extra)


def log_api_call(endpoint: str, method: str, status: int, latency_ms: float, **extra):
    """API çağrısı logla"""
    logger = get_logger('api')
    _metrics.inc(API_CALL_COUNT, labels={'endpoint': endpoint, 'method': method, 'status': str(status)})

    logger.info(f"API call: {method} {endpoint}",
               endpoint=endpoint,
               method=method,
               status=status,
               latency_ms=latency_ms,
               **extra)


# ============================================================
# CLI Test
# ============================================================

if __name__ == '__main__':
    # Test logging
    setup_logging(level=logging.DEBUG, json_format=True)

    logger = get_logger('test')
    logger.info("Test message", user="admin", action="test")
    logger.warning("Warning message", code=123)

    try:
        raise ValueError("Test error")
    except Exception:
        logger.exception("Exception occurred")

    # Test metrics
    metrics = get_metrics()
    metrics.inc('test_counter', labels={'env': 'dev'})
    metrics.set('test_gauge', 42.5)
    metrics.observe('test_histogram', 0.15)
    metrics.observe('test_histogram', 0.25)
    metrics.observe('test_histogram', 0.5)

    print("\n=== Prometheus Export ===")
    print(metrics.export_prometheus())

    print("\n=== JSON Metrics ===")
    print(json.dumps(metrics.get_all_metrics(), indent=2))
