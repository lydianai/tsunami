#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Logging Configuration
=============================

Centralized logging with ELK Stack support (Elasticsearch, Logstash, Kibana).
Supports JSON structured logging for better log aggregation and analysis.

Usage:
    from utils.logging_config import setup_logging, get_logger

    # Setup once at application start
    setup_logging(
        app_name='tsunami',
        log_level='INFO',
        elk_enabled=True,
        logstash_host='localhost',
        logstash_port=5044
    )

    # Get logger in any module
    logger = get_logger(__name__)
    logger.info('Application started', extra={'user': 'admin', 'action': 'login'})

AILYDIAN AutoFix - Log Aggregation Enhancement
"""

import json
import logging
import logging.handlers
import os
import socket
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional
import threading

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent
LOG_DIR = PROJECT_ROOT / 'logs'


class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    Compatible with ELK Stack, Splunk, and other log aggregators.
    """

    def __init__(self, app_name: str = 'tsunami', include_hostname: bool = True):
        super().__init__()
        self.app_name = app_name
        self.hostname = socket.gethostname() if include_hostname else None

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            '@timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'app': self.app_name,
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }

        # Add hostname
        if self.hostname:
            log_data['hostname'] = self.hostname

        # Add thread info
        log_data['thread'] = {
            'id': record.thread,
            'name': record.threadName
        }

        # Add process info
        log_data['process'] = {
            'id': record.process,
            'name': record.processName
        }

        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__ if record.exc_info[0] else None,
                'message': str(record.exc_info[1]) if record.exc_info[1] else None,
                'stacktrace': ''.join(traceback.format_exception(*record.exc_info))
            }

        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename', 'funcName',
                          'levelname', 'levelno', 'lineno', 'module', 'msecs',
                          'pathname', 'process', 'processName', 'relativeCreated',
                          'stack_info', 'exc_info', 'exc_text', 'thread', 'threadName',
                          'message', 'taskName']:
                try:
                    json.dumps(value)  # Check if serializable
                    log_data[key] = value
                except (TypeError, ValueError):
                    log_data[key] = str(value)

        return json.dumps(log_data, ensure_ascii=False)


class LogstashHandler(logging.handlers.SocketHandler):
    """
    Handler for sending logs directly to Logstash via TCP.
    """

    def __init__(self, host: str, port: int):
        super().__init__(host, port)
        self.formatter = JSONFormatter()

    def makePickle(self, record: logging.LogRecord) -> bytes:
        """Format record as JSON and encode for transmission."""
        return (self.format(record) + '\n').encode('utf-8')


class AsyncLogstashHandler(logging.Handler):
    """
    Async handler for non-blocking log transmission to Logstash.
    Uses a queue and background thread to prevent logging from blocking.
    """

    def __init__(self, host: str, port: int, queue_size: int = 10000):
        super().__init__()
        self.host = host
        self.port = port
        self.queue = []
        self.queue_lock = threading.Lock()
        self.max_queue_size = queue_size
        self.socket = None
        self.connected = False
        self.formatter = JSONFormatter()

        # Start background sender thread
        self._stop_event = threading.Event()
        self._sender_thread = threading.Thread(target=self._sender_loop, daemon=True)
        self._sender_thread.start()

    def emit(self, record: logging.LogRecord):
        """Add record to queue for async transmission."""
        try:
            msg = self.format(record)
            with self.queue_lock:
                if len(self.queue) < self.max_queue_size:
                    self.queue.append(msg)
        except Exception:
            self.handleError(record)

    def _connect(self) -> bool:
        """Establish connection to Logstash."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5)
            self.socket.connect((self.host, self.port))
            self.connected = True
            return True
        except Exception:
            self.connected = False
            return False

    def _sender_loop(self):
        """Background loop to send queued logs."""
        while not self._stop_event.is_set():
            # Get messages from queue
            messages = []
            with self.queue_lock:
                messages = self.queue[:]
                self.queue = []

            if messages:
                if not self.connected:
                    self._connect()

                if self.connected:
                    try:
                        for msg in messages:
                            self.socket.sendall((msg + '\n').encode('utf-8'))
                    except Exception:
                        self.connected = False
                        # Put messages back in queue
                        with self.queue_lock:
                            self.queue = messages + self.queue

            self._stop_event.wait(0.5)  # Send every 500ms

    def close(self):
        """Clean shutdown."""
        self._stop_event.set()
        self._sender_thread.join(timeout=2)
        if self.socket:
            self.socket.close()
        super().close()


class SentryHandler(logging.Handler):
    """
    Handler for sending errors to Sentry.
    Requires sentry-sdk to be installed.
    """

    def __init__(self, dsn: str, level: int = logging.ERROR):
        super().__init__(level)
        try:
            import sentry_sdk
            sentry_sdk.init(dsn=dsn, traces_sample_rate=0.1)
            self.sentry = sentry_sdk
            self.enabled = True
        except ImportError:
            self.enabled = False

    def emit(self, record: logging.LogRecord):
        if not self.enabled:
            return

        try:
            if record.exc_info:
                self.sentry.capture_exception(record.exc_info)
            else:
                self.sentry.capture_message(
                    record.getMessage(),
                    level=record.levelname.lower()
                )
        except Exception:
            self.handleError(record)


def setup_logging(
    app_name: str = 'tsunami',
    log_level: str = 'INFO',
    log_file: Optional[str] = None,
    elk_enabled: bool = False,
    logstash_host: str = 'localhost',
    logstash_port: int = 5044,
    sentry_dsn: Optional[str] = None,
    json_format: bool = True
) -> logging.Logger:
    """
    Setup centralized logging configuration.

    Args:
        app_name: Application name for log identification
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional file path for file logging
        elk_enabled: Enable Logstash integration
        logstash_host: Logstash host address
        logstash_port: Logstash TCP port
        sentry_dsn: Sentry DSN for error tracking
        json_format: Use JSON format for console output

    Returns:
        Root logger instance
    """
    # Create log directory
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    # Get root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))

    # Clear existing handlers
    root_logger.handlers.clear()

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)

    if json_format:
        console_handler.setFormatter(JSONFormatter(app_name))
    else:
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))

    root_logger.addHandler(console_handler)

    # File handler (JSON format, rotating)
    if log_file or True:  # Always create file log
        file_path = log_file or str(LOG_DIR / f'{app_name}.log')
        file_handler = logging.handlers.RotatingFileHandler(
            file_path,
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(JSONFormatter(app_name))
        root_logger.addHandler(file_handler)

    # Error file handler (separate file for errors)
    error_file = str(LOG_DIR / f'{app_name}_errors.log')
    error_handler = logging.handlers.RotatingFileHandler(
        error_file,
        maxBytes=10 * 1024 * 1024,
        backupCount=10,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(JSONFormatter(app_name))
    root_logger.addHandler(error_handler)

    # Logstash handler (ELK integration)
    if elk_enabled:
        try:
            logstash_handler = AsyncLogstashHandler(logstash_host, logstash_port)
            logstash_handler.setLevel(logging.INFO)
            root_logger.addHandler(logstash_handler)
            root_logger.info(f'Logstash handler configured: {logstash_host}:{logstash_port}')
        except Exception as e:
            root_logger.warning(f'Failed to setup Logstash handler: {e}')

    # Sentry handler (error tracking)
    if sentry_dsn:
        sentry_handler = SentryHandler(sentry_dsn)
        root_logger.addHandler(sentry_handler)
        root_logger.info('Sentry error tracking enabled')

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance with the given name.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Pre-configured loggers for common modules
class TsunamiLoggers:
    """Pre-configured logger instances for TSUNAMI modules."""

    @staticmethod
    def web() -> logging.Logger:
        return get_logger('tsunami.web')

    @staticmethod
    def security() -> logging.Logger:
        return get_logger('tsunami.security')

    @staticmethod
    def database() -> logging.Logger:
        return get_logger('tsunami.database')

    @staticmethod
    def api() -> logging.Logger:
        return get_logger('tsunami.api')

    @staticmethod
    def stealth() -> logging.Logger:
        return get_logger('tsunami.stealth')

    @staticmethod
    def osint() -> logging.Logger:
        return get_logger('tsunami.osint')

    @staticmethod
    def celery() -> logging.Logger:
        return get_logger('tsunami.celery')


# Export convenience function
loggers = TsunamiLoggers()


# Example Logstash configuration (for reference)
LOGSTASH_CONFIG_EXAMPLE = """
# /etc/logstash/conf.d/tsunami.conf

input {
  tcp {
    port => 5044
    codec => json_lines
  }
}

filter {
  if [app] == "tsunami" {
    mutate {
      add_field => { "[@metadata][index]" => "tsunami-logs" }
    }

    if [level] == "ERROR" or [level] == "CRITICAL" {
      mutate {
        add_tag => ["alert"]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{[@metadata][index]}-%{+YYYY.MM.dd}"
  }

  # Optional: Send alerts to Slack
  if "alert" in [tags] {
    http {
      url => "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
      http_method => "post"
      format => "json"
      mapping => {
        "text" => "[%{level}] %{message}"
      }
    }
  }
}
"""


# Example Kibana dashboard query (for reference)
KIBANA_QUERIES = {
    'all_errors': 'level:ERROR OR level:CRITICAL',
    'auth_failures': 'logger:tsunami.security AND message:*failed*',
    'api_requests': 'logger:tsunami.api',
    'slow_requests': 'response_time:>1000',
    'security_events': 'tags:security',
}
