#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Production Configuration
    Global-Scale Cyber Intelligence Platform
================================================================================
"""

import os
import secrets
from datetime import timedelta

# === Environment ===
ENV = os.getenv('TSUNAMI_ENV', 'production')
DEBUG = False
TESTING = False

# === Security ===
SECRET_KEY = os.getenv('TSUNAMI_SECRET_KEY', secrets.token_hex(32))
SESSION_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

# === CSRF Protection ===
WTF_CSRF_ENABLED = True
WTF_CSRF_TIME_LIMIT = 3600

# === Password Policy ===
PASSWORD_MIN_LENGTH = 12
PASSWORD_REQUIRE_UPPERCASE = True
PASSWORD_REQUIRE_LOWERCASE = True
PASSWORD_REQUIRE_NUMBERS = True
PASSWORD_REQUIRE_SPECIAL = True
PASSWORD_MAX_AGE_DAYS = 90
ACCOUNT_LOCKOUT_ATTEMPTS = 5
ACCOUNT_LOCKOUT_DURATION = timedelta(minutes=30)

# === Rate Limiting ===
RATELIMIT_ENABLED = True
RATELIMIT_DEFAULT = "100/minute"
RATELIMIT_STORAGE_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
RATELIMIT_HEADERS_ENABLED = True

# API Rate Limits
API_RATE_LIMITS = {
    'default': '100/minute',
    'auth': '10/minute',
    'osint': '30/minute',
    'scan': '10/minute',
    'export': '5/minute'
}

# === Database ===
DATABASE_PATH = os.getenv('TSUNAMI_DB_PATH', '/var/lib/tsunami/dalga.db')
SQLALCHEMY_DATABASE_URI = f'sqlite:///{DATABASE_PATH}'
SQLALCHEMY_TRACK_MODIFICATIONS = False

# Redis for sessions and caching
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# === Celery (Background Tasks) ===
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL', REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND', REDIS_URL)
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TIMEZONE = 'Europe/Istanbul'
CELERY_ENABLE_UTC = True

# Beat schedule for periodic tasks
CELERY_BEAT_SCHEDULE = {
    'threat-feed-sync': {
        'task': 'tasks.sync_threat_feeds',
        'schedule': timedelta(hours=1),
    },
    'cleanup-old-data': {
        'task': 'tasks.cleanup_old_data',
        'schedule': timedelta(days=1),
    },
    'health-check': {
        'task': 'tasks.system_health_check',
        'schedule': timedelta(minutes=5),
    },
    'geo-analysis': {
        'task': 'tasks.run_geo_analysis',
        'schedule': timedelta(hours=6),
    },
}

# === Logging ===
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - [%(request_id)s] - %(message)s'
LOG_FILE = '/var/log/tsunami/tsunami.log'
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10MB
LOG_BACKUP_COUNT = 10

# Audit logging
AUDIT_LOG_ENABLED = True
AUDIT_LOG_FILE = '/var/log/tsunami/audit.log'

# === API Keys (from environment) ===
API_KEYS = {
    'shodan': os.getenv('SHODAN_API_KEY'),
    'opencellid': os.getenv('OPENCELLID_API_KEY'),
    'n2yo': os.getenv('N2YO_API_KEY'),
    'hibp': os.getenv('HIBP_API_KEY'),
    'virustotal': os.getenv('VIRUSTOTAL_API_KEY'),
    'abuseipdb': os.getenv('ABUSEIPDB_KEY'),
    'otx': os.getenv('OTX_KEY'),
}

# === Threat Intelligence Feeds ===
THREAT_FEEDS = {
    'alienvault_otx': {
        'url': 'https://otx.alienvault.com/api/v1/pulses/subscribed',
        'enabled': bool(os.getenv('OTX_KEY')),
        'interval': 3600
    },
    'abuse_ip': {
        'url': 'https://api.abuseipdb.com/api/v2/blacklist',
        'enabled': bool(os.getenv('ABUSEIPDB_KEY')),
        'interval': 86400
    },
    'feodo_tracker': {
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
        'enabled': True,
        'interval': 3600
    },
    'emergingthreats': {
        'url': 'https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt',
        'enabled': True,
        'interval': 86400
    }
}

# === BEYIN (AI Brain) Configuration ===
BEYIN_ENABLED = True
BEYIN_AUTONOMOUS_MODE = True
BEYIN_DEFCON_DEFAULT = 'GUVENLI'
BEYIN_THREAT_THRESHOLD = 0.7
BEYIN_AUTO_RESPONSE_ENABLED = True
BEYIN_MAX_CONCURRENT_ANALYSES = 10

# === Geospatial ===
GEO_DEFAULT_CENTER = [39.0, 35.0]  # Turkey center
GEO_DEFAULT_ZOOM = 6
GEO_TILE_SERVER = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
GEO_MAX_MARKERS = 10000

# === Security Headers ===
SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.socket.io https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; connect-src 'self' wss: https:;",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(self), microphone=()'
}

# === File Upload ===
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'json', 'csv', 'xml', 'pcap', 'cap'}
UPLOAD_FOLDER = '/var/lib/tsunami/uploads'

# === Export ===
EXPORT_FOLDER = '/var/lib/tsunami/exports'
EXPORT_MAX_RECORDS = 100000

# === Monitoring ===
PROMETHEUS_ENABLED = True
PROMETHEUS_PORT = 9090
SENTRY_DSN = os.getenv('SENTRY_DSN')

# === Health Check ===
HEALTH_CHECK_SERVICES = [
    {'name': 'database', 'critical': True},
    {'name': 'redis', 'critical': True},
    {'name': 'celery', 'critical': False},
    {'name': 'beyin', 'critical': False},
]
