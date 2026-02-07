#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Test Configuration v2.0
================================

Comprehensive pytest fixtures for Flask app, test client, mock data,
and all TSUNAMI modules.

pytest tests/ -v --cov=. --cov-report=html
"""

import pytest
import sys
import os
import json
import tempfile
import asyncio
import sqlite3
import secrets
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from unittest.mock import Mock, MagicMock, patch

# Parent dizini path'e ekle
sys.path.insert(0, str(Path(__file__).parent.parent))

# pytest-asyncio configuration
try:
    import pytest_asyncio
    pytest_plugins = ['pytest_asyncio']
except ImportError:
    pass


# ============================================================
# Core Fixtures
# ============================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    try:
        loop = asyncio.get_event_loop_policy().new_event_loop()
        yield loop
        loop.close()
    except Exception:
        yield None


@pytest.fixture(scope="session")
def temp_dir():
    """Geçici test dizini (session-scoped)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_test_dir():
    """Geçici test dizini (function-scoped)"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


# ============================================================
# Flask Application Fixtures
# ============================================================

@pytest.fixture(scope="module")
def flask_app():
    """Flask application instance for testing"""
    from flask import Flask

    app = Flask(__name__)
    app.secret_key = secrets.token_bytes(32)
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_COOKIE_SECURE'] = False

    # Register basic test routes
    @app.route('/health')
    def health():
        return {'status': 'healthy'}

    @app.route('/api/test', methods=['GET', 'POST'])
    def api_test():
        from flask import request, jsonify
        return jsonify({'method': request.method, 'data': request.get_json(silent=True)})

    return app


@pytest.fixture
def test_client(flask_app):
    """Flask test client"""
    return flask_app.test_client()


@pytest.fixture
def app_context(flask_app):
    """Flask application context"""
    with flask_app.app_context():
        yield flask_app


@pytest.fixture
def request_context(flask_app):
    """Flask request context"""
    with flask_app.test_request_context():
        yield


# ============================================================
# Environment & Mock Fixtures
# ============================================================

@pytest.fixture
def mock_env(monkeypatch):
    """Mock environment variables for testing"""
    test_env = {
        'SHODAN_API_KEY': 'test_shodan_key_12345',
        'N2YO_API_KEY': 'test_n2yo_key_67890',
        'OPENCELLID_API_KEY': 'test_opencellid_key',
        'HIBP_API_KEY': 'test_hibp_key',
        'VIRUSTOTAL_API_KEY': 'test_vt_key',
        'OTX_KEY': 'test_otx_key',
        'GROQ_API_KEY': 'test_groq_key',
        'WIGLE_API_NAME': 'test_wigle_name',
        'WIGLE_API_TOKEN': 'test_wigle_token',
        'REDIS_URL': 'redis://localhost:6379/0',
        'FLASK_ENV': 'testing',
        'ALLOWED_ORIGINS': 'http://localhost:8080',
    }

    for key, value in test_env.items():
        monkeypatch.setenv(key, value)

    return test_env


@pytest.fixture
def mock_redis():
    """Mock Redis client"""
    mock = MagicMock()
    mock.get.return_value = None
    mock.set.return_value = True
    mock.delete.return_value = 1
    mock.pipeline.return_value = mock
    mock.execute.return_value = [True, True, 0, True]
    mock.zremrangebyscore.return_value = 0
    mock.zadd.return_value = 1
    mock.zcard.return_value = 1
    mock.expire.return_value = True
    return mock


# ============================================================
# Database Fixtures
# ============================================================

@pytest.fixture
def test_db(temp_test_dir):
    """SQLite test database"""
    db_path = temp_test_dir / "test_tsunami.db"
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    # Create basic test tables
    cursor = conn.cursor()
    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            totp_secret TEXT
        );

        CREATE TABLE IF NOT EXISTS wifi_networks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            bssid TEXT UNIQUE NOT NULL,
            ssid TEXT,
            channel INTEGER,
            signal_strength INTEGER,
            encryption TEXT,
            vendor TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            latitude REAL,
            longitude REAL
        );

        CREATE TABLE IF NOT EXISTS bluetooth_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT UNIQUE NOT NULL,
            device_name TEXT,
            device_type TEXT,
            device_class TEXT,
            signal_strength INTEGER,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            category TEXT
        );

        CREATE TABLE IF NOT EXISTS cell_towers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cell_id TEXT UNIQUE NOT NULL,
            lac INTEGER,
            mcc INTEGER,
            mnc INTEGER,
            radio_type TEXT,
            signal_strength INTEGER,
            latitude REAL,
            longitude REAL,
            operator TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            devices_found INTEGER,
            duration_seconds REAL,
            parameters TEXT,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_name TEXT UNIQUE NOT NULL,
            api_key TEXT,
            api_secret TEXT,
            last_used TIMESTAMP,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user TEXT,
            action TEXT,
            resource TEXT,
            ip_address TEXT,
            user_agent TEXT,
            success INTEGER,
            details TEXT
        );
    """)
    conn.commit()

    yield conn

    conn.close()


# ============================================================
# Security Module Fixtures
# ============================================================

@pytest.fixture
def password_manager():
    """PasswordManager instance"""
    from dalga_security import PasswordManager
    return PasswordManager()


@pytest.fixture
def rate_limiter():
    """RateLimiter instance (memory-based)"""
    from dalga_security import RateLimiter
    return RateLimiter(redis_client=None)


@pytest.fixture
def account_lockout():
    """AccountLockout instance"""
    from dalga_security import AccountLockout
    return AccountLockout(max_attempts=5, lockout_duration=300)


@pytest.fixture
def input_sanitizer():
    """InputSanitizer instance"""
    from dalga_security import InputSanitizer
    return InputSanitizer()


@pytest.fixture
def audit_logger(temp_test_dir):
    """AuditLogger instance with temp file"""
    from dalga_security import AuditLogger
    log_file = temp_test_dir / "audit.log"
    return AuditLogger(log_file=str(log_file))


@pytest.fixture
def two_factor_auth():
    """TwoFactorAuth instance"""
    from dalga_security import TwoFactorAuth
    return TwoFactorAuth()


@pytest.fixture
def geo_fence():
    """GeoFence instance"""
    from dalga_security import GeoFence
    return GeoFence()


@pytest.fixture
def security_manager():
    """SecurityManager singleton instance"""
    from dalga_security import SecurityManager
    return SecurityManager.get_instance()


# ============================================================
# Validation Fixtures
# ============================================================

@pytest.fixture
def validation_test_data():
    """Test data for validation tests"""
    return {
        'valid_ips': ['8.8.8.8', '1.1.1.1', '192.0.2.1', '203.0.113.1'],
        'invalid_ips': ['256.1.1.1', '1.2.3', 'not.an.ip', ''],
        'private_ips': ['192.168.1.1', '10.0.0.1', '172.16.0.1', '127.0.0.1'],
        'valid_domains': ['example.com', 'sub.example.com', 'test.co.uk'],
        'invalid_domains': ['localhost', 'internal.local', '-invalid.com', ''],
        'valid_emails': ['user@example.com', 'test.user@domain.org'],
        'invalid_emails': ['notanemail', '@invalid.com', 'user@', ''],
        'valid_ports': ['1-1000', '80', '443', '1-65535'],
        'invalid_ports': ['0', '65536', '-1-100', 'abc'],
        'sql_injections': [
            "' OR 1=1 --",
            "admin'--",
            "1; DROP TABLE users",
            "' UNION SELECT * FROM users --",
            "'; DELETE FROM users; --",
            "1' AND '1'='1",
        ],
        'xss_payloads': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<iframe src='evil.com'>",
            "<body onload=alert('XSS')>",
            "onclick=alert(1)",
        ],
        'path_traversals': [
            '../../../etc/passwd',
            '..\\..\\windows\\system32',
            '%2e%2e%2f',
            '....//....//etc/passwd',
        ],
    }


# ============================================================
# OSINT & SIGINT Fixtures
# ============================================================

@pytest.fixture
def osint_manager():
    """OSINTYoneticisi instance"""
    try:
        from dalga_osint import OSINTYoneticisi
        return OSINTYoneticisi()
    except ImportError:
        pytest.skip("OSINT module not available")


@pytest.fixture
def mock_wifi_scan_results():
    """Mock WiFi scan results"""
    return [
        {
            'bssid': 'AA:BB:CC:DD:EE:FF',
            'ssid': 'TestNetwork1',
            'channel': 6,
            'signal': 75,
            'encryption': 'WPA2',
            'vendor': 'Intel',
        },
        {
            'bssid': '11:22:33:44:55:66',
            'ssid': 'TestNetwork2',
            'channel': 11,
            'signal': 60,
            'encryption': 'WPA3',
            'vendor': 'Apple',
        },
        {
            'bssid': '99:88:77:66:55:44',
            'ssid': '<Hidden>',
            'channel': 1,
            'signal': 40,
            'encryption': 'Open',
            'vendor': 'Unknown',
        },
    ]


@pytest.fixture
def mock_bluetooth_scan_results():
    """Mock Bluetooth scan results"""
    return [
        {
            'mac': 'AA:BB:CC:11:22:33',
            'name': 'AirPods Pro',
            'type': 'BLE',
            'category': 'headphone',
            'signal': -45,
        },
        {
            'mac': 'DD:EE:FF:44:55:66',
            'name': 'iPhone 15',
            'type': 'Classic',
            'category': 'phone',
            'signal': -60,
        },
        {
            'mac': '77:88:99:AA:BB:CC',
            'name': 'Unknown Device',
            'type': 'BLE',
            'category': 'other',
            'signal': -80,
        },
    ]


@pytest.fixture
def mock_cell_tower_results():
    """Mock cell tower results"""
    return [
        {
            'cell_id': '12345',
            'lac': 1000,
            'mcc': 286,
            'mnc': 1,
            'radio': 'LTE',
            'lat': 41.0082,
            'lng': 28.9784,
            'signal': -85,
        },
        {
            'cell_id': '67890',
            'lac': 1001,
            'mcc': 286,
            'mnc': 2,
            'radio': '5G',
            'lat': 41.0100,
            'lng': 28.9800,
            'signal': -75,
        },
    ]


# ============================================================
# Mock External API Responses
# ============================================================

@pytest.fixture
def mock_shodan_response():
    """Mock Shodan API response"""
    return {
        'matches': [
            {
                'ip_str': '192.0.2.1',
                'port': 80,
                'org': 'Test Organization',
                'product': 'nginx',
                'location': {
                    'latitude': 41.0082,
                    'longitude': 28.9784,
                    'country_name': 'Turkey',
                    'city': 'Istanbul',
                },
                'data': 'HTTP/1.1 200 OK\r\nServer: nginx\r\n',
            }
        ],
        'total': 1,
    }


@pytest.fixture
def mock_wigle_response():
    """Mock WiGLE API response"""
    return {
        'success': True,
        'results': [
            {
                'netid': 'AA:BB:CC:DD:EE:FF',
                'ssid': 'TestNetwork',
                'trilat': 41.0082,
                'trilong': 28.9784,
                'level': -65,
                'lastupdt': '2024-01-01',
            }
        ],
        'totalResults': 1,
    }


@pytest.fixture
def mock_hibp_response():
    """Mock Have I Been Pwned API response"""
    return [
        {
            'Name': 'TestBreach',
            'BreachDate': '2023-01-01',
            'PwnCount': 1000000,
            'DataClasses': ['Email addresses', 'Passwords'],
        }
    ]


@pytest.fixture
def mock_virustotal_response():
    """Mock VirusTotal API response"""
    return {
        'data': {
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 0,
                    'suspicious': 0,
                    'harmless': 70,
                    'undetected': 5,
                },
                'type_description': 'PNG image',
                'names': ['test.png'],
            }
        }
    }


@pytest.fixture
def mock_ip_geolocation_response():
    """Mock IP geolocation response"""
    return {
        'status': 'success',
        'country': 'Turkey',
        'countryCode': 'TR',
        'region': 'Istanbul',
        'regionName': 'Istanbul',
        'city': 'Istanbul',
        'lat': 41.0082,
        'lon': 28.9784,
        'timezone': 'Europe/Istanbul',
        'isp': 'Test ISP',
        'org': 'Test Organization',
    }


# ============================================================
# Vault & Secrets Fixtures
# ============================================================

@pytest.fixture
def vault(temp_test_dir):
    """TsunamiVault instance with temp storage"""
    try:
        from dalga_vault import TsunamiVault
        vault = TsunamiVault()
        vault.VAULT_DIR = temp_test_dir / ".vault"
        vault.VAULT_FILE = vault.VAULT_DIR / "test.vault"
        vault.VAULT_DIR.mkdir(parents=True, exist_ok=True)
        return vault
    except ImportError:
        pytest.skip("Vault module not available")


# ============================================================
# Threat Intelligence Fixtures
# ============================================================

@pytest.fixture
def threat_intel():
    """GlobalThreatIntelligence instance"""
    try:
        from dalga_threat_intel import GlobalThreatIntelligence
        return GlobalThreatIntelligence.get_instance()
    except ImportError:
        pytest.skip("Threat Intel module not available")


@pytest.fixture
def mock_threat_data():
    """Mock threat intelligence data"""
    return {
        'iocs': [
            {'type': 'ip', 'value': '192.0.2.100', 'threat_type': 'c2_server'},
            {'type': 'domain', 'value': 'malware.test', 'threat_type': 'malware_distribution'},
            {'type': 'hash', 'value': 'a' * 64, 'threat_type': 'ransomware'},
        ],
        'apt_groups': [
            {'name': 'APT29', 'aliases': ['Cozy Bear'], 'origin': 'RU'},
            {'name': 'APT41', 'aliases': ['Winnti'], 'origin': 'CN'},
        ],
        'cves': [
            {'id': 'CVE-2024-0001', 'severity': 'critical', 'cvss': 9.8},
        ],
    }


# ============================================================
# Hypothesis Strategy Fixtures
# ============================================================

try:
    from hypothesis import strategies as st

    @pytest.fixture
    def ip_strategy():
        """Hypothesis strategy for IP addresses"""
        return st.ip_addresses(v=4).map(str)

    @pytest.fixture
    def domain_strategy():
        """Hypothesis strategy for domain names"""
        return st.from_regex(
            r'^[a-z][a-z0-9-]{0,61}[a-z0-9]\.[a-z]{2,}$',
            fullmatch=True
        )

    @pytest.fixture
    def email_strategy():
        """Hypothesis strategy for email addresses"""
        return st.emails()

    @pytest.fixture
    def port_strategy():
        """Hypothesis strategy for port numbers"""
        return st.integers(min_value=1, max_value=65535)

except ImportError:
    pass


# ============================================================
# Utility Fixtures
# ============================================================

@pytest.fixture
def sample_user_data():
    """Sample user data for authentication tests"""
    return {
        'username': 'testuser',
        'password': 'SecureP@ssw0rd123!',
        'email': 'test@example.com',
        'totp_secret': 'JBSWY3DPEHPK3PXP',  # Test secret
    }


@pytest.fixture
def sample_weak_passwords():
    """Sample weak passwords for validation tests"""
    return [
        'password',
        '123456',
        'qwerty',
        'admin',
        'letmein',
        'welcome',
        'monkey',
        'dragon',
        'master',
        'abc123',
    ]


@pytest.fixture
def sample_strong_passwords():
    """Sample strong passwords for validation tests"""
    return [
        'K9$mP2nQ#xL5vR8@',
        'Tr0ub4dor&3',
        'Correct-Horse-Battery-Staple-42!',
        'MyS3cur3P@ssw0rd!2024',
    ]


@pytest.fixture
def http_request_headers():
    """Sample HTTP request headers"""
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'X-Forwarded-For': '192.0.2.1',
        'X-Real-IP': '192.0.2.1',
    }


# ============================================================
# Async Fixtures
# ============================================================

@pytest.fixture
async def async_client():
    """Async HTTP client for testing"""
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            yield session
    except ImportError:
        pytest.skip("aiohttp not available")


# ============================================================
# Cleanup Fixtures
# ============================================================

@pytest.fixture(autouse=True)
def cleanup_singletons():
    """Clean up singletons after each test"""
    yield
    # Reset any singleton instances if needed
    pass


# ============================================================
# Markers Configuration
# ============================================================

def pytest_configure(config):
    """Configure custom pytest markers"""
    config.addinivalue_line("markers", "slow: marks tests as slow")
    config.addinivalue_line("markers", "integration: marks integration tests")
    config.addinivalue_line("markers", "security: marks security tests")
    config.addinivalue_line("markers", "api: marks API tests")
    config.addinivalue_line("markers", "osint: marks OSINT tests")
    config.addinivalue_line("markers", "sigint: marks SIGINT tests")
    config.addinivalue_line("markers", "requires_network: marks tests requiring network")
    config.addinivalue_line("markers", "requires_root: marks tests requiring root privileges")
