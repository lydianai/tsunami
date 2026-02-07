#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Security Tests v1.0
===========================

Güvenlik modülleri için unit testler.
pytest tests/test_security.py -v
"""

import os
import sys
import time
import pytest
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSecretsManager:
    """SecretsManager testleri"""

    def test_get_secret_from_env(self):
        from dalga_secrets import get_secret
        os.environ['TEST_SECRET'] = 'test_value_123'
        value = get_secret('TEST_SECRET')
        assert value == 'test_value_123'
        del os.environ['TEST_SECRET']

    def test_get_secret_default(self):
        from dalga_secrets import get_secret
        value = get_secret('NON_EXISTENT_SECRET', default='default_value')
        assert value == 'default_value'

    def test_get_secret_required_raises(self):
        from dalga_secrets import get_secret
        with pytest.raises(ValueError, match="Zorunlu secret"):
            get_secret('DEFINITELY_NOT_EXISTS', required=True)

    def test_secret_available(self):
        from dalga_secrets import secret_available
        os.environ['AVAILABLE_SECRET'] = 'yes'
        assert secret_available('AVAILABLE_SECRET') == True
        assert secret_available('NOT_AVAILABLE_SECRET') == False
        del os.environ['AVAILABLE_SECRET']

    def test_secrets_manager_singleton(self):
        from dalga_secrets import SecretsManager
        sm1 = SecretsManager()
        sm2 = SecretsManager()
        assert sm1 is sm2

    def test_mask_value(self):
        from dalga_secrets import SecretsManager
        sm = SecretsManager()
        masked = sm.mask_value("secret_api_key_12345", show_chars=4)
        assert masked.startswith("secr")
        assert "12345" not in masked

    def test_get_status(self):
        from dalga_secrets import SecretsManager
        sm = SecretsManager()
        status = sm.get_status()
        assert 'total' in status
        assert 'loaded' in status


class TestInputValidation:
    """Input validation testleri"""

    def test_safe_string_normal(self):
        from dalga_validation import is_safe_string
        is_safe, reason = is_safe_string("Hello World")
        assert is_safe == True

    def test_sql_injection_detection(self):
        from dalga_validation import is_safe_string
        dangerous_inputs = ["' OR 1=1 --", "admin'--", "1; DROP TABLE users"]
        for inp in dangerous_inputs:
            is_safe, reason = is_safe_string(inp)
            assert is_safe == False, f"Should detect: {inp}"

    def test_xss_detection(self):
        from dalga_validation import is_safe_string
        dangerous_inputs = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        for inp in dangerous_inputs:
            is_safe, reason = is_safe_string(inp)
            assert is_safe == False, f"Should detect: {inp}"

    def test_sanitize_string(self):
        from dalga_validation import sanitize_string
        result = sanitize_string("<script>alert(1)</script>")
        assert "<script>" not in result

    def test_valid_ip_public(self):
        """Public IP validation"""
        from dalga_validation import is_valid_ip
        assert is_valid_ip("8.8.8.8") == True
        assert is_valid_ip("1.1.1.1") == True
        assert is_valid_ip("256.1.1.1") == False
        assert is_valid_ip("not.an.ip") == False

    def test_valid_domain(self):
        from dalga_validation import is_valid_domain
        assert is_valid_domain("example.com") == True
        assert is_valid_domain("sub.example.com") == True
        assert is_valid_domain("localhost") == False


class TestCSRFProtection:
    """CSRF protection testleri"""

    def test_generate_token(self):
        from dalga_auth import CSRFProtection
        from flask import Flask
        app = Flask(__name__)
        app.secret_key = 'test_secret'
        with app.test_request_context():
            from flask import session
            csrf = CSRFProtection()
            token = csrf.generate_token()
            assert token is not None
            assert len(token) >= 32

    def test_validate_token(self):
        from dalga_auth import CSRFProtection
        from flask import Flask
        app = Flask(__name__)
        app.secret_key = 'test_secret'
        with app.test_request_context():
            csrf = CSRFProtection()
            token = csrf.generate_token()
            assert csrf.validate_token(token) == True
            assert csrf.validate_token("invalid") == False


class TestRateLimiter:
    """Rate limiter testleri"""

    def test_allow_requests_within_limit(self):
        from dalga_auth import RateLimiter
        limiter = RateLimiter()
        for i in range(5):
            allowed, info = limiter.is_allowed('test_rate_ip', limit=10, window=60)
            assert allowed == True

    def test_block_requests_over_limit(self):
        from dalga_auth import RateLimiter
        limiter = RateLimiter()
        for i in range(15):
            limiter.is_allowed('over_limit_ip', limit=10, window=60)
        allowed, info = limiter.is_allowed('over_limit_ip', limit=10, window=60)
        assert allowed == False


class TestBruteForceProtection:
    """Brute force protection testleri"""

    def test_allow_first_attempts(self):
        from dalga_auth import BruteForceProtection
        bf = BruteForceProtection()
        # First attempt - not blocked yet
        blocked, remaining = bf.is_blocked('bf_new_test_ip')
        assert blocked == False

    def test_block_after_failures(self):
        from dalga_auth import BruteForceProtection
        bf = BruteForceProtection()
        # Record multiple failures (5+ should trigger block)
        for i in range(6):
            bf.record_attempt('bf_fail_test_ip', success=False)
        # Should be blocked now
        blocked, remaining = bf.is_blocked('bf_fail_test_ip')
        assert blocked == True

    def test_reset_on_success(self):
        from dalga_auth import BruteForceProtection
        bf = BruteForceProtection()
        # Record some failures
        for i in range(3):
            bf.record_attempt('bf_success_test_ip', success=False)
        # Record success - should reset
        bf.record_attempt('bf_success_test_ip', success=True)
        # Should not be blocked
        blocked, remaining = bf.is_blocked('bf_success_test_ip')
        assert blocked == False


class TestTOTPManager:
    """TOTP 2FA testleri"""

    def test_generate_secret(self):
        try:
            from dalga_auth import TOTPManager
            totp = TOTPManager()
            secret = totp.generate_secret()
            assert secret is not None
            assert len(secret) == 32
        except RuntimeError:
            pytest.skip("pyotp not installed")


class TestSessionSecurityManager:
    """Session security testleri"""

    def test_clear_session(self):
        from dalga_auth import SessionSecurityManager
        from flask import Flask
        app = Flask(__name__)
        app.secret_key = 'test_secret'
        with app.test_request_context():
            from flask import session
            session['user'] = 'admin'
            sm = SessionSecurityManager()
            sm.clear_session()
            assert session.get('user') is None


class TestStructuredLogging:
    """Structured logging testleri"""

    def test_json_formatter(self):
        from dalga_logging import JSONFormatter
        import logging
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name='test', level=logging.INFO, pathname='test.py',
            lineno=1, msg='Test message', args=(), exc_info=None
        )
        output = formatter.format(record)
        data = json.loads(output)
        assert data['level'] == 'INFO'
        assert data['message'] == 'Test message'

    def test_get_logger(self):
        from dalga_logging import get_logger
        logger = get_logger('test_module')
        assert logger is not None


class TestPrometheusMetrics:
    """Prometheus metrics testleri"""

    def test_counter_increment(self):
        from dalga_logging import PrometheusMetrics
        metrics = PrometheusMetrics()
        metrics.inc('test_counter', 5)
        assert metrics.get_counter('test_counter') == 5

    def test_gauge_set(self):
        from dalga_logging import PrometheusMetrics
        metrics = PrometheusMetrics()
        metrics.set('test_gauge', 42.5)
        assert metrics.get_gauge('test_gauge') == 42.5

    def test_histogram_observe(self):
        from dalga_logging import PrometheusMetrics
        metrics = PrometheusMetrics()
        metrics.observe('test_histogram', 0.1)
        metrics.observe('test_histogram', 0.2)
        metrics.observe('test_histogram', 0.3)
        stats = metrics.get_histogram_stats('test_histogram')
        assert stats['count'] == 3


class TestIntegration:
    """Entegrasyon testleri"""

    def test_full_security_flow(self):
        from dalga_validation import is_safe_string, sanitize_string
        from dalga_auth import RateLimiter, BruteForceProtection
        # Input validation
        is_safe, _ = is_safe_string("test_user")
        assert is_safe == True
        # Rate limiting
        limiter = RateLimiter()
        allowed, _ = limiter.is_allowed('flow_test_ip', limit=100, window=60)
        assert allowed == True
        # Brute force
        bf = BruteForceProtection()
        blocked, _ = bf.is_blocked('flow_test_ip')
        assert blocked == False


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
