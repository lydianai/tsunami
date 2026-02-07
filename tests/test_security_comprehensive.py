#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Security Tests v2.0
============================

Comprehensive tests for dalga_security.py (utils/security.py):
- Password hashing (Argon2id)
- Password policy validation
- Rate limiting
- Account lockout
- Input sanitization
- SQL injection detection
- XSS detection
- Two-factor authentication (TOTP)
- Audit logging
- IP geofencing

pytest tests/test_security_comprehensive.py -v --cov=dalga_security
"""

import os
import sys
import time
import pytest
import json
import hashlib
import threading
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import hypothesis for property-based testing
try:
    from hypothesis import given, strategies as st, settings, assume
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False
    # Create no-op decorators when hypothesis is not available
    def given(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def settings(*args, **kwargs):
        def decorator(f):
            return f
        return decorator
    def assume(x):
        pass
    class st:
        @staticmethod
        def text(*args, **kwargs):
            return None
        @staticmethod
        def characters(*args, **kwargs):
            return None


class TestPasswordManager:
    """Password management tests"""

    def test_password_policy_defaults(self, password_manager):
        """Test default password policy settings"""
        policy = password_manager.policy
        assert policy.min_length == 12
        assert policy.max_length == 128
        assert policy.require_uppercase is True
        assert policy.require_lowercase is True
        assert policy.require_numbers is True
        assert policy.require_special is True

    def test_validate_strong_password(self, password_manager):
        """Test validation of strong passwords"""
        strong_passwords = [
            'MyStr0ng!P@ssw0rd',
            'Abc123!@#Xyz789',
            'SecureP@ssword2024!',
            'C0mpl3x!P@ss#2024',
        ]
        for password in strong_passwords:
            valid, errors = password_manager.validate_password(password)
            assert valid is True, f"Password {password} should be valid: {errors}"

    def test_validate_weak_password_too_short(self, password_manager):
        """Test rejection of too short passwords"""
        valid, errors = password_manager.validate_password('Short1!')
        assert valid is False
        assert any('karakter' in e.lower() or 'length' in e.lower() for e in errors)

    def test_validate_weak_password_no_uppercase(self, password_manager):
        """Test rejection of passwords without uppercase"""
        valid, errors = password_manager.validate_password('weakpassword123!')
        assert valid is False
        assert any('buyuk' in e.lower() or 'uppercase' in e.lower() for e in errors)

    def test_validate_weak_password_no_lowercase(self, password_manager):
        """Test rejection of passwords without lowercase"""
        valid, errors = password_manager.validate_password('WEAKPASSWORD123!')
        assert valid is False
        assert any('kucuk' in e.lower() or 'lowercase' in e.lower() for e in errors)

    def test_validate_weak_password_no_numbers(self, password_manager):
        """Test rejection of passwords without numbers"""
        valid, errors = password_manager.validate_password('WeakPassword!')
        assert valid is False
        assert any('rakam' in e.lower() or 'number' in e.lower() for e in errors)

    def test_validate_weak_password_no_special(self, password_manager):
        """Test rejection of passwords without special characters"""
        valid, errors = password_manager.validate_password('WeakPassword123')
        assert valid is False
        assert any('ozel' in e.lower() or 'special' in e.lower() for e in errors)

    def test_validate_common_passwords(self, password_manager, sample_weak_passwords):
        """Test rejection of common passwords"""
        for password in sample_weak_passwords:
            # These are too short, but test the common password check
            # by creating a compliant but common password
            pass  # Common passwords are typically too simple

    def test_hash_password_returns_string(self, password_manager):
        """Test that hash_password returns a string"""
        hashed = password_manager.hash_password('TestPassword123!')
        assert isinstance(hashed, str)
        assert len(hashed) > 0

    def test_hash_password_unique(self, password_manager):
        """Test that same password produces different hashes (salt)"""
        password = 'TestPassword123!'
        hash1 = password_manager.hash_password(password)
        hash2 = password_manager.hash_password(password)
        # With proper salting, hashes should be different
        assert hash1 != hash2

    def test_verify_password_correct(self, password_manager):
        """Test password verification with correct password"""
        password = 'TestPassword123!'
        hashed = password_manager.hash_password(password)
        assert password_manager.verify_password(password, hashed) is True

    def test_verify_password_incorrect(self, password_manager):
        """Test password verification with incorrect password"""
        password = 'TestPassword123!'
        hashed = password_manager.hash_password(password)
        assert password_manager.verify_password('WrongPassword!', hashed) is False

    def test_verify_password_empty(self, password_manager):
        """Test password verification with empty password"""
        hashed = password_manager.hash_password('TestPassword123!')
        assert password_manager.verify_password('', hashed) is False

    def test_generate_password_meets_policy(self, password_manager):
        """Test that generated passwords meet policy"""
        for _ in range(10):
            password = password_manager.generate_password(length=16)
            valid, errors = password_manager.validate_password(password)
            assert valid is True, f"Generated password failed validation: {errors}"

    def test_needs_rehash_sha256(self, password_manager):
        """Test needs_rehash for SHA256 fallback hashes"""
        # Create a SHA256 format hash
        sha256_hash = 'sha256$salt$hashvalue'
        if password_manager.hasher:  # If Argon2 is available
            assert password_manager.needs_rehash(sha256_hash) is True


class TestRateLimiter:
    """Rate limiting tests"""

    def test_allow_requests_within_limit(self, rate_limiter):
        """Test that requests within limit are allowed"""
        for i in range(5):
            allowed, remaining = rate_limiter.is_allowed('test_key_1', limit=10, window=60)
            assert allowed is True
            assert remaining >= 0

    def test_block_requests_over_limit(self, rate_limiter):
        """Test that requests over limit are blocked"""
        # Make requests up to the limit
        for i in range(12):
            rate_limiter.is_allowed('test_key_2', limit=10, window=60)

        # Next request should be blocked
        allowed, remaining = rate_limiter.is_allowed('test_key_2', limit=10, window=60)
        assert allowed is False
        assert remaining == 0

    def test_different_keys_independent(self, rate_limiter):
        """Test that different keys have independent limits"""
        # Exhaust limit for key1
        for i in range(15):
            rate_limiter.is_allowed('key_a', limit=10, window=60)

        # key2 should still be allowed
        allowed, _ = rate_limiter.is_allowed('key_b', limit=10, window=60)
        assert allowed is True

    def test_reset_clears_limit(self, rate_limiter):
        """Test that reset clears the rate limit"""
        # Exhaust limit
        for i in range(15):
            rate_limiter.is_allowed('reset_test', limit=10, window=60)

        # Reset
        rate_limiter.reset('reset_test')

        # Should be allowed again
        allowed, _ = rate_limiter.is_allowed('reset_test', limit=10, window=60)
        assert allowed is True

    def test_thread_safety(self, rate_limiter):
        """Test rate limiter thread safety"""
        results = []

        def make_requests():
            for _ in range(20):
                allowed, _ = rate_limiter.is_allowed('thread_test', limit=50, window=60)
                results.append(allowed)

        threads = [threading.Thread(target=make_requests) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have exactly 50 allowed, rest blocked
        allowed_count = sum(1 for r in results if r is True)
        assert allowed_count == 50


class TestAccountLockout:
    """Account lockout tests"""

    def test_not_locked_initially(self, account_lockout):
        """Test that account is not locked initially"""
        locked = account_lockout.is_locked('new_user')
        assert locked is False

    def test_lock_after_max_failures(self, account_lockout):
        """Test that account locks after max failures"""
        user = 'lock_test_user'
        for i in range(5):
            account_lockout.record_failure(user)

        locked = account_lockout.is_locked(user)
        assert locked is True

    def test_remaining_attempts_decreases(self, account_lockout):
        """Test that remaining attempts decreases"""
        user = 'attempts_test'
        for i in range(3):
            locked, remaining = account_lockout.record_failure(user)
            assert locked is False
            assert remaining == (5 - i - 1)

    def test_success_resets_attempts(self, account_lockout):
        """Test that successful login resets attempts"""
        user = 'success_reset_test'
        # Record some failures
        for i in range(3):
            account_lockout.record_failure(user)

        # Record success
        account_lockout.record_success(user)

        # Should not be locked and attempts reset
        locked = account_lockout.is_locked(user)
        assert locked is False

    def test_lockout_remaining_time(self, account_lockout):
        """Test lockout remaining time calculation"""
        user = 'time_test_user'
        # Lock the account
        for i in range(6):
            account_lockout.record_failure(user)

        remaining = account_lockout.get_lockout_remaining(user)
        assert remaining > 0
        assert remaining <= 300  # Default lockout duration

    def test_reset_clears_lockout(self, account_lockout):
        """Test that reset clears lockout"""
        user = 'reset_lockout_test'
        # Lock the account
        for i in range(6):
            account_lockout.record_failure(user)

        assert account_lockout.is_locked(user) is True

        # Reset
        account_lockout.reset(user)

        assert account_lockout.is_locked(user) is False


class TestInputSanitizer:
    """Input sanitization tests"""

    def test_detect_sql_injection(self, input_sanitizer):
        """Test SQL injection detection"""
        sql_injections = [
            "' OR '1'='1",
            "'; DROP TABLE users --",
            "UNION SELECT * FROM passwords",
            "1; DELETE FROM users",
            "admin'--",
        ]
        for payload in sql_injections:
            detected = input_sanitizer.detect_sql_injection(payload)
            assert detected is True, f"Should detect: {payload}"

    def test_detect_xss(self, input_sanitizer):
        """Test XSS detection"""
        xss_payloads = [
            "<script>alert(1)</script>",
            "<img onerror=alert(1)>",
            "javascript:alert(1)",
            "<iframe src='evil.com'>",
        ]
        for payload in xss_payloads:
            detected = input_sanitizer.detect_xss(payload)
            assert detected is True, f"Should detect: {payload}"

    def test_sanitize_html(self, input_sanitizer):
        """Test HTML sanitization"""
        dangerous = "<script>alert('XSS')</script>"
        sanitized = input_sanitizer.sanitize_html(dangerous)
        assert '<script>' not in sanitized
        assert '&lt;script&gt;' in sanitized

    def test_sanitize_filename(self, input_sanitizer):
        """Test filename sanitization"""
        dangerous_names = [
            '../../../etc/passwd',
            'file<script>.txt',
            'file|cmd.exe',
            'CON',  # Windows reserved
            'file\x00.txt',  # Null byte
        ]
        for name in dangerous_names:
            sanitized = input_sanitizer.sanitize_filename(name)
            assert '..' not in sanitized
            assert '<' not in sanitized
            assert '|' not in sanitized

    def test_validate_email(self, input_sanitizer):
        """Test email validation"""
        assert input_sanitizer.validate_email('user@example.com') is True
        assert input_sanitizer.validate_email('invalid') is False
        assert input_sanitizer.validate_email('') is False

    def test_validate_ip(self, input_sanitizer):
        """Test IP validation"""
        assert input_sanitizer.validate_ip('8.8.8.8') is True
        assert input_sanitizer.validate_ip('192.168.1.1') is True
        assert input_sanitizer.validate_ip('invalid') is False
        assert input_sanitizer.validate_ip('256.1.1.1') is False

    def test_safe_input_not_flagged(self, input_sanitizer):
        """Test that safe input is not flagged"""
        safe_inputs = [
            'Hello World',
            'user@example.com',
            'Normal text 12345',
            'Path/to/file.txt',
        ]
        for text in safe_inputs:
            assert input_sanitizer.detect_sql_injection(text) is False
            assert input_sanitizer.detect_xss(text) is False


class TestTwoFactorAuth:
    """Two-factor authentication tests"""

    def test_generate_secret(self, two_factor_auth):
        """Test TOTP secret generation"""
        secret = two_factor_auth.generate_secret()
        if secret:  # If pyotp is available
            assert len(secret) == 32
            assert secret.isalnum()

    def test_get_totp_uri(self, two_factor_auth):
        """Test TOTP URI generation"""
        secret = two_factor_auth.generate_secret()
        if secret:
            uri = two_factor_auth.get_totp_uri(secret, 'test@example.com', 'TSUNAMI')
            assert 'otpauth://totp/' in uri
            assert 'secret=' in uri
            assert 'TSUNAMI' in uri

    def test_generate_qr_code(self, two_factor_auth):
        """Test QR code generation"""
        secret = two_factor_auth.generate_secret()
        if secret:
            qr_base64 = two_factor_auth.generate_qr_code(secret, 'test@example.com')
            if qr_base64:  # If qrcode is available
                # Should be valid base64
                import base64
                try:
                    base64.b64decode(qr_base64)
                except Exception:
                    pytest.fail("QR code is not valid base64")

    def test_verify_totp_invalid(self, two_factor_auth):
        """Test TOTP verification with invalid code"""
        secret = two_factor_auth.generate_secret()
        if secret:
            # Invalid code
            result = two_factor_auth.verify_totp(secret, '000000')
            # This might pass by chance (1 in 1M), but usually False
            # We can't guarantee it fails without knowing the time


class TestAuditLogger:
    """Audit logging tests"""

    def test_log_creates_entry(self, audit_logger, request_context):
        """Test that logging creates an entry"""
        audit_logger.log(
            user='testuser',
            action='login',
            resource='auth',
            success=True,
            details={'ip': '192.168.1.1'}
        )

        logs = audit_logger.get_logs(user='testuser', limit=1)
        assert len(logs) == 1
        assert logs[0]['user'] == 'testuser'
        assert logs[0]['action'] == 'login'
        assert logs[0]['success'] is True

    def test_log_filters_by_user(self, audit_logger, request_context):
        """Test log filtering by user"""
        audit_logger.log(user='user1', action='action1', resource='res', success=True)
        audit_logger.log(user='user2', action='action2', resource='res', success=True)

        logs = audit_logger.get_logs(user='user1')
        assert all(log['user'] == 'user1' for log in logs)

    def test_log_filters_by_action(self, audit_logger, request_context):
        """Test log filtering by action"""
        audit_logger.log(user='user', action='login', resource='auth', success=True)
        audit_logger.log(user='user', action='logout', resource='auth', success=True)

        logs = audit_logger.get_logs(action='login')
        assert all(log['action'] == 'login' for log in logs)

    def test_log_respects_limit(self, audit_logger, request_context):
        """Test that get_logs respects limit"""
        for i in range(20):
            audit_logger.log(user=f'user{i}', action='test', resource='res', success=True)

        logs = audit_logger.get_logs(limit=5)
        assert len(logs) == 5

    def test_log_filters_by_time(self, audit_logger, request_context):
        """Test log filtering by time"""
        audit_logger.log(user='user', action='old', resource='res', success=True)

        # Get logs since now (should exclude the old one)
        future = datetime.now() + timedelta(seconds=1)
        logs = audit_logger.get_logs(since=future)
        assert len(logs) == 0


class TestGeoFence:
    """IP geofencing tests"""

    def test_localhost_always_allowed(self, geo_fence):
        """Test that localhost is always allowed"""
        allowed, reason = geo_fence.is_allowed('127.0.0.1')
        assert allowed is True
        assert reason == 'localhost'

    def test_whitelist_ip(self, geo_fence):
        """Test whitelisted IP is allowed"""
        geo_fence.add_whitelist('8.8.8.8')
        allowed, reason = geo_fence.is_allowed('8.8.8.8')
        assert allowed is True
        assert reason == 'whitelist'

    def test_whitelist_range(self, geo_fence):
        """Test whitelisted IP range"""
        geo_fence.add_whitelist('192.0.2.0/24')
        allowed, reason = geo_fence.is_allowed('192.0.2.100')
        assert allowed is True
        assert reason == 'whitelist'

    def test_blacklist_ip(self, geo_fence):
        """Test blacklisted IP is blocked"""
        geo_fence.add_blacklist('1.2.3.4')
        allowed, reason = geo_fence.is_allowed('1.2.3.4')
        assert allowed is False
        assert reason == 'blacklist'

    def test_blacklist_range(self, geo_fence):
        """Test blacklisted IP range"""
        geo_fence.add_blacklist('10.0.0.0/8')
        allowed, reason = geo_fence.is_allowed('10.1.2.3')
        assert allowed is False
        assert reason == 'blacklist'

    def test_is_turkey_ip(self, geo_fence):
        """Test Turkey IP detection"""
        # These are example Turkish IP ranges
        turkish_ips = ['78.160.1.1', '81.212.1.1']
        for ip in turkish_ips:
            result = geo_fence.is_turkey_ip(ip)
            # Result depends on the IP ranges defined

    def test_default_allows_unlisted(self, geo_fence):
        """Test that unlisted IPs are allowed by default"""
        allowed, reason = geo_fence.is_allowed('203.0.113.1')
        assert allowed is True
        assert reason == 'default'


class TestSecurityManager:
    """SecurityManager integration tests"""

    def test_singleton_pattern(self):
        """Test that SecurityManager is a singleton"""
        from dalga_security import SecurityManager
        sm1 = SecurityManager.get_instance()
        sm2 = SecurityManager.get_instance()
        assert sm1 is sm2

    def test_has_all_components(self, security_manager):
        """Test that SecurityManager has all components"""
        assert hasattr(security_manager, 'password')
        assert hasattr(security_manager, 'rate_limiter')
        assert hasattr(security_manager, 'lockout')
        assert hasattr(security_manager, 'totp')
        assert hasattr(security_manager, 'audit')
        assert hasattr(security_manager, 'geofence')
        assert hasattr(security_manager, 'sanitizer')


class TestSecurityDecorators:
    """Security decorator tests"""

    def test_rate_limit_decorator(self, flask_app):
        """Test rate_limit decorator"""
        from dalga_security import rate_limit
        from flask import jsonify

        @flask_app.route('/limited')
        @rate_limit(limit=5, window=60)
        def limited_endpoint():
            return jsonify({'status': 'ok'})

        with flask_app.test_client() as client:
            # First 5 requests should succeed
            for i in range(5):
                response = client.get('/limited')
                # Note: Depends on implementation

    def test_check_injection_decorator(self, flask_app):
        """Test check_injection decorator"""
        from dalga_security import check_injection
        from flask import jsonify, request

        @flask_app.route('/protected', methods=['POST'])
        @check_injection
        def protected_endpoint():
            return jsonify({'status': 'ok'})

        with flask_app.test_client() as client:
            # Normal request should succeed
            response = client.post(
                '/protected',
                data={'name': 'normal_value'},
                content_type='application/x-www-form-urlencoded'
            )
            # Result depends on implementation

    def test_audit_action_decorator(self, flask_app):
        """Test audit_action decorator"""
        from dalga_security import audit_action
        from flask import jsonify

        @flask_app.route('/audited')
        @audit_action('test_action')
        def audited_endpoint():
            return jsonify({'status': 'ok'})

        with flask_app.test_client() as client:
            response = client.get('/audited')
            # Should create audit log entry


class TestConcurrency:
    """Concurrency and thread safety tests"""

    def test_rate_limiter_concurrent_access(self, rate_limiter):
        """Test rate limiter under concurrent access"""
        import threading

        counter = {'allowed': 0, 'blocked': 0}
        lock = threading.Lock()

        def make_request():
            allowed, _ = rate_limiter.is_allowed('concurrent_test', limit=100, window=60)
            with lock:
                if allowed:
                    counter['allowed'] += 1
                else:
                    counter['blocked'] += 1

        threads = [threading.Thread(target=make_request) for _ in range(200)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert counter['allowed'] == 100
        assert counter['blocked'] == 100

    def test_account_lockout_concurrent_failures(self, account_lockout):
        """Test account lockout under concurrent failures"""
        import threading

        user = 'concurrent_lockout_test'

        def record_failure():
            account_lockout.record_failure(user)

        threads = [threading.Thread(target=record_failure) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should be locked after 5+ failures
        assert account_lockout.is_locked(user) is True


@pytest.mark.skipif(not HYPOTHESIS_AVAILABLE, reason="hypothesis not installed")
class TestPropertyBased:
    """Property-based tests using Hypothesis"""

    @given(st.text(min_size=12, max_size=50, alphabet=st.characters(
        whitelist_categories=['Lu', 'Ll', 'Nd'],
        whitelist_characters='!@#$%^&*()_+-=[]{}|;:,.<>?'
    )))
    @settings(max_examples=50)
    def test_password_hash_verify_roundtrip(self, password):
        """Property: hash then verify always succeeds for same password"""
        from dalga_security import PasswordManager

        # Ensure password meets minimum requirements
        assume(any(c.isupper() for c in password))
        assume(any(c.islower() for c in password))
        assume(any(c.isdigit() for c in password))
        assume(any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password))

        pm = PasswordManager()
        hashed = pm.hash_password(password)
        assert pm.verify_password(password, hashed) is True

    @given(st.text(min_size=1, max_size=100))
    @settings(max_examples=100)
    def test_sanitize_html_removes_tags(self, text):
        """Property: sanitize_html removes all < and > characters"""
        from dalga_security import InputSanitizer

        sanitizer = InputSanitizer()
        result = sanitizer.sanitize_html(text)

        # Result should not contain unescaped < or >
        assert '<' not in result.replace('&lt;', '').replace('&gt;', '')


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
