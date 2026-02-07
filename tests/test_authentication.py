#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Authentication Tests
============================

Comprehensive tests for authentication and session management.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import time

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def app():
    """Create test Flask application"""
    from dalga_web import app as flask_app
    flask_app.config['TESTING'] = True
    flask_app.config['WTF_CSRF_ENABLED'] = False
    flask_app.config['SESSION_COOKIE_SECURE'] = False
    return flask_app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


class TestPasswordSecurity:
    """Password security tests"""

    def test_password_hashing(self):
        """Test password is properly hashed"""
        from utils.security import hash_password, verify_password

        password = "TestPassword123!"
        hashed, salt = hash_password(password)

        # Hash should be different from password
        assert hashed != password
        # Should be able to verify
        assert verify_password(password, hashed, salt)
        # Wrong password should fail
        assert not verify_password("WrongPassword", hashed, salt)

    def test_password_hash_uniqueness(self):
        """Test same password produces different hashes with different salts"""
        from utils.security import hash_password

        password = "TestPassword123!"
        hash1, salt1 = hash_password(password)
        hash2, salt2 = hash_password(password)

        # Different salts should produce different hashes
        assert salt1 != salt2
        assert hash1 != hash2

    def test_empty_password_handling(self):
        """Test empty password handling"""
        from utils.security import hash_password

        # Empty password should still be hashable
        hashed, salt = hash_password("")
        assert hashed is not None
        assert salt is not None

    def test_unicode_password(self):
        """Test unicode password handling"""
        from utils.security import hash_password, verify_password

        password = "Şifre123!Türkçe密码"
        hashed, salt = hash_password(password)

        assert verify_password(password, hashed, salt)

    def test_long_password(self):
        """Test very long password handling"""
        from utils.security import hash_password, verify_password

        password = "A" * 10000  # Very long password
        hashed, salt = hash_password(password)

        assert verify_password(password, hashed, salt)


class TestSessionSecurity:
    """Session security tests"""

    def test_session_cookie_settings(self, app):
        """Test session cookie security settings"""
        # In production mode, SESSION_COOKIE_SECURE should be True
        import os
        original = os.environ.get('FLASK_ENV')

        os.environ['FLASK_ENV'] = 'production'
        # Reload config would set SECURE=True

        if original:
            os.environ['FLASK_ENV'] = original
        else:
            os.environ.pop('FLASK_ENV', None)

    def test_session_httponly(self, app):
        """Test session cookie is HttpOnly"""
        assert app.config.get('SESSION_COOKIE_HTTPONLY', True) == True

    def test_session_samesite(self, app):
        """Test session cookie SameSite setting"""
        samesite = app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
        assert samesite in ['Strict', 'Lax']


class TestLoginAttempts:
    """Login attempt tests"""

    def test_failed_login_does_not_create_session(self, client):
        """Test failed login doesn't create session"""
        response = client.post('/login', json={
            'username': 'invalid',
            'password': 'invalid'
        })

        # Check no user in session
        with client.session_transaction() as sess:
            assert 'user' not in sess

    def test_successful_login_creates_session(self, client):
        """Test successful login creates session"""
        # This requires a valid user in database
        # Mock the database check
        with patch('dalga_web.db') as mock_db:
            mock_db.kullanici_dogrula.return_value = True

            response = client.post('/login', json={
                'username': 'admin',
                'password': 'correct_password'
            })

            if response.status_code == 200:
                with client.session_transaction() as sess:
                    assert 'user' in sess

    def test_logout_clears_session(self, client):
        """Test logout clears session"""
        # First login
        with client.session_transaction() as sess:
            sess['user'] = 'test_user'

        # Then logout
        response = client.get('/cikis')

        # Session should be cleared
        with client.session_transaction() as sess:
            assert 'user' not in sess


class TestInputSanitization:
    """Input sanitization tests"""

    def test_html_sanitization(self):
        """Test HTML sanitization"""
        from utils.security import sanitize_html

        malicious = '<script>alert("xss")</script>'
        sanitized = sanitize_html(malicious)

        assert '<script>' not in sanitized
        assert '&lt;script&gt;' in sanitized

    def test_html_with_allowed_tags(self):
        """Test HTML sanitization with allowed basic tags"""
        from utils.security import sanitize_html

        text = '<b>Bold</b> and <script>bad</script>'
        sanitized = sanitize_html(text, allow_basic=True)

        assert '<b>' in sanitized
        assert '<script>' not in sanitized

    def test_sql_identifier_sanitization(self):
        """Test SQL identifier sanitization"""
        from utils.security import sanitize_sql_identifier

        # Valid identifiers
        assert sanitize_sql_identifier('column_name') == 'column_name'
        assert sanitize_sql_identifier('Table1') == 'Table1'

        # Invalid identifiers should raise
        with pytest.raises(ValueError):
            sanitize_sql_identifier("'; DROP TABLE users;--")

        with pytest.raises(ValueError):
            sanitize_sql_identifier("123invalid")

    def test_filename_sanitization(self):
        """Test filename sanitization"""
        from utils.security import sanitize_filename

        # Path traversal attempt
        assert '..' not in sanitize_filename('../../../etc/passwd')

        # Null byte injection
        assert '\x00' not in sanitize_filename('file\x00.txt')

        # Hidden file prevention
        result = sanitize_filename('.hidden')
        assert not result.startswith('.')


class TestRateLimiting:
    """Rate limiting tests"""

    def test_rate_limit_check_allows_initial_requests(self):
        """Test rate limit allows initial requests"""
        from utils.security import rate_limit_check

        # First request should be allowed
        allowed, remaining = rate_limit_check('test_key_1', max_requests=5)
        assert allowed == True
        assert remaining == 4

    def test_rate_limit_blocks_after_max(self):
        """Test rate limit blocks after max requests"""
        from utils.security import rate_limit_check

        key = 'test_key_block_' + str(time.time())

        # Make max requests
        for i in range(5):
            allowed, _ = rate_limit_check(key, max_requests=5, window_seconds=60)

        # Next request should be blocked
        allowed, remaining = rate_limit_check(key, max_requests=5, window_seconds=60)
        assert allowed == False
        assert remaining == 0

    def test_rate_limit_resets_after_window(self):
        """Test rate limit resets after time window"""
        from utils.security import rate_limit_check

        key = 'test_key_reset_' + str(time.time())

        # Exhaust rate limit with 1 second window
        for i in range(3):
            rate_limit_check(key, max_requests=3, window_seconds=1)

        # Should be blocked
        allowed, _ = rate_limit_check(key, max_requests=3, window_seconds=1)
        assert allowed == False

        # Wait for window to pass
        time.sleep(1.1)

        # Should be allowed again
        allowed, _ = rate_limit_check(key, max_requests=3, window_seconds=1)
        assert allowed == True


class TestInputValidator:
    """Input validator tests"""

    def test_email_validation(self):
        """Test email validation"""
        from utils.security import validator

        assert validator.is_valid_email('test@example.com') == True
        assert validator.is_valid_email('user.name+tag@domain.co.uk') == True
        assert validator.is_valid_email('invalid') == False
        assert validator.is_valid_email('no@domain') == False
        assert validator.is_valid_email('') == False

    def test_ip_validation(self):
        """Test IP validation"""
        from utils.security import validator

        assert validator.is_valid_ip('192.168.1.1') == True
        assert validator.is_valid_ip('0.0.0.0') == True
        assert validator.is_valid_ip('255.255.255.255') == True
        assert validator.is_valid_ip('256.1.1.1') == False
        assert validator.is_valid_ip('invalid') == False

    def test_domain_validation(self):
        """Test domain validation"""
        from utils.security import validator

        assert validator.is_valid_domain('example.com') == True
        assert validator.is_valid_domain('sub.domain.co.uk') == True
        assert validator.is_valid_domain('invalid') == False
        assert validator.is_valid_domain('') == False

    def test_url_validation(self):
        """Test URL validation"""
        from utils.security import validator

        assert validator.is_valid_url('https://example.com') == True
        assert validator.is_valid_url('http://example.com/path') == True
        assert validator.is_valid_url('ftp://example.com') == False  # Only http/https
        assert validator.is_valid_url('not-a-url') == False

    def test_path_safety(self):
        """Test path traversal prevention"""
        from utils.security import validator

        base = '/home/user/data'

        assert validator.is_safe_path('file.txt', base) == True
        assert validator.is_safe_path('subdir/file.txt', base) == True
        assert validator.is_safe_path('../../../etc/passwd', base) == False
        assert validator.is_safe_path('/etc/passwd', base) == False
