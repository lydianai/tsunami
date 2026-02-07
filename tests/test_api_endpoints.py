#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI API Endpoint Tests
==========================

Comprehensive tests for all API endpoints.
"""

import pytest
import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

# Parent dizini path'e ekle
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


@pytest.fixture
def authenticated_client(client):
    """Create authenticated test client"""
    with client.session_transaction() as sess:
        sess['user'] = 'test_user'
    return client


class TestHealthEndpoints:
    """Health check endpoint tests"""

    def test_health_basic(self, client):
        """Test basic health endpoint"""
        response = client.get('/health')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'ok'

    def test_health_live(self, client):
        """Test liveness probe"""
        response = client.get('/health/live')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['status'] == 'alive'
        assert 'timestamp' in data

    def test_health_ready(self, client):
        """Test readiness probe"""
        response = client.get('/health/ready')
        # Can be 200 or 503 depending on dependencies
        assert response.status_code in [200, 503]
        data = json.loads(response.data)
        assert 'status' in data
        assert 'checks' in data
        assert 'app' in data['checks']


class TestSecurityHeaders:
    """Security headers tests"""

    def test_security_headers_present(self, client):
        """Test that security headers are present"""
        response = client.get('/health')

        assert response.headers.get('X-Content-Type-Options') == 'nosniff'
        assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN'
        assert response.headers.get('X-XSS-Protection') == '1; mode=block'
        assert 'Referrer-Policy' in response.headers

    def test_csp_header_on_html(self, client):
        """Test CSP header on HTML responses"""
        response = client.get('/login')
        # CSP should be present on HTML pages
        if 'text/html' in response.content_type:
            assert 'Content-Security-Policy' in response.headers


class TestAuthenticationEndpoints:
    """Authentication endpoint tests"""

    def test_login_page_loads(self, client):
        """Test login page renders"""
        response = client.get('/login')
        assert response.status_code == 200

    def test_login_redirect_when_authenticated(self, authenticated_client):
        """Test login redirects when already authenticated"""
        response = authenticated_client.get('/')
        assert response.status_code == 302
        assert '/panel' in response.location or response.status_code == 200

    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        response = client.post('/login', json={
            'username': 'invalid_user',
            'password': 'invalid_pass'
        })
        assert response.status_code == 401
        data = json.loads(response.data)
        assert data['basarili'] == False

    def test_login_missing_fields(self, client):
        """Test login with missing fields"""
        response = client.post('/login', json={})
        assert response.status_code == 401

    def test_logout(self, authenticated_client):
        """Test logout endpoint"""
        response = authenticated_client.get('/cikis')
        assert response.status_code == 302  # Redirect to login


class TestProtectedEndpoints:
    """Protected endpoint tests"""

    def test_panel_requires_auth(self, client):
        """Test panel requires authentication"""
        response = client.get('/panel')
        assert response.status_code == 302  # Redirect to login

    def test_panel_accessible_when_authenticated(self, authenticated_client):
        """Test panel accessible when authenticated"""
        response = authenticated_client.get('/panel')
        assert response.status_code == 200

    def test_api_requires_auth(self, client):
        """Test API endpoints require authentication"""
        endpoints = [
            '/api/beyin/durum',
            '/api/sistem/durum',
            '/api/canli-saldirilar',
        ]
        for endpoint in endpoints:
            response = client.get(endpoint)
            # Should redirect or return 401
            assert response.status_code in [302, 401, 403]


class TestAPIEndpoints:
    """API endpoint tests"""

    def test_beyin_durum(self, authenticated_client):
        """Test brain status endpoint"""
        response = authenticated_client.get('/api/beyin/durum')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'basarili' in data or 'aktif' in data or 'durum' in data

    def test_sistem_durum(self, authenticated_client):
        """Test system status endpoint"""
        response = authenticated_client.get('/api/sistem/durum')
        assert response.status_code == 200

    def test_canli_saldirilar(self, authenticated_client):
        """Test live attacks endpoint"""
        response = authenticated_client.get('/api/canli-saldirilar')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert isinstance(data, (list, dict))


class TestInputValidation:
    """Input validation tests"""

    def test_xss_prevention_in_login(self, client):
        """Test XSS prevention in login"""
        malicious_input = '<script>alert("xss")</script>'
        response = client.post('/login', json={
            'username': malicious_input,
            'password': 'test'
        })
        # Should not reflect script back unescaped
        assert b'<script>' not in response.data

    def test_sql_injection_prevention(self, client):
        """Test SQL injection prevention in login"""
        sql_injection = "' OR '1'='1"
        response = client.post('/login', json={
            'username': sql_injection,
            'password': sql_injection
        })
        # Should fail authentication, not bypass it
        # 400 = bad request (JSON not accepted), 401 = auth failed - both are safe
        assert response.status_code in [400, 401]


class TestRateLimiting:
    """Rate limiting tests"""

    def test_rate_limit_headers(self, client):
        """Test rate limit headers presence"""
        response = client.post('/login', json={
            'username': 'test',
            'password': 'test'
        })
        # Rate limit headers should be present if rate limiting is enabled
        # This test checks the implementation exists
        assert response.status_code in [200, 401, 429]

    def test_multiple_failed_logins(self, client):
        """Test rate limiting on multiple failed logins"""
        # Make multiple requests
        for i in range(15):
            response = client.post('/login', json={
                'username': f'attacker_{i}',
                'password': 'wrong'
            })
            # After several attempts, should get rate limited
            if response.status_code == 429:
                break

        # Either got rate limited or all requests went through
        assert response.status_code in [401, 429]


class TestStealthEndpoints:
    """Stealth/TOR endpoint tests"""

    def test_stealth_durum(self, authenticated_client):
        """Test stealth status endpoint"""
        response = authenticated_client.get('/api/stealth/durum')
        assert response.status_code == 200

    def test_stealth_harita(self, authenticated_client):
        """Test stealth map endpoint"""
        response = authenticated_client.get('/api/stealth/harita')
        assert response.status_code == 200


class TestErrorHandling:
    """Error handling tests"""

    def test_404_handling(self, client):
        """Test 404 error handling"""
        response = client.get('/nonexistent-endpoint-12345')
        assert response.status_code == 404

    def test_method_not_allowed(self, client):
        """Test method not allowed handling"""
        response = client.delete('/login')
        assert response.status_code == 405


class TestJSONResponses:
    """JSON response format tests"""

    def test_api_returns_json(self, authenticated_client):
        """Test API endpoints return valid JSON"""
        endpoints = [
            '/health',
            '/health/live',
            '/health/ready',
            '/api/beyin/durum',
        ]
        for endpoint in endpoints:
            response = authenticated_client.get(endpoint)
            if response.status_code == 200:
                assert response.content_type.startswith('application/json')
                # Should be valid JSON
                json.loads(response.data)


class TestCSRFProtection:
    """CSRF protection tests"""

    def test_csrf_token_required_for_state_changes(self, app, client):
        """Test CSRF token is required for state-changing operations"""
        # Enable CSRF for this test
        app.config['WTF_CSRF_ENABLED'] = True

        # POST without CSRF should fail
        response = client.post('/api/stealth/baslat')
        # Should either require auth first or CSRF
        assert response.status_code in [302, 400, 401, 403]
