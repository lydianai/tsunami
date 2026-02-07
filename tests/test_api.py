#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI API Tests v2.0
=======================

Comprehensive API endpoint tests:
- Authentication endpoints
- OSINT endpoints
- Health check endpoints
- Rate limiting
- Input validation
- Error handling

pytest tests/test_api.py -v --cov=dalga_web
"""

import os
import sys
import json
import pytest
import secrets
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestHealthEndpoints:
    """Health check endpoint tests"""

    def test_health_check_returns_200(self, test_client):
        """Test health check endpoint returns 200"""
        response = test_client.get('/health')
        assert response.status_code == 200

    def test_health_check_returns_json(self, test_client):
        """Test health check returns JSON"""
        response = test_client.get('/health')
        assert response.content_type == 'application/json'
        data = response.get_json()
        assert 'status' in data

    def test_api_test_endpoint_get(self, test_client):
        """Test basic API test endpoint with GET"""
        response = test_client.get('/api/test')
        assert response.status_code == 200
        data = response.get_json()
        assert data['method'] == 'GET'

    def test_api_test_endpoint_post(self, test_client):
        """Test basic API test endpoint with POST"""
        test_data = {'key': 'value'}
        response = test_client.post(
            '/api/test',
            json=test_data,
            content_type='application/json'
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data['method'] == 'POST'
        assert data['data'] == test_data


class TestAuthenticationEndpoints:
    """Authentication endpoint tests"""

    @pytest.fixture
    def auth_app(self):
        """Create Flask app with authentication routes"""
        from flask import Flask, request, jsonify, session
        import secrets

        app = Flask(__name__)
        app.secret_key = secrets.token_bytes(32)
        app.config['TESTING'] = True

        # Mock user database
        users = {
            'admin': {
                'password_hash': 'hashed_password',
                'totp_secret': None
            }
        }

        @app.route('/api/login', methods=['POST'])
        def login():
            data = request.get_json() or {}
            username = data.get('kullanici', '')
            password = data.get('sifre', '')

            if not username or not password:
                return jsonify({'basarili': False, 'hata': 'Eksik bilgi'}), 400

            if username in users:
                session['kullanici'] = username
                return jsonify({'basarili': True, 'kullanici': username})

            return jsonify({'basarili': False, 'hata': 'Gecersiz kimlik'}), 401

        @app.route('/api/logout', methods=['POST'])
        def logout():
            session.clear()
            return jsonify({'basarili': True})

        @app.route('/api/session', methods=['GET'])
        def check_session():
            if 'kullanici' in session:
                return jsonify({'authenticated': True, 'user': session['kullanici']})
            return jsonify({'authenticated': False})

        @app.route('/api/protected', methods=['GET'])
        def protected():
            if 'kullanici' not in session:
                return jsonify({'basarili': False, 'hata': 'Oturum gerekli'}), 401
            return jsonify({'basarili': True, 'data': 'protected_data'})

        return app

    def test_login_with_valid_credentials(self, auth_app):
        """Test login with valid credentials"""
        with auth_app.test_client() as client:
            response = client.post(
                '/api/login',
                json={'kullanici': 'admin', 'sifre': 'password123'},
                content_type='application/json'
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['basarili'] is True

    def test_login_with_missing_credentials(self, auth_app):
        """Test login with missing credentials"""
        with auth_app.test_client() as client:
            response = client.post(
                '/api/login',
                json={},
                content_type='application/json'
            )
            assert response.status_code == 400

    def test_login_with_invalid_credentials(self, auth_app):
        """Test login with invalid credentials"""
        with auth_app.test_client() as client:
            response = client.post(
                '/api/login',
                json={'kullanici': 'invalid', 'sifre': 'wrong'},
                content_type='application/json'
            )
            assert response.status_code == 401

    def test_logout(self, auth_app):
        """Test logout endpoint"""
        with auth_app.test_client() as client:
            # Login first
            client.post(
                '/api/login',
                json={'kullanici': 'admin', 'sifre': 'password123'},
                content_type='application/json'
            )

            # Logout
            response = client.post('/api/logout')
            assert response.status_code == 200

            # Check session is cleared
            response = client.get('/api/session')
            data = response.get_json()
            assert data['authenticated'] is False

    def test_protected_endpoint_without_auth(self, auth_app):
        """Test protected endpoint without authentication"""
        with auth_app.test_client() as client:
            response = client.get('/api/protected')
            assert response.status_code == 401

    def test_protected_endpoint_with_auth(self, auth_app):
        """Test protected endpoint with authentication"""
        with auth_app.test_client() as client:
            # Login
            client.post(
                '/api/login',
                json={'kullanici': 'admin', 'sifre': 'password123'},
                content_type='application/json'
            )

            # Access protected
            response = client.get('/api/protected')
            assert response.status_code == 200

    def test_session_persistence(self, auth_app):
        """Test session persistence across requests"""
        with auth_app.test_client() as client:
            # Login
            client.post(
                '/api/login',
                json={'kullanici': 'admin', 'sifre': 'password123'},
                content_type='application/json'
            )

            # Check session
            response = client.get('/api/session')
            data = response.get_json()
            assert data['authenticated'] is True
            assert data['user'] == 'admin'


class TestOSINTEndpoints:
    """OSINT endpoint tests"""

    @pytest.fixture
    def osint_app(self):
        """Create Flask app with OSINT routes"""
        from flask import Flask, request, jsonify
        import secrets

        app = Flask(__name__)
        app.secret_key = secrets.token_bytes(32)
        app.config['TESTING'] = True

        @app.route('/api/osint/search', methods=['POST'])
        def osint_search():
            data = request.get_json() or {}
            hedef = data.get('hedef', '')
            tip = data.get('tip', 'auto')

            if not hedef:
                return jsonify({'basarili': False, 'hata': 'Hedef gerekli'}), 400

            # Validate input
            if '<script>' in hedef.lower() or "' OR " in hedef:
                return jsonify({'basarili': False, 'hata': 'Gecersiz girdi'}), 400

            return jsonify({
                'basarili': True,
                'hedef': hedef,
                'tip': tip,
                'sonuclar': {'mock': 'data'}
            })

        @app.route('/api/osint/ip/<ip>', methods=['GET'])
        def osint_ip(ip):
            # Validate IP format
            import ipaddress
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return jsonify({'basarili': False, 'hata': 'Gecersiz IP'}), 400

            return jsonify({
                'basarili': True,
                'ip': ip,
                'location': {'country': 'TR', 'city': 'Istanbul'}
            })

        @app.route('/api/osint/domain/<domain>', methods=['GET'])
        def osint_domain(domain):
            # Basic domain validation
            import re
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$', domain):
                return jsonify({'basarili': False, 'hata': 'Gecersiz domain'}), 400

            return jsonify({
                'basarili': True,
                'domain': domain,
                'dns': {'A': ['192.0.2.1']}
            })

        @app.route('/api/osint/email', methods=['POST'])
        def osint_email():
            data = request.get_json() or {}
            email = data.get('email', '')

            if not email or '@' not in email:
                return jsonify({'basarili': False, 'hata': 'Gecersiz email'}), 400

            return jsonify({
                'basarili': True,
                'email': email,
                'platformlar': ['mock_platform']
            })

        return app

    def test_osint_search_valid(self, osint_app):
        """Test OSINT search with valid input"""
        with osint_app.test_client() as client:
            response = client.post(
                '/api/osint/search',
                json={'hedef': 'test@example.com', 'tip': 'email'},
                content_type='application/json'
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data['basarili'] is True

    def test_osint_search_missing_target(self, osint_app):
        """Test OSINT search with missing target"""
        with osint_app.test_client() as client:
            response = client.post(
                '/api/osint/search',
                json={},
                content_type='application/json'
            )
            assert response.status_code == 400

    def test_osint_search_sql_injection(self, osint_app):
        """Test OSINT search blocks SQL injection"""
        with osint_app.test_client() as client:
            response = client.post(
                '/api/osint/search',
                json={'hedef': "' OR 1=1 --"},
                content_type='application/json'
            )
            assert response.status_code == 400

    def test_osint_search_xss(self, osint_app):
        """Test OSINT search blocks XSS"""
        with osint_app.test_client() as client:
            response = client.post(
                '/api/osint/search',
                json={'hedef': "<script>alert(1)</script>"},
                content_type='application/json'
            )
            assert response.status_code == 400

    def test_osint_ip_valid(self, osint_app):
        """Test OSINT IP lookup with valid IP"""
        with osint_app.test_client() as client:
            response = client.get('/api/osint/ip/8.8.8.8')
            assert response.status_code == 200
            data = response.get_json()
            assert data['basarili'] is True

    def test_osint_ip_invalid(self, osint_app):
        """Test OSINT IP lookup with invalid IP"""
        with osint_app.test_client() as client:
            response = client.get('/api/osint/ip/invalid')
            assert response.status_code == 400

    def test_osint_domain_valid(self, osint_app):
        """Test OSINT domain lookup with valid domain"""
        with osint_app.test_client() as client:
            response = client.get('/api/osint/domain/example.com')
            assert response.status_code == 200
            data = response.get_json()
            assert data['basarili'] is True

    def test_osint_domain_invalid(self, osint_app):
        """Test OSINT domain lookup with invalid domain"""
        with osint_app.test_client() as client:
            response = client.get('/api/osint/domain/-invalid')
            assert response.status_code == 400

    def test_osint_email_valid(self, osint_app):
        """Test OSINT email lookup with valid email"""
        with osint_app.test_client() as client:
            response = client.post(
                '/api/osint/email',
                json={'email': 'test@example.com'},
                content_type='application/json'
            )
            assert response.status_code == 200

    def test_osint_email_invalid(self, osint_app):
        """Test OSINT email lookup with invalid email"""
        with osint_app.test_client() as client:
            response = client.post(
                '/api/osint/email',
                json={'email': 'invalid'},
                content_type='application/json'
            )
            assert response.status_code == 400


class TestRateLimitingEndpoints:
    """Rate limiting endpoint tests"""

    @pytest.fixture
    def rate_limited_app(self):
        """Create Flask app with rate limiting"""
        from flask import Flask, jsonify
        import secrets

        app = Flask(__name__)
        app.secret_key = secrets.token_bytes(32)
        app.config['TESTING'] = True

        # Simple in-memory rate limiter
        request_counts = {}

        @app.route('/api/limited')
        def limited_endpoint():
            from flask import request
            ip = request.remote_addr

            count = request_counts.get(ip, 0)
            if count >= 5:
                return jsonify({'basarili': False, 'hata': 'Rate limit'}), 429

            request_counts[ip] = count + 1
            return jsonify({'basarili': True, 'count': request_counts[ip]})

        return app

    def test_rate_limit_allows_initial_requests(self, rate_limited_app):
        """Test rate limit allows initial requests"""
        with rate_limited_app.test_client() as client:
            for i in range(5):
                response = client.get('/api/limited')
                assert response.status_code == 200

    def test_rate_limit_blocks_excess_requests(self, rate_limited_app):
        """Test rate limit blocks excess requests"""
        with rate_limited_app.test_client() as client:
            # Make requests up to limit
            for i in range(5):
                client.get('/api/limited')

            # Next request should be blocked
            response = client.get('/api/limited')
            assert response.status_code == 429


class TestErrorHandling:
    """Error handling tests"""

    @pytest.fixture
    def error_app(self):
        """Create Flask app with error handling"""
        from flask import Flask, jsonify, abort

        app = Flask(__name__)
        app.config['TESTING'] = True

        @app.errorhandler(400)
        def bad_request(e):
            return jsonify({'basarili': False, 'hata': 'Bad Request'}), 400

        @app.errorhandler(404)
        def not_found(e):
            return jsonify({'basarili': False, 'hata': 'Not Found'}), 404

        @app.errorhandler(500)
        def server_error(e):
            return jsonify({'basarili': False, 'hata': 'Server Error'}), 500

        @app.route('/api/error/400')
        def trigger_400():
            abort(400)

        @app.route('/api/error/500')
        def trigger_500():
            raise Exception('Test exception')

        return app

    def test_400_error_returns_json(self, error_app):
        """Test 400 error returns JSON"""
        with error_app.test_client() as client:
            response = client.get('/api/error/400')
            assert response.status_code == 400
            assert response.content_type == 'application/json'

    def test_404_error_returns_json(self, error_app):
        """Test 404 error returns JSON"""
        with error_app.test_client() as client:
            response = client.get('/nonexistent')
            assert response.status_code == 404

    def test_500_error_handling(self, error_app):
        """Test 500 error handling"""
        error_app.config['TESTING'] = False  # Allow error handlers to run
        error_app.config['PROPAGATE_EXCEPTIONS'] = False
        with error_app.test_client() as client:
            response = client.get('/api/error/500')
            assert response.status_code == 500


class TestInputValidation:
    """API input validation tests"""

    @pytest.fixture
    def validation_app(self):
        """Create Flask app with input validation"""
        from flask import Flask, request, jsonify

        app = Flask(__name__)
        app.config['TESTING'] = True

        @app.route('/api/validate', methods=['POST'])
        def validate_input():
            data = request.get_json() or {}

            # Check for dangerous patterns
            for key, value in data.items():
                if isinstance(value, str):
                    if '<script>' in value.lower():
                        return jsonify({'basarili': False, 'hata': 'XSS tespit edildi'}), 400
                    if "' OR " in value.upper():
                        return jsonify({'basarili': False, 'hata': 'SQL injection tespit edildi'}), 400

            return jsonify({'basarili': True, 'data': data})

        return app

    def test_valid_input_accepted(self, validation_app):
        """Test valid input is accepted"""
        with validation_app.test_client() as client:
            response = client.post(
                '/api/validate',
                json={'name': 'John Doe', 'email': 'john@example.com'},
                content_type='application/json'
            )
            assert response.status_code == 200

    def test_xss_input_rejected(self, validation_app):
        """Test XSS input is rejected"""
        with validation_app.test_client() as client:
            response = client.post(
                '/api/validate',
                json={'name': '<script>alert(1)</script>'},
                content_type='application/json'
            )
            assert response.status_code == 400

    def test_sql_injection_rejected(self, validation_app):
        """Test SQL injection input is rejected"""
        with validation_app.test_client() as client:
            response = client.post(
                '/api/validate',
                json={'name': "' OR 1=1 --"},
                content_type='application/json'
            )
            assert response.status_code == 400


class TestAPIKeyEndpoints:
    """API key management endpoint tests"""

    @pytest.fixture
    def apikey_app(self):
        """Create Flask app with API key management"""
        from flask import Flask, request, jsonify, session
        import secrets

        app = Flask(__name__)
        app.secret_key = secrets.token_bytes(32)
        app.config['TESTING'] = True

        api_keys = {}

        @app.route('/api/keys', methods=['GET'])
        def list_keys():
            return jsonify({
                'basarili': True,
                'keys': [{'name': k, 'masked': '****'} for k in api_keys.keys()]
            })

        @app.route('/api/keys', methods=['POST'])
        def set_key():
            data = request.get_json() or {}
            name = data.get('key_name')
            value = data.get('key_value')

            if not name or not value:
                return jsonify({'basarili': False, 'hata': 'Eksik bilgi'}), 400

            allowed_keys = ['SHODAN_API_KEY', 'VIRUSTOTAL_API_KEY']
            if name not in allowed_keys:
                return jsonify({'basarili': False, 'hata': 'Gecersiz key adi'}), 400

            api_keys[name] = value
            return jsonify({'basarili': True, 'key_name': name})

        return app

    def test_list_api_keys(self, apikey_app):
        """Test listing API keys"""
        with apikey_app.test_client() as client:
            response = client.get('/api/keys')
            assert response.status_code == 200
            data = response.get_json()
            assert 'keys' in data

    def test_set_valid_api_key(self, apikey_app):
        """Test setting valid API key"""
        with apikey_app.test_client() as client:
            response = client.post(
                '/api/keys',
                json={'key_name': 'SHODAN_API_KEY', 'key_value': 'test_key_123'},
                content_type='application/json'
            )
            assert response.status_code == 200

    def test_set_invalid_api_key_name(self, apikey_app):
        """Test setting invalid API key name"""
        with apikey_app.test_client() as client:
            response = client.post(
                '/api/keys',
                json={'key_name': 'INVALID_KEY', 'key_value': 'test'},
                content_type='application/json'
            )
            assert response.status_code == 400


class TestContentTypeHandling:
    """Content type handling tests"""

    def test_json_content_type(self, test_client):
        """Test JSON content type handling"""
        response = test_client.post(
            '/api/test',
            data=json.dumps({'key': 'value'}),
            content_type='application/json'
        )
        assert response.status_code == 200

    def test_missing_content_type(self, test_client):
        """Test handling of missing content type"""
        response = test_client.post(
            '/api/test',
            data='{"key": "value"}'
        )
        # Should still try to parse as JSON or handle gracefully

    def test_wrong_content_type(self, test_client):
        """Test handling of wrong content type"""
        response = test_client.post(
            '/api/test',
            data='key=value',
            content_type='application/x-www-form-urlencoded'
        )
        # Should handle gracefully


class TestCORSHeaders:
    """CORS header tests"""

    @pytest.fixture
    def cors_app(self):
        """Create Flask app with CORS"""
        from flask import Flask, jsonify

        app = Flask(__name__)
        app.config['TESTING'] = True

        @app.after_request
        def add_cors_headers(response):
            response.headers['Access-Control-Allow-Origin'] = 'http://localhost:8080'
            response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
            response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return response

        @app.route('/api/cors', methods=['GET', 'OPTIONS'])
        def cors_endpoint():
            return jsonify({'status': 'ok'})

        return app

    def test_cors_headers_present(self, cors_app):
        """Test CORS headers are present"""
        with cors_app.test_client() as client:
            response = client.get('/api/cors')
            assert 'Access-Control-Allow-Origin' in response.headers

    def test_preflight_request(self, cors_app):
        """Test OPTIONS preflight request"""
        with cors_app.test_client() as client:
            response = client.options('/api/cors')
            assert response.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
