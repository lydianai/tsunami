"""
TSUNAMI - dalga_hardening.py Test Suite
Security hardening middleware tests
"""

import pytest
from flask import Flask
from unittest.mock import patch, MagicMock


@pytest.fixture
def app():
    """Test Flask app"""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'test-secret-key'
    app.config['TESTING'] = True

    @app.route('/test')
    def test_route():
        return 'OK'

    @app.route('/api/data', methods=['POST'])
    def api_data():
        return {'status': 'ok'}

    return app


class TestSecurityHeaders:
    """Güvenlik header testleri"""

    def test_import_hardening(self):
        """Modül import edilebilmeli"""
        import dalga_hardening
        assert hasattr(dalga_hardening, 'HardeningManager')

    def test_session_cookie_config(self, app):
        """Session cookie güvenlik ayarları"""
        from dalga_auth import secure_session_config
        secure_session_config(app)

        assert app.config['SESSION_COOKIE_HTTPONLY'] is True
        assert app.config['SESSION_COOKIE_SAMESITE'] == 'Lax'
        assert app.config['SESSION_REFRESH_EACH_REQUEST'] is True

    def test_session_cookie_secure_dev(self, app):
        """Development ortamında SESSION_COOKIE_SECURE=False"""
        with patch.dict('os.environ', {'FLASK_ENV': 'development'}):
            from dalga_auth import secure_session_config
            secure_session_config(app)
            assert app.config['SESSION_COOKIE_SECURE'] is False

    def test_session_cookie_secure_prod(self, app):
        """Production ortamında SESSION_COOKIE_SECURE=True"""
        with patch.dict('os.environ', {'FLASK_ENV': 'production'}):
            from dalga_auth import secure_session_config
            secure_session_config(app)
            assert app.config['SESSION_COOKIE_SECURE'] is True


class TestIPValidation:
    """IP doğrulama testleri"""

    def test_valid_ipv4(self):
        """Geçerli IPv4 adresleri"""
        import ipaddress
        valid_ips = ["192.168.1.1", "10.0.0.1", "8.8.8.8"]
        for ip in valid_ips:
            assert ipaddress.ip_address(ip)

    def test_invalid_ip(self):
        """Geçersiz IP adresleri"""
        import ipaddress
        with pytest.raises(ValueError):
            ipaddress.ip_address("999.999.999.999")

    def test_private_ip_detection(self):
        """Özel IP tespiti"""
        import ipaddress
        assert ipaddress.ip_address("192.168.1.1").is_private
        assert ipaddress.ip_address("10.0.0.1").is_private
        assert not ipaddress.ip_address("8.8.8.8").is_private
