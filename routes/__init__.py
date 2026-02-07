"""
TSUNAMI v5.0 - Modular Routes
============================

Modüler route yapısı:
- auth.py    - Authentication routes
- osint.py   - OSINT intelligence routes
- sigint.py  - SIGINT scanning routes
- admin.py   - Admin panel routes
- api.py     - REST API v1 routes
- maps.py    - Map and geolocation routes
- beyin.py   - AI/BEYIN routes
"""

from flask import Blueprint

# Blueprint'leri oluştur
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')
osint_bp = Blueprint('osint', __name__, url_prefix='/api/osint')
sigint_bp = Blueprint('sigint', __name__, url_prefix='/api/sigint')
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')
api_v1_bp = Blueprint('api_v1', __name__, url_prefix='/api/v1')
api_v2_bp = Blueprint('api_v2', __name__, url_prefix='/api/v2')
maps_bp = Blueprint('maps', __name__, url_prefix='/api/maps')
beyin_bp = Blueprint('beyin', __name__, url_prefix='/api/beyin')


def register_blueprints(app):
    """Tüm blueprint'leri Flask app'e kaydet"""
    from routes import auth, osint, sigint, admin, api_v1, maps, beyin

    app.register_blueprint(auth_bp)
    app.register_blueprint(osint_bp)
    app.register_blueprint(sigint_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_v1_bp)
    app.register_blueprint(api_v2_bp)
    app.register_blueprint(maps_bp)
    app.register_blueprint(beyin_bp)

    return app


__all__ = [
    'auth_bp', 'osint_bp', 'sigint_bp', 'admin_bp',
    'api_v1_bp', 'api_v2_bp', 'maps_bp', 'beyin_bp',
    'register_blueprints'
]
