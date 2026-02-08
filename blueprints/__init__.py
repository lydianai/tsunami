"""
TSUNAMI Blueprints
==================

dalga_web.py monolith'inin modüler Blueprint yapısına geçişi.

Kullanım:
    from blueprints import register_blueprints
    register_blueprints(app)
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask


def register_blueprints(app: 'Flask'):
    """Tüm blueprint'leri Flask app'e kaydet"""
    from blueprints.api_status import api_status_bp
    app.register_blueprint(api_status_bp)

    # Gelecekte eklenecek blueprint'ler:
    # from blueprints.api_auth import api_auth_bp
    # from blueprints.api_scan import api_scan_bp
    # from blueprints.api_threat import api_threat_bp
    # from blueprints.api_network import api_network_bp
    # from blueprints.api_export import api_export_bp
    # app.register_blueprint(api_auth_bp)
    # app.register_blueprint(api_scan_bp)
    # app.register_blueprint(api_threat_bp)
    # app.register_blueprint(api_network_bp)
    # app.register_blueprint(api_export_bp)
