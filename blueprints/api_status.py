"""
TSUNAMI Blueprint - API Status Routes
======================================

/api/durum ve /api/guvenlik/durum endpoint'leri.
dalga_web.py'den ilk çıkarılan blueprint.
"""

from flask import Blueprint, jsonify, session
from datetime import datetime

api_status_bp = Blueprint('api_status', __name__)


@api_status_bp.route('/api/v2/durum')
def api_system_status():
    """Sistem durum bilgisi (v2)"""
    return jsonify({
        'status': 'operational',
        'version': '6.0.0',
        'codename': 'NEPTUNE_GHOST',
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'modules': {
            'auth': True,
            'rate_limiting': True,
            'monitoring': True,
        }
    })


@api_status_bp.route('/api/v2/health')
def api_health_check():
    """Health check endpoint (load balancer / k8s probes)"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    }), 200
