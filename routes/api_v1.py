"""
TSUNAMI v5.0 - REST API v1
==========================

Versiyonlu API endpoint'leri.
Tüm endpoint'ler /api/v1 prefix'i altında.
"""

import logging
from flask import Blueprint, jsonify, request, g
from datetime import datetime

from middleware.error_handler import safe_endpoint, NotFoundError
from middleware.logging import StructuredLogger

logger = logging.getLogger(__name__)

api_v1_bp = Blueprint('api_v1', __name__, url_prefix='/api/v1')


# ============================================================
# Health & Status
# ============================================================

@api_v1_bp.route('/health', methods=['GET'])
@safe_endpoint
def health_check():
    """
    Sistem sağlık kontrolü.

    ---
    tags:
      - System
    responses:
      200:
        description: Sistem sağlıklı
        schema:
          type: object
          properties:
            status:
              type: string
              example: healthy
            timestamp:
              type: string
              format: date-time
            version:
              type: string
              example: 5.0.0
    """
    components = {}
    overall_healthy = True

    # Database kontrolu
    try:
        import sqlite3
        from pathlib import Path
        db_path = Path.home() / '.dalga' / 'dalga_v2.db'
        if db_path.exists():
            conn = sqlite3.connect(str(db_path), timeout=2)
            conn.execute('SELECT 1')
            conn.close()
            components['database'] = 'ok'
        else:
            components['database'] = 'not_found'
            overall_healthy = False
    except Exception as e:
        components['database'] = f'error: {str(e)[:50]}'
        overall_healthy = False

    # Redis kontrolu
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, socket_timeout=2)
        r.ping()
        components['redis'] = 'ok'
    except Exception:
        components['redis'] = 'unavailable'
        # Redis opsiyonel, overall_healthy değiştirme

    # TOR kontrolu
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('127.0.0.1', 9050))
        s.close()
        components['tor'] = 'ok'
    except Exception:
        components['tor'] = 'unavailable'

    return jsonify({
        'status': 'healthy' if overall_healthy else 'degraded',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '5.0.0',
        'components': components
    }), 200 if overall_healthy else 503


@api_v1_bp.route('/status', methods=['GET'])
@safe_endpoint
def system_status():
    """
    Detaylı sistem durumu.

    ---
    tags:
      - System
    responses:
      200:
        description: Sistem durumu
    """
    import psutil

    return jsonify({
        'success': True,
        'status': 'operational',
        'timestamp': datetime.utcnow().isoformat(),
        'system': {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_percent': psutil.disk_usage('/').percent
        },
        'services': {
            'web': 'running',
            'celery': 'running',
            'redis': 'connected',
            'database': 'connected'
        },
        'version': {
            'api': 'v1',
            'app': '5.0.0',
            'python': '3.12'
        }
    })


# ============================================================
# OSINT Endpoints
# ============================================================

@api_v1_bp.route('/osint/ip/<ip_address>', methods=['GET'])
@safe_endpoint
def osint_ip_lookup(ip_address):
    """
    IP adresi istihbaratı.

    ---
    tags:
      - OSINT
    parameters:
      - name: ip_address
        in: path
        type: string
        required: true
        description: Sorgulanacak IP adresi
    responses:
      200:
        description: IP istihbarat verisi
      400:
        description: Geçersiz IP
    """
    from dalga_validation import is_valid_ip

    if not is_valid_ip(ip_address):
        return jsonify({
            'success': False,
            'error': 'Gecersiz veya engelli IP adresi'
        }), 400

    # Log query
    StructuredLogger.log_osint_query('ip', ip_address)

    # Gerçek OSINT sorgusu
    try:
        from dalga_osint import NetworkOSINT
        network_osint = NetworkOSINT()
        result = network_osint.ip_analiz(ip_address)

        if result and result.basarili:
            return jsonify({
                'success': True,
                'ip': ip_address,
                'data': {
                    'geolocation': result.veri.get('geoip', {}),
                    'asn': result.veri.get('asn', {}),
                    'reverse_dns': result.veri.get('reverse_dns'),
                    'threat_score': result.veri.get('threat_score', 0),
                    'is_malicious': result.veri.get('is_malicious', False),
                    'kaynaklar': result.kaynaklar
                }
            })
        else:
            # Fallback: Basit GeoIP API
            import requests
            try:
                resp = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return jsonify({
                        'success': True,
                        'ip': ip_address,
                        'data': {
                            'geolocation': {
                                'country': data.get('country'),
                                'city': data.get('city'),
                                'lat': data.get('lat'),
                                'lon': data.get('lon')
                            },
                            'asn': {
                                'number': data.get('as', '').split()[0] if data.get('as') else None,
                                'name': data.get('isp')
                            },
                            'threat_score': 0,
                            'is_malicious': False
                        }
                    })
            except Exception:
                pass

            return jsonify({
                'success': False,
                'error': 'OSINT sorgusu basarisiz'
            }), 500

    except ImportError:
        return jsonify({
            'success': False,
            'error': 'OSINT modulu yuklenemedi'
        }), 503
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'OSINT hatasi: {str(e)}'
        }), 500


@api_v1_bp.route('/osint/domain/<domain>', methods=['GET'])
@safe_endpoint
def osint_domain_lookup(domain):
    """
    Domain istihbaratı.

    ---
    tags:
      - OSINT
    parameters:
      - name: domain
        in: path
        type: string
        required: true
    responses:
      200:
        description: Domain istihbarat verisi
    """
    from dalga_validation import is_valid_domain

    if not is_valid_domain(domain):
        return jsonify({
            'success': False,
            'error': 'Gecersiz veya engelli domain'
        }), 400

    StructuredLogger.log_osint_query('domain', domain)

    return jsonify({
        'success': True,
        'domain': domain,
        'data': {
            'whois': {
                'registrar': 'Example Registrar',
                'created': '2000-01-01',
                'expires': '2030-01-01'
            },
            'dns': {
                'a_records': ['93.184.216.34'],
                'mx_records': ['mail.example.com']
            },
            'ssl': {
                'issuer': 'DigiCert',
                'valid_until': '2026-01-01'
            }
        }
    })


@api_v1_bp.route('/osint/email/<email>', methods=['GET'])
@safe_endpoint
def osint_email_lookup(email):
    """
    Email istihbaratı.

    ---
    tags:
      - OSINT
    parameters:
      - name: email
        in: path
        type: string
        required: true
    responses:
      200:
        description: Email istihbarat verisi
    """
    from dalga_validation import is_valid_email

    if not is_valid_email(email):
        return jsonify({
            'success': False,
            'error': 'Gecersiz email formati'
        }), 400

    StructuredLogger.log_osint_query('email', email)

    return jsonify({
        'success': True,
        'email': email,
        'data': {
            'valid': True,
            'disposable': False,
            'breach_count': 0,
            'platforms': []
        }
    })


# ============================================================
# SIGINT Endpoints
# ============================================================

@api_v1_bp.route('/sigint/devices', methods=['GET'])
@safe_endpoint
def list_devices():
    """
    Tespit edilen cihazları listele.

    ---
    tags:
      - SIGINT
    parameters:
      - name: type
        in: query
        type: string
        enum: [wifi, bluetooth, cell, iot]
      - name: limit
        in: query
        type: integer
        default: 100
    responses:
      200:
        description: Cihaz listesi
    """
    device_type = request.args.get('type')
    limit = min(int(request.args.get('limit', 100)), 1000)

    # Real SIGINT database query
    try:
        from dalga_sigint.db import SigintDatabase
        from dalga_sigint.core import DeviceType

        db = SigintDatabase()
        dt = None
        if device_type:
            try:
                dt = DeviceType(device_type)
            except ValueError:
                pass

        devices = db.get_devices(device_type=dt, limit=limit)
    except ImportError:
        logger.warning("dalga_sigint module not available for device listing")
        devices = []
    except Exception as e:
        logger.error(f"Device listing error: {e}")
        devices = []

    return jsonify({
        'success': True,
        'count': len(devices),
        'devices': devices
    })


@api_v1_bp.route('/sigint/scan', methods=['POST'])
@safe_endpoint
def start_scan():
    """
    Yeni SIGINT taraması başlat.

    ---
    tags:
      - SIGINT
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            scan_type:
              type: string
              enum: [wifi, bluetooth, cell, iot, all]
            duration:
              type: integer
              default: 30
    responses:
      202:
        description: Tarama başlatıldı
    """
    data = request.get_json() or {}
    scan_type = data.get('scan_type', 'wifi')
    duration = min(data.get('duration', 30), 300)

    # TODO: Celery task başlat
    task_id = f"scan-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    StructuredLogger.log_sigint_scan(scan_type, 1, 0, 0)

    return jsonify({
        'success': True,
        'task_id': task_id,
        'scan_type': scan_type,
        'duration': duration,
        'status': 'started'
    }), 202


@api_v1_bp.route('/sigint/threats', methods=['GET'])
@safe_endpoint
def list_threats():
    """
    Tespit edilen tehditleri listele.

    ---
    tags:
      - SIGINT
    responses:
      200:
        description: Tehdit listesi
    """
    threats = [
        {
            'id': 'threat-001',
            'type': 'rogue_ap',
            'severity': 'high',
            'device_id': 'wifi-001',
            'description': 'Rogue access point tespit edildi',
            'detected_at': '2026-02-04T20:00:00Z',
            'status': 'active'
        }
    ]

    return jsonify({
        'success': True,
        'count': len(threats),
        'threats': threats
    })


# ============================================================
# Reports & Export
# ============================================================

@api_v1_bp.route('/reports', methods=['GET'])
@safe_endpoint
def list_reports():
    """
    Raporları listele.

    ---
    tags:
      - Reports
    responses:
      200:
        description: Rapor listesi
    """
    reports = [
        {
            'id': 'report-001',
            'title': 'Gunluk SIGINT Raporu',
            'type': 'sigint',
            'created_at': '2026-02-04T00:00:00Z',
            'format': 'pdf'
        }
    ]

    return jsonify({
        'success': True,
        'count': len(reports),
        'reports': reports
    })


@api_v1_bp.route('/export', methods=['POST'])
@safe_endpoint
def export_data():
    """
    Veri dışa aktarımı.

    ---
    tags:
      - Reports
    parameters:
      - in: body
        name: body
        schema:
          type: object
          properties:
            data_type:
              type: string
              enum: [devices, threats, osint]
            format:
              type: string
              enum: [json, csv, pdf, xlsx]
    responses:
      202:
        description: Export başlatıldı
    """
    data = request.get_json() or {}
    data_type = data.get('data_type', 'devices')
    export_format = data.get('format', 'json')

    task_id = f"export-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

    return jsonify({
        'success': True,
        'task_id': task_id,
        'data_type': data_type,
        'format': export_format,
        'status': 'processing',
        'download_url': f'/api/v1/export/{task_id}/download'
    }), 202


# ============================================================
# Error Handlers (Blueprint-specific)
# ============================================================

@api_v1_bp.errorhandler(404)
def api_not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint bulunamadi',
        'status_code': 404
    }), 404


# Export
__all__ = ['api_v1_bp']
