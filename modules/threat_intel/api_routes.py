#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Threat Intelligence API Routes v5.0
    Flask Blueprint for Threat Intel Integration
================================================================================

    Endpoints:
    - GET  /api/v5/threat-intel/feeds          - List active feeds
    - GET  /api/v5/threat-intel/indicators     - Get indicators with filters
    - POST /api/v5/threat-intel/check          - Check IP/domain/hash
    - POST /api/v5/threat-intel/check-batch    - Check multiple indicators
    - GET  /api/v5/threat-intel/stats          - Feed statistics
    - GET  /api/v5/threat-intel/alerts         - Get threat alerts
    - PUT  /api/v5/threat-intel/alerts/<id>    - Update alert status
    - POST /api/v5/threat-intel/refresh        - Refresh feeds
    - PUT  /api/v5/threat-intel/feeds/<name>   - Configure feed

================================================================================
"""

import logging
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import Blueprint, request, jsonify, current_app

from .stix_taxii_client import get_stix_client, ThreatFeedConfig, FeedType
from .stix_parser import STIXParser
from .threat_correlator import (
    get_correlator, ThreatCorrelator,
    ThreatSeverity, AlertStatus
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint
threat_intel_bp = Blueprint('threat_intel', __name__, url_prefix='/api/v5/threat-intel')

# Rate limiting decorator (simple in-memory)
_rate_limits = {}


def rate_limit(limit: int = 60, window: int = 60):
    """Rate limit decorator"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            client_ip = request.remote_addr
            key = f"{f.__name__}:{client_ip}"

            now = datetime.now().timestamp()
            if key not in _rate_limits:
                _rate_limits[key] = []

            # Clean old entries
            _rate_limits[key] = [t for t in _rate_limits[key] if t > now - window]

            if len(_rate_limits[key]) >= limit:
                return jsonify({
                    'success': False,
                    'error': 'Rate limit exceeded',
                    'retry_after': window
                }), 429

            _rate_limits[key].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def api_response(data: dict, status: int = 200):
    """Standard API response format"""
    response = {
        'success': status < 400,
        'timestamp': datetime.now().isoformat(),
        **data
    }
    return jsonify(response), status


def error_response(message: str, status: int = 400, details: Optional[dict] = None):
    """Standard error response"""
    response = {
        'success': False,
        'error': message,
        'timestamp': datetime.now().isoformat()
    }
    if details:
        response['details'] = details
    return jsonify(response), status


# ==================== API Endpoints ====================

@threat_intel_bp.route('/feeds', methods=['GET'])
@rate_limit(limit=60)
def list_feeds():
    """
    List all configured threat feeds

    Returns:
        JSON with feed configurations and status
    """
    try:
        client = get_stix_client()
        feed_status = client.get_feed_status()

        return api_response({
            'feeds': feed_status,
            'total_feeds': len(feed_status),
            'enabled_feeds': sum(1 for f in feed_status.values() if f['enabled'])
        })

    except Exception as e:
        logger.error(f"[API] Error listing feeds: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/feeds/<name>', methods=['PUT'])
@rate_limit(limit=30)
def configure_feed(name: str):
    """
    Configure a threat feed

    Body:
        {
            "enabled": bool,
            "api_key": str (optional),
            "update_interval": int (optional)
        }
    """
    try:
        client = get_stix_client()

        if name not in client.feeds:
            return error_response(f"Feed not found: {name}", 404)

        data = request.get_json() or {}

        # Update enabled status
        if 'enabled' in data:
            client.enable_feed(name, data['enabled'])

        # Update API key
        if 'api_key' in data:
            client.set_api_key(name, data['api_key'])

        # Update interval
        if 'update_interval' in data:
            client.feeds[name].update_interval = int(data['update_interval'])

        return api_response({
            'message': f'Feed {name} updated',
            'feed': client.get_feed_status()[name]
        })

    except Exception as e:
        logger.error(f"[API] Error configuring feed: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/indicators', methods=['GET'])
@rate_limit(limit=30)
def get_indicators():
    """
    Get threat indicators with optional filters

    Query params:
        - type: Filter by indicator type (ip, domain, url, hash, etc.)
        - source: Filter by source feed
        - limit: Max results (default 100, max 1000)
        - offset: Pagination offset
    """
    try:
        ind_type = request.args.get('type')
        source = request.args.get('source')
        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))

        client = get_stix_client()
        correlator = get_correlator()

        # Get all indicators from feeds
        all_indicators = []

        for feed_name, feed_config in client.feeds.items():
            if source and feed_name != source:
                continue

            if not feed_config.enabled:
                continue

            try:
                indicators = client.fetch_feed(feed_name)
                for ind in indicators:
                    if ind_type and ind.get('type', '').lower() != ind_type.lower():
                        continue
                    all_indicators.append(ind)
            except Exception as e:
                logger.warning(f"Error fetching {feed_name}: {e}")

        # Apply pagination
        total = len(all_indicators)
        indicators = all_indicators[offset:offset + limit]

        return api_response({
            'indicators': indicators,
            'total': total,
            'limit': limit,
            'offset': offset,
            'has_more': offset + limit < total
        })

    except Exception as e:
        logger.error(f"[API] Error getting indicators: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/check', methods=['POST'])
@rate_limit(limit=120)
def check_indicator():
    """
    Check if an indicator matches known threats

    Body:
        {
            "value": "192.168.1.1",
            "type": "ip"  (optional, auto-detected)
        }

    Returns:
        Correlation result with threat score and details
    """
    try:
        data = request.get_json()

        if not data or 'value' not in data:
            return error_response("Missing 'value' in request body")

        value = data['value'].strip()
        ind_type = data.get('type')

        if not value:
            return error_response("Empty indicator value")

        correlator = get_correlator()
        result = correlator.check_indicator(value, ind_type)

        return api_response({
            'result': result.to_dict()
        })

    except Exception as e:
        logger.error(f"[API] Error checking indicator: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/check-batch', methods=['POST'])
@rate_limit(limit=30)
def check_batch():
    """
    Check multiple indicators at once

    Body:
        {
            "indicators": [
                {"value": "192.168.1.1", "type": "ip"},
                {"value": "malware.com", "type": "domain"},
                ...
            ]
        }

    Returns:
        List of correlation results
    """
    try:
        data = request.get_json()

        if not data or 'indicators' not in data:
            return error_response("Missing 'indicators' in request body")

        indicators = data['indicators']

        if not isinstance(indicators, list):
            return error_response("'indicators' must be a list")

        if len(indicators) > 100:
            return error_response("Maximum 100 indicators per batch")

        correlator = get_correlator()
        results = correlator.check_batch(indicators)

        return api_response({
            'results': [r.to_dict() for r in results],
            'total_checked': len(results),
            'threats_found': sum(1 for r in results if r.is_threat)
        })

    except Exception as e:
        logger.error(f"[API] Error checking batch: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/stats', methods=['GET'])
@rate_limit(limit=60)
def get_statistics():
    """
    Get threat intelligence statistics

    Returns:
        Statistics about feeds, indicators, alerts
    """
    try:
        client = get_stix_client()
        correlator = get_correlator()

        client_stats = client.get_statistics()
        correlator_stats = correlator.get_statistics()

        return api_response({
            'client': client_stats,
            'correlator': correlator_stats,
            'summary': {
                'total_feeds': client_stats['total_feeds'],
                'active_feeds': client_stats['active_feeds'],
                'total_indicators': correlator_stats['index_stats']['total'],
                'total_checks': correlator_stats['total_checks'],
                'total_alerts': correlator_stats['total_alerts']
            }
        })

    except Exception as e:
        logger.error(f"[API] Error getting stats: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/alerts', methods=['GET'])
@rate_limit(limit=60)
def get_alerts():
    """
    Get threat alerts

    Query params:
        - severity: Filter by severity (critical, high, medium, low, info)
        - status: Filter by status (new, acknowledged, investigating, resolved, false_positive)
        - limit: Max results (default 100)
    """
    try:
        severity_str = request.args.get('severity')
        status_str = request.args.get('status')
        limit = min(int(request.args.get('limit', 100)), 500)

        severity = None
        status = None

        if severity_str:
            try:
                severity = ThreatSeverity(severity_str.lower())
            except ValueError:
                return error_response(f"Invalid severity: {severity_str}")

        if status_str:
            try:
                status = AlertStatus(status_str.lower())
            except ValueError:
                return error_response(f"Invalid status: {status_str}")

        correlator = get_correlator()
        alerts = correlator.get_alerts(severity=severity, status=status, limit=limit)

        return api_response({
            'alerts': [a.to_dict() for a in alerts],
            'total': len(alerts)
        })

    except Exception as e:
        logger.error(f"[API] Error getting alerts: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/alerts/<alert_id>', methods=['PUT'])
@rate_limit(limit=60)
def update_alert(alert_id: str):
    """
    Update alert status

    Body:
        {
            "status": "acknowledged|investigating|resolved|false_positive",
            "notes": "Analyst notes" (optional)
        }
    """
    try:
        data = request.get_json()

        if not data or 'status' not in data:
            return error_response("Missing 'status' in request body")

        try:
            status = AlertStatus(data['status'].lower())
        except ValueError:
            return error_response(f"Invalid status: {data['status']}")

        notes = data.get('notes', '')

        correlator = get_correlator()
        success = correlator.update_alert_status(alert_id, status, notes)

        if not success:
            return error_response(f"Alert not found: {alert_id}", 404)

        return api_response({
            'message': f'Alert {alert_id} updated',
            'status': status.value
        })

    except Exception as e:
        logger.error(f"[API] Error updating alert: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/refresh', methods=['POST'])
@rate_limit(limit=5)
def refresh_feeds():
    """
    Refresh threat feeds

    Body:
        {
            "force": true  (optional, force refresh even if cached)
        }
    """
    try:
        data = request.get_json() or {}
        force = data.get('force', False)

        correlator = get_correlator()
        result = correlator.refresh_indicators(force=force)

        if result['success']:
            return api_response({
                'message': 'Feeds refreshed successfully',
                **result
            })
        else:
            return error_response(result.get('error', 'Unknown error'), 500)

    except Exception as e:
        logger.error(f"[API] Error refreshing feeds: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/mitre/techniques', methods=['GET'])
@rate_limit(limit=60)
def get_mitre_techniques():
    """
    Get MITRE ATT&CK techniques from current threat data
    """
    try:
        from .stix_parser import MITREMapper

        correlator = get_correlator()

        # Get all techniques from parser
        parser = correlator.parser
        techniques = parser.get_mitre_techniques()

        # Get tactic mapping
        tactics = MITREMapper.TACTICS

        return api_response({
            'techniques': techniques,
            'tactics': tactics,
            'total_techniques': len(techniques)
        })

    except Exception as e:
        logger.error(f"[API] Error getting MITRE techniques: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/parse', methods=['POST'])
@rate_limit(limit=30)
def parse_stix():
    """
    Parse a STIX bundle

    Body:
        {
            "bundle": { STIX bundle JSON },
            "source": "custom" (optional)
        }
    """
    try:
        data = request.get_json()

        if not data or 'bundle' not in data:
            return error_response("Missing 'bundle' in request body")

        bundle = data['bundle']
        source = data.get('source', 'custom')

        parser = STIXParser()
        result = parser.parse_bundle(bundle, source)

        return api_response({
            'parsed': result,
            'statistics': parser.get_statistics()
        })

    except Exception as e:
        logger.error(f"[API] Error parsing STIX: {e}")
        return error_response(str(e), 500)


@threat_intel_bp.route('/extract', methods=['POST'])
@rate_limit(limit=60)
def extract_indicators():
    """
    Extract indicators from plain text

    Body:
        {
            "text": "Text containing IPs, domains, hashes, etc.",
            "check_threats": true (optional, check extracted indicators)
        }
    """
    try:
        data = request.get_json()

        if not data or 'text' not in data:
            return error_response("Missing 'text' in request body")

        text = data['text']
        check_threats = data.get('check_threats', False)

        parser = STIXParser()
        indicators = parser.extract_indicators_from_text(text, source='extracted')

        result = {
            'indicators': [ind.to_dict() for ind in indicators],
            'total_extracted': len(indicators)
        }

        # Optionally check against threat intel
        if check_threats and indicators:
            correlator = get_correlator()
            threat_results = []

            for ind in indicators[:50]:  # Limit checks
                check_result = correlator.check_indicator(ind.value, ind.type)
                if check_result.is_threat:
                    threat_results.append({
                        'indicator': ind.to_dict(),
                        'threat': check_result.to_dict()
                    })

            result['threats'] = threat_results
            result['threats_found'] = len(threat_results)

        return api_response(result)

    except Exception as e:
        logger.error(f"[API] Error extracting indicators: {e}")
        return error_response(str(e), 500)


# Health check endpoint
@threat_intel_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        client = get_stix_client()
        correlator = get_correlator()

        return api_response({
            'status': 'healthy',
            'components': {
                'stix_client': 'ok',
                'correlator': 'ok',
                'index_size': correlator.index.get_stats()['total']
            }
        })
    except Exception as e:
        return error_response(f'Unhealthy: {e}', 503)


# Error handlers for blueprint
@threat_intel_bp.errorhandler(404)
def not_found(e):
    return error_response('Endpoint not found', 404)


@threat_intel_bp.errorhandler(405)
def method_not_allowed(e):
    return error_response('Method not allowed', 405)


@threat_intel_bp.errorhandler(500)
def internal_error(e):
    return error_response('Internal server error', 500)
