#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    MITRE ATT&CK API Routes
    Flask API endpoints for MITRE ATT&CK integration
================================================================================

    Endpoints:
    - GET  /api/v5/mitre/techniques - List all techniques
    - GET  /api/v5/mitre/techniques/<id> - Get specific technique
    - GET  /api/v5/mitre/tactics - List all tactics
    - GET  /api/v5/mitre/mitigations - List all mitigations
    - GET  /api/v5/mitre/groups - List all threat groups
    - GET  /api/v5/mitre/software - List all software/malware
    - POST /api/v5/mitre/map - Map event to techniques
    - POST /api/v5/mitre/map/cve - Map CVE to techniques
    - POST /api/v5/mitre/map/stix - Map STIX pattern to techniques
    - GET  /api/v5/mitre/coverage - Defense coverage analysis
    - GET  /api/v5/mitre/coverage/<technique_id> - Specific technique coverage
    - POST /api/v5/mitre/gaps - Analyze defense gaps
    - GET  /api/v5/mitre/navigator - Generate Navigator layer
    - POST /api/v5/mitre/navigator/detection - Create detection layer
    - POST /api/v5/mitre/navigator/coverage - Create coverage layer
    - GET  /api/v5/mitre/navigator/group/<name> - Group techniques layer
    - GET  /api/v5/mitre/search - Search techniques
    - GET  /api/v5/mitre/stats - Get statistics
    - POST /api/v5/mitre/refresh - Force data refresh

================================================================================
"""

import logging
from datetime import datetime
from typing import Optional
from functools import wraps

try:
    from flask import Blueprint, request, jsonify, send_file, current_app
except ImportError:
    # Standalone mode
    Blueprint = None
    request = None
    jsonify = None

from .attack_data import MITREAttackData, get_attack_data
from .technique_mapper import TechniqueMapper, get_technique_mapper, EventType
from .defense_analyzer import DefenseAnalyzer, get_defense_analyzer
from .attack_navigator import NavigatorGenerator, get_navigator_generator, ColorScheme

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint for Flask integration
if Blueprint:
    mitre_bp = Blueprint('mitre', __name__, url_prefix='/api/v5/mitre')
else:
    mitre_bp = None


def api_response(data=None, error=None, status=200):
    """
    Standardized API response format

    Args:
        data: Response data
        error: Error message if any
        status: HTTP status code

    Returns:
        JSON response tuple
    """
    response = {
        'success': error is None,
        'timestamp': datetime.now().isoformat(),
        'version': 'v5.0'
    }

    if error:
        response['error'] = error
    if data is not None:
        response['data'] = data

    return jsonify(response), status


def require_data_loaded(f):
    """Decorator to ensure ATT&CK data is loaded"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        attack_data = get_attack_data()
        if not attack_data.is_loaded():
            return api_response(error="ATT&CK data not loaded", status=503)
        return f(*args, **kwargs)
    return decorated_function


# ==================== TECHNIQUE ROUTES ====================

@mitre_bp.route('/techniques', methods=['GET'])
@require_data_loaded
def list_techniques():
    """
    List all ATT&CK techniques

    Query params:
    - include_subtechniques: bool (default True)
    - include_deprecated: bool (default False)
    - tactic: Filter by tactic shortname
    - platform: Filter by platform
    - limit: Max results
    - offset: Pagination offset
    """
    attack_data = get_attack_data()

    include_subs = request.args.get('include_subtechniques', 'true').lower() == 'true'
    include_deprecated = request.args.get('include_deprecated', 'false').lower() == 'true'
    tactic = request.args.get('tactic')
    platform = request.args.get('platform')
    limit = int(request.args.get('limit', 500))
    offset = int(request.args.get('offset', 0))

    # Get techniques
    if tactic:
        techniques = attack_data.get_techniques_by_tactic(tactic)
    elif platform:
        techniques = attack_data.get_techniques_by_platform(platform)
    else:
        techniques = attack_data.list_techniques(
            include_subtechniques=include_subs,
            include_deprecated=include_deprecated
        )

    # Filter subtechniques if needed
    if not include_subs:
        techniques = [t for t in techniques if not t.is_subtechnique]

    # Pagination
    total = len(techniques)
    techniques = techniques[offset:offset + limit]

    return api_response({
        'total': total,
        'limit': limit,
        'offset': offset,
        'techniques': [t.to_dict() for t in techniques]
    })


@mitre_bp.route('/techniques/<technique_id>', methods=['GET'])
@require_data_loaded
def get_technique(technique_id):
    """
    Get specific technique by ID

    Returns technique with related mitigations, groups, software
    """
    attack_data = get_attack_data()

    technique = attack_data.get_technique(technique_id.upper())
    if not technique:
        return api_response(error=f"Technique not found: {technique_id}", status=404)

    # Get related data
    mitigations = attack_data.get_mitigations_for_technique(technique_id)
    groups = attack_data.get_groups_using_technique(technique_id)
    software = attack_data.get_software_using_technique(technique_id)

    data = technique.to_dict()
    data['mitigations_detail'] = [m.to_dict() for m in mitigations]
    data['groups_detail'] = [g.to_dict() for g in groups]
    data['software_detail'] = [s.to_dict() for s in software]

    # Get subtechniques if parent
    if not technique.is_subtechnique:
        subtechs = [attack_data.get_technique(sid) for sid in technique.subtechniques]
        data['subtechniques_detail'] = [s.to_dict() for s in subtechs if s]

    return api_response(data)


# ==================== TACTIC ROUTES ====================

@mitre_bp.route('/tactics', methods=['GET'])
@require_data_loaded
def list_tactics():
    """List all ATT&CK tactics in kill chain order"""
    attack_data = get_attack_data()
    tactics = attack_data.list_tactics()

    return api_response({
        'total': len(tactics),
        'tactics': [t.to_dict() for t in tactics]
    })


# ==================== MITIGATION ROUTES ====================

@mitre_bp.route('/mitigations', methods=['GET'])
@require_data_loaded
def list_mitigations():
    """List all mitigations"""
    attack_data = get_attack_data()
    include_deprecated = request.args.get('include_deprecated', 'false').lower() == 'true'
    limit = int(request.args.get('limit', 500))
    offset = int(request.args.get('offset', 0))

    mitigations = attack_data.list_mitigations(include_deprecated=include_deprecated)
    total = len(mitigations)
    mitigations = mitigations[offset:offset + limit]

    return api_response({
        'total': total,
        'limit': limit,
        'offset': offset,
        'mitigations': [m.to_dict() for m in mitigations]
    })


@mitre_bp.route('/mitigations/<mitigation_id>', methods=['GET'])
@require_data_loaded
def get_mitigation(mitigation_id):
    """Get specific mitigation by ID"""
    attack_data = get_attack_data()

    mitigation = attack_data.get_mitigation(mitigation_id.upper())
    if not mitigation:
        return api_response(error=f"Mitigation not found: {mitigation_id}", status=404)

    return api_response(mitigation.to_dict())


# ==================== GROUP ROUTES ====================

@mitre_bp.route('/groups', methods=['GET'])
@require_data_loaded
def list_groups():
    """List all threat groups"""
    attack_data = get_attack_data()
    include_deprecated = request.args.get('include_deprecated', 'false').lower() == 'true'
    limit = int(request.args.get('limit', 500))
    offset = int(request.args.get('offset', 0))

    groups = attack_data.list_groups(include_deprecated=include_deprecated)
    total = len(groups)
    groups = groups[offset:offset + limit]

    return api_response({
        'total': total,
        'limit': limit,
        'offset': offset,
        'groups': [g.to_dict() for g in groups]
    })


@mitre_bp.route('/groups/<group_id>', methods=['GET'])
@require_data_loaded
def get_group(group_id):
    """Get specific group by ID or name"""
    attack_data = get_attack_data()

    group = attack_data.get_group(group_id)
    if not group:
        return api_response(error=f"Group not found: {group_id}", status=404)

    # Get techniques used
    techniques = [attack_data.get_technique(tid) for tid in group.techniques]
    data = group.to_dict()
    data['techniques_detail'] = [t.to_dict() for t in techniques if t]

    return api_response(data)


# ==================== SOFTWARE ROUTES ====================

@mitre_bp.route('/software', methods=['GET'])
@require_data_loaded
def list_software():
    """List all software (malware and tools)"""
    attack_data = get_attack_data()
    software_type = request.args.get('type')  # 'malware' or 'tool'
    include_deprecated = request.args.get('include_deprecated', 'false').lower() == 'true'
    limit = int(request.args.get('limit', 500))
    offset = int(request.args.get('offset', 0))

    software = attack_data.list_software(
        software_type=software_type,
        include_deprecated=include_deprecated
    )
    total = len(software)
    software = software[offset:offset + limit]

    return api_response({
        'total': total,
        'limit': limit,
        'offset': offset,
        'software': [s.to_dict() for s in software]
    })


@mitre_bp.route('/software/<software_id>', methods=['GET'])
@require_data_loaded
def get_software(software_id):
    """Get specific software by ID or name"""
    attack_data = get_attack_data()

    software = attack_data.get_software(software_id)
    if not software:
        return api_response(error=f"Software not found: {software_id}", status=404)

    return api_response(software.to_dict())


# ==================== MAPPING ROUTES ====================

@mitre_bp.route('/map', methods=['POST'])
@require_data_loaded
def map_event():
    """
    Map a security event to ATT&CK techniques

    Request body:
    {
        "event_id": "optional-id",
        "event_type": "process_creation",
        "timestamp": "ISO datetime",
        "source": "sysmon",
        "process_name": "powershell.exe",
        "command_line": "powershell -enc ...",
        "file_path": "...",
        "registry_key": "...",
        "network_port": 443,
        "network_proto": "tcp"
    }
    """
    mapper = get_technique_mapper()
    event = request.get_json()

    if not event:
        return api_response(error="No event data provided", status=400)

    try:
        mapping = mapper.map_event(event)
        return api_response(mapping.to_dict())
    except Exception as e:
        logger.error(f"[MITRE-API] Event mapping error: {e}")
        return api_response(error=str(e), status=500)


@mitre_bp.route('/map/cve', methods=['POST'])
@require_data_loaded
def map_cve():
    """
    Map CVE(s) to ATT&CK techniques

    Request body:
    {
        "cve_ids": ["CVE-2021-44228", "CVE-2021-34527"]
    }
    or
    {
        "cve_id": "CVE-2021-44228"
    }
    """
    mapper = get_technique_mapper()
    data = request.get_json()

    if not data:
        return api_response(error="No CVE data provided", status=400)

    # Handle single or multiple CVEs
    cve_ids = data.get('cve_ids', [])
    if not cve_ids and 'cve_id' in data:
        cve_ids = [data['cve_id']]

    if not cve_ids:
        return api_response(error="No CVE IDs provided", status=400)

    results = {}
    for cve_id in cve_ids:
        matches = mapper.map_cve(cve_id)
        results[cve_id] = [m.to_dict() for m in matches]

    return api_response({
        'cve_mappings': results,
        'total_techniques': sum(len(m) for m in results.values())
    })


@mitre_bp.route('/map/stix', methods=['POST'])
@require_data_loaded
def map_stix():
    """
    Map STIX pattern to ATT&CK techniques

    Request body:
    {
        "pattern": "[process:name = 'powershell.exe']"
    }
    """
    mapper = get_technique_mapper()
    data = request.get_json()

    if not data or 'pattern' not in data:
        return api_response(error="No STIX pattern provided", status=400)

    pattern = data['pattern']
    matches = mapper.map_stix_pattern(pattern)

    return api_response({
        'pattern': pattern,
        'matches': [m.to_dict() for m in matches],
        'total_techniques': len(matches)
    })


# ==================== COVERAGE ROUTES ====================

@mitre_bp.route('/coverage', methods=['GET'])
@require_data_loaded
def get_coverage_overview():
    """
    Get defense coverage overview

    Query params:
    - technique_ids: Comma-separated technique IDs (optional)
    """
    analyzer = get_defense_analyzer()
    attack_data = get_attack_data()

    technique_ids = request.args.get('technique_ids', '')
    if technique_ids:
        technique_ids = [t.strip().upper() for t in technique_ids.split(',')]
    else:
        # Default to sample techniques or all main techniques
        techniques = attack_data.list_techniques(include_subtechniques=False)[:50]
        technique_ids = [t.id for t in techniques]

    report = analyzer.generate_gap_report(technique_ids)

    return api_response(report)


@mitre_bp.route('/coverage/<technique_id>', methods=['GET'])
@require_data_loaded
def get_technique_coverage(technique_id):
    """Get defense coverage for specific technique"""
    analyzer = get_defense_analyzer()

    coverage = analyzer.analyze_coverage(technique_id.upper())

    return api_response(coverage.to_dict())


@mitre_bp.route('/gaps', methods=['POST'])
@require_data_loaded
def analyze_gaps():
    """
    Analyze defense gaps for given techniques

    Request body:
    {
        "technique_ids": ["T1059", "T1003", "T1055"]
    }
    """
    analyzer = get_defense_analyzer()
    data = request.get_json()

    if not data or 'technique_ids' not in data:
        return api_response(error="No technique_ids provided", status=400)

    technique_ids = [t.upper() for t in data['technique_ids']]
    gaps = analyzer.analyze_gaps(technique_ids)

    return api_response({
        'total_gaps': len(gaps),
        'gaps': [g.to_dict() for g in gaps]
    })


@mitre_bp.route('/recommendations', methods=['POST'])
@require_data_loaded
def get_recommendations():
    """
    Get mitigation recommendations for techniques

    Request body:
    {
        "technique_ids": ["T1059", "T1003"],
        "max_recommendations": 10
    }
    """
    analyzer = get_defense_analyzer()
    data = request.get_json()

    if not data or 'technique_ids' not in data:
        return api_response(error="No technique_ids provided", status=400)

    technique_ids = [t.upper() for t in data['technique_ids']]
    max_recs = data.get('max_recommendations', 10)

    recommendations = analyzer.recommend_mitigations(technique_ids, max_recs)

    return api_response({
        'total': len(recommendations),
        'recommendations': [r.to_dict() for r in recommendations]
    })


# ==================== NAVIGATOR ROUTES ====================

@mitre_bp.route('/navigator', methods=['GET'])
@require_data_loaded
def get_navigator_info():
    """Get Navigator generator information and capabilities"""
    generator = get_navigator_generator()

    return api_response({
        'navigator_version': '4.9.1',
        'attack_version': '15',
        'available_color_schemes': [cs.value for cs in ColorScheme],
        'statistics': generator.get_statistics(),
        'endpoints': {
            'detection_layer': 'POST /api/v5/mitre/navigator/detection',
            'coverage_layer': 'POST /api/v5/mitre/navigator/coverage',
            'group_layer': 'GET /api/v5/mitre/navigator/group/<name>',
            'software_layer': 'GET /api/v5/mitre/navigator/software/<name>',
            'trend_layer': 'GET /api/v5/mitre/navigator/trends'
        }
    })


@mitre_bp.route('/navigator/detection', methods=['POST'])
@require_data_loaded
def create_detection_layer():
    """
    Create Navigator layer from detection data

    Request body:
    {
        "detections": {"T1059": 5, "T1003": 3, "T1055": 1},
        "name": "My Detection Layer",
        "description": "Optional description",
        "color_scheme": "red",
        "show_all": true
    }
    """
    generator = get_navigator_generator()
    data = request.get_json()

    if not data or 'detections' not in data:
        return api_response(error="No detections data provided", status=400)

    detections = data['detections']
    name = data.get('name', 'Detection Layer')
    description = data.get('description', '')
    color_scheme_str = data.get('color_scheme', 'red')
    show_all = data.get('show_all', True)

    try:
        color_scheme = ColorScheme(color_scheme_str)
    except ValueError:
        color_scheme = ColorScheme.RED

    layer = generator.create_detection_layer(
        detections=detections,
        name=name,
        description=description,
        color_scheme=color_scheme,
        show_all=show_all
    )

    return api_response({
        'layer': layer.to_dict(),
        'json': layer.to_json()
    })


@mitre_bp.route('/navigator/coverage', methods=['POST'])
@require_data_loaded
def create_coverage_layer():
    """
    Create Navigator layer from coverage data

    Request body:
    {
        "coverage": {"T1059": 0.8, "T1003": 0.3, "T1055": 0.0},
        "name": "Defense Coverage",
        "description": "Optional description"
    }
    """
    generator = get_navigator_generator()
    data = request.get_json()

    if not data or 'coverage' not in data:
        return api_response(error="No coverage data provided", status=400)

    coverage = data['coverage']
    name = data.get('name', 'Coverage Layer')
    description = data.get('description', '')

    layer = generator.create_coverage_layer(
        coverage=coverage,
        name=name,
        description=description
    )

    return api_response({
        'layer': layer.to_dict(),
        'json': layer.to_json()
    })


@mitre_bp.route('/navigator/group/<group_name>', methods=['GET'])
@require_data_loaded
def create_group_layer(group_name):
    """Create Navigator layer for a threat group"""
    generator = get_navigator_generator()
    color = request.args.get('color', '#fa5252')

    layer = generator.create_group_layer(group_name, color)
    if not layer:
        return api_response(error=f"Group not found: {group_name}", status=404)

    return api_response({
        'layer': layer.to_dict(),
        'json': layer.to_json()
    })


@mitre_bp.route('/navigator/software/<software_name>', methods=['GET'])
@require_data_loaded
def create_software_layer(software_name):
    """Create Navigator layer for software/malware"""
    generator = get_navigator_generator()
    color = request.args.get('color', '#228be6')

    layer = generator.create_software_layer(software_name, color)
    if not layer:
        return api_response(error=f"Software not found: {software_name}", status=404)

    return api_response({
        'layer': layer.to_dict(),
        'json': layer.to_json()
    })


@mitre_bp.route('/navigator/trends', methods=['GET'])
@require_data_loaded
def create_trends_layer():
    """Create Navigator layer showing detection trends"""
    generator = get_navigator_generator()
    days = int(request.args.get('days', 30))
    name = request.args.get('name', f'Detection Trends ({days} days)')

    layer = generator.create_trend_layer(days=days, name=name)

    return api_response({
        'layer': layer.to_dict(),
        'json': layer.to_json()
    })


@mitre_bp.route('/navigator/compare', methods=['POST'])
@require_data_loaded
def create_comparison_layer():
    """
    Create Navigator layer comparing two detection sets

    Request body:
    {
        "layer_a": {"T1059": 5, "T1003": 3},
        "layer_b": {"T1059": 2, "T1055": 4},
        "name": "Comparison",
        "label_a": "Week 1",
        "label_b": "Week 2"
    }
    """
    generator = get_navigator_generator()
    data = request.get_json()

    if not data or 'layer_a' not in data or 'layer_b' not in data:
        return api_response(error="Missing layer_a or layer_b", status=400)

    layer = generator.create_comparison_layer(
        layer_a=data['layer_a'],
        layer_b=data['layer_b'],
        name=data.get('name', 'Comparison'),
        label_a=data.get('label_a', 'Set A'),
        label_b=data.get('label_b', 'Set B')
    )

    return api_response({
        'layer': layer.to_dict(),
        'json': layer.to_json()
    })


# ==================== SEARCH ROUTES ====================

@mitre_bp.route('/search', methods=['GET'])
@require_data_loaded
def search_techniques():
    """
    Search techniques by keyword

    Query params:
    - q: Search query
    - limit: Max results (default 20)
    """
    attack_data = get_attack_data()
    query = request.args.get('q', '')
    limit = int(request.args.get('limit', 20))

    if not query:
        return api_response(error="No search query provided", status=400)

    results = attack_data.search_techniques(query, limit=limit)

    return api_response({
        'query': query,
        'total': len(results),
        'results': [
            {
                'technique': t.to_dict(),
                'relevance': score
            }
            for t, score in results
        ]
    })


# ==================== UTILITY ROUTES ====================

@mitre_bp.route('/stats', methods=['GET'])
@require_data_loaded
def get_statistics():
    """Get overall MITRE ATT&CK module statistics"""
    attack_data = get_attack_data()
    mapper = get_technique_mapper()
    analyzer = get_defense_analyzer()
    navigator = get_navigator_generator()

    return api_response({
        'attack_data': attack_data.get_statistics(),
        'mapper': mapper.get_statistics(),
        'defense_analyzer': analyzer.get_statistics(),
        'navigator': navigator.get_statistics()
    })


@mitre_bp.route('/refresh', methods=['POST'])
def refresh_data():
    """Force refresh of ATT&CK data from MITRE"""
    attack_data = get_attack_data()

    try:
        success = attack_data.load_data(force_refresh=True)
        if success:
            return api_response({
                'message': 'Data refreshed successfully',
                'statistics': attack_data.get_statistics()
            })
        else:
            return api_response(error="Failed to refresh data", status=500)
    except Exception as e:
        logger.error(f"[MITRE-API] Refresh error: {e}")
        return api_response(error=str(e), status=500)


@mitre_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    attack_data = get_attack_data()

    return api_response({
        'status': 'healthy' if attack_data.is_loaded() else 'degraded',
        'data_loaded': attack_data.is_loaded(),
        'version': 'v5.0'
    })


# ==================== DEFENSES ROUTES ====================

@mitre_bp.route('/defenses', methods=['GET'])
@require_data_loaded
def list_defenses():
    """List all D3FEND defenses"""
    analyzer = get_defense_analyzer()
    category = request.args.get('category')

    from .defense_analyzer import DefenseCategory

    cat_filter = None
    if category:
        try:
            cat_filter = DefenseCategory(category)
        except ValueError:
            pass

    defenses = analyzer.list_defenses(category=cat_filter)

    return api_response({
        'total': len(defenses),
        'defenses': [d.to_dict() for d in defenses]
    })


@mitre_bp.route('/defenses/<defense_id>', methods=['GET'])
@require_data_loaded
def get_defense(defense_id):
    """Get specific defense by ID"""
    analyzer = get_defense_analyzer()

    defense = analyzer.get_defense(defense_id.upper())
    if not defense:
        return api_response(error=f"Defense not found: {defense_id}", status=404)

    return api_response(defense.to_dict())


# ==================== HELPER FUNCTION FOR STANDALONE USE ====================

def register_routes(app):
    """
    Register MITRE routes with a Flask app

    Args:
        app: Flask application instance
    """
    if mitre_bp:
        app.register_blueprint(mitre_bp)
        logger.info("[MITRE-API] Routes registered at /api/v5/mitre/")

        # Initialize data on first request
        @app.before_first_request
        def init_mitre_data():
            logger.info("[MITRE-API] Loading ATT&CK data...")
            attack_data = get_attack_data()
            if not attack_data.is_loaded():
                attack_data.load_data()
            logger.info("[MITRE-API] ATT&CK data ready")
    else:
        logger.warning("[MITRE-API] Flask not available, routes not registered")


def init_data():
    """Initialize ATT&CK data (call on startup)"""
    attack_data = get_attack_data()
    if not attack_data.is_loaded():
        attack_data.load_data()
    return attack_data.is_loaded()
