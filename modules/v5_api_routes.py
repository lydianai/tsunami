#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 API ROUTES
    Flask Blueprint for all v5.0 module APIs
================================================================================
"""

import json
import logging
from functools import wraps
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app

logger = logging.getLogger(__name__)

# Create Blueprint
v5_api = Blueprint('v5_api', __name__, url_prefix='/api/v5')


def handle_errors(f):
    """Error handling decorator for API routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"API Error in {f.__name__}: {e}")
            return jsonify({
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }), 500
    return decorated


# =============================================================================
# THREAT INTELLIGENCE ROUTES
# =============================================================================

@v5_api.route('/threat-intel/feeds', methods=['GET'])
@handle_errors
def get_threat_feeds():
    """Get configured threat intelligence feeds"""
    from .threat_intel import get_threat_intel_client
    client = get_threat_intel_client()
    feeds = client.list_feeds() if hasattr(client, 'list_feeds') else []
    return jsonify({
        'success': True,
        'feeds': feeds,
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/threat-intel/indicators', methods=['GET'])
@handle_errors
def get_indicators():
    """Get threat indicators with optional filtering"""
    from .threat_intel import get_threat_intel_client

    feed = request.args.get('feed')
    indicator_type = request.args.get('type')
    limit = request.args.get('limit', 100, type=int)

    client = get_threat_intel_client()
    indicators = client.get_indicators(
        feed=feed,
        indicator_type=indicator_type,
        limit=limit
    ) if hasattr(client, 'get_indicators') else []

    return jsonify({
        'success': True,
        'indicators': indicators,
        'count': len(indicators),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/threat-intel/refresh', methods=['POST'])
@handle_errors
def refresh_threat_intel():
    """Refresh threat intelligence from all feeds"""
    from .threat_intel import get_threat_intel_client
    client = get_threat_intel_client()
    result = client.refresh_all() if hasattr(client, 'refresh_all') else {'status': 'not implemented'}
    return jsonify({
        'success': True,
        'result': result,
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# MITRE ATT&CK ROUTES
# =============================================================================

@v5_api.route('/mitre/techniques', methods=['GET'])
@handle_errors
def get_mitre_techniques():
    """Get MITRE ATT&CK techniques"""
    from .mitre_attack import get_attack_data

    tactic = request.args.get('tactic')
    platform = request.args.get('platform')

    attack_data = get_attack_data()

    if tactic:
        techniques = attack_data.get_techniques_by_tactic(tactic)
    elif platform:
        techniques = attack_data.get_techniques_by_platform(platform)
    else:
        techniques = attack_data.list_techniques()

    return jsonify({
        'success': True,
        'techniques': [t.to_dict() if hasattr(t, 'to_dict') else t for t in techniques[:100]],
        'count': len(techniques),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/mitre/tactics', methods=['GET'])
@handle_errors
def get_mitre_tactics():
    """Get MITRE ATT&CK tactics"""
    from .mitre_attack import get_attack_data
    attack_data = get_attack_data()
    tactics = attack_data.list_tactics()
    return jsonify({
        'success': True,
        'tactics': [t.to_dict() if hasattr(t, 'to_dict') else t for t in tactics],
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/mitre/map-event', methods=['POST'])
@handle_errors
def map_event_to_mitre():
    """Map a security event to MITRE techniques"""
    from .mitre_attack import get_technique_mapper

    event = request.get_json()
    mapper = get_technique_mapper()
    mapping = mapper.map_event(event)

    return jsonify({
        'success': True,
        'mapping': mapping.to_dict() if hasattr(mapping, 'to_dict') else mapping,
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# AI THREAT PREDICTION ROUTES
# =============================================================================

@v5_api.route('/ai/predict', methods=['POST'])
@handle_errors
def predict_threat():
    """Get AI threat prediction for network data"""
    from .ai_prediction import ThreatPredictor

    data = request.get_json()
    predictor = ThreatPredictor()

    # Try to load existing model
    predictor.load_models()

    prediction = predictor.predict(data)

    return jsonify({
        'success': True,
        'prediction': {
            'prediction_id': prediction.prediction_id,
            'threat_level': prediction.threat_level.value,
            'threat_type': prediction.threat_type,
            'confidence': prediction.confidence,
            'anomaly_score': prediction.anomaly_score,
            'explanation': prediction.explanation,
            'recommended_actions': prediction.recommended_actions
        },
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/ai/zero-day/detect', methods=['POST'])
@handle_errors
def detect_zero_day():
    """Detect potential zero-day threats"""
    from .ai_prediction import ZeroDayDetector

    data = request.get_json()
    detector = ZeroDayDetector()
    detector.load_models()

    alert = detector.detect(data)

    return jsonify({
        'success': True,
        'is_anomaly': alert is not None,
        'alert': alert.to_dict() if alert else None,
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/ai/stats', methods=['GET'])
@handle_errors
def get_ai_stats():
    """Get AI prediction system statistics"""
    from .ai_prediction import ThreatPredictor

    predictor = ThreatPredictor()
    predictor.load_models()
    stats = predictor.get_statistics()

    return jsonify({
        'success': True,
        'statistics': stats,
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# SELF-HEALING NETWORK ROUTES
# =============================================================================

@v5_api.route('/self-healing/status', methods=['GET'])
@handle_errors
def get_self_healing_status():
    """Get self-healing network status"""
    from .self_healing import NetworkMonitor, HealthChecker, get_anomaly_detector

    monitor = NetworkMonitor()
    health = HealthChecker()
    anomaly = get_anomaly_detector()

    return jsonify({
        'success': True,
        'network': {
            'interfaces': monitor.get_interfaces(),
            'connections': len(monitor.get_all_connections())
        },
        'health': health.get_full_status().to_dict() if hasattr(health.get_full_status(), 'to_dict') else {},
        'anomalies': anomaly.get_summary() if hasattr(anomaly, 'get_summary') else {},
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/self-healing/network', methods=['GET'])
@handle_errors
def get_network_info():
    """Get detailed network information"""
    from .self_healing import NetworkMonitor

    monitor = NetworkMonitor()

    return jsonify({
        'success': True,
        'interfaces': monitor.get_interfaces(),
        'bandwidth': monitor.get_bandwidth_usage(),
        'connections': {
            'total': len(monitor.get_all_connections()),
            'established': len([c for c in monitor.get_all_connections() if c.state.value == 'ESTABLISHED']),
            'listening': len([c for c in monitor.get_all_connections() if c.state.value == 'LISTEN'])
        },
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/self-healing/health', methods=['GET'])
@handle_errors
def get_system_health():
    """Get system health metrics"""
    from .self_healing import HealthChecker

    checker = HealthChecker()
    status = checker.get_full_status()

    return jsonify({
        'success': True,
        'health': status.to_dict() if hasattr(status, 'to_dict') else status,
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/self-healing/anomalies', methods=['GET'])
@handle_errors
def get_anomalies():
    """Get detected network anomalies"""
    from .self_healing import get_anomaly_detector

    hours = request.args.get('hours', 24, type=int)

    detector = get_anomaly_detector()
    anomalies = detector.get_anomaly_history(hours=hours)

    return jsonify({
        'success': True,
        'anomalies': [a.to_dict() for a in anomalies],
        'active_count': len(detector.get_active_anomalies()),
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# QUANTUM CRYPTO ROUTES
# =============================================================================

@v5_api.route('/quantum/algorithms', methods=['GET'])
@handle_errors
def get_quantum_algorithms():
    """Get available quantum-resistant algorithms"""
    from .quantum_crypto import PQCAlgorithms

    return jsonify({
        'success': True,
        'algorithms': PQCAlgorithms.list_available_algorithms(),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/quantum/generate-keypair', methods=['POST'])
@handle_errors
def generate_quantum_keypair():
    """Generate a quantum-resistant key pair"""
    from .quantum_crypto import PQCAlgorithms, SecurityLevel

    data = request.get_json() or {}
    level = data.get('security_level', 3)

    pqc = PQCAlgorithms(SecurityLevel(level))
    keypair = pqc.generate_kem_keypair()

    return jsonify({
        'success': True,
        'keypair': {
            'algorithm': keypair.algorithm,
            'security_level': keypair.security_level.value,
            'public_key_size': len(keypair.public_key),
            'public_key_hash': keypair.fingerprint()
        },
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# SOAR/XDR ROUTES
# =============================================================================

@v5_api.route('/soar/playbooks', methods=['GET'])
@handle_errors
def get_playbooks():
    """Get available SOAR playbooks"""
    from .soar_xdr import get_playbook_engine

    engine = get_playbook_engine()
    playbooks = engine.list_playbooks()

    return jsonify({
        'success': True,
        'playbooks': [p.to_dict() for p in playbooks],
        'count': len(playbooks),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/soar/playbooks/<playbook_id>/execute', methods=['POST'])
@handle_errors
def execute_playbook(playbook_id):
    """Execute a SOAR playbook"""
    from .soar_xdr import get_playbook_engine

    data = request.get_json() or {}
    variables = data.get('variables', {})
    trigger_event = data.get('trigger_event')

    engine = get_playbook_engine()
    execution_id = engine.execute(
        playbook_id=playbook_id,
        variables=variables,
        trigger_event=trigger_event
    )

    return jsonify({
        'success': True,
        'execution_id': execution_id,
        'status': 'started',
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/soar/executions/<execution_id>', methods=['GET'])
@handle_errors
def get_execution_status(execution_id):
    """Get playbook execution status"""
    from .soar_xdr import get_playbook_engine

    engine = get_playbook_engine()
    status = engine.get_execution_status(execution_id)

    return jsonify({
        'success': True,
        'execution': status,
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# AUTONOMOUS PENTEST ROUTES
# =============================================================================

@v5_api.route('/pentest/scan', methods=['POST'])
@handle_errors
def start_pentest_scan():
    """Start autonomous penetration test scan"""
    from .auto_pentest import ReconEngine

    data = request.get_json()
    target = data.get('target')
    scan_type = data.get('scan_type', 'full')

    engine = ReconEngine()
    result = engine.scan_target(target, scan_type)

    return jsonify({
        'success': True,
        'scan_id': result.scan_id if hasattr(result, 'scan_id') else 'scan-001',
        'result': result.to_dict() if hasattr(result, 'to_dict') else result,
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/pentest/vulnerabilities', methods=['GET'])
@handle_errors
def get_vulnerabilities():
    """Get discovered vulnerabilities"""
    from .auto_pentest import get_vuln_scanner

    scanner = get_vuln_scanner()
    results = scanner.get_results()

    return jsonify({
        'success': True,
        'vulnerabilities': results,
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# AGENTIC SOC ROUTES
# =============================================================================

@v5_api.route('/soc/classify', methods=['POST'])
@handle_errors
def classify_alert():
    """Classify a security alert using AI"""
    from .agentic_soc import get_classifier, Alert

    data = request.get_json()

    alert = Alert(
        id=data.get('id', 'alert-001'),
        title=data.get('title', ''),
        description=data.get('description', ''),
        source=data.get('source', 'unknown'),
        timestamp=datetime.now(),
        initial_severity=data.get('severity', 'medium'),
        source_ip=data.get('source_ip'),
        dest_ip=data.get('dest_ip'),
        dest_port=data.get('dest_port'),
        username=data.get('username'),
        hostname=data.get('hostname')
    )

    classifier = get_classifier()
    result = classifier.classify(alert)

    return jsonify({
        'success': True,
        'classification': result.to_dict(),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/soc/investigate', methods=['POST'])
@handle_errors
def investigate_alert():
    """Start automated investigation of an alert"""
    from .agentic_soc import InvestigationAgent

    data = request.get_json()

    agent = InvestigationAgent()
    result = agent.investigate(data)

    return jsonify({
        'success': True,
        'investigation': result.to_dict() if hasattr(result, 'to_dict') else result,
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# DARK WEB INTELLIGENCE ROUTES
# =============================================================================

@v5_api.route('/darkweb/status', methods=['GET'])
@handle_errors
def get_darkweb_status():
    """Get dark web monitoring status"""
    from .darkweb_intel import get_tor_client, get_paste_monitor

    tor = get_tor_client()
    paste = get_paste_monitor()

    return jsonify({
        'success': True,
        'tor': {
            'connected': tor.is_connected() if hasattr(tor, 'is_connected') else False,
            'circuit_count': tor.get_circuit_count() if hasattr(tor, 'get_circuit_count') else 0
        },
        'paste_monitor': paste.get_statistics(),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/darkweb/paste/search', methods=['POST'])
@handle_errors
def search_pastes():
    """Search paste sites for sensitive data"""
    from .darkweb_intel import get_paste_monitor

    data = request.get_json()
    query = data.get('query')

    monitor = get_paste_monitor()
    results = monitor.search_all_sites(query)

    return jsonify({
        'success': True,
        'results': [r.__dict__ for r in results[:50]],
        'count': len(results),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/darkweb/paste/monitor', methods=['POST'])
@handle_errors
def add_paste_keywords():
    """Add keywords to paste monitor"""
    from .darkweb_intel import get_paste_monitor

    data = request.get_json()
    keywords = data.get('keywords', [])

    monitor = get_paste_monitor()
    monitor.add_keywords(keywords)

    return jsonify({
        'success': True,
        'message': f'Added {len(keywords)} keywords',
        'timestamp': datetime.now().isoformat()
    })


# =============================================================================
# V5 DASHBOARD / UNIFIED ROUTES
# =============================================================================

@v5_api.route('/dashboard', methods=['GET'])
@handle_errors
def get_dashboard():
    """Get unified v5 dashboard data"""
    from .v5_core import get_dashboard

    dashboard = get_dashboard()
    data = dashboard.get_dashboard_data()

    return jsonify({
        'success': True,
        'dashboard': data,
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/dashboard/metrics', methods=['GET'])
@handle_errors
def get_dashboard_metrics():
    """Get aggregated metrics"""
    from .v5_core import get_dashboard

    dashboard = get_dashboard()
    metrics = dashboard.collect_metrics()

    return jsonify({
        'success': True,
        'metrics': metrics.to_dict(),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/dashboard/executive-summary', methods=['GET'])
@handle_errors
def get_executive_summary():
    """Get executive security summary"""
    from .v5_core import get_dashboard

    period = request.args.get('period', 'daily')

    dashboard = get_dashboard()
    summary = dashboard.generate_executive_summary(period=period)

    return jsonify({
        'success': True,
        'summary': summary.to_dict(),
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/status', methods=['GET'])
@handle_errors
def get_v5_status():
    """Get overall v5 system status"""
    from .v5_core import get_orchestrator

    orchestrator = get_orchestrator()
    status = orchestrator.get_status()

    return jsonify({
        'success': True,
        'status': status,
        'version': '5.0.0',
        'timestamp': datetime.now().isoformat()
    })


@v5_api.route('/initialize', methods=['POST'])
@handle_errors
def initialize_v5():
    """Initialize v5 modules"""
    from .v5_core import initialize_v5

    data = request.get_json() or {}
    modules = data.get('modules')  # None = all modules

    orchestrator = initialize_v5(enabled_modules=modules)
    status = orchestrator.get_status()

    return jsonify({
        'success': True,
        'status': status,
        'message': 'V5 system initialized',
        'timestamp': datetime.now().isoformat()
    })


# Health check endpoint
@v5_api.route('/health', methods=['GET'])
def health_check():
    """Simple health check"""
    return jsonify({
        'status': 'healthy',
        'version': '5.0.0',
        'timestamp': datetime.now().isoformat()
    })
