#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 API ROUTES
    Flask REST API endpoints for v5 core functionality
================================================================================

    Endpoints:
    - GET  /api/v5/status        - Overall system status
    - GET  /api/v5/dashboard     - Dashboard data
    - GET  /api/v5/config        - Current configuration
    - POST /api/v5/config        - Update configuration
    - GET  /api/v5/modules       - Module status
    - POST /api/v5/modules/<name>/toggle - Enable/disable module
    - GET  /api/v5/events        - Recent events
    - POST /api/v5/events        - Submit new event
    - GET  /api/v5/alerts        - Get alerts
    - POST /api/v5/alerts/<id>/status - Update alert status
    - GET  /api/v5/pipeline/stats - Pipeline statistics
    - GET  /api/v5/features      - Feature flags
    - POST /api/v5/features/<name>/toggle - Toggle feature
    - GET  /api/v5/license       - License info
    - POST /api/v5/license/activate - Activate license
    - GET  /api/v5/executive-summary - Executive summary

================================================================================
"""

import logging
from datetime import datetime
from functools import wraps
from typing import Any, Dict, Optional

try:
    from flask import Blueprint, jsonify, request, g
except ImportError:
    # Create mock Blueprint for when Flask isn't available
    class Blueprint:
        def __init__(self, name, import_name, **kwargs):
            self.name = name

        def route(self, *args, **kwargs):
            def decorator(f):
                return f
            return decorator

        def before_request(self, f):
            return f

logger = logging.getLogger("v5_api")

# Create Blueprint
v5_core_bp = Blueprint('v5_core', __name__, url_prefix='/api/v5')


def api_response(data: Any = None, message: str = "", success: bool = True, status_code: int = 200):
    """Standard API response format"""
    response = {
        "success": success,
        "message": message,
        "data": data,
        "timestamp": datetime.now().isoformat(),
        "version": "5.0.0"
    }
    return jsonify(response), status_code


def handle_errors(f):
    """Decorator to handle API errors"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"API error in {f.__name__}: {e}")
            return api_response(
                data=None,
                message=str(e),
                success=False,
                status_code=500
            )
    return decorated


@v5_core_bp.before_request
def before_request():
    """Pre-request processing"""
    g.request_start = datetime.now()


# ============================================================================
# SYSTEM STATUS ENDPOINTS
# ============================================================================

@v5_core_bp.route('/status', methods=['GET'])
@handle_errors
def get_system_status():
    """
    GET /api/v5/status
    Get overall system status including all modules
    """
    from .v5_orchestrator import get_orchestrator

    orchestrator = get_orchestrator()
    status = orchestrator.get_status()

    return api_response(
        data=status,
        message="System status retrieved"
    )


@v5_core_bp.route('/health', methods=['GET'])
@handle_errors
def get_health():
    """
    GET /api/v5/health
    Simple health check endpoint
    """
    from .v5_orchestrator import get_orchestrator

    orchestrator = get_orchestrator()
    status = orchestrator.get_status()

    healthy = status.get("modules", {}).get("errors", 0) == 0

    return api_response(
        data={
            "healthy": healthy,
            "modules_running": status.get("modules", {}).get("running", 0),
            "modules_total": status.get("modules", {}).get("total", 0)
        },
        message="Health check complete",
        status_code=200 if healthy else 503
    )


# ============================================================================
# DASHBOARD ENDPOINTS
# ============================================================================

@v5_core_bp.route('/dashboard', methods=['GET'])
@handle_errors
def get_dashboard():
    """
    GET /api/v5/dashboard
    Get unified dashboard data
    """
    from .unified_dashboard import get_dashboard

    dashboard = get_dashboard()
    data = dashboard.get_dashboard_data()

    return api_response(
        data=data,
        message="Dashboard data retrieved"
    )


@v5_core_bp.route('/dashboard/metrics', methods=['GET'])
@handle_errors
def get_dashboard_metrics():
    """
    GET /api/v5/dashboard/metrics
    Get aggregated metrics only
    """
    from .unified_dashboard import get_dashboard

    force_refresh = request.args.get('refresh', 'false').lower() == 'true'

    dashboard = get_dashboard()
    metrics = dashboard.collect_metrics(force_refresh=force_refresh)

    return api_response(
        data=metrics.to_dict(),
        message="Metrics retrieved"
    )


@v5_core_bp.route('/executive-summary', methods=['GET'])
@handle_errors
def get_executive_summary():
    """
    GET /api/v5/executive-summary
    Get executive-level security summary
    """
    from .unified_dashboard import get_dashboard

    period = request.args.get('period', 'daily')

    dashboard = get_dashboard()
    summary = dashboard.generate_executive_summary(period=period)

    return api_response(
        data=summary.to_dict(),
        message="Executive summary generated"
    )


# ============================================================================
# MODULE MANAGEMENT ENDPOINTS
# ============================================================================

@v5_core_bp.route('/modules', methods=['GET'])
@handle_errors
def get_modules():
    """
    GET /api/v5/modules
    Get status of all modules
    """
    from .v5_orchestrator import get_orchestrator

    orchestrator = get_orchestrator()
    status = orchestrator.get_status()

    return api_response(
        data=status.get("modules", {}),
        message="Module status retrieved"
    )


@v5_core_bp.route('/modules/<name>', methods=['GET'])
@handle_errors
def get_module_status(name: str):
    """
    GET /api/v5/modules/<name>
    Get status of a specific module
    """
    from .v5_orchestrator import get_orchestrator

    orchestrator = get_orchestrator()
    status = orchestrator.get_module_status(name)

    if not status:
        return api_response(
            data=None,
            message=f"Module '{name}' not found",
            success=False,
            status_code=404
        )

    return api_response(
        data=status,
        message=f"Module {name} status retrieved"
    )


@v5_core_bp.route('/modules/<name>/toggle', methods=['POST'])
@handle_errors
def toggle_module(name: str):
    """
    POST /api/v5/modules/<name>/toggle
    Enable or disable a module

    Body: {"enabled": true/false}
    """
    from .v5_orchestrator import get_orchestrator

    data = request.get_json() or {}
    enabled = data.get('enabled', True)

    orchestrator = get_orchestrator()
    success = orchestrator.toggle_module(name, enabled)

    if not success:
        return api_response(
            data=None,
            message=f"Could not toggle module '{name}'",
            success=False,
            status_code=400
        )

    return api_response(
        data={"module": name, "enabled": enabled},
        message=f"Module {name} {'enabled' if enabled else 'disabled'}"
    )


# ============================================================================
# CONFIGURATION ENDPOINTS
# ============================================================================

@v5_core_bp.route('/config', methods=['GET'])
@handle_errors
def get_config():
    """
    GET /api/v5/config
    Get current configuration (secrets masked)
    """
    from .config_manager import get_config_manager

    config_manager = get_config_manager()
    config = config_manager.get_full_config(include_secrets=False)

    return api_response(
        data=config,
        message="Configuration retrieved"
    )


@v5_core_bp.route('/config', methods=['POST'])
@handle_errors
def update_config():
    """
    POST /api/v5/config
    Update configuration settings

    Body: {"key": "path.to.setting", "value": "new_value"}
    """
    from .config_manager import get_config_manager

    data = request.get_json() or {}
    key = data.get('key')
    value = data.get('value')

    if not key:
        return api_response(
            data=None,
            message="Missing 'key' in request body",
            success=False,
            status_code=400
        )

    config_manager = get_config_manager()
    config_manager.set(key, value)

    return api_response(
        data={"key": key, "value": value},
        message=f"Configuration updated: {key}"
    )


@v5_core_bp.route('/config/module/<name>', methods=['GET'])
@handle_errors
def get_module_config(name: str):
    """
    GET /api/v5/config/module/<name>
    Get configuration for a specific module
    """
    from .config_manager import get_config_manager

    config_manager = get_config_manager()
    config = config_manager.get_module_config(name)

    if not config:
        return api_response(
            data=None,
            message=f"No configuration for module '{name}'",
            success=False,
            status_code=404
        )

    return api_response(
        data=config.to_dict(include_secrets=False),
        message=f"Module {name} configuration retrieved"
    )


@v5_core_bp.route('/config/api-key', methods=['POST'])
@handle_errors
def set_api_key():
    """
    POST /api/v5/config/api-key
    Set an API key for a module

    Body: {"module": "module_name", "key_name": "API_KEY", "value": "key_value"}
    """
    from .config_manager import get_config_manager

    data = request.get_json() or {}
    module = data.get('module')
    key_name = data.get('key_name')
    value = data.get('value')

    if not all([module, key_name, value]):
        return api_response(
            data=None,
            message="Missing required fields: module, key_name, value",
            success=False,
            status_code=400
        )

    config_manager = get_config_manager()
    config_manager.set_api_key(module, key_name, value)

    return api_response(
        data={"module": module, "key_name": key_name},
        message="API key saved"
    )


# ============================================================================
# EVENT PIPELINE ENDPOINTS
# ============================================================================

@v5_core_bp.route('/events', methods=['GET'])
@handle_errors
def get_events():
    """
    GET /api/v5/events
    Get recent events from the event bus
    """
    from .v5_orchestrator import get_orchestrator

    limit = request.args.get('limit', 100, type=int)
    event_type = request.args.get('type')

    orchestrator = get_orchestrator()
    events = orchestrator.event_bus.get_history(event_type=event_type, limit=limit)

    return api_response(
        data=events,
        message=f"Retrieved {len(events)} events"
    )


@v5_core_bp.route('/events', methods=['POST'])
@handle_errors
def submit_event():
    """
    POST /api/v5/events
    Submit a new security event for processing

    Body: {
        "event_type": "network|endpoint|application|identity|cloud|threat_intel|vulnerability|compliance|custom",
        "source": "source_name",
        "data": {...},
        "priority": "critical|high|medium|low|info"
    }
    """
    from .event_pipeline import get_pipeline, SecurityEvent, EventType, EventPriority

    data = request.get_json() or {}

    # Map event type
    event_type_str = data.get('event_type', 'custom')
    try:
        event_type = EventType(event_type_str)
    except ValueError:
        event_type = EventType.CUSTOM

    # Map priority
    priority_str = data.get('priority', 'medium')
    try:
        priority = EventPriority[priority_str.upper()]
    except KeyError:
        priority = EventPriority.MEDIUM

    event = SecurityEvent(
        event_type=event_type,
        source=data.get('source', 'api'),
        raw_data=data.get('data', {}),
        priority=priority
    )

    pipeline = get_pipeline()
    event_id = pipeline.submit_event(event)

    return api_response(
        data={"event_id": event_id},
        message="Event submitted for processing"
    )


@v5_core_bp.route('/pipeline/stats', methods=['GET'])
@handle_errors
def get_pipeline_stats():
    """
    GET /api/v5/pipeline/stats
    Get event pipeline statistics
    """
    from .event_pipeline import get_pipeline

    pipeline = get_pipeline()
    stats = pipeline.get_stats()

    return api_response(
        data=stats,
        message="Pipeline statistics retrieved"
    )


@v5_core_bp.route('/pipeline/start', methods=['POST'])
@handle_errors
def start_pipeline():
    """
    POST /api/v5/pipeline/start
    Start the event pipeline

    Body: {"workers": 4}
    """
    from .event_pipeline import get_pipeline

    data = request.get_json() or {}
    num_workers = data.get('workers', 4)

    pipeline = get_pipeline()
    pipeline.start(num_workers=num_workers)

    return api_response(
        data={"workers": num_workers},
        message="Pipeline started"
    )


@v5_core_bp.route('/pipeline/stop', methods=['POST'])
@handle_errors
def stop_pipeline():
    """
    POST /api/v5/pipeline/stop
    Stop the event pipeline
    """
    from .event_pipeline import get_pipeline

    pipeline = get_pipeline()
    pipeline.stop()

    return api_response(
        data=None,
        message="Pipeline stopped"
    )


# ============================================================================
# ALERT ENDPOINTS
# ============================================================================

@v5_core_bp.route('/alerts', methods=['GET'])
@handle_errors
def get_alerts():
    """
    GET /api/v5/alerts
    Get alerts with optional filtering

    Query params:
    - severity: critical|high|medium|low|info
    - status: new|acknowledged|in_progress|resolved|false_positive
    - source: module name
    - limit: number (default 100)
    """
    from .unified_dashboard import get_dashboard, AlertSeverity, AlertStatus

    dashboard = get_dashboard()

    # Parse filters
    severity = None
    if request.args.get('severity'):
        try:
            severity = AlertSeverity(request.args.get('severity'))
        except ValueError:
            pass

    status = None
    if request.args.get('status'):
        try:
            status = AlertStatus(request.args.get('status'))
        except ValueError:
            pass

    source = request.args.get('source')
    limit = request.args.get('limit', 100, type=int)

    alerts = dashboard.alert_consolidator.get_alerts(
        severity=severity,
        status=status,
        source=source,
        limit=limit
    )

    return api_response(
        data=[a.to_dict() for a in alerts],
        message=f"Retrieved {len(alerts)} alerts"
    )


@v5_core_bp.route('/alerts/<alert_id>/status', methods=['POST'])
@handle_errors
def update_alert_status(alert_id: str):
    """
    POST /api/v5/alerts/<id>/status
    Update alert status

    Body: {"status": "new|acknowledged|in_progress|resolved|false_positive"}
    """
    from .unified_dashboard import get_dashboard, AlertStatus

    data = request.get_json() or {}
    status_str = data.get('status')

    if not status_str:
        return api_response(
            data=None,
            message="Missing 'status' in request body",
            success=False,
            status_code=400
        )

    try:
        status = AlertStatus(status_str)
    except ValueError:
        return api_response(
            data=None,
            message=f"Invalid status: {status_str}",
            success=False,
            status_code=400
        )

    dashboard = get_dashboard()
    success = dashboard.alert_consolidator.update_alert_status(alert_id, status)

    if not success:
        return api_response(
            data=None,
            message=f"Alert '{alert_id}' not found",
            success=False,
            status_code=404
        )

    return api_response(
        data={"alert_id": alert_id, "status": status_str},
        message="Alert status updated"
    )


# ============================================================================
# FEATURE FLAG ENDPOINTS
# ============================================================================

@v5_core_bp.route('/features', methods=['GET'])
@handle_errors
def get_features():
    """
    GET /api/v5/features
    Get all feature flags
    """
    from .config_manager import get_config_manager

    config_manager = get_config_manager()
    features = config_manager.get_all_features()

    return api_response(
        data=features,
        message="Feature flags retrieved"
    )


@v5_core_bp.route('/features/<name>/toggle', methods=['POST'])
@handle_errors
def toggle_feature(name: str):
    """
    POST /api/v5/features/<name>/toggle
    Toggle a feature flag

    Body: {"enabled": true/false}
    """
    from .config_manager import get_config_manager

    data = request.get_json() or {}
    enabled = data.get('enabled', True)

    config_manager = get_config_manager()
    config_manager.set_feature_toggle(name, enabled)

    return api_response(
        data={"feature": name, "enabled": enabled},
        message=f"Feature '{name}' {'enabled' if enabled else 'disabled'}"
    )


# ============================================================================
# LICENSE ENDPOINTS
# ============================================================================

@v5_core_bp.route('/license', methods=['GET'])
@handle_errors
def get_license():
    """
    GET /api/v5/license
    Get current license information
    """
    from .config_manager import get_config_manager

    config_manager = get_config_manager()
    license_info = config_manager.license_manager.get_license()

    if not license_info:
        return api_response(
            data=None,
            message="No license found",
            success=False,
            status_code=404
        )

    return api_response(
        data=license_info.to_dict(include_key=False),
        message="License information retrieved"
    )


@v5_core_bp.route('/license/activate', methods=['POST'])
@handle_errors
def activate_license():
    """
    POST /api/v5/license/activate
    Activate a license key

    Body: {"license_key": "XXXX-XXXX-XXXX-XXXX"}
    """
    from .config_manager import get_config_manager

    data = request.get_json() or {}
    license_key = data.get('license_key')

    if not license_key:
        return api_response(
            data=None,
            message="Missing 'license_key' in request body",
            success=False,
            status_code=400
        )

    config_manager = get_config_manager()
    success = config_manager.license_manager.activate_license(license_key)

    if not success:
        return api_response(
            data=None,
            message="Invalid license key",
            success=False,
            status_code=400
        )

    license_info = config_manager.license_manager.get_license()
    return api_response(
        data=license_info.to_dict(include_key=False) if license_info else None,
        message="License activated successfully"
    )


# ============================================================================
# INITIALIZATION ENDPOINTS
# ============================================================================

@v5_core_bp.route('/initialize', methods=['POST'])
@handle_errors
def initialize_system():
    """
    POST /api/v5/initialize
    Initialize the v5 system

    Body: {"modules": ["module1", "module2"]} or {} for all modules
    """
    from .v5_orchestrator import initialize_v5

    data = request.get_json() or {}
    enabled_modules = data.get('modules')

    orchestrator = initialize_v5(enabled_modules=enabled_modules)
    status = orchestrator.get_status()

    return api_response(
        data=status,
        message="System initialized"
    )


@v5_core_bp.route('/shutdown', methods=['POST'])
@handle_errors
def shutdown_system():
    """
    POST /api/v5/shutdown
    Gracefully shutdown the v5 system
    """
    from .v5_orchestrator import get_orchestrator
    from .event_pipeline import get_pipeline

    # Stop pipeline first
    pipeline = get_pipeline()
    pipeline.stop()

    # Shutdown orchestrator
    orchestrator = get_orchestrator()
    orchestrator.shutdown()

    return api_response(
        data=None,
        message="System shutdown complete"
    )
