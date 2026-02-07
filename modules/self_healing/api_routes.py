#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SELF-HEALING API v5.0
    Flask REST API Endpoints for Self-Healing Module
================================================================================

    Endpoints:
    - GET  /api/v5/healing/status      - System health status
    - GET  /api/v5/healing/anomalies   - Detected anomalies
    - POST /api/v5/healing/remediate   - Trigger remediation
    - GET  /api/v5/healing/policies    - List policies
    - POST /api/v5/healing/policies    - Create policy
    - PUT  /api/v5/healing/policies/<id> - Update policy
    - DELETE /api/v5/healing/policies/<id> - Delete policy
    - GET  /api/v5/healing/history     - Remediation history

================================================================================
"""

import logging
from datetime import datetime
from functools import wraps
from typing import Callable

from flask import Blueprint, request, jsonify, g

# Import self-healing components
from .network_monitor import NetworkMonitor, get_network_monitor
from .health_checker import HealthChecker, get_health_checker, HealthStatus
from .anomaly_detector import AnomalyDetector, get_anomaly_detector, AnomalyType, Severity
from .auto_remediation import AutoRemediation, get_auto_remediation, ActionType
from .policy_engine import (
    PolicyEngine, get_policy_engine, HealingPolicy, PolicyCondition,
    PolicyAction, ActionTrigger, ConditionOperator
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Blueprint
self_healing_bp = Blueprint('self_healing', __name__, url_prefix='/api/v5/healing')

# Initialize components (lazy loading)
_components_initialized = False


def _init_components():
    """Initialize all self-healing components"""
    global _components_initialized
    if _components_initialized:
        return

    try:
        # Initialize in order of dependency
        g.network_monitor = get_network_monitor()
        g.health_checker = get_health_checker()
        g.anomaly_detector = get_anomaly_detector(network_monitor=g.network_monitor)
        g.auto_remediation = get_auto_remediation(dry_run=False)
        g.policy_engine = get_policy_engine(auto_remediation=g.auto_remediation)

        _components_initialized = True
        logger.info("[HEALING_API] Components initialized")
    except Exception as e:
        logger.error("[HEALING_API] Failed to initialize components: %s", e)
        raise


def require_components(f: Callable) -> Callable:
    """Decorator to ensure components are initialized"""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            _init_components()
        except Exception as e:
            return jsonify({
                'success': False,
                'error': f'Component initialization failed: {str(e)}'
            }), 500
        return f(*args, **kwargs)
    return decorated


def json_response(data: dict, status: int = 200):
    """Create standard JSON response"""
    response = {
        'success': status < 400,
        'timestamp': datetime.now().isoformat(),
        **data
    }
    return jsonify(response), status


# ==================== Health Status Endpoints ====================

@self_healing_bp.route('/status', methods=['GET'])
@require_components
def get_system_status():
    """
    Get comprehensive system health status.

    Query params:
        include_network: bool - Include network monitoring data
        include_resources: bool - Include resource metrics
        services: str - Comma-separated list of services to check
        processes: str - Comma-separated list of processes to check
    """
    try:
        include_network = request.args.get('include_network', 'true').lower() == 'true'
        include_resources = request.args.get('include_resources', 'true').lower() == 'true'
        services = request.args.get('services', '').split(',') if request.args.get('services') else None
        processes = request.args.get('processes', '').split(',') if request.args.get('processes') else None

        health_checker = get_health_checker()
        network_monitor = get_network_monitor()
        anomaly_detector = get_anomaly_detector()

        status = {
            'overall_health': HealthStatus.HEALTHY.value,
            'components': {}
        }

        # Resource health
        if include_resources:
            resource_check = health_checker.check_resource_health()
            status['components']['resources'] = resource_check.to_dict()
            if resource_check.status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]:
                status['overall_health'] = resource_check.status.value

        # Network status
        if include_network:
            status['components']['network'] = network_monitor.get_summary()

        # Service checks
        if services:
            service_results = []
            for service in services:
                if service.strip():
                    check = health_checker.check_service_systemctl(service.strip())
                    service_results.append(check.to_dict())
                    if check.status in [HealthStatus.UNHEALTHY, HealthStatus.CRITICAL]:
                        status['overall_health'] = check.status.value
            status['components']['services'] = service_results

        # Process checks
        if processes:
            process_results = []
            for process in processes:
                if process.strip():
                    check = health_checker.check_service_process(process.strip())
                    process_results.append(check.to_dict())
            status['components']['processes'] = process_results

        # Anomaly summary
        status['components']['anomalies'] = anomaly_detector.get_summary()

        return json_response({'status': status})

    except Exception as e:
        logger.error("[HEALING_API] Status check error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/health', methods=['GET'])
@require_components
def get_detailed_health():
    """
    Get detailed health check results.

    Query params:
        services: str - Comma-separated services
        processes: str - Comma-separated processes
        ports: str - Comma-separated host:port pairs
        ssl_hosts: str - Comma-separated host:port pairs for SSL check
        dns_hosts: str - Comma-separated hostnames for DNS check
    """
    try:
        services = request.args.get('services', '').split(',') if request.args.get('services') else None
        services = [s.strip() for s in services if s.strip()] if services else None

        processes = request.args.get('processes', '').split(',') if request.args.get('processes') else None
        processes = [p.strip() for p in processes if p.strip()] if processes else None

        # Parse ports (format: host:port,host:port)
        ports = None
        if request.args.get('ports'):
            ports = []
            for p in request.args.get('ports').split(','):
                if ':' in p:
                    host, port = p.strip().rsplit(':', 1)
                    ports.append({'host': host, 'port': int(port)})

        # Parse SSL hosts
        ssl_hosts = None
        if request.args.get('ssl_hosts'):
            ssl_hosts = []
            for h in request.args.get('ssl_hosts').split(','):
                if ':' in h:
                    host, port = h.strip().rsplit(':', 1)
                    ssl_hosts.append({'host': host, 'port': int(port)})
                else:
                    ssl_hosts.append({'host': h.strip(), 'port': 443})

        # Parse DNS hosts
        dns_hosts = request.args.get('dns_hosts', '').split(',') if request.args.get('dns_hosts') else None
        dns_hosts = [h.strip() for h in dns_hosts if h.strip()] if dns_hosts else None

        health_checker = get_health_checker()
        results = health_checker.run_all_checks(
            services=services,
            processes=processes,
            ports=ports,
            ssl_hosts=ssl_hosts,
            dns_hosts=dns_hosts
        )

        return json_response({'health': results})

    except Exception as e:
        logger.error("[HEALING_API] Health check error: %s", e)
        return json_response({'error': str(e)}, 500)


# ==================== Anomaly Endpoints ====================

@self_healing_bp.route('/anomalies', methods=['GET'])
@require_components
def get_anomalies():
    """
    Get detected anomalies.

    Query params:
        active_only: bool - Only return active (unresolved) anomalies
        hours: int - History duration in hours (default 24)
        type: str - Filter by anomaly type
        severity: str - Filter by severity (low, medium, high, critical)
    """
    try:
        active_only = request.args.get('active_only', 'false').lower() == 'true'
        hours = int(request.args.get('hours', 24))
        anomaly_type = request.args.get('type')
        severity = request.args.get('severity')

        anomaly_detector = get_anomaly_detector()

        if active_only:
            anomalies = anomaly_detector.get_active_anomalies()
        else:
            anomaly_type_enum = AnomalyType(anomaly_type) if anomaly_type else None
            severity_enum = Severity(severity) if severity else None
            anomalies = anomaly_detector.get_anomaly_history(
                hours=hours,
                anomaly_type=anomaly_type_enum,
                severity=severity_enum
            )

        return json_response({
            'anomalies': [a.to_dict() for a in anomalies],
            'count': len(anomalies)
        })

    except Exception as e:
        logger.error("[HEALING_API] Anomaly fetch error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/anomalies/detect', methods=['POST'])
@require_components
def run_anomaly_detection():
    """Run anomaly detection scan now"""
    try:
        anomaly_detector = get_anomaly_detector()
        network_monitor = get_network_monitor()

        # Get fresh data
        connections = network_monitor.get_all_connections()
        bandwidth = network_monitor.get_bandwidth_usage()

        # Run detection
        anomalies = anomaly_detector.run_detection(
            connections=[c.to_dict() for c in connections],
            bandwidth=bandwidth
        )

        return json_response({
            'anomalies_detected': len(anomalies),
            'anomalies': [a.to_dict() for a in anomalies]
        })

    except Exception as e:
        logger.error("[HEALING_API] Detection error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/anomalies/<anomaly_id>/resolve', methods=['POST'])
@require_components
def resolve_anomaly(anomaly_id: str):
    """Mark an anomaly as resolved"""
    try:
        data = request.get_json() or {}
        note = data.get('note', '')

        anomaly_detector = get_anomaly_detector()
        anomaly_detector.resolve_anomaly(anomaly_id, note)

        return json_response({'message': f'Anomaly {anomaly_id} resolved'})

    except Exception as e:
        logger.error("[HEALING_API] Resolve error: %s", e)
        return json_response({'error': str(e)}, 500)


# ==================== Remediation Endpoints ====================

@self_healing_bp.route('/remediate', methods=['POST'])
@require_components
def trigger_remediation():
    """
    Trigger a remediation action.

    Request body:
        action: str - Action type (block_ip, kill_process, restart_service, etc.)
        target: str - Target of the action
        parameters: dict - Additional parameters
        reason: str - Reason for action
        anomaly_id: str - Associated anomaly ID (optional)
    """
    try:
        data = request.get_json()
        if not data:
            return json_response({'error': 'Request body required'}, 400)

        action = data.get('action')
        target = data.get('target')
        parameters = data.get('parameters', {})
        reason = data.get('reason', 'Manual remediation')
        anomaly_id = data.get('anomaly_id')

        if not action or not target:
            return json_response({'error': 'action and target required'}, 400)

        auto_remediation = get_auto_remediation()

        # Execute action based on type
        if action == 'block_ip':
            result = auto_remediation.block_ip(
                ip=target,
                reason=reason,
                duration_minutes=parameters.get('duration_minutes', 0),
                anomaly_id=anomaly_id
            )
        elif action == 'unblock_ip':
            result = auto_remediation.unblock_ip(ip=target, reason=reason)
        elif action == 'kill_process':
            if str(target).isdigit():
                result = auto_remediation.kill_process(
                    pid=int(target),
                    force=parameters.get('force', False),
                    reason=reason,
                    anomaly_id=anomaly_id
                )
            else:
                result = auto_remediation.kill_process(
                    name=target,
                    force=parameters.get('force', False),
                    reason=reason,
                    anomaly_id=anomaly_id
                )
        elif action == 'restart_service':
            result = auto_remediation.restart_service(
                service_name=target,
                reason=reason,
                anomaly_id=anomaly_id
            )
        elif action == 'stop_service':
            result = auto_remediation.stop_service(
                service_name=target,
                reason=reason,
                anomaly_id=anomaly_id
            )
        elif action == 'quarantine_file':
            result = auto_remediation.quarantine_file(
                file_path=target,
                reason=reason,
                anomaly_id=anomaly_id
            )
        elif action == 'rate_limit':
            result = auto_remediation.rate_limit_ip(
                ip=target,
                rate=parameters.get('rate'),
                reason=reason,
                anomaly_id=anomaly_id
            )
        elif action == 'close_port':
            result = auto_remediation.close_port(
                port=int(target),
                protocol=parameters.get('protocol', 'tcp'),
                reason=reason,
                anomaly_id=anomaly_id
            )
        elif action == 'rollback':
            result = auto_remediation.rollback_last()
        else:
            return json_response({'error': f'Unknown action: {action}'}, 400)

        return json_response({
            'result': result.to_dict(),
            'success': result.status.value in ['success', 'dry_run']
        })

    except Exception as e:
        logger.error("[HEALING_API] Remediation error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/remediate/blocked-ips', methods=['GET'])
@require_components
def get_blocked_ips():
    """Get list of currently blocked IPs"""
    try:
        auto_remediation = get_auto_remediation()
        blocked = auto_remediation.get_blocked_ips()

        return json_response({
            'blocked_ips': blocked,
            'count': len(blocked)
        })

    except Exception as e:
        logger.error("[HEALING_API] Blocked IPs error: %s", e)
        return json_response({'error': str(e)}, 500)


# ==================== Policy Endpoints ====================

@self_healing_bp.route('/policies', methods=['GET'])
@require_components
def list_policies():
    """
    List healing policies.

    Query params:
        enabled_only: bool - Only return enabled policies
        trigger: str - Filter by trigger type
        tags: str - Comma-separated tags to filter by
    """
    try:
        enabled_only = request.args.get('enabled_only', 'false').lower() == 'true'
        trigger = request.args.get('trigger')
        tags = request.args.get('tags', '').split(',') if request.args.get('tags') else None
        tags = [t.strip() for t in tags if t.strip()] if tags else None

        trigger_enum = ActionTrigger(trigger) if trigger else None

        policy_engine = get_policy_engine()
        policies = policy_engine.list_policies(
            enabled_only=enabled_only,
            trigger=trigger_enum,
            tags=tags
        )

        return json_response({
            'policies': [p.to_dict() for p in policies],
            'count': len(policies)
        })

    except Exception as e:
        logger.error("[HEALING_API] Policy list error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/policies', methods=['POST'])
@require_components
def create_policy():
    """
    Create a new healing policy.

    Request body: HealingPolicy JSON
    """
    try:
        data = request.get_json()
        if not data:
            return json_response({'error': 'Request body required'}, 400)

        # Validate required fields
        required = ['id', 'name', 'trigger', 'actions']
        missing = [f for f in required if f not in data]
        if missing:
            return json_response({'error': f'Missing required fields: {missing}'}, 400)

        policy = HealingPolicy.from_dict(data)
        policy_engine = get_policy_engine()

        if policy_engine.add_policy(policy):
            return json_response({
                'message': f'Policy {policy.id} created',
                'policy': policy.to_dict()
            }, 201)
        else:
            return json_response({'error': 'Policy already exists'}, 409)

    except Exception as e:
        logger.error("[HEALING_API] Policy create error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/policies/<policy_id>', methods=['GET'])
@require_components
def get_policy(policy_id: str):
    """Get a specific policy by ID"""
    try:
        policy_engine = get_policy_engine()
        policy = policy_engine.get_policy(policy_id)

        if policy:
            return json_response({'policy': policy.to_dict()})
        else:
            return json_response({'error': 'Policy not found'}, 404)

    except Exception as e:
        logger.error("[HEALING_API] Policy get error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/policies/<policy_id>', methods=['PUT'])
@require_components
def update_policy(policy_id: str):
    """Update an existing policy"""
    try:
        data = request.get_json()
        if not data:
            return json_response({'error': 'Request body required'}, 400)

        # Ensure ID matches
        data['id'] = policy_id

        policy = HealingPolicy.from_dict(data)
        policy_engine = get_policy_engine()

        if policy_engine.update_policy(policy):
            return json_response({
                'message': f'Policy {policy_id} updated',
                'policy': policy.to_dict()
            })
        else:
            return json_response({'error': 'Policy not found'}, 404)

    except Exception as e:
        logger.error("[HEALING_API] Policy update error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/policies/<policy_id>', methods=['DELETE'])
@require_components
def delete_policy(policy_id: str):
    """Delete a policy"""
    try:
        policy_engine = get_policy_engine()

        if policy_engine.delete_policy(policy_id):
            return json_response({'message': f'Policy {policy_id} deleted'})
        else:
            return json_response({'error': 'Policy not found'}, 404)

    except Exception as e:
        logger.error("[HEALING_API] Policy delete error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/policies/<policy_id>/enable', methods=['POST'])
@require_components
def enable_policy(policy_id: str):
    """Enable a policy"""
    try:
        policy_engine = get_policy_engine()

        if policy_engine.enable_policy(policy_id):
            return json_response({'message': f'Policy {policy_id} enabled'})
        else:
            return json_response({'error': 'Policy not found'}, 404)

    except Exception as e:
        logger.error("[HEALING_API] Policy enable error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/policies/<policy_id>/disable', methods=['POST'])
@require_components
def disable_policy(policy_id: str):
    """Disable a policy"""
    try:
        policy_engine = get_policy_engine()

        if policy_engine.disable_policy(policy_id):
            return json_response({'message': f'Policy {policy_id} disabled'})
        else:
            return json_response({'error': 'Policy not found'}, 404)

    except Exception as e:
        logger.error("[HEALING_API] Policy disable error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/policies/evaluate', methods=['POST'])
@require_components
def evaluate_policies():
    """
    Evaluate policies against provided data.

    Request body:
        trigger: str - Trigger type
        data: dict - Data to evaluate against
        execute: bool - Whether to execute matching policies (default false)
    """
    try:
        body = request.get_json()
        if not body:
            return json_response({'error': 'Request body required'}, 400)

        trigger = body.get('trigger')
        data = body.get('data', {})
        execute = body.get('execute', False)

        if not trigger:
            return json_response({'error': 'trigger required'}, 400)

        trigger_enum = ActionTrigger(trigger)
        policy_engine = get_policy_engine()

        # Evaluate matching policies
        matching = policy_engine.evaluate_policies(data, trigger_enum)

        results = {
            'matching_policies': [p.to_dict() for p in matching],
            'count': len(matching)
        }

        # Execute if requested
        if execute and matching:
            executions = []
            for policy in matching:
                execution = policy_engine.execute_policy(policy, data)
                executions.append(execution.to_dict())
            results['executions'] = executions

        return json_response(results)

    except Exception as e:
        logger.error("[HEALING_API] Policy evaluate error: %s", e)
        return json_response({'error': str(e)}, 500)


# ==================== Approval Endpoints ====================

@self_healing_bp.route('/approvals', methods=['GET'])
@require_components
def get_pending_approvals():
    """Get pending approval requests"""
    try:
        policy_engine = get_policy_engine()
        pending = policy_engine.get_pending_approvals()

        return json_response({
            'pending_approvals': [p.to_dict() for p in pending],
            'count': len(pending)
        })

    except Exception as e:
        logger.error("[HEALING_API] Approvals error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/approvals/<execution_id>/approve', methods=['POST'])
@require_components
def approve_action(execution_id: str):
    """Approve a pending action"""
    try:
        data = request.get_json() or {}
        approved_by = data.get('approved_by', 'api_user')

        policy_engine = get_policy_engine()
        execution = policy_engine.approve_execution(execution_id, approved_by)

        if execution:
            return json_response({
                'message': f'Execution {execution_id} approved',
                'execution': execution.to_dict()
            })
        else:
            return json_response({'error': 'Execution not found'}, 404)

    except Exception as e:
        logger.error("[HEALING_API] Approval error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/approvals/<execution_id>/reject', methods=['POST'])
@require_components
def reject_action(execution_id: str):
    """Reject a pending action"""
    try:
        data = request.get_json() or {}
        rejected_by = data.get('rejected_by', 'api_user')
        reason = data.get('reason', '')

        policy_engine = get_policy_engine()
        execution = policy_engine.reject_execution(execution_id, rejected_by, reason)

        if execution:
            return json_response({
                'message': f'Execution {execution_id} rejected',
                'execution': execution.to_dict()
            })
        else:
            return json_response({'error': 'Execution not found'}, 404)

    except Exception as e:
        logger.error("[HEALING_API] Rejection error: %s", e)
        return json_response({'error': str(e)}, 500)


# ==================== History Endpoints ====================

@self_healing_bp.route('/history', methods=['GET'])
@require_components
def get_remediation_history():
    """
    Get remediation action history.

    Query params:
        hours: int - History duration in hours (default 24)
        action_type: str - Filter by action type
        status: str - Filter by status
    """
    try:
        hours = int(request.args.get('hours', 24))
        action_type = request.args.get('action_type')
        status = request.args.get('status')

        auto_remediation = get_auto_remediation()

        action_type_enum = ActionType(action_type) if action_type else None

        # Note: status filtering would need ActionStatus enum
        history = auto_remediation.get_action_history(
            hours=hours,
            action_type=action_type_enum
        )

        return json_response({
            'history': [h.to_dict() for h in history],
            'count': len(history)
        })

    except Exception as e:
        logger.error("[HEALING_API] History error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/history/policies', methods=['GET'])
@require_components
def get_policy_execution_history():
    """
    Get policy execution history.

    Query params:
        hours: int - History duration in hours (default 24)
        policy_id: str - Filter by policy ID
        status: str - Filter by execution status
    """
    try:
        hours = int(request.args.get('hours', 24))
        policy_id = request.args.get('policy_id')
        status = request.args.get('status')

        policy_engine = get_policy_engine()
        history = policy_engine.get_execution_history(
            hours=hours,
            policy_id=policy_id,
            status=status
        )

        return json_response({
            'history': [h.to_dict() for h in history],
            'count': len(history)
        })

    except Exception as e:
        logger.error("[HEALING_API] Policy history error: %s", e)
        return json_response({'error': str(e)}, 500)


# ==================== Network Monitoring Endpoints ====================

@self_healing_bp.route('/network/interfaces', methods=['GET'])
@require_components
def get_network_interfaces():
    """Get all network interface statistics"""
    try:
        network_monitor = get_network_monitor()
        interfaces = network_monitor.get_all_interfaces()

        return json_response({
            'interfaces': [i.to_dict() for i in interfaces],
            'count': len(interfaces)
        })

    except Exception as e:
        logger.error("[HEALING_API] Interfaces error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/network/connections', methods=['GET'])
@require_components
def get_network_connections():
    """
    Get network connections.

    Query params:
        state: str - Filter by connection state
        port: int - Filter by port
        process: str - Filter by process name
        outbound_only: bool - Only show outbound connections
    """
    try:
        state = request.args.get('state')
        port = request.args.get('port', type=int)
        process = request.args.get('process')
        outbound_only = request.args.get('outbound_only', 'false').lower() == 'true'

        network_monitor = get_network_monitor()

        if outbound_only:
            connections = network_monitor.get_outbound_connections()
        elif state:
            connections = network_monitor.get_connections_by_state(state)
        elif port:
            connections = network_monitor.get_connections_by_port(port)
        elif process:
            connections = network_monitor.get_connections_by_process(name=process)
        else:
            connections = network_monitor.get_all_connections()

        return json_response({
            'connections': [c.to_dict() for c in connections],
            'count': len(connections)
        })

    except Exception as e:
        logger.error("[HEALING_API] Connections error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/network/bandwidth', methods=['GET'])
@require_components
def get_bandwidth():
    """
    Get bandwidth usage.

    Query params:
        interface: str - Specific interface (optional)
        minutes: int - History duration in minutes (default 60)
    """
    try:
        interface = request.args.get('interface')
        minutes = int(request.args.get('minutes', 60))

        network_monitor = get_network_monitor()

        # Get current bandwidth
        current = network_monitor.get_bandwidth_usage()

        # Get history
        history = network_monitor.get_bandwidth_history(interface=interface, minutes=minutes)

        return json_response({
            'current': {k: asdict(v) for k, v in current.items()},
            'history': {
                k: [asdict(s) for s in v]
                for k, v in history.items()
            }
        })

    except Exception as e:
        logger.error("[HEALING_API] Bandwidth error: %s", e)
        return json_response({'error': str(e)}, 500)


@self_healing_bp.route('/network/listening', methods=['GET'])
@require_components
def get_listening_ports():
    """Get all listening ports"""
    try:
        network_monitor = get_network_monitor()
        ports = network_monitor.get_listening_ports()

        return json_response({
            'listening_ports': ports,
            'count': len(ports)
        })

    except Exception as e:
        logger.error("[HEALING_API] Listening ports error: %s", e)
        return json_response({'error': str(e)}, 500)


# ==================== Summary Endpoint ====================

@self_healing_bp.route('/summary', methods=['GET'])
@require_components
def get_full_summary():
    """Get complete self-healing system summary"""
    try:
        network_monitor = get_network_monitor()
        health_checker = get_health_checker()
        anomaly_detector = get_anomaly_detector()
        auto_remediation = get_auto_remediation()
        policy_engine = get_policy_engine()

        return json_response({
            'summary': {
                'network': network_monitor.get_summary(),
                'health': health_checker.check_resource_health().to_dict(),
                'anomalies': anomaly_detector.get_summary(),
                'remediation': auto_remediation.get_summary(),
                'policies': policy_engine.get_summary()
            }
        })

    except Exception as e:
        logger.error("[HEALING_API] Summary error: %s", e)
        return json_response({'error': str(e)}, 500)


# Helper function for asdict import
from dataclasses import asdict


def register_blueprint(app):
    """Register the self-healing blueprint with a Flask app"""
    app.register_blueprint(self_healing_bp)
    logger.info("[HEALING_API] Blueprint registered at /api/v5/healing")
