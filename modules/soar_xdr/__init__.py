#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOAR (Security Orchestration, Automation and Response)
    & XDR (Extended Detection and Response) Module v5.0
================================================================================

    Real security orchestration with:
    - Playbook execution engine with JSON/YAML support
    - Pre-built security action library
    - Incident lifecycle management
    - XDR correlation engine
    - Automated response orchestration
    - External system integrations

    Components:
    - playbook_engine.py: SOAR playbook execution with conditional logic
    - action_library.py: Pre-built security actions
    - incident_manager.py: Incident lifecycle management
    - correlation_engine.py: XDR event correlation
    - response_orchestrator.py: Automated response coordination
    - integration_adapters.py: External system integrations
    - api_routes.py: Flask REST API endpoints

================================================================================
"""

from .playbook_engine import (
    PlaybookEngine,
    Playbook,
    PlaybookStep,
    PlaybookExecution,
    PlaybookStatus,
    ExecutionContext,
    get_playbook_engine
)

from .action_library import (
    ActionLibrary,
    ActionResult,
    ActionType,
    SecurityAction,
    # Action implementations
    block_ip,
    unblock_ip,
    kill_process,
    isolate_host,
    send_alert,
    query_threat_intel,
    create_ticket,
    collect_forensics,
    run_scan,
    quarantine_file,
    disable_user,
    get_action_library
)

from .incident_manager import (
    IncidentManager,
    Incident,
    IncidentStatus,
    IncidentSeverity,
    IncidentTimeline,
    TimelineEvent,
    Evidence,
    EscalationRule,
    SLATracker,
    get_incident_manager
)

from .correlation_engine import (
    CorrelationEngine,
    CorrelatedEvent,
    EventCluster,
    AlertGroup,
    AttackChain,
    RootCauseAnalysis,
    CorrelationRule,
    get_correlation_engine
)

from .response_orchestrator import (
    ResponseOrchestrator,
    ResponsePlan,
    ResponseStep,
    ResponseMetrics,
    ResponseLearning,
    get_response_orchestrator
)

from .integration_adapters import (
    IntegrationManager,
    WebhookReceiver,
    SyslogInput,
    RESTConnector,
    EmailParser,
    get_integration_manager
)

from .api_routes import soar_xdr_bp

__version__ = "5.0.0"
__author__ = "TSUNAMI Security Team"

__all__ = [
    # Playbook Engine
    'PlaybookEngine',
    'Playbook',
    'PlaybookStep',
    'PlaybookExecution',
    'PlaybookStatus',
    'ExecutionContext',
    'get_playbook_engine',

    # Action Library
    'ActionLibrary',
    'ActionResult',
    'ActionType',
    'SecurityAction',
    'block_ip',
    'unblock_ip',
    'kill_process',
    'isolate_host',
    'send_alert',
    'query_threat_intel',
    'create_ticket',
    'collect_forensics',
    'run_scan',
    'quarantine_file',
    'disable_user',
    'get_action_library',

    # Incident Manager
    'IncidentManager',
    'Incident',
    'IncidentStatus',
    'IncidentSeverity',
    'IncidentTimeline',
    'TimelineEvent',
    'Evidence',
    'EscalationRule',
    'SLATracker',
    'get_incident_manager',

    # Correlation Engine
    'CorrelationEngine',
    'CorrelatedEvent',
    'EventCluster',
    'AlertGroup',
    'AttackChain',
    'RootCauseAnalysis',
    'CorrelationRule',
    'get_correlation_engine',

    # Response Orchestrator
    'ResponseOrchestrator',
    'ResponsePlan',
    'ResponseStep',
    'ResponseMetrics',
    'ResponseLearning',
    'get_response_orchestrator',

    # Integration Adapters
    'IntegrationManager',
    'WebhookReceiver',
    'SyslogInput',
    'RESTConnector',
    'EmailParser',
    'get_integration_manager',

    # API
    'soar_xdr_bp'
]
