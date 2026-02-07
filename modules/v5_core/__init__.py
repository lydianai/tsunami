#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 CORE INTEGRATION MODULE
    Central orchestration for all v5 security modules
================================================================================

    This module provides:
    - Central orchestration of all v5 modules
    - Unified dashboard data aggregation
    - Event processing pipeline
    - Configuration management
    - API routes for system control

    Modules Integrated:
    - threat_intel: STIX/TAXII threat intelligence
    - mitre_attack: MITRE ATT&CK framework
    - ai_prediction: ML-based threat prediction
    - self_healing: Auto-remediation system
    - quantum_crypto: Post-quantum cryptography
    - soar_xdr: Security orchestration & XDR
    - auto_pentest: Autonomous penetration testing
    - agentic_soc: AI-powered SOC automation
    - darkweb_intel: Dark web monitoring

================================================================================
"""

from .v5_orchestrator import (
    V5Orchestrator,
    ModuleStatus,
    EventBus,
    get_orchestrator,
    initialize_v5
)

from .unified_dashboard import (
    UnifiedDashboard,
    DashboardMetrics,
    RiskScoreCalculator,
    AlertConsolidator,
    ExecutiveSummary,
    get_dashboard
)

from .event_pipeline import (
    EventPipeline,
    SecurityEvent,
    EnrichedEvent,
    PipelineStage,
    EventProcessor,
    get_pipeline
)

from .config_manager import (
    ConfigManager,
    ModuleConfig,
    FeatureToggle,
    LicenseManager,
    get_config_manager
)

from .api_routes import v5_core_bp

__version__ = "5.0.0"
__author__ = "TSUNAMI Security Team"

__all__ = [
    # Orchestrator
    'V5Orchestrator',
    'ModuleStatus',
    'EventBus',
    'get_orchestrator',
    'initialize_v5',

    # Dashboard
    'UnifiedDashboard',
    'DashboardMetrics',
    'RiskScoreCalculator',
    'AlertConsolidator',
    'ExecutiveSummary',
    'get_dashboard',

    # Pipeline
    'EventPipeline',
    'SecurityEvent',
    'EnrichedEvent',
    'PipelineStage',
    'EventProcessor',
    'get_pipeline',

    # Config
    'ConfigManager',
    'ModuleConfig',
    'FeatureToggle',
    'LicenseManager',
    'get_config_manager',

    # API
    'v5_core_bp'
]
