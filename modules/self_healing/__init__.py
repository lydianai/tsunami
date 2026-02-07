#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SELF-HEALING NETWORK MODULE v5.0
    Real-time Network Monitoring and Auto-Remediation System
================================================================================

    Components:
    - network_monitor.py: Real-time network interface monitoring
    - health_checker.py: System health monitoring (CPU, memory, disk, services)
    - anomaly_detector.py: Network anomaly detection
    - auto_remediation.py: Automatic response and healing actions
    - policy_engine.py: JSON-based healing policy definitions
    - api_routes.py: Flask REST API endpoints

================================================================================
"""

from .network_monitor import NetworkMonitor, ConnectionInfo, InterfaceStats
from .health_checker import HealthChecker, HealthStatus, ServiceCheck
from .anomaly_detector import AnomalyDetector, Anomaly, AnomalyType
from .auto_remediation import AutoRemediation, RemediationAction, RemediationResult
from .policy_engine import PolicyEngine, HealingPolicy, PolicyCondition

__version__ = "5.0.0"
__all__ = [
    'NetworkMonitor',
    'ConnectionInfo',
    'InterfaceStats',
    'HealthChecker',
    'HealthStatus',
    'ServiceCheck',
    'AnomalyDetector',
    'Anomaly',
    'AnomalyType',
    'AutoRemediation',
    'RemediationAction',
    'RemediationResult',
    'PolicyEngine',
    'HealingPolicy',
    'PolicyCondition',
]
