#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Agentic SOC Module v5.0
================================================================================

    Autonomous Security Operations Center with AI-powered:
    - Tier 1 Alert Triage Automation
    - ML-based Alert Classification
    - Automated Investigation
    - Autonomous Decision Making
    - Knowledge Base Learning
    - Human-AI Collaboration

================================================================================
"""

from .soc_agent import (
    SOCAgent,
    AgentConfig,
    AgentDecision,
    AgentAction,
    get_soc_agent
)

from .alert_classifier import (
    AlertClassifier,
    ClassificationResult,
    AlertCategory,
    SeverityLevel,
    get_classifier
)

from .investigation_agent import (
    InvestigationAgent,
    Investigation,
    InvestigationStep,
    InvestigationResult,
    get_investigation_agent
)

from .decision_engine import (
    DecisionEngine,
    Decision,
    DecisionType,
    RiskAssessment,
    get_decision_engine
)

from .knowledge_base import (
    KnowledgeBase,
    IncidentPattern,
    ThreatActorProfile,
    PlaybookRecommendation,
    get_knowledge_base
)

from .analyst_interface import (
    AnalystInterface,
    Finding,
    FeedbackType,
    AnalystFeedback,
    PerformanceMetrics,
    get_analyst_interface
)

from .api_routes import agentic_soc_bp

__version__ = "5.0.0"
__all__ = [
    # SOC Agent
    'SOCAgent',
    'AgentConfig',
    'AgentDecision',
    'AgentAction',
    'get_soc_agent',
    # Alert Classifier
    'AlertClassifier',
    'ClassificationResult',
    'AlertCategory',
    'SeverityLevel',
    'get_classifier',
    # Investigation Agent
    'InvestigationAgent',
    'Investigation',
    'InvestigationStep',
    'InvestigationResult',
    'get_investigation_agent',
    # Decision Engine
    'DecisionEngine',
    'Decision',
    'DecisionType',
    'RiskAssessment',
    'get_decision_engine',
    # Knowledge Base
    'KnowledgeBase',
    'IncidentPattern',
    'ThreatActorProfile',
    'PlaybookRecommendation',
    'get_knowledge_base',
    # Analyst Interface
    'AnalystInterface',
    'Finding',
    'FeedbackType',
    'AnalystFeedback',
    'PerformanceMetrics',
    'get_analyst_interface',
    # API
    'agentic_soc_bp'
]
