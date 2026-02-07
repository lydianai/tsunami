#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI AI PREDICTION ENGINE v5.0
    Machine Learning-Based Threat Prediction & Zero-Day Detection
================================================================================

    Real ML algorithms for:
    - Anomaly Detection (Isolation Forest)
    - Behavioral Analysis
    - Kill Chain Prediction
    - Vulnerability Risk Scoring
    - Time Series Attack Prediction

================================================================================
"""

from .threat_predictor import ThreatPredictor, ZeroDayDetector, NetworkFeatureExtractor
from .behavior_analyzer import BehaviorAnalyzer, EntityProfile, BehaviorBaseline
from .killchain_predictor import KillChainPredictor, KillChainStage, AttackPath
from .vulnerability_scorer import VulnerabilityScorer, CVEData, ExploitabilityScore
from .model_trainer import ModelTrainer, ModelManager, TrainingMetrics

__version__ = "5.0.0"
__all__ = [
    "ThreatPredictor",
    "ZeroDayDetector",
    "NetworkFeatureExtractor",
    "BehaviorAnalyzer",
    "EntityProfile",
    "BehaviorBaseline",
    "KillChainPredictor",
    "KillChainStage",
    "AttackPath",
    "VulnerabilityScorer",
    "CVEData",
    "ExploitabilityScore",
    "ModelTrainer",
    "ModelManager",
    "TrainingMetrics",
]
