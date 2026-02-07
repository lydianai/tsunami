#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Agentic SOC - Decision Engine v5.0
================================================================================

    Autonomous decision making capabilities:
    - Rule-based + ML hybrid decisions
    - Confidence scoring
    - Escalation logic
    - Action selection
    - Risk assessment

================================================================================
"""

import logging
import uuid
import json
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

logger = logging.getLogger(__name__)


class DecisionType(Enum):
    """Types of decisions"""
    CLOSE_FALSE_POSITIVE = "close_false_positive"
    CLOSE_TRUE_POSITIVE_HANDLED = "close_true_positive_handled"
    ESCALATE_TO_TIER2 = "escalate_to_tier2"
    ESCALATE_TO_TIER3 = "escalate_to_tier3"
    ESCALATE_TO_INCIDENT_RESPONSE = "escalate_to_incident_response"
    AUTO_REMEDIATE = "auto_remediate"
    BLOCK_IP = "block_ip"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_USER = "disable_user"
    RESET_PASSWORD = "reset_password"
    QUARANTINE_FILE = "quarantine_file"
    MONITOR = "monitor"
    GATHER_MORE_INFO = "gather_more_info"
    PENDING_HUMAN_REVIEW = "pending_human_review"


class ActionType(Enum):
    """Types of automated actions"""
    BLOCK_IP_FIREWALL = "block_ip_firewall"
    BLOCK_IP_PROXY = "block_ip_proxy"
    ISOLATE_ENDPOINT = "isolate_endpoint"
    DISABLE_USER_ACCOUNT = "disable_user_account"
    FORCE_PASSWORD_RESET = "force_password_reset"
    QUARANTINE_FILE = "quarantine_file"
    DELETE_FILE = "delete_file"
    KILL_PROCESS = "kill_process"
    REVOKE_SESSIONS = "revoke_sessions"
    ADD_TO_WATCHLIST = "add_to_watchlist"
    CREATE_TICKET = "create_ticket"
    SEND_NOTIFICATION = "send_notification"
    NONE = "none"


class RiskLevel(Enum):
    """Risk levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class RiskAssessment:
    """Risk assessment result"""
    overall_risk: RiskLevel
    risk_score: float  # 0-100
    factors: Dict[str, float]
    business_impact: str
    data_sensitivity: str
    threat_actor_capability: str
    exploitability: str
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall_risk': self.overall_risk.value,
            'risk_score': self.risk_score,
            'factors': self.factors,
            'business_impact': self.business_impact,
            'data_sensitivity': self.data_sensitivity,
            'threat_actor_capability': self.threat_actor_capability,
            'exploitability': self.exploitability,
            'recommendations': self.recommendations
        }


@dataclass
class Action:
    """Automated action"""
    id: str
    action_type: ActionType
    target: str
    parameters: Dict[str, Any]
    status: str = "pending"  # pending, executing, completed, failed
    result: Optional[Dict[str, Any]] = None
    executed_at: Optional[datetime] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'action_type': self.action_type.value,
            'target': self.target,
            'parameters': self.parameters,
            'status': self.status,
            'result': self.result,
            'executed_at': self.executed_at.isoformat() if self.executed_at else None,
            'error': self.error
        }


@dataclass
class Decision:
    """Decision result"""
    id: str
    alert_id: str
    decision_type: DecisionType
    confidence: float
    risk_assessment: RiskAssessment
    recommended_actions: List[Action]
    auto_execute: bool
    requires_approval: bool
    reasoning: str
    evidence: List[str]
    alternative_decisions: List[Tuple[DecisionType, float]]
    created_at: datetime = field(default_factory=datetime.utcnow)
    approved: bool = False
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'alert_id': self.alert_id,
            'decision_type': self.decision_type.value,
            'confidence': self.confidence,
            'risk_assessment': self.risk_assessment.to_dict(),
            'recommended_actions': [a.to_dict() for a in self.recommended_actions],
            'auto_execute': self.auto_execute,
            'requires_approval': self.requires_approval,
            'reasoning': self.reasoning,
            'evidence': self.evidence,
            'alternative_decisions': [
                {'type': dt.value, 'confidence': conf}
                for dt, conf in self.alternative_decisions
            ],
            'created_at': self.created_at.isoformat(),
            'approved': self.approved,
            'approved_by': self.approved_by,
            'approved_at': self.approved_at.isoformat() if self.approved_at else None
        }


class DecisionRule:
    """Base class for decision rules"""

    def __init__(self, name: str, priority: int = 50):
        self.name = name
        self.priority = priority

    def evaluate(self, context: Dict[str, Any]) -> Optional[Tuple[DecisionType, float, str]]:
        """
        Evaluate rule against context.
        Returns (decision_type, confidence, reasoning) or None if rule doesn't apply.
        """
        raise NotImplementedError


class FalsePositiveRule(DecisionRule):
    """Rule for detecting false positives"""

    def __init__(self):
        super().__init__("FalsePositiveDetection", priority=90)

    def evaluate(self, context: Dict[str, Any]) -> Optional[Tuple[DecisionType, float, str]]:
        classification = context.get('classification', {})
        investigation = context.get('investigation', {})

        # High confidence false positive from classifier
        if classification.get('is_false_positive') and classification.get('false_positive_probability', 0) > 0.8:
            return (
                DecisionType.CLOSE_FALSE_POSITIVE,
                0.9,
                f"High confidence false positive (probability: {classification.get('false_positive_probability'):.2f})"
            )

        # Known good/approved activity
        alert_data = context.get('alert', {})
        title_lower = alert_data.get('title', '').lower()
        desc_lower = alert_data.get('description', '').lower()

        approved_keywords = ['scheduled scan', 'approved activity', 'penetration test', 'authorized']
        if any(kw in title_lower or kw in desc_lower for kw in approved_keywords):
            return (
                DecisionType.CLOSE_FALSE_POSITIVE,
                0.85,
                "Activity matches known approved/scheduled patterns"
            )

        return None


class CriticalThreatRule(DecisionRule):
    """Rule for critical threats requiring immediate escalation"""

    def __init__(self):
        super().__init__("CriticalThreatEscalation", priority=100)

    def evaluate(self, context: Dict[str, Any]) -> Optional[Tuple[DecisionType, float, str]]:
        classification = context.get('classification', {})
        investigation = context.get('investigation', {})

        # Critical severity with high confidence
        if (classification.get('severity') == 'critical' and
                classification.get('confidence', 0) > 0.7):
            return (
                DecisionType.ESCALATE_TO_INCIDENT_RESPONSE,
                0.95,
                "Critical severity alert with high classification confidence"
            )

        # Active data exfiltration
        category = classification.get('category', '')
        if category == 'data_exfiltration':
            blast_radius = investigation.get('blast_radius', {})
            if blast_radius.get('data_at_risk'):
                return (
                    DecisionType.ESCALATE_TO_INCIDENT_RESPONSE,
                    0.9,
                    "Active data exfiltration detected with data at risk"
                )

        # Known APT/threat actor
        steps = investigation.get('steps', [])
        for step in steps:
            if step.get('data_source') == 'threat_intel':
                result = step.get('result', {})
                intel_data = result.get('intel_data', {})
                for match in intel_data.get('matches', []):
                    if match.get('confidence', 0) > 85:
                        return (
                            DecisionType.ESCALATE_TO_INCIDENT_RESPONSE,
                            0.95,
                            f"High-confidence threat intel match: {match.get('malware_family', 'Unknown')}"
                        )

        return None


class AutoRemediationRule(DecisionRule):
    """Rule for automated remediation"""

    def __init__(self):
        super().__init__("AutoRemediation", priority=70)

    def evaluate(self, context: Dict[str, Any]) -> Optional[Tuple[DecisionType, float, str]]:
        classification = context.get('classification', {})
        alert_data = context.get('alert', {})

        category = classification.get('category', '')
        severity = classification.get('severity', '')

        # Auto-block malicious IPs for medium/high severity
        if category in ['command_and_control', 'intrusion'] and severity in ['high', 'medium']:
            if alert_data.get('dest_ip') or alert_data.get('source_ip'):
                return (
                    DecisionType.AUTO_REMEDIATE,
                    0.8,
                    f"Auto-remediation triggered for {category} activity"
                )

        # Quarantine detected malware
        if category == 'malware' and severity in ['critical', 'high']:
            return (
                DecisionType.QUARANTINE_FILE,
                0.85,
                "Quarantine recommended for detected malware"
            )

        return None


class EscalationRule(DecisionRule):
    """Rule for tier-based escalation"""

    def __init__(self):
        super().__init__("TierEscalation", priority=60)

    def evaluate(self, context: Dict[str, Any]) -> Optional[Tuple[DecisionType, float, str]]:
        classification = context.get('classification', {})
        investigation = context.get('investigation', {})

        severity = classification.get('severity', '')
        confidence = classification.get('confidence', 0)
        priority_score = classification.get('priority_score', 0)

        # High severity or low confidence -> Tier 2
        if severity == 'high' or (severity == 'medium' and confidence < 0.6):
            return (
                DecisionType.ESCALATE_TO_TIER2,
                0.75,
                f"Escalation to Tier 2: {severity} severity, {confidence:.2f} confidence"
            )

        # Complex investigation required -> Tier 3
        affected_assets = investigation.get('affected_assets', [])
        if len(affected_assets) > 5:
            return (
                DecisionType.ESCALATE_TO_TIER3,
                0.8,
                f"Escalation to Tier 3: Multiple affected assets ({len(affected_assets)})"
            )

        # Priority score based escalation
        if priority_score > 80:
            return (
                DecisionType.ESCALATE_TO_TIER2,
                0.7,
                f"Escalation based on high priority score ({priority_score:.0f})"
            )

        return None


class MonitoringRule(DecisionRule):
    """Rule for monitoring/observation decisions"""

    def __init__(self):
        super().__init__("Monitoring", priority=40)

    def evaluate(self, context: Dict[str, Any]) -> Optional[Tuple[DecisionType, float, str]]:
        classification = context.get('classification', {})

        severity = classification.get('severity', '')
        category = classification.get('category', '')

        # Low severity suspicious activity -> monitor
        if severity in ['low', 'informational'] and category == 'suspicious_activity':
            return (
                DecisionType.MONITOR,
                0.7,
                "Low severity suspicious activity - continue monitoring"
            )

        # Reconnaissance with low confidence
        if category == 'reconnaissance' and classification.get('confidence', 0) < 0.6:
            return (
                DecisionType.MONITOR,
                0.65,
                "Potential reconnaissance - monitor for escalation"
            )

        return None


class DecisionEngine:
    """Autonomous decision engine combining rules and ML"""

    # Action mappings for decision types
    DECISION_ACTIONS = {
        DecisionType.CLOSE_FALSE_POSITIVE: [],
        DecisionType.CLOSE_TRUE_POSITIVE_HANDLED: [],
        DecisionType.ESCALATE_TO_TIER2: [ActionType.CREATE_TICKET, ActionType.SEND_NOTIFICATION],
        DecisionType.ESCALATE_TO_TIER3: [ActionType.CREATE_TICKET, ActionType.SEND_NOTIFICATION],
        DecisionType.ESCALATE_TO_INCIDENT_RESPONSE: [
            ActionType.CREATE_TICKET, ActionType.SEND_NOTIFICATION, ActionType.ADD_TO_WATCHLIST
        ],
        DecisionType.AUTO_REMEDIATE: [ActionType.BLOCK_IP_FIREWALL, ActionType.ADD_TO_WATCHLIST],
        DecisionType.BLOCK_IP: [ActionType.BLOCK_IP_FIREWALL, ActionType.BLOCK_IP_PROXY],
        DecisionType.ISOLATE_ENDPOINT: [ActionType.ISOLATE_ENDPOINT, ActionType.SEND_NOTIFICATION],
        DecisionType.DISABLE_USER: [ActionType.DISABLE_USER_ACCOUNT, ActionType.REVOKE_SESSIONS],
        DecisionType.RESET_PASSWORD: [ActionType.FORCE_PASSWORD_RESET, ActionType.SEND_NOTIFICATION],
        DecisionType.QUARANTINE_FILE: [ActionType.QUARANTINE_FILE],
        DecisionType.MONITOR: [ActionType.ADD_TO_WATCHLIST],
        DecisionType.GATHER_MORE_INFO: [],
        DecisionType.PENDING_HUMAN_REVIEW: [ActionType.CREATE_TICKET]
    }

    # Decisions that can auto-execute
    AUTO_EXECUTABLE_DECISIONS = {
        DecisionType.CLOSE_FALSE_POSITIVE,
        DecisionType.MONITOR,
        DecisionType.BLOCK_IP,  # Can be auto-executed with high confidence
        DecisionType.QUARANTINE_FILE  # Can be auto-executed with high confidence
    }

    # Decisions requiring human approval
    APPROVAL_REQUIRED_DECISIONS = {
        DecisionType.ISOLATE_ENDPOINT,
        DecisionType.DISABLE_USER,
        DecisionType.ESCALATE_TO_INCIDENT_RESPONSE
    }

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize decision engine"""
        self.config = config or {}
        self.model_path = Path(self.config.get('model_path', '/tmp/tsunami_soc_models'))
        self.model_path.mkdir(parents=True, exist_ok=True)

        # Auto-execution thresholds
        self.auto_execute_confidence_threshold = self.config.get('auto_execute_threshold', 0.85)
        self.approval_confidence_threshold = self.config.get('approval_threshold', 0.7)

        # Initialize decision rules
        self.rules: List[DecisionRule] = [
            FalsePositiveRule(),
            CriticalThreatRule(),
            AutoRemediationRule(),
            EscalationRule(),
            MonitoringRule()
        ]
        # Sort by priority (higher first)
        self.rules.sort(key=lambda r: r.priority, reverse=True)

        # ML model for decision support
        self.ml_model: Optional[RandomForestClassifier] = None
        self.decision_encoder: Optional[LabelEncoder] = None
        self._load_or_train_model()

        # Decision history
        self.decisions: Dict[str, Decision] = {}

        # Feedback for learning
        self.feedback_data: List[Dict[str, Any]] = []

    def _load_or_train_model(self):
        """Load or train the ML decision model"""
        model_file = self.model_path / 'decision_model.joblib'
        encoder_file = self.model_path / 'decision_encoder.joblib'

        if model_file.exists() and encoder_file.exists():
            try:
                self.ml_model = joblib.load(model_file)
                self.decision_encoder = joblib.load(encoder_file)
                logger.info("Loaded existing decision model")
                return
            except Exception as e:
                logger.warning(f"Failed to load decision model: {e}")

        # Train new model with synthetic data
        self._train_initial_model()

    def _train_initial_model(self):
        """Train initial decision model with synthetic data"""
        logger.info("Training initial decision model")

        # Generate synthetic training data
        training_data = self._generate_training_data()

        if len(training_data) < 100:
            logger.warning("Insufficient training data for ML model")
            return

        # Prepare features and labels
        features = np.array([d['features'] for d in training_data])
        labels = [d['decision'] for d in training_data]

        # Encode labels
        self.decision_encoder = LabelEncoder()
        encoded_labels = self.decision_encoder.fit_transform(labels)

        # Train model
        self.ml_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.ml_model.fit(features, encoded_labels)

        # Save model
        try:
            joblib.dump(self.ml_model, self.model_path / 'decision_model.joblib')
            joblib.dump(self.decision_encoder, self.model_path / 'decision_encoder.joblib')
            logger.info("Decision model trained and saved")
        except Exception as e:
            logger.error(f"Failed to save decision model: {e}")

    def _generate_training_data(self) -> List[Dict[str, Any]]:
        """Generate synthetic training data"""
        data = []

        # Define feature ranges for different scenarios
        scenarios = [
            # False positives
            {'decision': DecisionType.CLOSE_FALSE_POSITIVE.value, 'fp_prob': (0.7, 1.0),
             'severity': 0, 'priority': (0, 30), 'confidence': (0.8, 1.0)},
            # Critical escalation
            {'decision': DecisionType.ESCALATE_TO_INCIDENT_RESPONSE.value, 'fp_prob': (0, 0.2),
             'severity': 4, 'priority': (80, 100), 'confidence': (0.7, 1.0)},
            # Tier 2 escalation
            {'decision': DecisionType.ESCALATE_TO_TIER2.value, 'fp_prob': (0.1, 0.4),
             'severity': 3, 'priority': (50, 80), 'confidence': (0.5, 0.8)},
            # Auto-remediation
            {'decision': DecisionType.AUTO_REMEDIATE.value, 'fp_prob': (0, 0.3),
             'severity': 3, 'priority': (60, 90), 'confidence': (0.75, 1.0)},
            # Monitoring
            {'decision': DecisionType.MONITOR.value, 'fp_prob': (0.2, 0.5),
             'severity': 1, 'priority': (20, 50), 'confidence': (0.4, 0.7)},
            # Gather more info
            {'decision': DecisionType.GATHER_MORE_INFO.value, 'fp_prob': (0.3, 0.6),
             'severity': 2, 'priority': (30, 60), 'confidence': (0.3, 0.5)},
        ]

        for scenario in scenarios:
            for _ in range(100):  # 100 samples per scenario
                fp_prob = np.random.uniform(*scenario['fp_prob'])
                severity = scenario['severity']
                priority = np.random.uniform(*scenario['priority'])
                confidence = np.random.uniform(*scenario['confidence'])

                features = [
                    fp_prob,
                    severity / 4,  # Normalize
                    priority / 100,  # Normalize
                    confidence,
                    np.random.randint(0, 10),  # Affected assets
                    np.random.randint(0, 5),   # Threat intel matches
                    np.random.random(),        # Risk score
                    np.random.randint(0, 24),  # Hour of day
                ]

                data.append({
                    'features': features,
                    'decision': scenario['decision']
                })

        return data

    def _extract_features(self, context: Dict[str, Any]) -> np.ndarray:
        """Extract features from decision context"""
        classification = context.get('classification', {})
        investigation = context.get('investigation', {})
        alert = context.get('alert', {})

        # Severity to numeric
        severity_map = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'informational': 0}
        severity = severity_map.get(classification.get('severity', 'medium'), 2)

        features = [
            classification.get('false_positive_probability', 0.0),
            severity / 4,  # Normalize
            classification.get('priority_score', 50) / 100,  # Normalize
            classification.get('confidence', 0.5),
            len(investigation.get('affected_assets', [])),
            len([s for s in investigation.get('steps', [])
                 if s.get('data_source') == 'threat_intel' and
                 s.get('result', {}).get('intel_data', {}).get('found')]),
            self._calculate_risk_score(context) / 100,
            datetime.utcnow().hour
        ]

        return np.array([features])

    def _calculate_risk_score(self, context: Dict[str, Any]) -> float:
        """Calculate overall risk score"""
        classification = context.get('classification', {})
        investigation = context.get('investigation', {})

        # Base score from severity
        severity_scores = {'critical': 90, 'high': 70, 'medium': 50, 'low': 30, 'informational': 10}
        score = severity_scores.get(classification.get('severity', 'medium'), 50)

        # Adjust for affected assets
        affected_count = len(investigation.get('affected_assets', []))
        score += min(20, affected_count * 5)

        # Adjust for threat intel
        blast_radius = investigation.get('blast_radius', {})
        if blast_radius.get('estimated_impact') == 'critical':
            score += 20

        # Adjust for false positive probability
        fp_prob = classification.get('false_positive_probability', 0)
        score *= (1 - fp_prob * 0.5)

        return min(100, max(0, score))

    def _assess_risk(self, context: Dict[str, Any]) -> RiskAssessment:
        """Perform risk assessment"""
        classification = context.get('classification', {})
        investigation = context.get('investigation', {})
        alert = context.get('alert', {})

        risk_score = self._calculate_risk_score(context)

        # Determine risk level
        if risk_score >= 80:
            overall_risk = RiskLevel.CRITICAL
        elif risk_score >= 60:
            overall_risk = RiskLevel.HIGH
        elif risk_score >= 40:
            overall_risk = RiskLevel.MEDIUM
        elif risk_score >= 20:
            overall_risk = RiskLevel.LOW
        else:
            overall_risk = RiskLevel.MINIMAL

        # Risk factors
        factors = {
            'severity': classification.get('priority_score', 50),
            'confidence': classification.get('confidence', 0.5) * 100,
            'affected_assets': len(investigation.get('affected_assets', [])) * 10,
            'threat_intel_match': 30 if any(
                s.get('result', {}).get('intel_data', {}).get('found')
                for s in investigation.get('steps', [])
            ) else 0
        }

        # Business impact assessment
        affected_assets = investigation.get('affected_assets', [])
        critical_assets = [a for a in affected_assets if a.get('criticality') == 'critical']

        if critical_assets:
            business_impact = 'Critical - Core business systems affected'
        elif any(a.get('criticality') == 'high' for a in affected_assets):
            business_impact = 'High - Important systems affected'
        elif affected_assets:
            business_impact = 'Medium - Standard systems affected'
        else:
            business_impact = 'Low - Minimal business impact'

        # Data sensitivity
        category = classification.get('category', '')
        if 'exfiltration' in category or 'credential' in category:
            data_sensitivity = 'High - Sensitive data potentially exposed'
        else:
            data_sensitivity = 'Standard - No confirmed sensitive data exposure'

        # Threat actor capability
        threat_intel_found = any(
            s.get('result', {}).get('intel_data', {}).get('found')
            for s in investigation.get('steps', [])
        )
        if threat_intel_found:
            threat_actor_capability = 'High - Known threat actor/malware'
        elif classification.get('category') in ['intrusion', 'lateral_movement']:
            threat_actor_capability = 'Medium - Sophisticated attack pattern'
        else:
            threat_actor_capability = 'Low - Basic/automated attack'

        # Exploitability
        if classification.get('severity') in ['critical', 'high']:
            exploitability = 'High - Active exploitation'
        else:
            exploitability = 'Medium - Potential exploitation'

        # Recommendations
        recommendations = []
        if overall_risk in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("Immediate containment recommended")
        if threat_intel_found:
            recommendations.append("Block identified IOCs")
        if critical_assets:
            recommendations.append("Priority focus on critical assets")
        recommendations.append("Preserve evidence for analysis")

        return RiskAssessment(
            overall_risk=overall_risk,
            risk_score=risk_score,
            factors=factors,
            business_impact=business_impact,
            data_sensitivity=data_sensitivity,
            threat_actor_capability=threat_actor_capability,
            exploitability=exploitability,
            recommendations=recommendations
        )

    def _create_actions(
        self,
        decision_type: DecisionType,
        context: Dict[str, Any]
    ) -> List[Action]:
        """Create actions for a decision"""
        action_types = self.DECISION_ACTIONS.get(decision_type, [])
        actions = []

        alert = context.get('alert', {})
        investigation = context.get('investigation', {})

        for action_type in action_types:
            # Determine target based on action type
            target = ""
            parameters = {}

            if action_type in [ActionType.BLOCK_IP_FIREWALL, ActionType.BLOCK_IP_PROXY]:
                target = alert.get('dest_ip') or alert.get('source_ip') or "unknown"
                parameters = {'duration_hours': 24}

            elif action_type == ActionType.ISOLATE_ENDPOINT:
                target = alert.get('hostname') or "unknown"
                parameters = {'full_isolation': False}

            elif action_type == ActionType.DISABLE_USER_ACCOUNT:
                target = alert.get('username') or "unknown"
                parameters = {'notify_user': True}

            elif action_type == ActionType.QUARANTINE_FILE:
                target = alert.get('file_path') or "unknown"
                parameters = {'backup': True}

            elif action_type == ActionType.CREATE_TICKET:
                target = "ticketing_system"
                parameters = {
                    'title': f"SOC Alert: {alert.get('title', 'Security Alert')}",
                    'priority': context.get('classification', {}).get('severity', 'medium'),
                    'alert_id': alert.get('id')
                }

            elif action_type == ActionType.SEND_NOTIFICATION:
                target = "notification_system"
                parameters = {
                    'channel': 'soc',
                    'message': f"Alert: {alert.get('title', 'Security Alert')}"
                }

            elif action_type == ActionType.ADD_TO_WATCHLIST:
                iocs = []
                if alert.get('dest_ip'):
                    iocs.append({'type': 'ip', 'value': alert['dest_ip']})
                if alert.get('source_ip'):
                    iocs.append({'type': 'ip', 'value': alert['source_ip']})
                target = "watchlist"
                parameters = {'iocs': iocs, 'duration_days': 30}

            else:
                target = "system"
                parameters = {}

            actions.append(Action(
                id=str(uuid.uuid4()),
                action_type=action_type,
                target=target,
                parameters=parameters
            ))

        return actions

    def _evaluate_rules(self, context: Dict[str, Any]) -> List[Tuple[DecisionType, float, str]]:
        """Evaluate all rules and return matching decisions"""
        matches = []

        for rule in self.rules:
            try:
                result = rule.evaluate(context)
                if result:
                    matches.append(result)
            except Exception as e:
                logger.warning(f"Rule {rule.name} evaluation failed: {e}")

        return matches

    def _get_ml_prediction(self, context: Dict[str, Any]) -> Optional[Tuple[DecisionType, float]]:
        """Get ML model prediction"""
        if not self.ml_model or not self.decision_encoder:
            return None

        try:
            features = self._extract_features(context)
            probabilities = self.ml_model.predict_proba(features)[0]
            predicted_idx = np.argmax(probabilities)
            confidence = probabilities[predicted_idx]

            decision_value = self.decision_encoder.inverse_transform([predicted_idx])[0]
            decision_type = DecisionType(decision_value)

            return decision_type, confidence
        except Exception as e:
            logger.warning(f"ML prediction failed: {e}")
            return None

    def make_decision(
        self,
        alert_data: Dict[str, Any],
        classification: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> Decision:
        """Make autonomous decision for an alert"""
        context = {
            'alert': alert_data,
            'classification': classification,
            'investigation': investigation
        }

        # Evaluate rules
        rule_matches = self._evaluate_rules(context)

        # Get ML prediction
        ml_prediction = self._get_ml_prediction(context)

        # Assess risk
        risk_assessment = self._assess_risk(context)

        # Combine rule and ML decisions
        all_decisions = []

        for decision_type, confidence, reasoning in rule_matches:
            all_decisions.append((decision_type, confidence, reasoning, 'rule'))

        if ml_prediction:
            ml_type, ml_confidence = ml_prediction
            # Check if ML agrees with any rule
            rule_types = [d[0] for d in rule_matches]
            if ml_type not in rule_types:
                all_decisions.append((ml_type, ml_confidence * 0.8, 'ML model prediction', 'ml'))

        # Select best decision
        if all_decisions:
            # Sort by confidence
            all_decisions.sort(key=lambda x: x[1], reverse=True)
            best_decision = all_decisions[0]
            decision_type = best_decision[0]
            confidence = best_decision[1]
            reasoning = best_decision[2]
        else:
            # Default to pending human review
            decision_type = DecisionType.PENDING_HUMAN_REVIEW
            confidence = 0.5
            reasoning = "No clear decision - requires human review"

        # Determine if auto-executable
        auto_execute = (
            decision_type in self.AUTO_EXECUTABLE_DECISIONS and
            confidence >= self.auto_execute_confidence_threshold
        )

        # Determine if approval required
        requires_approval = (
            decision_type in self.APPROVAL_REQUIRED_DECISIONS or
            confidence < self.approval_confidence_threshold
        )

        # Create actions
        actions = self._create_actions(decision_type, context)

        # Build evidence list
        evidence = []
        if classification.get('is_false_positive'):
            evidence.append(f"False positive probability: {classification.get('false_positive_probability', 0):.2f}")
        evidence.append(f"Classification confidence: {classification.get('confidence', 0):.2f}")
        evidence.append(f"Priority score: {classification.get('priority_score', 0):.0f}")
        if investigation.get('affected_assets'):
            evidence.append(f"Affected assets: {len(investigation['affected_assets'])}")

        # Alternative decisions
        alternatives = [
            (d[0], d[1]) for d in all_decisions[1:4]
        ] if len(all_decisions) > 1 else []

        decision = Decision(
            id=str(uuid.uuid4()),
            alert_id=alert_data.get('id', str(uuid.uuid4())),
            decision_type=decision_type,
            confidence=confidence,
            risk_assessment=risk_assessment,
            recommended_actions=actions,
            auto_execute=auto_execute,
            requires_approval=requires_approval,
            reasoning=reasoning,
            evidence=evidence,
            alternative_decisions=alternatives
        )

        # Store decision
        self.decisions[decision.id] = decision

        logger.info(
            f"Decision made: {decision_type.value} "
            f"(confidence: {confidence:.2f}, auto_execute: {auto_execute})"
        )

        return decision

    def approve_decision(
        self,
        decision_id: str,
        approved_by: str,
        modifications: Dict[str, Any] = None
    ) -> Optional[Decision]:
        """Approve a decision for execution"""
        decision = self.decisions.get(decision_id)
        if not decision:
            return None

        decision.approved = True
        decision.approved_by = approved_by
        decision.approved_at = datetime.utcnow()

        # Apply modifications if any
        if modifications:
            if 'decision_type' in modifications:
                decision.decision_type = DecisionType(modifications['decision_type'])
            if 'actions' in modifications:
                # Update actions
                pass

        logger.info(f"Decision {decision_id} approved by {approved_by}")

        return decision

    def reject_decision(
        self,
        decision_id: str,
        rejected_by: str,
        reason: str,
        correct_decision: Optional[DecisionType] = None
    ):
        """Reject a decision and learn from feedback"""
        decision = self.decisions.get(decision_id)
        if not decision:
            return

        # Store feedback for learning
        self.feedback_data.append({
            'original_decision': decision.decision_type.value,
            'correct_decision': correct_decision.value if correct_decision else None,
            'confidence': decision.confidence,
            'rejected_by': rejected_by,
            'reason': reason,
            'timestamp': datetime.utcnow().isoformat()
        })

        # Retrain if enough feedback
        if len(self.feedback_data) >= 20:
            self._incorporate_feedback()

    def _incorporate_feedback(self):
        """Incorporate analyst feedback into model"""
        # This would retrain the model with feedback
        # Implementation depends on how much feedback data is available
        logger.info(f"Incorporating {len(self.feedback_data)} feedback samples")
        self.feedback_data = []

    def get_decision(self, decision_id: str) -> Optional[Decision]:
        """Get decision by ID"""
        return self.decisions.get(decision_id)

    def get_recent_decisions(self, limit: int = 50) -> List[Decision]:
        """Get recent decisions"""
        sorted_decisions = sorted(
            self.decisions.values(),
            key=lambda d: d.created_at,
            reverse=True
        )
        return sorted_decisions[:limit]

    def get_stats(self) -> Dict[str, Any]:
        """Get decision engine statistics"""
        decision_counts = {}
        for decision in self.decisions.values():
            dt = decision.decision_type.value
            decision_counts[dt] = decision_counts.get(dt, 0) + 1

        approved_count = sum(1 for d in self.decisions.values() if d.approved)

        return {
            'total_decisions': len(self.decisions),
            'approved_decisions': approved_count,
            'pending_approval': sum(
                1 for d in self.decisions.values()
                if d.requires_approval and not d.approved
            ),
            'by_type': decision_counts,
            'auto_execute_threshold': self.auto_execute_confidence_threshold,
            'approval_threshold': self.approval_confidence_threshold,
            'rules_count': len(self.rules),
            'ml_model_loaded': self.ml_model is not None,
            'pending_feedback': len(self.feedback_data)
        }


# Global decision engine instance
_decision_engine: Optional[DecisionEngine] = None


def get_decision_engine() -> DecisionEngine:
    """Get or create the global decision engine instance"""
    global _decision_engine
    if _decision_engine is None:
        _decision_engine = DecisionEngine()
    return _decision_engine
