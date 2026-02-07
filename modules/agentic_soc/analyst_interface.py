#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Agentic SOC - Analyst Interface v5.0
================================================================================

    Human-AI collaboration interface for SOC analysts:
    - Human review and feedback collection
    - Performance metrics and learning
    - Analyst findings management
    - Feedback-driven model improvement

================================================================================
"""

import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import uuid

logger = logging.getLogger(__name__)


class FeedbackType(Enum):
    """Types of analyst feedback"""
    CONFIRM = "confirm"           # Analyst confirms AI decision
    CORRECT = "correct"           # Analyst corrects AI decision
    ESCALATE = "escalate"         # Analyst escalates to higher tier
    FALSE_POSITIVE = "false_positive"
    TRUE_POSITIVE = "true_positive"
    NEEDS_INVESTIGATION = "needs_investigation"
    CLOSED = "closed"


class FindingSeverity(Enum):
    """Severity levels for findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Finding:
    """Analyst finding or annotation"""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str = ""
    analyst_id: str = ""
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.MEDIUM
    indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalystFeedback:
    """Feedback from analyst on AI decision"""
    feedback_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str = ""
    decision_id: str = ""
    analyst_id: str = ""
    feedback_type: FeedbackType = FeedbackType.CONFIRM
    original_decision: str = ""
    corrected_decision: Optional[str] = None
    explanation: str = ""
    confidence_adjustment: float = 0.0
    training_eligible: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceMetrics:
    """Performance metrics for analyst or AI"""
    entity_id: str = ""  # analyst_id or "ai"
    period_start: datetime = field(default_factory=datetime.now)
    period_end: datetime = field(default_factory=datetime.now)
    alerts_processed: int = 0
    average_response_time: float = 0.0  # seconds
    accuracy_rate: float = 0.0
    false_positive_rate: float = 0.0
    escalation_rate: float = 0.0
    feedback_given: int = 0
    confirmations: int = 0
    corrections: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class AnalystInterface:
    """
    Interface for human analysts to interact with AI SOC agent
    Handles feedback collection, performance tracking, and collaboration
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.analysts: Dict[str, Dict[str, Any]] = {}
        self.findings: Dict[str, Finding] = {}
        self.feedback_history: List[AnalystFeedback] = []
        self.performance_cache: Dict[str, PerformanceMetrics] = {}
        self.feedback_callbacks: List[Callable] = []
        logger.info("AnalystInterface initialized")

    def register_analyst(
        self,
        analyst_id: str,
        name: str,
        tier: int = 1,
        specializations: Optional[List[str]] = None
    ) -> bool:
        """Register an analyst"""
        self.analysts[analyst_id] = {
            "name": name,
            "tier": tier,
            "specializations": specializations or [],
            "registered_at": datetime.now(),
            "active": True
        }
        logger.info(f"Registered analyst: {analyst_id}")
        return True

    def submit_feedback(self, feedback: AnalystFeedback) -> bool:
        """Submit analyst feedback on AI decision"""
        self.feedback_history.append(feedback)

        # Notify callbacks
        for callback in self.feedback_callbacks:
            try:
                callback(feedback)
            except Exception as e:
                logger.error(f"Feedback callback error: {e}")

        logger.info(f"Feedback submitted: {feedback.feedback_type.value} for alert {feedback.alert_id}")
        return True

    def add_finding(self, finding: Finding) -> str:
        """Add analyst finding"""
        self.findings[finding.finding_id] = finding
        logger.info(f"Finding added: {finding.finding_id}")
        return finding.finding_id

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID"""
        return self.findings.get(finding_id)

    def get_findings_for_alert(self, alert_id: str) -> List[Finding]:
        """Get all findings for an alert"""
        return [f for f in self.findings.values() if f.alert_id == alert_id]

    def get_performance_metrics(
        self,
        entity_id: str,
        period_days: int = 30
    ) -> PerformanceMetrics:
        """Get performance metrics for analyst or AI"""
        # Return cached or calculate new metrics
        if entity_id in self.performance_cache:
            return self.performance_cache[entity_id]

        # Calculate metrics from feedback history
        relevant_feedback = [
            f for f in self.feedback_history
            if f.analyst_id == entity_id or entity_id == "ai"
        ]

        confirmations = sum(1 for f in relevant_feedback if f.feedback_type == FeedbackType.CONFIRM)
        corrections = sum(1 for f in relevant_feedback if f.feedback_type == FeedbackType.CORRECT)

        total = confirmations + corrections
        accuracy = confirmations / total if total > 0 else 0.0

        metrics = PerformanceMetrics(
            entity_id=entity_id,
            alerts_processed=total,
            accuracy_rate=accuracy,
            confirmations=confirmations,
            corrections=corrections,
            feedback_given=len(relevant_feedback)
        )

        self.performance_cache[entity_id] = metrics
        return metrics

    def get_pending_reviews(self, analyst_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get alerts pending human review"""
        # This would integrate with the alert queue
        return []

    def register_feedback_callback(self, callback: Callable) -> None:
        """Register callback for feedback events"""
        self.feedback_callbacks.append(callback)

    def get_status(self) -> Dict[str, Any]:
        """Get interface status"""
        return {
            "registered_analysts": len(self.analysts),
            "active_analysts": sum(1 for a in self.analysts.values() if a["active"]),
            "total_findings": len(self.findings),
            "total_feedback": len(self.feedback_history),
            "feedback_by_type": {}
        }


# Global instance
_analyst_interface: Optional[AnalystInterface] = None


def get_analyst_interface() -> AnalystInterface:
    """Get the global AnalystInterface instance"""
    global _analyst_interface
    if _analyst_interface is None:
        _analyst_interface = AnalystInterface()
    return _analyst_interface
