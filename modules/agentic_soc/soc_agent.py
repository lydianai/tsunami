#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Agentic SOC - SOC Agent v5.0
================================================================================

    Autonomous SOC Agent capabilities:
    - Tier 1 alert triage automation
    - Contextual analysis of alerts
    - Decision making without human input
    - Action recommendation/execution
    - Learning from analyst feedback

================================================================================
"""

import asyncio
import logging
import uuid
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from pathlib import Path
import json

from .alert_classifier import (
    AlertClassifier, Alert, ClassificationResult, AlertCategory, SeverityLevel, get_classifier
)
from .investigation_agent import (
    InvestigationAgent, InvestigationResult, get_investigation_agent
)
from .decision_engine import (
    DecisionEngine, Decision, DecisionType, get_decision_engine
)
from .knowledge_base import (
    KnowledgeBase, PlaybookRecommendation, get_knowledge_base
)

logger = logging.getLogger(__name__)


class AgentState(Enum):
    """SOC agent states"""
    IDLE = "idle"
    ANALYZING = "analyzing"
    INVESTIGATING = "investigating"
    DECIDING = "deciding"
    EXECUTING = "executing"
    WAITING_APPROVAL = "waiting_approval"
    LEARNING = "learning"


class ActionStatus(Enum):
    """Action execution status"""
    PENDING = "pending"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    REQUIRES_APPROVAL = "requires_approval"


@dataclass
class AgentConfig:
    """SOC agent configuration"""
    auto_execute_enabled: bool = True
    auto_execute_confidence_threshold: float = 0.85
    escalation_enabled: bool = True
    learning_enabled: bool = True
    max_concurrent_analyses: int = 10
    analysis_timeout_seconds: int = 300
    action_timeout_seconds: int = 60

    def to_dict(self) -> Dict[str, Any]:
        return {
            'auto_execute_enabled': self.auto_execute_enabled,
            'auto_execute_confidence_threshold': self.auto_execute_confidence_threshold,
            'escalation_enabled': self.escalation_enabled,
            'learning_enabled': self.learning_enabled,
            'max_concurrent_analyses': self.max_concurrent_analyses,
            'analysis_timeout_seconds': self.analysis_timeout_seconds,
            'action_timeout_seconds': self.action_timeout_seconds
        }


@dataclass
class AgentAction:
    """Action taken by the agent"""
    id: str
    action_type: str
    target: str
    parameters: Dict[str, Any]
    status: ActionStatus
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'action_type': self.action_type,
            'target': self.target,
            'parameters': self.parameters,
            'status': self.status.value,
            'result': self.result,
            'error': self.error,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


@dataclass
class AgentDecision:
    """Decision made by the agent"""
    alert_id: str
    classification: ClassificationResult
    investigation: Optional[InvestigationResult]
    decision: Decision
    playbook_recommendations: List[PlaybookRecommendation]
    actions_taken: List[AgentAction]
    processing_time_seconds: float
    requires_human_review: bool
    review_reason: Optional[str] = None
    analyst_feedback: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'classification': self.classification.to_dict(),
            'investigation': self.investigation.to_dict() if self.investigation else None,
            'decision': self.decision.to_dict(),
            'playbook_recommendations': [p.to_dict() for p in self.playbook_recommendations],
            'actions_taken': [a.to_dict() for a in self.actions_taken],
            'processing_time_seconds': self.processing_time_seconds,
            'requires_human_review': self.requires_human_review,
            'review_reason': self.review_reason,
            'analyst_feedback': self.analyst_feedback,
            'created_at': self.created_at.isoformat()
        }


class SOCAgent:
    """Autonomous Security Operations Center Agent"""

    def __init__(self, config: Optional[AgentConfig] = None):
        """Initialize SOC Agent"""
        self.config = config or AgentConfig()
        self.state = AgentState.IDLE

        # Initialize components
        self.classifier = get_classifier()
        self.investigator = get_investigation_agent()
        self.decision_engine = get_decision_engine()
        self.knowledge_base = get_knowledge_base()

        # Processing queues
        self.alert_queue: List[Dict[str, Any]] = []
        self.processing: Dict[str, AgentDecision] = {}
        self.completed: Dict[str, AgentDecision] = {}
        self.pending_approval: Dict[str, AgentDecision] = {}

        # Action handlers
        self.action_handlers: Dict[str, Callable] = {
            'block_ip_firewall': self._handle_block_ip,
            'block_ip_proxy': self._handle_block_ip,
            'isolate_endpoint': self._handle_isolate_endpoint,
            'disable_user_account': self._handle_disable_user,
            'quarantine_file': self._handle_quarantine_file,
            'create_ticket': self._handle_create_ticket,
            'send_notification': self._handle_send_notification,
            'add_to_watchlist': self._handle_add_watchlist,
        }

        # Statistics
        self.stats = {
            'alerts_processed': 0,
            'auto_closed': 0,
            'escalated': 0,
            'actions_executed': 0,
            'false_positives_detected': 0,
            'true_positives_handled': 0
        }

        logger.info("SOC Agent initialized")

    async def analyze_alert(self, alert_data: Dict[str, Any]) -> AgentDecision:
        """Analyze an alert through the complete SOC pipeline"""
        start_time = datetime.utcnow()
        alert_id = alert_data.get('id', str(uuid.uuid4()))

        logger.info(f"Starting analysis of alert {alert_id}")

        self.state = AgentState.ANALYZING

        try:
            # Step 1: Classification
            alert = self._create_alert_object(alert_data)
            classification = self.classifier.classify(alert)

            logger.info(
                f"Alert {alert_id} classified: {classification.category.value} "
                f"({classification.severity.value}, confidence: {classification.confidence:.2f})"
            )

            # Step 2: Check for duplicates
            if classification.is_duplicate:
                logger.info(f"Alert {alert_id} is a duplicate of {classification.duplicate_of}")
                # Create minimal decision for duplicate
                decision = self._create_duplicate_decision(alert_id, classification)
                return self._finalize_decision(
                    alert_id, classification, None, decision, [], [], start_time, False
                )

            # Step 3: Investigation (skip for obvious false positives)
            investigation = None
            if not classification.is_false_positive or classification.false_positive_probability < 0.9:
                self.state = AgentState.INVESTIGATING
                investigation = await self.investigator.investigate(alert_data)
                logger.info(
                    f"Investigation complete for {alert_id}: "
                    f"{len(investigation.affected_assets)} assets, "
                    f"escalation: {investigation.requires_escalation}"
                )
            else:
                logger.info(f"Skipping investigation for high-confidence false positive {alert_id}")

            # Step 4: Get playbook recommendations
            playbook_recommendations = self.knowledge_base.get_playbook_recommendations(
                alert_data, classification.to_dict(),
                investigation.to_dict() if investigation else {}
            )

            # Step 5: Decision making
            self.state = AgentState.DECIDING
            decision = self.decision_engine.make_decision(
                alert_data,
                classification.to_dict(),
                investigation.to_dict() if investigation else {}
            )

            logger.info(
                f"Decision for {alert_id}: {decision.decision_type.value} "
                f"(confidence: {decision.confidence:.2f}, auto_execute: {decision.auto_execute})"
            )

            # Step 6: Execute actions (if auto-execute enabled and allowed)
            actions_taken = []
            if self.config.auto_execute_enabled and decision.auto_execute:
                self.state = AgentState.EXECUTING
                actions_taken = await self._execute_actions(decision)

            # Step 7: Determine if human review needed
            requires_review, review_reason = self._check_human_review_needed(
                classification, investigation, decision
            )

            # Step 8: Learn from this analysis
            if self.config.learning_enabled:
                self.state = AgentState.LEARNING
                self._update_knowledge_base(
                    alert_data, classification, investigation, decision
                )

            # Update stats
            self._update_stats(classification, decision)

            # Create final decision
            agent_decision = self._finalize_decision(
                alert_id, classification, investigation, decision,
                playbook_recommendations, actions_taken, start_time, requires_review, review_reason
            )

            # Store result
            if requires_review:
                self.pending_approval[alert_id] = agent_decision
            else:
                self.completed[alert_id] = agent_decision

            self.state = AgentState.IDLE
            return agent_decision

        except Exception as e:
            logger.error(f"Error analyzing alert {alert_id}: {e}")
            self.state = AgentState.IDLE
            raise

    def _create_alert_object(self, alert_data: Dict[str, Any]) -> Alert:
        """Create Alert object from raw data"""
        return Alert(
            id=alert_data.get('id', str(uuid.uuid4())),
            title=alert_data.get('title', 'Unknown Alert'),
            description=alert_data.get('description', ''),
            source=alert_data.get('source', 'unknown'),
            timestamp=datetime.fromisoformat(
                alert_data.get('timestamp', datetime.utcnow().isoformat())
            ),
            raw_data=alert_data,
            source_ip=alert_data.get('source_ip'),
            dest_ip=alert_data.get('dest_ip'),
            source_port=alert_data.get('source_port'),
            dest_port=alert_data.get('dest_port'),
            protocol=alert_data.get('protocol'),
            username=alert_data.get('username'),
            hostname=alert_data.get('hostname'),
            domain=alert_data.get('domain'),
            indicators=alert_data.get('indicators', []),
            mitre_techniques=alert_data.get('mitre_techniques', []),
            initial_severity=alert_data.get('severity'),
            initial_category=alert_data.get('category')
        )

    def _create_duplicate_decision(
        self,
        alert_id: str,
        classification: ClassificationResult
    ) -> Decision:
        """Create a minimal decision for duplicate alerts"""
        from .decision_engine import RiskAssessment, RiskLevel, Action

        return Decision(
            id=str(uuid.uuid4()),
            alert_id=alert_id,
            decision_type=DecisionType.CLOSE_FALSE_POSITIVE,
            confidence=0.95,
            risk_assessment=RiskAssessment(
                overall_risk=RiskLevel.MINIMAL,
                risk_score=5.0,
                factors={'duplicate': 100},
                business_impact='None - duplicate alert',
                data_sensitivity='N/A',
                threat_actor_capability='N/A',
                exploitability='N/A',
                recommendations=['No action needed - duplicate']
            ),
            recommended_actions=[],
            auto_execute=True,
            requires_approval=False,
            reasoning=f"Duplicate of alert {classification.duplicate_of}",
            evidence=[f"Duplicate detected with alert {classification.duplicate_of}"],
            alternative_decisions=[]
        )

    def _check_human_review_needed(
        self,
        classification: ClassificationResult,
        investigation: Optional[InvestigationResult],
        decision: Decision
    ) -> Tuple[bool, Optional[str]]:
        """Determine if human review is required"""
        reasons = []

        # Low confidence classification
        if classification.confidence < 0.6:
            reasons.append(f"Low classification confidence ({classification.confidence:.2f})")

        # Decision requires approval
        if decision.requires_approval:
            reasons.append("Decision type requires human approval")

        # Critical severity
        if classification.severity == SeverityLevel.CRITICAL:
            reasons.append("Critical severity alert")

        # Investigation requires escalation
        if investigation and investigation.requires_escalation:
            reasons.append(f"Investigation escalation: {investigation.escalation_reason}")

        # High risk assessment
        if decision.risk_assessment.overall_risk.value == 'critical':
            reasons.append("Critical risk level")

        if reasons:
            return True, '; '.join(reasons)
        return False, None

    async def _execute_actions(self, decision: Decision) -> List[AgentAction]:
        """Execute recommended actions"""
        executed_actions = []

        for action in decision.recommended_actions:
            agent_action = AgentAction(
                id=action.id,
                action_type=action.action_type.value,
                target=action.target,
                parameters=action.parameters,
                status=ActionStatus.PENDING
            )

            handler = self.action_handlers.get(action.action_type.value)
            if handler:
                try:
                    agent_action.status = ActionStatus.EXECUTING
                    agent_action.started_at = datetime.utcnow()

                    result = await handler(action.target, action.parameters)

                    agent_action.status = ActionStatus.COMPLETED
                    agent_action.result = result
                    agent_action.completed_at = datetime.utcnow()

                    self.stats['actions_executed'] += 1
                    logger.info(f"Action {action.action_type.value} completed for {action.target}")

                except Exception as e:
                    agent_action.status = ActionStatus.FAILED
                    agent_action.error = str(e)
                    agent_action.completed_at = datetime.utcnow()
                    logger.error(f"Action {action.action_type.value} failed: {e}")
            else:
                agent_action.status = ActionStatus.SKIPPED
                agent_action.error = f"No handler for action type: {action.action_type.value}"

            executed_actions.append(agent_action)

        return executed_actions

    async def _handle_block_ip(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle IP blocking action"""
        # In production, this would integrate with firewall/proxy APIs
        logger.info(f"Blocking IP {target} for {params.get('duration_hours', 24)} hours")
        return {
            'blocked': True,
            'ip': target,
            'duration_hours': params.get('duration_hours', 24),
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _handle_isolate_endpoint(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle endpoint isolation action"""
        # In production, this would integrate with EDR APIs
        logger.info(f"Isolating endpoint {target}")
        return {
            'isolated': True,
            'hostname': target,
            'full_isolation': params.get('full_isolation', False),
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _handle_disable_user(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle user account disabling"""
        # In production, this would integrate with IAM/AD APIs
        logger.info(f"Disabling user account {target}")
        return {
            'disabled': True,
            'username': target,
            'notify_user': params.get('notify_user', True),
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _handle_quarantine_file(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file quarantine action"""
        # In production, this would integrate with EDR/AV APIs
        logger.info(f"Quarantining file {target}")
        return {
            'quarantined': True,
            'file_path': target,
            'backup_created': params.get('backup', True),
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _handle_create_ticket(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle ticket creation"""
        # In production, this would integrate with ticketing system APIs
        ticket_id = f"INC{uuid.uuid4().hex[:8].upper()}"
        logger.info(f"Created ticket {ticket_id}: {params.get('title', 'Security Alert')}")
        return {
            'ticket_id': ticket_id,
            'title': params.get('title'),
            'priority': params.get('priority'),
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _handle_send_notification(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle notification sending"""
        # In production, this would integrate with notification systems
        logger.info(f"Sending notification to {params.get('channel', 'soc')}")
        return {
            'sent': True,
            'channel': params.get('channel'),
            'message': params.get('message'),
            'timestamp': datetime.utcnow().isoformat()
        }

    async def _handle_add_watchlist(self, target: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle watchlist addition"""
        # In production, this would integrate with SIEM/TI platforms
        iocs = params.get('iocs', [])
        logger.info(f"Adding {len(iocs)} IOCs to watchlist")
        return {
            'added': True,
            'iocs_count': len(iocs),
            'duration_days': params.get('duration_days', 30),
            'timestamp': datetime.utcnow().isoformat()
        }

    def _update_knowledge_base(
        self,
        alert_data: Dict[str, Any],
        classification: ClassificationResult,
        investigation: Optional[InvestigationResult],
        decision: Decision
    ):
        """Update knowledge base with analysis results"""
        outcome = 'true_positive' if not classification.is_false_positive else 'false_positive'

        self.knowledge_base.store_incident(
            alert_id=alert_data.get('id', ''),
            classification=classification.to_dict(),
            investigation=investigation.to_dict() if investigation else {},
            decision=decision.to_dict(),
            outcome=outcome
        )

    def _update_stats(self, classification: ClassificationResult, decision: Decision):
        """Update agent statistics"""
        self.stats['alerts_processed'] += 1

        if classification.is_false_positive:
            self.stats['false_positives_detected'] += 1

        if decision.decision_type in [
            DecisionType.CLOSE_FALSE_POSITIVE,
            DecisionType.CLOSE_TRUE_POSITIVE_HANDLED
        ]:
            self.stats['auto_closed'] += 1

        if decision.decision_type in [
            DecisionType.ESCALATE_TO_TIER2,
            DecisionType.ESCALATE_TO_TIER3,
            DecisionType.ESCALATE_TO_INCIDENT_RESPONSE
        ]:
            self.stats['escalated'] += 1

        if decision.decision_type == DecisionType.CLOSE_TRUE_POSITIVE_HANDLED:
            self.stats['true_positives_handled'] += 1

    def _finalize_decision(
        self,
        alert_id: str,
        classification: ClassificationResult,
        investigation: Optional[InvestigationResult],
        decision: Decision,
        playbook_recommendations: List[PlaybookRecommendation],
        actions_taken: List[AgentAction],
        start_time: datetime,
        requires_review: bool,
        review_reason: Optional[str] = None
    ) -> AgentDecision:
        """Finalize and create the agent decision"""
        processing_time = (datetime.utcnow() - start_time).total_seconds()

        return AgentDecision(
            alert_id=alert_id,
            classification=classification,
            investigation=investigation,
            decision=decision,
            playbook_recommendations=playbook_recommendations,
            actions_taken=actions_taken,
            processing_time_seconds=processing_time,
            requires_human_review=requires_review,
            review_reason=review_reason
        )

    def submit_alert(self, alert_data: Dict[str, Any]) -> str:
        """Submit an alert for processing"""
        alert_id = alert_data.get('id', str(uuid.uuid4()))
        alert_data['id'] = alert_id
        self.alert_queue.append(alert_data)
        logger.info(f"Alert {alert_id} submitted to queue")
        return alert_id

    async def process_queue(self):
        """Process alerts in the queue"""
        while self.alert_queue:
            alert_data = self.alert_queue.pop(0)
            try:
                await self.analyze_alert(alert_data)
            except Exception as e:
                logger.error(f"Failed to process alert: {e}")

    def provide_feedback(
        self,
        alert_id: str,
        correct_category: Optional[AlertCategory] = None,
        correct_severity: Optional[SeverityLevel] = None,
        was_false_positive: Optional[bool] = None,
        correct_decision: Optional[DecisionType] = None,
        analyst_notes: Optional[str] = None
    ):
        """Provide analyst feedback for learning"""
        # Get the decision
        decision = self.completed.get(alert_id) or self.pending_approval.get(alert_id)
        if not decision:
            logger.warning(f"No decision found for alert {alert_id}")
            return

        # Update classifier
        if correct_category or correct_severity or was_false_positive is not None:
            alert = self._create_alert_object(decision.classification.__dict__.get('raw_data', {}))
            self.classifier.learn_from_feedback(
                alert,
                correct_category or decision.classification.category,
                correct_severity or decision.classification.severity,
                was_false_positive if was_false_positive is not None else decision.classification.is_false_positive
            )

        # Update decision engine
        if correct_decision and correct_decision != decision.decision.decision_type:
            self.decision_engine.reject_decision(
                decision.decision.id,
                'analyst',
                analyst_notes or 'Manual correction',
                correct_decision
            )

        # Store feedback
        decision.analyst_feedback = analyst_notes

        logger.info(f"Feedback recorded for alert {alert_id}")

    def approve_decision(self, alert_id: str, analyst_id: str) -> bool:
        """Approve a pending decision"""
        if alert_id not in self.pending_approval:
            return False

        decision = self.pending_approval.pop(alert_id)

        # Approve in decision engine
        self.decision_engine.approve_decision(decision.decision.id, analyst_id)

        # Move to completed
        self.completed[alert_id] = decision

        logger.info(f"Decision for alert {alert_id} approved by {analyst_id}")
        return True

    def get_decision(self, alert_id: str) -> Optional[AgentDecision]:
        """Get decision for an alert"""
        return (
            self.completed.get(alert_id) or
            self.pending_approval.get(alert_id) or
            self.processing.get(alert_id)
        )

    def get_pending_decisions(self) -> List[AgentDecision]:
        """Get all decisions pending approval"""
        return list(self.pending_approval.values())

    def get_recent_decisions(self, limit: int = 50) -> List[AgentDecision]:
        """Get recent completed decisions"""
        all_decisions = list(self.completed.values()) + list(self.pending_approval.values())
        sorted_decisions = sorted(all_decisions, key=lambda d: d.created_at, reverse=True)
        return sorted_decisions[:limit]

    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status"""
        return {
            'queued': len(self.alert_queue),
            'processing': len(self.processing),
            'pending_approval': len(self.pending_approval),
            'completed': len(self.completed),
            'agent_state': self.state.value
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get agent statistics"""
        return {
            **self.stats,
            'config': self.config.to_dict(),
            'queue_status': self.get_queue_status(),
            'classifier_stats': self.classifier.get_stats(),
            'investigation_stats': self.investigator.get_stats(),
            'decision_stats': self.decision_engine.get_stats(),
            'knowledge_base_stats': self.knowledge_base.get_stats()
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        # Calculate average processing time
        completed = list(self.completed.values())
        avg_processing_time = 0.0
        if completed:
            avg_processing_time = sum(d.processing_time_seconds for d in completed) / len(completed)

        # Calculate auto-resolution rate
        auto_resolution_rate = 0.0
        if self.stats['alerts_processed'] > 0:
            auto_resolution_rate = self.stats['auto_closed'] / self.stats['alerts_processed']

        # Calculate escalation rate
        escalation_rate = 0.0
        if self.stats['alerts_processed'] > 0:
            escalation_rate = self.stats['escalated'] / self.stats['alerts_processed']

        # Calculate false positive rate
        false_positive_rate = 0.0
        if self.stats['alerts_processed'] > 0:
            false_positive_rate = self.stats['false_positives_detected'] / self.stats['alerts_processed']

        return {
            'total_alerts': self.stats['alerts_processed'],
            'average_processing_time_seconds': avg_processing_time,
            'auto_resolution_rate': auto_resolution_rate,
            'escalation_rate': escalation_rate,
            'false_positive_rate': false_positive_rate,
            'actions_executed': self.stats['actions_executed'],
            'pending_approval_count': len(self.pending_approval)
        }


# Global SOC agent instance
_soc_agent: Optional[SOCAgent] = None


def get_soc_agent() -> SOCAgent:
    """Get or create the global SOC agent instance"""
    global _soc_agent
    if _soc_agent is None:
        _soc_agent = SOCAgent()
    return _soc_agent
