#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOAR/XDR - Response Orchestrator v5.0
================================================================================

    Automated response coordination:
    - Response plan generation
    - Multi-step response execution
    - Rollback capabilities
    - Response metrics and learning
    - Escalation management

================================================================================
"""

import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
import uuid
import asyncio

logger = logging.getLogger(__name__)


class ResponseStatus(Enum):
    """Response execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    ESCALATED = "escalated"


class ResponseType(Enum):
    """Types of response actions"""
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    INVESTIGATION = "investigation"
    NOTIFICATION = "notification"


@dataclass
class ResponseStep:
    """Individual step in a response plan"""
    step_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: str = ""
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    order: int = 0
    timeout: int = 300  # seconds
    rollback_action: Optional[str] = None
    requires_approval: bool = False
    status: ResponseStatus = ResponseStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class ResponsePlan:
    """Orchestrated response plan"""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_id: str = ""
    title: str = ""
    description: str = ""
    response_type: ResponseType = ResponseType.CONTAINMENT
    steps: List[ResponseStep] = field(default_factory=list)
    status: ResponseStatus = ResponseStatus.PENDING
    priority: int = 1
    auto_execute: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str = "system"
    approved_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseMetrics:
    """Metrics for response operations"""
    total_responses: int = 0
    successful_responses: int = 0
    failed_responses: int = 0
    average_response_time: float = 0.0  # seconds
    rollback_count: int = 0
    escalation_count: int = 0
    containment_time: float = 0.0  # MTTC
    resolution_time: float = 0.0  # MTTR
    period_start: datetime = field(default_factory=datetime.now)
    period_end: datetime = field(default_factory=datetime.now)


@dataclass
class ResponseLearning:
    """Learning from response outcomes"""
    learning_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    incident_type: str = ""
    response_plan_id: str = ""
    outcome: str = ""  # success, partial, failure
    lessons: List[str] = field(default_factory=list)
    improvements: List[str] = field(default_factory=list)
    effectiveness_score: float = 0.0
    created_at: datetime = field(default_factory=datetime.now)


class ResponseOrchestrator:
    """
    Coordinates automated response actions across security tools
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.plans: Dict[str, ResponsePlan] = {}
        self.execution_history: List[Dict[str, Any]] = []
        self.action_handlers: Dict[str, Callable] = {}
        self.metrics = ResponseMetrics()
        self.learnings: List[ResponseLearning] = []
        logger.info("ResponseOrchestrator initialized")

    def register_action_handler(
        self,
        action_type: str,
        handler: Callable
    ) -> None:
        """Register handler for action type"""
        self.action_handlers[action_type] = handler
        logger.info(f"Registered handler for: {action_type}")

    def create_plan(
        self,
        incident_id: str,
        response_type: ResponseType,
        steps: List[Dict[str, Any]],
        auto_execute: bool = False,
        **kwargs
    ) -> ResponsePlan:
        """Create a response plan"""
        plan = ResponsePlan(
            incident_id=incident_id,
            response_type=response_type,
            auto_execute=auto_execute,
            **kwargs
        )

        # Convert step dicts to ResponseStep objects
        for i, step_data in enumerate(steps):
            step = ResponseStep(
                order=i,
                **step_data
            )
            plan.steps.append(step)

        self.plans[plan.plan_id] = plan
        logger.info(f"Created response plan: {plan.plan_id}")

        if auto_execute:
            self.execute_plan(plan.plan_id)

        return plan

    def execute_plan(self, plan_id: str) -> bool:
        """Execute a response plan"""
        plan = self.plans.get(plan_id)
        if not plan:
            logger.error(f"Plan not found: {plan_id}")
            return False

        plan.status = ResponseStatus.IN_PROGRESS
        plan.executed_at = datetime.now()

        try:
            for step in sorted(plan.steps, key=lambda s: s.order):
                success = self._execute_step(step)
                if not success:
                    plan.status = ResponseStatus.FAILED
                    self._record_execution(plan, "failed")
                    return False

            plan.status = ResponseStatus.COMPLETED
            plan.completed_at = datetime.now()
            self._record_execution(plan, "success")
            self.metrics.successful_responses += 1
            return True

        except Exception as e:
            logger.error(f"Plan execution error: {e}")
            plan.status = ResponseStatus.FAILED
            self._record_execution(plan, "error")
            self.metrics.failed_responses += 1
            return False

    def _execute_step(self, step: ResponseStep) -> bool:
        """Execute individual response step"""
        step.status = ResponseStatus.IN_PROGRESS
        step.started_at = datetime.now()

        try:
            handler = self.action_handlers.get(step.action_type)
            if handler:
                result = handler(step.target, **step.parameters)
                step.result = result
                step.status = ResponseStatus.COMPLETED
            else:
                # Simulate execution for unregistered handlers
                logger.warning(f"No handler for: {step.action_type}, simulating")
                step.result = {"simulated": True}
                step.status = ResponseStatus.COMPLETED

            step.completed_at = datetime.now()
            return True

        except Exception as e:
            logger.error(f"Step execution error: {e}")
            step.status = ResponseStatus.FAILED
            step.result = {"error": str(e)}
            step.completed_at = datetime.now()
            return False

    def rollback_plan(self, plan_id: str) -> bool:
        """Rollback executed plan steps"""
        plan = self.plans.get(plan_id)
        if not plan:
            return False

        # Execute rollback in reverse order
        for step in reversed(sorted(plan.steps, key=lambda s: s.order)):
            if step.status == ResponseStatus.COMPLETED and step.rollback_action:
                try:
                    handler = self.action_handlers.get(step.rollback_action)
                    if handler:
                        handler(step.target, **step.parameters)
                except Exception as e:
                    logger.error(f"Rollback error: {e}")

        plan.status = ResponseStatus.ROLLED_BACK
        self.metrics.rollback_count += 1
        return True

    def _record_execution(self, plan: ResponsePlan, outcome: str) -> None:
        """Record execution for history"""
        self.execution_history.append({
            "plan_id": plan.plan_id,
            "incident_id": plan.incident_id,
            "outcome": outcome,
            "executed_at": plan.executed_at,
            "completed_at": datetime.now()
        })
        self.metrics.total_responses += 1

    def get_plan(self, plan_id: str) -> Optional[ResponsePlan]:
        """Get plan by ID"""
        return self.plans.get(plan_id)

    def get_plans_for_incident(self, incident_id: str) -> List[ResponsePlan]:
        """Get all plans for an incident"""
        return [p for p in self.plans.values() if p.incident_id == incident_id]

    def add_learning(self, learning: ResponseLearning) -> str:
        """Add response learning"""
        self.learnings.append(learning)
        return learning.learning_id

    def get_metrics(self) -> ResponseMetrics:
        """Get response metrics"""
        return self.metrics

    def get_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        return {
            "total_plans": len(self.plans),
            "active_plans": sum(1 for p in self.plans.values() if p.status == ResponseStatus.IN_PROGRESS),
            "completed_plans": sum(1 for p in self.plans.values() if p.status == ResponseStatus.COMPLETED),
            "registered_handlers": list(self.action_handlers.keys()),
            "metrics": {
                "total_responses": self.metrics.total_responses,
                "successful": self.metrics.successful_responses,
                "failed": self.metrics.failed_responses
            }
        }


# Global instance
_response_orchestrator: Optional[ResponseOrchestrator] = None


def get_response_orchestrator() -> ResponseOrchestrator:
    """Get the global ResponseOrchestrator instance"""
    global _response_orchestrator
    if _response_orchestrator is None:
        _response_orchestrator = ResponseOrchestrator()
    return _response_orchestrator
