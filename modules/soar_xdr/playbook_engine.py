#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOAR Playbook Engine v5.0
    JSON/YAML Playbook Execution with Full Control Flow
================================================================================

    Features:
    - JSON/YAML playbook definitions
    - Conditional logic (if/else/switch)
    - Loop support (for, while, foreach)
    - Variable substitution with Jinja2
    - Action execution with rollback capability
    - Parallel task execution
    - Human approval gates
    - Audit logging

================================================================================
"""

import asyncio
import json
import logging
import os
import re
import threading
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import yaml
from jinja2 import Environment, BaseLoader, StrictUndefined

logger = logging.getLogger(__name__)


class PlaybookStatus(Enum):
    """Playbook execution status."""
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class StepType(Enum):
    """Types of playbook steps."""
    ACTION = "action"
    CONDITION = "condition"
    LOOP = "loop"
    PARALLEL = "parallel"
    APPROVAL = "approval"
    DELAY = "delay"
    SUBPROCESS = "subprocess"
    SWITCH = "switch"


@dataclass
class PlaybookStep:
    """A single step in a playbook."""
    id: str
    name: str
    type: StepType
    action: Optional[str] = None
    params: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None
    on_success: Optional[str] = None
    on_failure: Optional[str] = None
    rollback_action: Optional[str] = None
    rollback_params: Dict[str, Any] = field(default_factory=dict)
    timeout: int = 300  # seconds
    retries: int = 0
    retry_delay: int = 5
    continue_on_error: bool = False
    children: List['PlaybookStep'] = field(default_factory=list)
    loop_var: Optional[str] = None
    loop_items: Optional[str] = None
    parallel_steps: List['PlaybookStep'] = field(default_factory=list)
    switch_cases: Dict[str, List['PlaybookStep']] = field(default_factory=dict)
    approvers: List[str] = field(default_factory=list)
    approval_timeout: int = 3600  # 1 hour


@dataclass
class Playbook:
    """A complete playbook definition."""
    id: str
    name: str
    description: str
    version: str
    author: str
    tags: List[str]
    severity: str
    trigger_conditions: Dict[str, Any]
    variables: Dict[str, Any]
    steps: List[PlaybookStep]
    created_at: datetime
    updated_at: datetime
    enabled: bool = True
    rollback_on_failure: bool = True
    max_executions: int = 10  # Max concurrent executions
    cooldown: int = 60  # Seconds between auto-triggers

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Playbook':
        """Create a Playbook from a dictionary."""
        steps = [cls._parse_step(s) for s in data.get('steps', [])]
        return cls(
            id=data.get('id', str(uuid.uuid4())),
            name=data['name'],
            description=data.get('description', ''),
            version=data.get('version', '1.0.0'),
            author=data.get('author', 'unknown'),
            tags=data.get('tags', []),
            severity=data.get('severity', 'medium'),
            trigger_conditions=data.get('trigger_conditions', {}),
            variables=data.get('variables', {}),
            steps=steps,
            created_at=datetime.fromisoformat(data['created_at']) if 'created_at' in data else datetime.utcnow(),
            updated_at=datetime.fromisoformat(data['updated_at']) if 'updated_at' in data else datetime.utcnow(),
            enabled=data.get('enabled', True),
            rollback_on_failure=data.get('rollback_on_failure', True),
            max_executions=data.get('max_executions', 10),
            cooldown=data.get('cooldown', 60)
        )

    @classmethod
    def _parse_step(cls, data: Dict[str, Any]) -> PlaybookStep:
        """Parse a step from dictionary."""
        step_type = StepType(data.get('type', 'action'))

        children = [cls._parse_step(s) for s in data.get('children', [])]
        parallel_steps = [cls._parse_step(s) for s in data.get('parallel_steps', [])]
        switch_cases = {}
        for case, case_steps in data.get('switch_cases', {}).items():
            switch_cases[case] = [cls._parse_step(s) for s in case_steps]

        return PlaybookStep(
            id=data.get('id', str(uuid.uuid4())),
            name=data['name'],
            type=step_type,
            action=data.get('action'),
            params=data.get('params', {}),
            condition=data.get('condition'),
            on_success=data.get('on_success'),
            on_failure=data.get('on_failure'),
            rollback_action=data.get('rollback_action'),
            rollback_params=data.get('rollback_params', {}),
            timeout=data.get('timeout', 300),
            retries=data.get('retries', 0),
            retry_delay=data.get('retry_delay', 5),
            continue_on_error=data.get('continue_on_error', False),
            children=children,
            loop_var=data.get('loop_var'),
            loop_items=data.get('loop_items'),
            parallel_steps=parallel_steps,
            switch_cases=switch_cases,
            approvers=data.get('approvers', []),
            approval_timeout=data.get('approval_timeout', 3600)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'author': self.author,
            'tags': self.tags,
            'severity': self.severity,
            'trigger_conditions': self.trigger_conditions,
            'variables': self.variables,
            'steps': [self._step_to_dict(s) for s in self.steps],
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'enabled': self.enabled,
            'rollback_on_failure': self.rollback_on_failure,
            'max_executions': self.max_executions,
            'cooldown': self.cooldown
        }

    def _step_to_dict(self, step: PlaybookStep) -> Dict[str, Any]:
        """Convert a step to dictionary."""
        return {
            'id': step.id,
            'name': step.name,
            'type': step.type.value,
            'action': step.action,
            'params': step.params,
            'condition': step.condition,
            'on_success': step.on_success,
            'on_failure': step.on_failure,
            'rollback_action': step.rollback_action,
            'rollback_params': step.rollback_params,
            'timeout': step.timeout,
            'retries': step.retries,
            'retry_delay': step.retry_delay,
            'continue_on_error': step.continue_on_error,
            'children': [self._step_to_dict(c) for c in step.children],
            'loop_var': step.loop_var,
            'loop_items': step.loop_items,
            'parallel_steps': [self._step_to_dict(p) for p in step.parallel_steps],
            'switch_cases': {k: [self._step_to_dict(s) for s in v] for k, v in step.switch_cases.items()},
            'approvers': step.approvers,
            'approval_timeout': step.approval_timeout
        }


@dataclass
class StepResult:
    """Result of a step execution."""
    step_id: str
    step_name: str
    status: str
    output: Any
    error: Optional[str]
    started_at: datetime
    completed_at: datetime
    retries_used: int = 0


@dataclass
class ExecutionContext:
    """Context for playbook execution."""
    execution_id: str
    playbook_id: str
    variables: Dict[str, Any]
    step_results: Dict[str, StepResult]
    completed_steps: List[str]
    rollback_stack: List[Tuple[str, str, Dict[str, Any]]]  # (step_id, rollback_action, params)
    started_at: datetime
    status: PlaybookStatus
    current_step: Optional[str] = None
    error: Optional[str] = None
    trigger_event: Optional[Dict[str, Any]] = None
    approval_requests: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def get_variable(self, name: str) -> Any:
        """Get a variable from context."""
        return self.variables.get(name)

    def set_variable(self, name: str, value: Any) -> None:
        """Set a variable in context."""
        self.variables[name] = value

    def add_step_result(self, result: StepResult) -> None:
        """Add a step result."""
        self.step_results[result.step_id] = result
        if result.status == 'success':
            self.completed_steps.append(result.step_id)


@dataclass
class PlaybookExecution:
    """A playbook execution record."""
    id: str
    playbook_id: str
    playbook_name: str
    status: PlaybookStatus
    started_at: datetime
    completed_at: Optional[datetime]
    trigger_event: Optional[Dict[str, Any]]
    variables: Dict[str, Any]
    step_results: List[Dict[str, Any]]
    error: Optional[str]
    executed_by: str


class ApprovalGate:
    """Handles human approval gates."""

    def __init__(self):
        self._pending_approvals: Dict[str, Dict[str, Any]] = {}
        self._approval_callbacks: Dict[str, Callable] = {}
        self._lock = threading.Lock()

    def request_approval(
        self,
        execution_id: str,
        step_id: str,
        step_name: str,
        approvers: List[str],
        timeout: int,
        context: Dict[str, Any]
    ) -> str:
        """Request approval for a step."""
        approval_id = str(uuid.uuid4())

        with self._lock:
            self._pending_approvals[approval_id] = {
                'execution_id': execution_id,
                'step_id': step_id,
                'step_name': step_name,
                'approvers': approvers,
                'timeout': timeout,
                'context': context,
                'requested_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(seconds=timeout),
                'status': 'pending',
                'approved_by': None,
                'approved_at': None,
                'comments': None
            }

        logger.info(f"Approval requested: {approval_id} for step {step_name}")
        return approval_id

    def approve(
        self,
        approval_id: str,
        approver: str,
        comments: Optional[str] = None
    ) -> bool:
        """Approve a pending approval request."""
        with self._lock:
            if approval_id not in self._pending_approvals:
                return False

            approval = self._pending_approvals[approval_id]
            if approval['status'] != 'pending':
                return False

            if approver not in approval['approvers'] and '*' not in approval['approvers']:
                return False

            if datetime.utcnow() > approval['expires_at']:
                approval['status'] = 'expired'
                return False

            approval['status'] = 'approved'
            approval['approved_by'] = approver
            approval['approved_at'] = datetime.utcnow()
            approval['comments'] = comments

            # Trigger callback if registered
            if approval_id in self._approval_callbacks:
                self._approval_callbacks[approval_id](True)

        logger.info(f"Approval {approval_id} approved by {approver}")
        return True

    def reject(
        self,
        approval_id: str,
        rejector: str,
        comments: Optional[str] = None
    ) -> bool:
        """Reject a pending approval request."""
        with self._lock:
            if approval_id not in self._pending_approvals:
                return False

            approval = self._pending_approvals[approval_id]
            if approval['status'] != 'pending':
                return False

            approval['status'] = 'rejected'
            approval['approved_by'] = rejector
            approval['approved_at'] = datetime.utcnow()
            approval['comments'] = comments

            if approval_id in self._approval_callbacks:
                self._approval_callbacks[approval_id](False)

        logger.info(f"Approval {approval_id} rejected by {rejector}")
        return True

    def get_status(self, approval_id: str) -> Optional[Dict[str, Any]]:
        """Get status of an approval request."""
        with self._lock:
            return self._pending_approvals.get(approval_id)

    def list_pending(self, approver: Optional[str] = None) -> List[Dict[str, Any]]:
        """List pending approval requests."""
        with self._lock:
            pending = []
            for aid, approval in self._pending_approvals.items():
                if approval['status'] == 'pending':
                    if approver is None or approver in approval['approvers'] or '*' in approval['approvers']:
                        pending.append({**approval, 'approval_id': aid})
            return pending

    def register_callback(self, approval_id: str, callback: Callable) -> None:
        """Register a callback for approval resolution."""
        self._approval_callbacks[approval_id] = callback


class PlaybookEngine:
    """
    SOAR Playbook Execution Engine.

    Executes security playbooks with full control flow support including
    conditions, loops, parallel execution, and human approval gates.
    """

    def __init__(
        self,
        playbook_dir: str = "/etc/tsunami/playbooks",
        max_workers: int = 10,
        action_registry: Optional[Dict[str, Callable]] = None
    ):
        self.playbook_dir = Path(playbook_dir)
        self.playbook_dir.mkdir(parents=True, exist_ok=True)

        self.max_workers = max_workers
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

        self._playbooks: Dict[str, Playbook] = {}
        self._executions: Dict[str, ExecutionContext] = {}
        self._execution_history: List[PlaybookExecution] = []

        self._action_registry: Dict[str, Callable] = action_registry or {}
        self._approval_gate = ApprovalGate()

        self._jinja_env = Environment(
            loader=BaseLoader(),
            undefined=StrictUndefined
        )

        self._lock = threading.Lock()
        self._last_trigger_times: Dict[str, datetime] = {}

        self._load_playbooks()
        logger.info(f"PlaybookEngine initialized with {len(self._playbooks)} playbooks")

    def _load_playbooks(self) -> None:
        """Load playbooks from directory."""
        for ext in ['*.yaml', '*.yml', '*.json']:
            for path in self.playbook_dir.glob(ext):
                try:
                    self.load_playbook_file(path)
                except Exception as e:
                    logger.error(f"Failed to load playbook {path}: {e}")

    def load_playbook_file(self, path: Path) -> Playbook:
        """Load a playbook from a file."""
        with open(path, 'r') as f:
            if path.suffix == '.json':
                data = json.load(f)
            else:
                data = yaml.safe_load(f)

        playbook = Playbook.from_dict(data)
        self._playbooks[playbook.id] = playbook
        logger.info(f"Loaded playbook: {playbook.name} ({playbook.id})")
        return playbook

    def register_action(self, name: str, handler: Callable) -> None:
        """Register an action handler."""
        self._action_registry[name] = handler
        logger.debug(f"Registered action: {name}")

    def register_actions(self, actions: Dict[str, Callable]) -> None:
        """Register multiple action handlers."""
        self._action_registry.update(actions)
        logger.debug(f"Registered {len(actions)} actions")

    def create_playbook(self, data: Dict[str, Any]) -> Playbook:
        """Create a new playbook from data."""
        playbook = Playbook.from_dict(data)
        self._playbooks[playbook.id] = playbook

        # Save to file
        filepath = self.playbook_dir / f"{playbook.id}.yaml"
        with open(filepath, 'w') as f:
            yaml.dump(playbook.to_dict(), f, default_flow_style=False)

        logger.info(f"Created playbook: {playbook.name} ({playbook.id})")
        return playbook

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        """Get a playbook by ID."""
        return self._playbooks.get(playbook_id)

    def list_playbooks(
        self,
        tags: Optional[List[str]] = None,
        enabled_only: bool = True
    ) -> List[Playbook]:
        """List playbooks with optional filtering."""
        playbooks = list(self._playbooks.values())

        if enabled_only:
            playbooks = [p for p in playbooks if p.enabled]

        if tags:
            playbooks = [p for p in playbooks if any(t in p.tags for t in tags)]

        return playbooks

    def delete_playbook(self, playbook_id: str) -> bool:
        """Delete a playbook."""
        if playbook_id not in self._playbooks:
            return False

        del self._playbooks[playbook_id]

        # Remove file
        for ext in ['.yaml', '.yml', '.json']:
            filepath = self.playbook_dir / f"{playbook_id}{ext}"
            if filepath.exists():
                filepath.unlink()
                break

        logger.info(f"Deleted playbook: {playbook_id}")
        return True

    def execute(
        self,
        playbook_id: str,
        variables: Optional[Dict[str, Any]] = None,
        trigger_event: Optional[Dict[str, Any]] = None,
        executed_by: str = "system"
    ) -> str:
        """Execute a playbook."""
        playbook = self._playbooks.get(playbook_id)
        if not playbook:
            raise ValueError(f"Playbook not found: {playbook_id}")

        if not playbook.enabled:
            raise ValueError(f"Playbook is disabled: {playbook_id}")

        # Check cooldown
        last_trigger = self._last_trigger_times.get(playbook_id)
        if last_trigger and (datetime.utcnow() - last_trigger).total_seconds() < playbook.cooldown:
            raise ValueError(f"Playbook is in cooldown period")

        # Check max concurrent executions
        active = sum(1 for e in self._executions.values()
                     if e.playbook_id == playbook_id and e.status == PlaybookStatus.RUNNING)
        if active >= playbook.max_executions:
            raise ValueError(f"Max concurrent executions reached for playbook")

        # Create execution context
        execution_id = str(uuid.uuid4())
        merged_vars = {**playbook.variables, **(variables or {})}

        # Add trigger event data to variables
        if trigger_event:
            merged_vars['event'] = trigger_event
            merged_vars['trigger'] = trigger_event

        context = ExecutionContext(
            execution_id=execution_id,
            playbook_id=playbook_id,
            variables=merged_vars,
            step_results={},
            completed_steps=[],
            rollback_stack=[],
            started_at=datetime.utcnow(),
            status=PlaybookStatus.PENDING,
            trigger_event=trigger_event
        )

        with self._lock:
            self._executions[execution_id] = context
            self._last_trigger_times[playbook_id] = datetime.utcnow()

        # Execute asynchronously
        self.executor.submit(self._execute_playbook, playbook, context, executed_by)

        logger.info(f"Started playbook execution: {execution_id} for {playbook.name}")
        return execution_id

    def _execute_playbook(
        self,
        playbook: Playbook,
        context: ExecutionContext,
        executed_by: str
    ) -> None:
        """Execute a playbook (internal)."""
        context.status = PlaybookStatus.RUNNING

        try:
            for step in playbook.steps:
                if context.status in [PlaybookStatus.CANCELLED, PlaybookStatus.FAILED]:
                    break

                self._execute_step(step, context)

            if context.status == PlaybookStatus.RUNNING:
                context.status = PlaybookStatus.COMPLETED

        except Exception as e:
            logger.error(f"Playbook execution failed: {e}")
            context.status = PlaybookStatus.FAILED
            context.error = str(e)

            # Rollback if configured
            if playbook.rollback_on_failure and context.rollback_stack:
                self._execute_rollback(context)

        # Record execution
        execution = PlaybookExecution(
            id=context.execution_id,
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            status=context.status,
            started_at=context.started_at,
            completed_at=datetime.utcnow(),
            trigger_event=context.trigger_event,
            variables=context.variables,
            step_results=[{
                'step_id': r.step_id,
                'step_name': r.step_name,
                'status': r.status,
                'output': r.output,
                'error': r.error,
                'started_at': r.started_at.isoformat(),
                'completed_at': r.completed_at.isoformat()
            } for r in context.step_results.values()],
            error=context.error,
            executed_by=executed_by
        )

        with self._lock:
            self._execution_history.append(execution)
            # Keep last 1000 executions
            if len(self._execution_history) > 1000:
                self._execution_history = self._execution_history[-1000:]

        logger.info(f"Playbook execution completed: {context.execution_id} - {context.status.value}")

    def _execute_step(self, step: PlaybookStep, context: ExecutionContext) -> StepResult:
        """Execute a single step."""
        context.current_step = step.id
        started_at = datetime.utcnow()

        try:
            # Check condition
            if step.condition:
                if not self._evaluate_condition(step.condition, context):
                    logger.debug(f"Step {step.name} skipped due to condition")
                    result = StepResult(
                        step_id=step.id,
                        step_name=step.name,
                        status='skipped',
                        output=None,
                        error=None,
                        started_at=started_at,
                        completed_at=datetime.utcnow()
                    )
                    context.add_step_result(result)
                    return result

            # Execute based on step type
            if step.type == StepType.ACTION:
                output = self._execute_action_step(step, context)
            elif step.type == StepType.CONDITION:
                output = self._execute_condition_step(step, context)
            elif step.type == StepType.LOOP:
                output = self._execute_loop_step(step, context)
            elif step.type == StepType.PARALLEL:
                output = self._execute_parallel_step(step, context)
            elif step.type == StepType.APPROVAL:
                output = self._execute_approval_step(step, context)
            elif step.type == StepType.DELAY:
                output = self._execute_delay_step(step, context)
            elif step.type == StepType.SWITCH:
                output = self._execute_switch_step(step, context)
            elif step.type == StepType.SUBPROCESS:
                output = self._execute_subprocess_step(step, context)
            else:
                raise ValueError(f"Unknown step type: {step.type}")

            # Add to rollback stack if rollback action defined
            if step.rollback_action:
                context.rollback_stack.append((
                    step.id,
                    step.rollback_action,
                    self._render_params(step.rollback_params, context)
                ))

            result = StepResult(
                step_id=step.id,
                step_name=step.name,
                status='success',
                output=output,
                error=None,
                started_at=started_at,
                completed_at=datetime.utcnow()
            )
            context.add_step_result(result)

            # Store output in context
            context.set_variable(f"step_{step.id}_output", output)
            context.set_variable(f"last_output", output)

            logger.info(f"Step {step.name} completed successfully")
            return result

        except Exception as e:
            logger.error(f"Step {step.name} failed: {e}")

            # Retry logic
            for retry in range(step.retries):
                try:
                    import time
                    time.sleep(step.retry_delay)
                    logger.info(f"Retrying step {step.name} (attempt {retry + 2})")
                    return self._execute_step(step, context)
                except Exception:
                    continue

            result = StepResult(
                step_id=step.id,
                step_name=step.name,
                status='failed',
                output=None,
                error=str(e),
                started_at=started_at,
                completed_at=datetime.utcnow(),
                retries_used=step.retries
            )
            context.add_step_result(result)

            if not step.continue_on_error:
                context.status = PlaybookStatus.FAILED
                context.error = f"Step {step.name} failed: {e}"

            return result

    def _execute_action_step(self, step: PlaybookStep, context: ExecutionContext) -> Any:
        """Execute an action step."""
        if not step.action:
            raise ValueError(f"No action specified for step {step.name}")

        handler = self._action_registry.get(step.action)
        if not handler:
            raise ValueError(f"Unknown action: {step.action}")

        params = self._render_params(step.params, context)
        return handler(**params)

    def _execute_condition_step(self, step: PlaybookStep, context: ExecutionContext) -> Any:
        """Execute a conditional step."""
        condition = step.params.get('condition', step.condition)
        if not condition:
            raise ValueError(f"No condition specified for step {step.name}")

        result = self._evaluate_condition(condition, context)

        if result:
            for child in step.children:
                self._execute_step(child, context)
        elif step.params.get('else_steps'):
            for child_data in step.params['else_steps']:
                child = Playbook._parse_step(child_data)
                self._execute_step(child, context)

        return result

    def _execute_loop_step(self, step: PlaybookStep, context: ExecutionContext) -> List[Any]:
        """Execute a loop step."""
        results = []

        if step.loop_items:
            items = self._render_value(step.loop_items, context)
            if isinstance(items, str):
                items = context.get_variable(items) or []

            for i, item in enumerate(items):
                if step.loop_var:
                    context.set_variable(step.loop_var, item)
                context.set_variable('loop_index', i)

                for child in step.children:
                    result = self._execute_step(child, context)
                    results.append(result)

        elif step.params.get('count'):
            count = int(self._render_value(str(step.params['count']), context))
            for i in range(count):
                context.set_variable('loop_index', i)
                if step.loop_var:
                    context.set_variable(step.loop_var, i)

                for child in step.children:
                    result = self._execute_step(child, context)
                    results.append(result)

        elif step.params.get('while'):
            while self._evaluate_condition(step.params['while'], context):
                for child in step.children:
                    result = self._execute_step(child, context)
                    results.append(result)

        return results

    def _execute_parallel_step(self, step: PlaybookStep, context: ExecutionContext) -> List[Any]:
        """Execute steps in parallel."""
        futures = []
        results = []

        with ThreadPoolExecutor(max_workers=len(step.parallel_steps)) as executor:
            for parallel_step in step.parallel_steps:
                # Clone context for parallel execution
                parallel_context = ExecutionContext(
                    execution_id=context.execution_id,
                    playbook_id=context.playbook_id,
                    variables=dict(context.variables),
                    step_results=dict(context.step_results),
                    completed_steps=list(context.completed_steps),
                    rollback_stack=list(context.rollback_stack),
                    started_at=context.started_at,
                    status=context.status
                )
                futures.append(executor.submit(self._execute_step, parallel_step, parallel_context))

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    context.add_step_result(result)
                except Exception as e:
                    logger.error(f"Parallel step failed: {e}")
                    if not step.continue_on_error:
                        raise

        return results

    def _execute_approval_step(self, step: PlaybookStep, context: ExecutionContext) -> bool:
        """Execute an approval gate step."""
        context.status = PlaybookStatus.WAITING_APPROVAL

        approval_id = self._approval_gate.request_approval(
            execution_id=context.execution_id,
            step_id=step.id,
            step_name=step.name,
            approvers=step.approvers,
            timeout=step.approval_timeout,
            context={
                'playbook_id': context.playbook_id,
                'variables': context.variables,
                'step_params': step.params
            }
        )

        context.approval_requests[step.id] = {'approval_id': approval_id}

        # Wait for approval
        import time
        start_time = datetime.utcnow()
        while (datetime.utcnow() - start_time).total_seconds() < step.approval_timeout:
            status = self._approval_gate.get_status(approval_id)
            if status['status'] == 'approved':
                context.status = PlaybookStatus.RUNNING
                return True
            elif status['status'] in ['rejected', 'expired']:
                raise ValueError(f"Approval {status['status']}: {status.get('comments', 'No reason given')}")

            time.sleep(5)

        raise ValueError("Approval timeout exceeded")

    def _execute_delay_step(self, step: PlaybookStep, context: ExecutionContext) -> None:
        """Execute a delay step."""
        import time
        seconds = int(self._render_value(str(step.params.get('seconds', 0)), context))
        time.sleep(seconds)

    def _execute_switch_step(self, step: PlaybookStep, context: ExecutionContext) -> Any:
        """Execute a switch/case step."""
        value = self._render_value(step.params.get('value', ''), context)

        if str(value) in step.switch_cases:
            for case_step in step.switch_cases[str(value)]:
                self._execute_step(case_step, context)
            return value
        elif 'default' in step.switch_cases:
            for case_step in step.switch_cases['default']:
                self._execute_step(case_step, context)
            return 'default'

        return None

    def _execute_subprocess_step(self, step: PlaybookStep, context: ExecutionContext) -> str:
        """Execute a subprocess (nested playbook)."""
        sub_playbook_id = step.params.get('playbook_id')
        if not sub_playbook_id:
            raise ValueError("No playbook_id specified for subprocess")

        sub_vars = self._render_params(step.params.get('variables', {}), context)

        return self.execute(
            playbook_id=sub_playbook_id,
            variables=sub_vars,
            trigger_event=context.trigger_event
        )

    def _execute_rollback(self, context: ExecutionContext) -> None:
        """Execute rollback actions."""
        logger.info(f"Executing rollback for execution {context.execution_id}")
        context.status = PlaybookStatus.ROLLED_BACK

        while context.rollback_stack:
            step_id, action, params = context.rollback_stack.pop()

            try:
                handler = self._action_registry.get(action)
                if handler:
                    handler(**params)
                    logger.info(f"Rollback action {action} completed for step {step_id}")
            except Exception as e:
                logger.error(f"Rollback action {action} failed: {e}")

    def _evaluate_condition(self, condition: str, context: ExecutionContext) -> bool:
        """Evaluate a condition expression."""
        # Render any variables in the condition
        rendered = self._render_value(condition, context)

        # Create safe evaluation context
        eval_context = {
            'vars': context.variables,
            'results': context.step_results,
            'True': True,
            'False': False,
            'None': None,
            'len': len,
            'str': str,
            'int': int,
            'float': float,
            'bool': bool,
            'any': any,
            'all': all
        }

        try:
            return bool(eval(rendered, {"__builtins__": {}}, eval_context))
        except Exception as e:
            logger.error(f"Condition evaluation failed: {e}")
            return False

    def _render_value(self, value: str, context: ExecutionContext) -> str:
        """Render a value with Jinja2 templating."""
        if not isinstance(value, str) or '{{' not in value:
            return value

        try:
            template = self._jinja_env.from_string(value)
            return template.render(**context.variables)
        except Exception as e:
            logger.warning(f"Failed to render value: {e}")
            return value

    def _render_params(self, params: Dict[str, Any], context: ExecutionContext) -> Dict[str, Any]:
        """Render all parameters with Jinja2 templating."""
        rendered = {}
        for key, value in params.items():
            if isinstance(value, str):
                rendered[key] = self._render_value(value, context)
            elif isinstance(value, dict):
                rendered[key] = self._render_params(value, context)
            elif isinstance(value, list):
                rendered[key] = [
                    self._render_value(v, context) if isinstance(v, str) else v
                    for v in value
                ]
            else:
                rendered[key] = value
        return rendered

    def get_execution(self, execution_id: str) -> Optional[ExecutionContext]:
        """Get an execution context."""
        return self._executions.get(execution_id)

    def get_execution_status(self, execution_id: str) -> Optional[Dict[str, Any]]:
        """Get execution status."""
        context = self._executions.get(execution_id)
        if not context:
            return None

        return {
            'execution_id': context.execution_id,
            'playbook_id': context.playbook_id,
            'status': context.status.value,
            'current_step': context.current_step,
            'completed_steps': context.completed_steps,
            'started_at': context.started_at.isoformat(),
            'error': context.error,
            'approval_requests': context.approval_requests
        }

    def cancel_execution(self, execution_id: str) -> bool:
        """Cancel a running execution."""
        context = self._executions.get(execution_id)
        if not context:
            return False

        if context.status not in [PlaybookStatus.RUNNING, PlaybookStatus.WAITING_APPROVAL]:
            return False

        context.status = PlaybookStatus.CANCELLED
        logger.info(f"Cancelled execution: {execution_id}")
        return True

    def list_executions(
        self,
        playbook_id: Optional[str] = None,
        status: Optional[PlaybookStatus] = None,
        limit: int = 100
    ) -> List[PlaybookExecution]:
        """List execution history."""
        executions = self._execution_history

        if playbook_id:
            executions = [e for e in executions if e.playbook_id == playbook_id]

        if status:
            executions = [e for e in executions if e.status == status]

        return executions[-limit:]

    @property
    def approval_gate(self) -> ApprovalGate:
        """Get the approval gate."""
        return self._approval_gate


# Singleton instance
_playbook_engine: Optional[PlaybookEngine] = None


def get_playbook_engine(**kwargs) -> PlaybookEngine:
    """Get or create the playbook engine singleton."""
    global _playbook_engine
    if _playbook_engine is None:
        _playbook_engine = PlaybookEngine(**kwargs)
    return _playbook_engine
