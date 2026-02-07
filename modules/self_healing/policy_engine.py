#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI POLICY ENGINE v5.0
    JSON-Based Healing Policy Definitions
================================================================================

    Features:
    - JSON-based policy definitions
    - Condition-action rules
    - Severity thresholds
    - Cooldown periods
    - Approval workflows
    - Policy inheritance
    - Policy versioning

================================================================================
"""

import os
import json
import re
import logging
import threading
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Any, Union
from enum import Enum
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ConditionOperator(Enum):
    """Operators for condition evaluation"""
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    GREATER_EQUAL = "gte"
    LESS_EQUAL = "lte"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"  # Regex
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"


class ActionTrigger(Enum):
    """What triggers a policy action"""
    ANOMALY_DETECTED = "anomaly_detected"
    HEALTH_CHECK_FAILED = "health_check_failed"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    SCHEDULE = "schedule"
    MANUAL = "manual"


class ApprovalStatus(Enum):
    """Status of action approval"""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    AUTO_APPROVED = "auto_approved"


@dataclass
class PolicyCondition:
    """A single condition in a policy rule"""
    field: str
    operator: ConditionOperator
    value: Any
    case_sensitive: bool = True

    def evaluate(self, data: Dict) -> bool:
        """Evaluate condition against data"""
        # Get field value (supports nested fields with dot notation)
        field_value = self._get_field_value(data, self.field)

        if field_value is None and self.operator != ConditionOperator.EXISTS:
            return False

        # String comparison - handle case sensitivity
        if isinstance(field_value, str) and not self.case_sensitive:
            field_value = field_value.lower()
            if isinstance(self.value, str):
                compare_value = self.value.lower()
            else:
                compare_value = self.value
        else:
            compare_value = self.value

        if self.operator == ConditionOperator.EQUALS:
            return field_value == compare_value
        elif self.operator == ConditionOperator.NOT_EQUALS:
            return field_value != compare_value
        elif self.operator == ConditionOperator.GREATER_THAN:
            return field_value > compare_value
        elif self.operator == ConditionOperator.LESS_THAN:
            return field_value < compare_value
        elif self.operator == ConditionOperator.GREATER_EQUAL:
            return field_value >= compare_value
        elif self.operator == ConditionOperator.LESS_EQUAL:
            return field_value <= compare_value
        elif self.operator == ConditionOperator.CONTAINS:
            return compare_value in str(field_value)
        elif self.operator == ConditionOperator.NOT_CONTAINS:
            return compare_value not in str(field_value)
        elif self.operator == ConditionOperator.MATCHES:
            return bool(re.search(str(compare_value), str(field_value)))
        elif self.operator == ConditionOperator.IN:
            return field_value in compare_value
        elif self.operator == ConditionOperator.NOT_IN:
            return field_value not in compare_value
        elif self.operator == ConditionOperator.EXISTS:
            return field_value is not None

        return False

    def _get_field_value(self, data: Dict, field_path: str) -> Any:
        """Get field value supporting dot notation for nested fields"""
        parts = field_path.split('.')
        current = data

        for part in parts:
            if isinstance(current, dict):
                current = current.get(part)
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if idx < len(current) else None
            else:
                return None

            if current is None:
                return None

        return current

    def to_dict(self) -> Dict:
        return {
            'field': self.field,
            'operator': self.operator.value,
            'value': self.value,
            'case_sensitive': self.case_sensitive
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'PolicyCondition':
        return cls(
            field=data['field'],
            operator=ConditionOperator(data['operator']),
            value=data['value'],
            case_sensitive=data.get('case_sensitive', True)
        )


@dataclass
class PolicyAction:
    """Action to take when policy conditions are met"""
    type: str  # Maps to ActionType in auto_remediation
    target: str  # Dynamic target using template variables
    parameters: Dict = field(default_factory=dict)
    requires_approval: bool = False
    timeout_seconds: int = 60

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict) -> 'PolicyAction':
        return cls(
            type=data['type'],
            target=data['target'],
            parameters=data.get('parameters', {}),
            requires_approval=data.get('requires_approval', False),
            timeout_seconds=data.get('timeout_seconds', 60)
        )


@dataclass
class HealingPolicy:
    """A complete healing policy definition"""
    id: str
    name: str
    description: str
    enabled: bool
    priority: int  # Higher = evaluated first
    trigger: ActionTrigger
    conditions: List[PolicyCondition]
    conditions_logic: str  # "and" or "or"
    actions: List[PolicyAction]
    cooldown_seconds: int  # Min time between executions
    max_executions_per_hour: int
    severity_threshold: str  # Minimum severity to trigger
    requires_approval: bool
    tags: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    version: int = 1

    def evaluate(self, data: Dict) -> bool:
        """Evaluate if policy conditions are met"""
        if not self.enabled:
            return False

        if self.conditions_logic == 'and':
            return all(cond.evaluate(data) for cond in self.conditions)
        else:  # 'or'
            return any(cond.evaluate(data) for cond in self.conditions)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'priority': self.priority,
            'trigger': self.trigger.value,
            'conditions': [c.to_dict() for c in self.conditions],
            'conditions_logic': self.conditions_logic,
            'actions': [a.to_dict() for a in self.actions],
            'cooldown_seconds': self.cooldown_seconds,
            'max_executions_per_hour': self.max_executions_per_hour,
            'severity_threshold': self.severity_threshold,
            'requires_approval': self.requires_approval,
            'tags': self.tags,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'version': self.version
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'HealingPolicy':
        return cls(
            id=data['id'],
            name=data['name'],
            description=data.get('description', ''),
            enabled=data.get('enabled', True),
            priority=data.get('priority', 0),
            trigger=ActionTrigger(data['trigger']),
            conditions=[PolicyCondition.from_dict(c) for c in data.get('conditions', [])],
            conditions_logic=data.get('conditions_logic', 'and'),
            actions=[PolicyAction.from_dict(a) for a in data.get('actions', [])],
            cooldown_seconds=data.get('cooldown_seconds', 300),
            max_executions_per_hour=data.get('max_executions_per_hour', 10),
            severity_threshold=data.get('severity_threshold', 'low'),
            requires_approval=data.get('requires_approval', False),
            tags=data.get('tags', []),
            created_at=data.get('created_at', datetime.now().isoformat()),
            updated_at=data.get('updated_at', datetime.now().isoformat()),
            version=data.get('version', 1)
        )


@dataclass
class PolicyExecution:
    """Record of a policy execution"""
    id: str
    policy_id: str
    policy_name: str
    trigger_data: Dict
    actions_executed: List[Dict]
    status: str  # success, failed, pending_approval
    approval_status: ApprovalStatus
    approved_by: Optional[str] = None
    executed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['approval_status'] = self.approval_status.value
        return result


class PolicyEngine:
    """
    Policy engine for managing and executing healing policies.
    Supports JSON-based policy definitions with condition-action rules.
    """

    # Default policies directory
    DEFAULT_POLICIES_DIR = "/etc/tsunami/policies"

    # Built-in policies
    BUILTIN_POLICIES = [
        {
            'id': 'builtin-block-malicious-ip',
            'name': 'Block Known Malicious IP',
            'description': 'Automatically block connections from known malicious IPs',
            'enabled': True,
            'priority': 100,
            'trigger': 'anomaly_detected',
            'conditions': [
                {'field': 'type', 'operator': 'eq', 'value': 'known_bad_ip'}
            ],
            'conditions_logic': 'and',
            'actions': [
                {'type': 'block_ip', 'target': '{{dest_ip}}', 'parameters': {'duration_minutes': 1440}}
            ],
            'cooldown_seconds': 60,
            'max_executions_per_hour': 100,
            'severity_threshold': 'high',
            'requires_approval': False,
            'tags': ['security', 'network', 'auto']
        },
        {
            'id': 'builtin-kill-crypto-miner',
            'name': 'Kill Crypto Mining Processes',
            'description': 'Automatically kill detected crypto mining processes',
            'enabled': True,
            'priority': 90,
            'trigger': 'anomaly_detected',
            'conditions': [
                {'field': 'type', 'operator': 'eq', 'value': 'crypto_mining'}
            ],
            'conditions_logic': 'and',
            'actions': [
                {'type': 'kill_process', 'target': '{{process_id}}', 'parameters': {'force': True}}
            ],
            'cooldown_seconds': 30,
            'max_executions_per_hour': 50,
            'severity_threshold': 'high',
            'requires_approval': False,
            'tags': ['security', 'process', 'auto']
        },
        {
            'id': 'builtin-restart-failed-service',
            'name': 'Restart Failed Services',
            'description': 'Automatically restart services that have failed health checks',
            'enabled': True,
            'priority': 80,
            'trigger': 'health_check_failed',
            'conditions': [
                {'field': 'status', 'operator': 'eq', 'value': 'unhealthy'},
                {'field': 'check_type', 'operator': 'eq', 'value': 'service'}
            ],
            'conditions_logic': 'and',
            'actions': [
                {'type': 'restart_service', 'target': '{{service_name}}'}
            ],
            'cooldown_seconds': 300,
            'max_executions_per_hour': 5,
            'severity_threshold': 'medium',
            'requires_approval': False,
            'tags': ['availability', 'service', 'auto']
        },
        {
            'id': 'builtin-rate-limit-excessive-connections',
            'name': 'Rate Limit Excessive Connections',
            'description': 'Apply rate limiting to IPs making excessive connections',
            'enabled': True,
            'priority': 70,
            'trigger': 'anomaly_detected',
            'conditions': [
                {'field': 'type', 'operator': 'eq', 'value': 'excessive_connections'}
            ],
            'conditions_logic': 'and',
            'actions': [
                {'type': 'rate_limit', 'target': '{{source_ip}}', 'parameters': {'rate': '30/minute'}}
            ],
            'cooldown_seconds': 120,
            'max_executions_per_hour': 20,
            'severity_threshold': 'medium',
            'requires_approval': False,
            'tags': ['network', 'rate-limit', 'auto']
        },
        {
            'id': 'builtin-block-port-scanner',
            'name': 'Block Port Scanners',
            'description': 'Block IPs detected doing port scanning',
            'enabled': True,
            'priority': 95,
            'trigger': 'anomaly_detected',
            'conditions': [
                {'field': 'type', 'operator': 'eq', 'value': 'port_scan'}
            ],
            'conditions_logic': 'and',
            'actions': [
                {'type': 'block_ip', 'target': '{{source_ip}}', 'parameters': {'duration_minutes': 60}}
            ],
            'cooldown_seconds': 60,
            'max_executions_per_hour': 50,
            'severity_threshold': 'high',
            'requires_approval': False,
            'tags': ['security', 'network', 'auto']
        }
    ]

    def __init__(self, policies_dir: str = None, auto_remediation=None):
        """
        Initialize policy engine.

        Args:
            policies_dir: Directory containing JSON policy files
            auto_remediation: AutoRemediation instance for executing actions
        """
        self.policies_dir = policies_dir or self.DEFAULT_POLICIES_DIR
        self.auto_remediation = auto_remediation

        # State
        self._policies: Dict[str, HealingPolicy] = {}
        self._executions: List[PolicyExecution] = []
        self._pending_approvals: Dict[str, PolicyExecution] = {}
        self._last_execution: Dict[str, datetime] = {}  # Policy ID -> last execution time
        self._execution_counts: Dict[str, List[datetime]] = {}  # Policy ID -> execution times
        self._lock = threading.RLock()

        # Execution counter
        self._execution_counter = 0

        # Load built-in policies
        self._load_builtin_policies()

        # Load custom policies from directory
        self._load_policies_from_dir()

        logger.info("[POLICY_ENGINE] Initialized with %d policies", len(self._policies))

    def _load_builtin_policies(self):
        """Load built-in default policies"""
        for policy_data in self.BUILTIN_POLICIES:
            try:
                policy = HealingPolicy.from_dict(policy_data)
                self._policies[policy.id] = policy
            except Exception as e:
                logger.error("[POLICY_ENGINE] Failed to load builtin policy: %s", e)

    def _load_policies_from_dir(self):
        """Load policies from JSON files in policies directory"""
        if not os.path.exists(self.policies_dir):
            logger.info("[POLICY_ENGINE] Policies directory does not exist: %s", self.policies_dir)
            return

        for filename in os.listdir(self.policies_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.policies_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)

                    if isinstance(data, list):
                        # File contains multiple policies
                        for policy_data in data:
                            policy = HealingPolicy.from_dict(policy_data)
                            self._policies[policy.id] = policy
                    else:
                        # Single policy
                        policy = HealingPolicy.from_dict(data)
                        self._policies[policy.id] = policy

                    logger.info("[POLICY_ENGINE] Loaded policy file: %s", filename)

                except Exception as e:
                    logger.error("[POLICY_ENGINE] Failed to load policy file %s: %s", filename, e)

    def _generate_execution_id(self) -> str:
        """Generate unique execution ID"""
        self._execution_counter += 1
        return f"EXE-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._execution_counter:04d}"

    def _resolve_template(self, template: str, data: Dict) -> str:
        """Resolve template variables like {{field_name}}"""
        def replace_var(match):
            var_name = match.group(1)
            # Support nested fields
            parts = var_name.split('.')
            value = data
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part, '')
                else:
                    value = ''
                    break
            return str(value) if value else ''

        return re.sub(r'\{\{(\w+(?:\.\w+)*)\}\}', replace_var, template)

    def _check_cooldown(self, policy_id: str, cooldown_seconds: int) -> bool:
        """Check if policy is in cooldown period"""
        with self._lock:
            if policy_id not in self._last_execution:
                return True

            elapsed = datetime.now() - self._last_execution[policy_id]
            return elapsed.total_seconds() >= cooldown_seconds

    def _check_rate_limit(self, policy_id: str, max_per_hour: int) -> bool:
        """Check if policy execution rate limit is exceeded"""
        with self._lock:
            if policy_id not in self._execution_counts:
                return True

            # Count executions in last hour
            cutoff = datetime.now() - timedelta(hours=1)
            recent = [t for t in self._execution_counts[policy_id] if t > cutoff]
            self._execution_counts[policy_id] = recent

            return len(recent) < max_per_hour

    def _record_execution(self, policy_id: str):
        """Record policy execution time"""
        with self._lock:
            now = datetime.now()
            self._last_execution[policy_id] = now

            if policy_id not in self._execution_counts:
                self._execution_counts[policy_id] = []
            self._execution_counts[policy_id].append(now)

    # ==================== Policy Management ====================

    def add_policy(self, policy: HealingPolicy) -> bool:
        """Add a new policy"""
        with self._lock:
            if policy.id in self._policies:
                logger.warning("[POLICY_ENGINE] Policy %s already exists", policy.id)
                return False

            self._policies[policy.id] = policy
            logger.info("[POLICY_ENGINE] Added policy: %s", policy.name)
            return True

    def update_policy(self, policy: HealingPolicy) -> bool:
        """Update an existing policy"""
        with self._lock:
            if policy.id not in self._policies:
                logger.warning("[POLICY_ENGINE] Policy %s not found", policy.id)
                return False

            policy.updated_at = datetime.now().isoformat()
            policy.version = self._policies[policy.id].version + 1
            self._policies[policy.id] = policy
            logger.info("[POLICY_ENGINE] Updated policy: %s (v%d)", policy.name, policy.version)
            return True

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy"""
        with self._lock:
            if policy_id not in self._policies:
                return False

            del self._policies[policy_id]
            logger.info("[POLICY_ENGINE] Deleted policy: %s", policy_id)
            return True

    def get_policy(self, policy_id: str) -> Optional[HealingPolicy]:
        """Get a policy by ID"""
        with self._lock:
            return self._policies.get(policy_id)

    def list_policies(self, enabled_only: bool = False,
                     trigger: ActionTrigger = None,
                     tags: List[str] = None) -> List[HealingPolicy]:
        """List policies with optional filters"""
        with self._lock:
            policies = list(self._policies.values())

            if enabled_only:
                policies = [p for p in policies if p.enabled]

            if trigger:
                policies = [p for p in policies if p.trigger == trigger]

            if tags:
                policies = [p for p in policies if any(t in p.tags for t in tags)]

            # Sort by priority (highest first)
            policies.sort(key=lambda p: p.priority, reverse=True)

            return policies

    def enable_policy(self, policy_id: str) -> bool:
        """Enable a policy"""
        with self._lock:
            if policy_id not in self._policies:
                return False
            self._policies[policy_id].enabled = True
            return True

    def disable_policy(self, policy_id: str) -> bool:
        """Disable a policy"""
        with self._lock:
            if policy_id not in self._policies:
                return False
            self._policies[policy_id].enabled = False
            return True

    def save_policy_to_file(self, policy_id: str, filepath: str = None) -> bool:
        """Save a policy to JSON file"""
        with self._lock:
            if policy_id not in self._policies:
                return False

            policy = self._policies[policy_id]
            filepath = filepath or os.path.join(self.policies_dir, f"{policy_id}.json")

            os.makedirs(os.path.dirname(filepath), exist_ok=True)

            with open(filepath, 'w') as f:
                json.dump(policy.to_dict(), f, indent=2)

            logger.info("[POLICY_ENGINE] Saved policy to %s", filepath)
            return True

    # ==================== Policy Evaluation & Execution ====================

    def evaluate_policies(self, data: Dict,
                         trigger: ActionTrigger) -> List[HealingPolicy]:
        """Evaluate all matching policies for given trigger and data"""
        matching = []

        # Severity ordering for threshold comparison
        severity_order = ['low', 'medium', 'high', 'critical']
        data_severity = data.get('severity', 'low')
        if isinstance(data_severity, Enum):
            data_severity = data_severity.value
        data_severity_idx = severity_order.index(data_severity) if data_severity in severity_order else 0

        for policy in self.list_policies(enabled_only=True, trigger=trigger):
            # Check severity threshold
            threshold_idx = severity_order.index(policy.severity_threshold)
            if data_severity_idx < threshold_idx:
                continue

            # Evaluate conditions
            if policy.evaluate(data):
                matching.append(policy)

        return matching

    def execute_policy(self, policy: HealingPolicy, data: Dict) -> PolicyExecution:
        """Execute a policy's actions"""
        execution_id = self._generate_execution_id()

        # Check cooldown
        if not self._check_cooldown(policy.id, policy.cooldown_seconds):
            logger.info("[POLICY_ENGINE] Policy %s in cooldown", policy.name)
            return PolicyExecution(
                id=execution_id,
                policy_id=policy.id,
                policy_name=policy.name,
                trigger_data=data,
                actions_executed=[],
                status='skipped',
                approval_status=ApprovalStatus.AUTO_APPROVED,
                error="Policy in cooldown period"
            )

        # Check rate limit
        if not self._check_rate_limit(policy.id, policy.max_executions_per_hour):
            logger.info("[POLICY_ENGINE] Policy %s rate limit exceeded", policy.name)
            return PolicyExecution(
                id=execution_id,
                policy_id=policy.id,
                policy_name=policy.name,
                trigger_data=data,
                actions_executed=[],
                status='skipped',
                approval_status=ApprovalStatus.AUTO_APPROVED,
                error="Rate limit exceeded"
            )

        # Check if approval required
        if policy.requires_approval:
            execution = PolicyExecution(
                id=execution_id,
                policy_id=policy.id,
                policy_name=policy.name,
                trigger_data=data,
                actions_executed=[],
                status='pending_approval',
                approval_status=ApprovalStatus.PENDING
            )

            with self._lock:
                self._pending_approvals[execution_id] = execution

            logger.info("[POLICY_ENGINE] Policy %s requires approval: %s", policy.name, execution_id)
            return execution

        # Execute actions
        return self._execute_policy_actions(execution_id, policy, data)

    def _execute_policy_actions(self, execution_id: str, policy: HealingPolicy,
                               data: Dict) -> PolicyExecution:
        """Execute the actual policy actions"""
        actions_executed = []
        errors = []

        for action in policy.actions:
            # Resolve target template
            target = self._resolve_template(action.target, data)

            # Resolve parameter templates
            parameters = {}
            for key, value in action.parameters.items():
                if isinstance(value, str):
                    parameters[key] = self._resolve_template(value, data)
                else:
                    parameters[key] = value

            action_result = {
                'type': action.type,
                'target': target,
                'parameters': parameters,
                'status': 'pending'
            }

            # Execute if auto_remediation is available
            if self.auto_remediation:
                try:
                    result = self._execute_action(action.type, target, parameters, data)
                    action_result['status'] = 'success' if result else 'failed'
                    action_result['result'] = result
                except Exception as e:
                    action_result['status'] = 'error'
                    action_result['error'] = str(e)
                    errors.append(str(e))
            else:
                action_result['status'] = 'no_executor'

            actions_executed.append(action_result)

        # Record execution
        self._record_execution(policy.id)

        status = 'success' if not errors else 'partial_failure' if len(errors) < len(policy.actions) else 'failed'

        execution = PolicyExecution(
            id=execution_id,
            policy_id=policy.id,
            policy_name=policy.name,
            trigger_data=data,
            actions_executed=actions_executed,
            status=status,
            approval_status=ApprovalStatus.AUTO_APPROVED,
            completed_at=datetime.now().isoformat(),
            error="; ".join(errors) if errors else None
        )

        with self._lock:
            self._executions.append(execution)
            if len(self._executions) > 10000:
                self._executions = self._executions[-10000:]

        logger.info("[POLICY_ENGINE] Executed policy %s: %s", policy.name, status)
        return execution

    def _execute_action(self, action_type: str, target: str,
                       parameters: Dict, data: Dict) -> Optional[Dict]:
        """Execute a single remediation action"""
        if not self.auto_remediation:
            return None

        if action_type == 'block_ip':
            result = self.auto_remediation.block_ip(
                ip=target,
                reason=f"Policy execution",
                duration_minutes=parameters.get('duration_minutes', 0),
                anomaly_id=data.get('id')
            )
            return result.to_dict()

        elif action_type == 'unblock_ip':
            result = self.auto_remediation.unblock_ip(ip=target)
            return result.to_dict()

        elif action_type == 'kill_process':
            if target.isdigit():
                result = self.auto_remediation.kill_process(
                    pid=int(target),
                    force=parameters.get('force', False),
                    anomaly_id=data.get('id')
                )
            else:
                result = self.auto_remediation.kill_process(
                    name=target,
                    force=parameters.get('force', False),
                    anomaly_id=data.get('id')
                )
            return result.to_dict()

        elif action_type == 'restart_service':
            result = self.auto_remediation.restart_service(
                service_name=target,
                anomaly_id=data.get('id')
            )
            return result.to_dict()

        elif action_type == 'stop_service':
            result = self.auto_remediation.stop_service(
                service_name=target,
                anomaly_id=data.get('id')
            )
            return result.to_dict()

        elif action_type == 'quarantine_file':
            result = self.auto_remediation.quarantine_file(
                file_path=target,
                anomaly_id=data.get('id')
            )
            return result.to_dict()

        elif action_type == 'rate_limit':
            result = self.auto_remediation.rate_limit_ip(
                ip=target,
                rate=parameters.get('rate'),
                anomaly_id=data.get('id')
            )
            return result.to_dict()

        elif action_type == 'close_port':
            port = int(target.split('/')[0]) if '/' in target else int(target)
            protocol = target.split('/')[1] if '/' in target else 'tcp'
            result = self.auto_remediation.close_port(
                port=port,
                protocol=protocol,
                anomaly_id=data.get('id')
            )
            return result.to_dict()

        else:
            logger.warning("[POLICY_ENGINE] Unknown action type: %s", action_type)
            return None

    # ==================== Approval Workflow ====================

    def get_pending_approvals(self) -> List[PolicyExecution]:
        """Get all pending approval requests"""
        with self._lock:
            return list(self._pending_approvals.values())

    def approve_execution(self, execution_id: str, approved_by: str) -> Optional[PolicyExecution]:
        """Approve a pending execution"""
        with self._lock:
            if execution_id not in self._pending_approvals:
                return None

            execution = self._pending_approvals[execution_id]
            policy = self._policies.get(execution.policy_id)

            if not policy:
                return None

            # Execute the policy
            del self._pending_approvals[execution_id]

        result = self._execute_policy_actions(execution_id, policy, execution.trigger_data)
        result.approval_status = ApprovalStatus.APPROVED
        result.approved_by = approved_by

        return result

    def reject_execution(self, execution_id: str, rejected_by: str,
                        reason: str = "") -> Optional[PolicyExecution]:
        """Reject a pending execution"""
        with self._lock:
            if execution_id not in self._pending_approvals:
                return None

            execution = self._pending_approvals[execution_id]
            execution.approval_status = ApprovalStatus.REJECTED
            execution.status = 'rejected'
            execution.completed_at = datetime.now().isoformat()
            execution.error = f"Rejected by {rejected_by}: {reason}"

            del self._pending_approvals[execution_id]
            self._executions.append(execution)

        return execution

    # ==================== Execution History ====================

    def get_execution_history(self, hours: int = 24,
                             policy_id: str = None,
                             status: str = None) -> List[PolicyExecution]:
        """Get policy execution history"""
        cutoff = datetime.now() - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()

        with self._lock:
            results = []
            for execution in self._executions:
                if execution.executed_at < cutoff_str:
                    continue
                if policy_id and execution.policy_id != policy_id:
                    continue
                if status and execution.status != status:
                    continue
                results.append(execution)
            return results

    def get_summary(self) -> Dict:
        """Get policy engine summary"""
        with self._lock:
            policies = list(self._policies.values())

            return {
                'timestamp': datetime.now().isoformat(),
                'total_policies': len(policies),
                'enabled_policies': sum(1 for p in policies if p.enabled),
                'pending_approvals': len(self._pending_approvals),
                'executions_last_24h': len(self.get_execution_history(hours=24)),
                'policies_by_trigger': {
                    trigger.value: sum(1 for p in policies if p.trigger == trigger)
                    for trigger in ActionTrigger
                },
                'builtin_policies': [p.id for p in policies if p.id.startswith('builtin-')],
                'custom_policies': [p.id for p in policies if not p.id.startswith('builtin-')]
            }


# Singleton instance
_policy_engine: Optional[PolicyEngine] = None

def get_policy_engine(auto_remediation=None) -> PolicyEngine:
    """Get or create policy engine singleton"""
    global _policy_engine
    if _policy_engine is None:
        _policy_engine = PolicyEngine(auto_remediation=auto_remediation)
    return _policy_engine
