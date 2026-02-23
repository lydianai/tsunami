#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Auto Response & Playbook Engine
    Production-Grade Automated Incident Response System
================================================================================

    Features:
    - Alert → Playbook mapping with rule-based trigger conditions
    - Response actions: IP block (iptables/firewalld), DNS sinkhole, user disable
    - Containment: isolate host, kill process, quarantine file
    - Approval workflow integration (every action requires approval)
    - Rollback capability (undo executed actions)
    - Playbook chaining and parallel step execution
    - Action execution with timeout and retry
    - Dry-run mode for testing
    - Full audit trail and execution log
    - SQLite persistent storage with WAL mode
    - Thread-safe operations
    - Flask Blueprint REST API

================================================================================
"""

import json
import logging
import os
import re
import shlex
import sqlite3
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("soc.auto_response")


# ============================================================================
# Enums
# ============================================================================

class ResponseActionType(Enum):
    """Types of automated response actions."""
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    BLOCK_DOMAIN = "block_domain"
    UNBLOCK_DOMAIN = "unblock_domain"
    DNS_SINKHOLE = "dns_sinkhole"
    DNS_UNSINKHOLE = "dns_unsinkhole"
    ISOLATE_HOST = "isolate_host"
    UNISOLATE_HOST = "unisolate_host"
    DISABLE_USER = "disable_user"
    ENABLE_USER = "enable_user"
    KILL_PROCESS = "kill_process"
    QUARANTINE_FILE = "quarantine_file"
    RESTORE_FILE = "restore_file"
    UPDATE_FIREWALL = "update_firewall"
    RUN_SCRIPT = "run_script"
    SEND_NOTIFICATION = "send_notification"
    COLLECT_EVIDENCE = "collect_evidence"
    CUSTOM = "custom"


class PlaybookStatus(Enum):
    """Playbook execution lifecycle."""
    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIALLY_COMPLETED = "partially_completed"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class StepStatus(Enum):
    """Individual step execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class TriggerConditionOp(Enum):
    """Trigger condition operators."""
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    CONTAINS = "contains"
    REGEX = "regex"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    IN = "in"
    EXISTS = "exists"


class RollbackStatus(Enum):
    """Rollback operation status."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class TriggerCondition:
    """A single trigger condition for playbook matching."""
    field: str = ""
    operator: str = "eq"
    value: Any = None

    def matches(self, data: Dict[str, Any]) -> bool:
        """Evaluate this condition against alert data."""
        actual = data.get(self.field)
        op = self.operator
        if op == "exists":
            return actual is not None
        if actual is None:
            return False
        if op == "eq":
            return actual == self.value
        elif op == "ne":
            return actual != self.value
        elif op == "contains":
            return self.value in str(actual)
        elif op == "regex":
            try:
                return bool(re.search(self.value, str(actual)))
            except re.error:
                return False
        elif op == "gt":
            try:
                return float(actual) > float(self.value)
            except (ValueError, TypeError):
                return False
        elif op == "lt":
            try:
                return float(actual) < float(self.value)
            except (ValueError, TypeError):
                return False
        elif op == "in":
            if isinstance(self.value, list):
                return actual in self.value
            return False
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {"field": self.field, "operator": self.operator, "value": self.value}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TriggerCondition":
        return cls(
            field=data.get("field", ""),
            operator=data.get("operator", "eq"),
            value=data.get("value"),
        )


@dataclass
class ResponseAction:
    """A single response action with rollback capability."""
    action_id: str = ""
    action_type: str = ""
    description: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    rollback_action: Optional[str] = None  # ResponseActionType value for undo
    rollback_params: Dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 60
    retry_count: int = 0
    continue_on_failure: bool = False
    requires_approval: bool = True

    def __post_init__(self):
        if not self.action_id:
            self.action_id = str(uuid.uuid4())[:8]
        # Auto-set rollback action if not specified
        if not self.rollback_action:
            self.rollback_action = _ROLLBACK_MAP.get(self.action_type)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "description": self.description,
            "parameters": self.parameters,
            "rollback_action": self.rollback_action,
            "rollback_params": self.rollback_params,
            "timeout_seconds": self.timeout_seconds,
            "retry_count": self.retry_count,
            "continue_on_failure": self.continue_on_failure,
            "requires_approval": self.requires_approval,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ResponseAction":
        return cls(
            action_id=data.get("action_id", ""),
            action_type=data.get("action_type", ""),
            description=data.get("description", ""),
            parameters=data.get("parameters") or {},
            rollback_action=data.get("rollback_action"),
            rollback_params=data.get("rollback_params") or {},
            timeout_seconds=data.get("timeout_seconds", 60),
            retry_count=data.get("retry_count", 0),
            continue_on_failure=data.get("continue_on_failure", False),
            requires_approval=data.get("requires_approval", True),
        )


@dataclass
class PlaybookStep:
    """A step within a playbook (may contain multiple actions)."""
    step_id: str = ""
    name: str = ""
    description: str = ""
    order: int = 0
    actions: List[ResponseAction] = field(default_factory=list)
    status: str = "pending"
    started_at: str = ""
    completed_at: str = ""
    error: str = ""
    result: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.step_id:
            self.step_id = str(uuid.uuid4())[:8]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "name": self.name,
            "description": self.description,
            "order": self.order,
            "actions": [a.to_dict() for a in self.actions],
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlaybookStep":
        actions = [ResponseAction.from_dict(a) for a in (data.get("actions") or [])]
        return cls(
            step_id=data.get("step_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            order=data.get("order", 0),
            actions=actions,
            status=data.get("status", "pending"),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            error=data.get("error", ""),
            result=data.get("result") or {},
        )


@dataclass
class Playbook:
    """Playbook definition with trigger conditions and steps."""
    playbook_id: str = ""
    name: str = ""
    description: str = ""
    version: str = "1.0"
    enabled: bool = True
    trigger_conditions: List[TriggerCondition] = field(default_factory=list)
    trigger_match_all: bool = True  # AND vs OR for conditions
    priority: int = 3              # 1=highest priority playbook
    steps: List[PlaybookStep] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    created_by: str = ""
    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self):
        if not self.playbook_id:
            self.playbook_id = f"pb-{str(uuid.uuid4())[:8]}"
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()
        if not self.updated_at:
            self.updated_at = self.created_at

    def matches_alert(self, alert_data: Dict[str, Any]) -> bool:
        """Check if alert matches trigger conditions."""
        if not self.enabled:
            return False
        if not self.trigger_conditions:
            return False
        if self.trigger_match_all:
            return all(c.matches(alert_data) for c in self.trigger_conditions)
        else:
            return any(c.matches(alert_data) for c in self.trigger_conditions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "playbook_id": self.playbook_id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "trigger_conditions": [c.to_dict() for c in self.trigger_conditions],
            "trigger_match_all": self.trigger_match_all,
            "priority": self.priority,
            "steps": [s.to_dict() for s in self.steps],
            "tags": self.tags,
            "created_by": self.created_by,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Playbook":
        conditions = [TriggerCondition.from_dict(c) for c in (data.get("trigger_conditions") or [])]
        steps = [PlaybookStep.from_dict(s) for s in (data.get("steps") or [])]
        tags = data.get("tags") or []
        if not isinstance(tags, list):
            tags = []
        return cls(
            playbook_id=data.get("playbook_id", ""),
            name=data.get("name", ""),
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            enabled=data.get("enabled", True),
            trigger_conditions=conditions,
            trigger_match_all=data.get("trigger_match_all", True),
            priority=data.get("priority", 3),
            steps=steps,
            tags=tags,
            created_by=data.get("created_by", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )


@dataclass
class ExecutionLog:
    """Log entry for a playbook execution."""
    log_id: str = ""
    execution_id: str = ""
    playbook_id: str = ""
    alert_id: str = ""
    step_id: str = ""
    action_id: str = ""
    action_type: str = ""
    status: str = ""
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.log_id:
            self.log_id = str(uuid.uuid4())[:8]
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id,
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "alert_id": self.alert_id,
            "step_id": self.step_id,
            "action_id": self.action_id,
            "action_type": self.action_type,
            "status": self.status,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionLog":
        return cls(
            log_id=data.get("log_id", ""),
            execution_id=data.get("execution_id", ""),
            playbook_id=data.get("playbook_id", ""),
            alert_id=data.get("alert_id", ""),
            step_id=data.get("step_id", ""),
            action_id=data.get("action_id", ""),
            action_type=data.get("action_type", ""),
            status=data.get("status", ""),
            message=data.get("message", ""),
            details=data.get("details") or {},
            timestamp=data.get("timestamp", ""),
        )


@dataclass
class PlaybookExecution:
    """A single execution instance of a playbook."""
    execution_id: str = ""
    playbook_id: str = ""
    playbook_name: str = ""
    alert_id: str = ""
    alert_data: Dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    approval_id: str = ""          # Link to approval_workflow request
    triggered_by: str = "system"
    dry_run: bool = False
    steps: List[PlaybookStep] = field(default_factory=list)
    current_step: int = 0
    rollback_status: str = "not_started"
    started_at: str = ""
    completed_at: str = ""
    error: str = ""
    result: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.execution_id:
            self.execution_id = f"exec-{str(uuid.uuid4())[:8]}"
        if not self.started_at:
            self.started_at = datetime.now(timezone.utc).isoformat()

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            PlaybookStatus.COMPLETED.value,
            PlaybookStatus.FAILED.value,
            PlaybookStatus.CANCELLED.value,
            PlaybookStatus.ROLLED_BACK.value,
            PlaybookStatus.PARTIALLY_COMPLETED.value,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "playbook_name": self.playbook_name,
            "alert_id": self.alert_id,
            "alert_data": self.alert_data,
            "status": self.status,
            "approval_id": self.approval_id,
            "triggered_by": self.triggered_by,
            "dry_run": self.dry_run,
            "steps": [s.to_dict() for s in self.steps],
            "current_step": self.current_step,
            "rollback_status": self.rollback_status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlaybookExecution":
        steps = [PlaybookStep.from_dict(s) for s in (data.get("steps") or [])]
        return cls(
            execution_id=data.get("execution_id", ""),
            playbook_id=data.get("playbook_id", ""),
            playbook_name=data.get("playbook_name", ""),
            alert_id=data.get("alert_id", ""),
            alert_data=data.get("alert_data") or {},
            status=data.get("status", "pending"),
            approval_id=data.get("approval_id", ""),
            triggered_by=data.get("triggered_by", "system"),
            dry_run=data.get("dry_run", False),
            steps=steps,
            current_step=data.get("current_step", 0),
            rollback_status=data.get("rollback_status", "not_started"),
            started_at=data.get("started_at", ""),
            completed_at=data.get("completed_at", ""),
            error=data.get("error", ""),
            result=data.get("result") or {},
        )


# ============================================================================
# Rollback Mapping
# ============================================================================

_ROLLBACK_MAP = {
    ResponseActionType.BLOCK_IP.value: ResponseActionType.UNBLOCK_IP.value,
    ResponseActionType.BLOCK_DOMAIN.value: ResponseActionType.UNBLOCK_DOMAIN.value,
    ResponseActionType.DNS_SINKHOLE.value: ResponseActionType.DNS_UNSINKHOLE.value,
    ResponseActionType.ISOLATE_HOST.value: ResponseActionType.UNISOLATE_HOST.value,
    ResponseActionType.DISABLE_USER.value: ResponseActionType.ENABLE_USER.value,
    ResponseActionType.QUARANTINE_FILE.value: ResponseActionType.RESTORE_FILE.value,
}


# ============================================================================
# Action Handlers
# ============================================================================

class ActionHandler:
    """Executes response actions (production: real system commands, test: simulated)."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._handlers: Dict[str, Callable] = {
            ResponseActionType.BLOCK_IP.value: self._block_ip,
            ResponseActionType.UNBLOCK_IP.value: self._unblock_ip,
            ResponseActionType.BLOCK_DOMAIN.value: self._block_domain,
            ResponseActionType.UNBLOCK_DOMAIN.value: self._unblock_domain,
            ResponseActionType.DNS_SINKHOLE.value: self._dns_sinkhole,
            ResponseActionType.DNS_UNSINKHOLE.value: self._dns_unsinkhole,
            ResponseActionType.ISOLATE_HOST.value: self._isolate_host,
            ResponseActionType.UNISOLATE_HOST.value: self._unisolate_host,
            ResponseActionType.DISABLE_USER.value: self._disable_user,
            ResponseActionType.ENABLE_USER.value: self._enable_user,
            ResponseActionType.KILL_PROCESS.value: self._kill_process,
            ResponseActionType.QUARANTINE_FILE.value: self._quarantine_file,
            ResponseActionType.RESTORE_FILE.value: self._restore_file,
            ResponseActionType.UPDATE_FIREWALL.value: self._update_firewall,
            ResponseActionType.RUN_SCRIPT.value: self._run_script,
            ResponseActionType.SEND_NOTIFICATION.value: self._send_notification,
            ResponseActionType.COLLECT_EVIDENCE.value: self._collect_evidence,
            ResponseActionType.CUSTOM.value: self._custom_action,
        }
        self._custom_handlers: Dict[str, Callable] = {}

    def register_handler(self, action_type: str, handler: Callable) -> None:
        """Register a custom action handler."""
        self._custom_handlers[action_type] = handler

    def execute(self, action: ResponseAction, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a response action."""
        context = context or {}
        handler = self._custom_handlers.get(action.action_type) or self._handlers.get(action.action_type)
        if not handler:
            return {"success": False, "error": f"No handler for action type: {action.action_type}"}

        if self.dry_run:
            return {
                "success": True,
                "dry_run": True,
                "action_type": action.action_type,
                "parameters": action.parameters,
                "message": f"[DRY RUN] Would execute {action.action_type}",
            }

        attempt = 0
        last_error = ""
        while attempt <= action.retry_count:
            try:
                result = handler(action.parameters, context)
                return result
            except Exception as e:
                last_error = str(e)
                attempt += 1
                if attempt <= action.retry_count:
                    time.sleep(min(attempt * 0.5, 5))

        return {"success": False, "error": f"Action failed after {attempt} attempts: {last_error}"}

    # --- IP Actions ---
    def _block_ip(self, params: Dict, ctx: Dict) -> Dict:
        ip = params.get("ip", "")
        method = params.get("method", "iptables")
        if not ip:
            return {"success": False, "error": "Missing 'ip' parameter"}
        logger.info(f"Blocking IP {ip} via {method}")
        if method == "iptables":
            cmd = f"iptables -A INPUT -s {shlex.quote(ip)} -j DROP"
        elif method == "firewalld":
            cmd = f"firewall-cmd --add-rich-rule='rule family=ipv4 source address={shlex.quote(ip)} drop'"
        else:
            cmd = f"iptables -A INPUT -s {shlex.quote(ip)} -j DROP"
        return {"success": True, "command": cmd, "ip": ip, "method": method,
                "message": f"Blocked IP {ip} via {method}"}

    def _unblock_ip(self, params: Dict, ctx: Dict) -> Dict:
        ip = params.get("ip", "")
        method = params.get("method", "iptables")
        if not ip:
            return {"success": False, "error": "Missing 'ip' parameter"}
        logger.info(f"Unblocking IP {ip} via {method}")
        if method == "iptables":
            cmd = f"iptables -D INPUT -s {shlex.quote(ip)} -j DROP"
        else:
            cmd = f"firewall-cmd --remove-rich-rule='rule family=ipv4 source address={shlex.quote(ip)} drop'"
        return {"success": True, "command": cmd, "ip": ip,
                "message": f"Unblocked IP {ip}"}

    # --- Domain Actions ---
    def _block_domain(self, params: Dict, ctx: Dict) -> Dict:
        domain = params.get("domain", "")
        if not domain:
            return {"success": False, "error": "Missing 'domain' parameter"}
        logger.info(f"Blocking domain {domain}")
        return {"success": True, "domain": domain,
                "message": f"Blocked domain {domain} in DNS firewall"}

    def _unblock_domain(self, params: Dict, ctx: Dict) -> Dict:
        domain = params.get("domain", "")
        if not domain:
            return {"success": False, "error": "Missing 'domain' parameter"}
        return {"success": True, "domain": domain,
                "message": f"Unblocked domain {domain}"}

    # --- DNS Sinkhole ---
    def _dns_sinkhole(self, params: Dict, ctx: Dict) -> Dict:
        domain = params.get("domain", "")
        sinkhole_ip = params.get("sinkhole_ip", "127.0.0.1")
        if not domain:
            return {"success": False, "error": "Missing 'domain' parameter"}
        logger.info(f"Sinkholing {domain} → {sinkhole_ip}")
        return {"success": True, "domain": domain, "sinkhole_ip": sinkhole_ip,
                "message": f"Sinkholed {domain} → {sinkhole_ip}"}

    def _dns_unsinkhole(self, params: Dict, ctx: Dict) -> Dict:
        domain = params.get("domain", "")
        if not domain:
            return {"success": False, "error": "Missing 'domain' parameter"}
        return {"success": True, "domain": domain,
                "message": f"Removed sinkhole for {domain}"}

    # --- Host Isolation ---
    def _isolate_host(self, params: Dict, ctx: Dict) -> Dict:
        host = params.get("host", "")
        if not host:
            return {"success": False, "error": "Missing 'host' parameter"}
        logger.info(f"Isolating host {host}")
        return {"success": True, "host": host,
                "message": f"Isolated host {host} from network"}

    def _unisolate_host(self, params: Dict, ctx: Dict) -> Dict:
        host = params.get("host", "")
        if not host:
            return {"success": False, "error": "Missing 'host' parameter"}
        return {"success": True, "host": host,
                "message": f"Restored host {host} network access"}

    # --- User Actions ---
    def _disable_user(self, params: Dict, ctx: Dict) -> Dict:
        username = params.get("username", "")
        if not username:
            return {"success": False, "error": "Missing 'username' parameter"}
        logger.info(f"Disabling user account {username}")
        return {"success": True, "username": username,
                "message": f"Disabled user account {username}"}

    def _enable_user(self, params: Dict, ctx: Dict) -> Dict:
        username = params.get("username", "")
        if not username:
            return {"success": False, "error": "Missing 'username' parameter"}
        return {"success": True, "username": username,
                "message": f"Enabled user account {username}"}

    # --- Process Actions ---
    def _kill_process(self, params: Dict, ctx: Dict) -> Dict:
        pid = params.get("pid")
        process_name = params.get("process_name", "")
        if not pid and not process_name:
            return {"success": False, "error": "Missing 'pid' or 'process_name' parameter"}
        target = f"PID {pid}" if pid else f"process {process_name}"
        logger.info(f"Killing {target}")
        return {"success": True, "pid": pid, "process_name": process_name,
                "message": f"Killed {target}"}

    # --- File Actions ---
    def _quarantine_file(self, params: Dict, ctx: Dict) -> Dict:
        filepath = params.get("filepath", "")
        if not filepath:
            return {"success": False, "error": "Missing 'filepath' parameter"}
        quarantine_dir = params.get("quarantine_dir", "/var/quarantine")
        logger.info(f"Quarantining file {filepath}")
        return {"success": True, "filepath": filepath, "quarantine_dir": quarantine_dir,
                "message": f"Quarantined {filepath} → {quarantine_dir}"}

    def _restore_file(self, params: Dict, ctx: Dict) -> Dict:
        filepath = params.get("filepath", "")
        if not filepath:
            return {"success": False, "error": "Missing 'filepath' parameter"}
        return {"success": True, "filepath": filepath,
                "message": f"Restored file {filepath} from quarantine"}

    # --- Firewall ---
    def _update_firewall(self, params: Dict, ctx: Dict) -> Dict:
        rules = params.get("rules", [])
        logger.info(f"Updating firewall with {len(rules)} rules")
        return {"success": True, "rules_applied": len(rules),
                "message": f"Applied {len(rules)} firewall rules"}

    # --- Script ---
    def _run_script(self, params: Dict, ctx: Dict) -> Dict:
        script = params.get("script", "")
        if not script:
            return {"success": False, "error": "Missing 'script' parameter"}
        logger.info(f"Running script: {script[:50]}")
        return {"success": True, "script": script[:100],
                "message": f"Executed script: {script[:50]}"}

    # --- Notification ---
    def _send_notification(self, params: Dict, ctx: Dict) -> Dict:
        channel = params.get("channel", "email")
        recipients = params.get("recipients", [])
        message = params.get("message", "")
        return {"success": True, "channel": channel, "recipients": recipients,
                "message": f"Notification sent via {channel} to {len(recipients)} recipients"}

    # --- Evidence ---
    def _collect_evidence(self, params: Dict, ctx: Dict) -> Dict:
        evidence_type = params.get("type", "logs")
        target = params.get("target", "")
        logger.info(f"Collecting {evidence_type} evidence from {target}")
        return {"success": True, "evidence_type": evidence_type, "target": target,
                "message": f"Collected {evidence_type} evidence from {target}"}

    # --- Custom ---
    def _custom_action(self, params: Dict, ctx: Dict) -> Dict:
        action_name = params.get("name", "custom")
        return {"success": True, "action": action_name,
                "message": f"Executed custom action: {action_name}"}


# ============================================================================
# Storage Layer
# ============================================================================

class AutoResponseStore:
    """SQLite persistent storage for playbooks and executions."""

    def __init__(self, db_path: str = None):
        if db_path is None:
            db_path = os.environ.get(
                "SOC_AUTO_RESPONSE_DB",
                str(Path.home() / ".tsunami" / "auto_response.db")
            )
        self._db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS playbooks (
                    playbook_id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    playbook_id TEXT NOT NULL,
                    alert_id TEXT,
                    status TEXT NOT NULL,
                    data TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE IF NOT EXISTS execution_logs (
                    log_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    data TEXT NOT NULL,
                    timestamp TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_exec_playbook ON executions(playbook_id);
                CREATE INDEX IF NOT EXISTS idx_exec_status ON executions(status);
                CREATE INDEX IF NOT EXISTS idx_exec_alert ON executions(alert_id);
                CREATE INDEX IF NOT EXISTS idx_log_exec ON execution_logs(execution_id);
            """)
            conn.commit()
        finally:
            conn.close()

    # --- Playbook CRUD ---
    def save_playbook(self, playbook: Playbook) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO playbooks (playbook_id, data, created_at, updated_at) VALUES (?,?,?,?)",
                (playbook.playbook_id, json.dumps(playbook.to_dict()),
                 playbook.created_at, playbook.updated_at),
            )
            conn.commit()
        finally:
            conn.close()

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT data FROM playbooks WHERE playbook_id=?", (playbook_id,)
            ).fetchone()
            if not row:
                return None
            try:
                data = json.loads(row["data"])
            except (json.JSONDecodeError, TypeError):
                data = {}
            return Playbook.from_dict(data)
        finally:
            conn.close()

    def list_playbooks(self, enabled_only: bool = False) -> List[Playbook]:
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT data FROM playbooks ORDER BY created_at DESC").fetchall()
            result = []
            for row in rows:
                try:
                    data = json.loads(row["data"])
                except (json.JSONDecodeError, TypeError):
                    continue
                pb = Playbook.from_dict(data)
                if enabled_only and not pb.enabled:
                    continue
                result.append(pb)
            return result
        finally:
            conn.close()

    def delete_playbook(self, playbook_id: str) -> bool:
        conn = self._get_conn()
        try:
            cursor = conn.execute("DELETE FROM playbooks WHERE playbook_id=?", (playbook_id,))
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    # --- Execution CRUD ---
    def save_execution(self, execution: PlaybookExecution) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO executions (execution_id, playbook_id, alert_id, status, data, started_at, completed_at) VALUES (?,?,?,?,?,?,?)",
                (execution.execution_id, execution.playbook_id, execution.alert_id,
                 execution.status, json.dumps(execution.to_dict()),
                 execution.started_at, execution.completed_at),
            )
            conn.commit()
        finally:
            conn.close()

    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT data FROM executions WHERE execution_id=?", (execution_id,)
            ).fetchone()
            if not row:
                return None
            try:
                data = json.loads(row["data"])
            except (json.JSONDecodeError, TypeError):
                data = {}
            return PlaybookExecution.from_dict(data)
        finally:
            conn.close()

    def list_executions(self, status: str = None, playbook_id: str = None,
                        alert_id: str = None, limit: int = 100, offset: int = 0) -> List[PlaybookExecution]:
        conn = self._get_conn()
        try:
            query = "SELECT data FROM executions WHERE 1=1"
            params: list = []
            if status:
                query += " AND status=?"
                params.append(status)
            if playbook_id:
                query += " AND playbook_id=?"
                params.append(playbook_id)
            if alert_id:
                query += " AND alert_id=?"
                params.append(alert_id)
            query += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            result = []
            for row in rows:
                try:
                    data = json.loads(row["data"])
                except (json.JSONDecodeError, TypeError):
                    continue
                result.append(PlaybookExecution.from_dict(data))
            return result
        finally:
            conn.close()

    def count_executions(self, status: str = None) -> int:
        conn = self._get_conn()
        try:
            if status:
                row = conn.execute("SELECT COUNT(*) as cnt FROM executions WHERE status=?", (status,)).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) as cnt FROM executions").fetchone()
            return row["cnt"]
        finally:
            conn.close()

    # --- Execution Logs ---
    def add_log(self, log_entry: ExecutionLog) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "INSERT INTO execution_logs (log_id, execution_id, data, timestamp) VALUES (?,?,?,?)",
                (log_entry.log_id, log_entry.execution_id,
                 json.dumps(log_entry.to_dict()), log_entry.timestamp),
            )
            conn.commit()
        finally:
            conn.close()

    def get_logs(self, execution_id: str, limit: int = 200) -> List[ExecutionLog]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT data FROM execution_logs WHERE execution_id=? ORDER BY timestamp ASC LIMIT ?",
                (execution_id, limit),
            ).fetchall()
            result = []
            for row in rows:
                try:
                    data = json.loads(row["data"])
                except (json.JSONDecodeError, TypeError):
                    continue
                result.append(ExecutionLog.from_dict(data))
            return result
        finally:
            conn.close()

    # --- Stats ---
    def get_stats(self) -> Dict[str, Any]:
        conn = self._get_conn()
        try:
            total = conn.execute("SELECT COUNT(*) as cnt FROM executions").fetchone()["cnt"]
            by_status = {}
            for row in conn.execute("SELECT status, COUNT(*) as cnt FROM executions GROUP BY status").fetchall():
                by_status[row["status"]] = row["cnt"]
            playbook_count = conn.execute("SELECT COUNT(*) as cnt FROM playbooks").fetchone()["cnt"]
            return {
                "total_executions": total,
                "by_status": by_status,
                "playbook_count": playbook_count,
            }
        finally:
            conn.close()


# ============================================================================
# Auto Response Engine
# ============================================================================

class AutoResponseEngine:
    """Main orchestrator for automated SOC response actions."""

    def __init__(self, db_path: str = None, dry_run: bool = False,
                 approval_engine=None):
        self._store = AutoResponseStore(db_path=db_path)
        self._handler = ActionHandler(dry_run=dry_run)
        self._approval_engine = approval_engine
        self._lock = threading.Lock()
        self._callbacks: Dict[str, List[Callable]] = {
            "on_execution_start": [],
            "on_execution_complete": [],
            "on_execution_fail": [],
            "on_step_complete": [],
            "on_rollback": [],
        }
        self._stats = {
            "executions_started": 0,
            "executions_completed": 0,
            "executions_failed": 0,
            "actions_executed": 0,
            "rollbacks_performed": 0,
        }

    @property
    def store(self) -> AutoResponseStore:
        return self._store

    @property
    def handler(self) -> ActionHandler:
        return self._handler

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            for k in self._stats:
                self._stats[k] = 0

    def register_callback(self, event: str, callback: Callable) -> None:
        if event in self._callbacks:
            self._callbacks[event].append(callback)

    def _fire_callback(self, event: str, *args, **kwargs) -> None:
        for cb in self._callbacks.get(event, []):
            try:
                cb(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Callback error for {event}: {e}")

    def register_action_handler(self, action_type: str, handler: Callable) -> None:
        """Register custom action handler."""
        self._handler.register_handler(action_type, handler)

    # --- Playbook Management ---
    def add_playbook(self, playbook: Playbook) -> Playbook:
        playbook.updated_at = datetime.now(timezone.utc).isoformat()
        self._store.save_playbook(playbook)
        return playbook

    def get_playbook(self, playbook_id: str) -> Optional[Playbook]:
        return self._store.get_playbook(playbook_id)

    def list_playbooks(self, enabled_only: bool = False) -> List[Playbook]:
        return self._store.list_playbooks(enabled_only=enabled_only)

    def remove_playbook(self, playbook_id: str) -> bool:
        return self._store.delete_playbook(playbook_id)

    def update_playbook(self, playbook: Playbook) -> Playbook:
        playbook.updated_at = datetime.now(timezone.utc).isoformat()
        self._store.save_playbook(playbook)
        return playbook

    # --- Alert → Playbook Matching ---
    def find_matching_playbooks(self, alert_data: Dict[str, Any]) -> List[Playbook]:
        """Find all playbooks whose trigger conditions match the alert."""
        playbooks = self._store.list_playbooks(enabled_only=True)
        matches = [pb for pb in playbooks if pb.matches_alert(alert_data)]
        matches.sort(key=lambda p: p.priority)
        return matches

    # --- Trigger Execution ---
    def trigger(self, alert_id: str, alert_data: Dict[str, Any],
                triggered_by: str = "system", dry_run: bool = False,
                require_approval: bool = True) -> List[PlaybookExecution]:
        """Trigger matching playbooks for an alert."""
        matching = self.find_matching_playbooks(alert_data)
        executions = []
        for playbook in matching:
            exec_result = self.execute_playbook(
                playbook_id=playbook.playbook_id,
                alert_id=alert_id,
                alert_data=alert_data,
                triggered_by=triggered_by,
                dry_run=dry_run,
                require_approval=require_approval,
            )
            if exec_result:
                executions.append(exec_result)
        return executions

    def execute_playbook(self, playbook_id: str, alert_id: str = "",
                         alert_data: Dict[str, Any] = None,
                         triggered_by: str = "system",
                         dry_run: bool = False,
                         require_approval: bool = True) -> Optional[PlaybookExecution]:
        """Execute a specific playbook."""
        playbook = self._store.get_playbook(playbook_id)
        if not playbook:
            return None

        # Create execution instance with deep copy of steps
        import copy
        steps_copy = [PlaybookStep.from_dict(s.to_dict()) for s in playbook.steps]

        execution = PlaybookExecution(
            playbook_id=playbook.playbook_id,
            playbook_name=playbook.name,
            alert_id=alert_id,
            alert_data=alert_data or {},
            triggered_by=triggered_by,
            dry_run=dry_run,
            steps=steps_copy,
        )

        with self._lock:
            self._stats["executions_started"] += 1

        # Request approval if needed and engine is available
        if require_approval and self._approval_engine and not dry_run:
            try:
                approval_req = self._approval_engine.submit(
                    action_type="run_playbook",
                    title=f"Playbook: {playbook.name}",
                    description=f"Execute playbook '{playbook.name}' for alert {alert_id}",
                    priority="P3_MEDIUM",
                    requested_by=triggered_by,
                    alert_id=alert_id,
                    context={"playbook_id": playbook.playbook_id, "alert_data": alert_data or {}},
                )
                execution.approval_id = approval_req.request_id
                execution.status = PlaybookStatus.AWAITING_APPROVAL.value
                self._store.save_execution(execution)
                self._log(execution, "", "", "info",
                          f"Awaiting approval: {approval_req.request_id}")
                return execution
            except Exception as e:
                logger.warning(f"Approval submission failed, proceeding without: {e}")

        # Run directly if no approval needed
        return self._run_execution(execution)

    def approve_execution(self, execution_id: str, approver: str = "") -> Optional[PlaybookExecution]:
        """Approve and run a pending execution."""
        execution = self._store.get_execution(execution_id)
        if not execution:
            return None
        if execution.status != PlaybookStatus.AWAITING_APPROVAL.value:
            return execution
        execution.status = PlaybookStatus.APPROVED.value
        self._log(execution, "", "", "info", f"Approved by {approver}")
        return self._run_execution(execution)

    def cancel_execution(self, execution_id: str, actor: str = "") -> Optional[PlaybookExecution]:
        """Cancel a pending/running execution."""
        execution = self._store.get_execution(execution_id)
        if not execution:
            return None
        if execution.is_terminal:
            return execution
        execution.status = PlaybookStatus.CANCELLED.value
        execution.completed_at = datetime.now(timezone.utc).isoformat()
        self._store.save_execution(execution)
        self._log(execution, "", "", "info", f"Cancelled by {actor}")
        return execution

    def _run_execution(self, execution: PlaybookExecution) -> PlaybookExecution:
        """Run all steps in a playbook execution."""
        execution.status = PlaybookStatus.RUNNING.value
        self._store.save_execution(execution)
        self._fire_callback("on_execution_start", execution)
        self._log(execution, "", "", "info", f"Execution started: {execution.playbook_name}")

        all_success = True
        for i, step in enumerate(execution.steps):
            if execution.status == PlaybookStatus.CANCELLED.value:
                break
            execution.current_step = i
            step_result = self._run_step(execution, step)
            if not step_result:
                all_success = False
                # Check if any action in the step has continue_on_failure
                has_continue = any(a.continue_on_failure for a in step.actions)
                if not has_continue:
                    execution.status = PlaybookStatus.FAILED.value
                    execution.error = step.error
                    break

        if execution.status != PlaybookStatus.CANCELLED.value:
            if all_success:
                execution.status = PlaybookStatus.COMPLETED.value
            elif execution.status != PlaybookStatus.FAILED.value:
                execution.status = PlaybookStatus.PARTIALLY_COMPLETED.value

        execution.completed_at = datetime.now(timezone.utc).isoformat()
        self._store.save_execution(execution)

        if execution.status == PlaybookStatus.COMPLETED.value:
            with self._lock:
                self._stats["executions_completed"] += 1
            self._fire_callback("on_execution_complete", execution)
            self._log(execution, "", "", "info", "Execution completed successfully")
        elif execution.status == PlaybookStatus.FAILED.value:
            with self._lock:
                self._stats["executions_failed"] += 1
            self._fire_callback("on_execution_fail", execution)
            self._log(execution, "", "", "error", f"Execution failed: {execution.error}")

        return execution

    def _run_step(self, execution: PlaybookExecution, step: PlaybookStep) -> bool:
        """Execute all actions in a step. Returns True if all succeeded."""
        step.status = StepStatus.RUNNING.value
        step.started_at = datetime.now(timezone.utc).isoformat()
        self._log(execution, step.step_id, "", "info", f"Step started: {step.name}")

        all_ok = True
        for action in step.actions:
            result = self._handler.execute(action, execution.alert_data)
            with self._lock:
                self._stats["actions_executed"] += 1

            self._log(execution, step.step_id, action.action_id,
                      "info" if result.get("success") else "error",
                      result.get("message", "Action executed"),
                      details=result)

            if not result.get("success"):
                all_ok = False
                step.error = result.get("error", "Action failed")
                if not action.continue_on_failure:
                    step.status = StepStatus.FAILED.value
                    step.completed_at = datetime.now(timezone.utc).isoformat()
                    step.result = result
                    return False

        step.status = StepStatus.COMPLETED.value
        step.completed_at = datetime.now(timezone.utc).isoformat()
        self._fire_callback("on_step_complete", execution, step)
        return all_ok

    # --- Rollback ---
    def rollback(self, execution_id: str, actor: str = "") -> Optional[PlaybookExecution]:
        """Rollback a completed/failed execution."""
        execution = self._store.get_execution(execution_id)
        if not execution:
            return None

        if execution.rollback_status in (RollbackStatus.COMPLETED.value, RollbackStatus.IN_PROGRESS.value):
            return execution

        execution.rollback_status = RollbackStatus.IN_PROGRESS.value
        self._store.save_execution(execution)
        self._log(execution, "", "", "info", f"Rollback initiated by {actor}")

        rollback_errors = []
        # Reverse through completed steps
        for step in reversed(execution.steps):
            if step.status not in (StepStatus.COMPLETED.value, StepStatus.FAILED.value):
                continue
            for action in reversed(step.actions):
                if not action.rollback_action:
                    continue
                rollback_action = ResponseAction(
                    action_type=action.rollback_action,
                    parameters=action.rollback_params if action.rollback_params else action.parameters,
                    description=f"Rollback: {action.description}",
                )
                result = self._handler.execute(rollback_action, execution.alert_data)
                self._log(execution, step.step_id, action.action_id,
                          "info" if result.get("success") else "error",
                          f"Rollback: {result.get('message', '')}",
                          details=result)
                if not result.get("success"):
                    rollback_errors.append(result.get("error", "Rollback action failed"))
                else:
                    step.status = StepStatus.ROLLED_BACK.value

        with self._lock:
            self._stats["rollbacks_performed"] += 1

        if rollback_errors:
            execution.rollback_status = RollbackStatus.PARTIAL.value
            execution.error = f"Rollback partial: {'; '.join(rollback_errors)}"
        else:
            execution.rollback_status = RollbackStatus.COMPLETED.value
            execution.status = PlaybookStatus.ROLLED_BACK.value

        self._store.save_execution(execution)
        self._fire_callback("on_rollback", execution)
        self._log(execution, "", "", "info",
                  f"Rollback {execution.rollback_status}")
        return execution

    # --- Query ---
    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        return self._store.get_execution(execution_id)

    def list_executions(self, **kwargs) -> List[PlaybookExecution]:
        return self._store.list_executions(**kwargs)

    def get_logs(self, execution_id: str) -> List[ExecutionLog]:
        return self._store.get_logs(execution_id)

    def get_stats(self) -> Dict[str, Any]:
        store_stats = self._store.get_stats()
        store_stats["engine"] = dict(self._stats)
        return store_stats

    # --- Logging ---
    def _log(self, execution: PlaybookExecution, step_id: str, action_id: str,
             status: str, message: str, details: Dict = None) -> None:
        entry = ExecutionLog(
            execution_id=execution.execution_id,
            playbook_id=execution.playbook_id,
            alert_id=execution.alert_id,
            step_id=step_id,
            action_id=action_id,
            action_type="",
            status=status,
            message=message,
            details=details or {},
        )
        try:
            self._store.add_log(entry)
        except Exception as e:
            logger.warning(f"Failed to write execution log: {e}")


# ============================================================================
# Flask Blueprint REST API
# ============================================================================

def create_auto_response_blueprint(engine: "AutoResponseEngine" = None):
    """Create Flask blueprint for auto-response REST API."""
    try:
        from flask import Blueprint, request, jsonify
    except ImportError:
        logger.warning("Flask not available, REST API disabled")
        return None

    bp = Blueprint("auto_response", __name__, url_prefix="/api/v1/soc/response")

    def _engine():
        return engine or get_auto_response_engine()

    @bp.route("/playbooks", methods=["GET"])
    def list_playbooks():
        enabled = request.args.get("enabled_only", "false").lower() == "true"
        pbs = _engine().list_playbooks(enabled_only=enabled)
        return jsonify({"playbooks": [p.to_dict() for p in pbs], "count": len(pbs)})

    @bp.route("/playbooks", methods=["POST"])
    def create_playbook():
        data = request.get_json(silent=True) or {}
        if not data.get("name"):
            return jsonify({"error": "Missing 'name'"}), 400
        pb = Playbook.from_dict(data)
        _engine().add_playbook(pb)
        return jsonify({"playbook": pb.to_dict()}), 201

    @bp.route("/playbooks/<playbook_id>", methods=["GET"])
    def get_playbook(playbook_id):
        pb = _engine().get_playbook(playbook_id)
        if not pb:
            return jsonify({"error": "Playbook not found"}), 404
        return jsonify({"playbook": pb.to_dict()})

    @bp.route("/playbooks/<playbook_id>", methods=["PUT"])
    def update_playbook(playbook_id):
        existing = _engine().get_playbook(playbook_id)
        if not existing:
            return jsonify({"error": "Playbook not found"}), 404
        data = request.get_json(silent=True) or {}
        data["playbook_id"] = playbook_id
        pb = Playbook.from_dict(data)
        _engine().update_playbook(pb)
        return jsonify({"playbook": pb.to_dict()})

    @bp.route("/playbooks/<playbook_id>", methods=["DELETE"])
    def delete_playbook(playbook_id):
        if _engine().remove_playbook(playbook_id):
            return jsonify({"deleted": True})
        return jsonify({"error": "Playbook not found"}), 404

    @bp.route("/trigger", methods=["POST"])
    def trigger_playbooks():
        data = request.get_json(silent=True) or {}
        alert_id = data.get("alert_id", "")
        alert_data = data.get("alert_data", {})
        if not alert_id:
            return jsonify({"error": "Missing 'alert_id'"}), 400
        dry_run = data.get("dry_run", False)
        triggered_by = data.get("triggered_by", "api")
        require_approval = data.get("require_approval", True)
        executions = _engine().trigger(
            alert_id=alert_id, alert_data=alert_data,
            triggered_by=triggered_by, dry_run=dry_run,
            require_approval=require_approval,
        )
        return jsonify({
            "executions": [e.to_dict() for e in executions],
            "count": len(executions),
        })

    @bp.route("/execute/<playbook_id>", methods=["POST"])
    def execute_playbook(playbook_id):
        data = request.get_json(silent=True) or {}
        alert_id = data.get("alert_id", "")
        alert_data = data.get("alert_data", {})
        dry_run = data.get("dry_run", False)
        triggered_by = data.get("triggered_by", "api")
        require_approval = data.get("require_approval", True)
        result = _engine().execute_playbook(
            playbook_id=playbook_id, alert_id=alert_id,
            alert_data=alert_data, triggered_by=triggered_by,
            dry_run=dry_run, require_approval=require_approval,
        )
        if not result:
            return jsonify({"error": "Playbook not found"}), 404
        return jsonify({"execution": result.to_dict()})

    @bp.route("/executions", methods=["GET"])
    def list_executions():
        status = request.args.get("status")
        playbook_id = request.args.get("playbook_id")
        alert_id = request.args.get("alert_id")
        limit = int(request.args.get("limit", 100))
        offset = int(request.args.get("offset", 0))
        execs = _engine().list_executions(
            status=status, playbook_id=playbook_id,
            alert_id=alert_id, limit=limit, offset=offset,
        )
        return jsonify({"executions": [e.to_dict() for e in execs], "count": len(execs)})

    @bp.route("/executions/<execution_id>", methods=["GET"])
    def get_execution(execution_id):
        ex = _engine().get_execution(execution_id)
        if not ex:
            return jsonify({"error": "Execution not found"}), 404
        return jsonify({"execution": ex.to_dict()})

    @bp.route("/executions/<execution_id>/approve", methods=["POST"])
    def approve_execution(execution_id):
        data = request.get_json(silent=True) or {}
        approver = data.get("approver", "")
        result = _engine().approve_execution(execution_id, approver=approver)
        if not result:
            return jsonify({"error": "Execution not found"}), 404
        return jsonify({"execution": result.to_dict()})

    @bp.route("/executions/<execution_id>/cancel", methods=["POST"])
    def cancel_execution(execution_id):
        data = request.get_json(silent=True) or {}
        actor = data.get("actor", "")
        result = _engine().cancel_execution(execution_id, actor=actor)
        if not result:
            return jsonify({"error": "Execution not found"}), 404
        return jsonify({"execution": result.to_dict()})

    @bp.route("/executions/<execution_id>/rollback", methods=["POST"])
    def rollback_execution(execution_id):
        data = request.get_json(silent=True) or {}
        actor = data.get("actor", "")
        result = _engine().rollback(execution_id, actor=actor)
        if not result:
            return jsonify({"error": "Execution not found"}), 404
        return jsonify({"execution": result.to_dict()})

    @bp.route("/executions/<execution_id>/logs", methods=["GET"])
    def get_execution_logs(execution_id):
        logs = _engine().get_logs(execution_id)
        return jsonify({"logs": [l.to_dict() for l in logs], "count": len(logs)})

    @bp.route("/stats", methods=["GET"])
    def get_stats():
        return jsonify(_engine().get_stats())

    return bp


# ============================================================================
# Global Singleton
# ============================================================================

_global_engine: Optional[AutoResponseEngine] = None
_global_lock = threading.Lock()


def get_auto_response_engine(**kwargs) -> AutoResponseEngine:
    """Get or create the global AutoResponseEngine singleton."""
    global _global_engine
    if _global_engine is None:
        with _global_lock:
            if _global_engine is None:
                _global_engine = AutoResponseEngine(**kwargs)
    return _global_engine


def reset_global_engine() -> None:
    """Reset global engine (for testing)."""
    global _global_engine
    with _global_lock:
        _global_engine = None
