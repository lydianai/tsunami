#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI AUTO-REMEDIATION v5.0
    Automatic Response and Healing Actions
================================================================================

    Features:
    - Block suspicious IPs (iptables/nftables integration)
    - Kill malicious processes
    - Restart failed services
    - Quarantine suspicious files
    - Rate limit connections
    - Rollback configurations
    - Safe mode with dry-run support
    - Audit logging for all actions

================================================================================
"""

import os
import shutil
import signal
import logging
import threading
import subprocess
import time
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Callable, Any, Tuple
from enum import Enum
from pathlib import Path

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ActionType(Enum):
    """Types of remediation actions"""
    BLOCK_IP = "block_ip"
    UNBLOCK_IP = "unblock_ip"
    KILL_PROCESS = "kill_process"
    RESTART_SERVICE = "restart_service"
    STOP_SERVICE = "stop_service"
    QUARANTINE_FILE = "quarantine_file"
    RATE_LIMIT = "rate_limit"
    CLOSE_PORT = "close_port"
    OPEN_PORT = "open_port"
    ROLLBACK_CONFIG = "rollback_config"
    CUSTOM = "custom"


class ActionStatus(Enum):
    """Status of remediation action"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    DRY_RUN = "dry_run"


@dataclass
class RemediationAction:
    """A single remediation action"""
    id: str
    type: ActionType
    target: str
    parameters: Dict = field(default_factory=dict)
    reason: str = ""
    anomaly_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['type'] = self.type.value
        return result


@dataclass
class RemediationResult:
    """Result of a remediation action"""
    action_id: str
    action_type: ActionType
    status: ActionStatus
    message: str
    target: str
    executed_at: str
    duration_ms: float
    rollback_info: Optional[Dict] = None
    error: Optional[str] = None
    output: Optional[str] = None

    def to_dict(self) -> Dict:
        result = asdict(self)
        result['action_type'] = self.action_type.value
        result['status'] = self.status.value
        return result


class AutoRemediation:
    """
    Automatic remediation engine for security and health issues.
    Supports iptables, process management, service control, and more.
    """

    # Default quarantine directory
    DEFAULT_QUARANTINE_DIR = "/var/tsunami/quarantine"

    # Rate limit defaults
    DEFAULT_RATE_LIMIT = "10/minute"

    def __init__(self, dry_run: bool = False,
                 quarantine_dir: str = None,
                 require_approval: bool = False):
        """
        Initialize auto-remediation engine.

        Args:
            dry_run: If True, log actions but don't execute
            quarantine_dir: Directory for quarantined files
            require_approval: If True, queue actions for approval
        """
        if not PSUTIL_AVAILABLE:
            raise RuntimeError("psutil is required for auto-remediation")

        self.dry_run = dry_run
        self.quarantine_dir = quarantine_dir or self.DEFAULT_QUARANTINE_DIR
        self.require_approval = require_approval

        # State
        self._action_history: List[RemediationResult] = []
        self._pending_actions: Dict[str, RemediationAction] = {}
        self._blocked_ips: Dict[str, Dict] = {}  # IP -> {added_at, reason, rule_num}
        self._rate_limited_ips: Dict[str, Dict] = {}
        self._rollback_stack: List[Dict] = []
        self._lock = threading.RLock()

        # Action counter
        self._action_counter = 0

        # Callbacks
        self._pre_action_hooks: List[Callable[[RemediationAction], bool]] = []
        self._post_action_hooks: List[Callable[[RemediationResult], None]] = []

        # Check for iptables/nftables
        self._firewall_tool = self._detect_firewall_tool()

        # Create quarantine directory
        if not self.dry_run:
            os.makedirs(self.quarantine_dir, exist_ok=True)

        logger.info("[AUTO_REMEDIATION] Initialized (dry_run=%s, firewall=%s)",
                   dry_run, self._firewall_tool)

    def _detect_firewall_tool(self) -> Optional[str]:
        """Detect available firewall management tool"""
        try:
            subprocess.run(['which', 'iptables'], capture_output=True, check=True)
            return 'iptables'
        except subprocess.CalledProcessError:
            pass

        try:
            subprocess.run(['which', 'nft'], capture_output=True, check=True)
            return 'nftables'
        except subprocess.CalledProcessError:
            pass

        logger.warning("[AUTO_REMEDIATION] No firewall tool found (iptables/nftables)")
        return None

    def _generate_action_id(self) -> str:
        """Generate unique action ID"""
        self._action_counter += 1
        return f"ACT-{datetime.now().strftime('%Y%m%d%H%M%S')}-{self._action_counter:04d}"

    def register_pre_hook(self, hook: Callable[[RemediationAction], bool]):
        """Register pre-action hook (return False to cancel action)"""
        self._pre_action_hooks.append(hook)

    def register_post_hook(self, hook: Callable[[RemediationResult], None]):
        """Register post-action hook"""
        self._post_action_hooks.append(hook)

    def _run_pre_hooks(self, action: RemediationAction) -> bool:
        """Run pre-action hooks, return True if action should proceed"""
        for hook in self._pre_action_hooks:
            try:
                if not hook(action):
                    logger.info("[AUTO_REMEDIATION] Action %s cancelled by pre-hook", action.id)
                    return False
            except Exception as e:
                logger.error("[AUTO_REMEDIATION] Pre-hook error: %s", e)
        return True

    def _run_post_hooks(self, result: RemediationResult):
        """Run post-action hooks"""
        for hook in self._post_action_hooks:
            try:
                hook(result)
            except Exception as e:
                logger.error("[AUTO_REMEDIATION] Post-hook error: %s", e)

    def _execute_command(self, cmd: List[str], timeout: int = 30) -> Tuple[int, str, str]:
        """Execute shell command with timeout"""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timeout"
        except Exception as e:
            return -1, "", str(e)

    def _record_result(self, result: RemediationResult):
        """Record action result and run hooks"""
        with self._lock:
            self._action_history.append(result)
            if len(self._action_history) > 10000:
                self._action_history = self._action_history[-10000:]

        self._run_post_hooks(result)

        level = logging.INFO if result.status == ActionStatus.SUCCESS else logging.ERROR
        logger.log(level, "[AUTO_REMEDIATION] %s %s: %s (%s)",
                  result.action_type.value, result.status.value, result.target, result.message)

    # ==================== IP Blocking ====================

    def block_ip(self, ip: str, reason: str = "", duration_minutes: int = 0,
                anomaly_id: str = None) -> RemediationResult:
        """
        Block an IP address using iptables.

        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration_minutes: Auto-unblock after minutes (0 = permanent)
            anomaly_id: Associated anomaly ID
        """
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.BLOCK_IP,
            target=ip,
            parameters={'duration_minutes': duration_minutes},
            reason=reason,
            anomaly_id=anomaly_id
        )

        if not self._run_pre_hooks(action):
            return RemediationResult(
                action_id=action.id,
                action_type=ActionType.BLOCK_IP,
                status=ActionStatus.FAILED,
                message="Cancelled by pre-hook",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=0
            )

        start_time = time.time()

        # Dry run check
        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.BLOCK_IP,
                status=ActionStatus.DRY_RUN,
                message=f"Would block IP {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                rollback_info={'command': f'iptables -D INPUT -s {ip} -j DROP'}
            )
            self._record_result(result)
            return result

        # Check if already blocked
        if ip in self._blocked_ips:
            return RemediationResult(
                action_id=action.id,
                action_type=ActionType.BLOCK_IP,
                status=ActionStatus.SUCCESS,
                message=f"IP {ip} already blocked",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )

        # Execute iptables command
        if self._firewall_tool == 'iptables':
            cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
            returncode, stdout, stderr = self._execute_command(['sudo'] + cmd)
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.BLOCK_IP,
                status=ActionStatus.FAILED,
                message="No firewall tool available",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        duration_ms = (time.time() - start_time) * 1000

        if returncode == 0:
            with self._lock:
                self._blocked_ips[ip] = {
                    'added_at': datetime.now().isoformat(),
                    'reason': reason,
                    'action_id': action.id,
                    'duration_minutes': duration_minutes
                }

                # Add rollback info
                self._rollback_stack.append({
                    'type': 'unblock_ip',
                    'target': ip,
                    'action_id': action.id
                })

            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.BLOCK_IP,
                status=ActionStatus.SUCCESS,
                message=f"Blocked IP {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                rollback_info={'command': f'iptables -D INPUT -s {ip} -j DROP'}
            )
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.BLOCK_IP,
                status=ActionStatus.FAILED,
                message=f"Failed to block IP {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                error=stderr
            )

        self._record_result(result)
        return result

    def unblock_ip(self, ip: str, reason: str = "") -> RemediationResult:
        """Unblock a previously blocked IP"""
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.UNBLOCK_IP,
            target=ip,
            reason=reason
        )

        start_time = time.time()

        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.UNBLOCK_IP,
                status=ActionStatus.DRY_RUN,
                message=f"Would unblock IP {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        if self._firewall_tool == 'iptables':
            cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
            returncode, stdout, stderr = self._execute_command(['sudo'] + cmd)
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.UNBLOCK_IP,
                status=ActionStatus.FAILED,
                message="No firewall tool available",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        duration_ms = (time.time() - start_time) * 1000

        if returncode == 0:
            with self._lock:
                self._blocked_ips.pop(ip, None)

            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.UNBLOCK_IP,
                status=ActionStatus.SUCCESS,
                message=f"Unblocked IP {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms
            )
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.UNBLOCK_IP,
                status=ActionStatus.FAILED,
                message=f"Failed to unblock IP {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                error=stderr
            )

        self._record_result(result)
        return result

    # ==================== Process Management ====================

    def kill_process(self, pid: int = None, name: str = None,
                    reason: str = "", force: bool = False,
                    anomaly_id: str = None) -> RemediationResult:
        """
        Kill a process by PID or name.

        Args:
            pid: Process ID to kill
            name: Process name to kill (all matching)
            reason: Reason for killing
            force: Use SIGKILL instead of SIGTERM
            anomaly_id: Associated anomaly ID
        """
        target = f"PID:{pid}" if pid else f"name:{name}"
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.KILL_PROCESS,
            target=target,
            parameters={'force': force},
            reason=reason,
            anomaly_id=anomaly_id
        )

        if not self._run_pre_hooks(action):
            return RemediationResult(
                action_id=action.id,
                action_type=ActionType.KILL_PROCESS,
                status=ActionStatus.FAILED,
                message="Cancelled by pre-hook",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=0
            )

        start_time = time.time()

        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.KILL_PROCESS,
                status=ActionStatus.DRY_RUN,
                message=f"Would kill process {target}",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        killed = []
        errors = []
        sig = signal.SIGKILL if force else signal.SIGTERM

        try:
            if pid:
                # Kill specific PID
                proc = psutil.Process(pid)
                proc_name = proc.name()
                proc.send_signal(sig)
                killed.append({'pid': pid, 'name': proc_name})
            elif name:
                # Kill all matching processes
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if name.lower() in proc.info['name'].lower():
                            proc.send_signal(sig)
                            killed.append({'pid': proc.info['pid'], 'name': proc.info['name']})
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                        errors.append(str(e))

            duration_ms = (time.time() - start_time) * 1000

            if killed:
                result = RemediationResult(
                    action_id=action.id,
                    action_type=ActionType.KILL_PROCESS,
                    status=ActionStatus.SUCCESS,
                    message=f"Killed {len(killed)} process(es)",
                    target=target,
                    executed_at=datetime.now().isoformat(),
                    duration_ms=duration_ms,
                    output=str(killed)
                )
            else:
                result = RemediationResult(
                    action_id=action.id,
                    action_type=ActionType.KILL_PROCESS,
                    status=ActionStatus.FAILED,
                    message="No processes found or killed",
                    target=target,
                    executed_at=datetime.now().isoformat(),
                    duration_ms=duration_ms,
                    error="; ".join(errors) if errors else "No matching processes"
                )

        except psutil.NoSuchProcess:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.KILL_PROCESS,
                status=ActionStatus.FAILED,
                message="Process not found",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                error="Process does not exist"
            )
        except psutil.AccessDenied:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.KILL_PROCESS,
                status=ActionStatus.FAILED,
                message="Access denied",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                error="Permission denied (try running as root)"
            )
        except Exception as e:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.KILL_PROCESS,
                status=ActionStatus.FAILED,
                message="Error killing process",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )

        self._record_result(result)
        return result

    # ==================== Service Management ====================

    def restart_service(self, service_name: str, reason: str = "",
                       anomaly_id: str = None) -> RemediationResult:
        """Restart a systemd service"""
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.RESTART_SERVICE,
            target=service_name,
            reason=reason,
            anomaly_id=anomaly_id
        )

        if not self._run_pre_hooks(action):
            return RemediationResult(
                action_id=action.id,
                action_type=ActionType.RESTART_SERVICE,
                status=ActionStatus.FAILED,
                message="Cancelled by pre-hook",
                target=service_name,
                executed_at=datetime.now().isoformat(),
                duration_ms=0
            )

        start_time = time.time()

        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.RESTART_SERVICE,
                status=ActionStatus.DRY_RUN,
                message=f"Would restart service {service_name}",
                target=service_name,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        cmd = ['systemctl', 'restart', service_name]
        returncode, stdout, stderr = self._execute_command(['sudo'] + cmd, timeout=60)
        duration_ms = (time.time() - start_time) * 1000

        if returncode == 0:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.RESTART_SERVICE,
                status=ActionStatus.SUCCESS,
                message=f"Restarted service {service_name}",
                target=service_name,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                output=stdout
            )
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.RESTART_SERVICE,
                status=ActionStatus.FAILED,
                message=f"Failed to restart service {service_name}",
                target=service_name,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                error=stderr
            )

        self._record_result(result)
        return result

    def stop_service(self, service_name: str, reason: str = "",
                    anomaly_id: str = None) -> RemediationResult:
        """Stop a systemd service"""
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.STOP_SERVICE,
            target=service_name,
            reason=reason,
            anomaly_id=anomaly_id
        )

        start_time = time.time()

        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.STOP_SERVICE,
                status=ActionStatus.DRY_RUN,
                message=f"Would stop service {service_name}",
                target=service_name,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        cmd = ['systemctl', 'stop', service_name]
        returncode, stdout, stderr = self._execute_command(['sudo'] + cmd, timeout=60)
        duration_ms = (time.time() - start_time) * 1000

        if returncode == 0:
            with self._lock:
                self._rollback_stack.append({
                    'type': 'start_service',
                    'target': service_name,
                    'action_id': action.id
                })

            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.STOP_SERVICE,
                status=ActionStatus.SUCCESS,
                message=f"Stopped service {service_name}",
                target=service_name,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                rollback_info={'command': f'systemctl start {service_name}'}
            )
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.STOP_SERVICE,
                status=ActionStatus.FAILED,
                message=f"Failed to stop service {service_name}",
                target=service_name,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                error=stderr
            )

        self._record_result(result)
        return result

    # ==================== File Quarantine ====================

    def quarantine_file(self, file_path: str, reason: str = "",
                       anomaly_id: str = None) -> RemediationResult:
        """Move a suspicious file to quarantine"""
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.QUARANTINE_FILE,
            target=file_path,
            reason=reason,
            anomaly_id=anomaly_id
        )

        if not self._run_pre_hooks(action):
            return RemediationResult(
                action_id=action.id,
                action_type=ActionType.QUARANTINE_FILE,
                status=ActionStatus.FAILED,
                message="Cancelled by pre-hook",
                target=file_path,
                executed_at=datetime.now().isoformat(),
                duration_ms=0
            )

        start_time = time.time()

        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.QUARANTINE_FILE,
                status=ActionStatus.DRY_RUN,
                message=f"Would quarantine file {file_path}",
                target=file_path,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        if not os.path.exists(file_path):
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.QUARANTINE_FILE,
                status=ActionStatus.FAILED,
                message="File not found",
                target=file_path,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                error="File does not exist"
            )
            self._record_result(result)
            return result

        try:
            # Create quarantine subdirectory with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            quarantine_subdir = os.path.join(self.quarantine_dir, timestamp)
            os.makedirs(quarantine_subdir, exist_ok=True)

            # Move file
            dest_path = os.path.join(quarantine_subdir, os.path.basename(file_path))
            shutil.move(file_path, dest_path)

            # Create metadata file
            metadata_path = dest_path + '.meta'
            with open(metadata_path, 'w') as f:
                import json
                json.dump({
                    'original_path': file_path,
                    'quarantined_at': datetime.now().isoformat(),
                    'reason': reason,
                    'action_id': action.id,
                    'anomaly_id': anomaly_id
                }, f, indent=2)

            with self._lock:
                self._rollback_stack.append({
                    'type': 'restore_file',
                    'source': dest_path,
                    'target': file_path,
                    'action_id': action.id
                })

            duration_ms = (time.time() - start_time) * 1000
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.QUARANTINE_FILE,
                status=ActionStatus.SUCCESS,
                message=f"Quarantined file to {dest_path}",
                target=file_path,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                rollback_info={'quarantine_path': dest_path, 'original_path': file_path}
            )

        except Exception as e:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.QUARANTINE_FILE,
                status=ActionStatus.FAILED,
                message="Failed to quarantine file",
                target=file_path,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                error=str(e)
            )

        self._record_result(result)
        return result

    # ==================== Rate Limiting ====================

    def rate_limit_ip(self, ip: str, rate: str = None, reason: str = "",
                     anomaly_id: str = None) -> RemediationResult:
        """Apply rate limiting to an IP using iptables"""
        rate = rate or self.DEFAULT_RATE_LIMIT
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.RATE_LIMIT,
            target=ip,
            parameters={'rate': rate},
            reason=reason,
            anomaly_id=anomaly_id
        )

        start_time = time.time()

        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.RATE_LIMIT,
                status=ActionStatus.DRY_RUN,
                message=f"Would rate limit IP {ip} to {rate}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        if self._firewall_tool != 'iptables':
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.RATE_LIMIT,
                status=ActionStatus.FAILED,
                message="Rate limiting requires iptables",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        # Parse rate (e.g., "10/minute")
        parts = rate.split('/')
        limit_num = parts[0]
        limit_period = parts[1] if len(parts) > 1 else 'second'

        # iptables hashlimit rule
        cmd = [
            'iptables', '-A', 'INPUT', '-s', ip,
            '-m', 'hashlimit',
            '--hashlimit-above', f'{limit_num}/{limit_period}',
            '--hashlimit-mode', 'srcip',
            '--hashlimit-name', f'ratelimit_{ip.replace(".", "_")}',
            '-j', 'DROP'
        ]

        returncode, stdout, stderr = self._execute_command(['sudo'] + cmd)
        duration_ms = (time.time() - start_time) * 1000

        if returncode == 0:
            with self._lock:
                self._rate_limited_ips[ip] = {
                    'rate': rate,
                    'added_at': datetime.now().isoformat(),
                    'action_id': action.id
                }

            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.RATE_LIMIT,
                status=ActionStatus.SUCCESS,
                message=f"Applied rate limit {rate} to {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms
            )
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.RATE_LIMIT,
                status=ActionStatus.FAILED,
                message=f"Failed to rate limit {ip}",
                target=ip,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                error=stderr
            )

        self._record_result(result)
        return result

    # ==================== Port Management ====================

    def close_port(self, port: int, protocol: str = 'tcp',
                  reason: str = "", anomaly_id: str = None) -> RemediationResult:
        """Close a port using iptables"""
        target = f"{port}/{protocol}"
        action = RemediationAction(
            id=self._generate_action_id(),
            type=ActionType.CLOSE_PORT,
            target=target,
            reason=reason,
            anomaly_id=anomaly_id
        )

        start_time = time.time()

        if self.dry_run:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.CLOSE_PORT,
                status=ActionStatus.DRY_RUN,
                message=f"Would close port {target}",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        if self._firewall_tool == 'iptables':
            cmd = ['iptables', '-A', 'INPUT', '-p', protocol, '--dport', str(port), '-j', 'DROP']
            returncode, stdout, stderr = self._execute_command(['sudo'] + cmd)
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.CLOSE_PORT,
                status=ActionStatus.FAILED,
                message="No firewall tool available",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000
            )
            self._record_result(result)
            return result

        duration_ms = (time.time() - start_time) * 1000

        if returncode == 0:
            with self._lock:
                self._rollback_stack.append({
                    'type': 'open_port',
                    'port': port,
                    'protocol': protocol,
                    'action_id': action.id
                })

            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.CLOSE_PORT,
                status=ActionStatus.SUCCESS,
                message=f"Closed port {target}",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                rollback_info={'command': f'iptables -D INPUT -p {protocol} --dport {port} -j DROP'}
            )
        else:
            result = RemediationResult(
                action_id=action.id,
                action_type=ActionType.CLOSE_PORT,
                status=ActionStatus.FAILED,
                message=f"Failed to close port {target}",
                target=target,
                executed_at=datetime.now().isoformat(),
                duration_ms=duration_ms,
                error=stderr
            )

        self._record_result(result)
        return result

    # ==================== Rollback ====================

    def rollback_last(self) -> RemediationResult:
        """Rollback the last remediation action"""
        with self._lock:
            if not self._rollback_stack:
                return RemediationResult(
                    action_id=self._generate_action_id(),
                    action_type=ActionType.ROLLBACK_CONFIG,
                    status=ActionStatus.FAILED,
                    message="Nothing to rollback",
                    target="",
                    executed_at=datetime.now().isoformat(),
                    duration_ms=0
                )

            rollback = self._rollback_stack.pop()

        start_time = time.time()

        if rollback['type'] == 'unblock_ip':
            return self.unblock_ip(rollback['target'], reason="Rollback")

        elif rollback['type'] == 'start_service':
            cmd = ['systemctl', 'start', rollback['target']]
            returncode, stdout, stderr = self._execute_command(['sudo'] + cmd)
            status = ActionStatus.SUCCESS if returncode == 0 else ActionStatus.FAILED
            return RemediationResult(
                action_id=self._generate_action_id(),
                action_type=ActionType.ROLLBACK_CONFIG,
                status=status,
                message=f"Rolled back: started service {rollback['target']}",
                target=rollback['target'],
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                error=stderr if returncode != 0 else None
            )

        elif rollback['type'] == 'restore_file':
            try:
                shutil.move(rollback['source'], rollback['target'])
                return RemediationResult(
                    action_id=self._generate_action_id(),
                    action_type=ActionType.ROLLBACK_CONFIG,
                    status=ActionStatus.SUCCESS,
                    message=f"Restored file to {rollback['target']}",
                    target=rollback['target'],
                    executed_at=datetime.now().isoformat(),
                    duration_ms=(time.time() - start_time) * 1000
                )
            except Exception as e:
                return RemediationResult(
                    action_id=self._generate_action_id(),
                    action_type=ActionType.ROLLBACK_CONFIG,
                    status=ActionStatus.FAILED,
                    message="Failed to restore file",
                    target=rollback['target'],
                    executed_at=datetime.now().isoformat(),
                    duration_ms=(time.time() - start_time) * 1000,
                    error=str(e)
                )

        elif rollback['type'] == 'open_port':
            cmd = ['iptables', '-D', 'INPUT', '-p', rollback['protocol'],
                   '--dport', str(rollback['port']), '-j', 'DROP']
            returncode, stdout, stderr = self._execute_command(['sudo'] + cmd)
            status = ActionStatus.SUCCESS if returncode == 0 else ActionStatus.FAILED
            return RemediationResult(
                action_id=self._generate_action_id(),
                action_type=ActionType.ROLLBACK_CONFIG,
                status=status,
                message=f"Rolled back: opened port {rollback['port']}",
                target=f"{rollback['port']}/{rollback['protocol']}",
                executed_at=datetime.now().isoformat(),
                duration_ms=(time.time() - start_time) * 1000,
                error=stderr if returncode != 0 else None
            )

        return RemediationResult(
            action_id=self._generate_action_id(),
            action_type=ActionType.ROLLBACK_CONFIG,
            status=ActionStatus.FAILED,
            message=f"Unknown rollback type: {rollback['type']}",
            target="",
            executed_at=datetime.now().isoformat(),
            duration_ms=(time.time() - start_time) * 1000
        )

    # ==================== Status & History ====================

    def get_blocked_ips(self) -> Dict[str, Dict]:
        """Get all currently blocked IPs"""
        with self._lock:
            return dict(self._blocked_ips)

    def get_action_history(self, hours: int = 24,
                          action_type: ActionType = None,
                          status: ActionStatus = None) -> List[RemediationResult]:
        """Get remediation action history"""
        cutoff = datetime.now() - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()

        with self._lock:
            results = []
            for result in self._action_history:
                if result.executed_at < cutoff_str:
                    continue
                if action_type and result.action_type != action_type:
                    continue
                if status and result.status != status:
                    continue
                results.append(result)
            return results

    def get_summary(self) -> Dict:
        """Get remediation summary"""
        with self._lock:
            success_count = sum(1 for r in self._action_history if r.status == ActionStatus.SUCCESS)
            failed_count = sum(1 for r in self._action_history if r.status == ActionStatus.FAILED)

            by_type = {}
            for result in self._action_history:
                type_name = result.action_type.value
                by_type[type_name] = by_type.get(type_name, 0) + 1

            return {
                'timestamp': datetime.now().isoformat(),
                'dry_run': self.dry_run,
                'total_actions': len(self._action_history),
                'success_count': success_count,
                'failed_count': failed_count,
                'blocked_ips': len(self._blocked_ips),
                'rate_limited_ips': len(self._rate_limited_ips),
                'rollback_stack_size': len(self._rollback_stack),
                'by_action_type': by_type,
                'recent_actions': [r.to_dict() for r in self._action_history[-10:]]
            }


# Singleton instance
_auto_remediation: Optional[AutoRemediation] = None

def get_auto_remediation(dry_run: bool = False) -> AutoRemediation:
    """Get or create auto-remediation singleton"""
    global _auto_remediation
    if _auto_remediation is None:
        _auto_remediation = AutoRemediation(dry_run=dry_run)
    return _auto_remediation


