#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Auto Response & Playbook Engine Tests
    Comprehensive Test Suite (~200+ tests)
================================================================================
"""

import builtins
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.soc_core.auto_response import (
    ResponseActionType, PlaybookStatus, StepStatus, TriggerConditionOp,
    RollbackStatus,
    TriggerCondition, ResponseAction, PlaybookStep, Playbook,
    ExecutionLog, PlaybookExecution,
    ActionHandler, AutoResponseStore, AutoResponseEngine,
    create_auto_response_blueprint, get_auto_response_engine, reset_global_engine,
    _ROLLBACK_MAP,
)


# ============================================================================
# Enum Tests
# ============================================================================

class TestResponseActionType(unittest.TestCase):
    def test_all_members(self):
        self.assertEqual(len(ResponseActionType), 18)

    def test_values(self):
        self.assertEqual(ResponseActionType.BLOCK_IP.value, "block_ip")
        self.assertEqual(ResponseActionType.UNBLOCK_IP.value, "unblock_ip")
        self.assertEqual(ResponseActionType.DNS_SINKHOLE.value, "dns_sinkhole")
        self.assertEqual(ResponseActionType.ISOLATE_HOST.value, "isolate_host")
        self.assertEqual(ResponseActionType.DISABLE_USER.value, "disable_user")
        self.assertEqual(ResponseActionType.KILL_PROCESS.value, "kill_process")
        self.assertEqual(ResponseActionType.QUARANTINE_FILE.value, "quarantine_file")
        self.assertEqual(ResponseActionType.CUSTOM.value, "custom")


class TestPlaybookStatus(unittest.TestCase):
    def test_all_members(self):
        self.assertEqual(len(PlaybookStatus), 9)

    def test_values(self):
        self.assertEqual(PlaybookStatus.PENDING.value, "pending")
        self.assertEqual(PlaybookStatus.RUNNING.value, "running")
        self.assertEqual(PlaybookStatus.COMPLETED.value, "completed")
        self.assertEqual(PlaybookStatus.FAILED.value, "failed")
        self.assertEqual(PlaybookStatus.ROLLED_BACK.value, "rolled_back")
        self.assertEqual(PlaybookStatus.AWAITING_APPROVAL.value, "awaiting_approval")


class TestStepStatus(unittest.TestCase):
    def test_all_members(self):
        self.assertEqual(len(StepStatus), 6)


class TestTriggerConditionOp(unittest.TestCase):
    def test_all_members(self):
        self.assertEqual(len(TriggerConditionOp), 8)


class TestRollbackStatus(unittest.TestCase):
    def test_all_members(self):
        self.assertEqual(len(RollbackStatus), 5)


# ============================================================================
# TriggerCondition Tests
# ============================================================================

class TestTriggerCondition(unittest.TestCase):
    def test_default_creation(self):
        tc = TriggerCondition()
        self.assertEqual(tc.field, "")
        self.assertEqual(tc.operator, "eq")
        self.assertIsNone(tc.value)

    def test_eq_match(self):
        tc = TriggerCondition(field="severity", operator="eq", value="critical")
        self.assertTrue(tc.matches({"severity": "critical"}))
        self.assertFalse(tc.matches({"severity": "low"}))

    def test_ne_match(self):
        tc = TriggerCondition(field="severity", operator="ne", value="low")
        self.assertTrue(tc.matches({"severity": "critical"}))
        self.assertFalse(tc.matches({"severity": "low"}))

    def test_contains_match(self):
        tc = TriggerCondition(field="description", operator="contains", value="malware")
        self.assertTrue(tc.matches({"description": "Detected malware activity"}))
        self.assertFalse(tc.matches({"description": "Normal traffic"}))

    def test_regex_match(self):
        tc = TriggerCondition(field="source_ip", operator="regex", value=r"^192\.168\.")
        self.assertTrue(tc.matches({"source_ip": "192.168.1.100"}))
        self.assertFalse(tc.matches({"source_ip": "10.0.0.1"}))

    def test_regex_invalid(self):
        tc = TriggerCondition(field="x", operator="regex", value="[invalid")
        self.assertFalse(tc.matches({"x": "test"}))

    def test_gt_match(self):
        tc = TriggerCondition(field="score", operator="gt", value=7)
        self.assertTrue(tc.matches({"score": 8}))
        self.assertFalse(tc.matches({"score": 5}))

    def test_gt_non_numeric(self):
        tc = TriggerCondition(field="x", operator="gt", value=5)
        self.assertFalse(tc.matches({"x": "abc"}))

    def test_lt_match(self):
        tc = TriggerCondition(field="score", operator="lt", value=5)
        self.assertTrue(tc.matches({"score": 3}))
        self.assertFalse(tc.matches({"score": 8}))

    def test_lt_non_numeric(self):
        tc = TriggerCondition(field="x", operator="lt", value=5)
        self.assertFalse(tc.matches({"x": "abc"}))

    def test_in_match(self):
        tc = TriggerCondition(field="category", operator="in", value=["malware", "phishing"])
        self.assertTrue(tc.matches({"category": "malware"}))
        self.assertFalse(tc.matches({"category": "normal"}))

    def test_in_not_list(self):
        tc = TriggerCondition(field="x", operator="in", value="not_a_list")
        self.assertFalse(tc.matches({"x": "test"}))

    def test_exists_match(self):
        tc = TriggerCondition(field="indicator", operator="exists")
        self.assertTrue(tc.matches({"indicator": "anything"}))
        self.assertFalse(tc.matches({"other": "data"}))

    def test_missing_field(self):
        tc = TriggerCondition(field="missing", operator="eq", value="x")
        self.assertFalse(tc.matches({"other": "data"}))

    def test_unknown_operator(self):
        tc = TriggerCondition(field="x", operator="unknown", value="y")
        self.assertFalse(tc.matches({"x": "y"}))

    def test_to_dict(self):
        tc = TriggerCondition(field="a", operator="eq", value="b")
        d = tc.to_dict()
        self.assertEqual(d["field"], "a")
        self.assertEqual(d["operator"], "eq")
        self.assertEqual(d["value"], "b")

    def test_from_dict(self):
        tc = TriggerCondition.from_dict({"field": "x", "operator": "gt", "value": 10})
        self.assertEqual(tc.field, "x")
        self.assertEqual(tc.operator, "gt")
        self.assertEqual(tc.value, 10)

    def test_from_dict_defaults(self):
        tc = TriggerCondition.from_dict({})
        self.assertEqual(tc.field, "")
        self.assertEqual(tc.operator, "eq")
        self.assertIsNone(tc.value)


# ============================================================================
# ResponseAction Tests
# ============================================================================

class TestResponseAction(unittest.TestCase):
    def test_default_creation(self):
        a = ResponseAction(action_type="block_ip")
        self.assertTrue(a.action_id)
        self.assertEqual(a.action_type, "block_ip")
        self.assertEqual(a.rollback_action, "unblock_ip")  # auto-mapped

    def test_auto_rollback_mapping(self):
        a = ResponseAction(action_type="isolate_host")
        self.assertEqual(a.rollback_action, "unisolate_host")

    def test_no_rollback_for_custom(self):
        a = ResponseAction(action_type="send_notification")
        self.assertIsNone(a.rollback_action)

    def test_explicit_rollback(self):
        a = ResponseAction(action_type="block_ip", rollback_action="custom_unblock")
        self.assertEqual(a.rollback_action, "custom_unblock")

    def test_to_dict(self):
        a = ResponseAction(action_type="block_ip", parameters={"ip": "1.2.3.4"})
        d = a.to_dict()
        self.assertEqual(d["action_type"], "block_ip")
        self.assertEqual(d["parameters"]["ip"], "1.2.3.4")
        self.assertEqual(d["timeout_seconds"], 60)

    def test_from_dict(self):
        a = ResponseAction.from_dict({
            "action_type": "disable_user",
            "parameters": {"username": "attacker"},
            "retry_count": 2,
            "continue_on_failure": True,
        })
        self.assertEqual(a.action_type, "disable_user")
        self.assertEqual(a.parameters["username"], "attacker")
        self.assertEqual(a.retry_count, 2)
        self.assertTrue(a.continue_on_failure)

    def test_from_dict_empty(self):
        a = ResponseAction.from_dict({})
        self.assertEqual(a.action_type, "")
        self.assertEqual(a.parameters, {})


# ============================================================================
# PlaybookStep Tests
# ============================================================================

class TestPlaybookStep(unittest.TestCase):
    def test_default_creation(self):
        s = PlaybookStep(name="Block attacker")
        self.assertTrue(s.step_id)
        self.assertEqual(s.name, "Block attacker")
        self.assertEqual(s.status, "pending")

    def test_to_dict(self):
        action = ResponseAction(action_type="block_ip")
        s = PlaybookStep(name="Step 1", actions=[action], order=1)
        d = s.to_dict()
        self.assertEqual(d["name"], "Step 1")
        self.assertEqual(len(d["actions"]), 1)
        self.assertEqual(d["order"], 1)

    def test_from_dict(self):
        data = {
            "step_id": "s1",
            "name": "Test Step",
            "actions": [{"action_type": "block_ip", "parameters": {"ip": "1.1.1.1"}}],
            "status": "completed",
        }
        s = PlaybookStep.from_dict(data)
        self.assertEqual(s.step_id, "s1")
        self.assertEqual(len(s.actions), 1)
        self.assertEqual(s.actions[0].action_type, "block_ip")

    def test_from_dict_empty_actions(self):
        s = PlaybookStep.from_dict({})
        self.assertEqual(s.actions, [])


# ============================================================================
# Playbook Tests
# ============================================================================

class TestPlaybook(unittest.TestCase):
    def test_default_creation(self):
        pb = Playbook(name="Block Malware IPs")
        self.assertTrue(pb.playbook_id.startswith("pb-"))
        self.assertTrue(pb.created_at)
        self.assertEqual(pb.version, "1.0")
        self.assertTrue(pb.enabled)

    def test_matches_alert_and_logic(self):
        pb = Playbook(
            name="Test",
            trigger_match_all=True,
            trigger_conditions=[
                TriggerCondition(field="severity", operator="eq", value="critical"),
                TriggerCondition(field="type", operator="eq", value="malware"),
            ],
        )
        self.assertTrue(pb.matches_alert({"severity": "critical", "type": "malware"}))
        self.assertFalse(pb.matches_alert({"severity": "critical", "type": "normal"}))

    def test_matches_alert_or_logic(self):
        pb = Playbook(
            name="Test",
            trigger_match_all=False,
            trigger_conditions=[
                TriggerCondition(field="severity", operator="eq", value="critical"),
                TriggerCondition(field="type", operator="eq", value="malware"),
            ],
        )
        self.assertTrue(pb.matches_alert({"severity": "low", "type": "malware"}))
        self.assertFalse(pb.matches_alert({"severity": "low", "type": "normal"}))

    def test_matches_disabled(self):
        pb = Playbook(name="Test", enabled=False,
                      trigger_conditions=[TriggerCondition(field="x", operator="eq", value="y")])
        self.assertFalse(pb.matches_alert({"x": "y"}))

    def test_matches_no_conditions(self):
        pb = Playbook(name="Test")
        self.assertFalse(pb.matches_alert({"x": "y"}))

    def test_to_dict(self):
        pb = Playbook(name="PB1", tags=["critical", "malware"])
        d = pb.to_dict()
        self.assertEqual(d["name"], "PB1")
        self.assertEqual(d["tags"], ["critical", "malware"])

    def test_from_dict(self):
        data = {
            "playbook_id": "pb-test",
            "name": "Test PB",
            "trigger_conditions": [{"field": "x", "operator": "eq", "value": "y"}],
            "steps": [{"name": "S1", "actions": [{"action_type": "block_ip"}]}],
            "tags": ["test"],
        }
        pb = Playbook.from_dict(data)
        self.assertEqual(pb.playbook_id, "pb-test")
        self.assertEqual(len(pb.trigger_conditions), 1)
        self.assertEqual(len(pb.steps), 1)
        self.assertEqual(pb.tags, ["test"])

    def test_from_dict_invalid_tags(self):
        pb = Playbook.from_dict({"tags": "not_a_list"})
        self.assertEqual(pb.tags, [])

    def test_from_dict_none_conditions(self):
        pb = Playbook.from_dict({"trigger_conditions": None})
        self.assertEqual(pb.trigger_conditions, [])


# ============================================================================
# ExecutionLog Tests
# ============================================================================

class TestExecutionLog(unittest.TestCase):
    def test_default_creation(self):
        log = ExecutionLog(execution_id="e1", message="Test")
        self.assertTrue(log.log_id)
        self.assertTrue(log.timestamp)
        self.assertEqual(log.execution_id, "e1")

    def test_to_dict(self):
        log = ExecutionLog(execution_id="e1", status="info", message="Test")
        d = log.to_dict()
        self.assertEqual(d["execution_id"], "e1")
        self.assertEqual(d["status"], "info")

    def test_from_dict(self):
        log = ExecutionLog.from_dict({"execution_id": "e2", "message": "Hello"})
        self.assertEqual(log.execution_id, "e2")
        self.assertEqual(log.message, "Hello")

    def test_from_dict_empty(self):
        log = ExecutionLog.from_dict({})
        self.assertEqual(log.details, {})


# ============================================================================
# PlaybookExecution Tests
# ============================================================================

class TestPlaybookExecution(unittest.TestCase):
    def test_default_creation(self):
        ex = PlaybookExecution(playbook_id="pb-1", alert_id="a1")
        self.assertTrue(ex.execution_id.startswith("exec-"))
        self.assertTrue(ex.started_at)
        self.assertEqual(ex.status, "pending")
        self.assertFalse(ex.dry_run)

    def test_is_terminal(self):
        ex = PlaybookExecution(status="completed")
        self.assertTrue(ex.is_terminal)
        ex.status = "running"
        self.assertFalse(ex.is_terminal)
        ex.status = "failed"
        self.assertTrue(ex.is_terminal)
        ex.status = "cancelled"
        self.assertTrue(ex.is_terminal)
        ex.status = "rolled_back"
        self.assertTrue(ex.is_terminal)

    def test_to_dict(self):
        ex = PlaybookExecution(playbook_id="pb-1")
        d = ex.to_dict()
        self.assertEqual(d["playbook_id"], "pb-1")
        self.assertIn("steps", d)

    def test_from_dict(self):
        data = {
            "execution_id": "exec-123",
            "playbook_id": "pb-1",
            "status": "running",
            "steps": [{"name": "S1", "actions": []}],
        }
        ex = PlaybookExecution.from_dict(data)
        self.assertEqual(ex.execution_id, "exec-123")
        self.assertEqual(len(ex.steps), 1)

    def test_from_dict_defaults(self):
        ex = PlaybookExecution.from_dict({})
        self.assertEqual(ex.alert_data, {})
        self.assertEqual(ex.result, {})


# ============================================================================
# Rollback Map Tests
# ============================================================================

class TestRollbackMap(unittest.TestCase):
    def test_block_ip_rollback(self):
        self.assertEqual(_ROLLBACK_MAP["block_ip"], "unblock_ip")

    def test_isolate_host_rollback(self):
        self.assertEqual(_ROLLBACK_MAP["isolate_host"], "unisolate_host")

    def test_disable_user_rollback(self):
        self.assertEqual(_ROLLBACK_MAP["disable_user"], "enable_user")

    def test_quarantine_file_rollback(self):
        self.assertEqual(_ROLLBACK_MAP["quarantine_file"], "restore_file")

    def test_dns_sinkhole_rollback(self):
        self.assertEqual(_ROLLBACK_MAP["dns_sinkhole"], "dns_unsinkhole")

    def test_all_entries(self):
        self.assertEqual(len(_ROLLBACK_MAP), 6)


# ============================================================================
# ActionHandler Tests
# ============================================================================

class TestActionHandler(unittest.TestCase):
    def setUp(self):
        self.handler = ActionHandler(dry_run=False)
        self.dry_handler = ActionHandler(dry_run=True)

    def test_dry_run(self):
        action = ResponseAction(action_type="block_ip", parameters={"ip": "1.2.3.4"})
        result = self.dry_handler.execute(action)
        self.assertTrue(result["success"])
        self.assertTrue(result["dry_run"])
        self.assertIn("DRY RUN", result["message"])

    def test_block_ip_iptables(self):
        action = ResponseAction(action_type="block_ip",
                                parameters={"ip": "10.0.0.1", "method": "iptables"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])
        self.assertIn("iptables", result["command"])

    def test_block_ip_firewalld(self):
        action = ResponseAction(action_type="block_ip",
                                parameters={"ip": "10.0.0.1", "method": "firewalld"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])
        self.assertIn("firewall-cmd", result["command"])

    def test_block_ip_default_method(self):
        action = ResponseAction(action_type="block_ip",
                                parameters={"ip": "10.0.0.1", "method": "other"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_block_ip_missing_param(self):
        action = ResponseAction(action_type="block_ip", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])
        self.assertIn("Missing", result["error"])

    def test_unblock_ip(self):
        action = ResponseAction(action_type="unblock_ip",
                                parameters={"ip": "10.0.0.1"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_unblock_ip_firewalld(self):
        action = ResponseAction(action_type="unblock_ip",
                                parameters={"ip": "10.0.0.1", "method": "firewalld"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_unblock_ip_missing(self):
        action = ResponseAction(action_type="unblock_ip", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_block_domain(self):
        action = ResponseAction(action_type="block_domain",
                                parameters={"domain": "evil.com"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_block_domain_missing(self):
        action = ResponseAction(action_type="block_domain", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_unblock_domain(self):
        action = ResponseAction(action_type="unblock_domain",
                                parameters={"domain": "evil.com"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_unblock_domain_missing(self):
        action = ResponseAction(action_type="unblock_domain", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_dns_sinkhole(self):
        action = ResponseAction(action_type="dns_sinkhole",
                                parameters={"domain": "malware.com", "sinkhole_ip": "127.0.0.1"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])
        self.assertEqual(result["sinkhole_ip"], "127.0.0.1")

    def test_dns_sinkhole_missing(self):
        action = ResponseAction(action_type="dns_sinkhole", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_dns_unsinkhole(self):
        action = ResponseAction(action_type="dns_unsinkhole",
                                parameters={"domain": "malware.com"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_dns_unsinkhole_missing(self):
        action = ResponseAction(action_type="dns_unsinkhole", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_isolate_host(self):
        action = ResponseAction(action_type="isolate_host",
                                parameters={"host": "workstation-01"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_isolate_host_missing(self):
        action = ResponseAction(action_type="isolate_host", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_unisolate_host(self):
        action = ResponseAction(action_type="unisolate_host",
                                parameters={"host": "workstation-01"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_unisolate_host_missing(self):
        action = ResponseAction(action_type="unisolate_host", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_disable_user(self):
        action = ResponseAction(action_type="disable_user",
                                parameters={"username": "compromised_user"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_disable_user_missing(self):
        action = ResponseAction(action_type="disable_user", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_enable_user(self):
        action = ResponseAction(action_type="enable_user",
                                parameters={"username": "user1"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_enable_user_missing(self):
        action = ResponseAction(action_type="enable_user", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_kill_process_pid(self):
        action = ResponseAction(action_type="kill_process",
                                parameters={"pid": 12345})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_kill_process_name(self):
        action = ResponseAction(action_type="kill_process",
                                parameters={"process_name": "malware.exe"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_kill_process_missing(self):
        action = ResponseAction(action_type="kill_process", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_quarantine_file(self):
        action = ResponseAction(action_type="quarantine_file",
                                parameters={"filepath": "/tmp/malware.bin"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_quarantine_file_missing(self):
        action = ResponseAction(action_type="quarantine_file", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_restore_file(self):
        action = ResponseAction(action_type="restore_file",
                                parameters={"filepath": "/tmp/malware.bin"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_restore_file_missing(self):
        action = ResponseAction(action_type="restore_file", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_update_firewall(self):
        action = ResponseAction(action_type="update_firewall",
                                parameters={"rules": [{"src": "10.0.0.0/8", "action": "deny"}]})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])
        self.assertEqual(result["rules_applied"], 1)

    def test_run_script(self):
        action = ResponseAction(action_type="run_script",
                                parameters={"script": "echo hello"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_run_script_missing(self):
        action = ResponseAction(action_type="run_script", parameters={})
        result = self.handler.execute(action)
        self.assertFalse(result["success"])

    def test_send_notification(self):
        action = ResponseAction(action_type="send_notification",
                                parameters={"channel": "slack", "recipients": ["#soc"],
                                             "message": "Alert!"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_collect_evidence(self):
        action = ResponseAction(action_type="collect_evidence",
                                parameters={"type": "memory_dump", "target": "host-01"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_custom_action(self):
        action = ResponseAction(action_type="custom",
                                parameters={"name": "my_action"})
        result = self.handler.execute(action)
        self.assertTrue(result["success"])

    def test_unknown_action(self):
        action = ResponseAction(action_type="nonexistent")
        # Override __post_init__ behavior
        action.action_type = "nonexistent"
        result = self.handler.execute(action)
        self.assertFalse(result["success"])
        self.assertIn("No handler", result["error"])

    def test_register_custom_handler(self):
        def custom_handler(params, ctx):
            return {"success": True, "message": "Custom!"}
        self.handler.register_handler("my_custom", custom_handler)
        action = ResponseAction(action_type="my_custom")
        action.action_type = "my_custom"
        result = self.handler.execute(action)
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "Custom!")

    def test_retry_on_failure(self):
        call_count = {"n": 0}
        def failing_handler(params, ctx):
            call_count["n"] += 1
            if call_count["n"] < 3:
                raise ValueError("Temporary failure")
            return {"success": True, "message": "OK"}
        self.handler.register_handler("retry_test", failing_handler)
        action = ResponseAction(action_type="retry_test", retry_count=3)
        action.action_type = "retry_test"
        result = self.handler.execute(action)
        self.assertTrue(result["success"])
        self.assertEqual(call_count["n"], 3)

    def test_retry_exhausted(self):
        def always_fail(params, ctx):
            raise ValueError("Permanent failure")
        self.handler.register_handler("fail_test", always_fail)
        action = ResponseAction(action_type="fail_test", retry_count=1)
        action.action_type = "fail_test"
        result = self.handler.execute(action)
        self.assertFalse(result["success"])
        self.assertIn("2 attempts", result["error"])


# ============================================================================
# AutoResponseStore Tests
# ============================================================================

class TestAutoResponseStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_response.db")
        self.store = AutoResponseStore(db_path=self.db_path)

    def test_init_creates_db(self):
        self.assertTrue(os.path.exists(self.db_path))

    # --- Playbook CRUD ---
    def test_save_and_get_playbook(self):
        pb = Playbook(name="Test PB")
        self.store.save_playbook(pb)
        retrieved = self.store.get_playbook(pb.playbook_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "Test PB")

    def test_get_playbook_not_found(self):
        self.assertIsNone(self.store.get_playbook("nonexistent"))

    def test_list_playbooks(self):
        self.store.save_playbook(Playbook(name="PB1"))
        self.store.save_playbook(Playbook(name="PB2"))
        pbs = self.store.list_playbooks()
        self.assertEqual(len(pbs), 2)

    def test_list_playbooks_enabled_only(self):
        pb1 = Playbook(name="PB1", enabled=True)
        pb2 = Playbook(name="PB2", enabled=False)
        self.store.save_playbook(pb1)
        self.store.save_playbook(pb2)
        enabled = self.store.list_playbooks(enabled_only=True)
        self.assertEqual(len(enabled), 1)
        self.assertEqual(enabled[0].name, "PB1")

    def test_delete_playbook(self):
        pb = Playbook(name="ToDelete")
        self.store.save_playbook(pb)
        self.assertTrue(self.store.delete_playbook(pb.playbook_id))
        self.assertIsNone(self.store.get_playbook(pb.playbook_id))

    def test_delete_playbook_not_found(self):
        self.assertFalse(self.store.delete_playbook("nonexistent"))

    def test_update_playbook(self):
        pb = Playbook(name="Original")
        self.store.save_playbook(pb)
        pb.name = "Updated"
        self.store.save_playbook(pb)
        retrieved = self.store.get_playbook(pb.playbook_id)
        self.assertEqual(retrieved.name, "Updated")

    # --- Execution CRUD ---
    def test_save_and_get_execution(self):
        ex = PlaybookExecution(playbook_id="pb-1", alert_id="a1")
        self.store.save_execution(ex)
        retrieved = self.store.get_execution(ex.execution_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.playbook_id, "pb-1")

    def test_get_execution_not_found(self):
        self.assertIsNone(self.store.get_execution("nonexistent"))

    def test_list_executions(self):
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="completed"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="failed"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-2", status="completed"))
        self.assertEqual(len(self.store.list_executions()), 3)

    def test_list_executions_filter_status(self):
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="completed"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="failed"))
        completed = self.store.list_executions(status="completed")
        self.assertEqual(len(completed), 1)

    def test_list_executions_filter_playbook(self):
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-2"))
        self.assertEqual(len(self.store.list_executions(playbook_id="pb-1")), 1)

    def test_list_executions_filter_alert(self):
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", alert_id="a1"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", alert_id="a2"))
        self.assertEqual(len(self.store.list_executions(alert_id="a1")), 1)

    def test_list_executions_limit_offset(self):
        for i in range(5):
            self.store.save_execution(PlaybookExecution(playbook_id=f"pb-{i}"))
        result = self.store.list_executions(limit=2, offset=1)
        self.assertEqual(len(result), 2)

    def test_count_executions(self):
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="completed"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="failed"))
        self.assertEqual(self.store.count_executions(), 2)
        self.assertEqual(self.store.count_executions(status="completed"), 1)

    # --- Logs ---
    def test_add_and_get_logs(self):
        log1 = ExecutionLog(execution_id="e1", message="Step 1 started")
        log2 = ExecutionLog(execution_id="e1", message="Step 1 completed")
        log3 = ExecutionLog(execution_id="e2", message="Other exec")
        self.store.add_log(log1)
        self.store.add_log(log2)
        self.store.add_log(log3)
        logs = self.store.get_logs("e1")
        self.assertEqual(len(logs), 2)

    def test_get_logs_limit(self):
        for i in range(10):
            self.store.add_log(ExecutionLog(execution_id="e1", message=f"Log {i}"))
        logs = self.store.get_logs("e1", limit=5)
        self.assertEqual(len(logs), 5)

    # --- Stats ---
    def test_stats(self):
        self.store.save_playbook(Playbook(name="PB1"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="completed"))
        self.store.save_execution(PlaybookExecution(playbook_id="pb-1", status="failed"))
        stats = self.store.get_stats()
        self.assertEqual(stats["total_executions"], 2)
        self.assertEqual(stats["playbook_count"], 1)
        self.assertEqual(stats["by_status"]["completed"], 1)
        self.assertEqual(stats["by_status"]["failed"], 1)

    def test_store_default_path(self):
        with patch.dict(os.environ, {"SOC_AUTO_RESPONSE_DB": os.path.join(self.tmpdir, "env_test.db")}):
            store = AutoResponseStore()
            self.assertIn("env_test.db", store._db_path)

    def test_corrupt_json_playbook(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO playbooks VALUES (?, ?, ?, ?)",
                      ("corrupt", "{bad json", "2024-01-01", "2024-01-01"))
        conn.commit()
        conn.close()
        result = self.store.get_playbook("corrupt")
        # Should return Playbook with defaults due to empty dict from failed parse
        self.assertIsNotNone(result)

    def test_corrupt_json_execution(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO executions VALUES (?, ?, ?, ?, ?, ?, ?)",
                      ("corrupt", "pb-1", "a1", "pending", "{bad", "2024-01-01", None))
        conn.commit()
        conn.close()
        result = self.store.get_execution("corrupt")
        self.assertIsNotNone(result)

    def test_corrupt_json_in_list(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO playbooks VALUES (?, ?, ?, ?)",
                      ("corrupt", "not json", "2024-01-01", "2024-01-01"))
        conn.commit()
        conn.close()
        pbs = self.store.list_playbooks()
        self.assertEqual(len(pbs), 0)  # Skipped corrupt entries


# ============================================================================
# AutoResponseEngine Tests
# ============================================================================

class TestAutoResponseEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "engine_test.db")
        self.engine = AutoResponseEngine(db_path=self.db_path, dry_run=True)

    def _create_playbook(self, name="Test PB", trigger_field="severity",
                         trigger_value="critical", action_type="block_ip",
                         action_params=None):
        pb = Playbook(
            name=name,
            trigger_conditions=[
                TriggerCondition(field=trigger_field, operator="eq", value=trigger_value),
            ],
            steps=[
                PlaybookStep(
                    name="Step 1",
                    order=1,
                    actions=[
                        ResponseAction(
                            action_type=action_type,
                            parameters=action_params or {"ip": "10.0.0.1"},
                        ),
                    ],
                ),
            ],
        )
        return self.engine.add_playbook(pb)

    # --- Playbook Management ---
    def test_add_playbook(self):
        pb = self._create_playbook()
        self.assertIsNotNone(self.engine.get_playbook(pb.playbook_id))

    def test_list_playbooks(self):
        self._create_playbook("PB1")
        self._create_playbook("PB2")
        self.assertEqual(len(self.engine.list_playbooks()), 2)

    def test_list_playbooks_enabled_only(self):
        pb = self._create_playbook("PB1")
        pb2 = Playbook(name="PB2", enabled=False)
        self.engine.add_playbook(pb2)
        self.assertEqual(len(self.engine.list_playbooks(enabled_only=True)), 1)

    def test_remove_playbook(self):
        pb = self._create_playbook()
        self.assertTrue(self.engine.remove_playbook(pb.playbook_id))
        self.assertIsNone(self.engine.get_playbook(pb.playbook_id))

    def test_update_playbook(self):
        pb = self._create_playbook("Original")
        pb.name = "Updated"
        self.engine.update_playbook(pb)
        retrieved = self.engine.get_playbook(pb.playbook_id)
        self.assertEqual(retrieved.name, "Updated")

    # --- Matching ---
    def test_find_matching_playbooks(self):
        self._create_playbook("PB1", trigger_value="critical")
        self._create_playbook("PB2", trigger_value="low")
        matches = self.engine.find_matching_playbooks({"severity": "critical"})
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].name, "PB1")

    def test_find_matching_no_match(self):
        self._create_playbook("PB1", trigger_value="critical")
        matches = self.engine.find_matching_playbooks({"severity": "info"})
        self.assertEqual(len(matches), 0)

    # --- Trigger ---
    def test_trigger_matching(self):
        self._create_playbook("PB1", trigger_value="critical")
        executions = self.engine.trigger(
            alert_id="alert-1",
            alert_data={"severity": "critical"},
            require_approval=False,
        )
        self.assertEqual(len(executions), 1)
        self.assertEqual(executions[0].status, PlaybookStatus.COMPLETED.value)

    def test_trigger_no_match(self):
        self._create_playbook("PB1", trigger_value="critical")
        executions = self.engine.trigger(
            alert_id="alert-1",
            alert_data={"severity": "info"},
            require_approval=False,
        )
        self.assertEqual(len(executions), 0)

    def test_trigger_multiple_playbooks(self):
        self._create_playbook("PB1", trigger_value="critical")
        self._create_playbook("PB2", trigger_value="critical")
        executions = self.engine.trigger(
            alert_id="alert-1",
            alert_data={"severity": "critical"},
            require_approval=False,
        )
        self.assertEqual(len(executions), 2)

    def test_trigger_dry_run(self):
        self._create_playbook("PB1", trigger_value="critical")
        executions = self.engine.trigger(
            alert_id="alert-1",
            alert_data={"severity": "critical"},
            dry_run=True,
            require_approval=False,
        )
        self.assertEqual(len(executions), 1)
        self.assertEqual(executions[0].dry_run, True)

    # --- Execute Playbook ---
    def test_execute_playbook_not_found(self):
        result = self.engine.execute_playbook("nonexistent", require_approval=False)
        self.assertIsNone(result)

    def test_execute_playbook_success(self):
        pb = self._create_playbook()
        result = self.engine.execute_playbook(
            pb.playbook_id, alert_id="a1", require_approval=False)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)
        self.assertTrue(result.completed_at)

    def test_execute_playbook_with_approval(self):
        mock_approval = MagicMock()
        mock_req = MagicMock()
        mock_req.request_id = "apr-123"
        mock_approval.submit.return_value = mock_req
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "apr.db"),
                                    approval_engine=mock_approval)
        pb = Playbook(name="NeedApproval",
                      trigger_conditions=[TriggerCondition(field="x", operator="eq", value="y")],
                      steps=[PlaybookStep(name="S1", actions=[ResponseAction(action_type="block_ip",
                                                                              parameters={"ip": "1.1.1.1"})])])
        engine.add_playbook(pb)
        result = engine.execute_playbook(pb.playbook_id, alert_id="a1", require_approval=True)
        self.assertEqual(result.status, PlaybookStatus.AWAITING_APPROVAL.value)
        self.assertEqual(result.approval_id, "apr-123")

    def test_execute_approval_failure_continues(self):
        mock_approval = MagicMock()
        mock_approval.submit.side_effect = Exception("Approval service down")
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "apr_fail.db"),
                                    dry_run=True, approval_engine=mock_approval)
        pb = Playbook(name="ApprFail",
                      trigger_conditions=[TriggerCondition(field="x", operator="eq", value="y")],
                      steps=[PlaybookStep(name="S1", actions=[ResponseAction(action_type="block_ip",
                                                                              parameters={"ip": "1.1.1.1"})])])
        engine.add_playbook(pb)
        result = engine.execute_playbook(pb.playbook_id, require_approval=True)
        # Should proceed without approval on failure
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)

    # --- Approve Execution ---
    def test_approve_execution(self):
        pb = self._create_playbook()
        mock_approval = MagicMock()
        mock_req = MagicMock()
        mock_req.request_id = "apr-456"
        mock_approval.submit.return_value = mock_req
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "approve.db"),
                                    dry_run=True, approval_engine=mock_approval)
        engine.add_playbook(pb)
        ex = engine.execute_playbook(pb.playbook_id, require_approval=True)
        self.assertEqual(ex.status, PlaybookStatus.AWAITING_APPROVAL.value)
        approved = engine.approve_execution(ex.execution_id, approver="admin")
        self.assertEqual(approved.status, PlaybookStatus.COMPLETED.value)

    def test_approve_execution_not_found(self):
        self.assertIsNone(self.engine.approve_execution("nonexistent"))

    def test_approve_execution_not_awaiting(self):
        pb = self._create_playbook()
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        result = self.engine.approve_execution(ex.execution_id)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)  # Already completed

    # --- Cancel Execution ---
    def test_cancel_execution(self):
        mock_approval = MagicMock()
        mock_req = MagicMock()
        mock_req.request_id = "apr-789"
        mock_approval.submit.return_value = mock_req
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "cancel.db"),
                                    dry_run=True, approval_engine=mock_approval)
        pb = self._create_playbook()
        engine.add_playbook(pb)
        ex = engine.execute_playbook(pb.playbook_id, require_approval=True)
        cancelled = engine.cancel_execution(ex.execution_id, actor="admin")
        self.assertEqual(cancelled.status, PlaybookStatus.CANCELLED.value)

    def test_cancel_execution_not_found(self):
        self.assertIsNone(self.engine.cancel_execution("nonexistent"))

    def test_cancel_terminal_execution(self):
        pb = self._create_playbook()
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        # Already completed, cannot cancel
        result = self.engine.cancel_execution(ex.execution_id)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)

    # --- Step Failure Handling ---
    def test_step_failure_stops_execution(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "fail.db"),
                                    dry_run=False)
        pb = Playbook(name="FailPB",
                      steps=[
                          PlaybookStep(name="S1", order=1, actions=[
                              ResponseAction(action_type="block_ip", parameters={}),  # Will fail: no IP
                          ]),
                          PlaybookStep(name="S2", order=2, actions=[
                              ResponseAction(action_type="block_domain", parameters={"domain": "ok.com"}),
                          ]),
                      ])
        engine.add_playbook(pb)
        result = engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(result.status, PlaybookStatus.FAILED.value)
        self.assertTrue(result.error)

    def test_continue_on_failure(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "cont.db"),
                                    dry_run=False)
        pb = Playbook(name="ContPB",
                      steps=[
                          PlaybookStep(name="S1", order=1, actions=[
                              ResponseAction(action_type="block_ip", parameters={},
                                             continue_on_failure=True),  # Fails but continues
                          ]),
                          PlaybookStep(name="S2", order=2, actions=[
                              ResponseAction(action_type="block_domain",
                                             parameters={"domain": "ok.com"}),
                          ]),
                      ])
        engine.add_playbook(pb)
        result = engine.execute_playbook(pb.playbook_id, require_approval=False)
        # Should be partially completed since S1 failed but continued
        self.assertIn(result.status,
                      [PlaybookStatus.PARTIALLY_COMPLETED.value, PlaybookStatus.COMPLETED.value])

    # --- Rollback ---
    def test_rollback_success(self):
        pb = self._create_playbook(action_type="block_ip", action_params={"ip": "1.2.3.4"})
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        rolled = self.engine.rollback(ex.execution_id, actor="admin")
        self.assertEqual(rolled.rollback_status, RollbackStatus.COMPLETED.value)
        self.assertEqual(rolled.status, PlaybookStatus.ROLLED_BACK.value)

    def test_rollback_not_found(self):
        self.assertIsNone(self.engine.rollback("nonexistent"))

    def test_rollback_already_done(self):
        pb = self._create_playbook()
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.engine.rollback(ex.execution_id)
        result = self.engine.rollback(ex.execution_id)
        self.assertEqual(result.rollback_status, RollbackStatus.COMPLETED.value)

    def test_rollback_no_rollback_action(self):
        pb = Playbook(name="NoRollback",
                      steps=[PlaybookStep(name="S1", actions=[
                          ResponseAction(action_type="send_notification",
                                         parameters={"channel": "email", "recipients": ["a@b.com"],
                                                      "message": "Alert"}),
                      ])])
        self.engine.add_playbook(pb)
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        rolled = self.engine.rollback(ex.execution_id)
        self.assertEqual(rolled.rollback_status, RollbackStatus.COMPLETED.value)

    # --- Query ---
    def test_get_execution(self):
        pb = self._create_playbook()
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        retrieved = self.engine.get_execution(ex.execution_id)
        self.assertEqual(retrieved.execution_id, ex.execution_id)

    def test_list_executions(self):
        pb = self._create_playbook()
        self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        execs = self.engine.list_executions()
        self.assertEqual(len(execs), 2)

    def test_get_logs(self):
        pb = self._create_playbook()
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        logs = self.engine.get_logs(ex.execution_id)
        self.assertTrue(len(logs) > 0)

    # --- Stats ---
    def test_stats(self):
        pb = self._create_playbook()
        self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        stats = self.engine.get_stats()
        self.assertEqual(stats["total_executions"], 1)
        self.assertIn("engine", stats)
        self.assertGreaterEqual(stats["engine"]["executions_started"], 1)

    def test_reset_stats(self):
        pb = self._create_playbook()
        self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.engine.reset_stats()
        self.assertEqual(self.engine.stats["executions_started"], 0)

    # --- Callbacks ---
    def test_callback_on_start(self):
        results = []
        self.engine.register_callback("on_execution_start", lambda ex: results.append("start"))
        pb = self._create_playbook()
        self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertIn("start", results)

    def test_callback_on_complete(self):
        results = []
        self.engine.register_callback("on_execution_complete", lambda ex: results.append("done"))
        pb = self._create_playbook()
        self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertIn("done", results)

    def test_callback_on_fail(self):
        results = []
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "fail_cb.db"),
                                    dry_run=False)
        engine.register_callback("on_execution_fail", lambda ex: results.append("fail"))
        pb = Playbook(name="FailCB",
                      steps=[PlaybookStep(name="S1", actions=[
                          ResponseAction(action_type="block_ip", parameters={}),
                      ])])
        engine.add_playbook(pb)
        engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertIn("fail", results)

    def test_callback_on_step_complete(self):
        results = []
        self.engine.register_callback("on_step_complete", lambda ex, step: results.append(step.name))
        pb = self._create_playbook()
        self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(len(results), 1)

    def test_callback_on_rollback(self):
        results = []
        self.engine.register_callback("on_rollback", lambda ex: results.append("rollback"))
        pb = self._create_playbook()
        ex = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.engine.rollback(ex.execution_id)
        self.assertIn("rollback", results)

    def test_callback_exception_handled(self):
        def bad_cb(ex):
            raise RuntimeError("Callback error")
        self.engine.register_callback("on_execution_start", bad_cb)
        pb = self._create_playbook()
        # Should not raise
        result = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)

    # --- Custom Action Handler ---
    def test_register_action_handler(self):
        def my_handler(params, ctx):
            return {"success": True, "message": "Custom executed"}
        self.engine.register_action_handler("my_action", my_handler)
        pb = Playbook(name="Custom",
                      steps=[PlaybookStep(name="S1", actions=[
                          ResponseAction(action_type="my_action", parameters={}),
                      ])])
        # Override action_type after creation (avoid rollback mapping)
        pb.steps[0].actions[0].action_type = "my_action"
        self.engine.add_playbook(pb)
        result = self.engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)


# ============================================================================
# Flask Blueprint Tests
# ============================================================================

class TestAutoResponseBlueprint(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.engine = AutoResponseEngine(
            db_path=os.path.join(self.tmpdir, "bp_test.db"),
            dry_run=True,
        )
        from flask import Flask
        self.app = Flask(__name__)
        bp = create_auto_response_blueprint(engine=self.engine)
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()
        # Add a playbook
        self.pb = Playbook(
            name="Test PB",
            trigger_conditions=[TriggerCondition(field="severity", operator="eq", value="critical")],
            steps=[PlaybookStep(name="S1", actions=[
                ResponseAction(action_type="block_ip", parameters={"ip": "10.0.0.1"}),
            ])],
        )
        self.engine.add_playbook(self.pb)

    # --- Playbook Endpoints ---
    def test_list_playbooks(self):
        resp = self.client.get("/api/v1/soc/response/playbooks")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 1)

    def test_list_playbooks_enabled_only(self):
        resp = self.client.get("/api/v1/soc/response/playbooks?enabled_only=true")
        self.assertEqual(resp.status_code, 200)

    def test_create_playbook(self):
        resp = self.client.post("/api/v1/soc/response/playbooks",
                                json={"name": "New PB", "steps": []})
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["playbook"]["name"], "New PB")

    def test_create_playbook_missing_name(self):
        resp = self.client.post("/api/v1/soc/response/playbooks", json={})
        self.assertEqual(resp.status_code, 400)

    def test_get_playbook(self):
        resp = self.client.get(f"/api/v1/soc/response/playbooks/{self.pb.playbook_id}")
        self.assertEqual(resp.status_code, 200)

    def test_get_playbook_not_found(self):
        resp = self.client.get("/api/v1/soc/response/playbooks/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_update_playbook(self):
        resp = self.client.put(f"/api/v1/soc/response/playbooks/{self.pb.playbook_id}",
                               json={"name": "Updated PB"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["playbook"]["name"], "Updated PB")

    def test_update_playbook_not_found(self):
        resp = self.client.put("/api/v1/soc/response/playbooks/nonexistent",
                               json={"name": "X"})
        self.assertEqual(resp.status_code, 404)

    def test_delete_playbook(self):
        resp = self.client.delete(f"/api/v1/soc/response/playbooks/{self.pb.playbook_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["deleted"])

    def test_delete_playbook_not_found(self):
        resp = self.client.delete("/api/v1/soc/response/playbooks/nonexistent")
        self.assertEqual(resp.status_code, 404)

    # --- Trigger Endpoint ---
    def test_trigger_endpoint(self):
        resp = self.client.post("/api/v1/soc/response/trigger",
                                json={
                                    "alert_id": "alert-1",
                                    "alert_data": {"severity": "critical"},
                                    "require_approval": False,
                                })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 1)

    def test_trigger_missing_alert_id(self):
        resp = self.client.post("/api/v1/soc/response/trigger", json={})
        self.assertEqual(resp.status_code, 400)

    def test_trigger_no_match(self):
        resp = self.client.post("/api/v1/soc/response/trigger",
                                json={"alert_id": "a1", "alert_data": {"severity": "low"},
                                      "require_approval": False})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["count"], 0)

    # --- Execute Endpoint ---
    def test_execute_endpoint(self):
        resp = self.client.post(f"/api/v1/soc/response/execute/{self.pb.playbook_id}",
                                json={"alert_id": "a1", "require_approval": False})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["execution"]["status"], "completed")

    def test_execute_not_found(self):
        resp = self.client.post("/api/v1/soc/response/execute/nonexistent",
                                json={"require_approval": False})
        self.assertEqual(resp.status_code, 404)

    # --- Execution Endpoints ---
    def test_list_executions(self):
        self.engine.execute_playbook(self.pb.playbook_id, require_approval=False)
        resp = self.client.get("/api/v1/soc/response/executions")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(resp.get_json()["count"], 1)

    def test_list_executions_with_filters(self):
        self.engine.execute_playbook(self.pb.playbook_id, require_approval=False)
        resp = self.client.get("/api/v1/soc/response/executions?status=completed&limit=10&offset=0")
        self.assertEqual(resp.status_code, 200)

    def test_get_execution(self):
        ex = self.engine.execute_playbook(self.pb.playbook_id, require_approval=False)
        resp = self.client.get(f"/api/v1/soc/response/executions/{ex.execution_id}")
        self.assertEqual(resp.status_code, 200)

    def test_get_execution_not_found(self):
        resp = self.client.get("/api/v1/soc/response/executions/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_approve_execution(self):
        mock_approval = MagicMock()
        mock_req = MagicMock()
        mock_req.request_id = "apr-test"
        mock_approval.submit.return_value = mock_req
        engine = AutoResponseEngine(
            db_path=os.path.join(self.tmpdir, "bp_apr.db"),
            dry_run=True, approval_engine=mock_approval,
        )
        engine.add_playbook(self.pb)
        ex = engine.execute_playbook(self.pb.playbook_id, require_approval=True)
        # Create new Flask app with this engine
        from flask import Flask
        app = Flask(__name__)
        app.register_blueprint(create_auto_response_blueprint(engine=engine))
        client = app.test_client()
        resp = client.post(f"/api/v1/soc/response/executions/{ex.execution_id}/approve",
                           json={"approver": "admin"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["execution"]["status"], "completed")

    def test_approve_execution_not_found(self):
        resp = self.client.post("/api/v1/soc/response/executions/nonexistent/approve",
                                json={"approver": "admin"})
        self.assertEqual(resp.status_code, 404)

    def test_cancel_execution(self):
        mock_approval = MagicMock()
        mock_req = MagicMock()
        mock_req.request_id = "apr-cancel"
        mock_approval.submit.return_value = mock_req
        engine = AutoResponseEngine(
            db_path=os.path.join(self.tmpdir, "bp_cancel.db"),
            dry_run=True, approval_engine=mock_approval,
        )
        engine.add_playbook(self.pb)
        ex = engine.execute_playbook(self.pb.playbook_id, require_approval=True)
        from flask import Flask
        app = Flask(__name__)
        app.register_blueprint(create_auto_response_blueprint(engine=engine))
        client = app.test_client()
        resp = client.post(f"/api/v1/soc/response/executions/{ex.execution_id}/cancel",
                           json={"actor": "admin"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["execution"]["status"], "cancelled")

    def test_cancel_execution_not_found(self):
        resp = self.client.post("/api/v1/soc/response/executions/nonexistent/cancel",
                                json={"actor": "admin"})
        self.assertEqual(resp.status_code, 404)

    def test_rollback_execution(self):
        ex = self.engine.execute_playbook(self.pb.playbook_id, require_approval=False)
        resp = self.client.post(f"/api/v1/soc/response/executions/{ex.execution_id}/rollback",
                                json={"actor": "admin"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["execution"]["rollback_status"], "completed")

    def test_rollback_execution_not_found(self):
        resp = self.client.post("/api/v1/soc/response/executions/nonexistent/rollback",
                                json={"actor": "admin"})
        self.assertEqual(resp.status_code, 404)

    def test_execution_logs(self):
        ex = self.engine.execute_playbook(self.pb.playbook_id, require_approval=False)
        resp = self.client.get(f"/api/v1/soc/response/executions/{ex.execution_id}/logs")
        self.assertEqual(resp.status_code, 200)
        self.assertGreater(resp.get_json()["count"], 0)

    # --- Stats ---
    def test_stats_endpoint(self):
        resp = self.client.get("/api/v1/soc/response/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total_executions", data)


# ============================================================================
# Global Singleton Tests
# ============================================================================

class TestGlobalSingleton(unittest.TestCase):
    def setUp(self):
        reset_global_engine()

    def tearDown(self):
        reset_global_engine()

    def test_get_returns_instance(self):
        with patch.dict(os.environ, {"SOC_AUTO_RESPONSE_DB":
                                      os.path.join(tempfile.mkdtemp(), "singleton.db")}):
            engine = get_auto_response_engine()
            self.assertIsInstance(engine, AutoResponseEngine)

    def test_same_instance(self):
        with patch.dict(os.environ, {"SOC_AUTO_RESPONSE_DB":
                                      os.path.join(tempfile.mkdtemp(), "singleton2.db")}):
            e1 = get_auto_response_engine()
            e2 = get_auto_response_engine()
            self.assertIs(e1, e2)

    def test_reset(self):
        with patch.dict(os.environ, {"SOC_AUTO_RESPONSE_DB":
                                      os.path.join(tempfile.mkdtemp(), "singleton3.db")}):
            e1 = get_auto_response_engine()
            reset_global_engine()
            e2 = get_auto_response_engine()
            self.assertIsNot(e1, e2)


# ============================================================================
# Blueprint No Flask Test
# ============================================================================

class TestBlueprintNoFlask(unittest.TestCase):
    def test_no_flask_returns_none(self):
        """When Flask import fails inside the function, it returns None."""
        original_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "flask":
                raise ImportError("No module named 'flask'")
            return original_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=mock_import):
            bp = create_auto_response_blueprint()
            self.assertIsNone(bp)


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_empty_playbook_steps(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "edge1.db"), dry_run=True)
        pb = Playbook(name="Empty Steps", steps=[])
        engine.add_playbook(pb)
        result = engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)

    def test_playbook_with_empty_actions(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "edge2.db"), dry_run=True)
        pb = Playbook(name="Empty Actions",
                      steps=[PlaybookStep(name="S1", actions=[])])
        engine.add_playbook(pb)
        result = engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)

    def test_thread_safety(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "thread.db"), dry_run=True)
        pb = Playbook(name="ThreadPB",
                      trigger_conditions=[TriggerCondition(field="x", operator="eq", value="y")],
                      steps=[PlaybookStep(name="S1", actions=[
                          ResponseAction(action_type="block_ip", parameters={"ip": "1.1.1.1"}),
                      ])])
        engine.add_playbook(pb)

        errors = []
        def run_trigger():
            try:
                engine.trigger("alert-1", {"x": "y"}, require_approval=False)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=run_trigger) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(len(errors), 0)
        # All 4 threads should have created executions
        execs = engine.list_executions()
        self.assertEqual(len(execs), 4)

    def test_log_write_failure_handled(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "logfail.db"), dry_run=True)
        pb = Playbook(name="LogFail",
                      steps=[PlaybookStep(name="S1", actions=[
                          ResponseAction(action_type="block_ip", parameters={"ip": "1.1.1.1"}),
                      ])])
        engine.add_playbook(pb)
        # Monkey-patch store to fail on log writes
        original_add_log = engine._store.add_log
        engine._store.add_log = MagicMock(side_effect=Exception("DB write failed"))
        # Should not raise
        result = engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)
        engine._store.add_log = original_add_log

    def test_multiple_steps_sequential(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "multi.db"), dry_run=True)
        pb = Playbook(name="MultiStep",
                      steps=[
                          PlaybookStep(name="S1", order=1, actions=[
                              ResponseAction(action_type="block_ip", parameters={"ip": "1.1.1.1"}),
                          ]),
                          PlaybookStep(name="S2", order=2, actions=[
                              ResponseAction(action_type="disable_user",
                                             parameters={"username": "attacker"}),
                          ]),
                          PlaybookStep(name="S3", order=3, actions=[
                              ResponseAction(action_type="send_notification",
                                             parameters={"channel": "slack", "recipients": ["#soc"],
                                                          "message": "Alert handled"}),
                          ]),
                      ])
        engine.add_playbook(pb)
        result = engine.execute_playbook(pb.playbook_id, require_approval=False)
        self.assertEqual(result.status, PlaybookStatus.COMPLETED.value)
        self.assertEqual(len(result.steps), 3)
        for step in result.steps:
            self.assertEqual(step.status, StepStatus.COMPLETED.value)

    def test_rollback_partial_failure(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "rollpart.db"), dry_run=False)
        pb = Playbook(name="RollPartial",
                      steps=[PlaybookStep(name="S1", actions=[
                          ResponseAction(action_type="block_ip", parameters={"ip": "1.2.3.4"}),
                      ])])
        engine.add_playbook(pb)
        ex = engine.execute_playbook(pb.playbook_id, require_approval=False)

        # Make rollback handler fail
        def fail_unblock(params, ctx):
            return {"success": False, "error": "Rollback failed"}
        engine.handler.register_handler("unblock_ip", fail_unblock)
        rolled = engine.rollback(ex.execution_id)
        self.assertEqual(rolled.rollback_status, RollbackStatus.PARTIAL.value)


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_full_workflow_trigger_execute_rollback(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "integ1.db"), dry_run=True)

        # Create playbook
        pb = Playbook(
            name="Block Malware C2",
            trigger_conditions=[
                TriggerCondition(field="alert_type", operator="eq", value="c2_communication"),
                TriggerCondition(field="confidence", operator="gt", value=80),
            ],
            steps=[
                PlaybookStep(name="Block C2 IP", order=1, actions=[
                    ResponseAction(action_type="block_ip",
                                   parameters={"ip": "evil.com", "method": "iptables"}),
                ]),
                PlaybookStep(name="Sinkhole Domain", order=2, actions=[
                    ResponseAction(action_type="dns_sinkhole",
                                   parameters={"domain": "evil.com", "sinkhole_ip": "127.0.0.1"}),
                ]),
                PlaybookStep(name="Isolate Host", order=3, actions=[
                    ResponseAction(action_type="isolate_host",
                                   parameters={"host": "workstation-42"}),
                ]),
            ],
        )
        engine.add_playbook(pb)

        # Trigger
        alert_data = {"alert_type": "c2_communication", "confidence": 95, "source_ip": "10.0.0.5"}
        executions = engine.trigger("alert-001", alert_data, require_approval=False)
        self.assertEqual(len(executions), 1)
        ex = executions[0]
        self.assertEqual(ex.status, PlaybookStatus.COMPLETED.value)

        # Rollback
        rolled = engine.rollback(ex.execution_id, actor="analyst")
        self.assertEqual(rolled.rollback_status, RollbackStatus.COMPLETED.value)

        # Stats
        stats = engine.get_stats()
        self.assertEqual(stats["engine"]["executions_completed"], 1)
        self.assertEqual(stats["engine"]["rollbacks_performed"], 1)

    def test_approval_integration(self):
        mock_approval = MagicMock()
        mock_req = MagicMock()
        mock_req.request_id = "apr-integ"
        mock_approval.submit.return_value = mock_req

        engine = AutoResponseEngine(
            db_path=os.path.join(self.tmpdir, "integ2.db"),
            dry_run=True,
            approval_engine=mock_approval,
        )

        pb = Playbook(
            name="Disable Compromised User",
            trigger_conditions=[
                TriggerCondition(field="alert_type", operator="eq", value="credential_theft"),
            ],
            steps=[
                PlaybookStep(name="Disable User", order=1, actions=[
                    ResponseAction(action_type="disable_user",
                                   parameters={"username": "victim_user"}),
                ]),
            ],
        )
        engine.add_playbook(pb)

        # Trigger (with approval)
        executions = engine.trigger("alert-002",
                                    {"alert_type": "credential_theft"},
                                    require_approval=True)
        self.assertEqual(len(executions), 1)
        ex = executions[0]
        self.assertEqual(ex.status, PlaybookStatus.AWAITING_APPROVAL.value)

        # Approve
        approved = engine.approve_execution(ex.execution_id, approver="soc_lead")
        self.assertEqual(approved.status, PlaybookStatus.COMPLETED.value)

    def test_multi_playbook_priority_ordering(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "integ3.db"), dry_run=True)

        pb1 = Playbook(name="Low Priority", priority=5,
                       trigger_conditions=[TriggerCondition(field="x", operator="eq", value="y")],
                       steps=[PlaybookStep(name="S1", actions=[
                           ResponseAction(action_type="send_notification",
                                          parameters={"channel": "email", "recipients": ["a@b.com"],
                                                       "message": "Alert"}),
                       ])])
        pb2 = Playbook(name="High Priority", priority=1,
                       trigger_conditions=[TriggerCondition(field="x", operator="eq", value="y")],
                       steps=[PlaybookStep(name="S1", actions=[
                           ResponseAction(action_type="block_ip",
                                          parameters={"ip": "1.2.3.4"}),
                       ])])
        engine.add_playbook(pb1)
        engine.add_playbook(pb2)

        matches = engine.find_matching_playbooks({"x": "y"})
        self.assertEqual(len(matches), 2)
        self.assertEqual(matches[0].name, "High Priority")  # Priority 1 first
        self.assertEqual(matches[1].name, "Low Priority")   # Priority 5 second

    def test_or_trigger_conditions(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "integ4.db"), dry_run=True)
        pb = Playbook(
            name="OR Logic",
            trigger_match_all=False,
            trigger_conditions=[
                TriggerCondition(field="severity", operator="eq", value="critical"),
                TriggerCondition(field="category", operator="eq", value="ransomware"),
            ],
            steps=[PlaybookStep(name="S1", actions=[
                ResponseAction(action_type="isolate_host", parameters={"host": "host-1"}),
            ])],
        )
        engine.add_playbook(pb)

        # Should match on severity alone (OR)
        executions = engine.trigger("alert-3", {"severity": "critical", "category": "normal"},
                                    require_approval=False)
        self.assertEqual(len(executions), 1)

        # Should match on category alone (OR)
        executions = engine.trigger("alert-4", {"severity": "low", "category": "ransomware"},
                                    require_approval=False)
        self.assertEqual(len(executions), 1)

    def test_stats_tracking_comprehensive(self):
        engine = AutoResponseEngine(db_path=os.path.join(self.tmpdir, "integ5.db"), dry_run=True)
        pb = Playbook(
            name="Stats PB",
            trigger_conditions=[TriggerCondition(field="x", operator="eq", value="y")],
            steps=[
                PlaybookStep(name="S1", order=1, actions=[
                    ResponseAction(action_type="block_ip", parameters={"ip": "1.1.1.1"}),
                    ResponseAction(action_type="block_domain", parameters={"domain": "bad.com"}),
                ]),
                PlaybookStep(name="S2", order=2, actions=[
                    ResponseAction(action_type="isolate_host", parameters={"host": "h1"}),
                ]),
            ],
        )
        engine.add_playbook(pb)

        engine.trigger("a1", {"x": "y"}, require_approval=False)
        engine.trigger("a2", {"x": "y"}, require_approval=False)

        stats = engine.stats
        self.assertEqual(stats["executions_started"], 2)
        self.assertEqual(stats["executions_completed"], 2)
        self.assertEqual(stats["actions_executed"], 6)  # 3 actions × 2 executions


if __name__ == "__main__":
    unittest.main()
