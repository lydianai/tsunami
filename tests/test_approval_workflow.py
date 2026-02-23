#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for TSUNAMI SOC - Approval Workflow Engine
"""

import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.soc_core.approval_workflow import (
    ActionType,
    ApprovalPriority,
    ApprovalRequest,
    ApprovalStatus,
    ApprovalStore,
    ApprovalWorkflowEngine,
    AuditAction,
    AuditEntry,
    AutoApproveRule,
    EscalationLevel,
    create_approval_blueprint,
    get_approval_engine,
    reset_global_engine,
)


# ============================================================================
# Enum Tests
# ============================================================================

class TestApprovalStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ApprovalStatus.PENDING.value, "pending")
        self.assertEqual(ApprovalStatus.APPROVED.value, "approved")
        self.assertEqual(ApprovalStatus.REJECTED.value, "rejected")
        self.assertEqual(ApprovalStatus.EXPIRED.value, "expired")
        self.assertEqual(ApprovalStatus.CANCELLED.value, "cancelled")
        self.assertEqual(ApprovalStatus.ESCALATED.value, "escalated")

    def test_all_members(self):
        self.assertEqual(len(ApprovalStatus), 6)


class TestApprovalPriority(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ApprovalPriority.P1_CRITICAL.value, 1)
        self.assertEqual(ApprovalPriority.P4_LOW.value, 4)

    def test_timeout_minutes(self):
        self.assertEqual(ApprovalPriority.P1_CRITICAL.timeout_minutes, 5)
        self.assertEqual(ApprovalPriority.P2_HIGH.timeout_minutes, 15)
        self.assertEqual(ApprovalPriority.P3_MEDIUM.timeout_minutes, 60)
        self.assertEqual(ApprovalPriority.P4_LOW.timeout_minutes, 240)

    def test_label(self):
        self.assertEqual(ApprovalPriority.P1_CRITICAL.label, "CRITICAL")
        self.assertEqual(ApprovalPriority.P4_LOW.label, "LOW")


class TestActionType(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ActionType.BLOCK_IP.value, "block_ip")
        self.assertEqual(ActionType.ISOLATE_HOST.value, "isolate_host")
        self.assertEqual(ActionType.CUSTOM.value, "custom")

    def test_all_members(self):
        self.assertEqual(len(ActionType), 13)


class TestEscalationLevel(unittest.TestCase):
    def test_values(self):
        self.assertEqual(EscalationLevel.L1_ANALYST.value, 1)
        self.assertEqual(EscalationLevel.L5_DIRECTOR.value, 5)

    def test_all_members(self):
        self.assertEqual(len(EscalationLevel), 5)


class TestAuditAction(unittest.TestCase):
    def test_values(self):
        self.assertEqual(AuditAction.CREATED.value, "created")
        self.assertEqual(AuditAction.APPROVED.value, "approved")
        self.assertEqual(AuditAction.AUTO_APPROVED.value, "auto_approved")

    def test_all_members(self):
        self.assertEqual(len(AuditAction), 9)


# ============================================================================
# AutoApproveRule Tests
# ============================================================================

class TestAutoApproveRule(unittest.TestCase):
    def test_default_creation(self):
        rule = AutoApproveRule(name="Test Rule")
        self.assertTrue(rule.rule_id)
        self.assertEqual(rule.name, "Test Rule")
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.max_priority, 4)
        self.assertTrue(rule.created_at)

    def test_from_dict(self):
        data = {
            "rule_id": "r1",
            "name": "Allow Notifications",
            "action_type": "send_notification",
            "conditions": {"severity": "low"},
            "enabled": True,
            "max_priority": 4,
        }
        rule = AutoApproveRule.from_dict(data)
        self.assertEqual(rule.rule_id, "r1")
        self.assertEqual(rule.action_type, "send_notification")
        self.assertEqual(rule.conditions, {"severity": "low"})

    def test_to_dict(self):
        rule = AutoApproveRule(rule_id="r2", name="Test")
        d = rule.to_dict()
        self.assertEqual(d["rule_id"], "r2")
        self.assertEqual(d["name"], "Test")
        self.assertIn("created_at", d)

    def test_matches_action_type(self):
        rule = AutoApproveRule(action_type="block_ip", max_priority=4)
        req = ApprovalRequest(
            action_type="block_ip",
            priority=ApprovalPriority.P4_LOW,
        )
        self.assertTrue(rule.matches(req))

    def test_no_match_wrong_action(self):
        rule = AutoApproveRule(action_type="block_ip", max_priority=4)
        req = ApprovalRequest(
            action_type="isolate_host",
            priority=ApprovalPriority.P4_LOW,
        )
        self.assertFalse(rule.matches(req))

    def test_matches_wildcard(self):
        rule = AutoApproveRule(action_type="*", max_priority=4)
        req = ApprovalRequest(
            action_type="anything",
            priority=ApprovalPriority.P4_LOW,
        )
        self.assertTrue(rule.matches(req))

    def test_no_match_priority_too_high(self):
        rule = AutoApproveRule(action_type="*", max_priority=4)
        req = ApprovalRequest(
            action_type="block_ip",
            priority=ApprovalPriority.P1_CRITICAL,
        )
        self.assertFalse(rule.matches(req))

    def test_matches_disabled(self):
        rule = AutoApproveRule(action_type="*", max_priority=4, enabled=False)
        req = ApprovalRequest(
            action_type="test",
            priority=ApprovalPriority.P4_LOW,
        )
        self.assertFalse(rule.matches(req))

    def test_conditions_simple_match(self):
        rule = AutoApproveRule(
            action_type="*",
            max_priority=4,
            conditions={"env": "production"},
        )
        req = ApprovalRequest(
            action_type="test",
            priority=ApprovalPriority.P4_LOW,
            context={"env": "production"},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_simple_no_match(self):
        rule = AutoApproveRule(
            action_type="*",
            max_priority=4,
            conditions={"env": "production"},
        )
        req = ApprovalRequest(
            action_type="test",
            priority=ApprovalPriority.P4_LOW,
            context={"env": "staging"},
        )
        self.assertFalse(rule.matches(req))

    def test_conditions_list(self):
        rule = AutoApproveRule(
            action_type="*",
            max_priority=4,
            conditions={"env": ["staging", "dev"]},
        )
        req = ApprovalRequest(
            action_type="test",
            priority=ApprovalPriority.P4_LOW,
            context={"env": "staging"},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_list_no_match(self):
        rule = AutoApproveRule(
            action_type="*",
            max_priority=4,
            conditions={"env": ["staging", "dev"]},
        )
        req = ApprovalRequest(
            action_type="test",
            priority=ApprovalPriority.P4_LOW,
            context={"env": "production"},
        )
        self.assertFalse(rule.matches(req))

    def test_conditions_operator_eq(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"count": {"op": "eq", "value": 5}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"count": 5},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_operator_ne(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"status": {"op": "ne", "value": "blocked"}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"status": "active"},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_operator_gt(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"score": {"op": "gt", "value": 50}},
        )
        req_pass = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"score": 75},
        )
        req_fail = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"score": 30},
        )
        self.assertTrue(rule.matches(req_pass))
        self.assertFalse(rule.matches(req_fail))

    def test_conditions_operator_lt(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"risk": {"op": "lt", "value": 3}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"risk": 1},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_operator_in(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"tier": {"op": "in", "value": ["gold", "platinum"]}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"tier": "gold"},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_operator_contains(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"desc": {"op": "contains", "value": "safe"}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"desc": "This is safe to apply"},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_operator_regex(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"ip": {"op": "regex", "value": r"^10\.0\."}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={"ip": "10.0.1.5"},
        )
        self.assertTrue(rule.matches(req))

    def test_conditions_missing_key(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"env": "prod"},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={},
        )
        self.assertFalse(rule.matches(req))

    def test_conditions_operator_gt_none(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"score": {"op": "gt", "value": 50}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={},
        )
        self.assertFalse(rule.matches(req))

    def test_conditions_operator_lt_none(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"risk": {"op": "lt", "value": 3}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={},
        )
        self.assertFalse(rule.matches(req))

    def test_conditions_operator_contains_none(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"desc": {"op": "contains", "value": "safe"}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={},
        )
        self.assertFalse(rule.matches(req))

    def test_conditions_operator_regex_none(self):
        rule = AutoApproveRule(
            action_type="*", max_priority=4,
            conditions={"ip": {"op": "regex", "value": r"^10\."}},
        )
        req = ApprovalRequest(
            action_type="t", priority=ApprovalPriority.P4_LOW,
            context={},
        )
        self.assertFalse(rule.matches(req))


# ============================================================================
# AuditEntry Tests
# ============================================================================

class TestAuditEntry(unittest.TestCase):
    def test_default_creation(self):
        e = AuditEntry(request_id="r1", action="created", actor="user1")
        self.assertTrue(e.entry_id)
        self.assertEqual(e.request_id, "r1")
        self.assertEqual(e.action, "created")
        self.assertTrue(e.timestamp)

    def test_to_dict(self):
        e = AuditEntry(entry_id="e1", request_id="r1", action="approved", actor="admin")
        d = e.to_dict()
        self.assertEqual(d["entry_id"], "e1")
        self.assertEqual(d["action"], "approved")

    def test_from_dict(self):
        data = {
            "entry_id": "e2",
            "request_id": "r2",
            "action": "rejected",
            "actor": "mgr",
            "comment": "Denied",
        }
        e = AuditEntry.from_dict(data)
        self.assertEqual(e.entry_id, "e2")
        self.assertEqual(e.comment, "Denied")


# ============================================================================
# ApprovalRequest Tests
# ============================================================================

class TestApprovalRequest(unittest.TestCase):
    def test_default_creation(self):
        req = ApprovalRequest(action_type="block_ip", requester="analyst1")
        self.assertTrue(req.request_id.startswith("APR-"))
        self.assertEqual(req.action_type, "block_ip")
        self.assertEqual(req.status, ApprovalStatus.PENDING)
        self.assertEqual(req.priority, ApprovalPriority.P3_MEDIUM)
        self.assertTrue(req.created_at)
        self.assertTrue(req.expires_at)

    def test_is_pending(self):
        req = ApprovalRequest()
        self.assertTrue(req.is_pending)

    def test_is_decided_approved(self):
        req = ApprovalRequest(status=ApprovalStatus.APPROVED)
        self.assertTrue(req.is_decided)

    def test_is_decided_rejected(self):
        req = ApprovalRequest(status=ApprovalStatus.REJECTED)
        self.assertTrue(req.is_decided)

    def test_is_not_decided_pending(self):
        req = ApprovalRequest()
        self.assertFalse(req.is_decided)

    def test_is_expired_false(self):
        req = ApprovalRequest()
        self.assertFalse(req.is_expired)

    def test_is_expired_true(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        req = ApprovalRequest(expires_at=past)
        self.assertTrue(req.is_expired)

    def test_is_expired_not_pending(self):
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        req = ApprovalRequest(
            expires_at=past, status=ApprovalStatus.APPROVED,
        )
        self.assertFalse(req.is_expired)

    def test_time_remaining(self):
        future = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        req = ApprovalRequest(expires_at=future)
        remaining = req.time_remaining_seconds
        self.assertGreater(remaining, 1700)
        self.assertLess(remaining, 1810)

    def test_time_remaining_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        req = ApprovalRequest(expires_at=past)
        self.assertLess(req.time_remaining_seconds, 0)

    def test_time_remaining_invalid(self):
        req = ApprovalRequest(expires_at="invalid")
        self.assertEqual(req.time_remaining_seconds, 0.0)

    def test_is_expired_invalid_date(self):
        req = ApprovalRequest(expires_at="invalid")
        self.assertFalse(req.is_expired)

    def test_to_dict(self):
        req = ApprovalRequest(
            request_id="APR-TEST1",
            action_type="block_ip",
            requester="analyst",
            tags=["urgent"],
        )
        d = req.to_dict()
        self.assertEqual(d["request_id"], "APR-TEST1")
        self.assertEqual(d["action_type"], "block_ip")
        self.assertEqual(d["status"], "pending")
        self.assertIn("is_pending", d)
        self.assertIn("is_expired", d)
        self.assertIn("time_remaining_seconds", d)
        self.assertIn("priority_label", d)
        self.assertEqual(d["tags"], ["urgent"])

    def test_from_dict(self):
        data = {
            "request_id": "APR-X",
            "action_type": "isolate_host",
            "status": "approved",
            "priority": 2,
            "escalation_level": 3,
            "requester": "user1",
            "tags": '["tag1", "tag2"]',
            "auto_approved": True,
        }
        req = ApprovalRequest.from_dict(data)
        self.assertEqual(req.request_id, "APR-X")
        self.assertEqual(req.status, ApprovalStatus.APPROVED)
        self.assertEqual(req.priority, ApprovalPriority.P2_HIGH)
        self.assertEqual(req.escalation_level, EscalationLevel.L3_LEAD)
        self.assertEqual(req.tags, ["tag1", "tag2"])
        self.assertTrue(req.auto_approved)

    def test_from_dict_string_priority(self):
        data = {"priority": "1"}
        req = ApprovalRequest.from_dict(data)
        self.assertEqual(req.priority, ApprovalPriority.P1_CRITICAL)

    def test_from_dict_invalid_tags(self):
        data = {"tags": "not-json"}
        req = ApprovalRequest.from_dict(data)
        self.assertEqual(req.tags, [])


# ============================================================================
# ApprovalStore Tests
# ============================================================================

class TestApprovalStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_approval.db")
        self.store = ApprovalStore(db_path=self.db_path)

    def test_init_creates_db(self):
        self.assertTrue(os.path.exists(self.db_path))

    def test_save_and_get(self):
        req = ApprovalRequest(
            request_id="APR-001",
            action_type="block_ip",
            requester="analyst",
            action_params={"ip": "10.0.0.1"},
            context={"severity": "high"},
        )
        self.store.save_request(req)
        loaded = self.store.get_request("APR-001")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.request_id, "APR-001")
        self.assertEqual(loaded.action_params, {"ip": "10.0.0.1"})
        self.assertEqual(loaded.context, {"severity": "high"})

    def test_get_not_found(self):
        self.assertIsNone(self.store.get_request("nonexistent"))

    def test_list_requests(self):
        for i in range(5):
            req = ApprovalRequest(
                request_id=f"APR-{i:03d}",
                action_type="block_ip",
                requester="user",
            )
            self.store.save_request(req)
        results = self.store.list_requests()
        self.assertEqual(len(results), 5)

    def test_list_filter_status(self):
        req1 = ApprovalRequest(request_id="A1", action_type="t", requester="u")
        req2 = ApprovalRequest(
            request_id="A2", action_type="t", requester="u",
            status=ApprovalStatus.APPROVED,
        )
        self.store.save_request(req1)
        self.store.save_request(req2)
        pending = self.store.list_requests(status="pending")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].request_id, "A1")

    def test_list_filter_approver(self):
        req1 = ApprovalRequest(request_id="B1", action_type="t", approver="alice")
        req2 = ApprovalRequest(request_id="B2", action_type="t", approver="bob")
        self.store.save_request(req1)
        self.store.save_request(req2)
        results = self.store.list_requests(approver="alice")
        self.assertEqual(len(results), 1)

    def test_list_filter_priority(self):
        req1 = ApprovalRequest(
            request_id="C1", action_type="t",
            priority=ApprovalPriority.P1_CRITICAL,
        )
        req2 = ApprovalRequest(
            request_id="C2", action_type="t",
            priority=ApprovalPriority.P4_LOW,
        )
        self.store.save_request(req1)
        self.store.save_request(req2)
        results = self.store.list_requests(priority=1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].request_id, "C1")

    def test_list_filter_action_type(self):
        req1 = ApprovalRequest(request_id="D1", action_type="block_ip")
        req2 = ApprovalRequest(request_id="D2", action_type="isolate_host")
        self.store.save_request(req1)
        self.store.save_request(req2)
        results = self.store.list_requests(action_type="block_ip")
        self.assertEqual(len(results), 1)

    def test_list_limit_offset(self):
        for i in range(10):
            req = ApprovalRequest(request_id=f"E{i}", action_type="t")
            self.store.save_request(req)
        results = self.store.list_requests(limit=3, offset=0)
        self.assertEqual(len(results), 3)

    def test_count_requests(self):
        for i in range(3):
            self.store.save_request(ApprovalRequest(request_id=f"F{i}", action_type="t"))
        self.assertEqual(self.store.count_requests(), 3)
        self.assertEqual(self.store.count_requests(status="pending"), 3)

    def test_delete_request(self):
        self.store.save_request(ApprovalRequest(request_id="G1", action_type="t"))
        self.assertTrue(self.store.delete_request("G1"))
        self.assertIsNone(self.store.get_request("G1"))

    def test_delete_not_found(self):
        self.assertFalse(self.store.delete_request("nonexistent"))

    def test_get_pending_expired(self):
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        req1 = ApprovalRequest(request_id="H1", action_type="t", expires_at=past)
        req2 = ApprovalRequest(request_id="H2", action_type="t", expires_at=future)
        self.store.save_request(req1)
        self.store.save_request(req2)
        expired = self.store.get_pending_expired()
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].request_id, "H1")

    def test_update_request(self):
        req = ApprovalRequest(request_id="I1", action_type="t")
        self.store.save_request(req)
        req.status = ApprovalStatus.APPROVED
        self.store.save_request(req)
        loaded = self.store.get_request("I1")
        self.assertEqual(loaded.status, ApprovalStatus.APPROVED)

    # --- Audit ---

    def test_add_and_get_audit(self):
        self.store.save_request(ApprovalRequest(request_id="J1", action_type="t"))
        entry = AuditEntry(request_id="J1", action="created", actor="user1")
        self.store.add_audit_entry(entry)
        trail = self.store.get_audit_trail("J1")
        self.assertEqual(len(trail), 1)
        self.assertEqual(trail[0].action, "created")

    def test_recent_audit(self):
        self.store.save_request(ApprovalRequest(request_id="K1", action_type="t"))
        for i in range(3):
            self.store.add_audit_entry(
                AuditEntry(request_id="K1", action=f"act{i}", actor="u")
            )
        recent = self.store.get_recent_audit(limit=2)
        self.assertEqual(len(recent), 2)

    # --- Rules ---

    def test_save_and_list_rules(self):
        rule = AutoApproveRule(rule_id="r1", name="Test Rule", action_type="block_ip")
        self.store.save_rule(rule)
        rules = self.store.list_rules()
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0].rule_id, "r1")

    def test_list_rules_enabled_only(self):
        self.store.save_rule(AutoApproveRule(rule_id="r1", name="A", enabled=True))
        self.store.save_rule(AutoApproveRule(rule_id="r2", name="B", enabled=False))
        enabled = self.store.list_rules(enabled_only=True)
        self.assertEqual(len(enabled), 1)

    def test_get_rule(self):
        self.store.save_rule(AutoApproveRule(rule_id="r3", name="C"))
        rule = self.store.get_rule("r3")
        self.assertIsNotNone(rule)
        self.assertEqual(rule.name, "C")

    def test_get_rule_not_found(self):
        self.assertIsNone(self.store.get_rule("nonexistent"))

    def test_delete_rule(self):
        self.store.save_rule(AutoApproveRule(rule_id="r4", name="D"))
        self.assertTrue(self.store.delete_rule("r4"))
        self.assertIsNone(self.store.get_rule("r4"))

    def test_delete_rule_not_found(self):
        self.assertFalse(self.store.delete_rule("nonexistent"))

    # --- Stats ---

    def test_stats(self):
        self.store.save_request(ApprovalRequest(request_id="S1", action_type="t"))
        self.store.save_request(ApprovalRequest(
            request_id="S2", action_type="t",
            status=ApprovalStatus.APPROVED, auto_approved=True,
        ))
        self.store.save_rule(AutoApproveRule(rule_id="sr1", name="R1"))
        self.store.add_audit_entry(AuditEntry(request_id="S1", action="c", actor="u"))
        stats = self.store.get_stats()
        self.assertEqual(stats["total_requests"], 2)
        self.assertEqual(stats["count_pending"], 1)
        self.assertEqual(stats["count_approved"], 1)
        self.assertEqual(stats["auto_approved_total"], 1)
        self.assertEqual(stats["audit_entries"], 1)
        self.assertEqual(stats["active_rules"], 1)

    def test_list_filter_alert_id(self):
        req1 = ApprovalRequest(request_id="AL1", action_type="t", alert_id="ALERT-100")
        req2 = ApprovalRequest(request_id="AL2", action_type="t", alert_id="ALERT-200")
        self.store.save_request(req1)
        self.store.save_request(req2)
        results = self.store.list_requests(alert_id="ALERT-100")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].request_id, "AL1")


# ============================================================================
# ApprovalWorkflowEngine Tests
# ============================================================================

class TestApprovalWorkflowEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_engine.db")
        self.engine = ApprovalWorkflowEngine(db_path=self.db_path)

    def test_submit_creates_request(self):
        req = self.engine.submit(
            action_type="block_ip",
            requester="analyst1",
            title="Block malicious IP",
        )
        self.assertTrue(req.request_id.startswith("APR-"))
        self.assertEqual(req.status, ApprovalStatus.PENDING)
        self.assertEqual(self.engine._stats["submitted"], 1)

    def test_submit_with_all_params(self):
        req = self.engine.submit(
            action_type="isolate_host",
            requester="analyst2",
            title="Isolate compromised host",
            description="Critical malware detected",
            action_params={"hostname": "srv01"},
            context={"severity": "critical"},
            approver="manager1",
            priority=ApprovalPriority.P1_CRITICAL,
            alert_id="ALERT-001",
            case_id="CASE-001",
            tags=["malware", "urgent"],
        )
        self.assertEqual(req.action_type, "isolate_host")
        self.assertEqual(req.approver, "manager1")
        self.assertEqual(req.priority, ApprovalPriority.P1_CRITICAL)
        self.assertEqual(req.tags, ["malware", "urgent"])
        self.assertEqual(req.alert_id, "ALERT-001")

    def test_submit_auto_approve(self):
        rule = AutoApproveRule(
            name="Auto notify",
            action_type="send_notification",
            max_priority=4,
        )
        self.engine.add_rule(rule)
        req = self.engine.submit(
            action_type="send_notification",
            requester="system",
            priority=ApprovalPriority.P4_LOW,
        )
        self.assertEqual(req.status, ApprovalStatus.APPROVED)
        self.assertTrue(req.auto_approved)
        self.assertEqual(req.auto_approve_rule, rule.rule_id)
        self.assertEqual(self.engine._stats["auto_approved"], 1)

    def test_submit_auto_approve_no_match(self):
        rule = AutoApproveRule(
            name="Only low notify",
            action_type="send_notification",
            max_priority=4,
        )
        self.engine.add_rule(rule)
        req = self.engine.submit(
            action_type="block_ip",
            requester="user",
            priority=ApprovalPriority.P4_LOW,
        )
        self.assertEqual(req.status, ApprovalStatus.PENDING)
        self.assertFalse(req.auto_approved)

    def test_approve(self):
        req = self.engine.submit("block_ip", "analyst")
        result = self.engine.approve(req.request_id, "manager", comment="Looks good")
        self.assertEqual(result.status, ApprovalStatus.APPROVED)
        self.assertEqual(result.decision_comment, "Looks good")
        self.assertTrue(result.decided_at)
        self.assertEqual(self.engine._stats["approved"], 1)

    def test_approve_sets_approver(self):
        req = self.engine.submit("block_ip", "analyst")
        result = self.engine.approve(req.request_id, "manager")
        self.assertEqual(result.approver, "manager")

    def test_approve_preserves_existing_approver(self):
        req = self.engine.submit("block_ip", "analyst", approver="lead")
        result = self.engine.approve(req.request_id, "lead")
        self.assertEqual(result.approver, "lead")

    def test_reject(self):
        req = self.engine.submit("block_ip", "analyst")
        result = self.engine.reject(req.request_id, "manager", comment="Not justified")
        self.assertEqual(result.status, ApprovalStatus.REJECTED)
        self.assertEqual(result.decision_comment, "Not justified")
        self.assertEqual(self.engine._stats["rejected"], 1)

    def test_cancel(self):
        req = self.engine.submit("block_ip", "analyst")
        result = self.engine.cancel(req.request_id, "analyst", comment="No longer needed")
        self.assertEqual(result.status, ApprovalStatus.CANCELLED)
        self.assertEqual(self.engine._stats["cancelled"], 1)

    def test_approve_not_found(self):
        with self.assertRaises(KeyError):
            self.engine.approve("nonexistent", "user")

    def test_approve_already_decided(self):
        req = self.engine.submit("block_ip", "analyst")
        self.engine.approve(req.request_id, "manager")
        with self.assertRaises(ValueError):
            self.engine.approve(req.request_id, "manager")

    def test_reject_already_decided(self):
        req = self.engine.submit("block_ip", "analyst")
        self.engine.reject(req.request_id, "manager")
        with self.assertRaises(ValueError):
            self.engine.reject(req.request_id, "manager")

    def test_cancel_not_pending(self):
        req = self.engine.submit("block_ip", "analyst")
        self.engine.approve(req.request_id, "manager")
        with self.assertRaises(ValueError):
            self.engine.cancel(req.request_id, "analyst")

    # --- Delegate ---

    def test_delegate(self):
        req = self.engine.submit("block_ip", "analyst", approver="manager1")
        result = self.engine.delegate(
            req.request_id, "manager1", "manager2", comment="Out of office",
        )
        self.assertEqual(result.approver, "manager2")
        self.assertEqual(result.delegated_from, "manager1")
        self.assertEqual(self.engine._stats["delegated"], 1)

    def test_delegate_not_found(self):
        with self.assertRaises(KeyError):
            self.engine.delegate("nope", "a", "b")

    # --- Escalation ---

    def test_escalate(self):
        chain = {2: "senior_analyst", 3: "team_lead"}
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "esc.db"),
            escalation_chain=chain,
        )
        req = engine.submit("block_ip", "analyst", approver="analyst1")
        result = engine.escalate(req.request_id)
        self.assertEqual(result.escalation_level, EscalationLevel.L2_SENIOR)
        self.assertEqual(result.approver, "senior_analyst")
        self.assertEqual(result.status, ApprovalStatus.PENDING)
        self.assertEqual(engine._stats["escalated"], 1)

    def test_escalate_max_level_expires(self):
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "esc2.db"),
        )
        req = engine.submit("block_ip", "analyst")
        # Manually set to L5
        req.escalation_level = EscalationLevel.L5_DIRECTOR
        engine.store.save_request(req)
        result = engine.escalate(req.request_id)
        self.assertEqual(result.status, ApprovalStatus.EXPIRED)

    def test_escalate_not_found(self):
        with self.assertRaises(KeyError):
            self.engine.escalate("nope")

    def test_expire(self):
        req = self.engine.submit("block_ip", "analyst")
        result = self.engine.expire(req.request_id)
        self.assertEqual(result.status, ApprovalStatus.EXPIRED)
        self.assertEqual(self.engine._stats["expired"], 1)

    # --- Process Expired ---

    def test_process_expired_escalates(self):
        chain = {2: "senior"}
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "pe.db"),
            escalation_chain=chain,
        )
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        req = ApprovalRequest(
            request_id="PE1", action_type="block_ip",
            requester="u", expires_at=past,
        )
        engine.store.save_request(req)
        processed = engine.process_expired(escalate=True)
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0].escalation_level, EscalationLevel.L2_SENIOR)

    def test_process_expired_no_escalate(self):
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "pe2.db"),
        )
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        req = ApprovalRequest(
            request_id="PE2", action_type="block_ip",
            requester="u", expires_at=past,
        )
        engine.store.save_request(req)
        processed = engine.process_expired(escalate=False)
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0].status, ApprovalStatus.EXPIRED)

    def test_process_expired_at_max_level(self):
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "pe3.db"),
        )
        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        req = ApprovalRequest(
            request_id="PE3", action_type="block_ip",
            requester="u", expires_at=past,
            escalation_level=EscalationLevel.L5_DIRECTOR,
        )
        engine.store.save_request(req)
        processed = engine.process_expired(escalate=True)
        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0].status, ApprovalStatus.EXPIRED)

    # --- Bulk ---

    def test_bulk_approve(self):
        ids = []
        for i in range(3):
            req = self.engine.submit(f"action_{i}", "user")
            ids.append(req.request_id)
        result = self.engine.bulk_approve(ids, "manager")
        self.assertEqual(len(result["approved"]), 3)
        self.assertEqual(len(result["errors"]), 0)

    def test_bulk_approve_with_errors(self):
        req = self.engine.submit("block_ip", "user")
        self.engine.approve(req.request_id, "mgr")
        result = self.engine.bulk_approve(
            [req.request_id, "nonexistent"], "mgr",
        )
        self.assertEqual(len(result["errors"]), 2)

    def test_bulk_reject(self):
        ids = []
        for i in range(2):
            req = self.engine.submit(f"action_{i}", "user")
            ids.append(req.request_id)
        result = self.engine.bulk_reject(ids, "manager", comment="Denied all")
        self.assertEqual(len(result["rejected"]), 2)

    # --- Comments ---

    def test_add_comment(self):
        req = self.engine.submit("block_ip", "analyst")
        entry = self.engine.add_comment(req.request_id, "reviewer", "Need more info")
        self.assertEqual(entry.action, "comment_added")
        self.assertEqual(entry.comment, "Need more info")

    def test_add_comment_not_found(self):
        with self.assertRaises(KeyError):
            self.engine.add_comment("nope", "user", "test")

    # --- Query ---

    def test_get_request(self):
        req = self.engine.submit("block_ip", "analyst")
        loaded = self.engine.get_request(req.request_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.request_id, req.request_id)

    def test_list_pending(self):
        self.engine.submit("a", "u")
        self.engine.submit("b", "u")
        req3 = self.engine.submit("c", "u")
        self.engine.approve(req3.request_id, "mgr")
        pending = self.engine.list_pending()
        self.assertEqual(len(pending), 2)

    def test_list_pending_by_approver(self):
        self.engine.submit("a", "u", approver="alice")
        self.engine.submit("b", "u", approver="bob")
        results = self.engine.list_pending(approver="alice")
        self.assertEqual(len(results), 1)

    def test_list_requests_by_status(self):
        req1 = self.engine.submit("a", "u")
        req2 = self.engine.submit("b", "u")
        self.engine.approve(req1.request_id, "mgr")
        approved = self.engine.list_requests(status="approved")
        self.assertEqual(len(approved), 1)

    def test_get_audit_trail(self):
        req = self.engine.submit("block_ip", "analyst")
        self.engine.approve(req.request_id, "manager")
        trail = self.engine.get_audit_trail(req.request_id)
        self.assertGreaterEqual(len(trail), 2)  # created + approved
        actions = [e.action for e in trail]
        self.assertIn("created", actions)
        self.assertIn("approved", actions)

    def test_get_recent_activity(self):
        self.engine.submit("a", "u")
        self.engine.submit("b", "u")
        activity = self.engine.get_recent_activity(limit=10)
        self.assertGreaterEqual(len(activity), 2)

    # --- Rules ---

    def test_add_and_list_rules(self):
        rule = AutoApproveRule(name="Test", action_type="notify")
        self.engine.add_rule(rule)
        rules = self.engine.list_rules()
        self.assertEqual(len(rules), 1)

    def test_remove_rule(self):
        rule = AutoApproveRule(rule_id="rx", name="X")
        self.engine.add_rule(rule)
        self.assertTrue(self.engine.remove_rule("rx"))
        self.assertEqual(len(self.engine.list_rules()), 0)

    def test_get_rule(self):
        rule = AutoApproveRule(rule_id="ry", name="Y")
        self.engine.add_rule(rule)
        loaded = self.engine.get_rule("ry")
        self.assertEqual(loaded.name, "Y")

    # --- Stats ---

    def test_get_stats(self):
        self.engine.submit("a", "u")
        stats = self.engine.get_stats()
        self.assertIn("session", stats)
        self.assertIn("database", stats)
        self.assertEqual(stats["session"]["submitted"], 1)

    def test_reset_stats(self):
        self.engine.submit("a", "u")
        self.engine.reset_stats()
        self.assertEqual(self.engine._stats["submitted"], 0)

    # --- Callbacks ---

    def test_callback_on_approved(self):
        callback = MagicMock()
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "cb1.db"),
            on_approved=callback,
        )
        req = engine.submit("block_ip", "analyst")
        engine.approve(req.request_id, "manager")
        callback.assert_called_once()
        self.assertEqual(callback.call_args[0][0].request_id, req.request_id)

    def test_callback_on_rejected(self):
        callback = MagicMock()
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "cb2.db"),
            on_rejected=callback,
        )
        req = engine.submit("block_ip", "analyst")
        engine.reject(req.request_id, "manager")
        callback.assert_called_once()

    def test_callback_on_escalated(self):
        callback = MagicMock()
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "cb3.db"),
            on_escalated=callback,
            escalation_chain={2: "senior"},
        )
        req = engine.submit("block_ip", "analyst")
        engine.escalate(req.request_id)
        callback.assert_called_once()

    def test_callback_on_expired(self):
        callback = MagicMock()
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "cb4.db"),
            on_expired=callback,
        )
        req = engine.submit("block_ip", "analyst")
        engine.expire(req.request_id)
        callback.assert_called_once()

    def test_callback_auto_approve(self):
        callback = MagicMock()
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "cb5.db"),
            on_approved=callback,
        )
        engine.add_rule(AutoApproveRule(
            name="Auto", action_type="notify", max_priority=4,
        ))
        engine.submit("notify", "system", priority=ApprovalPriority.P4_LOW)
        callback.assert_called_once()

    def test_callback_exception_handled(self):
        def bad_callback(req):
            raise RuntimeError("boom")
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "cb6.db"),
            on_approved=bad_callback,
        )
        req = engine.submit("block_ip", "analyst")
        # Should not raise
        engine.approve(req.request_id, "manager")

    # --- Default title ---

    def test_submit_default_title(self):
        req = self.engine.submit("block_ip", "analyst")
        self.assertIn("block_ip", req.title)


# ============================================================================
# Blueprint Tests
# ============================================================================

class TestApprovalBlueprint(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "bp.db"),
        )
        try:
            from flask import Flask
            self.app = Flask(__name__)
            bp = create_approval_blueprint(self.engine)
            self.app.register_blueprint(bp)
            self.client = self.app.test_client()
            self.flask_available = True
        except ImportError:
            self.flask_available = False

    def _skip_no_flask(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")

    def test_submit_endpoint(self):
        self._skip_no_flask()
        resp = self.client.post("/api/v1/soc/approval/submit", json={
            "action_type": "block_ip",
            "requester": "analyst",
            "title": "Block bad IP",
            "priority": 2,
        })
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertIn("request", data)
        self.assertTrue(data["request"]["request_id"].startswith("APR-"))

    def test_submit_missing_fields(self):
        self._skip_no_flask()
        resp = self.client.post("/api/v1/soc/approval/submit", json={})
        self.assertEqual(resp.status_code, 400)

    def test_pending_endpoint(self):
        self._skip_no_flask()
        self.engine.submit("block_ip", "analyst")
        resp = self.client.get("/api/v1/soc/approval/pending")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertGreaterEqual(data["count"], 1)

    def test_list_endpoint(self):
        self._skip_no_flask()
        self.engine.submit("block_ip", "analyst")
        resp = self.client.get("/api/v1/soc/approval/list")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(resp.get_json()["count"], 1)

    def test_get_request_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.get(f"/api/v1/soc/approval/request/{req.request_id}")
        self.assertEqual(resp.status_code, 200)

    def test_get_request_not_found(self):
        self._skip_no_flask()
        resp = self.client.get("/api/v1/soc/approval/request/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_delete_request_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.delete(f"/api/v1/soc/approval/request/{req.request_id}")
        self.assertEqual(resp.status_code, 200)

    def test_delete_request_not_found(self):
        self._skip_no_flask()
        resp = self.client.delete("/api/v1/soc/approval/request/nope")
        self.assertEqual(resp.status_code, 404)

    def test_approve_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/approve/{req.request_id}",
            json={"approver": "manager", "comment": "OK"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["request"]["status"], "approved")

    def test_approve_missing_approver(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/approve/{req.request_id}", json={},
        )
        self.assertEqual(resp.status_code, 400)

    def test_approve_not_found(self):
        self._skip_no_flask()
        resp = self.client.post(
            "/api/v1/soc/approval/approve/nope",
            json={"approver": "mgr"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_approve_conflict(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        self.engine.approve(req.request_id, "mgr")
        resp = self.client.post(
            f"/api/v1/soc/approval/approve/{req.request_id}",
            json={"approver": "mgr"},
        )
        self.assertEqual(resp.status_code, 409)

    def test_reject_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/reject/{req.request_id}",
            json={"approver": "manager"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["request"]["status"], "rejected")

    def test_reject_missing_approver(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/reject/{req.request_id}", json={},
        )
        self.assertEqual(resp.status_code, 400)

    def test_cancel_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/cancel/{req.request_id}",
            json={"actor": "analyst"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["request"]["status"], "cancelled")

    def test_cancel_missing_actor(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/cancel/{req.request_id}", json={},
        )
        self.assertEqual(resp.status_code, 400)

    def test_delegate_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst", approver="mgr1")
        resp = self.client.post(
            f"/api/v1/soc/approval/delegate/{req.request_id}",
            json={"from_approver": "mgr1", "to_approver": "mgr2"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["request"]["approver"], "mgr2")

    def test_delegate_missing_fields(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/delegate/{req.request_id}",
            json={"from_approver": "mgr1"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_escalate_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/escalate/{req.request_id}",
            json={"actor": "system"},
        )
        self.assertEqual(resp.status_code, 200)

    def test_escalate_not_found(self):
        self._skip_no_flask()
        resp = self.client.post(
            "/api/v1/soc/approval/escalate/nope",
            json={"actor": "system"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_bulk_approve_endpoint(self):
        self._skip_no_flask()
        r1 = self.engine.submit("a", "u")
        r2 = self.engine.submit("b", "u")
        resp = self.client.post("/api/v1/soc/approval/bulk/approve", json={
            "request_ids": [r1.request_id, r2.request_id],
            "approver": "manager",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()["approved"]), 2)

    def test_bulk_approve_missing_fields(self):
        self._skip_no_flask()
        resp = self.client.post("/api/v1/soc/approval/bulk/approve", json={})
        self.assertEqual(resp.status_code, 400)

    def test_bulk_reject_endpoint(self):
        self._skip_no_flask()
        r1 = self.engine.submit("a", "u")
        resp = self.client.post("/api/v1/soc/approval/bulk/reject", json={
            "request_ids": [r1.request_id],
            "approver": "manager",
        })
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.get_json()["rejected"]), 1)

    def test_bulk_reject_missing_fields(self):
        self._skip_no_flask()
        resp = self.client.post("/api/v1/soc/approval/bulk/reject", json={})
        self.assertEqual(resp.status_code, 400)

    def test_comment_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/comment/{req.request_id}",
            json={"actor": "reviewer", "comment": "Need details"},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["entry"]["action"], "comment_added")

    def test_comment_missing_fields(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.post(
            f"/api/v1/soc/approval/comment/{req.request_id}",
            json={"actor": "u"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_comment_not_found(self):
        self._skip_no_flask()
        resp = self.client.post(
            "/api/v1/soc/approval/comment/nope",
            json={"actor": "u", "comment": "x"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_audit_endpoint(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        resp = self.client.get(f"/api/v1/soc/approval/audit/{req.request_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(resp.get_json()["count"], 1)

    def test_activity_endpoint(self):
        self._skip_no_flask()
        self.engine.submit("block_ip", "analyst")
        resp = self.client.get("/api/v1/soc/approval/activity")
        self.assertEqual(resp.status_code, 200)

    def test_rules_list_endpoint(self):
        self._skip_no_flask()
        self.engine.add_rule(AutoApproveRule(name="R1", action_type="t"))
        resp = self.client.get("/api/v1/soc/approval/rules")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["count"], 1)

    def test_rules_add_endpoint(self):
        self._skip_no_flask()
        resp = self.client.post("/api/v1/soc/approval/rules", json={
            "name": "New Rule",
            "action_type": "notify",
            "max_priority": 4,
        })
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.get_json()["rule"]["name"], "New Rule")

    def test_rules_add_missing_name(self):
        self._skip_no_flask()
        resp = self.client.post("/api/v1/soc/approval/rules", json={})
        self.assertEqual(resp.status_code, 400)

    def test_rules_get_endpoint(self):
        self._skip_no_flask()
        rule = AutoApproveRule(rule_id="rg1", name="G")
        self.engine.add_rule(rule)
        resp = self.client.get("/api/v1/soc/approval/rules/rg1")
        self.assertEqual(resp.status_code, 200)

    def test_rules_get_not_found(self):
        self._skip_no_flask()
        resp = self.client.get("/api/v1/soc/approval/rules/nope")
        self.assertEqual(resp.status_code, 404)

    def test_rules_delete_endpoint(self):
        self._skip_no_flask()
        rule = AutoApproveRule(rule_id="rd1", name="D")
        self.engine.add_rule(rule)
        resp = self.client.delete("/api/v1/soc/approval/rules/rd1")
        self.assertEqual(resp.status_code, 200)

    def test_rules_delete_not_found(self):
        self._skip_no_flask()
        resp = self.client.delete("/api/v1/soc/approval/rules/nope")
        self.assertEqual(resp.status_code, 404)

    def test_process_expired_endpoint(self):
        self._skip_no_flask()
        resp = self.client.post("/api/v1/soc/approval/process-expired", json={})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("processed", resp.get_json())

    def test_stats_endpoint(self):
        self._skip_no_flask()
        resp = self.client.get("/api/v1/soc/approval/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("session", data)
        self.assertIn("database", data)

    def test_reject_not_found(self):
        self._skip_no_flask()
        resp = self.client.post(
            "/api/v1/soc/approval/reject/nope",
            json={"approver": "mgr"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_reject_conflict(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        self.engine.reject(req.request_id, "mgr")
        resp = self.client.post(
            f"/api/v1/soc/approval/reject/{req.request_id}",
            json={"approver": "mgr"},
        )
        self.assertEqual(resp.status_code, 409)

    def test_cancel_not_found(self):
        self._skip_no_flask()
        resp = self.client.post(
            "/api/v1/soc/approval/cancel/nope",
            json={"actor": "u"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_cancel_conflict(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        self.engine.approve(req.request_id, "mgr")
        resp = self.client.post(
            f"/api/v1/soc/approval/cancel/{req.request_id}",
            json={"actor": "analyst"},
        )
        self.assertEqual(resp.status_code, 409)

    def test_delegate_not_found(self):
        self._skip_no_flask()
        resp = self.client.post(
            "/api/v1/soc/approval/delegate/nope",
            json={"from_approver": "a", "to_approver": "b"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_escalate_conflict(self):
        self._skip_no_flask()
        req = self.engine.submit("block_ip", "analyst")
        self.engine.approve(req.request_id, "mgr")
        resp = self.client.post(
            f"/api/v1/soc/approval/escalate/{req.request_id}",
            json={"actor": "system"},
        )
        self.assertEqual(resp.status_code, 409)


# ============================================================================
# Global Singleton Tests
# ============================================================================

class TestGlobalSingleton(unittest.TestCase):
    def setUp(self):
        reset_global_engine()

    def tearDown(self):
        reset_global_engine()

    def test_get_returns_instance(self):
        engine = get_approval_engine()
        self.assertIsInstance(engine, ApprovalWorkflowEngine)

    def test_same_instance(self):
        e1 = get_approval_engine()
        e2 = get_approval_engine()
        self.assertIs(e1, e2)

    def test_reset(self):
        e1 = get_approval_engine()
        reset_global_engine()
        e2 = get_approval_engine()
        self.assertIsNot(e1, e2)


# ============================================================================
# Blueprint No Flask Test
# ============================================================================

class TestBlueprintNoFlask(unittest.TestCase):
    @patch.dict("sys.modules", {"flask": None})
    def test_no_flask_returns_none(self):
        # Re-import to trigger ImportError
        import importlib
        import modules.soc_core.approval_workflow as mod
        result = mod.create_approval_blueprint()
        self.assertIsNone(result)


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_approval_request_empty_dict(self):
        req = ApprovalRequest.from_dict({})
        self.assertEqual(req.status, ApprovalStatus.PENDING)

    def test_audit_entry_empty_dict(self):
        e = AuditEntry.from_dict({})
        self.assertTrue(e.entry_id)

    def test_auto_approve_rule_empty_dict(self):
        r = AutoApproveRule.from_dict({})
        self.assertTrue(r.rule_id)

    def test_store_default_path(self):
        with patch.dict(os.environ, {"TSUNAMI_DATA_DIR": self.tmpdir}):
            store = ApprovalStore()
            self.assertIn(self.tmpdir, store.db_path)

    def test_store_invalid_json_action_params(self):
        """Store handles corrupt JSON gracefully."""
        store = ApprovalStore(db_path=os.path.join(self.tmpdir, "corrupt.db"))
        req = ApprovalRequest(request_id="C1", action_type="t")
        store.save_request(req)
        # Corrupt the stored JSON
        conn = store._get_conn()
        conn.execute(
            "UPDATE approval_requests SET action_params = 'not-json' WHERE request_id = 'C1'"
        )
        conn.commit()
        conn.close()
        loaded = store.get_request("C1")
        self.assertEqual(loaded.action_params, {})

    def test_store_invalid_json_context(self):
        store = ApprovalStore(db_path=os.path.join(self.tmpdir, "corrupt2.db"))
        req = ApprovalRequest(request_id="C2", action_type="t")
        store.save_request(req)
        conn = store._get_conn()
        conn.execute(
            "UPDATE approval_requests SET context = 'bad' WHERE request_id = 'C2'"
        )
        conn.commit()
        conn.close()
        loaded = store.get_request("C2")
        self.assertEqual(loaded.context, {})

    def test_store_invalid_json_tags(self):
        store = ApprovalStore(db_path=os.path.join(self.tmpdir, "corrupt3.db"))
        req = ApprovalRequest(request_id="C3", action_type="t")
        store.save_request(req)
        conn = store._get_conn()
        conn.execute(
            "UPDATE approval_requests SET tags = 'bad' WHERE request_id = 'C3'"
        )
        conn.commit()
        conn.close()
        loaded = store.get_request("C3")
        self.assertEqual(loaded.tags, [])

    def test_store_invalid_json_audit_details(self):
        store = ApprovalStore(db_path=os.path.join(self.tmpdir, "corrupt4.db"))
        store.save_request(ApprovalRequest(request_id="C4", action_type="t"))
        entry = AuditEntry(entry_id="e1", request_id="C4", action="x", actor="u")
        store.add_audit_entry(entry)
        conn = store._get_conn()
        conn.execute("UPDATE audit_trail SET details = 'bad' WHERE entry_id = 'e1'")
        conn.commit()
        conn.close()
        trail = store.get_audit_trail("C4")
        self.assertEqual(trail[0].details, {})

    def test_store_invalid_json_rule_conditions(self):
        store = ApprovalStore(db_path=os.path.join(self.tmpdir, "corrupt5.db"))
        rule = AutoApproveRule(rule_id="cr1", name="R")
        store.save_rule(rule)
        conn = store._get_conn()
        conn.execute("UPDATE auto_approve_rules SET conditions = 'bad' WHERE rule_id = 'cr1'")
        conn.commit()
        conn.close()
        loaded = store.get_rule("cr1")
        self.assertEqual(loaded.conditions, {})

    def test_thread_safety(self):
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "thread.db"),
        )
        errors = []

        def submit_many():
            try:
                for _ in range(10):
                    engine.submit("block_ip", "user")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=submit_many) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 0)
        pending = engine.list_pending(limit=100)
        self.assertEqual(len(pending), 40)

    def test_request_from_dict_none_tags(self):
        req = ApprovalRequest.from_dict({"tags": None})
        self.assertEqual(req.tags, [])

    def test_request_from_dict_none_action_params(self):
        req = ApprovalRequest.from_dict({"action_params": None})
        self.assertEqual(req.action_params, {})

    def test_request_from_dict_none_context(self):
        req = ApprovalRequest.from_dict({"context": None})
        self.assertEqual(req.context, {})

    def test_auto_approve_rule_from_dict_none_conditions(self):
        rule = AutoApproveRule.from_dict({"conditions": None})
        self.assertEqual(rule.conditions, {})

    def test_audit_entry_from_dict_none_details(self):
        e = AuditEntry.from_dict({"details": None})
        self.assertEqual(e.details, {})


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

    def test_full_workflow(self):
        """Test complete lifecycle: submit → comment → approve → audit."""
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "int1.db"),
        )
        # Submit
        req = engine.submit(
            action_type="block_ip",
            requester="analyst",
            title="Block 10.0.0.1",
            action_params={"ip": "10.0.0.1"},
            approver="manager",
            priority=ApprovalPriority.P2_HIGH,
        )
        self.assertEqual(req.status, ApprovalStatus.PENDING)

        # Comment
        engine.add_comment(req.request_id, "analyst", "Confirmed malicious")

        # Approve
        result = engine.approve(req.request_id, "manager", comment="Proceed")
        self.assertEqual(result.status, ApprovalStatus.APPROVED)

        # Audit trail
        trail = engine.get_audit_trail(req.request_id)
        actions = [e.action for e in trail]
        self.assertIn("created", actions)
        self.assertIn("comment_added", actions)
        self.assertIn("approved", actions)

    def test_escalation_chain(self):
        """Test multi-level escalation flow."""
        chain = {
            2: "senior_analyst",
            3: "team_lead",
            4: "soc_manager",
            5: "ciso",
        }
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "int2.db"),
            escalation_chain=chain,
        )
        req = engine.submit("isolate_host", "analyst", approver="analyst1")

        # Escalate through levels
        for level in range(2, 6):
            req = engine.escalate(req.request_id)
            expected_level = EscalationLevel(min(level, 5))
            self.assertEqual(req.escalation_level, expected_level)
            if level <= 5 and level in chain:
                self.assertEqual(req.approver, chain[level])

        # At max level, escalation should expire
        result = engine.escalate(req.request_id)
        self.assertEqual(result.status, ApprovalStatus.EXPIRED)

    def test_auto_approve_with_conditions(self):
        """Test auto-approve rule with complex conditions."""
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "int3.db"),
        )
        rule = AutoApproveRule(
            name="Auto-approve low-risk notifications",
            action_type="send_notification",
            conditions={
                "risk_level": {"op": "lt", "value": 3},
                "environment": ["staging", "dev"],
            },
            max_priority=4,
        )
        engine.add_rule(rule)

        # Should auto-approve (matches all conditions)
        req1 = engine.submit(
            "send_notification", "system",
            priority=ApprovalPriority.P4_LOW,
            context={"risk_level": 1, "environment": "staging"},
        )
        self.assertTrue(req1.auto_approved)

        # Should NOT auto-approve (risk too high)
        req2 = engine.submit(
            "send_notification", "system",
            priority=ApprovalPriority.P4_LOW,
            context={"risk_level": 5, "environment": "staging"},
        )
        self.assertFalse(req2.auto_approved)
        self.assertEqual(req2.status, ApprovalStatus.PENDING)

        # Should NOT auto-approve (wrong environment)
        req3 = engine.submit(
            "send_notification", "system",
            priority=ApprovalPriority.P4_LOW,
            context={"risk_level": 1, "environment": "production"},
        )
        self.assertFalse(req3.auto_approved)

    def test_delegate_then_approve(self):
        """Test delegation followed by approval."""
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "int4.db"),
        )
        req = engine.submit("block_ip", "analyst", approver="mgr1")
        engine.delegate(req.request_id, "mgr1", "mgr2", comment="Delegating")
        result = engine.approve(req.request_id, "mgr2", comment="Approved after delegation")
        self.assertEqual(result.status, ApprovalStatus.APPROVED)
        self.assertEqual(result.approver, "mgr2")
        self.assertEqual(result.delegated_from, "mgr1")

    def test_stats_tracking(self):
        """Verify stats accumulate correctly."""
        engine = ApprovalWorkflowEngine(
            db_path=os.path.join(self.tmpdir, "int5.db"),
        )
        engine.add_rule(AutoApproveRule(
            name="Auto", action_type="notify", max_priority=4,
        ))

        engine.submit("block_ip", "u")
        r2 = engine.submit("block_ip", "u")
        engine.approve(r2.request_id, "mgr")
        r3 = engine.submit("block_ip", "u")
        engine.reject(r3.request_id, "mgr")
        r4 = engine.submit("block_ip", "u")
        engine.cancel(r4.request_id, "u")
        engine.submit("notify", "u", priority=ApprovalPriority.P4_LOW)  # auto

        stats = engine.get_stats()
        self.assertEqual(stats["session"]["submitted"], 5)
        self.assertEqual(stats["session"]["approved"], 1)
        self.assertEqual(stats["session"]["rejected"], 1)
        self.assertEqual(stats["session"]["cancelled"], 1)
        self.assertEqual(stats["session"]["auto_approved"], 1)


if __name__ == "__main__":
    unittest.main()
