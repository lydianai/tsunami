#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - TheHive Connector Tests
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
import uuid
from unittest.mock import MagicMock, patch, PropertyMock
from datetime import datetime, timezone

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.case_management.thehive_connector import (
    TLP, PAP, CaseSeverity, CaseStatus, TaskStatus, AlertStatus,
    ObservableDataType, SyncDirection, SyncStatus,
    TheHiveCase, TheHiveTask, TheHiveObservable, TheHiveAlert, SyncRecord,
    TheHiveClient, SyncStore, TheHiveConnector,
    create_thehive_blueprint, get_thehive_connector, reset_global_connector,
)


# ============================================================================
# Enum Tests
# ============================================================================

class TestTLP(unittest.TestCase):
    def test_all_levels(self):
        self.assertEqual(TLP.CLEAR, 0)
        self.assertEqual(TLP.GREEN, 1)
        self.assertEqual(TLP.AMBER, 2)
        self.assertEqual(TLP.AMBER_STRICT, 3)
        self.assertEqual(TLP.RED, 4)

    def test_count(self):
        self.assertEqual(len(TLP), 5)


class TestPAP(unittest.TestCase):
    def test_all_levels(self):
        self.assertEqual(PAP.CLEAR, 0)
        self.assertEqual(PAP.GREEN, 1)
        self.assertEqual(PAP.AMBER, 2)
        self.assertEqual(PAP.RED, 3)

    def test_count(self):
        self.assertEqual(len(PAP), 4)


class TestCaseSeverity(unittest.TestCase):
    def test_values(self):
        self.assertEqual(CaseSeverity.LOW, 1)
        self.assertEqual(CaseSeverity.MEDIUM, 2)
        self.assertEqual(CaseSeverity.HIGH, 3)
        self.assertEqual(CaseSeverity.CRITICAL, 4)


class TestCaseStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(CaseStatus.NEW.value, "New")
        self.assertEqual(CaseStatus.IN_PROGRESS.value, "InProgress")
        self.assertEqual(CaseStatus.RESOLVED.value, "Resolved")
        self.assertEqual(CaseStatus.CLOSED.value, "Closed")
        self.assertEqual(CaseStatus.DELETED.value, "Deleted")


class TestTaskStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(TaskStatus.WAITING.value, "Waiting")
        self.assertEqual(TaskStatus.IN_PROGRESS.value, "InProgress")
        self.assertEqual(TaskStatus.COMPLETED.value, "Completed")
        self.assertEqual(TaskStatus.CANCEL.value, "Cancel")


class TestAlertStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(AlertStatus.NEW.value, "New")
        self.assertEqual(AlertStatus.UPDATED.value, "Updated")
        self.assertEqual(AlertStatus.IGNORED.value, "Ignored")
        self.assertEqual(AlertStatus.IMPORTED.value, "Imported")


class TestObservableDataType(unittest.TestCase):
    def test_has_common_types(self):
        self.assertEqual(ObservableDataType.IP.value, "ip")
        self.assertEqual(ObservableDataType.DOMAIN.value, "domain")
        self.assertEqual(ObservableDataType.URL.value, "url")
        self.assertEqual(ObservableDataType.HASH.value, "hash")
        self.assertEqual(ObservableDataType.MAIL.value, "mail")

    def test_count(self):
        self.assertEqual(len(ObservableDataType), 16)


class TestSyncDirection(unittest.TestCase):
    def test_values(self):
        self.assertEqual(SyncDirection.TSUNAMI_TO_THEHIVE.value, "tsunami_to_thehive")
        self.assertEqual(SyncDirection.THEHIVE_TO_TSUNAMI.value, "thehive_to_tsunami")
        self.assertEqual(SyncDirection.BIDIRECTIONAL.value, "bidirectional")


class TestSyncStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(SyncStatus.PENDING.value, "pending")
        self.assertEqual(SyncStatus.SYNCED.value, "synced")
        self.assertEqual(SyncStatus.FAILED.value, "failed")
        self.assertEqual(SyncStatus.CONFLICT.value, "conflict")


# ============================================================================
# Data Class Tests
# ============================================================================

class TestTheHiveCase(unittest.TestCase):
    def test_default_creation(self):
        c = TheHiveCase()
        self.assertIsNone(c.id)
        self.assertEqual(c.title, "")
        self.assertEqual(c.severity, CaseSeverity.MEDIUM.value)
        self.assertEqual(c.tlp, TLP.AMBER.value)
        self.assertEqual(c.status, CaseStatus.NEW.value)

    def test_creation_with_values(self):
        c = TheHiveCase(
            title="Test Case",
            description="A test case",
            severity=CaseSeverity.HIGH.value,
            tags=["test", "critical"],
        )
        self.assertEqual(c.title, "Test Case")
        self.assertEqual(c.severity, 3)
        self.assertEqual(len(c.tags), 2)

    def test_to_create_dict(self):
        c = TheHiveCase(title="Test", description="Desc", owner="admin", template="default")
        d = c.to_create_dict()
        self.assertEqual(d["title"], "Test")
        self.assertEqual(d["description"], "Desc")
        self.assertEqual(d["owner"], "admin")
        self.assertEqual(d["template"], "default")
        self.assertNotIn("id", d)
        self.assertNotIn("status", d)

    def test_to_create_dict_no_optional(self):
        c = TheHiveCase(title="Test", description="Desc")
        d = c.to_create_dict()
        self.assertNotIn("owner", d)
        self.assertNotIn("assignee", d)
        self.assertNotIn("template", d)

    def test_to_dict(self):
        c = TheHiveCase(id="case1", title="Test", tags=["a"])
        d = c.to_dict()
        self.assertEqual(d["id"], "case1")
        self.assertEqual(d["tags"], ["a"])
        self.assertIn("tsunami_alert_id", d)

    def test_from_dict(self):
        d = {"_id": "case1", "title": "Test", "severity": 3, "startDate": "2025-01-01"}
        c = TheHiveCase.from_dict(d)
        self.assertEqual(c.id, "case1")
        self.assertEqual(c.title, "Test")
        self.assertEqual(c.severity, 3)
        self.assertEqual(c.start_date, "2025-01-01")

    def test_from_dict_defaults(self):
        c = TheHiveCase.from_dict({})
        self.assertEqual(c.title, "")
        self.assertEqual(c.severity, CaseSeverity.MEDIUM.value)

    def test_from_dict_custom_fields(self):
        d = {"customFields": {"priority": "P1"}}
        c = TheHiveCase.from_dict(d)
        self.assertEqual(c.custom_fields, {"priority": "P1"})

    def test_roundtrip(self):
        c = TheHiveCase(
            id="r1", title="Roundtrip", description="Test",
            severity=4, tlp=1, pap=3, tags=["x"], flag=True,
        )
        c2 = TheHiveCase.from_dict(c.to_dict())
        self.assertEqual(c2.id, c.id)
        self.assertEqual(c2.title, c.title)
        self.assertEqual(c2.severity, c.severity)


class TestTheHiveTask(unittest.TestCase):
    def test_default_creation(self):
        t = TheHiveTask()
        self.assertEqual(t.status, TaskStatus.WAITING.value)
        self.assertFalse(t.flag)
        self.assertFalse(t.mandatory)

    def test_to_create_dict(self):
        t = TheHiveTask(title="Investigate", group="analysis", assignee="analyst1")
        d = t.to_create_dict()
        self.assertEqual(d["title"], "Investigate")
        self.assertEqual(d["group"], "analysis")
        self.assertEqual(d["assignee"], "analyst1")

    def test_to_create_dict_minimal(self):
        t = TheHiveTask(title="T1")
        d = t.to_create_dict()
        self.assertNotIn("group", d)
        self.assertNotIn("assignee", d)

    def test_to_dict(self):
        t = TheHiveTask(id="t1", case_id="c1", title="Task1")
        d = t.to_dict()
        self.assertEqual(d["id"], "t1")
        self.assertEqual(d["case_id"], "c1")

    def test_from_dict(self):
        d = {"_id": "t1", "caseId": "c1", "title": "Task", "dueDate": "2025-12-31"}
        t = TheHiveTask.from_dict(d)
        self.assertEqual(t.id, "t1")
        self.assertEqual(t.case_id, "c1")
        self.assertEqual(t.due_date, "2025-12-31")

    def test_roundtrip(self):
        t = TheHiveTask(id="t1", title="RT", status="InProgress", order=5)
        t2 = TheHiveTask.from_dict(t.to_dict())
        self.assertEqual(t2.title, t.title)
        self.assertEqual(t2.order, 5)


class TestTheHiveObservable(unittest.TestCase):
    def test_default_creation(self):
        o = TheHiveObservable()
        self.assertEqual(o.data_type, ObservableDataType.OTHER.value)
        self.assertFalse(o.ioc)
        self.assertFalse(o.sighted)

    def test_to_create_dict(self):
        o = TheHiveObservable(data_type="ip", data="10.0.0.1", ioc=True, message="Suspicious")
        d = o.to_create_dict()
        self.assertEqual(d["dataType"], "ip")
        self.assertEqual(d["data"], "10.0.0.1")
        self.assertTrue(d["ioc"])
        self.assertEqual(d["message"], "Suspicious")

    def test_to_create_dict_no_data(self):
        o = TheHiveObservable(data_type="ip")
        d = o.to_create_dict()
        self.assertNotIn("data", d)

    def test_from_dict(self):
        d = {"_id": "o1", "dataType": "domain", "data": "evil.com", "ioc": True,
             "sightedAt": "2025-01-01", "ignoreSimilarity": True}
        o = TheHiveObservable.from_dict(d)
        self.assertEqual(o.id, "o1")
        self.assertEqual(o.data_type, "domain")
        self.assertTrue(o.ioc)
        self.assertEqual(o.sighted_at, "2025-01-01")
        self.assertTrue(o.ignore_similarity)

    def test_to_dict(self):
        o = TheHiveObservable(id="o1", data_type="ip", data="1.2.3.4", tags=["test"])
        d = o.to_dict()
        self.assertEqual(d["tags"], ["test"])
        self.assertEqual(d["data"], "1.2.3.4")

    def test_roundtrip(self):
        o = TheHiveObservable(data_type="hash", data="abc123", ioc=True, sighted=True)
        o2 = TheHiveObservable.from_dict(o.to_dict())
        self.assertEqual(o2.data, o.data)
        self.assertTrue(o2.ioc)


class TestTheHiveAlert(unittest.TestCase):
    def test_default_creation(self):
        a = TheHiveAlert()
        self.assertEqual(a.source, "TSUNAMI")
        self.assertEqual(a.type, "external")
        self.assertTrue(a.follow)

    def test_to_create_dict(self):
        a = TheHiveAlert(
            title="Malware Detected", description="Found malware",
            severity=3, source_ref="ref-1", artifacts=[{"dataType": "ip", "data": "1.1.1.1"}],
            case_template="malware",
        )
        d = a.to_create_dict()
        self.assertEqual(d["title"], "Malware Detected")
        self.assertEqual(d["sourceRef"], "ref-1")
        self.assertEqual(len(d["artifacts"]), 1)
        self.assertEqual(d["caseTemplate"], "malware")

    def test_to_create_dict_generates_source_ref(self):
        a = TheHiveAlert(title="Test")
        d = a.to_create_dict()
        self.assertIn("sourceRef", d)
        self.assertTrue(len(d["sourceRef"]) > 0)

    def test_from_dict(self):
        d = {"_id": "a1", "title": "Alert", "sourceRef": "ref1", "caseTemplate": "default",
             "customFields": {"field1": "val1"}}
        a = TheHiveAlert.from_dict(d)
        self.assertEqual(a.id, "a1")
        self.assertEqual(a.source_ref, "ref1")
        self.assertEqual(a.case_template, "default")
        self.assertEqual(a.custom_fields, {"field1": "val1"})

    def test_to_dict(self):
        a = TheHiveAlert(id="a1", title="Alert", tags=["test"])
        d = a.to_dict()
        self.assertEqual(d["tags"], ["test"])

    def test_roundtrip(self):
        a = TheHiveAlert(title="RT", severity=4, tags=["critical"])
        a2 = TheHiveAlert.from_dict(a.to_dict())
        self.assertEqual(a2.title, a.title)
        self.assertEqual(a2.severity, 4)


class TestSyncRecord(unittest.TestCase):
    def test_default_creation(self):
        s = SyncRecord()
        self.assertEqual(s.status, SyncStatus.PENDING.value)

    def test_to_dict(self):
        s = SyncRecord(
            id="s1", tsunami_id="t1", thehive_id="h1",
            entity_type="case", direction="tsunami_to_thehive",
            status="synced",
        )
        d = s.to_dict()
        self.assertEqual(d["id"], "s1")
        self.assertEqual(d["entity_type"], "case")

    def test_from_dict(self):
        d = {"id": "s1", "tsunami_id": "t1", "thehive_id": "h1",
             "entity_type": "case", "status": "failed", "error_message": "timeout"}
        s = SyncRecord.from_dict(d)
        self.assertEqual(s.id, "s1")
        self.assertEqual(s.status, "failed")
        self.assertEqual(s.error_message, "timeout")

    def test_roundtrip(self):
        s = SyncRecord(tsunami_id="t1", thehive_id="h1", entity_type="alert")
        s2 = SyncRecord.from_dict(s.to_dict())
        self.assertEqual(s2.tsunami_id, s.tsunami_id)


# ============================================================================
# TheHive Client Tests
# ============================================================================

class TestTheHiveClient(unittest.TestCase):
    def setUp(self):
        self.client = TheHiveClient(url="http://thehive:9000", api_key="test-key")

    def test_init(self):
        self.assertEqual(self.client.url, "http://thehive:9000")
        self.assertEqual(self.client.api_key, "test-key")
        self.assertEqual(self.client.max_retries, 3)

    def test_init_trailing_slash(self):
        c = TheHiveClient(url="http://thehive:9000/")
        self.assertEqual(c.url, "http://thehive:9000")

    def test_init_from_env(self):
        with patch.dict(os.environ, {"THEHIVE_API_KEY": "env-key"}):
            c = TheHiveClient()
            self.assertEqual(c.api_key, "env-key")

    @patch("modules.case_management.thehive_connector.TheHiveClient._get_session")
    def test_request_success(self, mock_session_getter):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '{"_id": "case1"}'
        mock_resp.json.return_value = {"_id": "case1"}
        mock_session = MagicMock()
        mock_session.request.return_value = mock_resp
        mock_session_getter.return_value = mock_session

        result = self.client._request("GET", "/case/case1")
        self.assertEqual(result["_id"], "case1")
        self.assertEqual(result["_status_code"], 200)

    @patch("modules.case_management.thehive_connector.TheHiveClient._get_session")
    def test_request_no_session(self, mock_getter):
        mock_getter.return_value = None
        result = self.client._request("GET", "/test")
        self.assertEqual(result["_status_code"], 0)
        self.assertIn("error", result)

    @patch("modules.case_management.thehive_connector.TheHiveClient._get_session")
    def test_request_server_error_retries(self, mock_getter):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = '{"error": "internal"}'
        mock_resp.json.return_value = {"error": "internal"}
        mock_session = MagicMock()
        mock_session.request.return_value = mock_resp
        mock_getter.return_value = mock_session

        self.client.max_retries = 2
        result = self.client._request("GET", "/test")
        self.assertEqual(mock_session.request.call_count, 2)

    @patch("modules.case_management.thehive_connector.TheHiveClient._get_session")
    def test_request_exception_retries(self, mock_getter):
        mock_session = MagicMock()
        mock_session.request.side_effect = Exception("Connection refused")
        mock_getter.return_value = mock_session

        self.client.max_retries = 2
        result = self.client._request("GET", "/test")
        self.assertIn("error", result)
        self.assertEqual(mock_session.request.call_count, 2)

    @patch("modules.case_management.thehive_connector.TheHiveClient._get_session")
    def test_request_json_parse_error(self, mock_getter):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "not json"
        mock_resp.json.side_effect = ValueError("bad json")
        mock_session = MagicMock()
        mock_session.request.return_value = mock_resp
        mock_getter.return_value = mock_session

        result = self.client._request("GET", "/test")
        self.assertEqual(result["_raw"], "not json")
        self.assertEqual(result["_status_code"], 200)

    @patch("modules.case_management.thehive_connector.TheHiveClient._get_session")
    def test_request_empty_response(self, mock_getter):
        mock_resp = MagicMock()
        mock_resp.status_code = 204
        mock_resp.text = ""
        mock_session = MagicMock()
        mock_session.request.return_value = mock_resp
        mock_getter.return_value = mock_session

        result = self.client._request("DELETE", "/case/1")
        self.assertEqual(result["_status_code"], 204)

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_health_check_healthy(self, mock_req):
        mock_req.return_value = {"_status_code": 200, "login": "admin", "organisation": "default"}
        result = self.client.health_check()
        self.assertTrue(result["healthy"])
        self.assertEqual(result["user"], "admin")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_health_check_unhealthy(self, mock_req):
        mock_req.return_value = {"_status_code": 401}
        result = self.client.health_check()
        self.assertFalse(result["healthy"])

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_create_case(self, mock_req):
        mock_req.return_value = {"_id": "case1", "_status_code": 201}
        case = TheHiveCase(title="Test")
        result = self.client.create_case(case)
        self.assertEqual(result["_id"], "case1")
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_get_case(self, mock_req):
        mock_req.return_value = {"_id": "c1", "_status_code": 200}
        result = self.client.get_case("c1")
        self.assertEqual(result["_id"], "c1")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_update_case(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.update_case("c1", {"title": "Updated"})
        mock_req.assert_called_with("PATCH", "/case/c1", data={"title": "Updated"})

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_delete_case(self, mock_req):
        mock_req.return_value = {"_status_code": 204}
        self.client.delete_case("c1")
        mock_req.assert_called_with("DELETE", "/case/c1")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_search_cases(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.search_cases(page_size=10, page=1)
        call_args = mock_req.call_args
        self.assertEqual(call_args[0][0], "POST")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_merge_cases(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.merge_cases("c1", "c2")
        mock_req.assert_called_with("POST", "/case/c1/_merge/c2")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_create_task(self, mock_req):
        mock_req.return_value = {"_id": "t1", "_status_code": 201}
        task = TheHiveTask(title="Investigate")
        self.client.create_task("c1", task)
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_get_task(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.get_task("t1")
        mock_req.assert_called_with("GET", "/case/task/t1")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_update_task(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.update_task("t1", {"status": "Completed"})
        mock_req.assert_called_with("PATCH", "/case/task/t1", data={"status": "Completed"})

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_list_case_tasks(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.list_case_tasks("c1")
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_add_task_log(self, mock_req):
        mock_req.return_value = {"_status_code": 201}
        self.client.add_task_log("t1", "Investigation started")
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_create_observable(self, mock_req):
        mock_req.return_value = {"_id": "o1", "_status_code": 201}
        obs = TheHiveObservable(data_type="ip", data="10.0.0.1")
        self.client.create_observable("c1", obs)
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_get_observable(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.get_observable("o1")
        mock_req.assert_called_with("GET", "/case/observable/o1")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_update_observable(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.update_observable("o1", {"ioc": True})
        mock_req.assert_called_with("PATCH", "/case/observable/o1", data={"ioc": True})

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_list_case_observables(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.list_case_observables("c1")
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_run_analyzer(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.run_analyzer("o1", "MaxMind_GeoIP")
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_create_alert(self, mock_req):
        mock_req.return_value = {"_id": "a1", "_status_code": 201}
        alert = TheHiveAlert(title="Phishing")
        self.client.create_alert(alert)
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_get_alert(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.get_alert("a1")
        mock_req.assert_called_with("GET", "/alert/a1")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_update_alert(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.update_alert("a1", {"status": "Ignored"})
        mock_req.assert_called_with("PATCH", "/alert/a1", data={"status": "Ignored"})

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_promote_alert(self, mock_req):
        mock_req.return_value = {"_status_code": 201}
        self.client.promote_alert("a1", case_template="default")
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_promote_alert_no_template(self, mock_req):
        mock_req.return_value = {"_status_code": 201}
        self.client.promote_alert("a1")
        call_data = mock_req.call_args[1].get("data", mock_req.call_args[0][2] if len(mock_req.call_args[0]) > 2 else {})
        # Just verify it was called
        mock_req.assert_called_once()

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_merge_alert_into_case(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.merge_alert_into_case("a1", "c1")
        mock_req.assert_called_with("POST", "/alert/a1/merge/c1")

    @patch("modules.case_management.thehive_connector.TheHiveClient._request")
    def test_search_alerts(self, mock_req):
        mock_req.return_value = {"_status_code": 200}
        self.client.search_alerts(page_size=20, page=0)
        mock_req.assert_called_once()

    def test_get_session_no_requests(self):
        """When requests library is not available."""
        original_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "requests":
                raise ImportError("No module named 'requests'")
            return original_import(name, *args, **kwargs)
        client = TheHiveClient()
        client._session = None
        with patch("builtins.__import__", side_effect=mock_import):
            session = client._get_session()
            self.assertIsNone(session)


# ============================================================================
# SyncStore Tests
# ============================================================================

class TestSyncStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_sync.db")
        self.store = SyncStore(db_path=self.db_path)

    def test_init_creates_db(self):
        self.assertTrue(os.path.exists(self.db_path))

    def test_default_path(self):
        store = SyncStore()
        self.assertIn("thehive_sync.db", store.db_path)

    def test_save_and_get_by_tsunami_id(self):
        record = SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case",
            direction="tsunami_to_thehive", status="synced",
        )
        saved = self.store.save_record(record)
        self.assertTrue(len(saved.id) > 0)

        retrieved = self.store.get_by_tsunami_id("t1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.thehive_id, "h1")

    def test_get_by_tsunami_id_with_type(self):
        self.store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case",
        ))
        self.store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h2", entity_type="alert",
        ))
        result = self.store.get_by_tsunami_id("t1", "alert")
        self.assertEqual(result.thehive_id, "h2")

    def test_get_by_tsunami_id_not_found(self):
        self.assertIsNone(self.store.get_by_tsunami_id("nonexistent"))

    def test_get_by_thehive_id(self):
        self.store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case",
        ))
        result = self.store.get_by_thehive_id("h1")
        self.assertIsNotNone(result)
        self.assertEqual(result.tsunami_id, "t1")

    def test_get_by_thehive_id_with_type(self):
        self.store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case",
        ))
        result = self.store.get_by_thehive_id("h1", "case")
        self.assertIsNotNone(result)
        result2 = self.store.get_by_thehive_id("h1", "alert")
        self.assertIsNone(result2)

    def test_get_by_thehive_id_not_found(self):
        self.assertIsNone(self.store.get_by_thehive_id("nonexistent"))

    def test_list_records(self):
        for i in range(5):
            self.store.save_record(SyncRecord(
                tsunami_id=f"t{i}", thehive_id=f"h{i}", entity_type="case",
                status="synced" if i < 3 else "failed",
            ))
        records = self.store.list_records()
        self.assertEqual(len(records), 5)

    def test_list_records_filter_type(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", thehive_id="h1", entity_type="case"))
        self.store.save_record(SyncRecord(tsunami_id="t2", thehive_id="h2", entity_type="alert"))
        records = self.store.list_records(entity_type="case")
        self.assertEqual(len(records), 1)

    def test_list_records_filter_status(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", thehive_id="h1", entity_type="case", status="synced"))
        self.store.save_record(SyncRecord(tsunami_id="t2", thehive_id="h2", entity_type="case", status="failed"))
        records = self.store.list_records(status="failed")
        self.assertEqual(len(records), 1)

    def test_list_records_pagination(self):
        for i in range(10):
            self.store.save_record(SyncRecord(
                tsunami_id=f"t{i}", thehive_id=f"h{i}", entity_type="case",
            ))
        page1 = self.store.list_records(limit=3, offset=0)
        page2 = self.store.list_records(limit=3, offset=3)
        self.assertEqual(len(page1), 3)
        self.assertEqual(len(page2), 3)

    def test_delete_record(self):
        record = self.store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case",
        ))
        self.assertTrue(self.store.delete_record(record.id))
        self.assertIsNone(self.store.get_by_tsunami_id("t1"))

    def test_delete_record_not_found(self):
        self.assertFalse(self.store.delete_record("nonexistent"))

    def test_count_records(self):
        for i in range(5):
            self.store.save_record(SyncRecord(
                tsunami_id=f"t{i}", thehive_id=f"h{i}", entity_type="case",
                status="synced" if i < 3 else "failed",
            ))
        self.assertEqual(self.store.count_records(), 5)
        self.assertEqual(self.store.count_records(entity_type="case"), 5)
        self.assertEqual(self.store.count_records(status="synced"), 3)
        self.assertEqual(self.store.count_records(status="failed"), 2)

    def test_upsert(self):
        record = self.store.save_record(SyncRecord(
            id="fixed-id", tsunami_id="t1", thehive_id="h1",
            entity_type="case", status="pending",
        ))
        record.status = "synced"
        self.store.save_record(record)
        retrieved = self.store.get_by_tsunami_id("t1")
        self.assertEqual(retrieved.status, "synced")


# ============================================================================
# TheHive Connector Tests
# ============================================================================

class TestTheHiveConnector(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mock_client = MagicMock(spec=TheHiveClient)
        self.sync_store = SyncStore(db_path=os.path.join(self.tmpdir, "sync.db"))
        self.connector = TheHiveConnector(
            client=self.mock_client,
            sync_store=self.sync_store,
        )

    # ---- Health ----

    def test_health_check(self):
        self.mock_client.health_check.return_value = {"healthy": True, "status_code": 200}
        result = self.connector.health_check()
        self.assertTrue(result["healthy"])

    # ---- Cases ----

    def test_create_case_success(self):
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        case = TheHiveCase(title="Test Case", tsunami_alert_id="alert-1")
        success, result = self.connector.create_case(case)
        self.assertTrue(success)
        self.assertEqual(result["_id"], "c1")
        # Check sync record created
        sr = self.sync_store.get_by_tsunami_id("alert-1", "case")
        self.assertIsNotNone(sr)
        self.assertEqual(sr.status, "synced")

    def test_create_case_failure(self):
        self.mock_client.create_case.return_value = {"error": "bad", "_status_code": 400}
        case = TheHiveCase(title="Test")
        success, result = self.connector.create_case(case)
        self.assertFalse(success)

    def test_create_case_callback(self):
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        cb = MagicMock()
        self.connector.on("case_created", cb)
        case = TheHiveCase(title="Test")
        self.connector.create_case(case)
        cb.assert_called_once()

    def test_get_case_success(self):
        self.mock_client.get_case.return_value = {"_id": "c1", "title": "T", "_status_code": 200}
        success, result = self.connector.get_case("c1")
        self.assertTrue(success)

    def test_get_case_not_found(self):
        self.mock_client.get_case.return_value = {"_status_code": 404}
        success, result = self.connector.get_case("nonexistent")
        self.assertFalse(success)

    def test_update_case(self):
        self.mock_client.update_case.return_value = {"_status_code": 200}
        cb = MagicMock()
        self.connector.on("case_updated", cb)
        success, _ = self.connector.update_case("c1", {"title": "Updated"})
        self.assertTrue(success)
        cb.assert_called_once()

    def test_update_case_failure(self):
        self.mock_client.update_case.return_value = {"_status_code": 400}
        success, _ = self.connector.update_case("c1", {"title": "Bad"})
        self.assertFalse(success)

    def test_close_case(self):
        self.mock_client.update_case.return_value = {"_status_code": 200}
        success, _ = self.connector.close_case("c1", summary="Resolved manually")
        self.assertTrue(success)
        call_data = self.mock_client.update_case.call_args[0][1]
        self.assertEqual(call_data["status"], "Resolved")
        self.assertEqual(call_data["summary"], "Resolved manually")

    def test_close_case_no_summary(self):
        self.mock_client.update_case.return_value = {"_status_code": 200}
        success, _ = self.connector.close_case("c1")
        call_data = self.mock_client.update_case.call_args[0][1]
        self.assertNotIn("summary", call_data)

    def test_delete_case(self):
        self.mock_client.delete_case.return_value = {"_status_code": 204}
        success, _ = self.connector.delete_case("c1")
        self.assertTrue(success)

    def test_search_cases(self):
        self.mock_client.search_cases.return_value = {"_status_code": 200}
        success, _ = self.connector.search_cases()
        self.assertTrue(success)

    def test_merge_cases(self):
        self.mock_client.merge_cases.return_value = {"_status_code": 200}
        success, _ = self.connector.merge_cases("c1", "c2")
        self.assertTrue(success)

    # ---- Tasks ----

    def test_create_task(self):
        self.mock_client.create_task.return_value = {"_id": "t1", "_status_code": 201}
        task = TheHiveTask(title="Investigate")
        success, result = self.connector.create_task("c1", task)
        self.assertTrue(success)

    def test_get_task(self):
        self.mock_client.get_task.return_value = {"_status_code": 200}
        success, _ = self.connector.get_task("t1")
        self.assertTrue(success)

    def test_update_task(self):
        self.mock_client.update_task.return_value = {"_status_code": 200}
        success, _ = self.connector.update_task("t1", {"status": "InProgress"})
        self.assertTrue(success)

    def test_complete_task(self):
        self.mock_client.update_task.return_value = {"_status_code": 200}
        success, _ = self.connector.complete_task("t1")
        self.assertTrue(success)
        call_data = self.mock_client.update_task.call_args[0][1]
        self.assertEqual(call_data["status"], "Completed")

    def test_list_case_tasks(self):
        self.mock_client.list_case_tasks.return_value = {"_status_code": 200}
        success, _ = self.connector.list_case_tasks("c1")
        self.assertTrue(success)

    def test_add_task_log(self):
        self.mock_client.add_task_log.return_value = {"_status_code": 201}
        success, _ = self.connector.add_task_log("t1", "Started investigation")
        self.assertTrue(success)

    # ---- Observables ----

    def test_add_observable(self):
        self.mock_client.create_observable.return_value = {"_id": "o1", "_status_code": 201}
        obs = TheHiveObservable(data_type="ip", data="1.2.3.4")
        success, _ = self.connector.add_observable("c1", obs)
        self.assertTrue(success)

    def test_get_observable(self):
        self.mock_client.get_observable.return_value = {"_status_code": 200}
        success, _ = self.connector.get_observable("o1")
        self.assertTrue(success)

    def test_update_observable(self):
        self.mock_client.update_observable.return_value = {"_status_code": 200}
        success, _ = self.connector.update_observable("o1", {"ioc": True})
        self.assertTrue(success)

    def test_list_case_observables(self):
        self.mock_client.list_case_observables.return_value = {"_status_code": 200}
        success, _ = self.connector.list_case_observables("c1")
        self.assertTrue(success)

    def test_run_analyzer(self):
        self.mock_client.run_analyzer.return_value = {"_status_code": 200}
        success, _ = self.connector.run_analyzer("o1", "MaxMind")
        self.assertTrue(success)

    # ---- Alerts ----

    def test_create_alert(self):
        self.mock_client.create_alert.return_value = {"_id": "a1", "_status_code": 201}
        cb = MagicMock()
        self.connector.on("alert_synced", cb)
        alert = TheHiveAlert(title="Phishing")
        success, _ = self.connector.create_alert(alert)
        self.assertTrue(success)
        cb.assert_called_once()

    def test_create_alert_failure(self):
        self.mock_client.create_alert.return_value = {"_status_code": 400}
        alert = TheHiveAlert(title="Bad")
        success, _ = self.connector.create_alert(alert)
        self.assertFalse(success)

    def test_get_alert(self):
        self.mock_client.get_alert.return_value = {"_status_code": 200}
        success, _ = self.connector.get_alert("a1")
        self.assertTrue(success)

    def test_promote_alert_to_case(self):
        self.mock_client.promote_alert.return_value = {"_status_code": 201}
        success, _ = self.connector.promote_alert_to_case("a1", "default")
        self.assertTrue(success)

    def test_merge_alert_into_case(self):
        self.mock_client.merge_alert_into_case.return_value = {"_status_code": 200}
        success, _ = self.connector.merge_alert_into_case("a1", "c1")
        self.assertTrue(success)

    # ---- Sync ----

    def test_sync_tsunami_alert_to_case_success(self):
        self.mock_client.create_case.return_value = {"_id": "hive-c1", "_status_code": 201}
        alert_data = {
            "alert_id": "tsunami-1",
            "title": "Brute Force Detected",
            "severity": "high",
            "tags": ["brute-force"],
            "assignee": "analyst1",
        }
        success, result = self.connector.sync_tsunami_alert_to_case(alert_data)
        self.assertTrue(success)
        # Verify sync record
        sr = self.sync_store.get_by_tsunami_id("tsunami-1", "case")
        self.assertIsNotNone(sr)
        self.assertEqual(sr.status, "synced")

    def test_sync_tsunami_alert_to_case_already_synced(self):
        self.sync_store.save_record(SyncRecord(
            tsunami_id="tsunami-1", thehive_id="h1", entity_type="case",
            status="synced",
        ))
        success, result = self.connector.sync_tsunami_alert_to_case(
            {"alert_id": "tsunami-1", "title": "Duplicate"}
        )
        self.assertTrue(success)
        self.assertIn("Already synced", result.get("message", ""))
        # Client should NOT be called
        self.mock_client.create_case.assert_not_called()

    def test_sync_tsunami_alert_to_case_failure(self):
        self.mock_client.create_case.return_value = {"error": "internal", "_status_code": 500}
        cb = MagicMock()
        self.connector.on("sync_error", cb)
        alert_data = {"alert_id": "t-fail", "title": "Fail"}
        success, _ = self.connector.sync_tsunami_alert_to_case(alert_data)
        self.assertFalse(success)
        cb.assert_called_once()
        sr = self.sync_store.get_by_tsunami_id("t-fail", "case")
        self.assertEqual(sr.status, "failed")

    def test_sync_tsunami_alert_severity_mapping(self):
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        for severity, expected in [
            ("low", 1), ("medium", 2), ("high", 3), ("critical", 4), ("unknown", 2),
        ]:
            self.connector.sync_tsunami_alert_to_case(
                {"alert_id": f"t-{severity}", "title": "Test", "severity": severity}
            )
            call_args = self.mock_client.create_case.call_args[0][0]
            self.assertEqual(call_args.severity, expected, f"Failed for {severity}")

    def test_sync_tsunami_alert_with_template(self):
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        self.connector.sync_tsunami_alert_to_case(
            {"alert_id": "t1", "title": "Test"}, template="custom"
        )
        call_args = self.mock_client.create_case.call_args[0][0]
        self.assertEqual(call_args.template, "custom")

    def test_sync_thehive_case_to_tsunami(self):
        self.mock_client.get_case.return_value = {
            "_id": "hive-1", "title": "Incident", "severity": 3,
            "status": "InProgress", "tags": ["test"], "_status_code": 200,
        }
        success, tsunami_data = self.connector.sync_thehive_case_to_tsunami("hive-1")
        self.assertTrue(success)
        self.assertEqual(tsunami_data["source"], "thehive")
        self.assertEqual(tsunami_data["severity"], "high")
        sr = self.sync_store.get_by_thehive_id("hive-1")
        self.assertIsNotNone(sr)

    def test_sync_thehive_case_to_tsunami_failure(self):
        self.mock_client.get_case.return_value = {"_status_code": 404}
        success, _ = self.connector.sync_thehive_case_to_tsunami("nonexistent")
        self.assertFalse(success)

    def test_add_observables_from_alert(self):
        self.mock_client.create_observable.return_value = {"_id": "o1", "_status_code": 201}
        alert_data = {
            "iocs": [
                {"type": "ip", "value": "10.0.0.1", "ioc": True},
                {"type": "domain", "value": "evil.com"},
                {"type": "sha256", "value": "abc123"},
            ]
        }
        results = self.connector.add_observables_from_alert("c1", alert_data)
        self.assertEqual(len(results), 3)
        for r in results:
            self.assertTrue(r["success"])

    def test_add_observables_type_mapping(self):
        self.mock_client.create_observable.return_value = {"_id": "o1", "_status_code": 201}
        alert_data = {
            "iocs": [
                {"type": "ip_address", "value": "10.0.0.1"},
                {"type": "src_ip", "value": "10.0.0.2"},
                {"type": "email", "value": "test@evil.com"},
                {"type": "hostname", "value": "server1"},
                {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"},
            ]
        }
        results = self.connector.add_observables_from_alert("c1", alert_data)
        self.assertEqual(len(results), 5)
        # Verify type mapping
        calls = self.mock_client.create_observable.call_args_list
        self.assertEqual(calls[0][0][1].data_type, "ip")
        self.assertEqual(calls[1][0][1].data_type, "ip")
        self.assertEqual(calls[2][0][1].data_type, "mail")
        self.assertEqual(calls[3][0][1].data_type, "hostname")
        self.assertEqual(calls[4][0][1].data_type, "hash")

    def test_add_observables_empty(self):
        results = self.connector.add_observables_from_alert("c1", {})
        self.assertEqual(len(results), 0)

    def test_add_observables_alternative_key(self):
        self.mock_client.create_observable.return_value = {"_id": "o1", "_status_code": 201}
        alert_data = {"observables": [{"type": "ip", "data": "1.1.1.1"}]}
        results = self.connector.add_observables_from_alert("c1", alert_data)
        self.assertEqual(len(results), 1)

    # ---- Sync State ----

    def test_get_sync_status(self):
        self.sync_store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case", status="synced",
        ))
        result = self.connector.get_sync_status("t1")
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "synced")

    def test_get_sync_status_not_found(self):
        self.assertIsNone(self.connector.get_sync_status("nonexistent"))

    def test_list_sync_records(self):
        self.sync_store.save_record(SyncRecord(tsunami_id="t1", thehive_id="h1", entity_type="case"))
        records = self.connector.list_sync_records()
        self.assertEqual(len(records), 1)

    def test_get_sync_stats(self):
        self.sync_store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case", status="synced",
        ))
        self.sync_store.save_record(SyncRecord(
            tsunami_id="t2", thehive_id="h2", entity_type="alert", status="failed",
        ))
        stats = self.connector.get_sync_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["synced"], 1)
        self.assertEqual(stats["failed"], 1)
        self.assertEqual(stats["cases"], 1)
        self.assertEqual(stats["alerts"], 1)

    # ---- Callbacks ----

    def test_callback_exception_handled(self):
        def bad_cb(event, data):
            raise RuntimeError("oops")
        self.connector.on("case_created", bad_cb)
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        # Should not raise
        success, _ = self.connector.create_case(TheHiveCase(title="Test"))
        self.assertTrue(success)

    def test_multiple_callbacks(self):
        cb1 = MagicMock()
        cb2 = MagicMock()
        self.connector.on("case_created", cb1)
        self.connector.on("case_created", cb2)
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        self.connector.create_case(TheHiveCase(title="Test"))
        cb1.assert_called_once()
        cb2.assert_called_once()


# ============================================================================
# Blueprint Tests
# ============================================================================

class TestTheHiveBlueprint(unittest.TestCase):
    def setUp(self):
        from flask import Flask
        self.tmpdir = tempfile.mkdtemp()
        self.mock_client = MagicMock(spec=TheHiveClient)
        self.sync_store = SyncStore(db_path=os.path.join(self.tmpdir, "sync.db"))
        self.connector = TheHiveConnector(
            client=self.mock_client,
            sync_store=self.sync_store,
        )
        self.app = Flask(__name__)
        bp = create_thehive_blueprint(self.connector)
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()

    # ---- Health ----

    def test_health_healthy(self):
        self.mock_client.health_check.return_value = {"healthy": True, "status_code": 200}
        resp = self.client.get("/api/v1/soc/thehive/health")
        self.assertEqual(resp.status_code, 200)

    def test_health_unhealthy(self):
        self.mock_client.health_check.return_value = {"healthy": False, "status_code": 401}
        resp = self.client.get("/api/v1/soc/thehive/health")
        self.assertEqual(resp.status_code, 503)

    # ---- Cases ----

    def test_create_case(self):
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/cases",
                                json={"title": "Test Case", "severity": 3})
        self.assertEqual(resp.status_code, 201)

    def test_create_case_missing_title(self):
        resp = self.client.post("/api/v1/soc/thehive/cases", json={})
        self.assertEqual(resp.status_code, 400)

    def test_get_case(self):
        self.mock_client.get_case.return_value = {"_id": "c1", "_status_code": 200}
        resp = self.client.get("/api/v1/soc/thehive/cases/c1")
        self.assertEqual(resp.status_code, 200)

    def test_get_case_not_found(self):
        self.mock_client.get_case.return_value = {"_status_code": 404}
        resp = self.client.get("/api/v1/soc/thehive/cases/bad")
        self.assertEqual(resp.status_code, 404)

    def test_update_case(self):
        self.mock_client.update_case.return_value = {"_status_code": 200}
        resp = self.client.patch("/api/v1/soc/thehive/cases/c1",
                                 json={"title": "Updated"})
        self.assertEqual(resp.status_code, 200)

    def test_delete_case(self):
        self.mock_client.delete_case.return_value = {"_status_code": 204}
        resp = self.client.delete("/api/v1/soc/thehive/cases/c1")
        self.assertEqual(resp.status_code, 200)

    def test_close_case(self):
        self.mock_client.update_case.return_value = {"_status_code": 200}
        resp = self.client.post("/api/v1/soc/thehive/cases/c1/close",
                                json={"summary": "Done"})
        self.assertEqual(resp.status_code, 200)

    def test_merge_cases(self):
        self.mock_client.merge_cases.return_value = {"_status_code": 200}
        resp = self.client.post("/api/v1/soc/thehive/cases/merge",
                                json={"case_id_1": "c1", "case_id_2": "c2"})
        self.assertEqual(resp.status_code, 200)

    def test_merge_cases_missing(self):
        resp = self.client.post("/api/v1/soc/thehive/cases/merge", json={})
        self.assertEqual(resp.status_code, 400)

    # ---- Tasks ----

    def test_create_task(self):
        self.mock_client.create_task.return_value = {"_id": "t1", "_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/cases/c1/tasks",
                                json={"title": "Investigate"})
        self.assertEqual(resp.status_code, 201)

    def test_create_task_missing_title(self):
        resp = self.client.post("/api/v1/soc/thehive/cases/c1/tasks", json={})
        self.assertEqual(resp.status_code, 400)

    def test_list_tasks(self):
        self.mock_client.list_case_tasks.return_value = {"_status_code": 200}
        resp = self.client.get("/api/v1/soc/thehive/cases/c1/tasks")
        self.assertEqual(resp.status_code, 200)

    def test_get_task(self):
        self.mock_client.get_task.return_value = {"_status_code": 200}
        resp = self.client.get("/api/v1/soc/thehive/tasks/t1")
        self.assertEqual(resp.status_code, 200)

    def test_update_task(self):
        self.mock_client.update_task.return_value = {"_status_code": 200}
        resp = self.client.patch("/api/v1/soc/thehive/tasks/t1",
                                 json={"status": "InProgress"})
        self.assertEqual(resp.status_code, 200)

    def test_complete_task(self):
        self.mock_client.update_task.return_value = {"_status_code": 200}
        resp = self.client.post("/api/v1/soc/thehive/tasks/t1/complete")
        self.assertEqual(resp.status_code, 200)

    def test_add_task_log(self):
        self.mock_client.add_task_log.return_value = {"_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/tasks/t1/log",
                                json={"message": "Found evidence"})
        self.assertEqual(resp.status_code, 201)

    def test_add_task_log_missing_message(self):
        resp = self.client.post("/api/v1/soc/thehive/tasks/t1/log", json={})
        self.assertEqual(resp.status_code, 400)

    # ---- Observables ----

    def test_add_observable(self):
        self.mock_client.create_observable.return_value = {"_id": "o1", "_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/cases/c1/observables",
                                json={"dataType": "ip", "data": "10.0.0.1"})
        self.assertEqual(resp.status_code, 201)

    def test_list_observables(self):
        self.mock_client.list_case_observables.return_value = {"_status_code": 200}
        resp = self.client.get("/api/v1/soc/thehive/cases/c1/observables")
        self.assertEqual(resp.status_code, 200)

    def test_get_observable(self):
        self.mock_client.get_observable.return_value = {"_status_code": 200}
        resp = self.client.get("/api/v1/soc/thehive/observables/o1")
        self.assertEqual(resp.status_code, 200)

    def test_analyze_observable(self):
        self.mock_client.run_analyzer.return_value = {"_status_code": 200}
        resp = self.client.post("/api/v1/soc/thehive/observables/o1/analyze",
                                json={"analyzer_id": "MaxMind_GeoIP"})
        self.assertEqual(resp.status_code, 200)

    def test_analyze_observable_missing_analyzer(self):
        resp = self.client.post("/api/v1/soc/thehive/observables/o1/analyze", json={})
        self.assertEqual(resp.status_code, 400)

    # ---- Alerts ----

    def test_create_alert(self):
        self.mock_client.create_alert.return_value = {"_id": "a1", "_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/alerts",
                                json={"title": "Phishing Alert"})
        self.assertEqual(resp.status_code, 201)

    def test_create_alert_missing_title(self):
        resp = self.client.post("/api/v1/soc/thehive/alerts", json={})
        self.assertEqual(resp.status_code, 400)

    def test_get_alert(self):
        self.mock_client.get_alert.return_value = {"_status_code": 200}
        resp = self.client.get("/api/v1/soc/thehive/alerts/a1")
        self.assertEqual(resp.status_code, 200)

    def test_promote_alert(self):
        self.mock_client.promote_alert.return_value = {"_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/alerts/a1/promote",
                                json={"case_template": "default"})
        self.assertEqual(resp.status_code, 201)

    def test_merge_alert_into_case(self):
        self.mock_client.merge_alert_into_case.return_value = {"_status_code": 200}
        resp = self.client.post("/api/v1/soc/thehive/alerts/a1/merge/c1")
        self.assertEqual(resp.status_code, 200)

    # ---- Sync ----

    def test_sync_alert_to_case(self):
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/sync/alert-to-case",
                                json={"alert_id": "t1", "title": "Brute Force"})
        self.assertEqual(resp.status_code, 201)

    def test_sync_alert_to_case_missing_id(self):
        resp = self.client.post("/api/v1/soc/thehive/sync/alert-to-case", json={})
        self.assertEqual(resp.status_code, 400)

    def test_sync_case_to_tsunami(self):
        self.mock_client.get_case.return_value = {
            "_id": "h1", "title": "Case", "severity": 2, "_status_code": 200,
        }
        resp = self.client.post("/api/v1/soc/thehive/sync/case-to-tsunami/h1")
        self.assertEqual(resp.status_code, 200)

    def test_sync_case_to_tsunami_not_found(self):
        self.mock_client.get_case.return_value = {"_status_code": 404}
        resp = self.client.post("/api/v1/soc/thehive/sync/case-to-tsunami/bad")
        self.assertEqual(resp.status_code, 400)

    def test_sync_observables(self):
        self.mock_client.create_observable.return_value = {"_id": "o1", "_status_code": 201}
        resp = self.client.post("/api/v1/soc/thehive/sync/observables/c1",
                                json={"iocs": [{"type": "ip", "value": "1.1.1.1"}]})
        self.assertEqual(resp.status_code, 200)

    def test_sync_status_found(self):
        self.sync_store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case", status="synced",
        ))
        resp = self.client.get("/api/v1/soc/thehive/sync/status/t1")
        self.assertEqual(resp.status_code, 200)

    def test_sync_status_not_found(self):
        resp = self.client.get("/api/v1/soc/thehive/sync/status/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_list_sync_records(self):
        resp = self.client.get("/api/v1/soc/thehive/sync/records")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("records", data)
        self.assertIn("total", data)

    def test_list_sync_records_with_filters(self):
        self.sync_store.save_record(SyncRecord(
            tsunami_id="t1", thehive_id="h1", entity_type="case", status="synced",
        ))
        resp = self.client.get("/api/v1/soc/thehive/sync/records?entity_type=case&status=synced")
        data = resp.get_json()
        self.assertEqual(data["total"], 1)

    def test_sync_stats(self):
        resp = self.client.get("/api/v1/soc/thehive/sync/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total", data)


# ============================================================================
# Global Singleton Tests
# ============================================================================

class TestGlobalSingleton(unittest.TestCase):
    def setUp(self):
        reset_global_connector()

    def tearDown(self):
        reset_global_connector()

    def test_get_returns_instance(self):
        conn = get_thehive_connector()
        self.assertIsNotNone(conn)
        self.assertIsInstance(conn, TheHiveConnector)

    def test_same_instance(self):
        c1 = get_thehive_connector()
        c2 = get_thehive_connector()
        self.assertIs(c1, c2)

    def test_reset(self):
        c1 = get_thehive_connector()
        reset_global_connector()
        c2 = get_thehive_connector()
        self.assertIsNot(c1, c2)


class TestBlueprintNoFlask(unittest.TestCase):
    def test_no_flask_returns_none(self):
        original_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "flask":
                raise ImportError("No module named 'flask'")
            return original_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=mock_import):
            bp = create_thehive_blueprint()
            self.assertIsNone(bp)


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mock_client = MagicMock(spec=TheHiveClient)
        self.sync_store = SyncStore(db_path=os.path.join(self.tmpdir, "sync.db"))
        self.connector = TheHiveConnector(
            client=self.mock_client,
            sync_store=self.sync_store,
        )

    def test_create_case_no_tsunami_alert_id(self):
        """Case creation without tsunami_alert_id should not create sync record."""
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        case = TheHiveCase(title="External Case")
        success, _ = self.connector.create_case(case)
        self.assertTrue(success)
        records = self.sync_store.list_records()
        self.assertEqual(len(records), 0)

    def test_thread_safety_sync_store(self):
        errors = []
        def write_records(n):
            try:
                for i in range(10):
                    self.sync_store.save_record(SyncRecord(
                        tsunami_id=f"thread-{n}-{i}",
                        thehive_id=f"h-{n}-{i}",
                        entity_type="case",
                    ))
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write_records, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0)
        self.assertEqual(self.sync_store.count_records(), 40)

    def test_sync_alert_with_id_key(self):
        """Support both 'alert_id' and 'id' keys."""
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        success, _ = self.connector.sync_tsunami_alert_to_case(
            {"id": "alt-id", "title": "Test"}
        )
        self.assertTrue(success)
        sr = self.sync_store.get_by_tsunami_id("alt-id", "case")
        self.assertIsNotNone(sr)

    def test_observable_with_unknown_type(self):
        """Unknown IOC types should pass through as-is."""
        self.mock_client.create_observable.return_value = {"_id": "o1", "_status_code": 201}
        alert_data = {"iocs": [{"type": "custom_type", "value": "something"}]}
        results = self.connector.add_observables_from_alert("c1", alert_data)
        self.assertEqual(len(results), 1)
        call_obs = self.mock_client.create_observable.call_args[0][1]
        self.assertEqual(call_obs.data_type, "custom_type")

    def test_sync_reverse_severity_mapping(self):
        for sev, label in [(1, "low"), (2, "medium"), (3, "high"), (4, "critical"), (99, "medium")]:
            self.mock_client.get_case.return_value = {
                "_id": f"h{sev}", "title": "Test", "severity": sev, "_status_code": 200,
            }
            success, data = self.connector.sync_thehive_case_to_tsunami(f"h{sev}")
            self.assertTrue(success)
            self.assertEqual(data["severity"], label, f"Failed for severity={sev}")


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.mock_client = MagicMock(spec=TheHiveClient)
        self.sync_store = SyncStore(db_path=os.path.join(self.tmpdir, "sync.db"))
        self.connector = TheHiveConnector(
            client=self.mock_client,
            sync_store=self.sync_store,
        )

    def test_full_workflow_alert_to_case_with_observables(self):
        """Full workflow: TSUNAMI alert → TheHive case → add observables → run analyzer."""
        # 1. Create case from alert
        self.mock_client.create_case.return_value = {"_id": "hive-case-1", "_status_code": 201}
        alert = {
            "alert_id": "tsunami-alert-1",
            "title": "SQL Injection Detected",
            "severity": "critical",
            "tags": ["sqli", "web-attack"],
            "iocs": [
                {"type": "ip", "value": "192.168.1.100"},
                {"type": "url", "value": "http://evil.com/inject?q=1"},
            ],
        }
        success, result = self.connector.sync_tsunami_alert_to_case(alert)
        self.assertTrue(success)

        # 2. Add observables
        self.mock_client.create_observable.return_value = {"_id": "obs-1", "_status_code": 201}
        obs_results = self.connector.add_observables_from_alert("hive-case-1", alert)
        self.assertEqual(len(obs_results), 2)

        # 3. Run analyzer
        self.mock_client.run_analyzer.return_value = {"_status_code": 200, "status": "InProgress"}
        success, _ = self.connector.run_analyzer("obs-1", "MaxMind_GeoIP")
        self.assertTrue(success)

        # 4. Verify sync state
        sr = self.sync_store.get_by_tsunami_id("tsunami-alert-1", "case")
        self.assertEqual(sr.status, "synced")
        self.assertEqual(sr.thehive_id, "hive-case-1")

    def test_bidirectional_sync(self):
        """Test bidirectional sync: TSUNAMI → TheHive → TSUNAMI."""
        # Forward sync
        self.mock_client.create_case.return_value = {"_id": "hive-1", "_status_code": 201}
        success, _ = self.connector.sync_tsunami_alert_to_case(
            {"alert_id": "t-bidir", "title": "Bidir Test", "severity": "high"}
        )
        self.assertTrue(success)

        # Reverse sync
        self.mock_client.get_case.return_value = {
            "_id": "hive-1", "title": "[TSUNAMI] Bidir Test",
            "severity": 3, "status": "InProgress", "_status_code": 200,
        }
        success, data = self.connector.sync_thehive_case_to_tsunami("hive-1")
        self.assertTrue(success)
        self.assertEqual(data["severity"], "high")

        # Verify both sync records
        forward = self.sync_store.get_by_tsunami_id("t-bidir", "case")
        self.assertIsNotNone(forward)
        reverse = self.sync_store.get_by_thehive_id("hive-1")
        self.assertIsNotNone(reverse)

    def test_case_with_tasks_workflow(self):
        """Create case → add tasks → complete tasks."""
        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        self.mock_client.create_task.return_value = {"_id": "t1", "_status_code": 201}
        self.mock_client.update_task.return_value = {"_status_code": 200}
        self.mock_client.add_task_log.return_value = {"_status_code": 201}

        # Create case
        case = TheHiveCase(title="Incident")
        success, _ = self.connector.create_case(case)
        self.assertTrue(success)

        # Add tasks
        task = TheHiveTask(title="Contain", group="containment")
        success, _ = self.connector.create_task("c1", task)
        self.assertTrue(success)

        # Add task log
        success, _ = self.connector.add_task_log("t1", "Started containment")
        self.assertTrue(success)

        # Complete task
        success, _ = self.connector.complete_task("t1")
        self.assertTrue(success)

    def test_stats_comprehensive(self):
        """Test sync stats tracking."""
        for i in range(3):
            self.sync_store.save_record(SyncRecord(
                tsunami_id=f"t{i}", thehive_id=f"h{i}", entity_type="case", status="synced",
            ))
        for i in range(2):
            self.sync_store.save_record(SyncRecord(
                tsunami_id=f"a{i}", thehive_id=f"ah{i}", entity_type="alert", status="failed",
            ))
        self.sync_store.save_record(SyncRecord(
            tsunami_id="p1", thehive_id="ph1", entity_type="case", status="pending",
        ))

        stats = self.connector.get_sync_stats()
        self.assertEqual(stats["total"], 6)
        self.assertEqual(stats["synced"], 3)
        self.assertEqual(stats["failed"], 2)
        self.assertEqual(stats["pending"], 1)
        self.assertEqual(stats["cases"], 4)
        self.assertEqual(stats["alerts"], 2)

    def test_callback_full_lifecycle(self):
        """Test callbacks fire during full lifecycle."""
        events = []
        def capture(event, data):
            events.append(event)

        self.connector.on("case_created", capture)
        self.connector.on("case_updated", capture)
        self.connector.on("alert_synced", capture)

        self.mock_client.create_case.return_value = {"_id": "c1", "_status_code": 201}
        self.connector.create_case(TheHiveCase(title="Test"))

        self.mock_client.update_case.return_value = {"_status_code": 200}
        self.connector.update_case("c1", {"title": "Updated"})

        self.mock_client.create_alert.return_value = {"_id": "a1", "_status_code": 201}
        self.connector.create_alert(TheHiveAlert(title="Alert"))

        self.assertEqual(events, ["case_created", "case_updated", "alert_synced"])


if __name__ == "__main__":
    unittest.main()
