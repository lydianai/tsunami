#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive tests for TSUNAMI SOC MISP Connector.
"""

import builtins
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.threat_sharing.misp_connector import (
    ThreatLevel, AnalysisLevel, Distribution, AttributeCategory, AttributeType,
    SightingType, SyncDirection, SyncStatus,
    MISPAttribute, MISPEvent, MISPSighting, MISPFeed, MISPGalaxyCluster, SyncRecord,
    MISPClient, SyncStore, MISPConnector,
    TSUNAMI_TO_MISP_TYPE_MAP, MISP_TO_TSUNAMI_TYPE_MAP,
    TSUNAMI_SEVERITY_TO_THREAT_LEVEL, THREAT_LEVEL_TO_TSUNAMI_SEVERITY,
    TLP_TAG_MAP,
    create_misp_blueprint, get_misp_connector, reset_global_connector,
)


# ===========================================================================
# Enum Tests
# ===========================================================================

class TestThreatLevel(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ThreatLevel.HIGH, 1)
        self.assertEqual(ThreatLevel.MEDIUM, 2)
        self.assertEqual(ThreatLevel.LOW, 3)
        self.assertEqual(ThreatLevel.UNDEFINED, 4)

    def test_count(self):
        self.assertEqual(len(ThreatLevel), 4)


class TestAnalysisLevel(unittest.TestCase):
    def test_values(self):
        self.assertEqual(AnalysisLevel.INITIAL, 0)
        self.assertEqual(AnalysisLevel.ONGOING, 1)
        self.assertEqual(AnalysisLevel.COMPLETE, 2)


class TestDistribution(unittest.TestCase):
    def test_values(self):
        self.assertEqual(Distribution.YOUR_ORGANISATION_ONLY, 0)
        self.assertEqual(Distribution.THIS_COMMUNITY_ONLY, 1)
        self.assertEqual(Distribution.CONNECTED_COMMUNITIES, 2)
        self.assertEqual(Distribution.ALL_COMMUNITIES, 3)
        self.assertEqual(Distribution.SHARING_GROUP, 4)

    def test_count(self):
        self.assertEqual(len(Distribution), 5)


class TestAttributeCategory(unittest.TestCase):
    def test_has_common_categories(self):
        self.assertEqual(AttributeCategory.NETWORK_ACTIVITY, "Network activity")
        self.assertEqual(AttributeCategory.PAYLOAD_DELIVERY, "Payload delivery")
        self.assertEqual(AttributeCategory.OTHER, "Other")

    def test_count(self):
        self.assertGreaterEqual(len(AttributeCategory), 10)


class TestAttributeType(unittest.TestCase):
    def test_has_common_types(self):
        self.assertEqual(AttributeType.IP_SRC, "ip-src")
        self.assertEqual(AttributeType.SHA256, "sha256")
        self.assertEqual(AttributeType.DOMAIN, "domain")
        self.assertEqual(AttributeType.YARA, "yara")

    def test_count(self):
        self.assertGreaterEqual(len(AttributeType), 20)


class TestSightingType(unittest.TestCase):
    def test_values(self):
        self.assertEqual(SightingType.TRUE_POSITIVE, 0)
        self.assertEqual(SightingType.FALSE_POSITIVE, 1)
        self.assertEqual(SightingType.EXPIRATION, 2)


class TestSyncDirection(unittest.TestCase):
    def test_values(self):
        self.assertEqual(SyncDirection.MISP_TO_TSUNAMI, "misp_to_tsunami")
        self.assertEqual(SyncDirection.TSUNAMI_TO_MISP, "tsunami_to_misp")
        self.assertEqual(SyncDirection.BIDIRECTIONAL, "bidirectional")


class TestSyncStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(SyncStatus.SYNCED, "synced")
        self.assertEqual(SyncStatus.PENDING, "pending")
        self.assertEqual(SyncStatus.FAILED, "failed")
        self.assertEqual(SyncStatus.CONFLICT, "conflict")


# ===========================================================================
# Data Class Tests
# ===========================================================================

class TestMISPAttribute(unittest.TestCase):
    def test_default_creation(self):
        attr = MISPAttribute()
        self.assertEqual(attr.type, "")
        self.assertEqual(attr.category, "Other")
        self.assertTrue(attr.to_ids)
        self.assertFalse(attr.disable_correlation)

    def test_creation_with_values(self):
        attr = MISPAttribute(type="ip-dst", value="1.2.3.4", category="Network activity")
        self.assertEqual(attr.type, "ip-dst")
        self.assertEqual(attr.value, "1.2.3.4")

    def test_to_create_dict(self):
        attr = MISPAttribute(type="sha256", value="abc123", comment="test hash")
        d = attr.to_create_dict()
        self.assertEqual(d["type"], "sha256")
        self.assertEqual(d["value"], "abc123")
        self.assertEqual(d["comment"], "test hash")
        self.assertNotIn("id", d)

    def test_to_create_dict_no_optional(self):
        attr = MISPAttribute(type="domain", value="evil.com")
        d = attr.to_create_dict()
        self.assertNotIn("comment", d)
        self.assertNotIn("first_seen", d)

    def test_to_dict(self):
        attr = MISPAttribute(type="url", value="http://bad.com", id="100")
        d = attr.to_dict()
        self.assertEqual(d["id"], "100")
        self.assertIn("uuid", d)

    def test_from_dict(self):
        data = {
            "type": "ip-src",
            "value": "10.0.0.1",
            "category": "Network activity",
            "to_ids": "1",
            "id": "42",
            "event_id": "5",
            "Tag": [{"name": "tlp:green"}],
        }
        attr = MISPAttribute.from_dict(data)
        self.assertEqual(attr.type, "ip-src")
        self.assertEqual(attr.value, "10.0.0.1")
        self.assertTrue(attr.to_ids)
        self.assertEqual(attr.id, "42")
        self.assertEqual(len(attr.tags), 1)

    def test_from_dict_with_attribute_key(self):
        data = {"Attribute": {"type": "domain", "value": "test.com"}}
        attr = MISPAttribute.from_dict(data)
        self.assertEqual(attr.type, "domain")

    def test_roundtrip(self):
        original = MISPAttribute(type="md5", value="abc", id="1", event_id="2")
        d = original.to_dict()
        restored = MISPAttribute.from_dict(d)
        self.assertEqual(restored.type, original.type)
        self.assertEqual(restored.value, original.value)


class TestMISPEvent(unittest.TestCase):
    def test_default_creation(self):
        ev = MISPEvent()
        self.assertEqual(ev.info, "")
        self.assertEqual(ev.threat_level_id, ThreatLevel.UNDEFINED)
        self.assertFalse(ev.published)

    def test_creation_with_values(self):
        ev = MISPEvent(info="Test event", threat_level_id=ThreatLevel.HIGH.value)
        self.assertEqual(ev.info, "Test event")
        self.assertEqual(ev.threat_level_id, 1)

    def test_to_create_dict(self):
        ev = MISPEvent(info="Incident", threat_level_id=2, date="2024-01-01")
        d = ev.to_create_dict()
        self.assertEqual(d["info"], "Incident")
        self.assertEqual(d["threat_level_id"], "2")
        self.assertEqual(d["date"], "2024-01-01")
        self.assertNotIn("id", d)

    def test_to_dict(self):
        ev = MISPEvent(info="Test", id="10", uuid="abc-123")
        d = ev.to_dict()
        self.assertEqual(d["id"], "10")
        self.assertEqual(d["uuid"], "abc-123")
        self.assertIn("Tag", d)
        self.assertIn("Attribute", d)

    def test_from_dict(self):
        data = {
            "Event": {
                "info": "Phishing campaign",
                "threat_level_id": "1",
                "analysis": "2",
                "published": "1",
                "id": "99",
                "Attribute": [{"type": "domain", "value": "evil.com"}],
                "Tag": [{"name": "tlp:amber"}],
                "Galaxy": [{"name": "threat-actor"}],
            }
        }
        ev = MISPEvent.from_dict(data)
        self.assertEqual(ev.info, "Phishing campaign")
        self.assertEqual(ev.threat_level_id, 1)
        self.assertTrue(ev.published)
        self.assertEqual(len(ev.attributes), 1)
        self.assertEqual(len(ev.tags), 1)
        self.assertEqual(len(ev.galaxies), 1)

    def test_from_dict_published_variants(self):
        for val, expected in [("true", True), ("True", True), (1, True), (0, False), (False, False)]:
            ev = MISPEvent.from_dict({"published": val})
            self.assertEqual(ev.published, expected, f"Failed for {val}")

    def test_roundtrip(self):
        original = MISPEvent(info="Test", id="5", threat_level_id=2)
        d = original.to_dict()
        restored = MISPEvent.from_dict(d)
        self.assertEqual(restored.info, original.info)
        self.assertEqual(restored.threat_level_id, original.threat_level_id)


class TestMISPSighting(unittest.TestCase):
    def test_default_creation(self):
        s = MISPSighting()
        self.assertEqual(s.type, SightingType.TRUE_POSITIVE)
        self.assertEqual(s.source, "TSUNAMI-SOC")

    def test_to_create_dict(self):
        s = MISPSighting(attribute_id="42", type=SightingType.FALSE_POSITIVE.value)
        d = s.to_create_dict()
        self.assertEqual(d["type"], "1")
        self.assertEqual(d["id"], "42")

    def test_to_dict(self):
        s = MISPSighting(attribute_id="1", id="10", uuid="abc")
        d = s.to_dict()
        self.assertEqual(d["sighting_id"], "10")
        self.assertEqual(d["sighting_uuid"], "abc")

    def test_from_dict(self):
        data = {"Sighting": {"attribute_id": "5", "type": "1", "source": "ext"}}
        s = MISPSighting.from_dict(data)
        self.assertEqual(s.attribute_id, "5")
        self.assertEqual(s.type, 1)
        self.assertEqual(s.source, "ext")

    def test_roundtrip(self):
        original = MISPSighting(attribute_id="7", type=2, source="test")
        d = original.to_dict()
        restored = MISPSighting.from_dict(d)
        self.assertEqual(restored.type, original.type)


class TestMISPFeed(unittest.TestCase):
    def test_default_creation(self):
        f = MISPFeed()
        self.assertTrue(f.enabled)
        self.assertEqual(f.source_format, "misp")

    def test_to_create_dict(self):
        f = MISPFeed(name="CIRCL", provider="CIRCL", url="https://circl.lu/feed")
        d = f.to_create_dict()
        self.assertEqual(d["name"], "CIRCL")
        self.assertEqual(d["url"], "https://circl.lu/feed")
        self.assertNotIn("id", d)

    def test_to_dict(self):
        f = MISPFeed(name="Test", id="1")
        d = f.to_dict()
        self.assertEqual(d["id"], "1")

    def test_from_dict(self):
        data = {"Feed": {"name": "OSINT", "url": "https://osint.feed", "enabled": "1", "id": "5"}}
        f = MISPFeed.from_dict(data)
        self.assertEqual(f.name, "OSINT")
        self.assertTrue(f.enabled)
        self.assertEqual(f.id, "5")

    def test_roundtrip(self):
        original = MISPFeed(name="Test", url="http://x.com", id="2")
        d = original.to_dict()
        restored = MISPFeed.from_dict(d)
        self.assertEqual(restored.name, original.name)


class TestMISPGalaxyCluster(unittest.TestCase):
    def test_default_creation(self):
        c = MISPGalaxyCluster()
        self.assertEqual(c.type, "")
        self.assertEqual(c.source, "")

    def test_to_dict(self):
        c = MISPGalaxyCluster(type="threat-actor", value="APT28", uuid="abc")
        d = c.to_dict()
        self.assertEqual(d["type"], "threat-actor")
        self.assertEqual(d["value"], "APT28")
        self.assertIn("tag_name", d)

    def test_tag_name_auto_generated(self):
        c = MISPGalaxyCluster(type="tool", value="Mimikatz")
        d = c.to_dict()
        self.assertEqual(d["tag_name"], 'misp-galaxy:tool="Mimikatz"')

    def test_from_dict(self):
        data = {"GalaxyCluster": {"type": "malware", "value": "Emotet", "uuid": "x"}}
        c = MISPGalaxyCluster.from_dict(data)
        self.assertEqual(c.type, "malware")
        self.assertEqual(c.value, "Emotet")

    def test_roundtrip(self):
        original = MISPGalaxyCluster(type="sector", value="Finance", uuid="123")
        d = original.to_dict()
        restored = MISPGalaxyCluster.from_dict(d)
        self.assertEqual(restored.type, original.type)
        self.assertEqual(restored.value, original.value)


class TestSyncRecord(unittest.TestCase):
    def test_default_creation(self):
        r = SyncRecord()
        self.assertEqual(r.entity_type, "event")
        self.assertEqual(r.status, SyncStatus.SYNCED.value)

    def test_to_dict(self):
        r = SyncRecord(tsunami_id="t1", misp_id="m1")
        d = r.to_dict()
        self.assertEqual(d["tsunami_id"], "t1")
        self.assertEqual(d["misp_id"], "m1")
        self.assertIn("last_synced", d)

    def test_from_dict(self):
        data = {"tsunami_id": "a", "misp_id": "b", "entity_type": "attribute",
                "status": "failed", "error_message": "timeout"}
        r = SyncRecord.from_dict(data)
        self.assertEqual(r.tsunami_id, "a")
        self.assertEqual(r.status, "failed")
        self.assertEqual(r.error_message, "timeout")

    def test_roundtrip(self):
        original = SyncRecord(tsunami_id="x", misp_id="y", entity_type="event")
        d = original.to_dict()
        restored = SyncRecord.from_dict(d)
        self.assertEqual(restored.tsunami_id, original.tsunami_id)


# ===========================================================================
# Mapping Tests
# ===========================================================================

class TestMappings(unittest.TestCase):
    def test_tsunami_to_misp_type_map(self):
        self.assertEqual(TSUNAMI_TO_MISP_TYPE_MAP["ip_address"], "ip-dst")
        self.assertEqual(TSUNAMI_TO_MISP_TYPE_MAP["sha256"], "sha256")
        self.assertEqual(TSUNAMI_TO_MISP_TYPE_MAP["domain"], "domain")
        self.assertEqual(TSUNAMI_TO_MISP_TYPE_MAP["yara"], "yara")

    def test_reverse_map(self):
        for k, v in TSUNAMI_TO_MISP_TYPE_MAP.items():
            self.assertIn(v, MISP_TO_TSUNAMI_TYPE_MAP)

    def test_severity_mapping(self):
        self.assertEqual(TSUNAMI_SEVERITY_TO_THREAT_LEVEL["critical"], ThreatLevel.HIGH)
        self.assertEqual(TSUNAMI_SEVERITY_TO_THREAT_LEVEL["medium"], ThreatLevel.MEDIUM)
        self.assertEqual(TSUNAMI_SEVERITY_TO_THREAT_LEVEL["low"], ThreatLevel.LOW)

    def test_reverse_severity(self):
        self.assertEqual(THREAT_LEVEL_TO_TSUNAMI_SEVERITY[ThreatLevel.HIGH], "high")
        self.assertEqual(THREAT_LEVEL_TO_TSUNAMI_SEVERITY[ThreatLevel.MEDIUM], "medium")

    def test_tlp_tag_map(self):
        self.assertEqual(TLP_TAG_MAP["TLP:CLEAR"], Distribution.ALL_COMMUNITIES)
        self.assertEqual(TLP_TAG_MAP["TLP:RED"], Distribution.YOUR_ORGANISATION_ONLY)
        self.assertEqual(TLP_TAG_MAP["TLP:GREEN"], Distribution.CONNECTED_COMMUNITIES)


# ===========================================================================
# MISPClient Tests
# ===========================================================================

class TestMISPClient(unittest.TestCase):
    def test_init(self):
        client = MISPClient(url="https://misp.test", api_key="key123")
        self.assertEqual(client.url, "https://misp.test")
        self.assertEqual(client.api_key, "key123")

    def test_init_trailing_slash(self):
        client = MISPClient(url="https://misp.test/")
        self.assertEqual(client.url, "https://misp.test")

    def test_init_from_env(self):
        with patch.dict(os.environ, {"MISP_URL": "https://env.misp", "MISP_API_KEY": "envkey"}):
            client = MISPClient()
            self.assertEqual(client.url, "https://env.misp")
            self.assertEqual(client.api_key, "envkey")

    def test_get_session_no_requests(self):
        client = MISPClient()
        original_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "requests":
                raise ImportError("no requests")
            return original_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=mock_import):
            client._session = None
            result = client._get_session()
            self.assertIsNone(result)

    def test_request_no_session(self):
        client = MISPClient()
        client._get_session = MagicMock(return_value=None)
        result = client._request("get", "/test")
        self.assertIn("error", result)

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_request_success(self, mock_session_fn):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"ok": true}'
        mock_resp.json.return_value = {"ok": True}
        mock_session.get.return_value = mock_resp
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test")
        result = client._request("get", "/test")
        self.assertEqual(result, {"ok": True})

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_request_server_error_retries(self, mock_session_fn):
        mock_session = MagicMock()
        mock_resp_500 = MagicMock()
        mock_resp_500.status_code = 500
        mock_resp_ok = MagicMock()
        mock_resp_ok.status_code = 200
        mock_resp_ok.content = b'{"ok": true}'
        mock_resp_ok.json.return_value = {"ok": True}
        mock_session.get.side_effect = [mock_resp_500, mock_resp_ok]
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test")
        result = client._request("get", "/test")
        self.assertEqual(result, {"ok": True})

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_request_client_error(self, mock_session_fn):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.json.return_value = {"message": "Not found"}
        mock_session.get.return_value = mock_resp
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test")
        result = client._request("get", "/test")
        self.assertEqual(result["error"], "Not found")

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_request_empty_response(self, mock_session_fn):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b''
        mock_session.get.return_value = mock_resp
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test")
        result = client._request("get", "/test")
        self.assertEqual(result, {"success": True})

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_request_json_parse_error(self, mock_session_fn):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'not json'
        mock_resp.json.side_effect = ValueError("bad json")
        mock_resp.text = "not json"
        mock_session.get.return_value = mock_resp
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test")
        result = client._request("get", "/test")
        self.assertEqual(result["raw"], "not json")

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_request_exception_retries(self, mock_session_fn):
        mock_session = MagicMock()
        mock_session.get.side_effect = ConnectionError("refused")
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test", max_retries=2)
        result = client._request("get", "/test")
        self.assertIn("error", result)
        self.assertEqual(mock_session.get.call_count, 2)

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_health_check_healthy(self, mock_session_fn):
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"version": "2.4.170"}'
        mock_resp.json.return_value = {"version": "2.4.170"}
        mock_session.get.return_value = mock_resp
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test")
        result = client.health_check()
        self.assertTrue(result["healthy"])

    @patch("modules.threat_sharing.misp_connector.MISPClient._get_session")
    def test_health_check_unhealthy(self, mock_session_fn):
        mock_session = MagicMock()
        mock_session.get.side_effect = ConnectionError("down")
        mock_session_fn.return_value = mock_session
        client = MISPClient(url="https://misp.test", max_retries=1)
        result = client.health_check()
        self.assertFalse(result["healthy"])

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_create_event(self, mock_req):
        mock_req.return_value = {"Event": {"id": "1", "info": "Test"}}
        client = MISPClient()
        result = client.create_event({"info": "Test"})
        mock_req.assert_called_with("post", "/events/add", {"Event": {"info": "Test"}})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_get_event(self, mock_req):
        mock_req.return_value = {"Event": {"id": "5"}}
        client = MISPClient()
        client.get_event("5")
        mock_req.assert_called_with("get", "/events/view/5")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_update_event(self, mock_req):
        mock_req.return_value = {"Event": {"id": "5"}}
        client = MISPClient()
        client.update_event("5", {"info": "Updated"})
        mock_req.assert_called_with("put", "/events/edit/5", {"Event": {"info": "Updated"}})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_delete_event(self, mock_req):
        mock_req.return_value = {"success": True}
        client = MISPClient()
        client.delete_event("5")
        mock_req.assert_called_with("delete", "/events/delete/5")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_publish_event(self, mock_req):
        mock_req.return_value = {"success": True}
        client = MISPClient()
        client.publish_event("5")
        mock_req.assert_called_with("post", "/events/publish/5")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_search_events(self, mock_req):
        mock_req.return_value = {"response": []}
        client = MISPClient()
        client.search_events({"type": "ip-src"})
        mock_req.assert_called_with("post", "/events/restSearch", {"request": {"type": "ip-src"}})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_add_attribute(self, mock_req):
        mock_req.return_value = {"Attribute": {"id": "10"}}
        client = MISPClient()
        client.add_attribute("1", {"type": "ip-dst", "value": "1.2.3.4"})
        mock_req.assert_called_with("post", "/attributes/add/1",
                                    {"Attribute": {"type": "ip-dst", "value": "1.2.3.4"}})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_get_attribute(self, mock_req):
        mock_req.return_value = {"Attribute": {"id": "10"}}
        client = MISPClient()
        client.get_attribute("10")
        mock_req.assert_called_with("get", "/attributes/view/10")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_search_attributes(self, mock_req):
        mock_req.return_value = {"response": {"Attribute": []}}
        client = MISPClient()
        client.search_attributes({"value": "1.2.3.4"})
        mock_req.assert_called_with("post", "/attributes/restSearch",
                                    {"request": {"value": "1.2.3.4"}})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_add_tag_to_event(self, mock_req):
        mock_req.return_value = {"success": True}
        client = MISPClient()
        client.add_tag_to_event("1", "tlp:green")
        mock_req.assert_called_with("post", "/events/addTag",
                                    {"event": "1", "tag": "tlp:green"})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_add_sighting(self, mock_req):
        mock_req.return_value = {"Sighting": {"id": "1"}}
        client = MISPClient()
        client.add_sighting({"id": "42", "type": "0"})
        mock_req.assert_called_with("post", "/sightings/add", {"id": "42", "type": "0"})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_list_feeds(self, mock_req):
        mock_req.return_value = [{"Feed": {"id": "1"}}]
        client = MISPClient()
        client.list_feeds()
        mock_req.assert_called_with("get", "/feeds")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_add_feed(self, mock_req):
        mock_req.return_value = {"Feed": {"id": "1"}}
        client = MISPClient()
        client.add_feed({"name": "Test", "url": "http://x"})
        mock_req.assert_called_with("post", "/feeds/add",
                                    {"Feed": {"name": "Test", "url": "http://x"}})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_enable_feed(self, mock_req):
        mock_req.return_value = {"success": True}
        client = MISPClient()
        client.enable_feed("1")
        mock_req.assert_called_with("post", "/feeds/enable/1")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_disable_feed(self, mock_req):
        mock_req.return_value = {"success": True}
        client = MISPClient()
        client.disable_feed("1")
        mock_req.assert_called_with("post", "/feeds/disable/1")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_list_galaxies(self, mock_req):
        mock_req.return_value = [{"Galaxy": {"id": "1"}}]
        client = MISPClient()
        client.list_galaxies()
        mock_req.assert_called_with("get", "/galaxies")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_attach_galaxy_cluster(self, mock_req):
        mock_req.return_value = {"success": True}
        client = MISPClient()
        client.attach_galaxy_cluster("1", "abc")
        mock_req.assert_called_with("post", "/galaxies/attachCluster/1/event",
                                    {"Galaxy": {"target_id": "abc"}})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_list_warninglists(self, mock_req):
        mock_req.return_value = {"Warninglists": []}
        client = MISPClient()
        client.list_warninglists()
        mock_req.assert_called_with("get", "/warninglists")

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_check_warninglist(self, mock_req):
        mock_req.return_value = {}
        client = MISPClient()
        client.check_warninglist(["8.8.8.8"])
        mock_req.assert_called_with("post", "/warninglists/checkValue", {"value": ["8.8.8.8"]})

    @patch("modules.threat_sharing.misp_connector.MISPClient._request")
    def test_get_correlations(self, mock_req):
        mock_req.return_value = {}
        client = MISPClient()
        client.get_correlations("5")
        mock_req.assert_called_with("get", "/events/view/5/includeCorrelations:1")


# ===========================================================================
# SyncStore Tests
# ===========================================================================

class TestSyncStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_sync.db")
        self.store = SyncStore(db_path=self.db_path)

    def test_init_creates_db(self):
        self.assertTrue(os.path.exists(self.db_path))

    def test_default_path(self):
        with patch.dict(os.environ, {"MISP_SYNC_DB": self.db_path}):
            store = SyncStore()
            self.assertEqual(store.db_path, self.db_path)

    def test_save_and_get_by_tsunami_id(self):
        rec = SyncRecord(tsunami_id="t1", misp_id="m1", entity_type="event")
        self.store.save_record(rec)
        result = self.store.get_by_tsunami_id("t1")
        self.assertIsNotNone(result)
        self.assertEqual(result.misp_id, "m1")

    def test_get_by_tsunami_id_not_found(self):
        result = self.store.get_by_tsunami_id("nonexistent")
        self.assertIsNone(result)

    def test_get_by_tsunami_id_with_type(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1", entity_type="event"))
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m2", entity_type="attribute"))
        result = self.store.get_by_tsunami_id("t1", "attribute")
        self.assertEqual(result.misp_id, "m2")

    def test_get_by_misp_id(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1"))
        result = self.store.get_by_misp_id("m1")
        self.assertIsNotNone(result)
        self.assertEqual(result.tsunami_id, "t1")

    def test_get_by_misp_id_not_found(self):
        result = self.store.get_by_misp_id("nonexistent")
        self.assertIsNone(result)

    def test_get_by_misp_id_with_type(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1", entity_type="event"))
        result = self.store.get_by_misp_id("m1", "event")
        self.assertIsNotNone(result)
        result2 = self.store.get_by_misp_id("m1", "attribute")
        self.assertIsNone(result2)

    def test_list_records(self):
        for i in range(5):
            self.store.save_record(SyncRecord(tsunami_id=f"t{i}", misp_id=f"m{i}"))
        records = self.store.list_records()
        self.assertEqual(len(records), 5)

    def test_list_records_filter_type(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1", entity_type="event"))
        self.store.save_record(SyncRecord(tsunami_id="t2", misp_id="m2", entity_type="attribute"))
        records = self.store.list_records(entity_type="event")
        self.assertEqual(len(records), 1)

    def test_list_records_filter_status(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1", status="synced"))
        self.store.save_record(SyncRecord(tsunami_id="t2", misp_id="m2", status="failed"))
        records = self.store.list_records(status="failed")
        self.assertEqual(len(records), 1)

    def test_list_records_pagination(self):
        for i in range(10):
            self.store.save_record(SyncRecord(tsunami_id=f"t{i}", misp_id=f"m{i}"))
        page1 = self.store.list_records(limit=3, offset=0)
        self.assertEqual(len(page1), 3)
        page2 = self.store.list_records(limit=3, offset=3)
        self.assertEqual(len(page2), 3)

    def test_delete_record(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1"))
        self.assertTrue(self.store.delete_record("t1"))
        self.assertIsNone(self.store.get_by_tsunami_id("t1"))

    def test_delete_record_not_found(self):
        self.assertFalse(self.store.delete_record("nonexistent"))

    def test_count_records(self):
        for i in range(4):
            self.store.save_record(SyncRecord(
                tsunami_id=f"t{i}", misp_id=f"m{i}",
                status="synced" if i < 3 else "failed"
            ))
        self.assertEqual(self.store.count_records(), 4)
        self.assertEqual(self.store.count_records(status="synced"), 3)
        self.assertEqual(self.store.count_records(status="failed"), 1)

    def test_upsert(self):
        self.store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1", status="pending"))
        self.store.upsert_record(SyncRecord(tsunami_id="t1", misp_id="m1_updated", status="synced"))
        result = self.store.get_by_tsunami_id("t1")
        self.assertEqual(result.misp_id, "m1_updated")
        self.assertEqual(result.status, "synced")

    def test_thread_safety(self):
        errors = []
        def writer(n):
            try:
                for i in range(20):
                    self.store.save_record(SyncRecord(
                        tsunami_id=f"thread{n}_t{i}", misp_id=f"thread{n}_m{i}"
                    ))
            except Exception as e:
                errors.append(e)
        threads = [threading.Thread(target=writer, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 0)
        self.assertEqual(self.store.count_records(), 60)


# ===========================================================================
# MISPConnector Tests
# ===========================================================================

class TestMISPConnector(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock(spec=MISPClient)
        self.tmpdir = tempfile.mkdtemp()
        self.sync_store = SyncStore(db_path=os.path.join(self.tmpdir, "test.db"))
        self.connector = MISPConnector(client=self.mock_client, sync_store=self.sync_store)

    # -- Health --
    def test_health_check(self):
        self.mock_client.health_check.return_value = {"healthy": True, "version": "2.4"}
        result = self.connector.health_check()
        self.assertTrue(result["healthy"])

    # -- Events --
    def test_create_event_success(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test", "uuid": "abc"}
        }
        event = MISPEvent(info="Test")
        result = self.connector.create_event(event)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, "1")

    def test_create_event_failure(self):
        self.mock_client.create_event.return_value = {"error": "forbidden"}
        result = self.connector.create_event(MISPEvent(info="Test"))
        self.assertIsNone(result)

    def test_create_event_callback(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        cb = MagicMock()
        self.connector.register_callback("event_created", cb)
        self.connector.create_event(MISPEvent(info="Test"))
        cb.assert_called_once()

    def test_get_event_success(self):
        self.mock_client.get_event.return_value = {
            "Event": {"id": "5", "info": "Found"}
        }
        result = self.connector.get_event("5")
        self.assertIsNotNone(result)
        self.assertEqual(result.info, "Found")

    def test_get_event_not_found(self):
        self.mock_client.get_event.return_value = {"error": "Not found"}
        result = self.connector.get_event("999")
        self.assertIsNone(result)

    def test_update_event(self):
        self.mock_client.update_event.return_value = {
            "Event": {"id": "5", "info": "Updated"}
        }
        result = self.connector.update_event("5", {"info": "Updated"})
        self.assertIsNotNone(result)
        self.assertEqual(result.info, "Updated")

    def test_update_event_failure(self):
        self.mock_client.update_event.return_value = {"error": "fail"}
        result = self.connector.update_event("5", {})
        self.assertIsNone(result)

    def test_delete_event(self):
        self.mock_client.delete_event.return_value = {"success": True}
        self.assertTrue(self.connector.delete_event("5"))

    def test_publish_event(self):
        self.mock_client.publish_event.return_value = {"success": True}
        self.assertTrue(self.connector.publish_event("5"))

    def test_search_events(self):
        self.mock_client.search_events.return_value = {
            "response": [
                {"Event": {"id": "1", "info": "A"}},
                {"Event": {"id": "2", "info": "B"}},
            ]
        }
        results = self.connector.search_events({"type": "ip-src"})
        self.assertEqual(len(results), 2)

    def test_search_events_error(self):
        self.mock_client.search_events.return_value = {"error": "fail"}
        results = self.connector.search_events({})
        self.assertEqual(len(results), 0)

    # -- Attributes --
    def test_add_attribute(self):
        self.mock_client.add_attribute.return_value = {
            "Attribute": {"id": "10", "type": "ip-dst", "value": "1.2.3.4"}
        }
        attr = MISPAttribute(type="ip-dst", value="1.2.3.4")
        result = self.connector.add_attribute("1", attr)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, "10")

    def test_add_attribute_failure(self):
        self.mock_client.add_attribute.return_value = {"error": "fail"}
        result = self.connector.add_attribute("1", MISPAttribute())
        self.assertIsNone(result)

    def test_get_attribute(self):
        self.mock_client.get_attribute.return_value = {
            "Attribute": {"id": "10", "type": "domain", "value": "evil.com"}
        }
        result = self.connector.get_attribute("10")
        self.assertIsNotNone(result)

    def test_update_attribute(self):
        self.mock_client.update_attribute.return_value = {
            "Attribute": {"id": "10", "value": "updated"}
        }
        result = self.connector.update_attribute("10", {"value": "updated"})
        self.assertIsNotNone(result)

    def test_delete_attribute(self):
        self.mock_client.delete_attribute.return_value = {"success": True}
        self.assertTrue(self.connector.delete_attribute("10"))

    def test_search_attributes(self):
        self.mock_client.search_attributes.return_value = {
            "response": {"Attribute": [
                {"type": "ip-src", "value": "1.1.1.1"},
            ]}
        }
        results = self.connector.search_attributes({"value": "1.1.1.1"})
        self.assertEqual(len(results), 1)

    def test_search_attributes_list_response(self):
        self.mock_client.search_attributes.return_value = {
            "response": [{"type": "domain", "value": "x.com"}]
        }
        results = self.connector.search_attributes({})
        self.assertEqual(len(results), 1)

    # -- Tags --
    def test_add_tag_to_event(self):
        self.mock_client.add_tag_to_event.return_value = {"success": True}
        self.assertTrue(self.connector.add_tag_to_event("1", "tlp:green"))

    def test_remove_tag_from_event(self):
        self.mock_client.remove_tag_from_event.return_value = {"success": True}
        self.assertTrue(self.connector.remove_tag_from_event("1", "tlp:green"))

    def test_add_tag_to_attribute(self):
        self.mock_client.add_tag_to_attribute.return_value = {"success": True}
        self.assertTrue(self.connector.add_tag_to_attribute("10", "malware:ransomware"))

    def test_get_all_tags(self):
        self.mock_client.get_all_tags.return_value = {
            "Tag": [{"name": "tlp:green"}, {"name": "tlp:red"}]
        }
        tags = self.connector.get_all_tags()
        self.assertEqual(len(tags), 2)

    def test_get_all_tags_error(self):
        self.mock_client.get_all_tags.return_value = {"error": "fail"}
        tags = self.connector.get_all_tags()
        self.assertEqual(len(tags), 0)

    # -- Sightings --
    def test_add_sighting(self):
        self.mock_client.add_sighting.return_value = {
            "Sighting": {"id": "1", "type": "0"}
        }
        s = MISPSighting(attribute_id="42")
        result = self.connector.add_sighting(s)
        self.assertIsNotNone(result)

    def test_add_sighting_failure(self):
        self.mock_client.add_sighting.return_value = {"error": "fail"}
        result = self.connector.add_sighting(MISPSighting())
        self.assertIsNone(result)

    def test_list_sightings(self):
        self.mock_client.list_sightings.return_value = [
            {"Sighting": {"id": "1"}}, {"Sighting": {"id": "2"}}
        ]
        results = self.connector.list_sightings("42")
        self.assertEqual(len(results), 2)

    def test_list_sightings_error(self):
        self.mock_client.list_sightings.return_value = {"error": "fail"}
        results = self.connector.list_sightings("42")
        self.assertEqual(len(results), 0)

    # -- Feeds --
    def test_list_feeds(self):
        self.mock_client.list_feeds.return_value = [
            {"Feed": {"id": "1", "name": "CIRCL"}}
        ]
        feeds = self.connector.list_feeds()
        self.assertEqual(len(feeds), 1)

    def test_list_feeds_error(self):
        self.mock_client.list_feeds.return_value = {"error": "fail"}
        self.assertEqual(len(self.connector.list_feeds()), 0)

    def test_get_feed(self):
        self.mock_client.get_feed.return_value = {
            "Feed": {"id": "1", "name": "Test"}
        }
        result = self.connector.get_feed("1")
        self.assertIsNotNone(result)

    def test_add_feed(self):
        self.mock_client.add_feed.return_value = {
            "Feed": {"id": "2", "name": "New"}
        }
        feed = MISPFeed(name="New", url="http://x")
        result = self.connector.add_feed(feed)
        self.assertIsNotNone(result)

    def test_enable_feed(self):
        self.mock_client.enable_feed.return_value = {"success": True}
        self.assertTrue(self.connector.enable_feed("1"))

    def test_disable_feed(self):
        self.mock_client.disable_feed.return_value = {"success": True}
        self.assertTrue(self.connector.disable_feed("1"))

    def test_fetch_from_feed(self):
        self.mock_client.fetch_from_feed.return_value = {"result": "ok"}
        result = self.connector.fetch_from_feed("1")
        self.assertEqual(result["result"], "ok")

    # -- Galaxies --
    def test_list_galaxies(self):
        self.mock_client.list_galaxies.return_value = [{"id": "1"}, {"id": "2"}]
        result = self.connector.list_galaxies()
        self.assertEqual(len(result), 2)

    def test_list_galaxies_error(self):
        self.mock_client.list_galaxies.return_value = {"error": "fail"}
        self.assertEqual(len(self.connector.list_galaxies()), 0)

    def test_get_galaxy(self):
        self.mock_client.get_galaxy.return_value = {"Galaxy": {"id": "1"}}
        result = self.connector.get_galaxy("1")
        self.assertIsNotNone(result)

    def test_get_galaxy_not_found(self):
        self.mock_client.get_galaxy.return_value = {"error": "Not found"}
        self.assertIsNone(self.connector.get_galaxy("999"))

    def test_search_galaxy_clusters(self):
        self.mock_client.search_galaxy_clusters.return_value = {
            "response": [{"type": "threat-actor", "value": "APT28"}]
        }
        results = self.connector.search_galaxy_clusters({"value": "APT28"})
        self.assertEqual(len(results), 1)

    def test_attach_galaxy_cluster(self):
        self.mock_client.attach_galaxy_cluster.return_value = {"success": True}
        self.assertTrue(self.connector.attach_galaxy_cluster("1", "abc"))

    # -- Warninglists --
    def test_list_warninglists(self):
        self.mock_client.list_warninglists.return_value = {
            "Warninglists": [{"id": "1"}]
        }
        result = self.connector.list_warninglists()
        self.assertEqual(len(result), 1)

    def test_check_warninglist(self):
        self.mock_client.check_warninglist.return_value = {"matched": []}
        result = self.connector.check_warninglist(["8.8.8.8"])
        self.assertIn("matched", result)

    # -- Correlations --
    def test_get_correlations(self):
        self.mock_client.get_correlations.return_value = {"Event": {"id": "1"}}
        result = self.connector.get_correlations("1")
        self.assertIn("Event", result)

    # -- IOC Export --
    def test_export_iocs_success(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "100", "info": "Test Alert"}
        }
        self.mock_client.add_attribute.return_value = {
            "Attribute": {"id": "200", "type": "ip-dst", "value": "1.2.3.4"}
        }
        self.mock_client.add_tag_to_event.return_value = {"success": True}
        alert = {
            "alert_id": "ALERT-001",
            "title": "Test Alert",
            "severity": "high",
            "tlp": "TLP:GREEN",
            "iocs": [
                {"type": "ip_address", "value": "1.2.3.4"},
                {"type": "domain", "value": "evil.com"},
            ],
        }
        result = self.connector.export_iocs_to_misp(alert)
        self.assertIsNotNone(result)
        self.assertEqual(result.id, "100")
        rec = self.sync_store.get_by_tsunami_id("ALERT-001")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.status, SyncStatus.SYNCED.value)

    def test_export_iocs_already_synced(self):
        self.sync_store.save_record(SyncRecord(
            tsunami_id="ALERT-001", misp_id="100",
            status=SyncStatus.SYNCED.value,
        ))
        self.mock_client.get_event.return_value = {
            "Event": {"id": "100", "info": "Existing"}
        }
        alert = {"alert_id": "ALERT-001", "title": "Test"}
        result = self.connector.export_iocs_to_misp(alert)
        self.mock_client.create_event.assert_not_called()

    def test_export_iocs_no_alert_id(self):
        result = self.connector.export_iocs_to_misp({})
        self.assertIsNone(result)

    def test_export_iocs_creation_failure(self):
        self.mock_client.create_event.return_value = {"error": "fail"}
        alert = {"alert_id": "ALERT-002", "title": "Fail", "severity": "low"}
        result = self.connector.export_iocs_to_misp(alert)
        self.assertIsNone(result)
        rec = self.sync_store.get_by_tsunami_id("ALERT-002")
        self.assertEqual(rec.status, SyncStatus.FAILED.value)

    def test_export_iocs_severity_mapping(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        for sev, expected_tl in [("critical", 1), ("high", 1), ("medium", 2), ("low", 3)]:
            alert = {"id": f"a-{sev}", "title": "Test", "severity": sev}
            self.connector.export_iocs_to_misp(alert)
            call_data = self.mock_client.create_event.call_args[0][0]
            self.assertEqual(call_data["threat_level_id"], str(expected_tl))

    def test_export_iocs_with_publish(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "50", "info": "Published"}
        }
        self.mock_client.publish_event.return_value = {"success": True}
        alert = {"alert_id": "PUB-001", "title": "Publish Test"}
        self.connector.export_iocs_to_misp(alert, publish=True)
        self.mock_client.publish_event.assert_called_once_with("50")

    def test_export_iocs_with_indicators_key(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        self.mock_client.add_attribute.return_value = {
            "Attribute": {"id": "1"}
        }
        alert = {
            "alert_id": "IND-001",
            "title": "Indicators",
            "indicators": [{"type": "sha256", "value": "abc"}],
        }
        self.connector.export_iocs_to_misp(alert)
        self.mock_client.add_attribute.assert_called_once()

    def test_export_iocs_callback(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        cb = MagicMock()
        self.connector.register_callback("ioc_exported", cb)
        alert = {"alert_id": "CB-001", "title": "Test"}
        self.connector.export_iocs_to_misp(alert)
        cb.assert_called_once()

    def test_export_failure_callback(self):
        self.mock_client.create_event.return_value = {"error": "fail"}
        cb = MagicMock()
        self.connector.register_callback("sync_error", cb)
        alert = {"alert_id": "ERR-001", "title": "Fail"}
        self.connector.export_iocs_to_misp(alert)
        cb.assert_called_once()

    # -- IOC Import --
    def test_import_iocs_success(self):
        self.mock_client.get_event.return_value = {
            "Event": {
                "id": "50",
                "info": "External Threat",
                "Attribute": [
                    {"type": "ip-dst", "value": "9.8.7.6", "category": "Network activity",
                     "to_ids": True, "comment": "C2 server"},
                    {"type": "sha256", "value": "deadbeef", "category": "Payload delivery",
                     "to_ids": True, "comment": ""},
                ],
            }
        }
        iocs = self.connector.import_iocs_from_misp("50")
        self.assertEqual(len(iocs), 2)
        self.assertEqual(iocs[0]["source"], "MISP")
        self.assertEqual(iocs[0]["misp_event_id"], "50")

    def test_import_iocs_event_not_found(self):
        self.mock_client.get_event.return_value = {"error": "Not found"}
        iocs = self.connector.import_iocs_from_misp("999")
        self.assertEqual(len(iocs), 0)

    def test_import_iocs_type_mapping(self):
        self.mock_client.get_event.return_value = {
            "Event": {
                "id": "1",
                "info": "Test",
                "Attribute": [
                    {"type": "ip-src", "value": "10.0.0.1"},
                    {"type": "domain", "value": "evil.com"},
                ],
            }
        }
        iocs = self.connector.import_iocs_from_misp("1")
        types = {i["type"] for i in iocs}
        self.assertIn("ip_src", types)
        self.assertIn("domain", types)

    def test_import_iocs_callback(self):
        self.mock_client.get_event.return_value = {
            "Event": {"id": "1", "info": "Test", "Attribute": []}
        }
        cb = MagicMock()
        self.connector.register_callback("ioc_imported", cb)
        self.connector.import_iocs_from_misp("1")
        cb.assert_called_once()

    def test_import_iocs_saves_sync_record(self):
        self.mock_client.get_event.return_value = {
            "Event": {"id": "77", "info": "Test", "Attribute": []}
        }
        self.connector.import_iocs_from_misp("77")
        rec = self.sync_store.get_by_tsunami_id("import_77")
        self.assertIsNotNone(rec)
        self.assertEqual(rec.direction, SyncDirection.MISP_TO_TSUNAMI.value)

    # -- Sync Status --
    def test_get_sync_status(self):
        self.sync_store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1"))
        result = self.connector.get_sync_status("t1")
        self.assertIsNotNone(result)
        self.assertEqual(result["misp_id"], "m1")

    def test_get_sync_status_not_found(self):
        result = self.connector.get_sync_status("nonexistent")
        self.assertIsNone(result)

    def test_list_sync_records(self):
        self.sync_store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1"))
        records = self.connector.list_sync_records()
        self.assertEqual(len(records), 1)

    def test_get_sync_stats(self):
        self.sync_store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1", status="synced"))
        self.sync_store.save_record(SyncRecord(tsunami_id="t2", misp_id="m2", status="failed"))
        stats = self.connector.get_sync_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["synced"], 1)
        self.assertEqual(stats["failed"], 1)

    # -- Category Guessing --
    def test_guess_category_network(self):
        self.assertEqual(MISPConnector._guess_category("ip-dst"), "Network activity")
        self.assertEqual(MISPConnector._guess_category("domain"), "Network activity")
        self.assertEqual(MISPConnector._guess_category("url"), "Network activity")

    def test_guess_category_payload(self):
        self.assertEqual(MISPConnector._guess_category("sha256"), "Payload delivery")
        self.assertEqual(MISPConnector._guess_category("md5"), "Payload delivery")

    def test_guess_category_email(self):
        self.assertEqual(MISPConnector._guess_category("email-src"), "Payload delivery")

    def test_guess_category_rule(self):
        self.assertEqual(MISPConnector._guess_category("yara"), "Payload installation")

    def test_guess_category_vulnerability(self):
        self.assertEqual(MISPConnector._guess_category("vulnerability"), "External analysis")

    def test_guess_category_persistence(self):
        self.assertEqual(MISPConnector._guess_category("regkey"), "Persistence mechanism")

    def test_guess_category_other(self):
        self.assertEqual(MISPConnector._guess_category("unknown-type"), "Other")

    # -- Callbacks --
    def test_callback_exception_handled(self):
        def bad_cb(event_type, data):
            raise RuntimeError("oops")
        self.connector.register_callback("event_created", bad_cb)
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        result = self.connector.create_event(MISPEvent(info="Test"))
        self.assertIsNotNone(result)

    def test_multiple_callbacks(self):
        cb1 = MagicMock()
        cb2 = MagicMock()
        self.connector.register_callback("event_created", cb1)
        self.connector.register_callback("event_created", cb2)
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        self.connector.create_event(MISPEvent(info="Test"))
        cb1.assert_called_once()
        cb2.assert_called_once()


# ===========================================================================
# Blueprint Tests
# ===========================================================================

class TestMISPBlueprint(unittest.TestCase):
    def setUp(self):
        from flask import Flask
        self.mock_client = MagicMock(spec=MISPClient)
        self.tmpdir = tempfile.mkdtemp()
        self.sync_store = SyncStore(db_path=os.path.join(self.tmpdir, "bp_test.db"))
        self.connector = MISPConnector(client=self.mock_client, sync_store=self.sync_store)
        self.app = Flask(__name__)
        bp = create_misp_blueprint(connector=self.connector)
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()

    # -- Health --
    def test_health_healthy(self):
        self.mock_client.health_check.return_value = {"healthy": True, "version": "2.4"}
        resp = self.client.get("/api/v1/soc/misp/health")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.get_json()["healthy"])

    def test_health_unhealthy(self):
        self.mock_client.health_check.return_value = {"healthy": False, "error": "down"}
        resp = self.client.get("/api/v1/soc/misp/health")
        self.assertEqual(resp.status_code, 503)

    # -- Events --
    def test_create_event(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        resp = self.client.post("/api/v1/soc/misp/events",
                                json={"info": "Test Event"})
        self.assertEqual(resp.status_code, 201)

    def test_create_event_missing_info(self):
        resp = self.client.post("/api/v1/soc/misp/events", json={})
        self.assertEqual(resp.status_code, 400)

    def test_get_event(self):
        self.mock_client.get_event.return_value = {
            "Event": {"id": "5", "info": "Found"}
        }
        resp = self.client.get("/api/v1/soc/misp/events/5")
        self.assertEqual(resp.status_code, 200)

    def test_get_event_not_found(self):
        self.mock_client.get_event.return_value = {"error": "Not found"}
        resp = self.client.get("/api/v1/soc/misp/events/999")
        self.assertEqual(resp.status_code, 404)

    def test_update_event(self):
        self.mock_client.update_event.return_value = {
            "Event": {"id": "5", "info": "Updated"}
        }
        resp = self.client.put("/api/v1/soc/misp/events/5",
                               json={"info": "Updated"})
        self.assertEqual(resp.status_code, 200)

    def test_delete_event(self):
        self.mock_client.delete_event.return_value = {"success": True}
        resp = self.client.delete("/api/v1/soc/misp/events/5")
        self.assertEqual(resp.status_code, 200)

    def test_publish_event(self):
        self.mock_client.publish_event.return_value = {"success": True}
        resp = self.client.post("/api/v1/soc/misp/events/5/publish")
        self.assertEqual(resp.status_code, 200)

    def test_search_events(self):
        self.mock_client.search_events.return_value = {"response": []}
        resp = self.client.post("/api/v1/soc/misp/events/search", json={})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("events", resp.get_json())

    # -- Attributes --
    def test_add_attribute(self):
        self.mock_client.add_attribute.return_value = {
            "Attribute": {"id": "10", "type": "ip-dst", "value": "1.2.3.4"}
        }
        resp = self.client.post("/api/v1/soc/misp/events/1/attributes",
                                json={"type": "ip-dst", "value": "1.2.3.4"})
        self.assertEqual(resp.status_code, 201)

    def test_add_attribute_missing_fields(self):
        resp = self.client.post("/api/v1/soc/misp/events/1/attributes", json={})
        self.assertEqual(resp.status_code, 400)

    def test_get_attribute(self):
        self.mock_client.get_attribute.return_value = {
            "Attribute": {"id": "10", "type": "domain"}
        }
        resp = self.client.get("/api/v1/soc/misp/attributes/10")
        self.assertEqual(resp.status_code, 200)

    def test_get_attribute_not_found(self):
        self.mock_client.get_attribute.return_value = {"error": "not found"}
        resp = self.client.get("/api/v1/soc/misp/attributes/999")
        self.assertEqual(resp.status_code, 404)

    def test_update_attribute(self):
        self.mock_client.update_attribute.return_value = {
            "Attribute": {"id": "10", "value": "updated"}
        }
        resp = self.client.put("/api/v1/soc/misp/attributes/10",
                               json={"value": "updated"})
        self.assertEqual(resp.status_code, 200)

    def test_delete_attribute(self):
        self.mock_client.delete_attribute.return_value = {"success": True}
        resp = self.client.delete("/api/v1/soc/misp/attributes/10")
        self.assertEqual(resp.status_code, 200)

    def test_search_attributes(self):
        self.mock_client.search_attributes.return_value = {
            "response": {"Attribute": []}
        }
        resp = self.client.post("/api/v1/soc/misp/attributes/search", json={})
        self.assertEqual(resp.status_code, 200)

    # -- Tags --
    def test_add_tag_to_event(self):
        self.mock_client.add_tag_to_event.return_value = {"success": True}
        resp = self.client.post("/api/v1/soc/misp/events/1/tags",
                                json={"tag": "tlp:green"})
        self.assertEqual(resp.status_code, 200)

    def test_add_tag_missing(self):
        resp = self.client.post("/api/v1/soc/misp/events/1/tags", json={})
        self.assertEqual(resp.status_code, 400)

    def test_remove_tag_from_event(self):
        self.mock_client.remove_tag_from_event.return_value = {"success": True}
        resp = self.client.delete("/api/v1/soc/misp/events/1/tags",
                                  json={"tag": "tlp:green"})
        self.assertEqual(resp.status_code, 200)

    def test_remove_tag_missing(self):
        resp = self.client.delete("/api/v1/soc/misp/events/1/tags", json={})
        self.assertEqual(resp.status_code, 400)

    def test_list_tags(self):
        self.mock_client.get_all_tags.return_value = {"Tag": [{"name": "tlp:green"}]}
        resp = self.client.get("/api/v1/soc/misp/tags")
        self.assertEqual(resp.status_code, 200)

    # -- Sightings --
    def test_add_sighting(self):
        self.mock_client.add_sighting.return_value = {
            "Sighting": {"id": "1", "type": "0"}
        }
        resp = self.client.post("/api/v1/soc/misp/sightings",
                                json={"attribute_id": "42"})
        self.assertEqual(resp.status_code, 201)

    def test_list_sightings(self):
        self.mock_client.list_sightings.return_value = [
            {"Sighting": {"id": "1"}}
        ]
        resp = self.client.get("/api/v1/soc/misp/sightings/42")
        self.assertEqual(resp.status_code, 200)

    # -- Feeds --
    def test_list_feeds(self):
        self.mock_client.list_feeds.return_value = [
            {"Feed": {"id": "1", "name": "CIRCL"}}
        ]
        resp = self.client.get("/api/v1/soc/misp/feeds")
        self.assertEqual(resp.status_code, 200)

    def test_get_feed(self):
        self.mock_client.get_feed.return_value = {
            "Feed": {"id": "1", "name": "Test"}
        }
        resp = self.client.get("/api/v1/soc/misp/feeds/1")
        self.assertEqual(resp.status_code, 200)

    def test_get_feed_not_found(self):
        self.mock_client.get_feed.return_value = {"error": "not found"}
        resp = self.client.get("/api/v1/soc/misp/feeds/999")
        self.assertEqual(resp.status_code, 404)

    def test_add_feed(self):
        self.mock_client.add_feed.return_value = {
            "Feed": {"id": "2", "name": "New Feed"}
        }
        resp = self.client.post("/api/v1/soc/misp/feeds",
                                json={"name": "New Feed", "url": "http://feed.test"})
        self.assertEqual(resp.status_code, 201)

    def test_add_feed_missing_fields(self):
        resp = self.client.post("/api/v1/soc/misp/feeds", json={})
        self.assertEqual(resp.status_code, 400)

    def test_enable_feed(self):
        self.mock_client.enable_feed.return_value = {"success": True}
        resp = self.client.post("/api/v1/soc/misp/feeds/1/enable")
        self.assertEqual(resp.status_code, 200)

    def test_disable_feed(self):
        self.mock_client.disable_feed.return_value = {"success": True}
        resp = self.client.post("/api/v1/soc/misp/feeds/1/disable")
        self.assertEqual(resp.status_code, 200)

    def test_fetch_feed(self):
        self.mock_client.fetch_from_feed.return_value = {"result": "ok"}
        resp = self.client.post("/api/v1/soc/misp/feeds/1/fetch")
        self.assertEqual(resp.status_code, 200)

    # -- Galaxies --
    def test_list_galaxies(self):
        self.mock_client.list_galaxies.return_value = [{"id": "1"}]
        resp = self.client.get("/api/v1/soc/misp/galaxies")
        self.assertEqual(resp.status_code, 200)

    def test_get_galaxy(self):
        self.mock_client.get_galaxy.return_value = {"Galaxy": {"id": "1"}}
        resp = self.client.get("/api/v1/soc/misp/galaxies/1")
        self.assertEqual(resp.status_code, 200)

    def test_get_galaxy_not_found(self):
        self.mock_client.get_galaxy.return_value = {"error": "not found"}
        resp = self.client.get("/api/v1/soc/misp/galaxies/999")
        self.assertEqual(resp.status_code, 404)

    def test_search_galaxy_clusters(self):
        self.mock_client.search_galaxy_clusters.return_value = {"response": []}
        resp = self.client.post("/api/v1/soc/misp/galaxies/clusters/search", json={})
        self.assertEqual(resp.status_code, 200)

    def test_attach_galaxy(self):
        self.mock_client.attach_galaxy_cluster.return_value = {"success": True}
        resp = self.client.post("/api/v1/soc/misp/events/1/galaxies",
                                json={"cluster_id": "abc"})
        self.assertEqual(resp.status_code, 200)

    def test_attach_galaxy_missing(self):
        resp = self.client.post("/api/v1/soc/misp/events/1/galaxies", json={})
        self.assertEqual(resp.status_code, 400)

    # -- Warninglists --
    def test_list_warninglists(self):
        self.mock_client.list_warninglists.return_value = {"Warninglists": []}
        resp = self.client.get("/api/v1/soc/misp/warninglists")
        self.assertEqual(resp.status_code, 200)

    def test_check_warninglist(self):
        self.mock_client.check_warninglist.return_value = {"matched": []}
        resp = self.client.post("/api/v1/soc/misp/warninglists/check",
                                json={"values": ["8.8.8.8"]})
        self.assertEqual(resp.status_code, 200)

    def test_check_warninglist_missing(self):
        resp = self.client.post("/api/v1/soc/misp/warninglists/check", json={})
        self.assertEqual(resp.status_code, 400)

    # -- Correlations --
    def test_get_correlations(self):
        self.mock_client.get_correlations.return_value = {"Event": {"id": "1"}}
        resp = self.client.get("/api/v1/soc/misp/events/1/correlations")
        self.assertEqual(resp.status_code, 200)

    # -- Export/Import --
    def test_export_iocs(self):
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Test"}
        }
        resp = self.client.post("/api/v1/soc/misp/export",
                                json={"alert_id": "A001", "title": "Test"})
        self.assertEqual(resp.status_code, 201)

    def test_export_iocs_missing_id(self):
        resp = self.client.post("/api/v1/soc/misp/export", json={})
        self.assertEqual(resp.status_code, 400)

    def test_import_iocs(self):
        self.mock_client.get_event.return_value = {
            "Event": {"id": "1", "info": "Test", "Attribute": []}
        }
        resp = self.client.post("/api/v1/soc/misp/import/1")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("iocs", data)
        self.assertIn("count", data)

    # -- Sync --
    def test_sync_status(self):
        self.sync_store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1"))
        resp = self.client.get("/api/v1/soc/misp/sync/status/t1")
        self.assertEqual(resp.status_code, 200)

    def test_sync_status_not_found(self):
        resp = self.client.get("/api/v1/soc/misp/sync/status/nonexistent")
        self.assertEqual(resp.status_code, 404)

    def test_sync_records(self):
        self.sync_store.save_record(SyncRecord(tsunami_id="t1", misp_id="m1"))
        resp = self.client.get("/api/v1/soc/misp/sync/records")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("records", resp.get_json())

    def test_sync_records_with_filters(self):
        resp = self.client.get("/api/v1/soc/misp/sync/records?entity_type=event&status=synced&limit=10&offset=0")
        self.assertEqual(resp.status_code, 200)

    def test_sync_stats(self):
        resp = self.client.get("/api/v1/soc/misp/sync/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total", data)


# ===========================================================================
# Global Singleton Tests
# ===========================================================================

class TestGlobalSingleton(unittest.TestCase):
    def setUp(self):
        reset_global_connector()

    def tearDown(self):
        reset_global_connector()

    def test_get_returns_instance(self):
        connector = get_misp_connector()
        self.assertIsInstance(connector, MISPConnector)

    def test_same_instance(self):
        c1 = get_misp_connector()
        c2 = get_misp_connector()
        self.assertIs(c1, c2)

    def test_reset(self):
        c1 = get_misp_connector()
        reset_global_connector()
        c2 = get_misp_connector()
        self.assertIsNot(c1, c2)


# ===========================================================================
# Blueprint No Flask Test
# ===========================================================================

class TestBlueprintNoFlask(unittest.TestCase):
    def test_no_flask_returns_none(self):
        original_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "flask":
                raise ImportError("No module named 'flask'")
            return original_import(name, *args, **kwargs)
        with patch("builtins.__import__", side_effect=mock_import):
            bp = create_misp_blueprint()
            self.assertIsNone(bp)


# ===========================================================================
# Integration Tests
# ===========================================================================

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock(spec=MISPClient)
        self.tmpdir = tempfile.mkdtemp()
        self.sync_store = SyncStore(db_path=os.path.join(self.tmpdir, "int_test.db"))
        self.connector = MISPConnector(client=self.mock_client, sync_store=self.sync_store)

    def test_full_export_import_workflow(self):
        """Export IOCs from TSUNAMI, then import from MISP event."""
        # Export
        self.mock_client.create_event.return_value = {
            "Event": {"id": "100", "info": "TSUNAMI Alert"}
        }
        self.mock_client.add_attribute.return_value = {
            "Attribute": {"id": "200", "type": "ip-dst", "value": "1.2.3.4"}
        }
        self.mock_client.add_tag_to_event.return_value = {"success": True}
        alert = {
            "alert_id": "INT-001",
            "title": "Integration Test",
            "severity": "high",
            "tlp": "TLP:AMBER",
            "iocs": [{"type": "ip_address", "value": "1.2.3.4"}],
        }
        exported = self.connector.export_iocs_to_misp(alert)
        self.assertIsNotNone(exported)

        # Import
        self.mock_client.get_event.return_value = {
            "Event": {
                "id": "100",
                "info": "TSUNAMI Alert",
                "Attribute": [
                    {"type": "ip-dst", "value": "1.2.3.4", "id": "200"},
                ],
            }
        }
        imported = self.connector.import_iocs_from_misp("100")
        self.assertEqual(len(imported), 1)
        self.assertEqual(imported[0]["value"], "1.2.3.4")

        # Verify sync records
        stats = self.connector.get_sync_stats()
        self.assertGreaterEqual(stats["total"], 2)

    def test_event_with_galaxy_and_tags_workflow(self):
        """Create event, add tags, attach galaxy cluster."""
        self.mock_client.create_event.return_value = {
            "Event": {"id": "10", "info": "APT Campaign"}
        }
        self.mock_client.add_tag_to_event.return_value = {"success": True}
        self.mock_client.attach_galaxy_cluster.return_value = {"success": True}
        self.mock_client.add_attribute.return_value = {
            "Attribute": {"id": "20", "type": "ip-dst", "value": "5.6.7.8"}
        }

        event = self.connector.create_event(MISPEvent(info="APT Campaign"))
        self.assertIsNotNone(event)

        self.assertTrue(self.connector.add_tag_to_event(event.id, "tlp:amber"))
        self.assertTrue(self.connector.attach_galaxy_cluster(event.id, "apt28-uuid"))

        attr = self.connector.add_attribute(
            event.id, MISPAttribute(type="ip-dst", value="5.6.7.8")
        )
        self.assertIsNotNone(attr)

    def test_feed_management_workflow(self):
        """Add, enable, fetch, disable feed."""
        self.mock_client.add_feed.return_value = {
            "Feed": {"id": "5", "name": "OSINT Feed"}
        }
        self.mock_client.enable_feed.return_value = {"success": True}
        self.mock_client.fetch_from_feed.return_value = {"result": "fetched 100 events"}
        self.mock_client.disable_feed.return_value = {"success": True}

        feed = self.connector.add_feed(
            MISPFeed(name="OSINT Feed", url="https://osint.feed/misp", provider="OSINT")
        )
        self.assertIsNotNone(feed)
        self.assertTrue(self.connector.enable_feed(feed.id))
        result = self.connector.fetch_from_feed(feed.id)
        self.assertIn("result", result)
        self.assertTrue(self.connector.disable_feed(feed.id))

    def test_sighting_workflow(self):
        """Add attributes, then add sightings."""
        self.mock_client.add_attribute.return_value = {
            "Attribute": {"id": "30", "type": "domain", "value": "evil.com"}
        }
        self.mock_client.add_sighting.return_value = {
            "Sighting": {"id": "1", "type": "0"}
        }
        self.mock_client.list_sightings.return_value = [
            {"Sighting": {"id": "1", "type": "0", "source": "TSUNAMI-SOC"}}
        ]

        attr = self.connector.add_attribute("1", MISPAttribute(type="domain", value="evil.com"))
        self.assertIsNotNone(attr)

        sighting = self.connector.add_sighting(MISPSighting(attribute_id=attr.id))
        self.assertIsNotNone(sighting)

        sightings = self.connector.list_sightings(attr.id)
        self.assertEqual(len(sightings), 1)

    def test_callback_full_lifecycle(self):
        """Register callbacks and verify they fire throughout lifecycle."""
        events_log = []
        def track(event_type, data):
            events_log.append(event_type)

        self.connector.register_callback("event_created", track)
        self.connector.register_callback("ioc_exported", track)
        self.connector.register_callback("ioc_imported", track)

        # Create event
        self.mock_client.create_event.return_value = {
            "Event": {"id": "1", "info": "Lifecycle"}
        }
        self.connector.create_event(MISPEvent(info="Lifecycle"))

        # Export
        alert = {"alert_id": "LC-001", "title": "Lifecycle Test"}
        self.connector.export_iocs_to_misp(alert)

        # Import
        self.mock_client.get_event.return_value = {
            "Event": {"id": "99", "info": "Import", "Attribute": []}
        }
        self.connector.import_iocs_from_misp("99")

        self.assertIn("event_created", events_log)
        self.assertIn("ioc_exported", events_log)
        self.assertIn("ioc_imported", events_log)


if __name__ == "__main__":
    unittest.main()
