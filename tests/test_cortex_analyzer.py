#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Cortex Analyzer Integration Tests
================================================================================
"""

import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.enrichment.cortex_analyzer import (
    # Enums
    JobStatus,
    TlpLevel,
    PapLevel,
    ObservableDataType,
    TaxonomyLevel,
    ConnectionStatus,
    POLL_DEFAULTS,
    # Data classes
    AnalyzerInfo,
    ResponderInfo,
    Taxonomy,
    Artifact,
    AnalysisReport,
    AnalysisBatchResult,
    # HTTP Client
    CortexHTTPClient,
    # Exceptions
    CortexError,
    CortexAuthError,
    CortexNotFoundError,
    CortexServerError,
    CortexAPIError,
    CortexTimeoutError,
    # Cache
    AnalysisCache,
    # Main Client
    CortexAnalyzerClient,
    # Blueprint
    create_cortex_blueprint,
    # Global
    get_cortex_client,
    reset_global_client,
)


# ============================================================================
# Test: Enums
# ============================================================================

class TestJobStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(JobStatus.WAITING.value, "Waiting")
        self.assertEqual(JobStatus.IN_PROGRESS.value, "InProgress")
        self.assertEqual(JobStatus.SUCCESS.value, "Success")
        self.assertEqual(JobStatus.FAILURE.value, "Failure")
        self.assertEqual(JobStatus.DELETED.value, "Deleted")
        self.assertEqual(JobStatus.UNKNOWN.value, "Unknown")

    def test_all_members(self):
        self.assertEqual(len(JobStatus), 6)


class TestTlpLevel(unittest.TestCase):
    def test_values(self):
        self.assertEqual(TlpLevel.WHITE.value, 0)
        self.assertEqual(TlpLevel.GREEN.value, 1)
        self.assertEqual(TlpLevel.AMBER.value, 2)
        self.assertEqual(TlpLevel.RED.value, 3)


class TestPapLevel(unittest.TestCase):
    def test_values(self):
        self.assertEqual(PapLevel.WHITE.value, 0)
        self.assertEqual(PapLevel.AMBER.value, 2)
        self.assertEqual(PapLevel.RED.value, 3)


class TestObservableDataType(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ObservableDataType.IP.value, "ip")
        self.assertEqual(ObservableDataType.DOMAIN.value, "domain")
        self.assertEqual(ObservableDataType.HASH.value, "hash")
        self.assertEqual(ObservableDataType.URL.value, "url")
        self.assertEqual(ObservableDataType.MAIL.value, "mail")
        self.assertEqual(ObservableDataType.FILE.value, "file")


class TestTaxonomyLevel(unittest.TestCase):
    def test_values(self):
        self.assertEqual(TaxonomyLevel.INFO.value, "info")
        self.assertEqual(TaxonomyLevel.SAFE.value, "safe")
        self.assertEqual(TaxonomyLevel.SUSPICIOUS.value, "suspicious")
        self.assertEqual(TaxonomyLevel.MALICIOUS.value, "malicious")


class TestConnectionStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ConnectionStatus.CONNECTED.value, "connected")
        self.assertEqual(ConnectionStatus.DEGRADED.value, "degraded")
        self.assertEqual(ConnectionStatus.DISCONNECTED.value, "disconnected")
        self.assertEqual(ConnectionStatus.AUTH_ERROR.value, "auth_error")


# ============================================================================
# Test: AnalyzerInfo
# ============================================================================

class TestAnalyzerInfo(unittest.TestCase):
    def test_default_creation(self):
        a = AnalyzerInfo()
        self.assertEqual(a.id, "")
        self.assertEqual(a.name, "")
        self.assertEqual(a.data_type_list, [])
        self.assertEqual(a.max_tlp, 3)

    def test_from_dict(self):
        data = {
            "id": "Abuse_Finder_3_0",
            "name": "Abuse_Finder",
            "version": "3.0",
            "description": "Find abuse contact",
            "dataTypeList": ["ip", "domain", "url", "mail"],
            "maxTlp": 3,
            "maxPap": 2,
            "author": "CERT-BDF",
            "url": "https://github.com/...",
            "license": "AGPL-3",
            "baseConfig": "Abuse_Finder",
        }
        a = AnalyzerInfo.from_dict(data)
        self.assertEqual(a.id, "Abuse_Finder_3_0")
        self.assertEqual(a.name, "Abuse_Finder")
        self.assertEqual(a.version, "3.0")
        self.assertIn("ip", a.data_type_list)
        self.assertIn("domain", a.data_type_list)
        self.assertEqual(a.max_pap, 2)

    def test_supports_data_type(self):
        a = AnalyzerInfo(data_type_list=["ip", "domain"])
        self.assertTrue(a.supports_data_type("ip"))
        self.assertTrue(a.supports_data_type("domain"))
        self.assertFalse(a.supports_data_type("hash"))

    def test_to_dict(self):
        a = AnalyzerInfo(id="test1", name="TestAnalyzer", data_type_list=["ip"])
        d = a.to_dict()
        self.assertEqual(d["id"], "test1")
        self.assertEqual(d["name"], "TestAnalyzer")
        self.assertEqual(d["dataTypeList"], ["ip"])

    def test_from_dict_with_rate(self):
        data = {"id": "a1", "rate": {"ratePerMinute": 10}}
        a = AnalyzerInfo.from_dict(data)
        self.assertEqual(a.rate_per_minute, 10)

    def test_from_dict_name_fallback(self):
        data = {"id": "fallback_id"}
        a = AnalyzerInfo.from_dict(data)
        self.assertEqual(a.name, "fallback_id")

    def test_from_dict_rate_not_dict(self):
        data = {"id": "a1", "rate": 5}
        a = AnalyzerInfo.from_dict(data)
        self.assertIsNone(a.rate_per_minute)


# ============================================================================
# Test: ResponderInfo
# ============================================================================

class TestResponderInfo(unittest.TestCase):
    def test_from_dict(self):
        data = {
            "id": "Mailer_1_0",
            "name": "Mailer",
            "version": "1.0",
            "description": "Send email",
            "dataTypeList": ["thehive:case", "thehive:alert"],
            "maxTlp": 2,
            "maxPap": 1,
            "author": "CERT-BDF",
        }
        r = ResponderInfo.from_dict(data)
        self.assertEqual(r.id, "Mailer_1_0")
        self.assertEqual(r.name, "Mailer")
        self.assertIn("thehive:case", r.data_type_list)

    def test_to_dict(self):
        r = ResponderInfo(id="r1", name="Resp1")
        d = r.to_dict()
        self.assertEqual(d["id"], "r1")
        self.assertEqual(d["name"], "Resp1")

    def test_default_creation(self):
        r = ResponderInfo()
        self.assertEqual(r.id, "")
        self.assertEqual(r.data_type_list, [])


# ============================================================================
# Test: Taxonomy
# ============================================================================

class TestTaxonomy(unittest.TestCase):
    def test_from_dict(self):
        data = {"level": "malicious", "namespace": "VT", "predicate": "score", "value": "15/60"}
        t = Taxonomy.from_dict(data)
        self.assertEqual(t.level, "malicious")
        self.assertEqual(t.namespace, "VT")
        self.assertEqual(t.value, "15/60")

    def test_to_dict(self):
        t = Taxonomy(level="safe", namespace="AB", predicate="status", value="clean")
        d = t.to_dict()
        self.assertEqual(d["level"], "safe")
        self.assertEqual(d["namespace"], "AB")

    def test_default(self):
        t = Taxonomy()
        self.assertEqual(t.level, "info")


# ============================================================================
# Test: Artifact
# ============================================================================

class TestArtifact(unittest.TestCase):
    def test_from_dict(self):
        data = {"dataType": "ip", "data": "1.2.3.4", "message": "found", "tlp": 1, "tags": ["ioc"]}
        a = Artifact.from_dict(data)
        self.assertEqual(a.data_type, "ip")
        self.assertEqual(a.data, "1.2.3.4")
        self.assertEqual(a.tags, ["ioc"])

    def test_to_dict(self):
        a = Artifact(data_type="domain", data="evil.com")
        d = a.to_dict()
        self.assertEqual(d["dataType"], "domain")
        self.assertEqual(d["data"], "evil.com")


# ============================================================================
# Test: AnalysisReport
# ============================================================================

class TestAnalysisReport(unittest.TestCase):
    def test_default(self):
        r = AnalysisReport()
        self.assertEqual(r.status, JobStatus.UNKNOWN.value)
        self.assertFalse(r.success)
        self.assertFalse(r.malicious)
        self.assertFalse(r.suspicious)
        self.assertEqual(r.max_severity, "info")

    def test_success_property(self):
        r = AnalysisReport(status=JobStatus.SUCCESS.value)
        self.assertTrue(r.success)

    def test_malicious_property(self):
        r = AnalysisReport(
            status=JobStatus.SUCCESS.value,
            taxonomies=[Taxonomy(level="malicious", namespace="VT", predicate="score", value="10")]
        )
        self.assertTrue(r.malicious)

    def test_suspicious_property(self):
        r = AnalysisReport(
            taxonomies=[Taxonomy(level="suspicious")]
        )
        self.assertTrue(r.suspicious)

    def test_max_severity_malicious(self):
        r = AnalysisReport(
            taxonomies=[
                Taxonomy(level="info"),
                Taxonomy(level="malicious"),
                Taxonomy(level="safe"),
            ]
        )
        self.assertEqual(r.max_severity, "malicious")

    def test_max_severity_suspicious(self):
        r = AnalysisReport(
            taxonomies=[
                Taxonomy(level="safe"),
                Taxonomy(level="suspicious"),
            ]
        )
        self.assertEqual(r.max_severity, "suspicious")

    def test_to_dict(self):
        r = AnalysisReport(
            job_id="j1",
            analyzer_id="a1",
            status=JobStatus.SUCCESS.value,
            data="8.8.8.8",
            data_type="ip",
        )
        d = r.to_dict()
        self.assertEqual(d["jobId"], "j1")
        self.assertEqual(d["analyzerId"], "a1")
        self.assertTrue(d["success"])
        self.assertFalse(d["malicious"])
        self.assertEqual(d["maxSeverity"], "info")

    def test_from_job_response_basic(self):
        job = {
            "id": "job123",
            "analyzerId": "VT_3_1",
            "analyzerName": "VirusTotal",
            "status": "Success",
            "data": "1.2.3.4",
            "dataType": "ip",
            "startDate": 1700000000000,
            "endDate": 1700000005000,
        }
        r = AnalysisReport.from_job_response(job)
        self.assertEqual(r.job_id, "job123")
        self.assertEqual(r.analyzer_id, "VT_3_1")
        self.assertTrue(r.success)
        self.assertIsNotNone(r.start_date)
        self.assertIsNotNone(r.end_date)
        self.assertEqual(r.duration_ms, 5000)

    def test_from_job_response_with_report(self):
        job = {"id": "j2", "analyzerId": "VT", "status": "Success", "data": "x", "dataType": "ip"}
        report = {
            "summary": {
                "taxonomies": [
                    {"level": "malicious", "namespace": "VT", "predicate": "score", "value": "15/60"},
                ]
            },
            "artifacts": [
                {"dataType": "ip", "data": "5.6.7.8", "tags": ["related"]}
            ],
        }
        r = AnalysisReport.from_job_response(job, report)
        self.assertEqual(len(r.taxonomies), 1)
        self.assertEqual(r.taxonomies[0].level, "malicious")
        self.assertEqual(len(r.artifacts), 1)
        self.assertEqual(r.artifacts[0].data, "5.6.7.8")
        self.assertTrue(r.malicious)

    def test_from_job_response_failure(self):
        job = {"id": "j3", "analyzerId": "A1", "status": "Failure", "data": "x", "dataType": "ip"}
        report = {"errorMessage": "Something went wrong"}
        r = AnalysisReport.from_job_response(job, report)
        self.assertFalse(r.success)
        self.assertEqual(r.error_message, "Something went wrong")

    def test_from_job_response_string_dates(self):
        job = {
            "id": "j4", "analyzerId": "A1", "status": "Success",
            "data": "x", "dataType": "ip",
            "startDate": "2024-01-01T00:00:00Z",
            "endDate": "2024-01-01T00:00:05Z",
        }
        r = AnalysisReport.from_job_response(job)
        self.assertIsNotNone(r.start_date)
        self.assertIsNotNone(r.end_date)
        self.assertEqual(r.duration_ms, 0)  # Non-numeric dates don't compute duration


# ============================================================================
# Test: AnalysisBatchResult
# ============================================================================

class TestAnalysisBatchResult(unittest.TestCase):
    def test_default(self):
        b = AnalysisBatchResult(observable="8.8.8.8", data_type="ip")
        self.assertFalse(b.any_malicious)
        self.assertFalse(b.any_suspicious)
        self.assertEqual(b.max_severity, "info")

    def test_any_malicious(self):
        b = AnalysisBatchResult(
            observable="8.8.8.8",
            data_type="ip",
            reports=[
                AnalysisReport(taxonomies=[Taxonomy(level="safe")]),
                AnalysisReport(taxonomies=[Taxonomy(level="malicious")]),
            ],
        )
        self.assertTrue(b.any_malicious)

    def test_any_suspicious(self):
        b = AnalysisBatchResult(
            observable="x",
            data_type="ip",
            reports=[AnalysisReport(taxonomies=[Taxonomy(level="suspicious")])],
        )
        self.assertTrue(b.any_suspicious)

    def test_max_severity(self):
        b = AnalysisBatchResult(
            observable="x",
            data_type="ip",
            reports=[
                AnalysisReport(taxonomies=[Taxonomy(level="info")]),
                AnalysisReport(taxonomies=[Taxonomy(level="suspicious")]),
            ],
        )
        self.assertEqual(b.max_severity, "suspicious")

    def test_to_dict(self):
        b = AnalysisBatchResult(observable="test", data_type="domain")
        d = b.to_dict()
        self.assertEqual(d["observable"], "test")
        self.assertEqual(d["dataType"], "domain")
        self.assertIn("reports", d)
        self.assertIn("timestamp", d)


# ============================================================================
# Test: CortexHTTPClient
# ============================================================================

class TestCortexHTTPClient(unittest.TestCase):
    def test_init(self):
        c = CortexHTTPClient("https://cortex.example.com", "apikey123")
        self.assertEqual(c.base_url, "https://cortex.example.com")
        self.assertEqual(c.api_key, "apikey123")

    def test_url_strip_trailing_slash(self):
        c = CortexHTTPClient("https://cortex.example.com/", "key")
        self.assertEqual(c.base_url, "https://cortex.example.com")

    def test_get_headers(self):
        c = CortexHTTPClient("https://cortex.example.com", "mykey")
        h = c._get_headers()
        self.assertEqual(h["Authorization"], "Bearer mykey")
        self.assertEqual(h["Content-Type"], "application/json")

    @patch("modules.enrichment.cortex_analyzer.CortexHTTPClient._request")
    def test_get(self, mock_req):
        mock_req.return_value = {"status": "ok"}
        c = CortexHTTPClient("http://localhost:9001", "key")
        result = c.get("/api/status")
        mock_req.assert_called_once_with("GET", "/api/status", params=None)
        self.assertEqual(result["status"], "ok")

    @patch("modules.enrichment.cortex_analyzer.CortexHTTPClient._request")
    def test_post(self, mock_req):
        mock_req.return_value = {"id": "job1"}
        c = CortexHTTPClient("http://localhost:9001", "key")
        result = c.post("/api/analyzer/VT/run", data={"data": "1.2.3.4"})
        mock_req.assert_called_once_with("POST", "/api/analyzer/VT/run", data={"data": "1.2.3.4"})
        self.assertEqual(result["id"], "job1")

    @patch("modules.enrichment.cortex_analyzer.CortexHTTPClient._request")
    def test_health_check_success(self, mock_req):
        mock_req.return_value = {"status": "ok"}
        c = CortexHTTPClient("http://localhost:9001", "key")
        self.assertTrue(c.health_check())

    @patch("modules.enrichment.cortex_analyzer.CortexHTTPClient._request")
    def test_health_check_failure(self, mock_req):
        mock_req.side_effect = Exception("Connection refused")
        c = CortexHTTPClient("http://localhost:9001", "key")
        self.assertFalse(c.health_check())


# ============================================================================
# Test: Exceptions
# ============================================================================

class TestExceptions(unittest.TestCase):
    def test_hierarchy(self):
        self.assertTrue(issubclass(CortexAuthError, CortexError))
        self.assertTrue(issubclass(CortexNotFoundError, CortexError))
        self.assertTrue(issubclass(CortexServerError, CortexError))
        self.assertTrue(issubclass(CortexAPIError, CortexError))
        self.assertTrue(issubclass(CortexTimeoutError, CortexError))

    def test_message(self):
        e = CortexAuthError("Bad key")
        self.assertEqual(str(e), "Bad key")


# ============================================================================
# Test: AnalysisCache
# ============================================================================

class TestAnalysisCache(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_cache.db")
        self.cache = AnalysisCache(db_path=self.db_path, default_ttl=60)

    def test_db_init(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='analysis_cache'")
        self.assertIsNotNone(cursor.fetchone())
        conn.close()

    def test_set_and_get(self):
        data = {"score": 85, "tags": ["malware"]}
        self.cache.set("1.2.3.4", "ip", "VT_3_1", data)
        result = self.cache.get("1.2.3.4", "ip", "VT_3_1")
        self.assertIsNotNone(result)
        self.assertEqual(result["score"], 85)

    def test_get_miss(self):
        result = self.cache.get("nonexistent", "ip", "VT")
        self.assertIsNone(result)

    def test_ttl_expiration(self):
        self.cache = AnalysisCache(db_path=self.db_path, default_ttl=1)
        self.cache.set("1.2.3.4", "ip", "VT", {"data": "test"})
        time.sleep(1.1)
        result = self.cache.get("1.2.3.4", "ip", "VT")
        self.assertIsNone(result)

    def test_overwrite(self):
        self.cache.set("1.2.3.4", "ip", "VT", {"v": 1})
        self.cache.set("1.2.3.4", "ip", "VT", {"v": 2})
        result = self.cache.get("1.2.3.4", "ip", "VT")
        self.assertEqual(result["v"], 2)

    def test_different_analyzers_separate(self):
        self.cache.set("1.2.3.4", "ip", "VT", {"source": "vt"})
        self.cache.set("1.2.3.4", "ip", "AB", {"source": "ab"})
        r1 = self.cache.get("1.2.3.4", "ip", "VT")
        r2 = self.cache.get("1.2.3.4", "ip", "AB")
        self.assertEqual(r1["source"], "vt")
        self.assertEqual(r2["source"], "ab")

    def test_delete(self):
        self.cache.set("1.2.3.4", "ip", "VT", {"data": "x"})
        self.cache.delete("1.2.3.4", "ip", "VT")
        self.assertIsNone(self.cache.get("1.2.3.4", "ip", "VT"))

    def test_clear(self):
        self.cache.set("a", "ip", "VT", {"x": 1})
        self.cache.set("b", "ip", "VT", {"x": 2})
        self.cache.clear()
        self.assertIsNone(self.cache.get("a", "ip", "VT"))
        self.assertIsNone(self.cache.get("b", "ip", "VT"))

    def test_clear_expired(self):
        self.cache = AnalysisCache(db_path=self.db_path, default_ttl=1)
        self.cache.set("exp", "ip", "VT", {"x": 1})
        time.sleep(1.1)
        removed = self.cache.clear_expired()
        self.assertGreaterEqual(removed, 1)

    def test_stats(self):
        self.cache.set("a", "ip", "VT", {"x": 1})
        self.cache.set("b", "ip", "VT", {"x": 2})
        stats = self.cache.stats()
        self.assertEqual(stats["total_entries"], 2)
        self.assertEqual(stats["active"], 2)
        self.assertEqual(stats["expired"], 0)


# ============================================================================
# Test: CortexAnalyzerClient
# ============================================================================

class TestCortexAnalyzerClient(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = AnalysisCache(db_path=os.path.join(self.tmpdir, "test.db"))
        self.client = CortexAnalyzerClient(
            base_url="http://localhost:9001",
            api_key="testkey123",
            cache=self.cache,
            poll_interval=0.1,
            poll_max_wait=2.0,
        )

    def test_configured(self):
        self.assertTrue(self.client.configured)

    def test_not_configured(self):
        c = CortexAnalyzerClient()
        self.assertFalse(c.configured)

    def test_http_property_created(self):
        http = self.client.http
        self.assertIsNotNone(http)
        self.assertIsInstance(http, CortexHTTPClient)

    def test_http_property_not_configured(self):
        c = CortexAnalyzerClient()
        with self.assertRaises(CortexError):
            _ = c.http

    @patch.object(CortexHTTPClient, "get")
    def test_check_connection_connected(self, mock_get):
        mock_get.return_value = {"status": "ok"}
        status = self.client.check_connection()
        self.assertEqual(status, ConnectionStatus.CONNECTED)

    @patch.object(CortexHTTPClient, "get")
    def test_check_connection_auth_error(self, mock_get):
        mock_get.side_effect = CortexAuthError("bad key")
        status = self.client.check_connection()
        self.assertEqual(status, ConnectionStatus.AUTH_ERROR)

    @patch.object(CortexHTTPClient, "get")
    def test_check_connection_disconnected(self, mock_get):
        mock_get.side_effect = Exception("connection refused")
        status = self.client.check_connection()
        self.assertEqual(status, ConnectionStatus.DISCONNECTED)

    def test_check_connection_not_configured(self):
        c = CortexAnalyzerClient()
        self.assertEqual(c.check_connection(), ConnectionStatus.DISCONNECTED)

    @patch.object(CortexHTTPClient, "get")
    def test_check_connection_degraded(self, mock_get):
        mock_get.return_value = {}  # Empty response
        status = self.client.check_connection()
        self.assertEqual(status, ConnectionStatus.DEGRADED)

    @patch.object(CortexHTTPClient, "get")
    def test_list_analyzers(self, mock_get):
        mock_get.return_value = [
            {"id": "VT_3_1", "name": "VirusTotal", "dataTypeList": ["ip", "domain"]},
            {"id": "AB_2_0", "name": "AbuseIPDB", "dataTypeList": ["ip"]},
        ]
        analyzers = self.client.list_analyzers()
        self.assertEqual(len(analyzers), 2)
        self.assertEqual(analyzers[0].id, "VT_3_1")
        self.assertIn("VT_3_1", self.client._analyzers)

    @patch.object(CortexHTTPClient, "get")
    def test_list_analyzers_by_type(self, mock_get):
        mock_get.return_value = [
            {"id": "VT_3_1", "name": "VirusTotal", "dataTypeList": ["ip"]},
        ]
        analyzers = self.client.list_analyzers(data_type="ip")
        mock_get.assert_called_with("/api/analyzer/type/ip")
        self.assertEqual(len(analyzers), 1)

    @patch.object(CortexHTTPClient, "get")
    def test_get_analyzer(self, mock_get):
        mock_get.return_value = {"id": "VT_3_1", "name": "VirusTotal", "dataTypeList": ["ip"]}
        a = self.client.get_analyzer("VT_3_1")
        self.assertEqual(a.id, "VT_3_1")

    def test_get_analyzer_cached(self):
        self.client._analyzers["cached"] = AnalyzerInfo(id="cached", name="Cached")
        a = self.client.get_analyzer("cached")
        self.assertEqual(a.name, "Cached")

    @patch.object(CortexHTTPClient, "get")
    def test_find_analyzers_for(self, mock_get):
        mock_get.return_value = [
            {"id": "VT", "dataTypeList": ["ip", "domain"]},
            {"id": "AB", "dataTypeList": ["ip"]},
            {"id": "WH", "dataTypeList": ["domain"]},
        ]
        self.client.list_analyzers()
        ip_analyzers = self.client.find_analyzers_for("ip")
        self.assertEqual(len(ip_analyzers), 2)

    @patch.object(CortexHTTPClient, "get")
    def test_list_responders(self, mock_get):
        mock_get.return_value = [
            {"id": "Mailer_1_0", "name": "Mailer", "dataTypeList": ["thehive:case"]},
        ]
        responders = self.client.list_responders()
        self.assertEqual(len(responders), 1)
        self.assertEqual(responders[0].id, "Mailer_1_0")

    @patch.object(CortexHTTPClient, "get")
    def test_list_responders_by_type(self, mock_get):
        mock_get.return_value = []
        self.client.list_responders(data_type="thehive:case")
        mock_get.assert_called_with("/api/responder/type/thehive:case")

    @patch.object(CortexHTTPClient, "get")
    def test_get_responder(self, mock_get):
        mock_get.return_value = {"id": "R1", "name": "Resp1"}
        r = self.client.get_responder("R1")
        self.assertEqual(r.id, "R1")

    def test_get_responder_cached(self):
        self.client._responders["cached"] = ResponderInfo(id="cached", name="CachedR")
        r = self.client.get_responder("cached")
        self.assertEqual(r.name, "CachedR")

    # --- Job Operations ---

    @patch.object(CortexHTTPClient, "post")
    def test_run_analyzer(self, mock_post):
        mock_post.return_value = {"id": "job1", "status": "Waiting"}
        result = self.client.run_analyzer("VT_3_1", "1.2.3.4", "ip")
        self.assertEqual(result["id"], "job1")
        self.assertEqual(self.client._stats["jobs_submitted"], 1)
        self.assertEqual(self.client._stats["cache_misses"], 1)

    @patch.object(CortexHTTPClient, "post")
    def test_run_analyzer_cache_hit(self, mock_post):
        # Pre-populate cache
        self.cache.set("1.2.3.4", "ip", "VT", {"data": "cached"})
        result = self.client.run_analyzer("VT", "1.2.3.4", "ip")
        mock_post.assert_not_called()
        self.assertEqual(result["data"], "cached")
        self.assertTrue(result["_cached"])
        self.assertEqual(self.client._stats["cache_hits"], 1)

    @patch.object(CortexHTTPClient, "post")
    def test_run_analyzer_force_bypass_cache(self, mock_post):
        self.cache.set("1.2.3.4", "ip", "VT", {"data": "cached"})
        mock_post.return_value = {"id": "job2"}
        result = self.client.run_analyzer("VT", "1.2.3.4", "ip", force=True)
        mock_post.assert_called_once()
        self.assertEqual(result["id"], "job2")

    @patch.object(CortexHTTPClient, "get")
    def test_get_job(self, mock_get):
        mock_get.return_value = {"id": "j1", "status": "Success"}
        result = self.client.get_job("j1")
        self.assertEqual(result["status"], "Success")

    @patch.object(CortexHTTPClient, "get")
    def test_get_job_report(self, mock_get):
        mock_get.return_value = {"summary": {"taxonomies": []}}
        result = self.client.get_job_report("j1")
        self.assertIn("summary", result)

    @patch.object(CortexHTTPClient, "delete")
    def test_delete_job(self, mock_del):
        mock_del.return_value = {}
        result = self.client.delete_job("j1")
        mock_del.assert_called_with("/api/job/j1")

    # --- Wait for Job ---

    @patch.object(CortexHTTPClient, "get")
    def test_wait_for_job_immediate_success(self, mock_get):
        mock_get.return_value = {"id": "j1", "status": "Success"}
        result = self.client.wait_for_job("j1")
        self.assertEqual(result["status"], "Success")
        self.assertEqual(self.client._stats["jobs_completed"], 1)

    @patch.object(CortexHTTPClient, "get")
    def test_wait_for_job_failure(self, mock_get):
        mock_get.return_value = {"id": "j1", "status": "Failure"}
        result = self.client.wait_for_job("j1")
        self.assertEqual(result["status"], "Failure")
        self.assertEqual(self.client._stats["jobs_failed"], 1)

    @patch.object(CortexHTTPClient, "get")
    def test_wait_for_job_deleted(self, mock_get):
        mock_get.return_value = {"id": "j1", "status": "Deleted"}
        result = self.client.wait_for_job("j1")
        self.assertEqual(result["status"], "Deleted")
        self.assertEqual(self.client._stats["jobs_failed"], 1)

    @patch.object(CortexHTTPClient, "get")
    def test_wait_for_job_timeout(self, mock_get):
        mock_get.return_value = {"id": "j1", "status": "InProgress"}
        with self.assertRaises(CortexTimeoutError):
            self.client.wait_for_job("j1", poll_interval=0.05, max_wait=0.2)
        self.assertEqual(self.client._stats["jobs_timeout"], 1)

    @patch.object(CortexHTTPClient, "get")
    def test_wait_for_job_polling_transitions(self, mock_get):
        mock_get.side_effect = [
            {"id": "j1", "status": "Waiting"},
            {"id": "j1", "status": "InProgress"},
            {"id": "j1", "status": "Success"},
        ]
        result = self.client.wait_for_job("j1", poll_interval=0.05)
        self.assertEqual(result["status"], "Success")
        self.assertEqual(mock_get.call_count, 3)

    # --- Full Analyze Flow ---

    @patch.object(CortexHTTPClient, "get")
    @patch.object(CortexHTTPClient, "post")
    def test_analyze_full_flow(self, mock_post, mock_get):
        mock_post.return_value = {"id": "job123"}
        mock_get.side_effect = [
            {"id": "job123", "analyzerId": "VT", "analyzerName": "VirusTotal",
             "status": "Success", "data": "1.2.3.4", "dataType": "ip",
             "startDate": 1700000000000, "endDate": 1700000002000},
            {"summary": {"taxonomies": [{"level": "safe", "namespace": "VT", "predicate": "score", "value": "0/60"}]}, "artifacts": []},
        ]
        report = self.client.analyze("VT", "1.2.3.4", "ip")
        self.assertTrue(report.success)
        self.assertEqual(len(report.taxonomies), 1)
        self.assertFalse(report.malicious)
        # Check cached
        cached = self.cache.get("1.2.3.4", "ip", "VT")
        self.assertIsNotNone(cached)

    @patch.object(CortexHTTPClient, "get")
    @patch.object(CortexHTTPClient, "post")
    def test_analyze_failure(self, mock_post, mock_get):
        mock_post.return_value = {"id": "jobfail"}
        mock_get.side_effect = [
            {"id": "jobfail", "analyzerId": "VT", "status": "Failure", "data": "x", "dataType": "ip"},
        ]
        report = self.client.analyze("VT", "x", "ip")
        self.assertFalse(report.success)
        # Failure should NOT be cached
        cached = self.cache.get("x", "ip", "VT")
        self.assertIsNone(cached)

    def test_analyze_cache_hit(self):
        cache_data = {
            "job_id": "j_cached",
            "analyzer_id": "VT",
            "analyzer_name": "VirusTotal",
            "status": "Success",
            "data": "1.2.3.4",
            "data_type": "ip",
            "taxonomies": [{"level": "safe", "namespace": "VT", "predicate": "score", "value": "0"}],
            "artifacts": [],
        }
        self.cache.set("1.2.3.4", "ip", "VT", cache_data)
        report = self.client.analyze("VT", "1.2.3.4", "ip")
        self.assertEqual(self.client._stats["cache_hits"], 1)

    @patch.object(CortexHTTPClient, "post")
    def test_analyze_no_job_id(self, mock_post):
        mock_post.return_value = {}
        report = self.client.analyze("VT", "test", "ip")
        self.assertFalse(report.success)
        self.assertIn("No job ID", report.error_message)

    @patch.object(CortexHTTPClient, "get")
    @patch.object(CortexHTTPClient, "post")
    def test_analyze_report_fetch_fails(self, mock_post, mock_get):
        mock_post.return_value = {"id": "j_ok"}
        mock_get.side_effect = [
            {"id": "j_ok", "analyzerId": "VT", "status": "Success", "data": "x", "dataType": "ip"},
            Exception("Report fetch failed"),
        ]
        report = self.client.analyze("VT", "x", "ip")
        self.assertTrue(report.success)  # Job succeeded, report fetch failed gracefully

    # --- Analyze Observable (multi-analyzer) ---

    @patch.object(CortexAnalyzerClient, "analyze")
    @patch.object(CortexAnalyzerClient, "find_analyzers_for")
    def test_analyze_observable_auto(self, mock_find, mock_analyze):
        mock_find.return_value = [
            AnalyzerInfo(id="VT", name="VT"),
            AnalyzerInfo(id="AB", name="AB"),
        ]
        mock_analyze.return_value = AnalysisReport(status=JobStatus.SUCCESS.value)
        result = self.client.analyze_observable("1.2.3.4", "ip")
        self.assertEqual(len(result.reports), 2)

    @patch.object(CortexAnalyzerClient, "analyze")
    def test_analyze_observable_specific(self, mock_analyze):
        mock_analyze.return_value = AnalysisReport(status=JobStatus.SUCCESS.value)
        result = self.client.analyze_observable("1.2.3.4", "ip", analyzer_ids=["VT"])
        self.assertEqual(len(result.reports), 1)

    @patch.object(CortexAnalyzerClient, "analyze")
    def test_analyze_observable_with_error(self, mock_analyze):
        mock_analyze.side_effect = Exception("Analysis failed")
        result = self.client.analyze_observable("1.2.3.4", "ip", analyzer_ids=["VT"])
        self.assertEqual(len(result.reports), 1)
        self.assertFalse(result.reports[0].success)

    # --- Responder ---

    @patch.object(CortexHTTPClient, "post")
    def test_run_responder(self, mock_post):
        mock_post.return_value = {"id": "resp_job1"}
        result = self.client.run_responder("Mailer_1_0", {"title": "Test Case"})
        self.assertEqual(result["id"], "resp_job1")
        self.assertEqual(self.client._stats["responder_runs"], 1)

    # --- Stats ---

    def test_get_stats(self):
        stats = self.client.get_stats()
        self.assertIn("jobs_submitted", stats)
        self.assertIn("cache_hits", stats)

    def test_reset_stats(self):
        self.client._stats["jobs_submitted"] = 10
        self.client.reset_stats()
        self.assertEqual(self.client._stats["jobs_submitted"], 0)

    def test_get_status(self):
        with patch.object(CortexAnalyzerClient, "check_connection", return_value=ConnectionStatus.CONNECTED):
            status = self.client.get_status()
            self.assertTrue(status["configured"])
            self.assertEqual(status["connection"], "connected")
            self.assertIn("stats", status)
            self.assertIn("cache", status)


# ============================================================================
# Test: Flask Blueprint
# ============================================================================

class TestCortexBlueprint(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = AnalysisCache(db_path=os.path.join(self.tmpdir, "bp_test.db"))
        self.client = CortexAnalyzerClient(
            base_url="http://localhost:9001",
            api_key="testkey",
            cache=self.cache,
            poll_interval=0.05,
            poll_max_wait=1.0,
        )
        try:
            from flask import Flask
            self.app = Flask(__name__)
            bp = create_cortex_blueprint(self.client)
            self.app.register_blueprint(bp)
            self.flask_client = self.app.test_client()
            self.flask_available = True
        except ImportError:
            self.flask_available = False

    def test_status_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexAnalyzerClient, "check_connection", return_value=ConnectionStatus.CONNECTED):
            resp = self.flask_client.get("/api/v1/soc/cortex/status")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertTrue(data["data"]["configured"])

    def test_analyzers_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", return_value=[
            {"id": "VT", "name": "VirusTotal", "dataTypeList": ["ip"]}
        ]):
            resp = self.flask_client.get("/api/v1/soc/cortex/analyzers")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])
            self.assertEqual(len(data["data"]), 1)

    def test_analyzers_error(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", side_effect=CortexAPIError("fail")):
            resp = self.flask_client.get("/api/v1/soc/cortex/analyzers")
            self.assertEqual(resp.status_code, 502)

    def test_get_analyzer_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", return_value={"id": "VT", "name": "VT"}):
            resp = self.flask_client.get("/api/v1/soc/cortex/analyzers/VT")
            self.assertEqual(resp.status_code, 200)

    def test_get_analyzer_not_found(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", side_effect=CortexNotFoundError("nope")):
            resp = self.flask_client.get("/api/v1/soc/cortex/analyzers/NOPE")
            self.assertEqual(resp.status_code, 404)

    def test_responders_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", return_value=[]):
            resp = self.flask_client.get("/api/v1/soc/cortex/responders")
            self.assertEqual(resp.status_code, 200)

    def test_analyze_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexAnalyzerClient, "analyze") as mock_analyze:
            mock_analyze.return_value = AnalysisReport(
                job_id="j1", analyzer_id="VT", status="Success", data="1.2.3.4", data_type="ip"
            )
            resp = self.flask_client.post(
                "/api/v1/soc/cortex/analyze",
                json={"data": "1.2.3.4", "dataType": "ip", "analyzerId": "VT"},
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertTrue(data["success"])

    def test_analyze_missing_fields(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        resp = self.flask_client.post("/api/v1/soc/cortex/analyze", json={"data": "1.2.3.4"})
        self.assertEqual(resp.status_code, 400)

    def test_analyze_timeout(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexAnalyzerClient, "analyze", side_effect=CortexTimeoutError("timeout")):
            resp = self.flask_client.post(
                "/api/v1/soc/cortex/analyze",
                json={"data": "x", "dataType": "ip", "analyzerId": "VT"},
            )
            self.assertEqual(resp.status_code, 408)

    def test_analyze_batch_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexAnalyzerClient, "analyze_observable") as mock:
            mock.return_value = AnalysisBatchResult(observable="x", data_type="ip")
            resp = self.flask_client.post(
                "/api/v1/soc/cortex/analyze/batch",
                json={"data": "1.2.3.4", "dataType": "ip"},
            )
            self.assertEqual(resp.status_code, 200)

    def test_analyze_batch_missing_fields(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        resp = self.flask_client.post("/api/v1/soc/cortex/analyze/batch", json={})
        self.assertEqual(resp.status_code, 400)

    def test_run_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "post", return_value={"id": "j1"}):
            resp = self.flask_client.post(
                "/api/v1/soc/cortex/run",
                json={"data": "1.2.3.4", "dataType": "ip", "analyzerId": "VT"},
            )
            self.assertEqual(resp.status_code, 200)

    def test_run_missing_fields(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        resp = self.flask_client.post("/api/v1/soc/cortex/run", json={"data": "x"})
        self.assertEqual(resp.status_code, 400)

    def test_job_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", return_value={"id": "j1", "status": "Success"}):
            resp = self.flask_client.get("/api/v1/soc/cortex/job/j1")
            self.assertEqual(resp.status_code, 200)

    def test_job_not_found(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", side_effect=CortexNotFoundError("nope")):
            resp = self.flask_client.get("/api/v1/soc/cortex/job/nope")
            self.assertEqual(resp.status_code, 404)

    def test_job_report_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "get", return_value={"summary": {}}):
            resp = self.flask_client.get("/api/v1/soc/cortex/job/j1/report")
            self.assertEqual(resp.status_code, 200)

    def test_delete_job_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "delete", return_value={}):
            resp = self.flask_client.delete("/api/v1/soc/cortex/job/j1")
            self.assertEqual(resp.status_code, 200)

    def test_run_responder_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        with patch.object(CortexHTTPClient, "post", return_value={"id": "rj1"}):
            resp = self.flask_client.post(
                "/api/v1/soc/cortex/responder/run",
                json={"responderId": "Mailer_1_0", "data": {"title": "test"}},
            )
            self.assertEqual(resp.status_code, 200)

    def test_run_responder_missing_fields(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        resp = self.flask_client.post("/api/v1/soc/cortex/responder/run", json={})
        self.assertEqual(resp.status_code, 400)

    def test_cache_clear_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        resp = self.flask_client.post("/api/v1/soc/cortex/cache/clear")
        self.assertEqual(resp.status_code, 200)

    def test_cache_stats_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        resp = self.flask_client.get("/api/v1/soc/cortex/cache/stats")
        self.assertEqual(resp.status_code, 200)

    def test_stats_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not available")
        resp = self.flask_client.get("/api/v1/soc/cortex/stats")
        self.assertEqual(resp.status_code, 200)


# ============================================================================
# Test: Global Singleton
# ============================================================================

class TestGlobalSingleton(unittest.TestCase):
    def setUp(self):
        reset_global_client()

    def tearDown(self):
        reset_global_client()

    def test_returns_instance(self):
        c = get_cortex_client()
        self.assertIsInstance(c, CortexAnalyzerClient)

    def test_same_instance(self):
        c1 = get_cortex_client()
        c2 = get_cortex_client()
        self.assertIs(c1, c2)

    def test_reset(self):
        c1 = get_cortex_client()
        reset_global_client()
        c2 = get_cortex_client()
        self.assertIsNot(c1, c2)


# ============================================================================
# Test: Blueprint without Flask
# ============================================================================

class TestBlueprintNoFlask(unittest.TestCase):
    def test_no_flask_returns_none(self):
        import importlib
        import modules.enrichment.cortex_analyzer as mod
        original = None
        # Save flask if present
        if "flask" in sys.modules:
            original = sys.modules["flask"]
        sys.modules["flask"] = None  # Block import
        try:
            result = mod.create_cortex_blueprint()
            self.assertIsNone(result)
        finally:
            if original is not None:
                sys.modules["flask"] = original
            elif "flask" in sys.modules:
                del sys.modules["flask"]


# ============================================================================
# Test: Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    def test_analyzer_info_empty_dict(self):
        a = AnalyzerInfo.from_dict({})
        self.assertEqual(a.id, "")
        self.assertEqual(a.data_type_list, [])

    def test_responder_info_empty_dict(self):
        r = ResponderInfo.from_dict({})
        self.assertEqual(r.id, "")

    def test_taxonomy_empty_dict(self):
        t = Taxonomy.from_dict({})
        self.assertEqual(t.level, "info")

    def test_artifact_empty_dict(self):
        a = Artifact.from_dict({})
        self.assertEqual(a.data_type, "")

    def test_report_no_taxonomies(self):
        r = AnalysisReport()
        self.assertEqual(r.max_severity, "info")
        self.assertFalse(r.malicious)
        self.assertFalse(r.suspicious)

    def test_report_parse_report_no_summary(self):
        r = AnalysisReport()
        r._parse_report({"artifacts": [{"dataType": "ip", "data": "1.2.3.4"}]})
        self.assertEqual(len(r.artifacts), 1)
        self.assertEqual(len(r.taxonomies), 0)

    def test_report_parse_report_non_dict_summary(self):
        r = AnalysisReport()
        r._parse_report({"summary": "not a dict"})
        self.assertEqual(len(r.taxonomies), 0)

    def test_report_parse_report_non_dict_taxonomy(self):
        r = AnalysisReport()
        r._parse_report({"summary": {"taxonomies": ["not_a_dict", {"level": "safe"}]}})
        self.assertEqual(len(r.taxonomies), 1)

    def test_batch_result_empty(self):
        b = AnalysisBatchResult()
        self.assertFalse(b.any_malicious)
        self.assertEqual(b.max_severity, "info")

    def test_list_analyzers_non_list_response(self):
        client = CortexAnalyzerClient(base_url="http://localhost", api_key="key")
        with patch.object(CortexHTTPClient, "get", return_value={"error": "bad"}):
            result = client.list_analyzers()
            self.assertEqual(len(result), 0)

    def test_list_analyzers_non_dict_items(self):
        client = CortexAnalyzerClient(base_url="http://localhost", api_key="key")
        with patch.object(CortexHTTPClient, "get", return_value=["not_a_dict", {"id": "valid"}]):
            result = client.list_analyzers()
            self.assertEqual(len(result), 1)

    def test_poll_defaults(self):
        self.assertIn("interval", POLL_DEFAULTS)
        self.assertIn("max_wait", POLL_DEFAULTS)
        self.assertIn("backoff_factor", POLL_DEFAULTS)

    def test_observable_data_type_all(self):
        self.assertEqual(len(ObservableDataType), 11)

    def test_client_env_vars(self):
        with patch.dict(os.environ, {"CORTEX_URL": "http://env.test", "CORTEX_API_KEY": "envkey"}):
            c = CortexAnalyzerClient()
            self.assertEqual(c.base_url, "http://env.test")
            self.assertEqual(c.api_key, "envkey")
            self.assertTrue(c.configured)

    def test_analyze_timeout_propagated(self):
        client = CortexAnalyzerClient(base_url="http://localhost", api_key="key", poll_max_wait=0.1)
        with patch.object(CortexHTTPClient, "post", return_value={"id": "j1"}):
            with patch.object(CortexHTTPClient, "get", return_value={"id": "j1", "status": "InProgress"}):
                with self.assertRaises(CortexTimeoutError):
                    client.analyze("VT", "x", "ip", poll_interval=0.02, max_wait=0.1)

    def test_run_analyzer_with_params(self):
        client = CortexAnalyzerClient(base_url="http://localhost", api_key="key")
        with patch.object(CortexHTTPClient, "post", return_value={"id": "j1"}) as mock_post:
            client.run_analyzer("VT", "1.2.3.4", "ip", tlp=3, pap=1, message="test msg", parameters={"extra": True}, force=True)
            call_data = mock_post.call_args[1]["data"]
            self.assertEqual(call_data["tlp"], 3)
            self.assertEqual(call_data["pap"], 1)
            self.assertEqual(call_data["message"], "test msg")
            self.assertEqual(call_data["parameters"], {"extra": True})

    def test_run_responder_with_params(self):
        client = CortexAnalyzerClient(base_url="http://localhost", api_key="key")
        with patch.object(CortexHTTPClient, "post", return_value={"id": "rj1"}) as mock_post:
            client.run_responder("R1", {"case": "c1"}, data_type="thehive:alert", tlp=3, message="resp msg", parameters={"x": 1})
            call_data = mock_post.call_args[1]["data"]
            self.assertEqual(call_data["dataType"], "thehive:alert")
            self.assertEqual(call_data["parameters"], {"x": 1})

    def test_cache_thread_safety(self):
        tmpdir = tempfile.mkdtemp()
        cache = AnalysisCache(db_path=os.path.join(tmpdir, "thread_test.db"))
        errors = []

        def writer(i):
            try:
                cache.set(f"obs_{i}", "ip", "VT", {"i": i})
                result = cache.get(f"obs_{i}", "ip", "VT")
                if result is None or result["i"] != i:
                    errors.append(f"Mismatch at {i}")
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 0, f"Thread safety errors: {errors}")


# ============================================================================
# Test: Integration
# ============================================================================

class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = AnalysisCache(db_path=os.path.join(self.tmpdir, "integ.db"))
        self.client = CortexAnalyzerClient(
            base_url="http://localhost:9001",
            api_key="testkey",
            cache=self.cache,
            poll_interval=0.05,
            poll_max_wait=1.0,
        )

    @patch.object(CortexHTTPClient, "get")
    @patch.object(CortexHTTPClient, "post")
    def test_full_analyze_cache_reuse(self, mock_post, mock_get):
        """First call hits API, second call uses cache."""
        mock_post.return_value = {"id": "j1"}
        mock_get.side_effect = [
            {"id": "j1", "analyzerId": "VT", "status": "Success", "data": "8.8.8.8", "dataType": "ip"},
            {"summary": {"taxonomies": [{"level": "safe", "namespace": "VT", "predicate": "score", "value": "0"}]}},
        ]
        r1 = self.client.analyze("VT", "8.8.8.8", "ip")
        self.assertTrue(r1.success)
        self.assertEqual(self.client._stats["cache_misses"], 2)  # analyze() miss + run_analyzer(force=True) miss

        # Second call should be cached
        r2 = self.client.analyze("VT", "8.8.8.8", "ip")
        self.assertEqual(self.client._stats["cache_hits"], 1)
        # API should NOT be called again
        self.assertEqual(mock_post.call_count, 1)

    @patch.object(CortexHTTPClient, "get")
    @patch.object(CortexHTTPClient, "post")
    def test_batch_with_mixed_results(self, mock_post, mock_get):
        """Batch analysis with one success and one failure."""
        # First analyzer succeeds
        mock_post.side_effect = [{"id": "j1"}, {"id": "j2"}]
        mock_get.side_effect = [
            {"id": "j1", "analyzerId": "VT", "status": "Success", "data": "x", "dataType": "ip"},
            {"summary": {"taxonomies": [{"level": "malicious", "namespace": "VT", "predicate": "score", "value": "50"}]}},
            {"id": "j2", "analyzerId": "AB", "status": "Failure", "data": "x", "dataType": "ip"},
        ]
        result = self.client.analyze_observable("x", "ip", analyzer_ids=["VT", "AB"])
        self.assertEqual(len(result.reports), 2)
        self.assertTrue(result.reports[0].success)
        self.assertFalse(result.reports[1].success)
        self.assertTrue(result.any_malicious)

    def test_stats_tracking(self):
        """Stats accumulate correctly."""
        self.assertEqual(self.client._stats["jobs_submitted"], 0)
        with patch.object(CortexHTTPClient, "post", return_value={"id": "j"}):
            self.client.run_analyzer("VT", "x", "ip", force=True)
        self.assertEqual(self.client._stats["jobs_submitted"], 1)

        with patch.object(CortexHTTPClient, "post", return_value={"id": "rj"}):
            self.client.run_responder("R1", {"x": 1})
        self.assertEqual(self.client._stats["responder_runs"], 1)


if __name__ == "__main__":
    unittest.main()
