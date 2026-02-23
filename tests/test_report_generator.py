#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive test suite for TSUNAMI SOC Compliance Report Generator.
Covers: Enums, Data Classes, Mappings, ComplianceStore, PDFReportGenerator,
        ComplianceReportEngine, Flask Blueprint, Global Singleton, Integration.
"""

import json
import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from io import BytesIO
from unittest.mock import MagicMock, patch, PropertyMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.compliance.report_generator import (
    # Enums
    ComplianceFramework, ReportType, ReportFormat, ReportPeriod,
    ControlStatus, NISTPhase, SeverityLevel,
    # Mappings
    NIST_800_61_PHASES, ISO_27001_DOMAINS, KVKK_NOTIFICATION_FIELDS,
    # Data classes
    ControlAssessment, IncidentRecord, BreachNotification, ComplianceReport,
    # Store
    ComplianceStore,
    # PDF
    PDFReportGenerator,
    # Engine
    ComplianceReportEngine,
    # Blueprint
    create_compliance_blueprint,
    # Singleton
    get_compliance_engine, reset_global_engine,
)


# =============================================================================
#   ENUM TESTS
# =============================================================================


class TestComplianceFramework(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ComplianceFramework.NIST_800_61.value, "nist_800_61")
        self.assertEqual(ComplianceFramework.ISO_27001.value, "iso_27001")
        self.assertEqual(ComplianceFramework.KVKK.value, "kvkk")
        self.assertEqual(ComplianceFramework.GDPR.value, "gdpr")

    def test_count(self):
        self.assertEqual(len(ComplianceFramework), 4)


class TestReportType(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ReportType.INCIDENT.value, "incident")
        self.assertEqual(ReportType.BREACH_NOTIFICATION.value, "breach_notification")
        self.assertEqual(ReportType.EXECUTIVE_SUMMARY.value, "executive_summary")
        self.assertEqual(ReportType.PERIODIC.value, "periodic")
        self.assertEqual(ReportType.GAP_ANALYSIS.value, "gap_analysis")
        self.assertEqual(ReportType.COMPLIANCE_AUDIT.value, "compliance_audit")

    def test_count(self):
        self.assertEqual(len(ReportType), 6)


class TestReportFormat(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ReportFormat.PDF.value, "pdf")
        self.assertEqual(ReportFormat.JSON.value, "json")
        self.assertEqual(ReportFormat.HTML.value, "html")


class TestReportPeriod(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ReportPeriod.DAILY.value, "daily")
        self.assertEqual(ReportPeriod.WEEKLY.value, "weekly")
        self.assertEqual(ReportPeriod.MONTHLY.value, "monthly")
        self.assertEqual(ReportPeriod.QUARTERLY.value, "quarterly")
        self.assertEqual(ReportPeriod.ANNUAL.value, "annual")

    def test_count(self):
        self.assertEqual(len(ReportPeriod), 5)


class TestControlStatus(unittest.TestCase):
    def test_values(self):
        self.assertEqual(ControlStatus.IMPLEMENTED.value, "implemented")
        self.assertEqual(ControlStatus.PARTIALLY_IMPLEMENTED.value, "partially_implemented")
        self.assertEqual(ControlStatus.PLANNED.value, "planned")
        self.assertEqual(ControlStatus.NOT_IMPLEMENTED.value, "not_implemented")
        self.assertEqual(ControlStatus.NOT_APPLICABLE.value, "not_applicable")


class TestNISTPhase(unittest.TestCase):
    def test_values(self):
        self.assertEqual(NISTPhase.PREPARATION.value, "preparation")
        self.assertEqual(NISTPhase.DETECTION_ANALYSIS.value, "detection_analysis")
        self.assertEqual(NISTPhase.CONTAINMENT_ERADICATION_RECOVERY.value, "containment_eradication_recovery")
        self.assertEqual(NISTPhase.POST_INCIDENT.value, "post_incident")


class TestSeverityLevel(unittest.TestCase):
    def test_values(self):
        self.assertEqual(SeverityLevel.CRITICAL.value, "critical")
        self.assertEqual(SeverityLevel.HIGH.value, "high")
        self.assertEqual(SeverityLevel.MEDIUM.value, "medium")
        self.assertEqual(SeverityLevel.LOW.value, "low")
        self.assertEqual(SeverityLevel.INFO.value, "info")


# =============================================================================
#   MAPPING TESTS
# =============================================================================


class TestMappings(unittest.TestCase):
    def test_nist_phases_has_all_phases(self):
        self.assertIn("preparation", NIST_800_61_PHASES)
        self.assertIn("detection_analysis", NIST_800_61_PHASES)
        self.assertIn("containment_eradication_recovery", NIST_800_61_PHASES)
        self.assertIn("post_incident", NIST_800_61_PHASES)

    def test_nist_phases_have_controls(self):
        for phase, data in NIST_800_61_PHASES.items():
            self.assertIn("controls", data)
            self.assertTrue(len(data["controls"]) > 0)
            for ctrl in data["controls"]:
                self.assertIn("id", ctrl)
                self.assertIn("name", ctrl)

    def test_iso_domains_has_expected(self):
        self.assertIn("A5", ISO_27001_DOMAINS)
        self.assertIn("A6", ISO_27001_DOMAINS)
        self.assertIn("A7", ISO_27001_DOMAINS)
        self.assertIn("A8", ISO_27001_DOMAINS)

    def test_iso_domains_have_controls(self):
        for domain, data in ISO_27001_DOMAINS.items():
            self.assertIn("controls", data)
            self.assertTrue(len(data["controls"]) > 0)

    def test_kvkk_fields(self):
        self.assertTrue(len(KVKK_NOTIFICATION_FIELDS) >= 10)
        for f in KVKK_NOTIFICATION_FIELDS:
            self.assertIn("id", f)
            self.assertIn("field", f)
            self.assertIn("label", f)


# =============================================================================
#   DATA CLASS TESTS
# =============================================================================


class TestControlAssessment(unittest.TestCase):
    def test_default(self):
        a = ControlAssessment(control_id="PR-1")
        self.assertEqual(a.control_id, "PR-1")
        self.assertTrue(a.id)
        self.assertTrue(a.assessed_at)
        self.assertEqual(a.status, "not_implemented")
        self.assertEqual(a.score, 0.0)

    def test_with_values(self):
        a = ControlAssessment(
            control_id="DA-2", control_name="SIEM Integration",
            framework="nist_800_61", status="implemented", score=0.9,
            evidence="Wazuh deployed", assessor="analyst1"
        )
        self.assertEqual(a.control_name, "SIEM Integration")
        self.assertEqual(a.score, 0.9)

    def test_to_dict(self):
        a = ControlAssessment(control_id="PR-1", id="test-id")
        d = a.to_dict()
        self.assertEqual(d["control_id"], "PR-1")
        self.assertEqual(d["id"], "test-id")

    def test_from_dict(self):
        d = {"control_id": "DA-1", "status": "implemented", "score": 0.8, "id": "abc"}
        a = ControlAssessment.from_dict(d)
        self.assertEqual(a.control_id, "DA-1")
        self.assertEqual(a.status, "implemented")
        self.assertEqual(a.id, "abc")

    def test_roundtrip(self):
        a = ControlAssessment(control_id="CER-1", score=0.75, framework="nist_800_61")
        d = a.to_dict()
        a2 = ControlAssessment.from_dict(d)
        self.assertEqual(a.control_id, a2.control_id)
        self.assertEqual(a.score, a2.score)
        self.assertEqual(a.id, a2.id)


class TestIncidentRecord(unittest.TestCase):
    def test_default(self):
        i = IncidentRecord(incident_id="INC-001")
        self.assertEqual(i.incident_id, "INC-001")
        self.assertTrue(i.id)
        self.assertEqual(i.severity, "medium")
        self.assertEqual(i.status, "open")
        self.assertIsInstance(i.affected_assets, list)

    def test_with_values(self):
        i = IncidentRecord(
            incident_id="INC-002", title="Brute Force",
            severity="critical", category="auth_attack",
            affected_assets=["server-01"], iocs=["10.0.0.1"],
            actions_taken=["blocked IP"]
        )
        self.assertEqual(i.title, "Brute Force")
        self.assertEqual(len(i.affected_assets), 1)

    def test_roundtrip(self):
        i = IncidentRecord(incident_id="INC-003", title="Test",
                           affected_assets=["a", "b"], iocs=["x"])
        d = i.to_dict()
        i2 = IncidentRecord.from_dict(d)
        self.assertEqual(i.incident_id, i2.incident_id)
        self.assertEqual(i.affected_assets, i2.affected_assets)


class TestBreachNotification(unittest.TestCase):
    def test_default(self):
        b = BreachNotification(breach_id="BRE-001")
        self.assertEqual(b.breach_id, "BRE-001")
        self.assertTrue(b.id)
        self.assertEqual(b.severity, "high")
        self.assertEqual(b.framework, "kvkk")
        self.assertFalse(b.data_subjects_notified)
        self.assertFalse(b.cross_border)

    def test_with_values(self):
        b = BreachNotification(
            breach_id="BRE-002",
            breach_description="Data leak",
            data_categories=["email", "phone"],
            affected_count=5000,
            dpo_contact="dpo@example.com",
            cross_border=True,
        )
        self.assertEqual(b.affected_count, 5000)
        self.assertTrue(b.cross_border)
        self.assertEqual(len(b.data_categories), 2)

    def test_roundtrip(self):
        b = BreachNotification(breach_id="BRE-003", data_categories=["name", "tc_no"])
        d = b.to_dict()
        b2 = BreachNotification.from_dict(d)
        self.assertEqual(b.breach_id, b2.breach_id)
        self.assertEqual(b.data_categories, b2.data_categories)


class TestComplianceReport(unittest.TestCase):
    def test_default(self):
        r = ComplianceReport(report_id="RPT-001")
        self.assertEqual(r.report_id, "RPT-001")
        self.assertTrue(r.generated_at)
        self.assertEqual(r.format, "json")

    def test_with_findings(self):
        r = ComplianceReport(
            report_id="RPT-002",
            title="Test Report",
            findings=[{"control_id": "PR-1", "status": "not_implemented"}],
            total_score=0.65,
        )
        self.assertEqual(len(r.findings), 1)
        self.assertEqual(r.total_score, 0.65)

    def test_roundtrip(self):
        r = ComplianceReport(
            report_id="RPT-003",
            findings=[{"a": 1}],
            data={"test": True},
        )
        d = r.to_dict()
        r2 = ComplianceReport.from_dict(d)
        self.assertEqual(r.report_id, r2.report_id)
        self.assertEqual(r.findings, r2.findings)


# =============================================================================
#   COMPLIANCE STORE TESTS
# =============================================================================


class TestComplianceStore(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_compliance.db")
        self.store = ComplianceStore(db_path=self.db_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_init_creates_db(self):
        self.assertTrue(os.path.exists(self.db_path))

    def test_default_path(self):
        s = ComplianceStore.__new__(ComplianceStore)
        s.__init__()
        self.assertIn("compliance.db", s.db_path)

    # -- Assessments --

    def test_save_and_get_assessment(self):
        a = ControlAssessment(control_id="PR-1", framework="nist_800_61", score=0.8)
        self.store.save_assessment(a)
        retrieved = self.store.get_assessment(a.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.control_id, "PR-1")
        self.assertEqual(retrieved.score, 0.8)

    def test_get_assessment_not_found(self):
        self.assertIsNone(self.store.get_assessment("nonexistent"))

    def test_list_assessments(self):
        for i in range(5):
            a = ControlAssessment(control_id=f"CTRL-{i}", framework="nist_800_61")
            self.store.save_assessment(a)
        results = self.store.list_assessments(framework="nist_800_61")
        self.assertEqual(len(results), 5)

    def test_list_assessments_filter_status(self):
        a1 = ControlAssessment(control_id="C1", framework="nist_800_61", status="implemented")
        a2 = ControlAssessment(control_id="C2", framework="nist_800_61", status="not_implemented")
        self.store.save_assessment(a1)
        self.store.save_assessment(a2)
        results = self.store.list_assessments(framework="nist_800_61", status="implemented")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].status, "implemented")

    def test_list_assessments_pagination(self):
        for i in range(10):
            self.store.save_assessment(ControlAssessment(control_id=f"C-{i}", framework="iso_27001"))
        page = self.store.list_assessments(framework="iso_27001", limit=3, offset=0)
        self.assertEqual(len(page), 3)

    def test_framework_score(self):
        self.store.save_assessment(ControlAssessment(control_id="A", framework="iso_27001", status="implemented", score=0.9))
        self.store.save_assessment(ControlAssessment(control_id="B", framework="iso_27001", status="not_implemented", score=0.2))
        score = self.store.get_framework_score("iso_27001")
        self.assertEqual(score["total"], 2)
        self.assertAlmostEqual(score["average_score"], 0.55, places=2)

    def test_framework_score_empty(self):
        score = self.store.get_framework_score("unknown_framework")
        self.assertEqual(score["total"], 0)
        self.assertEqual(score["average_score"], 0.0)

    # -- Incidents --

    def test_save_and_get_incident(self):
        i = IncidentRecord(incident_id="INC-001", title="Test Incident", severity="high",
                           affected_assets=["srv-1"], iocs=["1.2.3.4"])
        self.store.save_incident(i)
        retrieved = self.store.get_incident(i.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, "Test Incident")
        self.assertEqual(retrieved.affected_assets, ["srv-1"])

    def test_get_incident_by_incident_id(self):
        i = IncidentRecord(incident_id="INC-LOOKUP", title="Lookup Test")
        self.store.save_incident(i)
        retrieved = self.store.get_incident("INC-LOOKUP")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, "Lookup Test")

    def test_get_incident_not_found(self):
        self.assertIsNone(self.store.get_incident("nonexistent"))

    def test_list_incidents(self):
        for i in range(3):
            self.store.save_incident(IncidentRecord(incident_id=f"INC-{i}", severity="medium"))
        results = self.store.list_incidents()
        self.assertEqual(len(results), 3)

    def test_list_incidents_filter_severity(self):
        self.store.save_incident(IncidentRecord(incident_id="A", severity="critical"))
        self.store.save_incident(IncidentRecord(incident_id="B", severity="low"))
        results = self.store.list_incidents(severity="critical")
        self.assertEqual(len(results), 1)

    def test_list_incidents_filter_date(self):
        i = IncidentRecord(incident_id="DT", detected_at="2025-01-15T00:00:00+00:00")
        self.store.save_incident(i)
        results = self.store.list_incidents(start_date="2025-01-01", end_date="2025-02-01")
        self.assertEqual(len(results), 1)

    def test_incident_stats(self):
        self.store.save_incident(IncidentRecord(incident_id="S1", severity="critical", status="open",
                                                 nist_phase="detection_analysis"))
        self.store.save_incident(IncidentRecord(incident_id="S2", severity="high", status="resolved",
                                                 nist_phase="post_incident"))
        stats = self.store.get_incident_stats()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_status"]["resolved"], 1)

    # -- Breaches --

    def test_save_and_get_breach(self):
        b = BreachNotification(breach_id="BRE-001", breach_description="Data leak",
                               data_categories=["email"], cross_border=True)
        self.store.save_breach(b)
        retrieved = self.store.get_breach(b.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.breach_description, "Data leak")
        self.assertTrue(retrieved.cross_border)
        self.assertEqual(retrieved.data_categories, ["email"])

    def test_get_breach_by_breach_id(self):
        b = BreachNotification(breach_id="BRE-LOOKUP")
        self.store.save_breach(b)
        retrieved = self.store.get_breach("BRE-LOOKUP")
        self.assertIsNotNone(retrieved)

    def test_get_breach_not_found(self):
        self.assertIsNone(self.store.get_breach("nonexistent"))

    def test_list_breaches(self):
        for i in range(3):
            self.store.save_breach(BreachNotification(breach_id=f"B-{i}"))
        results = self.store.list_breaches()
        self.assertEqual(len(results), 3)

    def test_list_breaches_filter_framework(self):
        self.store.save_breach(BreachNotification(breach_id="BK", framework="kvkk"))
        self.store.save_breach(BreachNotification(breach_id="BG", framework="gdpr"))
        results = self.store.list_breaches(framework="kvkk")
        self.assertEqual(len(results), 1)

    # -- Reports --

    def test_save_and_get_report(self):
        r = ComplianceReport(report_id="RPT-001", title="Test", findings=[{"a": 1}],
                             data={"key": "val"})
        self.store.save_report(r)
        retrieved = self.store.get_report(r.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.title, "Test")
        self.assertEqual(retrieved.findings, [{"a": 1}])
        self.assertEqual(retrieved.data["key"], "val")

    def test_get_report_not_found(self):
        self.assertIsNone(self.store.get_report("nonexistent"))

    def test_list_reports(self):
        for i in range(3):
            self.store.save_report(ComplianceReport(report_id=f"R-{i}"))
        results = self.store.list_reports()
        self.assertEqual(len(results), 3)

    def test_list_reports_filter(self):
        self.store.save_report(ComplianceReport(report_id="R1", report_type="compliance_audit", framework="nist_800_61"))
        self.store.save_report(ComplianceReport(report_id="R2", report_type="executive_summary", framework="iso_27001"))
        results = self.store.list_reports(report_type="compliance_audit")
        self.assertEqual(len(results), 1)

    # -- Thread Safety --

    def test_thread_safety(self):
        errors = []

        def worker(n):
            try:
                a = ControlAssessment(control_id=f"T-{n}", framework="nist_800_61")
                self.store.save_assessment(a)
                self.store.get_assessment(a.id)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 0)


# =============================================================================
#   PDF REPORT GENERATOR TESTS
# =============================================================================


class TestPDFReportGenerator(unittest.TestCase):
    def setUp(self):
        self.pdf = PDFReportGenerator()

    def test_available(self):
        self.assertTrue(self.pdf.available)

    def test_generate_nist_report(self):
        incidents = [
            IncidentRecord(incident_id="INC-1", title="Test Alert", severity="critical",
                           nist_phase="detection_analysis"),
            IncidentRecord(incident_id="INC-2", title="Low Alert", severity="low",
                           nist_phase="post_incident"),
        ]
        assessments = [
            ControlAssessment(control_id="PR-1", control_name="IR Plan",
                              status="implemented", score=0.9),
            ControlAssessment(control_id="DA-1", control_name="Log Collection",
                              status="not_implemented", score=0.2),
        ]
        result = self.pdf.generate_nist_report(
            "NIST Test Report", incidents, assessments,
            "2025-01-01", "2025-01-31"
        )
        self.assertIsNotNone(result)
        self.assertIsInstance(result, bytes)
        self.assertTrue(len(result) > 100)
        # PDF magic bytes
        self.assertTrue(result[:5] == b"%PDF-")

    def test_generate_nist_report_empty(self):
        result = self.pdf.generate_nist_report(
            "Empty Report", [], [], "2025-01-01", "2025-01-31"
        )
        self.assertIsNotNone(result)
        self.assertTrue(result[:5] == b"%PDF-")

    def test_generate_iso27001_report(self):
        assessments = [
            ControlAssessment(control_id="A.5.1", control_name="Policies",
                              status="implemented", score=0.95),
        ]
        result = self.pdf.generate_iso27001_report(
            "ISO Test", assessments, "2025-01-01", "2025-01-31"
        )
        self.assertIsNotNone(result)
        self.assertTrue(result[:5] == b"%PDF-")

    def test_generate_iso27001_report_empty(self):
        result = self.pdf.generate_iso27001_report(
            "Empty ISO", [], "2025-01-01", "2025-01-31"
        )
        self.assertIsNotNone(result)

    def test_generate_breach_report(self):
        breach = BreachNotification(
            breach_id="BRE-001",
            breach_date="2025-01-10",
            breach_description="Unauthorized access to customer database",
            data_categories=["email", "name", "phone"],
            affected_count=10000,
            dpo_contact="dpo@company.com",
            measures_taken="Password reset enforced",
            consequences="Potential identity theft",
        )
        result = self.pdf.generate_breach_report("Breach Report", breach)
        self.assertIsNotNone(result)
        self.assertTrue(result[:5] == b"%PDF-")

    def test_generate_executive_summary(self):
        stats = {"total": 15, "by_severity": {"critical": 2, "high": 5},
                 "by_status": {"open": 3, "resolved": 12}}
        scores = {"nist_800_61": {"total": 20, "average_score": 0.75}}
        result = self.pdf.generate_executive_summary(
            "Exec Summary", stats, scores, 2, "2025-01-01", "2025-01-31"
        )
        self.assertIsNotNone(result)
        self.assertTrue(result[:5] == b"%PDF-")

    def test_no_reportlab(self):
        pdf = PDFReportGenerator.__new__(PDFReportGenerator)
        pdf._reportlab_available = False
        self.assertFalse(pdf.available)
        self.assertIsNone(pdf.generate_nist_report("T", [], [], "a", "b"))
        self.assertIsNone(pdf.generate_iso27001_report("T", [], "a", "b"))
        self.assertIsNone(pdf.generate_breach_report("T", BreachNotification(breach_id="X")))
        self.assertIsNone(pdf.generate_executive_summary("T", {}, {}, 0, "a", "b"))


# =============================================================================
#   COMPLIANCE REPORT ENGINE TESTS
# =============================================================================


class TestComplianceReportEngine(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test.db")
        self.out_dir = os.path.join(self.tmpdir, "reports")
        self.store = ComplianceStore(db_path=self.db_path)
        self.engine = ComplianceReportEngine(
            store=self.store, output_dir=self.out_dir
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- NIST --

    def test_get_nist_controls(self):
        controls = self.engine.get_nist_controls()
        self.assertEqual(len(controls), 4)
        self.assertIn("preparation", controls)

    def test_assess_nist_control(self):
        a = self.engine.assess_nist_control(
            control_id="PR-1", status="implemented", score=0.85,
            evidence="Plan documented", assessor="analyst"
        )
        self.assertEqual(a.control_id, "PR-1")
        self.assertEqual(a.framework, "nist_800_61")
        self.assertEqual(a.control_name, "Incident Response Plan")
        # Verify persisted
        retrieved = self.store.get_assessment(a.id)
        self.assertIsNotNone(retrieved)

    def test_assess_nist_control_score_clamped(self):
        a = self.engine.assess_nist_control("PR-2", "implemented", 1.5)
        self.assertEqual(a.score, 1.0)
        a2 = self.engine.assess_nist_control("PR-3", "not_implemented", -0.5)
        self.assertEqual(a2.score, 0.0)

    def test_assess_nist_control_unknown(self):
        a = self.engine.assess_nist_control("UNKNOWN-99", "planned", 0.3)
        self.assertEqual(a.control_name, "")

    def test_assess_nist_callback(self):
        cb = MagicMock()
        self.engine.register_callback("assessment_saved", cb)
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        cb.assert_called_once()
        self.assertEqual(cb.call_args[0][0], "assessment_saved")

    def test_generate_nist_report_json(self):
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        self.engine.assess_nist_control("DA-1", "not_implemented", 0.1)
        self.store.save_incident(IncidentRecord(incident_id="I1", severity="critical",
                                                 nist_phase="detection_analysis",
                                                 detected_at="2025-01-15T00:00:00+00:00"))
        report = self.engine.generate_nist_report("2025-01-01", "2025-02-01", "json")
        self.assertEqual(report.framework, "nist_800_61")
        self.assertEqual(report.control_count, 2)
        self.assertEqual(report.implemented_count, 1)
        self.assertEqual(report.gap_count, 1)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.data["incident_count"], 1)

    def test_generate_nist_report_pdf(self):
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        report = self.engine.generate_nist_report("2025-01-01", "2025-02-01", "pdf")
        self.assertTrue(report.file_path.endswith(".pdf"))
        self.assertTrue(os.path.exists(report.file_path))

    def test_generate_nist_report_callback(self):
        cb = MagicMock()
        self.engine.register_callback("report_generated", cb)
        self.engine.generate_nist_report("2025-01-01", "2025-02-01")
        cb.assert_called_once()

    # -- ISO 27001 --

    def test_get_iso27001_controls(self):
        controls = self.engine.get_iso27001_controls()
        self.assertIn("A5", controls)
        self.assertIn("A8", controls)

    def test_assess_iso27001_control(self):
        a = self.engine.assess_iso27001_control(
            control_id="A.5.1", status="implemented", score=0.95
        )
        self.assertEqual(a.framework, "iso_27001")
        self.assertEqual(a.control_name, "Policies for information security")

    def test_assess_iso27001_unknown(self):
        a = self.engine.assess_iso27001_control("A.99.99", "planned", 0.1)
        self.assertEqual(a.control_name, "")

    def test_generate_iso27001_report_json(self):
        self.engine.assess_iso27001_control("A.5.1", "implemented", 0.9)
        self.engine.assess_iso27001_control("A.8.7", "not_implemented", 0.1)
        report = self.engine.generate_iso27001_report("2025-01-01", "2025-02-01", "json")
        self.assertEqual(report.framework, "iso_27001")
        self.assertEqual(report.control_count, 2)
        self.assertEqual(report.gap_count, 1)

    def test_generate_iso27001_report_pdf(self):
        self.engine.assess_iso27001_control("A.5.1", "implemented", 0.9)
        report = self.engine.generate_iso27001_report("2025-01-01", "2025-02-01", "pdf")
        self.assertTrue(os.path.exists(report.file_path))

    # -- Breaches --

    def test_create_breach(self):
        b = self.engine.create_breach_notification(
            breach_description="Test breach",
            data_categories=["email"],
            affected_count=100,
        )
        self.assertIsNotNone(b.breach_id)
        self.assertEqual(b.affected_count, 100)
        retrieved = self.store.get_breach(b.breach_id)
        self.assertIsNotNone(retrieved)

    def test_create_breach_callback(self):
        cb = MagicMock()
        self.engine.register_callback("breach_created", cb)
        self.engine.create_breach_notification(breach_description="Test")
        cb.assert_called_once()

    def test_update_breach(self):
        b = self.engine.create_breach_notification(breach_description="Initial")
        updated = self.engine.update_breach_notification(
            b.breach_id, breach_description="Updated", status="submitted"
        )
        self.assertIsNotNone(updated)
        self.assertEqual(updated.breach_description, "Updated")
        self.assertEqual(updated.status, "submitted")

    def test_update_breach_not_found(self):
        result = self.engine.update_breach_notification("nonexistent", status="x")
        self.assertIsNone(result)

    def test_update_breach_callback(self):
        cb = MagicMock()
        self.engine.register_callback("breach_updated", cb)
        b = self.engine.create_breach_notification(breach_description="T")
        self.engine.update_breach_notification(b.breach_id, status="submitted")
        cb.assert_called_once()

    def test_generate_breach_report_json(self):
        b = self.engine.create_breach_notification(breach_description="Leak")
        report = self.engine.generate_breach_report(b.breach_id)
        self.assertIsNotNone(report)
        self.assertEqual(report.report_type, "breach_notification")

    def test_generate_breach_report_pdf(self):
        b = self.engine.create_breach_notification(
            breach_description="Leak", breach_date="2025-01-10",
            dpo_contact="dpo@test.com"
        )
        report = self.engine.generate_breach_report(b.breach_id, "pdf")
        self.assertIsNotNone(report)
        self.assertTrue(os.path.exists(report.file_path))

    def test_generate_breach_report_not_found(self):
        self.assertIsNone(self.engine.generate_breach_report("nonexistent"))

    def test_kvkk_fields(self):
        fields = self.engine.get_kvkk_notification_fields()
        self.assertTrue(len(fields) >= 10)

    # -- Executive Summary --

    def test_generate_executive_summary_json(self):
        self.store.save_incident(IncidentRecord(
            incident_id="E1", severity="high", status="open",
            detected_at="2025-01-15T00:00:00+00:00"
        ))
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        report = self.engine.generate_executive_summary("2025-01-01", "2025-02-01")
        self.assertEqual(report.report_type, "executive_summary")
        self.assertIn("incident_stats", report.data)
        self.assertIn("framework_scores", report.data)

    def test_generate_executive_summary_pdf(self):
        report = self.engine.generate_executive_summary("2025-01-01", "2025-02-01", "pdf")
        self.assertTrue(os.path.exists(report.file_path))

    # -- Gap Analysis --

    def test_gap_analysis_nist(self):
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        self.engine.assess_nist_control("PR-2", "not_implemented", 0.1)
        result = self.engine.generate_gap_analysis("nist_800_61")
        self.assertEqual(result["framework"], "nist_800_61")
        self.assertEqual(result["total_assessed"], 2)
        self.assertTrue(result["total_expected"] > 2)
        self.assertTrue(len(result["missing_assessments"]) > 0)
        self.assertEqual(result["gap_count"], 1)

    def test_gap_analysis_iso(self):
        result = self.engine.generate_gap_analysis("iso_27001")
        self.assertEqual(result["total_assessed"], 0)
        self.assertTrue(result["total_expected"] > 0)
        self.assertEqual(result["coverage_pct"], 0)

    def test_gap_analysis_unknown_framework(self):
        result = self.engine.generate_gap_analysis("unknown")
        self.assertEqual(result["total_expected"], 0)

    # -- Periodic Reports --

    def test_get_period_range_daily(self):
        ref = datetime(2025, 6, 15, 10, 30, tzinfo=timezone.utc)
        start, end = self.engine.get_period_range("daily", ref)
        self.assertIn("2025-06-15", start)

    def test_get_period_range_weekly(self):
        ref = datetime(2025, 6, 18, 10, 0, tzinfo=timezone.utc)  # Wednesday
        start, end = self.engine.get_period_range("weekly", ref)
        self.assertIn("2025-06-16", start)  # Monday

    def test_get_period_range_monthly(self):
        ref = datetime(2025, 6, 15, 10, 0, tzinfo=timezone.utc)
        start, end = self.engine.get_period_range("monthly", ref)
        self.assertIn("2025-06-01", start)

    def test_get_period_range_monthly_december(self):
        ref = datetime(2025, 12, 15, 10, 0, tzinfo=timezone.utc)
        start, end = self.engine.get_period_range("monthly", ref)
        self.assertIn("2025-12-01", start)

    def test_get_period_range_quarterly(self):
        ref = datetime(2025, 5, 15, 10, 0, tzinfo=timezone.utc)  # Q2
        start, end = self.engine.get_period_range("quarterly", ref)
        self.assertIn("2025-04-01", start)

    def test_get_period_range_annual(self):
        ref = datetime(2025, 6, 15, 10, 0, tzinfo=timezone.utc)
        start, end = self.engine.get_period_range("annual", ref)
        self.assertIn("2025-01-01", start)

    def test_get_period_range_unknown(self):
        start, end = self.engine.get_period_range("unknown")
        self.assertTrue(start)  # defaults to daily

    def test_generate_periodic_nist(self):
        report = self.engine.generate_periodic_report("monthly", "nist_800_61")
        self.assertEqual(report.framework, "nist_800_61")

    def test_generate_periodic_iso(self):
        report = self.engine.generate_periodic_report("monthly", "iso_27001")
        self.assertEqual(report.framework, "iso_27001")

    def test_generate_periodic_executive(self):
        report = self.engine.generate_periodic_report("monthly")
        self.assertEqual(report.report_type, "executive_summary")

    # -- Incidents --

    def test_record_incident(self):
        inc = self.engine.record_incident(
            title="Brute Force", severity="high",
            affected_assets=["srv-1"], iocs=["10.0.0.1"]
        )
        self.assertIsNotNone(inc.incident_id)
        self.assertEqual(inc.title, "Brute Force")
        retrieved = self.store.get_incident(inc.incident_id)
        self.assertIsNotNone(retrieved)

    def test_record_incident_callback(self):
        cb = MagicMock()
        self.engine.register_callback("incident_recorded", cb)
        self.engine.record_incident(title="Test")
        cb.assert_called_once()

    def test_update_incident(self):
        inc = self.engine.record_incident(title="Init", status="open")
        updated = self.engine.update_incident(inc.incident_id, status="resolved",
                                               resolved_at="2025-01-20T00:00:00+00:00")
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, "resolved")

    def test_update_incident_not_found(self):
        self.assertIsNone(self.engine.update_incident("nonexistent", status="x"))

    def test_update_incident_callback(self):
        cb = MagicMock()
        self.engine.register_callback("incident_updated", cb)
        inc = self.engine.record_incident(title="Test")
        self.engine.update_incident(inc.incident_id, status="resolved")
        cb.assert_called_once()

    # -- Dashboard --

    def test_dashboard_data(self):
        self.store.save_incident(IncidentRecord(incident_id="D1", severity="high",
                                                 detected_at=datetime.now(timezone.utc).isoformat()))
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        data = self.engine.get_dashboard_data()
        self.assertIn("incident_stats", data)
        self.assertIn("framework_scores", data)
        self.assertIn("breach_count", data)
        self.assertIn("recent_reports", data)

    def test_dashboard_data_with_dates(self):
        data = self.engine.get_dashboard_data("2025-01-01", "2025-02-01")
        self.assertEqual(data["period_start"], "2025-01-01")

    # -- Callback Error Handling --

    def test_callback_exception_handled(self):
        def bad_cb(event, data):
            raise RuntimeError("boom")

        self.engine.register_callback("assessment_saved", bad_cb)
        # Should not raise
        a = self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        self.assertIsNotNone(a)

    def test_multiple_callbacks(self):
        cb1 = MagicMock()
        cb2 = MagicMock()
        self.engine.register_callback("assessment_saved", cb1)
        self.engine.register_callback("assessment_saved", cb2)
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        cb1.assert_called_once()
        cb2.assert_called_once()


# =============================================================================
#   FLASK BLUEPRINT TESTS
# =============================================================================


class TestComplianceBlueprint(unittest.TestCase):
    def setUp(self):
        from flask import Flask
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "bp_test.db")
        self.out_dir = os.path.join(self.tmpdir, "reports")
        store = ComplianceStore(db_path=self.db_path)
        self.engine = ComplianceReportEngine(store=store, output_dir=self.out_dir)
        reset_global_engine()

        app = Flask(__name__)
        app.config["TESTING"] = True
        bp = create_compliance_blueprint()
        app.register_blueprint(bp)
        self.client = app.test_client()

        # Patch global engine
        import modules.compliance.report_generator as mod
        mod._global_engine = self.engine

    def tearDown(self):
        reset_global_engine()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- Framework Controls --

    def test_nist_controls(self):
        r = self.client.get("/api/v1/soc/compliance/frameworks/nist/controls")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["success"])
        self.assertIn("preparation", d["data"])

    def test_iso_controls(self):
        r = self.client.get("/api/v1/soc/compliance/frameworks/iso27001/controls")
        self.assertEqual(r.status_code, 200)
        self.assertIn("A5", r.get_json()["data"])

    def test_kvkk_fields(self):
        r = self.client.get("/api/v1/soc/compliance/frameworks/kvkk/fields")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.get_json()["data"]) >= 10)

    # -- Assessments --

    def test_create_assessment_nist(self):
        r = self.client.post("/api/v1/soc/compliance/assessments", json={
            "control_id": "PR-1", "framework": "nist_800_61",
            "status": "implemented", "score": 0.9
        })
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.get_json()["success"])

    def test_create_assessment_iso(self):
        r = self.client.post("/api/v1/soc/compliance/assessments", json={
            "control_id": "A.5.1", "framework": "iso_27001",
            "status": "implemented", "score": 0.95
        })
        self.assertEqual(r.status_code, 201)

    def test_create_assessment_missing_fields(self):
        r = self.client.post("/api/v1/soc/compliance/assessments", json={"status": "implemented"})
        self.assertEqual(r.status_code, 400)

    def test_create_assessment_bad_framework(self):
        r = self.client.post("/api/v1/soc/compliance/assessments", json={
            "control_id": "X", "framework": "unsupported"
        })
        self.assertEqual(r.status_code, 400)

    def test_list_assessments(self):
        self.client.post("/api/v1/soc/compliance/assessments", json={
            "control_id": "PR-1", "framework": "nist_800_61", "status": "implemented", "score": 0.9
        })
        r = self.client.get("/api/v1/soc/compliance/assessments?framework=nist_800_61")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["data"]), 1)

    def test_get_assessment(self):
        cr = self.client.post("/api/v1/soc/compliance/assessments", json={
            "control_id": "PR-1", "framework": "nist_800_61", "status": "implemented", "score": 0.9
        })
        aid = cr.get_json()["data"]["id"]
        r = self.client.get(f"/api/v1/soc/compliance/assessments/{aid}")
        self.assertEqual(r.status_code, 200)

    def test_get_assessment_not_found(self):
        r = self.client.get("/api/v1/soc/compliance/assessments/nonexistent")
        self.assertEqual(r.status_code, 404)

    # -- Incidents --

    def test_create_incident(self):
        r = self.client.post("/api/v1/soc/compliance/incidents", json={
            "title": "Test Alert", "severity": "high"
        })
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.get_json()["success"])

    def test_list_incidents(self):
        self.client.post("/api/v1/soc/compliance/incidents", json={"title": "A", "severity": "high"})
        r = self.client.get("/api/v1/soc/compliance/incidents")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.get_json()["data"]) >= 1)

    def test_get_incident(self):
        cr = self.client.post("/api/v1/soc/compliance/incidents", json={"title": "X"})
        iid = cr.get_json()["data"]["id"]
        r = self.client.get(f"/api/v1/soc/compliance/incidents/{iid}")
        self.assertEqual(r.status_code, 200)

    def test_get_incident_not_found(self):
        r = self.client.get("/api/v1/soc/compliance/incidents/nonexistent")
        self.assertEqual(r.status_code, 404)

    def test_update_incident(self):
        cr = self.client.post("/api/v1/soc/compliance/incidents", json={"title": "X"})
        iid = cr.get_json()["data"]["id"]
        r = self.client.put(f"/api/v1/soc/compliance/incidents/{iid}", json={"status": "resolved"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["data"]["status"], "resolved")

    def test_update_incident_not_found(self):
        r = self.client.put("/api/v1/soc/compliance/incidents/nonexistent", json={"status": "x"})
        self.assertEqual(r.status_code, 404)

    def test_incident_stats(self):
        self.client.post("/api/v1/soc/compliance/incidents", json={"title": "A", "severity": "critical"})
        r = self.client.get("/api/v1/soc/compliance/incidents/stats")
        self.assertEqual(r.status_code, 200)
        self.assertIn("total", r.get_json()["data"])

    # -- Breaches --

    def test_create_breach(self):
        r = self.client.post("/api/v1/soc/compliance/breaches", json={
            "breach_description": "Data leak", "affected_count": 500
        })
        self.assertEqual(r.status_code, 201)

    def test_list_breaches(self):
        self.client.post("/api/v1/soc/compliance/breaches", json={"breach_description": "T"})
        r = self.client.get("/api/v1/soc/compliance/breaches")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.get_json()["data"]) >= 1)

    def test_get_breach(self):
        cr = self.client.post("/api/v1/soc/compliance/breaches", json={"breach_description": "T"})
        bid = cr.get_json()["data"]["id"]
        r = self.client.get(f"/api/v1/soc/compliance/breaches/{bid}")
        self.assertEqual(r.status_code, 200)

    def test_get_breach_not_found(self):
        r = self.client.get("/api/v1/soc/compliance/breaches/nonexistent")
        self.assertEqual(r.status_code, 404)

    def test_update_breach(self):
        cr = self.client.post("/api/v1/soc/compliance/breaches", json={"breach_description": "T"})
        bid = cr.get_json()["data"]["id"]
        r = self.client.put(f"/api/v1/soc/compliance/breaches/{bid}", json={"status": "submitted"})
        self.assertEqual(r.status_code, 200)

    def test_update_breach_not_found(self):
        r = self.client.put("/api/v1/soc/compliance/breaches/nonexistent", json={"status": "x"})
        self.assertEqual(r.status_code, 404)

    # -- Reports --

    def test_generate_nist_report(self):
        r = self.client.post("/api/v1/soc/compliance/reports/nist", json={
            "period_start": "2025-01-01", "period_end": "2025-02-01"
        })
        self.assertEqual(r.status_code, 201)
        self.assertTrue(r.get_json()["success"])

    def test_generate_nist_report_missing_dates(self):
        r = self.client.post("/api/v1/soc/compliance/reports/nist", json={})
        self.assertEqual(r.status_code, 400)

    def test_generate_iso_report(self):
        r = self.client.post("/api/v1/soc/compliance/reports/iso27001", json={
            "period_start": "2025-01-01", "period_end": "2025-02-01"
        })
        self.assertEqual(r.status_code, 201)

    def test_generate_iso_report_missing_dates(self):
        r = self.client.post("/api/v1/soc/compliance/reports/iso27001", json={})
        self.assertEqual(r.status_code, 400)

    def test_generate_breach_report(self):
        cr = self.client.post("/api/v1/soc/compliance/breaches", json={"breach_description": "T"})
        bid = cr.get_json()["data"]["breach_id"]
        r = self.client.post(f"/api/v1/soc/compliance/reports/breach/{bid}",
                             json={"format": "json"})
        self.assertEqual(r.status_code, 201)

    def test_generate_breach_report_not_found(self):
        r = self.client.post("/api/v1/soc/compliance/reports/breach/nonexistent",
                             json={"format": "json"})
        self.assertEqual(r.status_code, 404)

    def test_generate_executive_report(self):
        r = self.client.post("/api/v1/soc/compliance/reports/executive", json={
            "period_start": "2025-01-01", "period_end": "2025-02-01"
        })
        self.assertEqual(r.status_code, 201)

    def test_generate_executive_missing_dates(self):
        r = self.client.post("/api/v1/soc/compliance/reports/executive", json={})
        self.assertEqual(r.status_code, 400)

    def test_generate_periodic_report(self):
        r = self.client.post("/api/v1/soc/compliance/reports/periodic", json={
            "period": "monthly", "framework": "nist_800_61"
        })
        self.assertEqual(r.status_code, 201)

    def test_list_reports(self):
        self.client.post("/api/v1/soc/compliance/reports/nist", json={
            "period_start": "2025-01-01", "period_end": "2025-02-01"
        })
        r = self.client.get("/api/v1/soc/compliance/reports")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(len(r.get_json()["data"]) >= 1)

    def test_get_report(self):
        cr = self.client.post("/api/v1/soc/compliance/reports/nist", json={
            "period_start": "2025-01-01", "period_end": "2025-02-01"
        })
        rid = cr.get_json()["data"]["id"]
        r = self.client.get(f"/api/v1/soc/compliance/reports/{rid}")
        self.assertEqual(r.status_code, 200)

    def test_get_report_not_found(self):
        r = self.client.get("/api/v1/soc/compliance/reports/nonexistent")
        self.assertEqual(r.status_code, 404)

    def test_download_report_pdf(self):
        # Generate a PDF report first
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        report = self.engine.generate_nist_report("2025-01-01", "2025-02-01", "pdf")
        r = self.client.get(f"/api/v1/soc/compliance/reports/{report.id}/download")
        self.assertEqual(r.status_code, 200)
        self.assertIn("application/pdf", r.content_type)

    def test_download_report_not_found(self):
        r = self.client.get("/api/v1/soc/compliance/reports/nonexistent/download")
        self.assertEqual(r.status_code, 404)

    def test_download_report_no_file(self):
        # JSON report has no file_path
        cr = self.client.post("/api/v1/soc/compliance/reports/nist", json={
            "period_start": "2025-01-01", "period_end": "2025-02-01", "format": "json"
        })
        rid = cr.get_json()["data"]["id"]
        r = self.client.get(f"/api/v1/soc/compliance/reports/{rid}/download")
        self.assertEqual(r.status_code, 404)

    # -- Gap Analysis --

    def test_gap_analysis(self):
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        r = self.client.get("/api/v1/soc/compliance/gap-analysis/nist_800_61")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()["data"]
        self.assertEqual(d["framework"], "nist_800_61")
        self.assertIn("missing_assessments", d)

    # -- Dashboard --

    def test_dashboard(self):
        r = self.client.get("/api/v1/soc/compliance/dashboard")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()["data"]
        self.assertIn("incident_stats", d)
        self.assertIn("framework_scores", d)

    def test_dashboard_with_dates(self):
        r = self.client.get("/api/v1/soc/compliance/dashboard?period_start=2025-01-01&period_end=2025-02-01")
        self.assertEqual(r.status_code, 200)

    # -- Framework Scores --

    def test_framework_score(self):
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        r = self.client.get("/api/v1/soc/compliance/scores/nist_800_61")
        self.assertEqual(r.status_code, 200)
        self.assertIn("average_score", r.get_json()["data"])


# =============================================================================
#   GLOBAL SINGLETON TESTS
# =============================================================================


class TestGlobalSingleton(unittest.TestCase):
    def setUp(self):
        reset_global_engine()

    def tearDown(self):
        reset_global_engine()

    def test_get_returns_instance(self):
        engine = get_compliance_engine()
        self.assertIsInstance(engine, ComplianceReportEngine)

    def test_same_instance(self):
        e1 = get_compliance_engine()
        e2 = get_compliance_engine()
        self.assertIs(e1, e2)

    def test_reset(self):
        e1 = get_compliance_engine()
        reset_global_engine()
        e2 = get_compliance_engine()
        self.assertIsNot(e1, e2)


# =============================================================================
#   BLUEPRINT NO FLASK TEST
# =============================================================================


class TestBlueprintNoFlask(unittest.TestCase):
    def test_no_flask_returns_none(self):
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "flask":
                raise ImportError("No flask")
            return original_import(name, *args, **kwargs)

        with patch.object(builtins, "__import__", side_effect=mock_import):
            result = create_compliance_blueprint()
        self.assertIsNone(result)


# =============================================================================
#   INTEGRATION TESTS
# =============================================================================


class TestIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "int_test.db")
        self.out_dir = os.path.join(self.tmpdir, "reports")
        store = ComplianceStore(db_path=self.db_path)
        self.engine = ComplianceReportEngine(store=store, output_dir=self.out_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_full_nist_workflow(self):
        # 1. Assess controls
        self.engine.assess_nist_control("PR-1", "implemented", 0.95, evidence="IR plan v3")
        self.engine.assess_nist_control("PR-2", "implemented", 0.90, evidence="Comm plan")
        self.engine.assess_nist_control("DA-1", "partially_implemented", 0.60)
        self.engine.assess_nist_control("DA-2", "implemented", 0.85)
        self.engine.assess_nist_control("CER-1", "not_implemented", 0.1)

        # 2. Record incidents
        self.engine.record_incident(
            title="SQL Injection Attempt", severity="critical",
            nist_phase="detection_analysis", category="web_attack",
            affected_assets=["web-01"], iocs=["192.168.1.100"],
            detected_at="2025-01-15T10:00:00+00:00"
        )
        self.engine.record_incident(
            title="Brute Force Login", severity="high",
            nist_phase="containment_eradication_recovery",
            detected_at="2025-01-20T14:00:00+00:00"
        )

        # 3. Generate JSON report
        report = self.engine.generate_nist_report("2025-01-01", "2025-02-01", "json")
        self.assertEqual(report.control_count, 5)
        self.assertEqual(report.implemented_count, 3)
        self.assertEqual(report.gap_count, 1)
        self.assertEqual(report.data["incident_count"], 2)

        # 4. Generate PDF report
        pdf_report = self.engine.generate_nist_report("2025-01-01", "2025-02-01", "pdf")
        self.assertTrue(os.path.exists(pdf_report.file_path))
        with open(pdf_report.file_path, "rb") as f:
            self.assertTrue(f.read(5) == b"%PDF-")

        # 5. Gap analysis
        gaps = self.engine.generate_gap_analysis("nist_800_61")
        self.assertEqual(gaps["total_assessed"], 5)
        self.assertTrue(gaps["gap_count"] >= 1)

    def test_full_iso27001_workflow(self):
        # Assess controls
        self.engine.assess_iso27001_control("A.5.1", "implemented", 0.95)
        self.engine.assess_iso27001_control("A.5.7", "implemented", 0.80)
        self.engine.assess_iso27001_control("A.8.7", "not_implemented", 0.0)
        self.engine.assess_iso27001_control("A.8.15", "partially_implemented", 0.50)

        # Generate report
        report = self.engine.generate_iso27001_report("2025-01-01", "2025-02-01", "json")
        self.assertEqual(report.control_count, 4)
        self.assertEqual(report.gap_count, 1)

        # PDF
        pdf_report = self.engine.generate_iso27001_report("2025-01-01", "2025-02-01", "pdf")
        self.assertTrue(os.path.exists(pdf_report.file_path))

    def test_full_breach_workflow(self):
        # 1. Create breach
        breach = self.engine.create_breach_notification(
            breach_date="2025-01-10T08:00:00+00:00",
            breach_description="Customer database accessed by unauthorized party",
            data_categories=["email", "name", "phone", "address"],
            affected_count=25000,
            consequences="Potential identity theft and phishing attacks",
            dpo_contact="dpo@company.com",
            legal_basis="KVKK Madde 12",
        )

        # 2. Update with measures and notification
        updated = self.engine.update_breach_notification(
            breach.breach_id,
            measures_taken="Password reset enforced; access revoked; forensic investigation started",
            data_subjects_notified=True,
            notification_date="2025-01-11T09:00:00+00:00",
            status="submitted",
        )
        self.assertTrue(updated.data_subjects_notified)

        # 3. Generate JSON report
        report = self.engine.generate_breach_report(breach.breach_id, "json")
        self.assertIsNotNone(report)
        self.assertEqual(report.report_type, "breach_notification")

        # 4. Generate PDF report
        pdf_report = self.engine.generate_breach_report(breach.breach_id, "pdf")
        self.assertTrue(os.path.exists(pdf_report.file_path))

    def test_executive_summary_workflow(self):
        # Populate data
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        self.engine.assess_iso27001_control("A.5.1", "implemented", 0.95)
        self.engine.record_incident(
            title="Alert", severity="high",
            detected_at="2025-01-15T00:00:00+00:00"
        )
        self.engine.create_breach_notification(
            breach_description="Test",
            discovery_date="2025-01-12T00:00:00+00:00",
        )

        # Generate
        report = self.engine.generate_executive_summary("2025-01-01", "2025-02-01", "json")
        self.assertEqual(report.report_type, "executive_summary")
        self.assertIn("incident_stats", report.data)
        self.assertIn("framework_scores", report.data)
        self.assertIn("breach_count", report.data)

        # PDF
        pdf_report = self.engine.generate_executive_summary("2025-01-01", "2025-02-01", "pdf")
        self.assertTrue(os.path.exists(pdf_report.file_path))

    def test_periodic_report_all_frameworks(self):
        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        self.engine.assess_iso27001_control("A.5.1", "implemented", 0.95)

        # NIST periodic
        r1 = self.engine.generate_periodic_report("monthly", "nist_800_61")
        self.assertEqual(r1.framework, "nist_800_61")

        # ISO periodic
        r2 = self.engine.generate_periodic_report("monthly", "iso_27001")
        self.assertEqual(r2.framework, "iso_27001")

        # Executive periodic
        r3 = self.engine.generate_periodic_report("monthly")
        self.assertEqual(r3.report_type, "executive_summary")

    def test_callback_full_lifecycle(self):
        events = []

        def tracker(event, data):
            events.append(event)

        self.engine.register_callback("assessment_saved", tracker)
        self.engine.register_callback("incident_recorded", tracker)
        self.engine.register_callback("incident_updated", tracker)
        self.engine.register_callback("breach_created", tracker)
        self.engine.register_callback("breach_updated", tracker)
        self.engine.register_callback("report_generated", tracker)

        self.engine.assess_nist_control("PR-1", "implemented", 0.9)
        inc = self.engine.record_incident(title="Test")
        self.engine.update_incident(inc.incident_id, status="resolved")
        breach = self.engine.create_breach_notification(breach_description="T")
        self.engine.update_breach_notification(breach.breach_id, status="submitted")
        self.engine.generate_nist_report("2025-01-01", "2025-02-01")

        self.assertIn("assessment_saved", events)
        self.assertIn("incident_recorded", events)
        self.assertIn("incident_updated", events)
        self.assertIn("breach_created", events)
        self.assertIn("breach_updated", events)
        self.assertIn("report_generated", events)


if __name__ == "__main__":
    unittest.main()
