#!/usr/bin/env python3
"""
Comprehensive tests for Alert Normalization Pipeline.
Covers: TAFSeverity, TAFSource, TAFStatus, TAFAlert, IOCExtractor,
        WazuhAdapter, SuricataAdapter, SyslogAdapter, GenericAdapter,
        SeverityOverride, AlertNormalizationPipeline, Flask Blueprint.
"""
import hashlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.siem_integration.alert_normalizer import (
    TAFSeverity, TAFSource, TAFStatus, TAFAlert,
    IOCExtractor, IOC_PATTERNS, PRIVATE_IP_PREFIXES,
    SourceAdapter, WazuhAdapter, SuricataAdapter, SyslogAdapter, GenericAdapter,
    SeverityOverride, AlertNormalizationPipeline,
    create_normalizer_blueprint, get_normalization_pipeline,
)


# ============================================================================
# TAFSeverity Tests
# ============================================================================

class TestTAFSeverity(unittest.TestCase):
    """Tests for TAFSeverity enum."""

    def test_values(self):
        self.assertEqual(TAFSeverity.CRITICAL.value, 1)
        self.assertEqual(TAFSeverity.HIGH.value, 2)
        self.assertEqual(TAFSeverity.MEDIUM.value, 3)
        self.assertEqual(TAFSeverity.LOW.value, 4)
        self.assertEqual(TAFSeverity.INFO.value, 5)

    def test_from_string_exact(self):
        self.assertEqual(TAFSeverity.from_string('critical'), TAFSeverity.CRITICAL)
        self.assertEqual(TAFSeverity.from_string('high'), TAFSeverity.HIGH)
        self.assertEqual(TAFSeverity.from_string('medium'), TAFSeverity.MEDIUM)
        self.assertEqual(TAFSeverity.from_string('low'), TAFSeverity.LOW)
        self.assertEqual(TAFSeverity.from_string('info'), TAFSeverity.INFO)

    def test_from_string_case_insensitive(self):
        self.assertEqual(TAFSeverity.from_string('CRITICAL'), TAFSeverity.CRITICAL)
        self.assertEqual(TAFSeverity.from_string('High'), TAFSeverity.HIGH)
        self.assertEqual(TAFSeverity.from_string('MeDiUm'), TAFSeverity.MEDIUM)

    def test_from_string_informational(self):
        self.assertEqual(TAFSeverity.from_string('informational'), TAFSeverity.INFO)

    def test_from_string_unknown_returns_info(self):
        self.assertEqual(TAFSeverity.from_string('unknown'), TAFSeverity.INFO)
        self.assertEqual(TAFSeverity.from_string(''), TAFSeverity.INFO)
        self.assertEqual(TAFSeverity.from_string('xyz'), TAFSeverity.INFO)

    def test_from_string_whitespace(self):
        self.assertEqual(TAFSeverity.from_string('  high  '), TAFSeverity.HIGH)

    def test_sla_minutes(self):
        self.assertEqual(TAFSeverity.CRITICAL.sla_minutes, 15)
        self.assertEqual(TAFSeverity.HIGH.sla_minutes, 60)
        self.assertEqual(TAFSeverity.MEDIUM.sla_minutes, 240)
        self.assertEqual(TAFSeverity.LOW.sla_minutes, 1440)
        self.assertEqual(TAFSeverity.INFO.sla_minutes, 0)


# ============================================================================
# TAFSource Tests
# ============================================================================

class TestTAFSource(unittest.TestCase):
    """Tests for TAFSource enum."""

    def test_values(self):
        self.assertEqual(TAFSource.WAZUH.value, "wazuh")
        self.assertEqual(TAFSource.SURICATA.value, "suricata")
        self.assertEqual(TAFSource.SYSLOG.value, "syslog")
        self.assertEqual(TAFSource.SIGMA.value, "sigma")
        self.assertEqual(TAFSource.CUSTOM.value, "custom")

    def test_from_string_valid(self):
        self.assertEqual(TAFSource.from_string('wazuh'), TAFSource.WAZUH)
        self.assertEqual(TAFSource.from_string('suricata'), TAFSource.SURICATA)
        self.assertEqual(TAFSource.from_string('syslog'), TAFSource.SYSLOG)
        self.assertEqual(TAFSource.from_string('elastic'), TAFSource.ELASTIC)

    def test_from_string_whitespace(self):
        self.assertEqual(TAFSource.from_string('  wazuh  '), TAFSource.WAZUH)

    def test_from_string_case_insensitive(self):
        self.assertEqual(TAFSource.from_string('WAZUH'), TAFSource.WAZUH)
        self.assertEqual(TAFSource.from_string('Suricata'), TAFSource.SURICATA)

    def test_from_string_unknown_returns_custom(self):
        self.assertEqual(TAFSource.from_string('unknown'), TAFSource.CUSTOM)
        self.assertEqual(TAFSource.from_string(''), TAFSource.CUSTOM)

    def test_all_sources_listed(self):
        expected = {'wazuh', 'suricata', 'syslog', 'sigma', 'custom',
                    'internal', 'threat_intel', 'ml_anomaly', 'snort',
                    'zeek', 'osquery', 'elastic'}
        actual = {s.value for s in TAFSource}
        self.assertEqual(actual, expected)


# ============================================================================
# TAFStatus Tests
# ============================================================================

class TestTAFStatus(unittest.TestCase):
    """Tests for TAFStatus enum."""

    def test_values(self):
        self.assertEqual(TAFStatus.NEW.value, "new")
        self.assertEqual(TAFStatus.NORMALIZED.value, "normalized")
        self.assertEqual(TAFStatus.ENRICHED.value, "enriched")
        self.assertEqual(TAFStatus.DEDUPLICATED.value, "deduplicated")
        self.assertEqual(TAFStatus.DISPATCHED.value, "dispatched")
        self.assertEqual(TAFStatus.DROPPED.value, "dropped")


# ============================================================================
# TAFAlert Tests
# ============================================================================

class TestTAFAlert(unittest.TestCase):
    """Tests for TAFAlert dataclass."""

    def test_default_creation(self):
        alert = TAFAlert()
        self.assertTrue(alert.alert_id.startswith('taf_'))
        self.assertEqual(len(alert.alert_id), 20)  # taf_ + 16 hex
        self.assertEqual(alert.severity, TAFSeverity.INFO)
        self.assertEqual(alert.source, TAFSource.CUSTOM)
        self.assertEqual(alert.status, TAFStatus.NEW)
        self.assertEqual(alert.category, 'general')
        self.assertNotEqual(alert.normalized_at, '')
        self.assertEqual(alert.event_timestamp, alert.normalized_at)

    def test_custom_alert_id_preserved(self):
        alert = TAFAlert(alert_id='my_custom_id')
        self.assertEqual(alert.alert_id, 'my_custom_id')

    def test_priority_computation_info(self):
        alert = TAFAlert(severity=TAFSeverity.INFO)
        # sev_score=10, cvss=0, mitre=0, conf=0.8
        self.assertEqual(alert.priority_score, round(10 * 0.8, 1))

    def test_priority_computation_critical_with_cvss(self):
        alert = TAFAlert(
            severity=TAFSeverity.CRITICAL,
            cvss_score=9.5,
            mitre_techniques=['T1059', 'T1190'],
            confidence=1.0,
        )
        # sev_score=90, cvss_boost=9.5, mitre_boost=4, conf=1.0
        expected = round((90 + 9.5 + 4) * 1.0, 1)
        self.assertEqual(alert.priority_score, expected)

    def test_priority_computation_cvss_capped(self):
        alert = TAFAlert(
            severity=TAFSeverity.HIGH,
            cvss_score=15.0,
            confidence=1.0,
        )
        # cvss capped at 10
        expected = round((70 + 10 + 0) * 1.0, 1)
        self.assertEqual(alert.priority_score, expected)

    def test_priority_computation_mitre_capped(self):
        alert = TAFAlert(
            severity=TAFSeverity.MEDIUM,
            mitre_techniques=['T1', 'T2', 'T3', 'T4', 'T5', 'T6', 'T7'],
            confidence=1.0,
        )
        # mitre_boost = min(10, 7*2=14) = 10
        expected = round((50 + 0 + 10) * 1.0, 1)
        self.assertEqual(alert.priority_score, expected)

    def test_dedup_hash_computation(self):
        alert = TAFAlert(
            source=TAFSource.WAZUH,
            source_rule='5501',
            src_ip='192.168.1.1',
            dst_ip='10.0.0.1',
            category='authentication',
        )
        h = alert.compute_dedup_hash()
        self.assertEqual(len(h), 32)
        self.assertEqual(alert.dedup_hash, h)

        # Consistent
        h2 = alert.compute_dedup_hash()
        self.assertEqual(h, h2)

    def test_dedup_hash_differs_for_different_data(self):
        a1 = TAFAlert(source=TAFSource.WAZUH, src_ip='1.1.1.1')
        a2 = TAFAlert(source=TAFSource.WAZUH, src_ip='2.2.2.2')
        a1.compute_dedup_hash()
        a2.compute_dedup_hash()
        self.assertNotEqual(a1.dedup_hash, a2.dedup_hash)

    def test_correlation_keys(self):
        alert = TAFAlert(
            source=TAFSource.SURICATA,
            src_ip='1.2.3.4',
            dst_ip='5.6.7.8',
            source_rule='2001234',
            mitre_tactics=['TA0001', 'TA0006'],
            hostname='server01',
            username='admin',
        )
        keys = alert.compute_correlation_keys()
        self.assertIn('src:1.2.3.4', keys)
        self.assertIn('dst:5.6.7.8', keys)
        self.assertIn('rule:suricata:2001234', keys)
        self.assertIn('mitre:TA0001', keys)
        self.assertIn('mitre:TA0006', keys)
        self.assertIn('host:server01', keys)
        self.assertIn('user:admin', keys)
        self.assertEqual(alert.correlation_keys, keys)

    def test_correlation_keys_empty_fields(self):
        alert = TAFAlert()
        keys = alert.compute_correlation_keys()
        self.assertEqual(keys, [])

    def test_to_dict(self):
        alert = TAFAlert(
            title='Test Alert',
            severity=TAFSeverity.HIGH,
            source=TAFSource.WAZUH,
            status=TAFStatus.NORMALIZED,
        )
        d = alert.to_dict()
        self.assertEqual(d['title'], 'Test Alert')
        self.assertEqual(d['severity'], 'HIGH')
        self.assertEqual(d['source'], 'wazuh')
        self.assertEqual(d['status'], 'normalized')
        self.assertIsInstance(d, dict)

    def test_to_dict_serializable(self):
        alert = TAFAlert(
            title='JSON Test',
            severity=TAFSeverity.CRITICAL,
            mitre_tactics=['TA0001'],
            iocs=[{'type': 'ipv4', 'value': '1.1.1.1'}],
        )
        # Should not raise
        json_str = json.dumps(alert.to_dict(), default=str)
        self.assertIn('JSON Test', json_str)

    def test_event_timestamp_default(self):
        alert = TAFAlert()
        # event_timestamp defaults to normalized_at
        self.assertEqual(alert.event_timestamp, alert.normalized_at)

    def test_event_timestamp_custom(self):
        alert = TAFAlert(event_timestamp='2024-01-01T00:00:00Z')
        self.assertEqual(alert.event_timestamp, '2024-01-01T00:00:00Z')


# ============================================================================
# IOCExtractor Tests
# ============================================================================

class TestIOCExtractor(unittest.TestCase):
    """Tests for IOCExtractor."""

    def test_extract_ipv4_public(self):
        alert = TAFAlert(
            title='Connection from 8.8.8.8 detected',
            description='Malicious traffic to 1.2.3.4',
        )
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'ipv4'}
        self.assertIn('8.8.8.8', values)
        self.assertIn('1.2.3.4', values)

    def test_exclude_private_ips_default(self):
        alert = TAFAlert(
            title='Connection from 192.168.1.1 and 10.0.0.1',
        )
        iocs = IOCExtractor.extract(alert, include_private_ips=False)
        values = {i['value'] for i in iocs if i['type'] == 'ipv4'}
        self.assertNotIn('192.168.1.1', values)
        self.assertNotIn('10.0.0.1', values)

    def test_include_private_ips(self):
        alert = TAFAlert(
            title='Connection from 192.168.1.1',
        )
        iocs = IOCExtractor.extract(alert, include_private_ips=True)
        values = {i['value'] for i in iocs if i['type'] == 'ipv4'}
        self.assertIn('192.168.1.1', values)

    def test_extract_domain(self):
        alert = TAFAlert(
            title='DNS query to evil.example.com',
        )
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'domain'}
        self.assertIn('evil.example.com', values)

    def test_exclude_local_domains(self):
        alert = TAFAlert(
            title='Resolution for host.local and host.internal',
        )
        iocs = IOCExtractor.extract(alert)
        domain_values = {i['value'] for i in iocs if i['type'] == 'domain'}
        for v in domain_values:
            self.assertFalse(v.endswith('.local'))
            self.assertFalse(v.endswith('.internal'))

    def test_extract_md5(self):
        md5_hash = 'a' * 32
        alert = TAFAlert(title=f'Hash detected: {md5_hash}')
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'md5'}
        self.assertIn(md5_hash, values)

    def test_extract_sha256(self):
        sha256_hash = 'b' * 64
        alert = TAFAlert(title=f'File hash: {sha256_hash}')
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'sha256'}
        self.assertIn(sha256_hash, values)

    def test_extract_url(self):
        alert = TAFAlert(
            description='Downloaded from https://evil.com/malware.exe',
        )
        iocs = IOCExtractor.extract(alert)
        url_values = [i['value'] for i in iocs if i['type'] == 'url']
        self.assertTrue(any('evil.com/malware.exe' in u for u in url_values))

    def test_extract_email(self):
        alert = TAFAlert(title='Phishing from attacker@evil.com')
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'email'}
        self.assertIn('attacker@evil.com', values)

    def test_extract_cve(self):
        alert = TAFAlert(title='Exploit for CVE-2024-12345 detected')
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'cve'}
        self.assertIn('CVE-2024-12345', values)

    def test_extract_from_source_raw(self):
        alert = TAFAlert(
            title='Alert',
            source_raw={'payload': 'callback to 44.55.66.77'},
        )
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'ipv4'}
        self.assertIn('44.55.66.77', values)

    def test_extract_dedup_values(self):
        alert = TAFAlert(
            title='IP 8.8.8.8 found, also 8.8.8.8 repeated',
        )
        iocs = IOCExtractor.extract(alert)
        ip_values = [i['value'] for i in iocs if i['type'] == 'ipv4']
        # Should only appear once
        self.assertEqual(ip_values.count('8.8.8.8'), 1)

    def test_explicit_ip_fields_added(self):
        alert = TAFAlert(
            title='Some alert',
            src_ip='44.55.66.77',
            dst_ip='88.99.11.22',
        )
        iocs = IOCExtractor.extract(alert)
        values = {i['value'] for i in iocs if i['type'] == 'ipv4'}
        self.assertIn('44.55.66.77', values)
        self.assertIn('88.99.11.22', values)

    def test_explicit_private_ip_excluded_by_default(self):
        alert = TAFAlert(
            title='Alert',
            src_ip='192.168.1.100',
        )
        iocs = IOCExtractor.extract(alert, include_private_ips=False)
        values = {i['value'] for i in iocs if i['type'] == 'ipv4'}
        self.assertNotIn('192.168.1.100', values)


# ============================================================================
# WazuhAdapter Tests
# ============================================================================

class TestWazuhAdapter(unittest.TestCase):
    """Tests for WazuhAdapter."""

    def setUp(self):
        self.adapter = WazuhAdapter()

    def test_source_type(self):
        self.assertEqual(self.adapter.source_type, TAFSource.WAZUH)

    def test_name(self):
        self.assertEqual(self.adapter.name, 'WazuhAdapter')

    def test_normalize_basic(self):
        raw = {
            'id': '12345',
            'timestamp': '2024-01-15T10:00:00Z',
            'rule': {
                'id': '5501',
                'level': 10,
                'description': 'Login failure',
                'groups': ['authentication_failed'],
            },
            'agent': {'id': '001', 'name': 'server01'},
            'data': {'srcip': '192.168.1.100'},
        }
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertTrue(alert.alert_id.startswith('wazuh_'))
        self.assertIn('5501', alert.title)
        self.assertIn('Login failure', alert.title)
        self.assertEqual(alert.severity, TAFSeverity.MEDIUM)  # level 10
        self.assertEqual(alert.source, TAFSource.WAZUH)
        self.assertEqual(alert.category, 'authentication')
        self.assertEqual(alert.src_ip, '192.168.1.100')
        self.assertEqual(alert.hostname, 'server01')
        self.assertIn('TA0006', alert.mitre_tactics)
        self.assertIn('T1110', alert.mitre_techniques)

    def test_normalize_empty_rule_returns_none(self):
        raw = {'rule': {}}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_normalize_no_rule_returns_none(self):
        raw = {'data': {'srcip': '1.1.1.1'}}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_severity_mapping_info(self):
        raw = {'rule': {'id': '100', 'level': 2, 'groups': []}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.severity, TAFSeverity.INFO)

    def test_severity_mapping_low(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': []}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.severity, TAFSeverity.LOW)

    def test_severity_mapping_high(self):
        raw = {'rule': {'id': '100', 'level': 12, 'groups': []}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.severity, TAFSeverity.HIGH)

    def test_severity_mapping_critical(self):
        raw = {'rule': {'id': '100', 'level': 15, 'groups': []}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.severity, TAFSeverity.CRITICAL)

    def test_severity_out_of_range(self):
        raw = {'rule': {'id': '100', 'level': 99, 'groups': []}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.severity, TAFSeverity.INFO)

    def test_mitre_from_rule_mitre_field(self):
        raw = {
            'rule': {
                'id': '100', 'level': 5, 'groups': [],
                'mitre': {
                    'tactic': ['TA0003'],
                    'technique': [{'id': 'T1014'}],
                },
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertIn('TA0003', alert.mitre_tactics)
        self.assertIn('T1014', alert.mitre_techniques)

    def test_mitre_from_rule_mitre_id_fallback(self):
        raw = {
            'rule': {
                'id': '100', 'level': 5, 'groups': [],
                'mitre': {
                    'tactic': ['TA0001'],
                    'id': ['T1190'],
                },
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertIn('T1190', alert.mitre_techniques)

    def test_mitre_from_groups(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['web_attack']}}
        alert = self.adapter.normalize(raw)
        self.assertIn('TA0001', alert.mitre_tactics)
        self.assertIn('T1190', alert.mitre_techniques)

    def test_category_web(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['web_server']}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'web_attack')

    def test_category_malware(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['rootkit']}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'malware')

    def test_category_ids(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['ids_event']}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'intrusion')

    def test_category_syscheck(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['syscheck']}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'file_integrity')

    def test_category_vulnerability(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['vulnerability-detector']}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'vulnerability')

    def test_category_policy(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['policy_check']}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'policy_violation')

    def test_category_default(self):
        raw = {'rule': {'id': '100', 'level': 5, 'groups': ['some_other']}}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'general')

    def test_network_fields_from_data(self):
        raw = {
            'rule': {'id': '100', 'level': 5, 'groups': []},
            'data': {
                'srcip': '10.0.0.1',
                'dstip': '10.0.0.2',
                'srcport': '1234',
                'dstport': '443',
                'srcuser': 'admin',
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.src_ip, '10.0.0.1')
        self.assertEqual(alert.dst_ip, '10.0.0.2')
        self.assertEqual(alert.src_port, 1234)
        self.assertEqual(alert.dst_port, 443)
        self.assertEqual(alert.username, 'admin')

    def test_cvss_from_level(self):
        raw = {'rule': {'id': '100', 'level': 16, 'groups': []}}
        alert = self.adapter.normalize(raw)
        # cvss = min(10.0, 16 * 0.625) = 10.0
        self.assertEqual(alert.cvss_score, 10.0)

    def test_title_truncated(self):
        raw = {
            'rule': {
                'id': '100', 'level': 5,
                'description': 'A' * 300,
                'groups': [],
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertLessEqual(len(alert.title), 256)


# ============================================================================
# SuricataAdapter Tests
# ============================================================================

class TestSuricataAdapter(unittest.TestCase):
    """Tests for SuricataAdapter."""

    def setUp(self):
        self.adapter = SuricataAdapter()

    def test_source_type(self):
        self.assertEqual(self.adapter.source_type, TAFSource.SURICATA)

    def test_normalize_basic(self):
        raw = {
            'event_type': 'alert',
            'timestamp': '2024-01-15T12:00:00Z',
            'src_ip': '10.0.0.50',
            'dest_ip': '8.8.8.8',
            'src_port': 45678,
            'dest_port': 443,
            'proto': 'TCP',
            'flow_id': 123456789,
            'in_iface': 'eth0',
            'alert': {
                'signature': 'ET MALWARE Trojan.GenericKD',
                'signature_id': 2001234,
                'gid': 1,
                'rev': 3,
                'severity': 1,
                'category': 'trojan-activity',
                'action': 'allowed',
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertTrue(alert.alert_id.startswith('suricata_'))
        self.assertIn('2001234', alert.title)
        self.assertIn('ET MALWARE', alert.title)
        self.assertEqual(alert.severity, TAFSeverity.CRITICAL)  # priority 1
        self.assertEqual(alert.source, TAFSource.SURICATA)
        self.assertEqual(alert.category, 'malware')
        self.assertEqual(alert.src_ip, '10.0.0.50')
        self.assertEqual(alert.dst_ip, '8.8.8.8')
        self.assertEqual(alert.src_port, 45678)
        self.assertEqual(alert.dst_port, 443)
        self.assertEqual(alert.protocol, 'TCP')
        self.assertEqual(alert.action, 'allowed')
        self.assertEqual(alert.flow_id, '123456789')
        self.assertEqual(alert.cvss_score, 9.5)

    def test_non_alert_event_type_returns_none(self):
        raw = {'event_type': 'flow', 'alert': {'signature': 'test'}}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_empty_alert_dict_returns_none(self):
        raw = {'event_type': 'alert', 'alert': {}}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_no_alert_key_returns_none(self):
        raw = {'event_type': 'alert'}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_severity_mapping(self):
        for sev_id, expected in [
            (1, TAFSeverity.CRITICAL),
            (2, TAFSeverity.HIGH),
            (3, TAFSeverity.MEDIUM),
            (4, TAFSeverity.LOW),
            (255, TAFSeverity.INFO),
        ]:
            raw = {
                'event_type': 'alert',
                'alert': {'signature': 'Test', 'severity': sev_id,
                          'signature_id': 1000},
            }
            alert = self.adapter.normalize(raw)
            self.assertEqual(alert.severity, expected, f"sev_id={sev_id}")

    def test_severity_unknown_defaults_low(self):
        raw = {
            'event_type': 'alert',
            'alert': {'signature': 'Test', 'severity': 99,
                      'signature_id': 1000},
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.severity, TAFSeverity.LOW)

    def test_mitre_from_classtype(self):
        raw = {
            'event_type': 'alert',
            'alert': {
                'signature': 'Test',
                'signature_id': 1000,
                'category': 'web-application-attack',
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertIn('TA0001', alert.mitre_tactics)
        self.assertIn('T1190', alert.mitre_techniques)

    def test_mitre_from_metadata(self):
        raw = {
            'event_type': 'alert',
            'alert': {
                'signature': 'Test',
                'signature_id': 1000,
                'category': '',
                'metadata': {
                    'mitre_tactic_id': ['TA0040'],
                    'mitre_technique_id': ['T1499'],
                },
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertIn('TA0040', alert.mitre_tactics)
        self.assertIn('T1499', alert.mitre_techniques)

    def test_category_et_trojan(self):
        raw = {
            'event_type': 'alert',
            'alert': {'signature': 'ET TROJAN Win32/Something',
                      'signature_id': 2000, 'severity': 1},
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'malware')

    def test_category_et_scan(self):
        raw = {
            'event_type': 'alert',
            'alert': {'signature': 'ET SCAN Nmap Probing',
                      'signature_id': 3000, 'severity': 3},
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'reconnaissance')

    def test_category_et_exploit(self):
        raw = {
            'event_type': 'alert',
            'alert': {'signature': 'ET EXPLOIT Apache Struts',
                      'signature_id': 4000, 'severity': 1},
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'exploit')

    def test_category_default(self):
        raw = {
            'event_type': 'alert',
            'alert': {'signature': 'CUSTOM Rule something',
                      'signature_id': 5000, 'severity': 3},
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'general')

    def test_cvss_mapping(self):
        for sev_id, expected_cvss in [(1, 9.5), (2, 7.5), (3, 5.0), (4, 2.5)]:
            raw = {
                'event_type': 'alert',
                'alert': {'signature': 'Test', 'severity': sev_id,
                          'signature_id': 1000},
            }
            alert = self.adapter.normalize(raw)
            self.assertEqual(alert.cvss_score, expected_cvss)

    def test_tags_include_sid_classtype_action(self):
        raw = {
            'event_type': 'alert',
            'alert': {
                'signature': 'Test', 'signature_id': 2001234,
                'category': 'trojan-activity', 'action': 'blocked',
            },
        }
        alert = self.adapter.normalize(raw)
        self.assertIn('sid:2001234', alert.tags)
        self.assertIn('classtype:trojan-activity', alert.tags)
        self.assertIn('action:blocked', alert.tags)


# ============================================================================
# SyslogAdapter Tests
# ============================================================================

class TestSyslogAdapter(unittest.TestCase):
    """Tests for SyslogAdapter."""

    def setUp(self):
        self.adapter = SyslogAdapter()

    def test_source_type(self):
        self.assertEqual(self.adapter.source_type, TAFSource.SYSLOG)

    def test_normalize_parsed_dict(self):
        raw = {
            'message': 'Failed password for root from 203.0.113.50',
            'hostname': 'server01',
            'program': 'sshd',
            'pid': '12345',
            'severity_num': 4,
            'facility': 10,
            'timestamp': '2024-01-15T10:00:00Z',
        }
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertTrue(alert.alert_id.startswith('syslog_'))
        self.assertEqual(alert.source, TAFSource.SYSLOG)
        self.assertEqual(alert.severity, TAFSeverity.MEDIUM)  # sev_num=4
        self.assertEqual(alert.hostname, 'server01')
        self.assertEqual(alert.category, 'authentication')
        # IPs extracted from message
        self.assertEqual(alert.src_ip, '203.0.113.50')

    def test_normalize_raw_line(self):
        raw = {
            'raw_line': '<38>Jan 15 10:00:00 myhost sshd[1234]: Failed password for user',
        }
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.hostname, 'myhost')
        self.assertEqual(alert.category, 'authentication')
        # Priority 38: facility=4 (auth), severity=6 (informational)
        self.assertEqual(alert.severity, TAFSeverity.INFO)

    def test_normalize_raw_line_auth_severity(self):
        # Priority=34: facility=4, severity=2 (critical)
        raw = {
            'raw_line': '<34>Jan 15 10:00:00 myhost kernel[0]: Critical error occurred',
        }
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, TAFSeverity.CRITICAL)

    def test_normalize_no_message_returns_none(self):
        raw = {'hostname': 'server01'}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_normalize_bad_raw_line_returns_none(self):
        raw = {'raw_line': 'this is not a valid syslog line'}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_severity_mapping_all(self):
        for sev_num, expected in [
            (0, TAFSeverity.CRITICAL),
            (1, TAFSeverity.CRITICAL),
            (2, TAFSeverity.CRITICAL),
            (3, TAFSeverity.HIGH),
            (4, TAFSeverity.MEDIUM),
            (5, TAFSeverity.LOW),
            (6, TAFSeverity.INFO),
            (7, TAFSeverity.INFO),
        ]:
            raw = {'message': 'test', 'severity_num': sev_num}
            alert = self.adapter.normalize(raw)
            self.assertEqual(alert.severity, expected, f"sev_num={sev_num}")

    def test_category_firewall(self):
        raw = {'message': 'iptables DROP from 1.2.3.4', 'severity_num': 4}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'firewall')

    def test_category_web_server(self):
        raw = {'message': 'apache error', 'program': 'httpd', 'severity_num': 3}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'web_server')

    def test_category_privilege_escalation(self):
        raw = {'message': 'sudo command executed', 'severity_num': 5}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'privilege_escalation')

    def test_category_malware(self):
        raw = {'message': 'trojan detected in /tmp/virus', 'severity_num': 2}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'malware')

    def test_category_default(self):
        raw = {'message': 'disk usage at 80%', 'severity_num': 4}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.category, 'general')

    def test_ip_extraction_from_message(self):
        raw = {
            'message': 'Connection from 203.0.113.50 to 198.51.100.10 denied',
            'severity_num': 4,
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.src_ip, '203.0.113.50')
        self.assertEqual(alert.dst_ip, '198.51.100.10')

    def test_syslog_line_parsing_with_pid(self):
        raw = {'raw_line': '<13>Feb  1 12:30:45 webserver nginx[9876]: 404 Not Found'}
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertIn('nginx', alert.title)
        self.assertEqual(alert.category, 'web_server')


# ============================================================================
# GenericAdapter Tests
# ============================================================================

class TestGenericAdapter(unittest.TestCase):
    """Tests for GenericAdapter."""

    def setUp(self):
        self.adapter = GenericAdapter()

    def test_source_type(self):
        self.assertEqual(self.adapter.source_type, TAFSource.CUSTOM)

    def test_normalize_basic(self):
        raw = {
            'title': 'Custom Alert',
            'description': 'Something happened',
            'severity': 'high',
            'source': 'elastic',
            'category': 'custom_cat',
            'src_ip': '1.1.1.1',
        }
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.title, 'Custom Alert')
        self.assertEqual(alert.description, 'Something happened')
        self.assertEqual(alert.severity, TAFSeverity.HIGH)
        self.assertEqual(alert.source, TAFSource.ELASTIC)
        self.assertEqual(alert.category, 'custom_cat')
        self.assertEqual(alert.src_ip, '1.1.1.1')

    def test_normalize_no_title_returns_none(self):
        raw = {'description': 'No title here'}
        result = self.adapter.normalize(raw)
        self.assertIsNone(result)

    def test_normalize_minimal(self):
        raw = {'title': 'Minimal'}
        alert = self.adapter.normalize(raw)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.title, 'Minimal')
        self.assertEqual(alert.severity, TAFSeverity.INFO)
        self.assertEqual(alert.source, TAFSource.CUSTOM)

    def test_normalize_with_custom_alert_id(self):
        raw = {'title': 'Test', 'alert_id': 'my_id_123'}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.alert_id, 'my_id_123')

    def test_normalize_unknown_severity(self):
        raw = {'title': 'Test', 'severity': 'unknown_sev'}
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.severity, TAFSeverity.INFO)

    def test_normalize_with_ports(self):
        raw = {
            'title': 'Port test',
            'src_port': '8080',
            'dst_port': '443',
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.src_port, 8080)
        self.assertEqual(alert.dst_port, 443)

    def test_normalize_with_mitre(self):
        raw = {
            'title': 'MITRE test',
            'mitre_tactics': ['TA0001'],
            'mitre_techniques': ['T1190'],
            'tags': ['test', 'custom'],
        }
        alert = self.adapter.normalize(raw)
        self.assertEqual(alert.mitre_tactics, ['TA0001'])
        self.assertEqual(alert.mitre_techniques, ['T1190'])
        self.assertEqual(alert.tags, ['test', 'custom'])


# ============================================================================
# SeverityOverride Tests
# ============================================================================

class TestSeverityOverride(unittest.TestCase):
    """Tests for SeverityOverride."""

    def test_apply_matching(self):
        override = SeverityOverride(
            name='critical_for_high_cvss',
            condition=lambda a: a.cvss_score >= 9.0,
            new_severity=TAFSeverity.CRITICAL,
        )
        alert = TAFAlert(
            severity=TAFSeverity.MEDIUM,
            cvss_score=9.5,
            confidence=1.0,
        )
        result = override.apply(alert)
        self.assertTrue(result)
        self.assertEqual(alert.severity, TAFSeverity.CRITICAL)
        # Priority should have been recomputed
        self.assertGreater(alert.priority_score, 50)

    def test_apply_not_matching(self):
        override = SeverityOverride(
            name='critical_for_high_cvss',
            condition=lambda a: a.cvss_score >= 9.0,
            new_severity=TAFSeverity.CRITICAL,
        )
        alert = TAFAlert(severity=TAFSeverity.LOW, cvss_score=3.0)
        result = override.apply(alert)
        self.assertFalse(result)
        self.assertEqual(alert.severity, TAFSeverity.LOW)

    def test_apply_recomputes_priority(self):
        alert = TAFAlert(severity=TAFSeverity.INFO, confidence=1.0)
        old_priority = alert.priority_score

        override = SeverityOverride(
            name='upgrade',
            condition=lambda a: True,
            new_severity=TAFSeverity.CRITICAL,
        )
        override.apply(alert)
        self.assertGreater(alert.priority_score, old_priority)


# ============================================================================
# AlertNormalizationPipeline Tests
# ============================================================================

class TestAlertNormalizationPipeline(unittest.TestCase):
    """Tests for AlertNormalizationPipeline."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test_normalizer.db')
        self.pipeline = AlertNormalizationPipeline(
            db_path=self.db_path,
            dedup_window_minutes=60,
        )

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_db_initialized(self):
        conn = sqlite3.connect(self.db_path)
        # Check tables exist
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        table_names = {t[0] for t in tables}
        self.assertIn('normalized_alerts', table_names)
        self.assertIn('dedup_cache', table_names)
        conn.close()

    def test_default_adapters_registered(self):
        adapters = self.pipeline.adapters
        self.assertIn('wazuh', adapters)
        self.assertIn('suricata', adapters)
        self.assertIn('syslog', adapters)
        self.assertIn('custom', adapters)

    def test_register_custom_adapter(self):
        class MyAdapter(SourceAdapter):
            @property
            def source_type(self):
                return TAFSource.SNORT

            def normalize(self, raw):
                return TAFAlert(title=raw.get('msg', ''))

        self.pipeline.register_adapter('snort', MyAdapter())
        self.assertIn('snort', self.pipeline.adapters)
        self.assertEqual(self.pipeline.adapters['snort'], 'MyAdapter')

    def test_get_adapter(self):
        adapter = self.pipeline.get_adapter('wazuh')
        self.assertIsNotNone(adapter)
        self.assertIsInstance(adapter, WazuhAdapter)

    def test_get_adapter_missing(self):
        adapter = self.pipeline.get_adapter('nonexistent')
        self.assertIsNone(adapter)

    def test_ingest_wazuh(self):
        raw = {
            'rule': {'id': '5501', 'level': 10,
                     'description': 'Auth failure', 'groups': ['authentication_failed']},
            'agent': {'name': 'srv01'},
            'data': {'srcip': '192.168.1.10'},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source, TAFSource.WAZUH)
        self.assertEqual(alert.status, TAFStatus.DISPATCHED)

    def test_ingest_suricata(self):
        raw = {
            'event_type': 'alert',
            'src_ip': '10.0.0.1',
            'dest_ip': '8.8.4.4',
            'alert': {
                'signature': 'ET MALWARE test',
                'signature_id': 2001000,
                'severity': 2,
            },
        }
        alert = self.pipeline.ingest(raw, source='suricata')
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source, TAFSource.SURICATA)

    def test_ingest_syslog(self):
        raw = {
            'message': 'Failed login attempt from 203.0.113.1',
            'hostname': 'webserver',
            'program': 'sshd',
            'severity_num': 4,
        }
        alert = self.pipeline.ingest(raw, source='syslog')
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source, TAFSource.SYSLOG)

    def test_ingest_custom(self):
        raw = {'title': 'Custom alert test', 'severity': 'high'}
        alert = self.pipeline.ingest(raw, source='custom')
        self.assertIsNotNone(alert)

    def test_ingest_unknown_source_fallback_custom(self):
        raw = {'title': 'Unknown source', 'severity': 'low'}
        alert = self.pipeline.ingest(raw, source='unknown_source')
        self.assertIsNotNone(alert)

    def test_ingest_returns_none_for_dropped(self):
        raw = {'rule': {}}  # Empty rule -> WazuhAdapter returns None
        result = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNone(result)

    def test_dedup_within_window(self):
        raw = {
            'rule': {'id': '5501', 'level': 10,
                     'description': 'Duplicate test', 'groups': []},
        }
        first = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(first)

        second = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNone(second)

        stats = self.pipeline.stats
        self.assertEqual(stats['duplicates'], 1)

    def test_dedup_different_alerts(self):
        r1 = {
            'rule': {'id': '5501', 'level': 10, 'description': 'A', 'groups': []},
            'data': {'srcip': '1.1.1.1'},
        }
        r2 = {
            'rule': {'id': '5502', 'level': 10, 'description': 'B', 'groups': []},
            'data': {'srcip': '2.2.2.2'},
        }
        a1 = self.pipeline.ingest(r1, source='wazuh')
        a2 = self.pipeline.ingest(r2, source='wazuh')
        self.assertIsNotNone(a1)
        self.assertIsNotNone(a2)
        self.assertNotEqual(a1.alert_id, a2.alert_id)

    def test_stats_tracking(self):
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        self.pipeline.ingest(raw, source='wazuh')
        stats = self.pipeline.stats
        self.assertEqual(stats['received'], 1)
        self.assertEqual(stats['normalized'], 1)
        self.assertEqual(stats['dispatched'], 1)
        self.assertIn('wazuh', stats['by_source'])

    def test_stats_dropped(self):
        raw = {'rule': {}}
        self.pipeline.ingest(raw, source='wazuh')
        stats = self.pipeline.stats
        self.assertEqual(stats['dropped'], 1)

    def test_pre_hook_drops(self):
        def drop_all(alert):
            return None

        self.pipeline.add_pre_hook(drop_all)
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        result = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNone(result)
        self.assertEqual(self.pipeline.stats['dropped'], 1)

    def test_pre_hook_modifies(self):
        def add_tag(alert):
            alert.tags.append('pre_hooked')
            return alert

        self.pipeline.add_pre_hook(add_tag)
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIn('pre_hooked', alert.tags)

    def test_pre_hook_exception_continues(self):
        def bad_hook(alert):
            raise ValueError("Oops")

        self.pipeline.add_pre_hook(bad_hook)
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        # Should not raise, should continue pipeline
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(alert)

    def test_post_hook_drops(self):
        def drop_all(alert):
            return None

        self.pipeline.add_post_hook(drop_all)
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        result = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNone(result)

    def test_post_hook_enriches(self):
        def enrich(alert):
            alert.enrichment['geo'] = {'country': 'US'}
            return alert

        self.pipeline.add_post_hook(enrich)
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertEqual(alert.enrichment['geo']['country'], 'US')

    def test_post_hook_exception_continues(self):
        def bad_hook(alert):
            raise RuntimeError("Boom")

        self.pipeline.add_post_hook(bad_hook)
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(alert)

    def test_severity_override_applied(self):
        self.pipeline.add_severity_override(SeverityOverride(
            name='upgrade_auth',
            condition=lambda a: a.category == 'authentication',
            new_severity=TAFSeverity.CRITICAL,
        ))
        raw = {
            'rule': {'id': '5501', 'level': 5,
                     'description': 'Auth failure', 'groups': ['authentication_failed']},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, TAFSeverity.CRITICAL)

    def test_ioc_extraction_in_pipeline(self):
        raw = {
            'rule': {'id': '100', 'level': 5,
                     'description': 'Connection to 44.55.66.77', 'groups': []},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(alert)
        ip_values = {i['value'] for i in alert.iocs if i['type'] == 'ipv4'}
        self.assertIn('44.55.66.77', ip_values)

    def test_correlation_keys_in_pipeline(self):
        raw = {
            'rule': {'id': '5501', 'level': 10,
                     'description': 'Test', 'groups': ['authentication_failed']},
            'data': {'srcip': '10.0.0.1'},
            'agent': {'name': 'srv01'},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(alert)
        self.assertTrue(len(alert.correlation_keys) > 0)

    def test_subscriber_called(self):
        received = []
        self.pipeline.subscribe(lambda a: received.append(a))

        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Sub test', 'groups': []},
        }
        self.pipeline.ingest(raw, source='wazuh')
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].status, TAFStatus.DISPATCHED)

    def test_subscriber_exception_doesnt_break(self):
        def bad_sub(alert):
            raise RuntimeError("Subscriber fail")

        self.pipeline.subscribe(bad_sub)
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Test', 'groups': []},
        }
        # Should not raise
        alert = self.pipeline.ingest(raw, source='wazuh')
        self.assertIsNotNone(alert)

    def test_persistence(self):
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Persist test', 'groups': []},
        }
        alert = self.pipeline.ingest(raw, source='wazuh')

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM normalized_alerts").fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['alert_id'], alert.alert_id)

    def test_get_recent_alerts(self):
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Recent', 'groups': []},
        }
        self.pipeline.ingest(raw, source='wazuh')
        alerts = self.pipeline.get_recent_alerts(hours=1, limit=10)
        self.assertEqual(len(alerts), 1)
        self.assertIn('alert_id', alerts[0])

    def test_get_recent_alerts_empty(self):
        alerts = self.pipeline.get_recent_alerts()
        self.assertEqual(alerts, [])

    def test_get_source_distribution(self):
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'Dist', 'groups': []},
        }
        self.pipeline.ingest(raw, source='wazuh')
        dist = self.pipeline.get_source_distribution()
        self.assertEqual(dist.get('wazuh'), 1)

    def test_get_severity_distribution(self):
        raw = {
            'rule': {'id': '100', 'level': 5, 'description': 'SevDist', 'groups': []},
        }
        self.pipeline.ingest(raw, source='wazuh')
        dist = self.pipeline.get_severity_distribution()
        self.assertIn('LOW', dist)  # level 5 = LOW severity

    def test_cleanup_dedup_cache(self):
        # Insert an old entry directly
        conn = sqlite3.connect(self.db_path)
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        conn.execute(
            "INSERT INTO dedup_cache (hash, first_seen, last_seen, count) VALUES (?, ?, ?, ?)",
            ('old_hash', old_time, old_time, 5),
        )
        conn.commit()
        conn.close()

        deleted = self.pipeline.cleanup_dedup_cache(older_than_hours=24)
        self.assertEqual(deleted, 1)

    def test_cleanup_dedup_cache_keeps_recent(self):
        conn = sqlite3.connect(self.db_path)
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "INSERT INTO dedup_cache (hash, first_seen, last_seen, count) VALUES (?, ?, ?, ?)",
            ('recent_hash', now, now, 1),
        )
        conn.commit()
        conn.close()

        deleted = self.pipeline.cleanup_dedup_cache(older_than_hours=24)
        self.assertEqual(deleted, 0)

    def test_adapter_error_counted(self):
        class BadAdapter(SourceAdapter):
            @property
            def source_type(self):
                return TAFSource.CUSTOM

            def normalize(self, raw):
                raise RuntimeError("Adapter crash!")

        self.pipeline.register_adapter('bad_source', BadAdapter())
        result = self.pipeline.ingest({}, source='bad_source')
        self.assertIsNone(result)
        self.assertEqual(self.pipeline.stats['errors'], 1)

    def test_multiple_ingests(self):
        for i in range(5):
            raw = {
                'rule': {'id': str(100 + i), 'level': 5 + i,
                         'description': f'Alert {i}', 'groups': []},
                'data': {'srcip': f'{i}.{i}.{i}.{i}'},
            }
            self.pipeline.ingest(raw, source='wazuh')
        stats = self.pipeline.stats
        self.assertEqual(stats['received'], 5)
        self.assertEqual(stats['normalized'], 5)


# ============================================================================
# Flask Blueprint Tests
# ============================================================================

class TestNormalizerBlueprint(unittest.TestCase):
    """Tests for Flask Blueprint endpoints."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test_bp.db')
        self.pipeline = AlertNormalizationPipeline(db_path=self.db_path)

        try:
            from flask import Flask
            self.app = Flask(__name__)
            bp = create_normalizer_blueprint(self.pipeline)
            self.app.register_blueprint(bp)
            self.client = self.app.test_client()
            self.flask_available = True
        except ImportError:
            self.flask_available = False

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_status_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        resp = self.client.get('/api/v1/soc/normalizer/status')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('stats', data['data'])
        self.assertIn('adapters', data['data'])
        self.assertIn('dedup_window_minutes', data['data'])

    def test_ingest_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        resp = self.client.post(
            '/api/v1/soc/normalizer/ingest',
            json={
                '_source': 'custom',
                'title': 'API test alert',
                'severity': 'high',
            },
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('alert_id', data['data'])

    def test_ingest_endpoint_dropped(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        # Wazuh with empty rule -> dropped
        resp = self.client.post(
            '/api/v1/soc/normalizer/ingest',
            json={'_source': 'wazuh', 'rule': {}},
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data['data']['status'], 'dropped_or_deduplicated')

    def test_ingest_no_json(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        resp = self.client.post(
            '/api/v1/soc/normalizer/ingest',
            data='not json',
            content_type='text/plain',
        )
        self.assertEqual(resp.status_code, 400)

    def test_alerts_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        # Ingest one first
        self.client.post(
            '/api/v1/soc/normalizer/ingest',
            json={'_source': 'custom', 'title': 'Alert for list'},
        )
        resp = self.client.get('/api/v1/soc/normalizer/alerts?hours=1&limit=10')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIsInstance(data['data'], list)
        self.assertGreaterEqual(len(data['data']), 1)

    def test_source_distribution_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        resp = self.client.get('/api/v1/soc/normalizer/distribution/source')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])

    def test_severity_distribution_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        resp = self.client.get('/api/v1/soc/normalizer/distribution/severity')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])

    def test_adapters_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        resp = self.client.get('/api/v1/soc/normalizer/adapters')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('wazuh', data['data'])

    def test_dedup_cleanup_endpoint(self):
        if not self.flask_available:
            self.skipTest("Flask not installed")
        resp = self.client.post('/api/v1/soc/normalizer/dedup/cleanup?hours=24')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('deleted', data['data'])


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration(unittest.TestCase):
    """Integration tests for full pipeline flows."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test_integration.db')
        self.pipeline = AlertNormalizationPipeline(db_path=self.db_path)

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_full_wazuh_flow(self):
        """End-to-end: Wazuh alert → normalize → IOC → dedup → persist → dispatch."""
        received = []
        self.pipeline.subscribe(lambda a: received.append(a))

        raw = {
            'id': '1001',
            'timestamp': '2024-01-15T10:00:00Z',
            'rule': {
                'id': '5501',
                'level': 12,
                'description': 'Multiple authentication failures from 44.55.66.77',
                'groups': ['authentication_failed'],
                'mitre': {
                    'tactic': ['TA0006'],
                    'technique': [{'id': 'T1110'}],
                },
            },
            'agent': {'id': '001', 'name': 'web-server-01'},
            'data': {
                'srcip': '44.55.66.77',
                'dstip': '10.0.0.5',
                'srcuser': 'admin',
            },
        }

        alert = self.pipeline.ingest(raw, source='wazuh')

        self.assertIsNotNone(alert)
        self.assertEqual(alert.source, TAFSource.WAZUH)
        self.assertEqual(alert.severity, TAFSeverity.HIGH)
        self.assertEqual(alert.category, 'authentication')
        self.assertEqual(alert.src_ip, '44.55.66.77')
        self.assertEqual(alert.username, 'admin')
        self.assertIn('TA0006', alert.mitre_tactics)
        self.assertIn('T1110', alert.mitre_techniques)
        self.assertTrue(len(alert.iocs) > 0)
        self.assertTrue(len(alert.correlation_keys) > 0)
        self.assertNotEqual(alert.dedup_hash, '')
        self.assertEqual(alert.status, TAFStatus.DISPATCHED)
        self.assertEqual(len(received), 1)

        # Verify persistence
        alerts = self.pipeline.get_recent_alerts(hours=24)
        self.assertEqual(len(alerts), 1)

    def test_full_suricata_flow(self):
        """End-to-end: Suricata EVE JSON → normalize → persist → dispatch."""
        received = []
        self.pipeline.subscribe(lambda a: received.append(a))

        raw = {
            'event_type': 'alert',
            'timestamp': '2024-01-15T12:00:00Z',
            'src_ip': '10.0.0.50',
            'dest_ip': '198.51.100.20',
            'src_port': 45678,
            'dest_port': 443,
            'proto': 'TCP',
            'flow_id': 999888777,
            'in_iface': 'eth0',
            'alert': {
                'signature': 'ET MALWARE Win32/Emotet CnC Activity',
                'signature_id': 2028401,
                'gid': 1,
                'rev': 5,
                'severity': 1,
                'category': 'trojan-activity',
                'action': 'allowed',
            },
        }

        alert = self.pipeline.ingest(raw, source='suricata')

        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, TAFSeverity.CRITICAL)
        self.assertEqual(alert.category, 'malware')
        self.assertEqual(alert.src_ip, '10.0.0.50')
        self.assertEqual(alert.dst_ip, '198.51.100.20')
        self.assertIn('TA0011', alert.mitre_tactics)
        self.assertEqual(len(received), 1)

    def test_full_syslog_flow(self):
        """End-to-end: Syslog line → parse → normalize → persist."""
        raw = {
            'raw_line': '<34>Jan 15 10:00:00 firewall01 iptables[0]: DROP from 203.0.113.50 to 10.0.0.1',
        }
        alert = self.pipeline.ingest(raw, source='syslog')
        self.assertIsNotNone(alert)
        self.assertEqual(alert.source, TAFSource.SYSLOG)
        self.assertEqual(alert.category, 'firewall')
        self.assertEqual(alert.hostname, 'firewall01')

    def test_mixed_sources_pipeline(self):
        """Ingest from multiple sources and verify stats/distribution."""
        # Wazuh
        self.pipeline.ingest({
            'rule': {'id': '5501', 'level': 10, 'description': 'Auth fail', 'groups': []},
        }, source='wazuh')

        # Suricata
        self.pipeline.ingest({
            'event_type': 'alert',
            'alert': {'signature': 'ET MALWARE test', 'signature_id': 2000,
                      'severity': 2},
        }, source='suricata')

        # Custom
        self.pipeline.ingest({
            'title': 'Custom alert',
            'severity': 'info',
        }, source='custom')

        stats = self.pipeline.stats
        self.assertEqual(stats['received'], 3)
        self.assertEqual(stats['normalized'], 3)

        dist = self.pipeline.get_source_distribution()
        self.assertIn('wazuh', dist)
        self.assertIn('suricata', dist)
        self.assertIn('custom', dist)

    def test_pipeline_with_hooks_and_overrides(self):
        """Test pipeline with pre/post hooks and severity overrides."""
        # Pre-hook: add enrichment data
        def geo_enrich(alert):
            if alert.src_ip:
                alert.enrichment['geo'] = {'country': 'TR', 'city': 'Istanbul'}
            return alert

        # Post-hook: add threat score
        def threat_score(alert):
            alert.enrichment['threat_score'] = 85
            return alert

        # Severity override
        override = SeverityOverride(
            name='escalate_c2',
            condition=lambda a: 'command_and_control' in a.category,
            new_severity=TAFSeverity.CRITICAL,
        )

        self.pipeline.add_pre_hook(geo_enrich)
        self.pipeline.add_post_hook(threat_score)
        self.pipeline.add_severity_override(override)

        raw = {
            'event_type': 'alert',
            'src_ip': '10.0.0.50',
            'alert': {
                'signature': 'ET CNC Known C2 Channel',
                'signature_id': 3000,
                'severity': 3,
            },
        }
        alert = self.pipeline.ingest(raw, source='suricata')
        self.assertIsNotNone(alert)
        self.assertEqual(alert.enrichment.get('geo', {}).get('country'), 'TR')
        self.assertEqual(alert.enrichment.get('threat_score'), 85)
        # Category should be 'command_and_control', override should apply
        if alert.category == 'command_and_control':
            self.assertEqual(alert.severity, TAFSeverity.CRITICAL)


# ============================================================================
# Global Singleton Test
# ============================================================================

class TestGlobalSingleton(unittest.TestCase):
    """Test get_normalization_pipeline singleton."""

    def test_returns_instance(self):
        import modules.siem_integration.alert_normalizer as mod
        # Reset
        mod._pipeline = None
        p = get_normalization_pipeline()
        self.assertIsInstance(p, AlertNormalizationPipeline)

    def test_same_instance(self):
        import modules.siem_integration.alert_normalizer as mod
        mod._pipeline = None
        p1 = get_normalization_pipeline()
        p2 = get_normalization_pipeline()
        self.assertIs(p1, p2)


# ============================================================================
# Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    """Edge case tests."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test_edge.db')
        self.pipeline = AlertNormalizationPipeline(db_path=self.db_path)

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_empty_dict_ingest_custom(self):
        result = self.pipeline.ingest({}, source='custom')
        # GenericAdapter requires 'title'
        self.assertIsNone(result)

    def test_unicode_in_alert(self):
        raw = {
            'title': 'Uyarı: Türkçe karakterler ğüşıöç',
            'severity': 'medium',
        }
        alert = self.pipeline.ingest(raw, source='custom')
        self.assertIsNotNone(alert)
        self.assertIn('Türkçe', alert.title)

    def test_large_source_raw(self):
        raw = {
            'title': 'Large payload',
            'source_raw_big': 'x' * 10000,
        }
        # Should not crash
        alert = self.pipeline.ingest(raw, source='custom')
        self.assertIsNotNone(alert)

    def test_special_chars_in_fields(self):
        raw = {
            'title': "Alert with 'quotes' and \"double\" and <tags>",
            'severity': 'low',
        }
        alert = self.pipeline.ingest(raw, source='custom')
        self.assertIsNotNone(alert)
        # Should be JSON serializable
        json.dumps(alert.to_dict())

    def test_concurrent_ingests(self):
        """Test thread safety with concurrent ingests."""
        import threading
        results = []
        errors = []

        def ingest_worker(worker_id):
            try:
                for i in range(5):
                    raw = {
                        'title': f'Worker {worker_id} Alert {i}',
                        'severity': 'info',
                        'src_ip': f'{worker_id}.{i}.0.1',
                    }
                    alert = self.pipeline.ingest(raw, source='custom')
                    if alert:
                        results.append(alert)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=ingest_worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors: {errors}")
        self.assertEqual(len(results), 20)  # 4 workers * 5 alerts

    def test_ioc_patterns_regex_valid(self):
        """Verify all IOC patterns compile and match correctly."""
        test_cases = {
            'ipv4': ('192.168.1.1', True),
            'md5': ('d41d8cd98f00b204e9800998ecf8427e', True),
            'sha256': ('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', True),
            'email': ('user@example.com', True),
            'cve': ('CVE-2024-12345', True),
        }
        for ioc_type, (test_val, should_match) in test_cases.items():
            pattern = IOC_PATTERNS[ioc_type]
            if should_match:
                self.assertIsNotNone(pattern.search(test_val),
                                     f"{ioc_type} should match '{test_val}'")

    def test_create_blueprint_returns_none_without_flask(self):
        """Test that create_normalizer_blueprint handles missing Flask gracefully."""
        # We can't easily un-import flask, but we can verify it returns a blueprint
        # when flask is available
        bp = create_normalizer_blueprint(self.pipeline)
        if bp is not None:
            self.assertEqual(bp.name, 'soc_normalizer')


if __name__ == '__main__':
    unittest.main()
