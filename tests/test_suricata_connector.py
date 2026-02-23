#!/usr/bin/env python3
"""
Comprehensive tests for TSUNAMI Suricata IDS/IPS Connector.
Tests all classes: Config, AlertNormalizer, EVELogReader, SuricataSocket,
RuleManager, StatsMonitor, SuricataConnector, and Flask Blueprint.
"""
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.siem_integration.suricata_connector import (
    SuricataConfig,
    SuricataAlertNormalizer,
    EVELogReader,
    SuricataSocket,
    SuricataRuleManager,
    SuricataStatsMonitor,
    SuricataConnector,
    SuricataEventType,
    SuricataAction,
    RuleAction,
    SURICATA_SEVERITY_MAP,
    SURICATA_MITRE_MAP,
    SURICATA_CATEGORY_MAP,
    create_suricata_blueprint,
)


# ============================================================================
# Test 1: SuricataConfig
# ============================================================================

class TestSuricataConfig(unittest.TestCase):
    """Test SuricataConfig defaults and from_env()."""

    def test_defaults(self):
        cfg = SuricataConfig()
        self.assertEqual(cfg.eve_log_path, "/var/log/suricata/eve.json")
        self.assertEqual(cfg.socket_path, "/var/run/suricata/suricata-command.socket")
        self.assertEqual(cfg.rules_dir, "/etc/suricata/rules")
        self.assertEqual(cfg.stats_interval, 30)
        self.assertEqual(cfg.tail_interval, 0.5)
        self.assertEqual(cfg.min_severity, 4)
        self.assertFalse(cfg.ingest_flows)
        self.assertTrue(cfg.ingest_dns)
        self.assertTrue(cfg.ingest_http)
        self.assertTrue(cfg.ingest_tls)
        self.assertTrue(cfg.ingest_fileinfo)
        self.assertEqual(cfg.batch_size, 100)

    def test_from_env(self):
        env_vars = {
            'SURICATA_EVE_LOG': '/tmp/test-eve.json',
            'SURICATA_SOCKET': '/tmp/suricata.sock',
            'SURICATA_RULES_DIR': '/tmp/rules',
            'SURICATA_STATS_INTERVAL': '60',
            'SURICATA_TAIL_INTERVAL': '1.0',
            'SURICATA_MIN_SEVERITY': '2',
            'SURICATA_INGEST_FLOWS': 'true',
            'SURICATA_INGEST_DNS': 'false',
            'SURICATA_INGEST_HTTP': 'false',
            'SURICATA_INGEST_TLS': 'false',
            'SURICATA_INGEST_FILEINFO': 'false',
            'SURICATA_BATCH_SIZE': '50',
        }
        with patch.dict(os.environ, env_vars):
            cfg = SuricataConfig.from_env()

        self.assertEqual(cfg.eve_log_path, '/tmp/test-eve.json')
        self.assertEqual(cfg.socket_path, '/tmp/suricata.sock')
        self.assertEqual(cfg.rules_dir, '/tmp/rules')
        self.assertEqual(cfg.stats_interval, 60)
        self.assertEqual(cfg.tail_interval, 1.0)
        self.assertEqual(cfg.min_severity, 2)
        self.assertTrue(cfg.ingest_flows)
        self.assertFalse(cfg.ingest_dns)
        self.assertFalse(cfg.ingest_http)
        self.assertFalse(cfg.ingest_tls)
        self.assertFalse(cfg.ingest_fileinfo)
        self.assertEqual(cfg.batch_size, 50)


# ============================================================================
# Test 2: SuricataAlertNormalizer
# ============================================================================

class TestSuricataAlertNormalizer(unittest.TestCase):
    """Test alert normalization from EVE JSON to TSUNAMI format."""

    def _make_eve_alert(self, **overrides):
        """Create a sample EVE alert event."""
        base = {
            'event_type': 'alert',
            'timestamp': '2025-01-15T10:30:00.000000+0000',
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'src_port': 54321,
            'dest_port': 80,
            'proto': 'TCP',
            'in_iface': 'eth0',
            'flow_id': 123456789,
            'alert': {
                'action': 'allowed',
                'gid': 1,
                'signature_id': 2024001,
                'rev': 3,
                'signature': 'ET MALWARE Win32/Emotet CnC Activity',
                'category': 'trojan-activity',
                'severity': 1,
                'metadata': {},
            }
        }
        # Deep merge overrides
        if 'alert' in overrides:
            base['alert'].update(overrides.pop('alert'))
        base.update(overrides)
        return base

    def test_normalizes_alert_event(self):
        eve = self._make_eve_alert()
        result = SuricataAlertNormalizer.normalize(eve)

        self.assertIsNotNone(result)
        self.assertEqual(result['severity'], 'CRITICAL')
        self.assertEqual(result['source'], 'suricata')
        self.assertEqual(result['category'], 'malware')
        self.assertEqual(result['src_ip'], '192.168.1.100')
        self.assertEqual(result['dst_ip'], '10.0.0.1')
        self.assertEqual(result['src_port'], 54321)
        self.assertEqual(result['dst_port'], 80)
        self.assertEqual(result['protocol'], 'TCP')
        self.assertEqual(result['action'], 'allowed')
        self.assertEqual(result['hostname'], 'eth0')
        self.assertEqual(result['source_id'], '1:2024001:3')
        self.assertEqual(result['cvss_score'], 9.5)
        self.assertIn('TA0011', result['mitre_tactics'])
        self.assertIn('T1071', result['mitre_techniques'])
        self.assertIn('sid:2024001', result['tags'])
        self.assertTrue(result['title'].startswith('[Suricata:'))

    def test_returns_none_for_non_alert(self):
        eve = {'event_type': 'flow', 'src_ip': '1.2.3.4'}
        result = SuricataAlertNormalizer.normalize(eve)
        self.assertIsNone(result)

    def test_returns_none_for_empty_alert(self):
        eve = {'event_type': 'alert', 'alert': {}}
        # alert is empty dict - normalize should still return something (severity=4=LOW)
        result = SuricataAlertNormalizer.normalize(eve)
        # Empty alert dict is falsy? No, {} is falsy in bool(), but in normalize:
        # if not alert: return None   -- empty dict IS falsy
        self.assertIsNone(result)

    def test_severity_mapping(self):
        for priority, expected in SURICATA_SEVERITY_MAP.items():
            eve = self._make_eve_alert(alert={'severity': priority})
            result = SuricataAlertNormalizer.normalize(eve)
            self.assertIsNotNone(result)
            self.assertEqual(result['severity'], expected, f"Priority {priority}")

    def test_cvss_mapping(self):
        test_cases = [
            (1, 9.5),
            (2, 7.5),
            (3, 5.0),
            (4, 2.5),
        ]
        for priority, expected_cvss in test_cases:
            eve = self._make_eve_alert(alert={'severity': priority})
            result = SuricataAlertNormalizer.normalize(eve)
            self.assertEqual(result['cvss_score'], expected_cvss, f"Priority {priority}")

    def test_mitre_from_classtype(self):
        eve = self._make_eve_alert(alert={'category': 'web-application-attack', 'severity': 2})
        result = SuricataAlertNormalizer.normalize(eve)
        self.assertIn('TA0001', result['mitre_tactics'])
        self.assertIn('T1190', result['mitre_techniques'])

    def test_mitre_from_metadata(self):
        eve = self._make_eve_alert(alert={
            'category': 'unknown-category',
            'severity': 3,
            'metadata': {
                'mitre_tactic_id': ['TA0003'],
                'mitre_technique_id': ['T1548'],
            }
        })
        result = SuricataAlertNormalizer.normalize(eve)
        self.assertIn('TA0003', result['mitre_tactics'])
        self.assertIn('T1548', result['mitre_techniques'])

    def test_category_from_signature_prefix(self):
        categories = {
            'ET MALWARE something': 'malware',
            'ET TROJAN something': 'malware',
            'ET SCAN nmap scan': 'reconnaissance',
            'ET EXPLOIT attempt': 'exploit',
            'ET CNC cnc_traffic': 'command_and_control',
            'ET DOS attack': 'denial_of_service',
            'ET POLICY violation': 'policy_violation',
            'GPL SNMP community string': 'general',
            'SURICATA protocol anomaly': 'protocol_anomaly',
        }
        for sig, expected_cat in categories.items():
            eve = self._make_eve_alert(alert={
                'signature': sig,
                'severity': 3,
                'category': 'misc-activity',
            })
            result = SuricataAlertNormalizer.normalize(eve)
            self.assertEqual(result['category'], expected_cat, f"Signature: {sig}")

    def test_alert_id_contains_sid(self):
        eve = self._make_eve_alert()
        result = SuricataAlertNormalizer.normalize(eve)
        self.assertTrue(result['alert_id'].startswith('suricata_2024001_'))


# ============================================================================
# Test 3: EVELogReader
# ============================================================================

class TestEVELogReader(unittest.TestCase):
    """Test EVE JSON log reader with file tailing."""

    def test_reads_events_from_file(self):
        """EVELogReader reads JSON lines and calls callback."""
        events = []
        callback = lambda e: events.append(e)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            fname = f.name
            f.write(json.dumps({'event_type': 'alert', 'src_ip': '1.1.1.1'}) + '\n')
            f.write(json.dumps({'event_type': 'flow', 'src_ip': '2.2.2.2'}) + '\n')
            f.write(json.dumps({'event_type': 'stats'}) + '\n')

        try:
            reader = EVELogReader(fname, callback, tail_interval=0.1)
            reader.start()
            time.sleep(1)
            reader.stop()

            self.assertEqual(len(events), 3)
            self.assertEqual(events[0]['event_type'], 'alert')
            self.assertEqual(events[1]['event_type'], 'flow')
            self.assertEqual(events[2]['event_type'], 'stats')
            self.assertEqual(reader.stats['events_parsed'], 3)
            self.assertGreaterEqual(reader.stats['lines_read'], 3)
        finally:
            os.unlink(fname)

    def test_handles_invalid_json(self):
        """Invalid JSON lines are counted as errors."""
        events = []
        callback = lambda e: events.append(e)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            fname = f.name
            f.write('not json\n')
            f.write(json.dumps({'event_type': 'alert'}) + '\n')
            f.write('{broken\n')

        try:
            reader = EVELogReader(fname, callback, tail_interval=0.1)
            reader.start()
            time.sleep(1)
            reader.stop()

            self.assertEqual(len(events), 1)
            self.assertEqual(reader.stats['errors'], 2)
        finally:
            os.unlink(fname)

    def test_detects_log_rotation(self):
        """Log rotation detection when file is replaced."""
        events = []
        callback = lambda e: events.append(e)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            fname = f.name
            f.write(json.dumps({'event_type': 'alert', 'id': 1}) + '\n')

        try:
            reader = EVELogReader(fname, callback, tail_interval=0.1)
            reader.start()
            time.sleep(0.5)

            # Simulate rotation: delete and recreate (new inode)
            os.unlink(fname)
            with open(fname, 'w') as f:
                f.write(json.dumps({'event_type': 'alert', 'id': 2}) + '\n')

            time.sleep(1)
            reader.stop()

            self.assertGreaterEqual(len(events), 2)
        finally:
            if os.path.exists(fname):
                os.unlink(fname)

    def test_handles_missing_file(self):
        """Reader waits if file doesn't exist yet."""
        events = []
        reader = EVELogReader('/tmp/nonexistent_eve_test.json', lambda e: events.append(e), tail_interval=0.1)
        reader.start()
        time.sleep(0.5)
        reader.stop()
        self.assertEqual(len(events), 0)


# ============================================================================
# Test 4: SuricataSocket
# ============================================================================

class TestSuricataSocket(unittest.TestCase):
    """Test Suricata Unix domain socket client."""

    def test_available_false_when_no_socket(self):
        sock = SuricataSocket('/tmp/nonexistent_suricata.sock')
        self.assertFalse(sock.available)

    def test_reload_rules_raises_when_no_socket(self):
        sock = SuricataSocket('/tmp/nonexistent_suricata.sock')
        with self.assertRaises(FileNotFoundError):
            sock.reload_rules()

    def test_get_version_returns_unavailable_on_error(self):
        sock = SuricataSocket('/tmp/nonexistent_suricata.sock')
        self.assertEqual(sock.get_version(), 'unavailable')

    def test_get_uptime_returns_zero_on_error(self):
        sock = SuricataSocket('/tmp/nonexistent_suricata.sock')
        self.assertEqual(sock.get_uptime(), 0)

    def test_get_iface_stats_returns_empty_on_error(self):
        sock = SuricataSocket('/tmp/nonexistent_suricata.sock')
        self.assertEqual(sock.get_iface_stats(), {})


# ============================================================================
# Test 5: SuricataRuleManager
# ============================================================================

class TestSuricataRuleManager(unittest.TestCase):
    """Test Suricata rule management."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.rules_dir = Path(self.tmpdir)
        self.manager = SuricataRuleManager(self.tmpdir)

        # Create sample rule files
        (self.rules_dir / 'emerging-malware.rules').write_text(
            'alert tcp $HOME_NET any -> $EXTERNAL_NET any '
            '(msg:"ET MALWARE Test Rule"; sid:2024001; rev:1;)\n'
            'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 '
            '(msg:"ET TROJAN Another Rule"; sid:2024002; rev:2;)\n'
            '# alert tcp any any -> any any (msg:"Disabled Rule"; sid:2024003; rev:1;)\n',
            encoding='utf-8'
        )
        (self.rules_dir / 'local.rules').write_text(
            'drop udp any any -> any 53 '
            '(msg:"Custom DNS Block"; sid:9000001; rev:1;)\n',
            encoding='utf-8'
        )

    def tearDown(self):
        import shutil
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def test_list_rule_files(self):
        files = self.manager.list_rule_files()
        self.assertIn('emerging-malware.rules', files)
        self.assertIn('local.rules', files)
        self.assertEqual(len(files), 2)

    def test_get_rule_count(self):
        counts = self.manager.get_rule_count()
        self.assertEqual(counts['alert'], 2)
        self.assertEqual(counts['drop'], 1)
        self.assertEqual(counts['total'], 3)
        self.assertEqual(counts['disabled'], 1)

    def test_find_rule_by_sid(self):
        rule = self.manager.find_rule_by_sid(2024001)
        self.assertIsNotNone(rule)
        self.assertEqual(rule['sid'], 2024001)
        self.assertEqual(rule['file'], 'emerging-malware.rules')
        self.assertFalse(rule['disabled'])
        self.assertIn('ET MALWARE Test Rule', rule['text'])

    def test_find_disabled_rule(self):
        rule = self.manager.find_rule_by_sid(2024003)
        self.assertIsNotNone(rule)
        self.assertTrue(rule['disabled'])

    def test_find_nonexistent_sid(self):
        rule = self.manager.find_rule_by_sid(9999999)
        self.assertIsNone(rule)

    def test_disable_sid(self):
        result = self.manager.disable_sid(2024001)
        self.assertTrue(result)
        # Verify it's now disabled
        rule = self.manager.find_rule_by_sid(2024001)
        self.assertTrue(rule['disabled'])

    def test_disable_already_disabled(self):
        result = self.manager.disable_sid(2024003)
        self.assertFalse(result)

    def test_enable_sid(self):
        result = self.manager.enable_sid(2024003)
        self.assertTrue(result)
        rule = self.manager.find_rule_by_sid(2024003)
        self.assertFalse(rule['disabled'])

    def test_enable_already_enabled(self):
        result = self.manager.enable_sid(2024001)
        self.assertFalse(result)

    def test_add_custom_rule(self):
        rule_text = 'alert tcp any any -> any 8080 (msg:"Custom Rule"; sid:9000002; rev:1;)'
        result = self.manager.add_custom_rule(rule_text, 'local.rules')
        self.assertTrue(result)
        # Verify it's in the file
        content = (self.rules_dir / 'local.rules').read_text()
        self.assertIn('sid:9000002', content)

    def test_add_invalid_rule(self):
        result = self.manager.add_custom_rule('invalid rule text')
        self.assertFalse(result)

    def test_add_threshold(self):
        threshold = self.manager.add_threshold(2024001, 'limit', 'by_src', 5, 120)
        self.assertIn('sig_id 2024001', threshold)
        self.assertIn('type limit', threshold)
        self.assertIn('track by_src', threshold)
        self.assertIn('count 5', threshold)
        self.assertIn('seconds 120', threshold)

    def test_add_suppress(self):
        suppress = self.manager.add_suppress(2024001, 'by_src', '192.168.1.0/24')
        self.assertIn('sig_id 2024001', suppress)
        self.assertIn('track by_src', suppress)
        self.assertIn('ip 192.168.1.0/24', suppress)

    def test_add_suppress_no_ip(self):
        suppress = self.manager.add_suppress(2024001, 'by_dst')
        self.assertIn('track by_dst', suppress)
        self.assertNotIn('ip', suppress.split('track')[1])

    def test_reload_rules_without_socket(self):
        result = self.manager.reload_rules()
        self.assertFalse(result)

    def test_reload_rules_with_socket(self):
        mock_socket = MagicMock()
        mock_socket.available = True
        mock_socket.reload_rules.return_value = {'return': 'OK'}
        self.manager.socket = mock_socket

        result = self.manager.reload_rules()
        self.assertTrue(result)
        mock_socket.reload_rules.assert_called_once()

    def test_empty_rules_dir(self):
        import shutil
        shutil.rmtree(self.tmpdir)
        files = self.manager.list_rule_files()
        self.assertEqual(files, [])
        counts = self.manager.get_rule_count()
        self.assertEqual(counts['total'], 0)


# ============================================================================
# Test 6: SuricataStatsMonitor
# ============================================================================

class TestSuricataStatsMonitor(unittest.TestCase):
    """Test Suricata engine stats monitor."""

    def _make_stats_event(self, **overrides):
        base = {
            'event_type': 'stats',
            'timestamp': '2025-01-15T10:30:00.000000+0000',
            'stats': {
                'uptime': 3600,
                'capture': {
                    'kernel_packets': 100000,
                    'kernel_drops': 50,
                    'kernel_ifdrops': 0,
                },
                'decoder': {
                    'pkts': 99000,
                    'bytes': 50000000,
                    'ipv4': 90000,
                    'ipv6': 9000,
                    'tcp': 70000,
                    'udp': 20000,
                    'avg_pkt_size': 505,
                },
                'flow': {
                    'tcp': 5000,
                    'udp': 2000,
                    'icmpv4': 100,
                    'active': 500,
                },
                'detect': {
                    'alert': 42,
                },
            }
        }
        if 'stats' in overrides:
            base['stats'].update(overrides.pop('stats'))
        base.update(overrides)
        return base

    def test_process_stats_event(self):
        monitor = SuricataStatsMonitor()
        event = self._make_stats_event()
        monitor.process_stats_event(event)

        latest = monitor.latest
        self.assertEqual(latest['uptime'], 3600)
        self.assertEqual(latest['capture']['kernel_packets'], 100000)
        self.assertEqual(latest['capture']['kernel_drops'], 50)
        self.assertEqual(latest['decoder']['pkts'], 99000)
        self.assertEqual(latest['decoder']['tcp'], 70000)
        self.assertEqual(latest['flow']['active'], 500)
        self.assertEqual(latest['detect']['alert'], 42)

    def test_ignores_non_stats_events(self):
        monitor = SuricataStatsMonitor()
        monitor.process_stats_event({'event_type': 'alert', 'src_ip': '1.1.1.1'})
        self.assertEqual(monitor.latest, {})

    def test_drop_rate_calculation(self):
        monitor = SuricataStatsMonitor()
        event = self._make_stats_event()
        monitor.process_stats_event(event)

        # 50 drops / 100000 packets = 0.05%
        drop_rate = monitor.get_drop_rate()
        self.assertEqual(drop_rate, 0.05)

    def test_drop_rate_zero_packets(self):
        monitor = SuricataStatsMonitor()
        # No stats yet
        self.assertEqual(monitor.get_drop_rate(), 0.0)

    def test_history_tracking(self):
        monitor = SuricataStatsMonitor()
        for i in range(5):
            event = self._make_stats_event()
            event['stats']['uptime'] = i * 30
            monitor.process_stats_event(event)

        history = monitor.history
        self.assertEqual(len(history), 5)
        self.assertEqual(history[0]['uptime'], 0)
        self.assertEqual(history[4]['uptime'], 120)

    def test_history_max_size(self):
        monitor = SuricataStatsMonitor()
        for i in range(70):
            event = self._make_stats_event()
            event['stats']['uptime'] = i
            monitor.process_stats_event(event)

        # Max is 60
        self.assertEqual(len(monitor.history), 60)
        # Should have the last 60
        self.assertEqual(monitor.history[0]['uptime'], 10)
        self.assertEqual(monitor.history[-1]['uptime'], 69)


# ============================================================================
# Test 7: SuricataConnector
# ============================================================================

class TestSuricataConnector(unittest.TestCase):
    """Test main Suricata connector."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test_suricata.db')
        self.eve_path = os.path.join(self.tmpdir, 'eve.json')
        self.rules_dir = os.path.join(self.tmpdir, 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)

        self.config = SuricataConfig(
            eve_log_path=self.eve_path,
            socket_path='/tmp/nonexistent_suricata_test.sock',
            rules_dir=self.rules_dir,
            tail_interval=0.1,
            min_severity=4,
        )
        self.connector = SuricataConnector(config=self.config, db_path=self.db_path)

    def tearDown(self):
        import shutil
        if hasattr(self, 'connector') and self.connector._running:
            self.connector.stop()
        shutil.rmtree(self.tmpdir)

    def _make_eve_alert(self, sid=2024001, severity=1, src_ip='192.168.1.100',
                        dst_ip='10.0.0.1', timestamp=None):
        return {
            'event_type': 'alert',
            'timestamp': timestamp or '2025-01-15T10:30:00.000000+0000',
            'src_ip': src_ip,
            'dest_ip': dst_ip,
            'src_port': 54321,
            'dest_port': 80,
            'proto': 'TCP',
            'in_iface': 'eth0',
            'flow_id': 123456789,
            'alert': {
                'action': 'allowed',
                'gid': 1,
                'signature_id': sid,
                'rev': 3,
                'signature': 'ET MALWARE Test Rule',
                'category': 'trojan-activity',
                'severity': severity,
            }
        }

    def test_db_init(self):
        """DB tables created on init."""
        conn = sqlite3.connect(self.db_path)
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        conn.close()
        table_names = [t[0] for t in tables]
        self.assertIn('suricata_alerts', table_names)
        self.assertIn('suricata_ingestion_state', table_names)

    def test_handle_alert_stores_in_db(self):
        """Alert events are stored in DB."""
        eve = self._make_eve_alert()
        self.connector._handle_eve_event(eve)

        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM suricata_alerts").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)
        self.assertEqual(self.connector._stats['alerts_ingested'], 1)
        self.assertEqual(self.connector._stats['alerts_normalized'], 1)

    def test_dedup_prevents_duplicate_alerts(self):
        """Same alert inserted twice → only 1 stored."""
        eve = self._make_eve_alert()
        self.connector._handle_eve_event(eve)
        self.connector._handle_eve_event(eve)

        conn = sqlite3.connect(self.db_path)
        count = conn.execute("SELECT COUNT(*) FROM suricata_alerts").fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)
        self.assertEqual(self.connector._stats['alerts_ingested'], 1)

    def test_different_alerts_both_stored(self):
        """Different alerts are both stored."""
        eve1 = self._make_eve_alert(sid=2024001, src_ip='1.1.1.1')
        eve2 = self._make_eve_alert(sid=2024002, src_ip='2.2.2.2')
        self.connector._handle_eve_event(eve1)
        self.connector._handle_eve_event(eve2)

        self.assertEqual(self.connector._stats['alerts_ingested'], 2)

    def test_severity_filter(self):
        """Alerts above min_severity are filtered out."""
        self.connector.config.min_severity = 2  # Only CRITICAL and HIGH
        eve_high = self._make_eve_alert(severity=2)
        eve_low = self._make_eve_alert(severity=4)

        self.connector._handle_eve_event(eve_high)
        self.connector._handle_eve_event(eve_low)

        self.assertEqual(self.connector._stats['alerts_ingested'], 1)

    def test_alert_callbacks_fired(self):
        """Registered alert callbacks receive normalized alerts."""
        received = []
        self.connector.on_alert(lambda a: received.append(a))

        eve = self._make_eve_alert()
        self.connector._handle_eve_event(eve)

        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]['severity'], 'CRITICAL')
        self.assertEqual(received[0]['source'], 'suricata')

    def test_flow_ingestion(self):
        """Flow events dispatched when ingest_flows=True."""
        self.connector.config.ingest_flows = True
        flows = []
        self.connector.on_flow(lambda f: flows.append(f))

        flow_event = {
            'event_type': 'flow',
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'proto': 'TCP',
        }
        self.connector._handle_eve_event(flow_event)

        self.assertEqual(len(flows), 1)
        self.assertEqual(self.connector._stats['flows_ingested'], 1)

    def test_flow_not_ingested_when_disabled(self):
        """Flow events skipped when ingest_flows=False."""
        self.connector.config.ingest_flows = False
        flows = []
        self.connector.on_flow(lambda f: flows.append(f))

        flow_event = {'event_type': 'flow', 'src_ip': '1.1.1.1'}
        self.connector._handle_eve_event(flow_event)

        self.assertEqual(len(flows), 0)
        self.assertEqual(self.connector._stats['flows_ingested'], 0)

    def test_stats_events_processed(self):
        """Stats events go to stats monitor."""
        stats_event = {
            'event_type': 'stats',
            'timestamp': '2025-01-15T10:30:00+00:00',
            'stats': {
                'uptime': 3600,
                'capture': {'kernel_packets': 50000, 'kernel_drops': 10, 'kernel_ifdrops': 0},
                'decoder': {'pkts': 49000, 'bytes': 25000000, 'ipv4': 40000,
                            'ipv6': 9000, 'tcp': 30000, 'udp': 10000, 'avg_pkt_size': 510},
                'flow': {'tcp': 3000, 'udp': 1000, 'icmpv4': 50, 'active': 200},
                'detect': {'alert': 15},
            }
        }
        self.connector._handle_eve_event(stats_event)
        self.assertEqual(self.connector.stats_monitor.latest['uptime'], 3600)

    def test_events_total_counter(self):
        """Every event increments events_total."""
        self.connector._handle_eve_event({'event_type': 'alert', 'alert': {
            'gid': 1, 'signature_id': 1001, 'rev': 1, 'severity': 3,
            'signature': 'Test', 'category': 'misc-activity', 'action': 'allowed',
        }, 'src_ip': '1.1.1.1', 'dest_ip': '2.2.2.2', 'timestamp': 't1'})
        self.connector._handle_eve_event({'event_type': 'stats', 'stats': {
            'uptime': 0, 'capture': {}, 'decoder': {}, 'flow': {}, 'detect': {},
        }})
        self.assertEqual(self.connector._stats['events_total'], 2)
        self.assertEqual(self.connector._stats['events_by_type']['alert'], 1)
        self.assertEqual(self.connector._stats['events_by_type']['stats'], 1)

    def test_connector_stats_property(self):
        """Stats property aggregates all sub-component stats."""
        stats = self.connector.stats
        self.assertIn('alerts_ingested', stats)
        self.assertIn('alerts_normalized', stats)
        self.assertIn('engine', stats)
        self.assertIn('drop_rate', stats)
        self.assertIn('rules', stats)

    def test_start_stop(self):
        """Connector start/stop lifecycle."""
        # Write a dummy EVE file so the reader has something
        with open(self.eve_path, 'w') as f:
            f.write(json.dumps({'event_type': 'stats', 'stats': {
                'uptime': 0, 'capture': {}, 'decoder': {}, 'flow': {}, 'detect': {},
            }}) + '\n')

        self.connector.start()
        self.assertTrue(self.connector._running)
        self.assertIsNotNone(self.connector.eve_reader)

        time.sleep(0.5)
        self.connector.stop()
        self.assertFalse(self.connector._running)

    def test_get_top_signatures(self):
        """Top signatures query works."""
        # Insert some alerts
        for i in range(5):
            eve = self._make_eve_alert(sid=2024001, src_ip=f'10.0.0.{i}',
                                       timestamp=f'2025-01-15T10:30:0{i}.000+0000')
            self.connector._handle_alert(eve)
        for i in range(3):
            eve = self._make_eve_alert(sid=2024002, src_ip=f'10.0.1.{i}',
                                       timestamp=f'2025-01-15T10:31:0{i}.000+0000')
            self.connector._handle_alert(eve)

        top = self.connector.get_top_signatures(hours=24*365)
        self.assertGreaterEqual(len(top), 2)
        self.assertEqual(top[0]['sid'], '2024001')
        self.assertEqual(top[0]['hit_count'], 5)

    def test_get_top_attackers(self):
        """Top attackers query works."""
        for i in range(4):
            eve = self._make_eve_alert(src_ip='10.0.0.1',
                                       timestamp=f'2025-01-15T10:30:0{i}.000+0000')
            self.connector._handle_alert(eve)
        for i in range(2):
            eve = self._make_eve_alert(src_ip='10.0.0.2',
                                       timestamp=f'2025-01-15T10:31:0{i}.000+0000')
            self.connector._handle_alert(eve)

        top = self.connector.get_top_attackers(hours=24*365)
        self.assertGreaterEqual(len(top), 2)
        self.assertEqual(top[0]['src_ip'], '10.0.0.1')
        self.assertEqual(top[0]['alert_count'], 4)

    def test_get_severity_distribution(self):
        """Severity distribution query works."""
        self.connector._handle_alert(self._make_eve_alert(severity=1,
            timestamp='2025-01-15T10:30:01.000+0000'))
        self.connector._handle_alert(self._make_eve_alert(severity=1, src_ip='2.2.2.2',
            timestamp='2025-01-15T10:30:02.000+0000'))
        self.connector._handle_alert(self._make_eve_alert(severity=3, src_ip='3.3.3.3',
            timestamp='2025-01-15T10:30:03.000+0000'))

        dist = self.connector.get_severity_distribution(hours=24*365)
        self.assertEqual(dist.get('CRITICAL', 0), 2)
        self.assertEqual(dist.get('MEDIUM', 0), 1)

    def test_get_alert_count(self):
        """Alert count query."""
        self.connector._handle_alert(self._make_eve_alert(
            timestamp='2025-01-15T10:30:01.000+0000'))
        self.connector._handle_alert(self._make_eve_alert(src_ip='5.5.5.5',
            timestamp='2025-01-15T10:30:02.000+0000'))

        count = self.connector.get_alert_count(hours=24*365)
        self.assertEqual(count, 2)


# ============================================================================
# Test 8: Flask Blueprint
# ============================================================================

class TestSuricataBlueprint(unittest.TestCase):
    """Test Flask API endpoints."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, 'test.db')
        self.rules_dir = os.path.join(self.tmpdir, 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)

        config = SuricataConfig(
            eve_log_path='/tmp/none.json',
            socket_path='/tmp/none.sock',
            rules_dir=self.rules_dir,
        )
        self.connector = SuricataConnector(config=config, db_path=self.db_path)
        bp = create_suricata_blueprint(self.connector)

        from flask import Flask
        self.app = Flask(__name__)
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir)

    def test_status_endpoint(self):
        resp = self.client.get('/api/v1/soc/suricata/status')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('stats', data['data'])
        self.assertFalse(data['data']['running'])

    def test_top_signatures_endpoint(self):
        resp = self.client.get('/api/v1/soc/suricata/alerts/top-signatures')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIsInstance(data['data'], list)

    def test_top_attackers_endpoint(self):
        resp = self.client.get('/api/v1/soc/suricata/alerts/top-attackers?hours=24&limit=10')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])

    def test_severity_endpoint(self):
        resp = self.client.get('/api/v1/soc/suricata/alerts/severity')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])

    def test_rule_stats_endpoint(self):
        resp = self.client.get('/api/v1/soc/suricata/rules/stats')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('total', data['data'])

    def test_find_rule_not_found(self):
        resp = self.client.get('/api/v1/soc/suricata/rules/find/9999999')
        self.assertEqual(resp.status_code, 404)

    def test_engine_stats_endpoint(self):
        resp = self.client.get('/api/v1/soc/suricata/engine/stats')
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('drop_rate', data['data'])


# ============================================================================
# Test 9: Enums
# ============================================================================

class TestEnums(unittest.TestCase):
    """Test enum definitions."""

    def test_event_types(self):
        self.assertEqual(SuricataEventType.ALERT.value, 'alert')
        self.assertEqual(SuricataEventType.FLOW.value, 'flow')
        self.assertEqual(SuricataEventType.DNS.value, 'dns')
        self.assertEqual(SuricataEventType.STATS.value, 'stats')

    def test_actions(self):
        self.assertEqual(SuricataAction.ALLOWED.value, 'allowed')
        self.assertEqual(SuricataAction.BLOCKED.value, 'blocked')

    def test_rule_actions(self):
        self.assertEqual(RuleAction.ALERT.value, 'alert')
        self.assertEqual(RuleAction.DROP.value, 'drop')
        self.assertEqual(RuleAction.REJECT.value, 'reject')


# ============================================================================
# Test 10: Constants
# ============================================================================

class TestConstants(unittest.TestCase):
    """Test constant mappings."""

    def test_severity_map_complete(self):
        for key in [1, 2, 3, 4, 255]:
            self.assertIn(key, SURICATA_SEVERITY_MAP)

    def test_mitre_map_has_entries(self):
        self.assertGreaterEqual(len(SURICATA_MITRE_MAP), 15)
        for key, (tactics, techniques) in SURICATA_MITRE_MAP.items():
            self.assertIsInstance(tactics, (list, tuple))
            self.assertIsInstance(techniques, (list, tuple))
            self.assertTrue(all(t.startswith('TA') for t in tactics))
            self.assertTrue(all(t.startswith('T') for t in techniques))

    def test_category_map_has_entries(self):
        self.assertGreaterEqual(len(SURICATA_CATEGORY_MAP), 10)
        self.assertIn('ET MALWARE', SURICATA_CATEGORY_MAP)
        self.assertIn('GPL', SURICATA_CATEGORY_MAP)
        self.assertIn('SURICATA', SURICATA_CATEGORY_MAP)


# ============================================================================
# Test 11: Integration - Full Pipeline
# ============================================================================

class TestIntegrationPipeline(unittest.TestCase):
    """Integration test: EVE file → Connector → Alert callback."""

    def test_full_pipeline(self):
        tmpdir = tempfile.mkdtemp()
        eve_path = os.path.join(tmpdir, 'eve.json')
        db_path = os.path.join(tmpdir, 'test.db')

        alerts = []

        config = SuricataConfig(
            eve_log_path=eve_path,
            socket_path='/tmp/none.sock',
            rules_dir=tmpdir,
            tail_interval=0.1,
        )
        connector = SuricataConnector(config=config, db_path=db_path)
        connector.on_alert(lambda a: alerts.append(a))

        # Write EVE events to file
        with open(eve_path, 'w') as f:
            f.write(json.dumps({
                'event_type': 'alert',
                'timestamp': '2025-01-15T10:30:00.000000+0000',
                'src_ip': '192.168.1.100',
                'dest_ip': '10.0.0.1',
                'src_port': 54321,
                'dest_port': 80,
                'proto': 'TCP',
                'in_iface': 'eth0',
                'flow_id': 111,
                'alert': {
                    'action': 'allowed',
                    'gid': 1,
                    'signature_id': 2024001,
                    'rev': 1,
                    'signature': 'ET MALWARE Test Malware',
                    'category': 'trojan-activity',
                    'severity': 1,
                }
            }) + '\n')
            f.write(json.dumps({
                'event_type': 'stats',
                'timestamp': '2025-01-15T10:30:01.000000+0000',
                'stats': {
                    'uptime': 60,
                    'capture': {'kernel_packets': 1000, 'kernel_drops': 1, 'kernel_ifdrops': 0},
                    'decoder': {'pkts': 990, 'bytes': 500000, 'ipv4': 900,
                                'ipv6': 90, 'tcp': 700, 'udp': 200, 'avg_pkt_size': 505},
                    'flow': {'tcp': 50, 'udp': 20, 'icmpv4': 5, 'active': 30},
                    'detect': {'alert': 1},
                }
            }) + '\n')

        connector.start()
        time.sleep(1.5)
        connector.stop()

        # Verify alerts received
        self.assertGreaterEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['severity'], 'CRITICAL')
        self.assertEqual(alerts[0]['source'], 'suricata')
        self.assertEqual(alerts[0]['category'], 'malware')

        # Verify DB
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM suricata_alerts").fetchone()[0]
        conn.close()
        self.assertGreaterEqual(count, 1)

        # Verify stats
        self.assertGreaterEqual(connector.stats_monitor.latest.get('uptime', 0), 60)

        import shutil
        shutil.rmtree(tmpdir)


# ============================================================================
# Test 12: Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling."""

    def test_normalizer_unknown_classtype(self):
        """Unknown classtype → no MITRE mapping, but alert still works."""
        eve = {
            'event_type': 'alert',
            'timestamp': '2025-01-15T10:30:00+00:00',
            'src_ip': '1.1.1.1',
            'dest_ip': '2.2.2.2',
            'src_port': 100,
            'dest_port': 200,
            'proto': 'UDP',
            'alert': {
                'gid': 1,
                'signature_id': 9999,
                'rev': 1,
                'signature': 'Unknown Rule',
                'category': 'some-unknown-thing',
                'severity': 3,
                'action': 'allowed',
            }
        }
        result = SuricataAlertNormalizer.normalize(eve)
        self.assertIsNotNone(result)
        self.assertEqual(result['mitre_tactics'], [])
        self.assertEqual(result['mitre_techniques'], [])
        self.assertEqual(result['category'], 'general')

    def test_connector_callback_error_doesnt_crash(self):
        """Bad callback doesn't crash the connector."""
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, 'test.db')
        config = SuricataConfig(rules_dir=tmpdir)
        connector = SuricataConnector(config=config, db_path=db_path)

        def bad_callback(a):
            raise RuntimeError("Callback exploded")

        connector.on_alert(bad_callback)

        eve = {
            'event_type': 'alert',
            'timestamp': '2025-01-15T10:30:00+00:00',
            'src_ip': '1.1.1.1',
            'dest_ip': '2.2.2.2',
            'alert': {
                'gid': 1, 'signature_id': 1001, 'rev': 1,
                'signature': 'Test', 'category': 'misc-activity',
                'severity': 3, 'action': 'allowed',
            }
        }
        # Should not raise
        connector._handle_eve_event(eve)
        self.assertEqual(connector._stats['alerts_ingested'], 1)

        import shutil
        shutil.rmtree(tmpdir)

    def test_normalizer_missing_fields_graceful(self):
        """Normalizer handles minimal alert data."""
        eve = {
            'event_type': 'alert',
            'alert': {
                'signature_id': 1,
                'signature': 'Minimal',
                'severity': 4,
                'action': 'allowed',
                'category': '',
            }
        }
        result = SuricataAlertNormalizer.normalize(eve)
        self.assertIsNotNone(result)
        self.assertEqual(result['severity'], 'LOW')
        self.assertEqual(result['src_ip'], '')
        self.assertEqual(result['dst_ip'], '')
        self.assertEqual(result['protocol'], '')


if __name__ == '__main__':
    unittest.main()
