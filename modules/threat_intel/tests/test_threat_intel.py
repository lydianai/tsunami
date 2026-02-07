#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Threat Intel Module Tests

Run with: pytest modules/threat_intel/tests/ -v
"""

import pytest
import json
from datetime import datetime
from unittest.mock import patch, MagicMock

# Import modules to test
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from modules.threat_intel.stix_taxii_client import (
    STIXTAXIIClient, ThreatFeedConfig, FeedType, FeedStatus
)
from modules.threat_intel.stix_parser import (
    STIXParser, ParsedIndicator, MITREMapper
)
from modules.threat_intel.threat_correlator import (
    ThreatCorrelator, ThreatSeverity, AlertStatus, IndicatorIndex
)


class TestSTIXParser:
    """Tests for STIX Parser"""

    def test_extract_ip_from_text(self):
        """Test IP extraction from plain text"""
        parser = STIXParser()
        text = "The attacker used IP 192.168.1.100 and 10.0.0.1 in the attack."
        indicators = parser.extract_indicators_from_text(text)

        ips = [i.value for i in indicators if i.type == 'ipv4']
        assert '192.168.1.100' in ips
        assert '10.0.0.1' in ips

    def test_extract_domain_from_text(self):
        """Test domain extraction from plain text"""
        parser = STIXParser()
        text = "Malware contacted evil.com and malware.example.org"
        indicators = parser.extract_indicators_from_text(text)

        domains = [i.value for i in indicators if i.type == 'domain']
        assert 'evil.com' in domains
        assert 'malware.example.org' in domains

    def test_extract_hash_from_text(self):
        """Test hash extraction from plain text"""
        parser = STIXParser()
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        text = f"File hashes: MD5={md5} SHA256={sha256}"

        indicators = parser.extract_indicators_from_text(text)

        hashes = {i.type: i.value for i in indicators}
        assert hashes.get('md5') == md5
        assert hashes.get('sha256') == sha256

    def test_extract_url_from_text(self):
        """Test URL extraction from plain text"""
        parser = STIXParser()
        text = "Download from https://evil.com/malware.exe and http://bad.org/payload"
        indicators = parser.extract_indicators_from_text(text)

        urls = [i.value for i in indicators if i.type == 'url']
        assert 'https://evil.com/malware.exe' in urls
        assert 'http://bad.org/payload' in urls

    def test_extract_cve_from_text(self):
        """Test CVE extraction from plain text"""
        parser = STIXParser()
        text = "Exploits CVE-2021-44228 (Log4Shell) and CVE-2023-12345"
        indicators = parser.extract_indicators_from_text(text)

        cves = [i.value for i in indicators if i.type == 'cve']
        assert 'CVE-2021-44228' in cves
        assert 'CVE-2023-12345' in cves

    def test_parse_stix_bundle(self):
        """Test parsing STIX 2.1 bundle"""
        parser = STIXParser()

        bundle = {
            "type": "bundle",
            "id": "bundle--test-123",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--test-1",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "labels": ["malicious-activity"]
                },
                {
                    "type": "malware",
                    "id": "malware--test-1",
                    "name": "TestMalware",
                    "malware_types": ["ransomware"],
                    "is_family": True
                }
            ]
        }

        result = parser.parse_bundle(bundle, source="test")

        assert result['statistics']['indicators_count'] == 1
        assert result['statistics']['malware_count'] == 1
        assert len(result['indicators']) == 1
        assert result['indicators'][0]['value'] == '1.2.3.4'


class TestMITREMapper:
    """Tests for MITRE ATT&CK Mapper"""

    def test_get_techniques_for_ip_indicator(self):
        """Test technique mapping for IP indicators"""
        techniques = MITREMapper.get_techniques_for_indicator('ipv4-addr')
        assert 'T1071' in techniques  # Application Layer Protocol

    def test_get_techniques_for_ransomware(self):
        """Test technique mapping for ransomware"""
        techniques = MITREMapper.get_techniques_for_malware(['ransomware'])
        assert 'T1486' in techniques  # Data Encrypted for Impact

    def test_get_tactic_id(self):
        """Test tactic ID lookup"""
        assert MITREMapper.get_tactic_id('initial-access') == 'TA0001'
        assert MITREMapper.get_tactic_id('command-and-control') == 'TA0011'

    def test_extract_mitre_id(self):
        """Test MITRE ID extraction from references"""
        refs = [
            {"source_name": "mitre-attack", "external_id": "T1566"},
            {"source_name": "other", "url": "http://example.com"}
        ]
        assert MITREMapper.extract_mitre_id(refs) == 'T1566'


class TestIndicatorIndex:
    """Tests for Indicator Index"""

    def test_add_and_lookup_ip(self):
        """Test IP indexing and lookup"""
        index = IndicatorIndex()
        indicator = {'type': 'ip', 'value': '192.168.1.1', 'source': 'test'}
        index.add_indicator(indicator)

        results = index.lookup_ip('192.168.1.1')
        assert len(results) == 1
        assert results[0]['value'] == '192.168.1.1'

    def test_cidr_lookup(self):
        """Test CIDR range lookup"""
        index = IndicatorIndex()
        indicator = {'type': 'ip', 'value': '10.0.0.0/8', 'source': 'test'}
        index.add_indicator(indicator)

        # IP within range
        results = index.lookup_ip('10.1.2.3')
        assert len(results) == 1

        # IP outside range
        results = index.lookup_ip('192.168.1.1')
        assert len(results) == 0

    def test_add_and_lookup_domain(self):
        """Test domain indexing and lookup"""
        index = IndicatorIndex()
        indicator = {'type': 'domain', 'value': 'evil.com', 'source': 'test'}
        index.add_indicator(indicator)

        results = index.lookup_domain('evil.com')
        assert len(results) == 1

    def test_wildcard_domain_lookup(self):
        """Test wildcard domain lookup"""
        index = IndicatorIndex()
        indicator = {'type': 'domain', 'value': '*.evil.com', 'source': 'test'}
        index.add_indicator(indicator)

        # Subdomain match
        results = index.lookup_domain('malware.evil.com')
        assert len(results) == 1

        # Root domain doesn't match wildcard
        results = index.lookup_domain('evil.com')
        assert len(results) == 1  # Pattern matches root too

    def test_add_and_lookup_hash(self):
        """Test hash indexing and lookup"""
        index = IndicatorIndex()
        hash_value = "d41d8cd98f00b204e9800998ecf8427e"
        indicator = {'type': 'hash_md5', 'value': hash_value, 'source': 'test'}
        index.add_indicator(indicator)

        results = index.lookup_hash(hash_value)
        assert len(results) == 1

        # Case insensitive
        results = index.lookup_hash(hash_value.upper())
        assert len(results) == 1

    def test_stats(self):
        """Test index statistics"""
        index = IndicatorIndex()
        index.add_indicator({'type': 'ip', 'value': '1.1.1.1', 'source': 'test'})
        index.add_indicator({'type': 'domain', 'value': 'test.com', 'source': 'test'})

        stats = index.get_stats()
        assert stats['total'] == 2
        assert stats['ips'] == 1
        assert stats['domains'] == 1


class TestThreatCorrelator:
    """Tests for Threat Correlator"""

    @pytest.fixture
    def correlator(self):
        """Create correlator with mocked client"""
        with patch('modules.threat_intel.threat_correlator.get_stix_client') as mock:
            mock_client = MagicMock()
            mock_client.fetch_all_feeds.return_value = {
                'test_feed': [
                    {'type': 'ip', 'value': '192.168.1.100', 'source': 'test_feed'},
                    {'type': 'domain', 'value': 'malware.com', 'source': 'test_feed'}
                ]
            }
            mock_client.get_feed_status.return_value = {}
            mock.return_value = mock_client

            correlator = ThreatCorrelator(stix_client=mock_client)
            return correlator

    def test_check_known_ip(self, correlator):
        """Test checking known malicious IP"""
        result = correlator.check_indicator('192.168.1.100', 'ip')

        assert result.is_threat
        assert result.score > 0
        assert 'test_feed' in result.sources

    def test_check_unknown_ip(self, correlator):
        """Test checking unknown IP"""
        result = correlator.check_indicator('8.8.8.8', 'ip')

        assert not result.is_threat
        assert result.score == 0

    def test_check_known_domain(self, correlator):
        """Test checking known malicious domain"""
        result = correlator.check_indicator('malware.com', 'domain')

        assert result.is_threat
        assert result.score > 0

    def test_auto_detect_type(self, correlator):
        """Test automatic type detection"""
        # IP
        result = correlator.check_indicator('1.2.3.4')
        assert result.indicator_type == 'ip'

        # Domain
        result = correlator.check_indicator('test.example.com')
        assert result.indicator_type == 'domain'

        # URL
        result = correlator.check_indicator('https://evil.com/path')
        assert result.indicator_type == 'url'

        # Hash MD5
        result = correlator.check_indicator('d41d8cd98f00b204e9800998ecf8427e')
        assert result.indicator_type == 'hash_md5'

        # CVE
        result = correlator.check_indicator('CVE-2021-44228')
        assert result.indicator_type == 'cve'

    def test_severity_scoring(self, correlator):
        """Test severity scoring"""
        # Known threat should have higher severity
        result = correlator.check_indicator('192.168.1.100', 'ip')

        assert result.severity in [
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH,
            ThreatSeverity.MEDIUM
        ]

    def test_check_batch(self, correlator):
        """Test batch indicator checking"""
        indicators = [
            {'value': '192.168.1.100', 'type': 'ip'},
            {'value': 'malware.com', 'type': 'domain'},
            {'value': '8.8.8.8', 'type': 'ip'}
        ]

        results = correlator.check_batch(indicators)

        assert len(results) == 3
        assert results[0].is_threat  # Known IP
        assert results[1].is_threat  # Known domain
        assert not results[2].is_threat  # Unknown IP

    def test_alert_creation(self, correlator):
        """Test alert creation for high severity threats"""
        # Add a high-confidence indicator
        correlator.index.add_indicator({
            'type': 'ip',
            'value': '10.0.0.1',
            'source': 'cisa_kev',  # High weight source
            'confidence': 99
        })

        result = correlator.check_indicator('10.0.0.1', 'ip')

        # Check if alert was created
        alerts = correlator.get_alerts()
        if result.severity in [ThreatSeverity.CRITICAL, ThreatSeverity.HIGH]:
            assert len(alerts) > 0

    def test_statistics(self, correlator):
        """Test statistics collection"""
        # Make some checks
        correlator.check_indicator('192.168.1.100', 'ip')
        correlator.check_indicator('8.8.8.8', 'ip')

        stats = correlator.get_statistics()

        assert stats['total_checks'] >= 2
        assert 'index_stats' in stats
        assert 'feed_status' in stats


class TestSTIXTAXIIClient:
    """Tests for STIX/TAXII Client"""

    def test_feed_initialization(self):
        """Test default feed configuration"""
        client = STIXTAXIIClient()

        assert len(client.feeds) > 0
        assert 'abuse_ch_urlhaus' in client.feeds
        assert 'cisa_kev' in client.feeds

    def test_add_custom_feed(self):
        """Test adding custom feed"""
        client = STIXTAXIIClient()

        custom_feed = ThreatFeedConfig(
            name='custom_feed',
            url='https://example.com/feed.json',
            feed_type=FeedType.JSON,
            description='Custom test feed'
        )

        client.add_feed(custom_feed)

        assert 'custom_feed' in client.feeds
        assert client.feeds['custom_feed'].description == 'Custom test feed'

    def test_enable_disable_feed(self):
        """Test enabling/disabling feeds"""
        client = STIXTAXIIClient()

        client.enable_feed('abuse_ch_urlhaus', False)
        assert not client.feeds['abuse_ch_urlhaus'].enabled

        client.enable_feed('abuse_ch_urlhaus', True)
        assert client.feeds['abuse_ch_urlhaus'].enabled

    def test_set_api_key(self):
        """Test setting API key"""
        client = STIXTAXIIClient()

        client.set_api_key('alienvault_otx', 'test-api-key')

        assert client.feeds['alienvault_otx'].api_key == 'test-api-key'
        assert client.feeds['alienvault_otx'].enabled

    def test_statistics(self):
        """Test client statistics"""
        client = STIXTAXIIClient()
        stats = client.get_statistics()

        assert 'total_feeds' in stats
        assert 'enabled_feeds' in stats
        assert stats['total_feeds'] > 0


# Integration test (requires network)
@pytest.mark.integration
@pytest.mark.skipif(True, reason="Requires network access")
class TestIntegration:
    """Integration tests that require network access"""

    def test_fetch_urlhaus(self):
        """Test fetching URLhaus feed"""
        client = STIXTAXIIClient()
        indicators = client.fetch_feed('abuse_ch_urlhaus')

        assert len(indicators) > 0
        assert all('type' in i for i in indicators)

    def test_fetch_feodo(self):
        """Test fetching Feodo tracker"""
        client = STIXTAXIIClient()
        indicators = client.fetch_feed('abuse_ch_feodo')

        assert len(indicators) > 0
        assert all(i.get('type') == 'ip' for i in indicators)

    def test_fetch_cisa_kev(self):
        """Test fetching CISA KEV"""
        client = STIXTAXIIClient()
        indicators = client.fetch_feed('cisa_kev')

        assert len(indicators) > 0
        assert all(i.get('type') == 'cve' for i in indicators)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
