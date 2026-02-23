#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - IOC Enrichment Engine Tests
    Comprehensive tests for VirusTotal, AbuseIPDB, Shodan integration
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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.enrichment.ioc_enrichment import (
    IOCType,
    ThreatLevel,
    ProviderStatus,
    detect_ioc_type,
    ProviderResult,
    EnrichmentResult,
    RateLimitState,
    EnrichmentCache,
    EnrichmentProvider,
    VirusTotalProvider,
    AbuseIPDBProvider,
    ShodanProvider,
    IOCEnrichmentEngine,
    create_enrichment_blueprint,
    get_enrichment_engine,
)


# ============================================================================
# Test IOC Type Detection
# ============================================================================

class TestIOCTypeDetection(unittest.TestCase):

    def test_ipv4(self):
        self.assertEqual(detect_ioc_type("192.168.1.1"), IOCType.IPV4)

    def test_ipv4_public(self):
        self.assertEqual(detect_ioc_type("8.8.8.8"), IOCType.IPV4)

    def test_ipv6(self):
        self.assertEqual(detect_ioc_type("2001:0db8::1"), IOCType.IPV6)

    def test_ipv6_full(self):
        self.assertEqual(detect_ioc_type("fe80::1ff:fe23:4567:890a"), IOCType.IPV6)

    def test_md5(self):
        self.assertEqual(
            detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e"), IOCType.MD5
        )

    def test_sha1(self):
        self.assertEqual(
            detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"), IOCType.SHA1
        )

    def test_sha256(self):
        self.assertEqual(
            detect_ioc_type(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            IOCType.SHA256,
        )

    def test_domain(self):
        self.assertEqual(detect_ioc_type("example.com"), IOCType.DOMAIN)

    def test_domain_subdomain(self):
        self.assertEqual(detect_ioc_type("sub.example.co.uk"), IOCType.DOMAIN)

    def test_url_http(self):
        self.assertEqual(detect_ioc_type("http://example.com/path"), IOCType.URL)

    def test_url_https(self):
        self.assertEqual(detect_ioc_type("https://example.com/path?q=1"), IOCType.URL)

    def test_email(self):
        self.assertEqual(detect_ioc_type("user@example.com"), IOCType.EMAIL)

    def test_unknown_string(self):
        self.assertEqual(detect_ioc_type("just_a_random_string"), IOCType.UNKNOWN)

    def test_empty_string(self):
        self.assertEqual(detect_ioc_type(""), IOCType.UNKNOWN)

    def test_none_input(self):
        self.assertEqual(detect_ioc_type(None), IOCType.UNKNOWN)

    def test_whitespace_stripped(self):
        self.assertEqual(detect_ioc_type("  8.8.8.8  "), IOCType.IPV4)

    def test_hash_priority_over_domain(self):
        # 32-char hex is MD5, not treated as domain
        self.assertEqual(
            detect_ioc_type("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb"), IOCType.MD5
        )

    def test_non_string(self):
        self.assertEqual(detect_ioc_type(12345), IOCType.UNKNOWN)


# ============================================================================
# Test IOCType Enum
# ============================================================================

class TestIOCType(unittest.TestCase):

    def test_values(self):
        self.assertEqual(IOCType.IPV4.value, "ipv4")
        self.assertEqual(IOCType.SHA256.value, "sha256")
        self.assertEqual(IOCType.UNKNOWN.value, "unknown")


# ============================================================================
# Test ThreatLevel Enum
# ============================================================================

class TestThreatLevel(unittest.TestCase):

    def test_numeric(self):
        self.assertEqual(ThreatLevel.CRITICAL.numeric, 5)
        self.assertEqual(ThreatLevel.HIGH.numeric, 4)
        self.assertEqual(ThreatLevel.MEDIUM.numeric, 3)
        self.assertEqual(ThreatLevel.LOW.numeric, 2)
        self.assertEqual(ThreatLevel.CLEAN.numeric, 1)
        self.assertEqual(ThreatLevel.UNKNOWN.numeric, 0)

    def test_values(self):
        self.assertEqual(ThreatLevel.CRITICAL.value, "critical")
        self.assertEqual(ThreatLevel.CLEAN.value, "clean")


# ============================================================================
# Test ProviderResult
# ============================================================================

class TestProviderResult(unittest.TestCase):

    def test_default_creation(self):
        r = ProviderResult(provider="test", ioc_value="1.2.3.4", ioc_type="ipv4")
        self.assertEqual(r.provider, "test")
        self.assertFalse(r.found)
        self.assertFalse(r.malicious)
        self.assertEqual(r.score, 0.0)
        self.assertIsNone(r.error)
        self.assertFalse(r.cached)

    def test_to_dict(self):
        r = ProviderResult(
            provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4",
            found=True, malicious=True, score=85.0, tags=["bad"],
        )
        d = r.to_dict()
        self.assertEqual(d["provider"], "vt")
        self.assertTrue(d["found"])
        self.assertEqual(d["score"], 85.0)
        self.assertIn("bad", d["tags"])

    def test_with_error(self):
        r = ProviderResult(
            provider="test", ioc_value="x", ioc_type="ipv4",
            error="timeout",
        )
        self.assertEqual(r.error, "timeout")


# ============================================================================
# Test EnrichmentResult
# ============================================================================

class TestEnrichmentResult(unittest.TestCase):

    def test_default_creation(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        self.assertEqual(r.threat_level, ThreatLevel.UNKNOWN.value)
        self.assertEqual(r.aggregate_score, 0.0)
        self.assertEqual(len(r.providers), 0)

    def test_compute_threat_level_critical(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4",
                          score=90.0, malicious=True),
        ]
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "critical")
        self.assertEqual(r.aggregate_score, 90.0)

    def test_compute_threat_level_high(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4",
                          score=65.0, malicious=True),
        ]
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "high")

    def test_compute_threat_level_medium(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4",
                          score=45.0, malicious=True),
        ]
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "medium")

    def test_compute_threat_level_low(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4",
                          score=20.0),
        ]
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "low")

    def test_compute_threat_level_clean(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4",
                          score=5.0),
        ]
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "clean")

    def test_compute_threat_level_unknown_no_providers(self):
        r = EnrichmentResult(ioc_value="x", ioc_type="unknown")
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "unknown")

    def test_compute_threat_level_all_errors(self):
        r = EnrichmentResult(ioc_value="x", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="x", ioc_type="ipv4",
                          error="timeout", score=0.0),
        ]
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "unknown")

    def test_compute_aggregates_tags(self):
        r = EnrichmentResult(ioc_value="x", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="x", ioc_type="ipv4",
                          score=10.0, tags=["tag1"]),
            ProviderResult(provider="abuse", ioc_value="x", ioc_type="ipv4",
                          score=5.0, tags=["tag2"]),
        ]
        r.compute_threat_level()
        self.assertIn("tag1", r.tags)
        self.assertIn("tag2", r.tags)

    def test_compute_malicious_uses_max_score(self):
        r = EnrichmentResult(ioc_value="x", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="x", ioc_type="ipv4",
                          score=90.0, malicious=True),
            ProviderResult(provider="abuse", ioc_value="x", ioc_type="ipv4",
                          score=20.0),
        ]
        r.compute_threat_level()
        self.assertEqual(r.aggregate_score, 90.0)  # max when malicious

    def test_compute_clean_uses_average(self):
        r = EnrichmentResult(ioc_value="x", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="x", ioc_type="ipv4",
                          score=10.0),
            ProviderResult(provider="abuse", ioc_value="x", ioc_type="ipv4",
                          score=20.0),
        ]
        r.compute_threat_level()
        self.assertEqual(r.aggregate_score, 15.0)  # average when no malicious

    def test_to_dict(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        r.tags.add("test")
        d = r.to_dict()
        self.assertEqual(d["ioc_value"], "1.2.3.4")
        self.assertIn("test", d["tags"])
        self.assertIsInstance(d["tags"], list)

    def test_to_dict_serializable(self):
        r = EnrichmentResult(ioc_value="1.2.3.4", ioc_type="ipv4")
        r.providers = [
            ProviderResult(provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4"),
        ]
        d = r.to_dict()
        serialized = json.dumps(d)
        self.assertIsInstance(serialized, str)


# ============================================================================
# Test RateLimitState
# ============================================================================

class TestRateLimitState(unittest.TestCase):

    def test_initial_state(self):
        rl = RateLimitState(requests_per_minute=2, requests_per_day=10)
        self.assertTrue(rl.can_request())

    def test_minute_limit(self):
        rl = RateLimitState(requests_per_minute=2, requests_per_day=100)
        rl.record_request()
        rl.record_request()
        self.assertFalse(rl.can_request())

    def test_day_limit(self):
        rl = RateLimitState(requests_per_minute=100, requests_per_day=2)
        rl.record_request()
        rl.record_request()
        self.assertFalse(rl.can_request())

    def test_reset_after_window(self):
        rl = RateLimitState(requests_per_minute=1, requests_per_day=100)
        rl.record_request()
        self.assertFalse(rl.can_request())
        # Simulate minute reset
        rl.minute_reset = time.time() - 1
        self.assertTrue(rl.can_request())

    def test_thread_safety(self):
        rl = RateLimitState(requests_per_minute=100, requests_per_day=100)
        errors = []

        def record():
            try:
                for _ in range(10):
                    rl.record_request()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 0)


# ============================================================================
# Test EnrichmentCache
# ============================================================================

class TestEnrichmentCache(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_cache.db")
        self.cache = EnrichmentCache(db_path=self.db_path, default_ttl=3600)

    def test_db_initialized(self):
        self.assertTrue(os.path.exists(self.db_path))

    def test_set_and_get(self):
        r = ProviderResult(
            provider="test", ioc_value="1.2.3.4", ioc_type="ipv4",
            found=True, score=50.0,
        )
        self.cache.set("1.2.3.4", "test", r)
        cached = self.cache.get("1.2.3.4", "test")
        self.assertIsNotNone(cached)
        self.assertTrue(cached.cached)
        self.assertEqual(cached.score, 50.0)

    def test_get_miss(self):
        result = self.cache.get("nonexistent", "test")
        self.assertIsNone(result)

    def test_ttl_expiration(self):
        r = ProviderResult(
            provider="test", ioc_value="1.2.3.4", ioc_type="ipv4",
        )
        self.cache.set("1.2.3.4", "test", r, ttl=1)
        time.sleep(1.1)
        result = self.cache.get("1.2.3.4", "test")
        self.assertIsNone(result)

    def test_delete(self):
        r = ProviderResult(provider="test", ioc_value="1.2.3.4", ioc_type="ipv4")
        self.cache.set("1.2.3.4", "test", r)
        self.cache.delete("1.2.3.4", "test")
        self.assertIsNone(self.cache.get("1.2.3.4", "test"))

    def test_clear(self):
        for i in range(5):
            r = ProviderResult(
                provider="test", ioc_value=f"1.2.3.{i}", ioc_type="ipv4",
            )
            self.cache.set(f"1.2.3.{i}", "test", r)
        self.cache.clear()
        self.assertEqual(self.cache.stats()["total"], 0)

    def test_clear_expired(self):
        r1 = ProviderResult(provider="test", ioc_value="1.2.3.1", ioc_type="ipv4")
        r2 = ProviderResult(provider="test", ioc_value="1.2.3.2", ioc_type="ipv4")
        self.cache.set("1.2.3.1", "test", r1, ttl=1)
        self.cache.set("1.2.3.2", "test", r2, ttl=3600)
        time.sleep(1.1)
        count = self.cache.clear_expired()
        self.assertEqual(count, 1)

    def test_stats(self):
        r = ProviderResult(provider="test", ioc_value="1.2.3.4", ioc_type="ipv4")
        self.cache.set("1.2.3.4", "test", r)
        stats = self.cache.stats()
        self.assertEqual(stats["total"], 1)
        self.assertEqual(stats["active"], 1)
        self.assertEqual(stats["expired"], 0)

    def test_overwrite(self):
        r1 = ProviderResult(
            provider="test", ioc_value="1.2.3.4", ioc_type="ipv4", score=10.0,
        )
        r2 = ProviderResult(
            provider="test", ioc_value="1.2.3.4", ioc_type="ipv4", score=90.0,
        )
        self.cache.set("1.2.3.4", "test", r1)
        self.cache.set("1.2.3.4", "test", r2)
        cached = self.cache.get("1.2.3.4", "test")
        self.assertEqual(cached.score, 90.0)

    def test_different_providers_separate_entries(self):
        r1 = ProviderResult(provider="vt", ioc_value="1.2.3.4", ioc_type="ipv4", score=80.0)
        r2 = ProviderResult(provider="abuse", ioc_value="1.2.3.4", ioc_type="ipv4", score=50.0)
        self.cache.set("1.2.3.4", "vt", r1)
        self.cache.set("1.2.3.4", "abuse", r2)
        c1 = self.cache.get("1.2.3.4", "vt")
        c2 = self.cache.get("1.2.3.4", "abuse")
        self.assertEqual(c1.score, 80.0)
        self.assertEqual(c2.score, 50.0)


# ============================================================================
# Test Provider Base Class
# ============================================================================

class MockProvider(EnrichmentProvider):
    NAME = "mock"
    SUPPORTED_TYPES = {IOCType.IPV4, IOCType.DOMAIN}

    def enrich(self, ioc_value, ioc_type):
        return ProviderResult(
            provider=self.NAME,
            ioc_value=ioc_value,
            ioc_type=ioc_type.value,
            found=True,
            score=50.0,
        )


class ErrorProvider(EnrichmentProvider):
    NAME = "error_mock"
    SUPPORTED_TYPES = {IOCType.IPV4}

    def enrich(self, ioc_value, ioc_type):
        raise ConnectionError("Simulated failure")


class TestEnrichmentProvider(unittest.TestCase):

    def test_supports_type(self):
        p = MockProvider(api_key="test")
        self.assertTrue(p.supports(IOCType.IPV4))
        self.assertTrue(p.supports(IOCType.DOMAIN))
        self.assertFalse(p.supports(IOCType.SHA256))

    def test_status_disabled_no_key(self):
        p = MockProvider()
        self.assertEqual(p.status, ProviderStatus.DISABLED)

    def test_status_healthy_with_key(self):
        p = MockProvider(api_key="test")
        self.assertEqual(p.status, ProviderStatus.HEALTHY)

    def test_status_disabled_explicit(self):
        p = MockProvider(api_key="test", enabled=False)
        self.assertEqual(p.status, ProviderStatus.DISABLED)

    def test_safe_enrich_success(self):
        p = MockProvider(api_key="test")
        result = p.safe_enrich("1.2.3.4", IOCType.IPV4)
        self.assertTrue(result.found)
        self.assertEqual(result.score, 50.0)

    def test_safe_enrich_no_key(self):
        p = MockProvider()
        result = p.safe_enrich("1.2.3.4", IOCType.IPV4)
        self.assertIn("disabled", result.error.lower())

    def test_safe_enrich_unsupported_type(self):
        p = MockProvider(api_key="test")
        result = p.safe_enrich("hash123", IOCType.SHA256)
        self.assertIn("not supported", result.error)

    def test_safe_enrich_rate_limited(self):
        p = MockProvider(api_key="test", rate_limit_rpm=1)
        p.safe_enrich("1.2.3.4", IOCType.IPV4)
        result = p.safe_enrich("1.2.3.5", IOCType.IPV4)
        self.assertIn("Rate limit", result.error)

    def test_safe_enrich_error_handling(self):
        p = ErrorProvider(api_key="test")
        result = p.safe_enrich("1.2.3.4", IOCType.IPV4)
        self.assertIn("Simulated failure", result.error)
        self.assertEqual(p._error_count, 1)

    def test_error_count_degrades_status(self):
        p = ErrorProvider(api_key="test", rate_limit_rpm=100)
        for _ in range(5):
            p.safe_enrich("1.2.3.4", IOCType.IPV4)
        self.assertEqual(p._status, ProviderStatus.DOWN)

    def test_success_reduces_error_count(self):
        p = MockProvider(api_key="test")
        p._error_count = 3
        p.safe_enrich("1.2.3.4", IOCType.IPV4)
        self.assertEqual(p._error_count, 2)

    def test_health(self):
        p = MockProvider(api_key="test")
        h = p.health()
        self.assertEqual(h["name"], "mock")
        self.assertEqual(h["status"], "healthy")
        self.assertTrue(h["has_api_key"])
        self.assertIn("ipv4", h["supported_types"])


# ============================================================================
# Test VirusTotal Provider
# ============================================================================

class TestVirusTotalProvider(unittest.TestCase):

    def test_init_from_env(self):
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "test_key"}):
            p = VirusTotalProvider()
            self.assertEqual(p.api_key, "test_key")

    def test_init_no_key(self):
        with patch.dict(os.environ, {}, clear=True):
            p = VirusTotalProvider()
            self.assertEqual(p.api_key, "")

    def test_supported_types(self):
        p = VirusTotalProvider(api_key="test")
        self.assertTrue(p.supports(IOCType.IPV4))
        self.assertTrue(p.supports(IOCType.SHA256))
        self.assertTrue(p.supports(IOCType.DOMAIN))
        self.assertTrue(p.supports(IOCType.URL))
        self.assertFalse(p.supports(IOCType.EMAIL))

    def test_get_endpoint_file(self):
        p = VirusTotalProvider(api_key="test")
        ep = p._get_endpoint("abc123", IOCType.SHA256)
        self.assertIn("/files/abc123", ep)

    def test_get_endpoint_ip(self):
        p = VirusTotalProvider(api_key="test")
        ep = p._get_endpoint("1.2.3.4", IOCType.IPV4)
        self.assertIn("/ip_addresses/1.2.3.4", ep)

    def test_get_endpoint_domain(self):
        p = VirusTotalProvider(api_key="test")
        ep = p._get_endpoint("evil.com", IOCType.DOMAIN)
        self.assertIn("/domains/evil.com", ep)

    def test_get_endpoint_url(self):
        p = VirusTotalProvider(api_key="test")
        ep = p._get_endpoint("http://evil.com/malware", IOCType.URL)
        self.assertIn("/urls/", ep)

    def test_get_endpoint_unknown(self):
        p = VirusTotalProvider(api_key="test")
        ep = p._get_endpoint("x", IOCType.EMAIL)
        self.assertIsNone(ep)

    def test_parse_response_malicious(self):
        p = VirusTotalProvider(api_key="test")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 30,
                        "suspicious": 5,
                        "undetected": 10,
                        "harmless": 55,
                    },
                    "reputation": -10,
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.generic",
                    },
                }
            }
        }
        result = p._parse_response(data, "hash123", IOCType.SHA256)
        self.assertTrue(result.found)
        self.assertTrue(result.malicious)
        self.assertGreater(result.score, 0)
        self.assertIn("malicious", result.tags)
        self.assertIn("trojan.generic", result.tags)

    def test_parse_response_clean(self):
        p = VirusTotalProvider(api_key="test")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 5,
                        "harmless": 60,
                    },
                    "reputation": 100,
                }
            }
        }
        result = p._parse_response(data, "hash123", IOCType.SHA256)
        self.assertTrue(result.found)
        self.assertFalse(result.malicious)
        self.assertEqual(result.score, 0.0)

    def test_parse_response_ip_extra_fields(self):
        p = VirusTotalProvider(api_key="test")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5, "suspicious": 0,
                        "undetected": 10, "harmless": 50,
                    },
                    "country": "US",
                    "as_owner": "Google LLC",
                    "asn": 15169,
                    "network": "8.8.8.0/24",
                }
            }
        }
        result = p._parse_response(data, "8.8.8.8", IOCType.IPV4)
        self.assertEqual(result.raw_data["country"], "US")
        self.assertEqual(result.raw_data["as_owner"], "Google LLC")

    def test_parse_response_domain_extra_fields(self):
        p = VirusTotalProvider(api_key="test")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "undetected": 5, "harmless": 60,
                    },
                    "registrar": "GoDaddy",
                    "creation_date": 1234567890,
                }
            }
        }
        result = p._parse_response(data, "example.com", IOCType.DOMAIN)
        self.assertEqual(result.raw_data["registrar"], "GoDaddy")

    def test_parse_response_file_extra_fields(self):
        p = VirusTotalProvider(api_key="test")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 40, "suspicious": 0,
                        "undetected": 5, "harmless": 15,
                    },
                    "type_description": "PE32 executable",
                    "size": 204800,
                    "names": ["malware.exe", "trojan.exe"],
                    "sha256": "abc123",
                    "md5": "def456",
                }
            }
        }
        result = p._parse_response(data, "hash123", IOCType.SHA256)
        self.assertEqual(result.raw_data["type_description"], "PE32 executable")
        self.assertEqual(result.raw_data["size"], 204800)

    def test_parse_response_zero_total(self):
        p = VirusTotalProvider(api_key="test")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0, "suspicious": 0,
                        "undetected": 0, "harmless": 0,
                    },
                }
            }
        }
        result = p._parse_response(data, "hash", IOCType.SHA256)
        self.assertEqual(result.score, 0.0)


# ============================================================================
# Test AbuseIPDB Provider
# ============================================================================

class TestAbuseIPDBProvider(unittest.TestCase):

    def test_init_from_env(self):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "abuse_key"}):
            p = AbuseIPDBProvider()
            self.assertEqual(p.api_key, "abuse_key")

    def test_supported_types(self):
        p = AbuseIPDBProvider(api_key="test")
        self.assertTrue(p.supports(IOCType.IPV4))
        self.assertTrue(p.supports(IOCType.IPV6))
        self.assertFalse(p.supports(IOCType.DOMAIN))

    def test_parse_response_malicious(self):
        p = AbuseIPDBProvider(api_key="test")
        data = {
            "data": {
                "abuseConfidenceScore": 85,
                "totalReports": 150,
                "isPublic": True,
                "isWhitelisted": False,
                "isTor": True,
                "countryCode": "CN",
                "isp": "Bad ISP",
                "domain": "bad.com",
                "usageType": "Data Center/Web Hosting/Transit",
                "numDistinctUsers": 42,
                "lastReportedAt": "2024-01-01T00:00:00+00:00",
                "reports": [
                    {"categories": [14, 18]},
                    {"categories": [22]},
                ],
            }
        }
        result = p._parse_response(data, "1.2.3.4", IOCType.IPV4)
        self.assertTrue(result.malicious)
        self.assertEqual(result.score, 85.0)
        self.assertIn("high-abuse", result.tags)
        self.assertIn("tor-exit", result.tags)
        self.assertIn("brute-force", result.tags)
        self.assertIn("ssh-attack", result.tags)
        self.assertIn("port-scan", result.tags)

    def test_parse_response_clean(self):
        p = AbuseIPDBProvider(api_key="test")
        data = {
            "data": {
                "abuseConfidenceScore": 0,
                "totalReports": 0,
                "isPublic": True,
                "isWhitelisted": True,
                "countryCode": "US",
                "isp": "Google",
            }
        }
        result = p._parse_response(data, "8.8.8.8", IOCType.IPV4)
        self.assertFalse(result.malicious)
        self.assertEqual(result.score, 0.0)
        self.assertIn("whitelisted", result.tags)

    def test_parse_response_moderate(self):
        p = AbuseIPDBProvider(api_key="test")
        data = {
            "data": {
                "abuseConfidenceScore": 40,
                "totalReports": 5,
                "reports": [],
            }
        }
        result = p._parse_response(data, "1.2.3.4", IOCType.IPV4)
        self.assertFalse(result.malicious)
        self.assertIn("moderate-abuse", result.tags)
        self.assertIn("reported", result.tags)


# ============================================================================
# Test Shodan Provider
# ============================================================================

class TestShodanProvider(unittest.TestCase):

    def test_init_from_env(self):
        with patch.dict(os.environ, {"SHODAN_API_KEY": "shodan_key"}):
            p = ShodanProvider()
            self.assertEqual(p.api_key, "shodan_key")

    def test_supported_types(self):
        p = ShodanProvider(api_key="test")
        self.assertTrue(p.supports(IOCType.IPV4))
        self.assertTrue(p.supports(IOCType.DOMAIN))
        self.assertFalse(p.supports(IOCType.SHA256))

    def test_parse_host_response_vulnerable(self):
        p = ShodanProvider(api_key="test")
        data = {
            "ports": [22, 80, 443, 3389],
            "vulns": ["CVE-2021-44228", "CVE-2023-1234"],
            "os": "Linux",
            "org": "Test Org",
            "isp": "Test ISP",
            "asn": "AS12345",
            "city": "Istanbul",
            "country_code": "TR",
            "country_name": "Turkey",
            "latitude": 41.0,
            "longitude": 29.0,
            "hostnames": ["test.com"],
            "domains": ["test.com"],
            "last_update": "2024-01-01",
        }
        result = p._parse_host_response(data, "1.2.3.4", IOCType.IPV4)
        self.assertTrue(result.found)
        self.assertGreater(result.score, 0)
        self.assertIn("vulnerable", result.tags)
        self.assertIn("CVE-2021-44228", result.tags)
        self.assertIn("high-risk-ports", result.tags)  # 3389 is high-risk
        self.assertEqual(result.raw_data["city"], "Istanbul")

    def test_parse_host_response_clean(self):
        p = ShodanProvider(api_key="test")
        data = {
            "ports": [80, 443],
            "os": "Linux",
            "org": "Google",
        }
        result = p._parse_host_response(data, "8.8.8.8", IOCType.IPV4)
        self.assertTrue(result.found)
        self.assertEqual(result.score, 0.0)

    def test_parse_host_response_many_ports(self):
        p = ShodanProvider(api_key="test")
        data = {"ports": list(range(25))}
        result = p._parse_host_response(data, "1.2.3.4", IOCType.IPV4)
        self.assertIn("many-open-ports", result.tags)

    def test_parse_domain_response_resolved(self):
        p = ShodanProvider(api_key="test")
        data = {"example.com": "93.184.216.34"}
        result = p._parse_domain_response(data, "example.com", IOCType.DOMAIN)
        self.assertTrue(result.found)
        self.assertIn("dns-resolved", result.tags)

    def test_parse_domain_response_not_resolved(self):
        p = ShodanProvider(api_key="test")
        data = {"nonexistent.xyz": None}
        result = p._parse_domain_response(data, "nonexistent.xyz", IOCType.DOMAIN)
        self.assertFalse(result.found)


# ============================================================================
# Test IOC Enrichment Engine
# ============================================================================

class TestIOCEnrichmentEngine(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = EnrichmentCache(
            db_path=os.path.join(self.tmpdir, "test.db"),
            default_ttl=3600,
        )
        self.engine = IOCEnrichmentEngine(cache=self.cache)
        # Register mock providers
        self.mock1 = MockProvider(api_key="key1")
        self.mock2 = MockProvider(api_key="key2")
        self.mock2.NAME = "mock2"
        self.engine.register_provider(self.mock1)
        self.engine.register_provider(self.mock2)

    def test_register_provider(self):
        self.assertEqual(len(self.engine.providers), 2)

    def test_register_replaces_duplicate(self):
        new_mock = MockProvider(api_key="key_new")
        self.engine.register_provider(new_mock)
        # Should replace existing mock provider
        self.assertEqual(len(self.engine.providers), 2)
        mock_providers = [p for p in self.engine.providers if p.NAME == "mock"]
        self.assertEqual(mock_providers[0].api_key, "key_new")

    def test_remove_provider(self):
        self.assertTrue(self.engine.remove_provider("mock"))
        self.assertEqual(len(self.engine.providers), 1)

    def test_remove_nonexistent(self):
        self.assertFalse(self.engine.remove_provider("nonexistent"))

    def test_enrich_auto_detect_type(self):
        result = self.engine.enrich("1.2.3.4")
        self.assertEqual(result.ioc_type, "ipv4")
        self.assertGreater(len(result.providers), 0)

    def test_enrich_explicit_type(self):
        result = self.engine.enrich("example.com", ioc_type=IOCType.DOMAIN)
        self.assertEqual(result.ioc_type, "domain")

    def test_enrich_filters_by_provider(self):
        result = self.engine.enrich("1.2.3.4", providers=["mock"])
        self.assertEqual(len(result.providers), 1)
        self.assertEqual(result.providers[0].provider, "mock")

    def test_enrich_computes_threat_level(self):
        result = self.engine.enrich("1.2.3.4")
        self.assertNotEqual(result.threat_level, "unknown")

    def test_enrich_caches_results(self):
        self.engine.enrich("1.2.3.4")
        # Second call should use cache
        result = self.engine.enrich("1.2.3.4")
        cached_count = sum(1 for p in result.providers if p.cached)
        self.assertGreater(cached_count, 0)

    def test_enrich_skip_cache(self):
        self.engine.enrich("1.2.3.4")
        result = self.engine.enrich("1.2.3.4", skip_cache=True)
        cached_count = sum(1 for p in result.providers if p.cached)
        self.assertEqual(cached_count, 0)

    def test_enrich_unsupported_type_skips_provider(self):
        result = self.engine.enrich(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        # MockProvider doesn't support SHA256
        self.assertEqual(len(result.providers), 0)

    def test_enrich_disabled_provider_skipped(self):
        self.mock1.enabled = False
        result = self.engine.enrich("1.2.3.4")
        provider_names = [p.provider for p in result.providers]
        self.assertNotIn("mock", provider_names)

    def test_enrich_bulk(self):
        iocs = ["1.2.3.4", "5.6.7.8", "example.com"]
        results = self.engine.enrich_bulk(iocs)
        self.assertEqual(len(results), 3)

    def test_enrich_bulk_with_concurrency(self):
        iocs = [f"1.2.3.{i}" for i in range(10)]
        results = self.engine.enrich_bulk(iocs, max_concurrent=3)
        self.assertEqual(len(results), 10)

    def test_stats_updated(self):
        self.engine.enrich("1.2.3.4")
        stats = self.engine.stats
        self.assertEqual(stats["total_enrichments"], 1)
        self.assertIn("ipv4", stats["by_type"])

    def test_stats_provider_calls_counted(self):
        self.engine.enrich("1.2.3.4", skip_cache=True)
        stats = self.engine.stats
        self.assertGreater(stats["provider_calls"], 0)

    def test_stats_cache_hits(self):
        self.engine.enrich("1.2.3.4")
        self.engine.enrich("1.2.3.4")
        stats = self.engine.stats
        self.assertGreater(stats["cache_hits"], 0)

    def test_provider_health(self):
        health = self.engine.provider_health()
        self.assertEqual(len(health), 2)
        self.assertEqual(health[0]["status"], "healthy")

    def test_stats_has_cache_info(self):
        stats = self.engine.stats
        self.assertIn("cache", stats)
        self.assertIn("total", stats["cache"])

    def test_enrich_error_provider_counted(self):
        err_provider = ErrorProvider(api_key="key", rate_limit_rpm=100)
        self.engine.register_provider(err_provider)
        self.engine.enrich("1.2.3.4", skip_cache=True)
        stats = self.engine.stats
        self.assertGreater(stats["provider_errors"], 0)


# ============================================================================
# Test Flask Blueprint
# ============================================================================

class TestEnrichmentBlueprint(unittest.TestCase):

    def setUp(self):
        try:
            from flask import Flask
        except ImportError:
            self.skipTest("Flask not available")

        self.tmpdir = tempfile.mkdtemp()
        self.cache = EnrichmentCache(
            db_path=os.path.join(self.tmpdir, "test_bp.db"),
        )
        self.engine = IOCEnrichmentEngine(cache=self.cache)
        self.engine.register_provider(MockProvider(api_key="test"))

        self.app = Flask(__name__)
        bp = create_enrichment_blueprint(engine=self.engine)
        self.app.register_blueprint(bp)
        self.client = self.app.test_client()

    def test_status_endpoint(self):
        resp = self.client.get("/api/v1/soc/enrich/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "operational")

    def test_enrich_ioc_endpoint(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/ioc",
            json={"ioc": "1.2.3.4"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["ioc_value"], "1.2.3.4")
        self.assertEqual(data["ioc_type"], "ipv4")

    def test_enrich_ioc_missing_field(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/ioc",
            json={},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_enrich_ioc_with_type(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/ioc",
            json={"ioc": "example.com", "type": "domain"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["ioc_type"], "domain")

    def test_enrich_ioc_with_providers(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/ioc",
            json={"ioc": "1.2.3.4", "providers": ["mock"]},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(len(data["providers"]), 1)

    def test_enrich_bulk_endpoint(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/bulk",
            json={"iocs": ["1.2.3.4", "5.6.7.8"]},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["count"], 2)

    def test_enrich_bulk_empty(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/bulk",
            json={"iocs": []},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_enrich_bulk_too_many(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/bulk",
            json={"iocs": [f"1.2.3.{i}" for i in range(101)]},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_detect_type_endpoint(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/detect-type",
            json={"value": "8.8.8.8"},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["type"], "ipv4")

    def test_detect_type_missing_value(self):
        resp = self.client.post(
            "/api/v1/soc/enrich/detect-type",
            json={},
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)

    def test_clear_cache_endpoint(self):
        resp = self.client.post("/api/v1/soc/enrich/cache/clear")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "cleared")

    def test_cache_stats_endpoint(self):
        resp = self.client.get("/api/v1/soc/enrich/cache/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total", data)

    def test_providers_endpoint(self):
        resp = self.client.get("/api/v1/soc/enrich/providers")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("providers", data)
        self.assertGreater(len(data["providers"]), 0)


# ============================================================================
# Test Global Singleton
# ============================================================================

class TestGlobalSingleton(unittest.TestCase):

    def test_returns_instance(self):
        import modules.enrichment.ioc_enrichment as mod
        mod._engine_instance = None
        engine = get_enrichment_engine()
        self.assertIsInstance(engine, IOCEnrichmentEngine)
        mod._engine_instance = None  # cleanup

    def test_same_instance(self):
        import modules.enrichment.ioc_enrichment as mod
        mod._engine_instance = None
        e1 = get_enrichment_engine()
        e2 = get_enrichment_engine()
        self.assertIs(e1, e2)
        mod._engine_instance = None


# ============================================================================
# Test Integration Scenarios
# ============================================================================

class TestIntegration(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache = EnrichmentCache(
            db_path=os.path.join(self.tmpdir, "integration.db"),
        )
        self.engine = IOCEnrichmentEngine(cache=self.cache)

    def test_full_enrichment_flow(self):
        """Complete flow: register providers, enrich, check results."""
        self.engine.register_provider(MockProvider(api_key="key1"))

        result = self.engine.enrich("1.2.3.4")
        self.assertIsNotNone(result)
        self.assertEqual(result.ioc_type, "ipv4")
        self.assertGreater(len(result.providers), 0)
        self.assertIn(result.threat_level,
                     ["critical", "high", "medium", "low", "clean", "unknown"])

    def test_bulk_enrichment_flow(self):
        """Bulk enrich multiple IOC types."""
        self.engine.register_provider(MockProvider(api_key="key1"))

        iocs = ["1.2.3.4", "example.com", "5.6.7.8"]
        results = self.engine.enrich_bulk(iocs)
        self.assertEqual(len(results), 3)

        types = {r.ioc_type for r in results}
        self.assertIn("ipv4", types)
        self.assertIn("domain", types)

    def test_cache_prevents_duplicate_calls(self):
        """Cache should prevent provider calls for same IOC."""
        call_count = {"n": 0}

        class CountingProvider(EnrichmentProvider):
            NAME = "counter"
            SUPPORTED_TYPES = {IOCType.IPV4}

            def enrich(self, ioc_value, ioc_type):
                call_count["n"] += 1
                return ProviderResult(
                    provider=self.NAME, ioc_value=ioc_value,
                    ioc_type=ioc_type.value, found=True, score=30.0,
                )

        self.engine.register_provider(CountingProvider(api_key="key"))
        self.engine.enrich("1.2.3.4")
        self.engine.enrich("1.2.3.4")  # Should be cached
        self.assertEqual(call_count["n"], 1)

    def test_error_provider_doesnt_break_others(self):
        """One provider error shouldn't affect other providers."""
        self.engine.register_provider(MockProvider(api_key="key1"))
        self.engine.register_provider(ErrorProvider(api_key="key2", rate_limit_rpm=100))

        result = self.engine.enrich("1.2.3.4", skip_cache=True)
        # Should have results from both providers
        self.assertEqual(len(result.providers), 2)
        # MockProvider should succeed
        mock_result = next(p for p in result.providers if p.provider == "mock")
        self.assertTrue(mock_result.found)
        # ErrorProvider should have error
        error_result = next(p for p in result.providers if p.provider == "error_mock")
        self.assertIsNotNone(error_result.error)

    def test_stats_accumulate(self):
        """Stats should accumulate across multiple enrichments."""
        self.engine.register_provider(MockProvider(api_key="key"))
        self.engine.enrich("1.2.3.4", skip_cache=True)
        self.engine.enrich("5.6.7.8", skip_cache=True)
        self.engine.enrich("example.com", skip_cache=True)

        stats = self.engine.stats
        self.assertEqual(stats["total_enrichments"], 3)
        self.assertIn("ipv4", stats["by_type"])
        self.assertIn("domain", stats["by_type"])


# ============================================================================
# Test Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):

    def test_ioc_type_values(self):
        for t in IOCType:
            self.assertIsInstance(t.value, str)

    def test_threat_level_all_values(self):
        levels = [ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.MEDIUM,
                  ThreatLevel.LOW, ThreatLevel.CLEAN, ThreatLevel.UNKNOWN]
        for level in levels:
            self.assertIsInstance(level.numeric, int)

    def test_provider_status_values(self):
        for s in ProviderStatus:
            self.assertIsInstance(s.value, str)

    def test_enrichment_result_empty_providers(self):
        r = EnrichmentResult(ioc_value="x", ioc_type="unknown")
        r.compute_threat_level()
        self.assertEqual(r.threat_level, "unknown")
        self.assertEqual(r.aggregate_score, 0.0)

    def test_enrichment_result_to_dict_with_set_tags(self):
        r = EnrichmentResult(ioc_value="x", ioc_type="ipv4")
        r.tags = {"b", "a", "c"}
        d = r.to_dict()
        self.assertEqual(d["tags"], ["a", "b", "c"])  # sorted

    def test_rate_limit_day_reset(self):
        rl = RateLimitState(requests_per_minute=100, requests_per_day=1)
        rl.record_request()
        self.assertFalse(rl.can_request())
        rl.day_reset = time.time() - 1
        self.assertTrue(rl.can_request())

    def test_cache_corrupted_data(self):
        tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(tmpdir, "corrupt.db")
        cache = EnrichmentCache(db_path=db_path)
        # Manually insert corrupted data
        conn = sqlite3.connect(db_path)
        conn.execute(
            """INSERT INTO cache (cache_key, ioc_value, ioc_type, provider,
               result_json, created_at, ttl)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (cache._make_key("x", "test"), "x", "ipv4", "test",
             "not-valid-json", time.time(), 3600)
        )
        conn.commit()
        conn.close()
        result = cache.get("x", "test")
        self.assertIsNone(result)

    def test_detect_ioc_type_url_case_insensitive(self):
        self.assertEqual(detect_ioc_type("HTTP://EXAMPLE.COM"), IOCType.URL)
        self.assertEqual(detect_ioc_type("Https://Example.com"), IOCType.URL)

    def test_create_blueprint_without_flask(self):
        import modules.enrichment.ioc_enrichment as mod
        orig = None
        try:
            # Temporarily make flask import fail
            import flask
            orig = flask
        except ImportError:
            pass

        with patch.dict("sys.modules", {"flask": None}):
            result = create_enrichment_blueprint()
            self.assertIsNone(result)

    def test_engine_no_providers(self):
        tmpdir = tempfile.mkdtemp()
        cache = EnrichmentCache(db_path=os.path.join(tmpdir, "empty.db"))
        engine = IOCEnrichmentEngine(cache=cache)
        result = engine.enrich("1.2.3.4")
        self.assertEqual(len(result.providers), 0)
        self.assertEqual(result.threat_level, "unknown")

    def test_concurrent_enrichment(self):
        tmpdir = tempfile.mkdtemp()
        cache = EnrichmentCache(db_path=os.path.join(tmpdir, "concurrent.db"))
        engine = IOCEnrichmentEngine(cache=cache)
        engine.register_provider(MockProvider(api_key="key", rate_limit_rpm=100))

        errors = []

        def enrich_ip(i):
            try:
                result = engine.enrich(f"1.2.3.{i}")
                assert result.ioc_type == "ipv4"
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=enrich_ip, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(errors), 0)

    def test_provider_result_with_raw_data(self):
        r = ProviderResult(
            provider="test", ioc_value="x", ioc_type="ipv4",
            raw_data={"nested": {"key": "value"}, "list": [1, 2, 3]},
        )
        d = r.to_dict()
        serialized = json.dumps(d)
        self.assertIn("nested", serialized)

    def test_virustotal_name(self):
        p = VirusTotalProvider(api_key="test")
        self.assertEqual(p.NAME, "virustotal")

    def test_abuseipdb_name(self):
        p = AbuseIPDBProvider(api_key="test")
        self.assertEqual(p.NAME, "abuseipdb")

    def test_shodan_name(self):
        p = ShodanProvider(api_key="test")
        self.assertEqual(p.NAME, "shodan")

    def test_high_risk_ports_detected(self):
        p = ShodanProvider(api_key="test")
        data = {"ports": [22, 3389, 5900]}
        result = p._parse_host_response(data, "1.2.3.4", IOCType.IPV4)
        self.assertIn("high-risk-ports", result.tags)

    def test_virustotal_score_capped_at_100(self):
        p = VirusTotalProvider(api_key="test")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 100, "suspicious": 50,
                        "undetected": 0, "harmless": 0,
                    },
                }
            }
        }
        result = p._parse_response(data, "hash", IOCType.SHA256)
        self.assertLessEqual(result.score, 100.0)


if __name__ == "__main__":
    unittest.main()
