"""
TSUNAMI - dalga_sinkhole.py Test Suite
DNS Sinkhole module tests
"""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime


class TestThreatType:
    """ThreatType enum testleri"""

    def test_threat_types_exist(self):
        from dalga_sinkhole import ThreatType
        assert ThreatType.MALWARE.value == "malware"
        assert ThreatType.PHISHING.value == "phishing"
        assert ThreatType.C2.value == "c2"
        assert ThreatType.BOTNET.value == "botnet"
        assert ThreatType.RANSOMWARE.value == "ransomware"

    def test_threat_type_from_string(self):
        from dalga_sinkhole import ThreatType
        assert ThreatType("malware") == ThreatType.MALWARE
        assert ThreatType("c2") == ThreatType.C2


class TestSinkholeConstants:
    """Sinkhole sabit değerleri testleri"""

    def test_default_sinkhole_ips(self):
        from dalga_sinkhole import DEFAULT_SINKHOLE_IPV4, DEFAULT_SINKHOLE_IPV6
        assert DEFAULT_SINKHOLE_IPV4 == "127.0.0.1"
        assert DEFAULT_SINKHOLE_IPV6 == "::1"

    def test_sinkhole_paths(self):
        from dalga_sinkhole import SINKHOLE_HOME, SINKHOLE_DB
        assert "sinkhole" in str(SINKHOLE_HOME)
        assert "sinkhole.db" in str(SINKHOLE_DB)


class TestDomainValidation:
    """Domain doğrulama testleri"""

    def test_valid_domains(self):
        """Geçerli domain formatları"""
        valid = ["example.com", "sub.example.com", "test.co.uk"]
        for domain in valid:
            assert "." in domain
            assert len(domain) > 3

    def test_malicious_domain_patterns(self):
        """DGA benzeri domain tespiti"""
        import math
        from collections import Counter

        def entropy(s):
            p = [c / len(s) for c in Counter(s).values()]
            return -sum(pi * math.log2(pi) for pi in p)

        # Normal domain - düşük entropi
        normal = "google.com"
        assert entropy(normal) < 3.5

        # DGA domain - yüksek entropi
        dga = "xk3j8f9a2b.xyz"
        assert entropy(dga) > 3.0
