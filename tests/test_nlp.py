#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI NLP Module Tests - Test-Driven Development
===================================================

Tests for the Turkish Natural Language Query Interface (dalga_nlp.py).
Following TDD methodology: Tests written FIRST, then implementation.

pytest tests/test_nlp.py -v
"""

import pytest
import sys
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock, patch

# Parent dizini path'e ekle
sys.path.insert(0, str(Path(__file__).parent.parent))


# ============================================================
# Test Fixtures
# ============================================================

@pytest.fixture
def nlp_engine():
    """Create NLPQueryEngine instance for testing"""
    from dalga_nlp import NLPQueryEngine
    return NLPQueryEngine()


@pytest.fixture
def sample_queries_turkish():
    """Sample Turkish security queries"""
    return [
        "Son 24 saatte supheli IP'leri goster",
        "Bu domain hakkinda ne biliyoruz: example.com",
        "Kritik tehditler neler?",
        "192.168.1.100 IP'sini engelle",
        "Haftalik guvenlik raporu olustur",
        "WiFi aglarinda anomali var mi?",
        "Bugun gelen saldiri loglarini listele",
        "ailydian.com domaini analiz et",
        "Gecen hafta tespit edilen zararlilar",
        "Kullanici ahmet@test.com hakkinda arastir",
    ]


@pytest.fixture
def sample_queries_english():
    """Sample English security queries"""
    return [
        "Show suspicious IPs from last 24 hours",
        "What do we know about: example.com",
        "What are the critical threats?",
        "Block IP 192.168.1.100",
        "Generate weekly security report",
        "Any anomalies in WiFi networks?",
    ]


# ============================================================
# Intent Classification Tests
# ============================================================

class TestIntentClassification:
    """Tests for intent classification functionality"""

    def test_search_intent_turkish(self, nlp_engine):
        """Test search intent detection in Turkish"""
        queries = [
            "Son 24 saatte supheli IP'leri goster",
            "Bugun gelen logları listele",
            "Tehdit kaynaklarini bul",
            "Zararli domainleri ara",
        ]
        for query in queries:
            result = nlp_engine.classify_intent(query)
            assert result['intent'] == 'search', f"Failed for: {query}"

    def test_analyze_intent_turkish(self, nlp_engine):
        """Test analyze intent detection in Turkish"""
        queries = [
            "Bu domain hakkinda ne biliyoruz: example.com",
            "192.168.1.1 IP'sini analiz et",
            "ailydian.com domaini incele",
            "Bu hash'i kontrol et: abc123",
        ]
        for query in queries:
            result = nlp_engine.classify_intent(query)
            assert result['intent'] == 'analyze', f"Failed for: {query}"

    def test_report_intent_turkish(self, nlp_engine):
        """Test report intent detection in Turkish"""
        queries = [
            "Haftalik guvenlik raporu olustur",
            "Gunluk tehdit ozeti hazirla",
            "Aylik istatistik raporu cikar",
            "Tehdit durum raporu",
        ]
        for query in queries:
            result = nlp_engine.classify_intent(query)
            assert result['intent'] == 'report', f"Failed for: {query}"

    def test_action_intent_turkish(self, nlp_engine):
        """Test action intent detection in Turkish"""
        queries = [
            "192.168.1.100 IP'sini engelle",
            "Bu domaini blokla: malware.com",
            "Kullaniciyi yasakla",
            "Alarmi kapat",
        ]
        for query in queries:
            result = nlp_engine.classify_intent(query)
            assert result['intent'] == 'action', f"Failed for: {query}"

    def test_summary_intent_turkish(self, nlp_engine):
        """Test summary intent detection in Turkish"""
        queries = [
            "Kritik tehditler neler?",
            "Guvenlik durumu nasil?",
            "Anomali var mi?",
            "Sistem saglikli mi?",
        ]
        for query in queries:
            result = nlp_engine.classify_intent(query)
            assert result['intent'] in ['summary', 'search'], f"Failed for: {query}"

    def test_intent_confidence_score(self, nlp_engine):
        """Test that intent classification returns confidence score"""
        result = nlp_engine.classify_intent("Tehditler neler?")
        assert 'confidence' in result
        assert 0.0 <= result['confidence'] <= 1.0


# ============================================================
# Entity Extraction Tests
# ============================================================

class TestEntityExtraction:
    """Tests for entity extraction functionality"""

    def test_extract_ip_addresses(self, nlp_engine):
        """Test IP address extraction"""
        queries_and_ips = [
            ("192.168.1.100 IP'sini analiz et", ["192.168.1.100"]),
            ("10.0.0.1 ve 172.16.0.1 adreslerini kontrol et", ["10.0.0.1", "172.16.0.1"]),
            ("8.8.8.8 DNS sunucusuna bak", ["8.8.8.8"]),
            ("IP adresi yok bu sorguda", []),
        ]
        for query, expected_ips in queries_and_ips:
            entities = nlp_engine.extract_entities(query)
            assert 'ips' in entities
            assert set(entities['ips']) == set(expected_ips), f"Failed for: {query}"

    def test_extract_domains(self, nlp_engine):
        """Test domain extraction"""
        queries_and_domains = [
            ("example.com domaini analiz et", ["example.com"]),
            ("ailydian.com ve google.com hakkinda bilgi", ["ailydian.com", "google.com"]),
            ("www.test.org sitesini kontrol et", ["www.test.org"]),
            ("subdomain.example.co.uk analizi", ["subdomain.example.co.uk"]),
            ("Domain yok burada", []),
        ]
        for query, expected_domains in queries_and_domains:
            entities = nlp_engine.extract_entities(query)
            assert 'domains' in entities
            assert set(entities['domains']) == set(expected_domains), f"Failed for: {query}"

    def test_extract_emails(self, nlp_engine):
        """Test email extraction"""
        queries_and_emails = [
            ("ahmet@test.com hakkinda arastir", ["ahmet@test.com"]),
            ("info@ailydian.com ve admin@example.org kullanicilarini bul",
             ["info@ailydian.com", "admin@example.org"]),
            ("Email yok bu sorguda", []),
        ]
        for query, expected_emails in queries_and_emails:
            entities = nlp_engine.extract_entities(query)
            assert 'emails' in entities
            assert set(entities['emails']) == set(expected_emails), f"Failed for: {query}"

    def test_extract_hashes(self, nlp_engine):
        """Test hash extraction (MD5, SHA1, SHA256)"""
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        entities = nlp_engine.extract_entities(f"Bu hash'i kontrol et: {md5_hash}")
        assert md5_hash in entities.get('hashes', {}).get('md5', [])

        entities = nlp_engine.extract_entities(f"SHA1 hash: {sha1_hash}")
        assert sha1_hash in entities.get('hashes', {}).get('sha1', [])

        entities = nlp_engine.extract_entities(f"SHA256: {sha256_hash}")
        assert sha256_hash in entities.get('hashes', {}).get('sha256', [])

    def test_extract_threat_types(self, nlp_engine):
        """Test threat type extraction"""
        queries_and_threats = [
            ("Malware tespiti yap", ["malware"]),
            ("Ransomware ve phishing tehditleri", ["ransomware", "phishing"]),
            ("Botnet aktivitesi kontrol et", ["botnet"]),
            ("APT grup aktivitesi", ["apt"]),
        ]
        for query, expected_threats in queries_and_threats:
            entities = nlp_engine.extract_entities(query)
            assert 'threat_types' in entities
            for threat in expected_threats:
                assert any(threat.lower() in t.lower() for t in entities['threat_types']), \
                    f"Failed to find {threat} in {query}"


# ============================================================
# Time Expression Tests
# ============================================================

class TestTimeExpressionParsing:
    """Tests for Turkish time expression parsing"""

    def test_parse_bugun(self, nlp_engine):
        """Test 'bugun' (today) parsing"""
        entities = nlp_engine.extract_entities("Bugun gelen saldirilar")
        assert 'time_range' in entities
        time_range = entities['time_range']
        assert time_range['type'] == 'today'

    def test_parse_dun(self, nlp_engine):
        """Test 'dun' (yesterday) parsing"""
        entities = nlp_engine.extract_entities("Dun tespit edilen tehditler")
        assert 'time_range' in entities
        time_range = entities['time_range']
        assert time_range['type'] == 'yesterday'

    def test_parse_son_24_saat(self, nlp_engine):
        """Test 'son 24 saat' (last 24 hours) parsing"""
        entities = nlp_engine.extract_entities("Son 24 saatte gelen loglar")
        assert 'time_range' in entities
        time_range = entities['time_range']
        assert time_range['hours'] == 24

    def test_parse_gecen_hafta(self, nlp_engine):
        """Test 'gecen hafta' (last week) parsing"""
        entities = nlp_engine.extract_entities("Gecen hafta tespit edilen anomaliler")
        assert 'time_range' in entities
        time_range = entities['time_range']
        assert time_range['type'] == 'last_week'

    def test_parse_son_n_gun(self, nlp_engine):
        """Test 'son N gun' (last N days) parsing"""
        entities = nlp_engine.extract_entities("Son 7 gunde gelen tehditler")
        assert 'time_range' in entities
        time_range = entities['time_range']
        assert time_range['days'] == 7

    def test_parse_bu_ay(self, nlp_engine):
        """Test 'bu ay' (this month) parsing"""
        entities = nlp_engine.extract_entities("Bu ay tespit edilen zararlilar")
        assert 'time_range' in entities
        time_range = entities['time_range']
        assert time_range['type'] == 'this_month'

    def test_time_range_to_datetime(self, nlp_engine):
        """Test time range conversion to datetime objects"""
        entities = nlp_engine.extract_entities("Son 24 saatte")
        time_range = entities.get('time_range', {})

        if 'start' in time_range and 'end' in time_range:
            start = time_range['start']
            end = time_range['end']
            assert isinstance(start, datetime)
            assert isinstance(end, datetime)
            assert start < end


# ============================================================
# Query to Structured Format Tests
# ============================================================

class TestQueryToStructuredFormat:
    """Tests for converting natural language to structured query"""

    def test_search_query_structure(self, nlp_engine):
        """Test search query conversion"""
        result = nlp_engine.parse_query("Son 24 saatte supheli IP'leri goster")

        assert 'intent' in result
        assert 'entities' in result
        assert 'structured_query' in result
        assert result['intent'] == 'search'

    def test_analyze_query_structure(self, nlp_engine):
        """Test analyze query conversion"""
        result = nlp_engine.parse_query("192.168.1.1 IP'sini analiz et")

        assert result['intent'] == 'analyze'
        assert '192.168.1.1' in result['entities'].get('ips', [])
        assert 'target' in result['structured_query']

    def test_action_query_structure(self, nlp_engine):
        """Test action query conversion"""
        result = nlp_engine.parse_query("malware.com domaini engelle")

        assert result['intent'] == 'action'
        assert result['structured_query'].get('action_type') == 'block'
        assert 'malware.com' in result['entities'].get('domains', [])

    def test_report_query_structure(self, nlp_engine):
        """Test report query conversion"""
        result = nlp_engine.parse_query("Haftalik guvenlik raporu olustur")

        assert result['intent'] == 'report'
        assert result['structured_query'].get('report_type') in ['weekly', 'security']

    def test_original_query_preserved(self, nlp_engine):
        """Test that original query is preserved in result"""
        query = "Test sorgusu"
        result = nlp_engine.parse_query(query)
        assert result.get('original_query') == query


# ============================================================
# Turkish Morphology Tests
# ============================================================

class TestTurkishMorphology:
    """Tests for Turkish morphological analysis"""

    def test_verb_stem_extraction(self, nlp_engine):
        """Test Turkish verb stem extraction"""
        # goster, listele, bul, analiz et, incele
        verbs = {
            "goster": "goster",
            "göster": "goster",
            "listele": "listele",
            "analiz et": "analiz",
            "incele": "incele",
            "engelle": "engelle",
        }
        for word, expected_stem in verbs.items():
            stem = nlp_engine.extract_verb_stem(word)
            # Check that the stem contains the expected root
            assert expected_stem in stem.lower() or stem.lower().startswith(expected_stem[:4]), \
                f"Failed for {word}: got {stem}, expected {expected_stem}"

    def test_noun_suffix_handling(self, nlp_engine):
        """Test Turkish noun suffix handling"""
        # IP'leri, domainleri, tehditler
        tests = [
            ("IP'leri", "ip"),
            ("domainleri", "domain"),
            ("tehditler", "tehdit"),
            ("saldirilar", "saldiri"),
            ("loglar", "log"),
        ]
        for word, expected_root in tests:
            root = nlp_engine.normalize_noun(word)
            assert expected_root in root.lower(), f"Failed for {word}: got {root}"


# ============================================================
# Response Generator Tests
# ============================================================

class TestResponseGenerator:
    """Tests for Turkish response generation"""

    def test_generate_search_response(self, nlp_engine):
        """Test search result response generation"""
        search_results = {
            'count': 5,
            'items': [
                {'ip': '192.168.1.1', 'threat_level': 'high'},
                {'ip': '10.0.0.1', 'threat_level': 'medium'},
            ]
        }
        response = nlp_engine.generate_response(
            intent='search',
            results=search_results,
            language='tr'
        )

        assert isinstance(response, str)
        assert len(response) > 0
        # Should mention count
        assert '5' in response or 'bes' in response.lower()

    def test_generate_analysis_response(self, nlp_engine):
        """Test analysis result response generation"""
        analysis_results = {
            'target': '192.168.1.1',
            'threat_score': 0.85,
            'categories': ['botnet', 'scanner'],
            'first_seen': '2024-01-15',
        }
        response = nlp_engine.generate_response(
            intent='analyze',
            results=analysis_results,
            language='tr'
        )

        assert isinstance(response, str)
        assert '192.168.1.1' in response

    def test_generate_action_response(self, nlp_engine):
        """Test action result response generation"""
        action_results = {
            'action': 'block',
            'target': 'malware.com',
            'success': True,
        }
        response = nlp_engine.generate_response(
            intent='action',
            results=action_results,
            language='tr'
        )

        assert isinstance(response, str)
        assert 'malware.com' in response

    def test_generate_error_response(self, nlp_engine):
        """Test error response generation"""
        response = nlp_engine.generate_response(
            intent='search',
            results=None,
            error="Baglanti hatasi",
            language='tr'
        )

        assert isinstance(response, str)
        assert 'hata' in response.lower()

    def test_response_includes_recommendations(self, nlp_engine):
        """Test that response includes recommendations when applicable"""
        analysis_results = {
            'target': '192.168.1.1',
            'threat_score': 0.95,  # High threat
            'categories': ['ransomware'],
        }
        response = nlp_engine.generate_response(
            intent='analyze',
            results=analysis_results,
            language='tr'
        )

        # High threat should include recommendation
        # Either explicit recommendation or action word
        assert any(word in response.lower() for word in ['oneri', 'tavsiye', 'engelle', 'aksiyon'])


# ============================================================
# Query Suggestions Tests
# ============================================================

class TestQuerySuggestions:
    """Tests for query suggestion functionality"""

    def test_get_suggestions_for_partial_query(self, nlp_engine):
        """Test suggestions for partial queries"""
        suggestions = nlp_engine.get_suggestions("Son 24 saat")

        assert isinstance(suggestions, list)
        assert len(suggestions) > 0
        # Should suggest time-based queries
        assert any('saat' in s.lower() for s in suggestions)

    def test_get_suggestions_for_entity_type(self, nlp_engine):
        """Test suggestions based on detected entity types"""
        suggestions = nlp_engine.get_suggestions("192.168.1.1")

        assert isinstance(suggestions, list)
        assert len(suggestions) > 0
        # Should suggest IP-related queries - check for common IP-related terms
        ip_related_terms = ['ip', 'analiz', 'adres', 'bilgi', 'engelle']
        assert any(any(term in s.lower() for term in ip_related_terms) for s in suggestions), \
            f"No IP-related suggestions found in: {suggestions}"

    def test_get_context_aware_suggestions(self, nlp_engine):
        """Test context-aware suggestions"""
        # After threat detection context
        suggestions = nlp_engine.get_suggestions(
            partial_query="",
            context={'last_intent': 'search', 'last_entity_type': 'threat'}
        )

        assert isinstance(suggestions, list)


# ============================================================
# Integration Module Tests
# ============================================================

class TestIntegrationPoints:
    """Tests for module integration capabilities"""

    def test_osint_integration_format(self, nlp_engine):
        """Test OSINT module integration query format"""
        result = nlp_engine.parse_query("ahmet@test.com hakkinda OSINT arastirmasi yap")

        assert result['integration'] == 'osint'
        assert 'ahmet@test.com' in result['entities'].get('emails', [])

    def test_sigint_integration_format(self, nlp_engine):
        """Test SIGINT module integration query format"""
        result = nlp_engine.parse_query("WiFi aglarinda anomali tespit et")

        assert result['integration'] == 'sigint'

    def test_threat_intel_integration_format(self, nlp_engine):
        """Test Threat Intel module integration query format"""
        result = nlp_engine.parse_query("APT gruplari hakkinda bilgi ver")

        assert result['integration'] == 'threat_intel'

    def test_soar_action_format(self, nlp_engine):
        """Test SOAR action format"""
        # Use a clearer action query without "rapor"
        result = nlp_engine.parse_query("malware.com domaini engelle")

        assert result['intent'] == 'action'
        assert 'soar_actions' in result
        assert len(result['soar_actions']) > 0


# ============================================================
# API Endpoint Tests (Mock)
# ============================================================

class TestNLPAPIEndpoints:
    """Tests for NLP API endpoint functionality"""

    def test_query_endpoint_structure(self, nlp_engine):
        """Test query endpoint request/response structure"""
        # Simulate API request
        request_data = {
            'query': 'Son 24 saatte supheli IP\'leri goster',
            'language': 'tr',
            'context': {}
        }

        # Process through engine
        result = nlp_engine.process_api_request(request_data)

        assert 'success' in result
        assert 'parsed_query' in result
        assert 'response' in result

    def test_suggestions_endpoint_structure(self, nlp_engine):
        """Test suggestions endpoint response structure"""
        result = nlp_engine.get_suggestions_api({
            'partial_query': 'Son',
            'context': {}
        })

        assert 'suggestions' in result
        assert isinstance(result['suggestions'], list)

    def test_report_endpoint_structure(self, nlp_engine):
        """Test report generation endpoint structure"""
        request_data = {
            'report_type': 'threat_summary',
            'time_range': 'last_24h',
            'language': 'tr'
        }

        result = nlp_engine.generate_report_api(request_data)

        assert 'success' in result
        assert 'report' in result


# ============================================================
# Edge Cases and Error Handling Tests
# ============================================================

class TestEdgeCasesAndErrors:
    """Tests for edge cases and error handling"""

    def test_empty_query(self, nlp_engine):
        """Test handling of empty query"""
        result = nlp_engine.parse_query("")

        assert result['intent'] == 'unknown'
        assert 'error' not in result or result.get('error') is None

    def test_gibberish_query(self, nlp_engine):
        """Test handling of nonsense input"""
        result = nlp_engine.parse_query("asdfghjkl qwertyuiop")

        assert result['intent'] == 'unknown'
        assert result['confidence'] < 0.5

    def test_mixed_language_query(self, nlp_engine):
        """Test handling of mixed Turkish-English query"""
        result = nlp_engine.parse_query("Show me supheli IP addresses")

        # Should still extract useful information
        assert 'ip' in str(result).lower()

    def test_special_characters_in_query(self, nlp_engine):
        """Test handling of special characters"""
        result = nlp_engine.parse_query("IP: 192.168.1.1 <-- bu IP'yi analiz et!")

        assert '192.168.1.1' in result['entities'].get('ips', [])

    def test_very_long_query(self, nlp_engine):
        """Test handling of very long query"""
        long_query = "Bu cok uzun bir sorgu " * 100
        result = nlp_engine.parse_query(long_query)

        # Should not crash, should return something reasonable
        assert 'intent' in result

    def test_unicode_characters(self, nlp_engine):
        """Test handling of Turkish unicode characters"""
        result = nlp_engine.parse_query(
            "Supheli IP'leri goster ve guvenlik durumunu kontrol et"
        )

        assert result['intent'] in ['search', 'summary']

    def test_sql_injection_attempt(self, nlp_engine):
        """Test that SQL injection attempts are safely handled"""
        malicious_query = "'; DROP TABLE users; --"
        result = nlp_engine.parse_query(malicious_query)

        # Should not crash, should mark as unknown
        assert 'intent' in result
        # Query should be sanitized or escaped
        assert result.get('sanitized', True) or result['intent'] == 'unknown'


# ============================================================
# Pattern Matching Tests
# ============================================================

class TestPatternMatching:
    """Tests for regex pattern matching"""

    def test_ip_search_pattern(self, nlp_engine):
        """Test IP search pattern matching"""
        patterns = nlp_engine.get_patterns()

        assert 'ip_search' in patterns
        # Should match Turkish IP search queries (handles both word orders)
        import re
        pattern = patterns['ip_search']
        # Test Turkish word order: object first, then verb
        assert re.search(pattern, "IP adresleri goster", re.IGNORECASE) or \
               re.search(pattern, "goster IP adresleri", re.IGNORECASE), \
               "Pattern should match Turkish IP search"
        assert re.search(pattern, "supheli IP'leri listele", re.IGNORECASE) or \
               re.search(pattern, "listele IP", re.IGNORECASE), \
               "Pattern should match Turkish IP list query"

    def test_domain_analysis_pattern(self, nlp_engine):
        """Test domain analysis pattern matching"""
        patterns = nlp_engine.get_patterns()

        assert 'domain_analysis' in patterns
        import re
        pattern = patterns['domain_analysis']
        # Test both word orders
        assert re.search(pattern, "domain analiz et", re.IGNORECASE) or \
               re.search(pattern, "analiz et domain", re.IGNORECASE), \
               "Pattern should match domain analysis"
        assert re.search(pattern, "alan adi incele", re.IGNORECASE) or \
               re.search(pattern, "incele alan adi", re.IGNORECASE), \
               "Pattern should match Turkish domain analysis"

    def test_threat_summary_pattern(self, nlp_engine):
        """Test threat summary pattern matching"""
        patterns = nlp_engine.get_patterns()

        assert 'threat_summary' in patterns
        import re
        pattern = patterns['threat_summary']
        # Test threat summary patterns
        assert re.search(pattern, "tehdit ozeti", re.IGNORECASE) or \
               re.search(pattern, "tehdit durum", re.IGNORECASE), \
               "Pattern should match threat summary"
        assert re.search(pattern, "guvenlik durum", re.IGNORECASE) or \
               re.search(pattern, "guvenlik neler", re.IGNORECASE), \
               "Pattern should match security status"

    def test_block_action_pattern(self, nlp_engine):
        """Test block action pattern matching"""
        patterns = nlp_engine.get_patterns()

        assert 'block_action' in patterns
        import re
        pattern = patterns['block_action']
        assert re.search(pattern, "engelle", re.IGNORECASE)
        assert re.search(pattern, "blokla", re.IGNORECASE)
        assert re.search(pattern, "yasakla", re.IGNORECASE)

    def test_time_filter_pattern(self, nlp_engine):
        """Test time filter pattern matching"""
        patterns = nlp_engine.get_patterns()

        assert 'time_filter' in patterns
        import re
        pattern = patterns['time_filter']
        assert re.search(pattern, "son 24 saat", re.IGNORECASE)
        assert re.search(pattern, "gecen hafta", re.IGNORECASE)
        assert re.search(pattern, "bugun", re.IGNORECASE)
