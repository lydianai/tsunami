#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    DALGA NLP - Turkish Natural Language Query Interface
    Turkce Dogal Dil Sorgu Arayuzu
================================================================================

    Ozellikler:
    - Turkce ve Ingilizce guvenlik sorgularini ayristirma
    - Niyet siniflandirma (arama, analiz, rapor, aksiyon)
    - Varlik cikarma (IP, domain, email, tarih araliklari, tehdit turleri)
    - Sorgudan yapisal formata donusum
    - Turkce morfolojik analiz
    - Dogal dil yanit uretimi

    Entegrasyonlar:
    - OSINT modulleri (dalga_osint.py)
    - SIGINT modulleri (dalga_sigint/)
    - Threat Intel (dalga_threat_intel.py)
    - SOAR aksiyonlari
    - Rapor uretimi

================================================================================
"""

import re
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# Enums and Data Classes
# ============================================================

class QueryIntent(Enum):
    """Sorgu niyet turleri"""
    SEARCH = "search"
    ANALYZE = "analyze"
    REPORT = "report"
    ACTION = "action"
    SUMMARY = "summary"
    UNKNOWN = "unknown"


class ActionType(Enum):
    """Aksiyon turleri"""
    BLOCK = "block"
    UNBLOCK = "unblock"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    SCAN = "scan"
    REPORT = "report"


class IntegrationTarget(Enum):
    """Entegrasyon hedefleri"""
    OSINT = "osint"
    SIGINT = "sigint"
    THREAT_INTEL = "threat_intel"
    SOAR = "soar"
    INTERNAL = "internal"


@dataclass
class ParsedQuery:
    """Ayristirilmis sorgu verisi"""
    original_query: str
    intent: str
    confidence: float
    entities: Dict[str, Any]
    structured_query: Dict[str, Any]
    integration: str
    soar_actions: List[Dict[str, Any]] = field(default_factory=list)
    language: str = "tr"
    sanitized: bool = True


# ============================================================
# Regex Patterns - Turkish Security Domain
# ============================================================

PATTERNS = {
    # Search patterns - handle both word orders (Turkish: verb at end, object first)
    'ip_search': r'(IP|adres|address).*(g[oö]ster|listele|bul|ara|getir)|(g[oö]ster|listele|bul|ara|getir).*(IP|adres|address)',
    'domain_analysis': r'(domain|alan\s*ad[iı]).*(analiz|incele|kontrol|ara[sş]t[iı]r)|(analiz|incele|kontrol|ara[sş]t[iı]r).*(domain|alan\s*ad[iı])',
    'threat_summary': r'(tehdit|risk|g[uü]venlik).*(özet|durum|neler)|(tehdit|risk|g[uü]venlik)\s+durum',
    'block_action': r'(engelle|blokla|yasakla|block)',
    'time_filter': r'(son|ge[cç]en|bug[uü]n|d[uü]n|hafta|ay|saat|g[uü]n)',
    'report_pattern': r'rapor\b|[oö]zet\b|istatistik\b',

    # Entity patterns
    'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
    'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'md5': r'\b[a-fA-F0-9]{32}\b',
    'sha1': r'\b[a-fA-F0-9]{40}\b',
    'sha256': r'\b[a-fA-F0-9]{64}\b',
    'cve': r'\bCVE-\d{4}-\d{4,7}\b',

    # Time expressions (Turkish)
    'son_n_saat': r'son\s+(\d+)\s*saat',
    'son_n_gun': r'son\s+(\d+)\s*g[uü]n',
    'son_n_hafta': r'son\s+(\d+)\s*hafta',
    'bugun': r'\bbug[uü]n\b',
    'dun': r'\bd[uü]n\b',
    'gecen_hafta': r'ge[cç]en\s*hafta',
    'bu_ay': r'bu\s*ay',
    'gecen_ay': r'ge[cç]en\s*ay',
}

# Intent keywords (Turkish)
INTENT_KEYWORDS = {
    'search': [
        'goster', 'göster', 'listele', 'bul', 'ara', 'getir', 'cek',
        'show', 'list', 'find', 'search', 'get', 'fetch',
        'supheli', 'şüpheli', 'zararli', 'zararlı', 'tehlike', 'anormal'
    ],
    'analyze': [
        'analiz', 'incele', 'kontrol', 'arastir', 'araştır', 'ne biliyoruz',
        'hakkinda', 'hakkında', 'detay', 'detayli', 'detaylı',
        'analyze', 'check', 'investigate', 'what do we know', 'about'
    ],
    'report': [
        'rapor', 'ozet', 'özet', 'istatistik', 'olustur', 'oluştur',
        'hazirla', 'hazırla', 'cikar', 'çıkar', 'dokuman', 'döküman',
        'report', 'summary', 'generate', 'create', 'statistics',
        'durum raporu'  # Compound phrase for "status report"
    ],
    'action': [
        'engelle', 'blokla', 'yasakla', 'kaldır', 'kaldir', 'sil',
        'kapat', 'ac', 'aç', 'aktif', 'pasif', 'durdur', 'baslat', 'başlat',
        'block', 'unblock', 'ban', 'remove', 'delete', 'stop', 'start'
    ],
    'summary': [
        'neler', 'nasil', 'nasıl', 'var mi', 'var mı',
        'saglik', 'sağlık', 'genel', 'toplam',
        'what', 'how', 'any', 'status', 'health', 'overall'
    ]
}

# Threat type keywords
THREAT_KEYWORDS = {
    'malware': ['malware', 'zararli', 'zararlı', 'virus', 'virüs', 'trojan', 'worm'],
    'ransomware': ['ransomware', 'fidye', 'sifrele', 'şifrele', 'encrypt'],
    'phishing': ['phishing', 'oltalama', 'sahte', 'dolandırıcı', 'scam'],
    'botnet': ['botnet', 'bot', 'zombie', 'ddos'],
    'apt': ['apt', 'advanced persistent', 'hedefli saldırı', 'hedefli saldiri'],
    'c2': ['c2', 'command and control', 'komuta kontrol'],
    'spam': ['spam', 'istenmeyen', 'junk'],
    'scanner': ['scanner', 'tarama', 'scan', 'port'],
    'brute_force': ['brute force', 'kaba kuvvet', 'deneme', 'sifre kirma'],
    'exploit': ['exploit', 'zafiyet', 'vulnerability', 'acik', 'açık'],
}

# Turkish verb suffixes to strip (ordered by length, longest first)
TURKISH_VERB_SUFFIXES = [
    'mek', 'mak',  # infinitive
    'eceğim', 'acağım', 'ecek', 'acak',  # future
    'iyor', 'ıyor', 'uyor', 'üyor', 'yor',  # continuous
    'di', 'dı', 'du', 'dü', 'ti', 'tı', 'tu', 'tü',  # past
    'sin', 'sın', 'sun', 'sün',  # imperative 2nd person
]

# Common Turkish security verbs (preserved as stems)
TURKISH_VERB_STEMS = {
    'goster': 'goster',
    'göster': 'goster',
    'listele': 'listele',
    'engelle': 'engelle',
    'analiz': 'analiz',
    'incele': 'incele',
    'kontrol': 'kontrol',
    'ara': 'ara',
    'bul': 'bul',
    'tara': 'tara',
}

# Turkish noun suffixes to strip
TURKISH_NOUN_SUFFIXES = [
    'ler', 'lar', 'leri', 'ları', 'lerin', 'ların',
    'i', 'ı', 'u', 'ü',  # accusative
    'in', 'ın', 'un', 'ün',  # genitive
    'de', 'da', 'te', 'ta',  # locative
    'den', 'dan', 'ten', 'tan',  # ablative
    'e', 'a',  # dative
    "'leri", "'ları", "'i", "'ı",  # with apostrophe
]

# Response templates (Turkish)
RESPONSE_TEMPLATES = {
    'search_results': {
        'found': "{count} adet sonuc bulundu.",
        'not_found': "Aramanizla eslesen sonuc bulunamadi.",
        'error': "Arama sirasinda hata olustu: {error}",
    },
    'analysis_results': {
        'high_threat': "{target} yuksek tehdit seviyesinde (skor: {score:.2f}). Acil aksiyon onerilir.",
        'medium_threat': "{target} orta seviye tehdit tespit edildi (skor: {score:.2f}).",
        'low_threat': "{target} dusuk seviye tehdit (skor: {score:.2f}).",
        'clean': "{target} temiz gorunuyor.",
    },
    'action_results': {
        'success': "{action} islemi {target} icin basariyla tamamlandi.",
        'failed': "{action} islemi {target} icin basarisiz oldu: {error}",
    },
    'recommendations': {
        'block': "Oneri: {target} adresini engellemeniz tavsiye edilir.",
        'monitor': "Oneri: {target} yakindan izlenmeli.",
        'investigate': "Oneri: {target} detayli arastirma gerektiriyor.",
    }
}


# ============================================================
# NLP Query Engine
# ============================================================

class NLPQueryEngine:
    """
    Turkish Natural Language Query Engine for Security Operations

    Turkce ve Ingilizce guvenlik sorgularini isleyen NLP motoru.
    """

    def __init__(self):
        """Initialize NLP engine"""
        self.patterns = self._compile_patterns()
        self.logger = logging.getLogger(f"{__name__}.NLPQueryEngine")

    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for performance"""
        compiled = {}
        for name, pattern in PATTERNS.items():
            try:
                compiled[name] = re.compile(pattern, re.IGNORECASE | re.UNICODE)
            except re.error as e:
                self.logger.error(f"Pattern compilation error for {name}: {e}")
        return compiled

    # ============================================================
    # Intent Classification
    # ============================================================

    def classify_intent(self, query: str) -> Dict[str, Any]:
        """
        Classify the intent of a natural language query.

        Args:
            query: Natural language query string

        Returns:
            Dict with intent type and confidence score
        """
        if not query or not query.strip():
            return {'intent': 'unknown', 'confidence': 0.0}

        query_lower = query.lower()
        scores = {intent: 0.0 for intent in INTENT_KEYWORDS.keys()}

        # Score based on keyword matches
        for intent, keywords in INTENT_KEYWORDS.items():
            for keyword in keywords:
                if keyword in query_lower:
                    # Exact word match scores higher
                    if re.search(rf'\b{re.escape(keyword)}\b', query_lower):
                        scores[intent] += 2.0
                    else:
                        scores[intent] += 1.0

        # Pattern-based scoring
        if self.patterns['block_action'].search(query):
            scores['action'] += 3.0
        if self.patterns['domain_analysis'].search(query):
            scores['analyze'] += 2.0
        if self.patterns['ip_search'].search(query):
            scores['search'] += 2.0

        # Check for report keywords FIRST (higher priority than summary)
        # "rapor" at word boundary indicates report intent
        if re.search(r'\brapor\b|\b[oö]zet\b|\bistatistik\b', query_lower):
            scores['report'] += 4.0  # Strong signal for report

        # Check for question patterns (summary) only if no report keyword
        if re.search(r'\?|neler|var\s*m[iı]|nas[iı]l', query_lower):
            if scores['report'] < 3.0:  # Only boost summary if not clearly a report
                scores['summary'] += 1.0

        # threat_summary pattern should only boost summary if no "rapor" word
        if self.patterns['threat_summary'].search(query) and 'rapor' not in query_lower:
            scores['summary'] += 2.0

        # Get highest scoring intent
        max_score = max(scores.values())
        if max_score == 0:
            return {'intent': 'unknown', 'confidence': 0.0}

        best_intent = max(scores, key=scores.get)

        # Calculate confidence (normalize to 0-1)
        total_score = sum(scores.values())
        confidence = min(max_score / max(total_score, 1) * 1.5, 1.0)

        return {
            'intent': best_intent,
            'confidence': confidence,
            'all_scores': scores
        }

    # ============================================================
    # Entity Extraction
    # ============================================================

    def extract_entities(self, query: str) -> Dict[str, Any]:
        """
        Extract security-related entities from query.

        Args:
            query: Natural language query string

        Returns:
            Dict containing extracted entities (IPs, domains, emails, etc.)
        """
        entities = {
            'ips': [],
            'domains': [],
            'emails': [],
            'hashes': {'md5': [], 'sha1': [], 'sha256': []},
            'threat_types': [],
            'cves': [],
            'time_range': None,
        }

        if not query:
            return entities

        # Extract IPs
        ipv4_matches = self.patterns['ipv4'].findall(query)
        entities['ips'] = list(set(ipv4_matches))

        # Extract domains (exclude emails)
        email_matches = self.patterns['email'].findall(query)
        entities['emails'] = list(set(email_matches))

        domain_matches = self.patterns['domain'].findall(query)
        # Filter out email domains
        email_domains = {e.split('@')[1] for e in email_matches}
        entities['domains'] = [d for d in set(domain_matches)
                              if d not in email_domains and not any(e.endswith(d) for e in email_matches)]

        # Extract hashes
        entities['hashes']['md5'] = list(set(self.patterns['md5'].findall(query)))
        entities['hashes']['sha1'] = list(set(self.patterns['sha1'].findall(query)))
        entities['hashes']['sha256'] = list(set(self.patterns['sha256'].findall(query)))

        # Filter out overlapping hashes (SHA256 contains MD5-like substrings)
        for sha256 in entities['hashes']['sha256']:
            entities['hashes']['md5'] = [h for h in entities['hashes']['md5'] if h not in sha256]
            entities['hashes']['sha1'] = [h for h in entities['hashes']['sha1'] if h not in sha256]
        for sha1 in entities['hashes']['sha1']:
            entities['hashes']['md5'] = [h for h in entities['hashes']['md5'] if h not in sha1]

        # Extract CVEs
        cve_matches = self.patterns['cve'].findall(query)
        entities['cves'] = list(set(cve_matches))

        # Extract threat types
        query_lower = query.lower()
        for threat_type, keywords in THREAT_KEYWORDS.items():
            for keyword in keywords:
                if keyword in query_lower:
                    if threat_type not in entities['threat_types']:
                        entities['threat_types'].append(threat_type)
                    break

        # Extract time range
        entities['time_range'] = self._extract_time_range(query)

        return entities

    def _extract_time_range(self, query: str) -> Optional[Dict[str, Any]]:
        """Extract time range from Turkish time expressions"""
        query_lower = query.lower()
        now = datetime.now()

        # Son N saat
        match = self.patterns['son_n_saat'].search(query_lower)
        if match:
            hours = int(match.group(1))
            return {
                'type': 'relative',
                'hours': hours,
                'start': now - timedelta(hours=hours),
                'end': now
            }

        # Son N gun
        match = self.patterns['son_n_gun'].search(query_lower)
        if match:
            days = int(match.group(1))
            return {
                'type': 'relative',
                'days': days,
                'start': now - timedelta(days=days),
                'end': now
            }

        # Son N hafta
        match = self.patterns['son_n_hafta'].search(query_lower)
        if match:
            weeks = int(match.group(1))
            return {
                'type': 'relative',
                'weeks': weeks,
                'start': now - timedelta(weeks=weeks),
                'end': now
            }

        # Bugun
        if self.patterns['bugun'].search(query_lower):
            today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
            return {
                'type': 'today',
                'start': today_start,
                'end': now
            }

        # Dun
        if self.patterns['dun'].search(query_lower):
            yesterday = now - timedelta(days=1)
            yesterday_start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
            yesterday_end = yesterday.replace(hour=23, minute=59, second=59, microsecond=999999)
            return {
                'type': 'yesterday',
                'start': yesterday_start,
                'end': yesterday_end
            }

        # Gecen hafta
        if self.patterns['gecen_hafta'].search(query_lower):
            days_since_monday = now.weekday()
            last_monday = now - timedelta(days=days_since_monday + 7)
            last_sunday = last_monday + timedelta(days=6)
            return {
                'type': 'last_week',
                'start': last_monday.replace(hour=0, minute=0, second=0, microsecond=0),
                'end': last_sunday.replace(hour=23, minute=59, second=59, microsecond=999999)
            }

        # Bu ay
        if self.patterns['bu_ay'].search(query_lower):
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            return {
                'type': 'this_month',
                'start': month_start,
                'end': now
            }

        # Gecen ay
        if self.patterns['gecen_ay'].search(query_lower):
            first_of_this_month = now.replace(day=1)
            last_month_end = first_of_this_month - timedelta(days=1)
            last_month_start = last_month_end.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            return {
                'type': 'last_month',
                'start': last_month_start,
                'end': last_month_end.replace(hour=23, minute=59, second=59, microsecond=999999)
            }

        return None

    # ============================================================
    # Turkish Morphology
    # ============================================================

    def extract_verb_stem(self, word: str) -> str:
        """Extract verb stem from Turkish verb"""
        word_orig = word
        word = word.lower().strip()

        # Handle compound verbs like "analiz et"
        if ' ' in word:
            parts = word.split()
            return parts[0]

        # Check if word is a known stem
        if word in TURKISH_VERB_STEMS:
            return TURKISH_VERB_STEMS[word]

        # Check for common base forms with suffixes
        for stem_key, stem_value in TURKISH_VERB_STEMS.items():
            if word.startswith(stem_key):
                return stem_value

        # Strip verb suffixes only for longer words
        result = word
        for suffix in sorted(TURKISH_VERB_SUFFIXES, key=len, reverse=True):
            if word.endswith(suffix) and len(word) > len(suffix) + 2:
                result = word[:-len(suffix)]
                break

        # Return the result, ensuring it's at least as long as common stems
        if len(result) >= 3:
            return result
        return word

    def normalize_noun(self, word: str) -> str:
        """Normalize Turkish noun by removing suffixes"""
        word = word.lower().strip()

        # Remove apostrophe suffix (e.g., IP'leri -> IP)
        if "'" in word:
            word = word.split("'")[0]

        # Strip noun suffixes
        for suffix in sorted(TURKISH_NOUN_SUFFIXES, key=len, reverse=True):
            if word.endswith(suffix) and len(word) > len(suffix) + 1:
                return word[:-len(suffix)]

        return word

    # ============================================================
    # Query Parsing (Main Interface)
    # ============================================================

    def parse_query(self, query: str) -> Dict[str, Any]:
        """
        Parse a natural language query into structured format.

        Args:
            query: Natural language query string

        Returns:
            Dict containing parsed query with intent, entities, and structured query
        """
        # Handle empty/whitespace queries
        if not query or not query.strip():
            return {
                'original_query': query or "",
                'intent': 'unknown',
                'confidence': 0.0,
                'entities': self.extract_entities(""),
                'structured_query': {},
                'integration': 'internal',
                'soar_actions': [],
                'sanitized': True
            }

        # Sanitize query
        sanitized_query = self._sanitize_query(query)

        # Classify intent
        intent_result = self.classify_intent(sanitized_query)

        # Extract entities
        entities = self.extract_entities(sanitized_query)

        # Build structured query
        structured_query = self._build_structured_query(
            intent_result['intent'],
            entities,
            sanitized_query
        )

        # Determine integration target
        integration = self._determine_integration(
            intent_result['intent'],
            entities,
            sanitized_query
        )

        # Extract SOAR actions if applicable
        soar_actions = self._extract_soar_actions(
            intent_result['intent'],
            entities,
            sanitized_query
        )

        return {
            'original_query': query,
            'intent': intent_result['intent'],
            'confidence': intent_result['confidence'],
            'entities': entities,
            'structured_query': structured_query,
            'integration': integration,
            'soar_actions': soar_actions,
            'sanitized': True
        }

    def _sanitize_query(self, query: str) -> str:
        """Sanitize query to prevent injection attacks"""
        if not query:
            return ""

        # Remove potential SQL injection patterns
        sanitized = re.sub(r'[;\'"\\]', '', query)

        # Remove excessive whitespace
        sanitized = ' '.join(sanitized.split())

        # Limit length
        if len(sanitized) > 1000:
            sanitized = sanitized[:1000]

        return sanitized

    def _build_structured_query(self, intent: str, entities: Dict,
                                 query: str) -> Dict[str, Any]:
        """Build structured query from parsed components"""
        structured = {}

        if intent == 'search':
            structured['search_type'] = self._determine_search_type(entities, query)
            if entities['ips']:
                structured['target_ips'] = entities['ips']
            if entities['domains']:
                structured['target_domains'] = entities['domains']
            if entities['threat_types']:
                structured['threat_filter'] = entities['threat_types']
            if entities['time_range']:
                structured['time_range'] = entities['time_range']

        elif intent == 'analyze':
            # Determine analysis target
            if entities['ips']:
                structured['target'] = entities['ips'][0]
                structured['target_type'] = 'ip'
            elif entities['domains']:
                structured['target'] = entities['domains'][0]
                structured['target_type'] = 'domain'
            elif entities['emails']:
                structured['target'] = entities['emails'][0]
                structured['target_type'] = 'email'
            elif entities['hashes']['sha256']:
                structured['target'] = entities['hashes']['sha256'][0]
                structured['target_type'] = 'hash_sha256'
            elif entities['hashes']['sha1']:
                structured['target'] = entities['hashes']['sha1'][0]
                structured['target_type'] = 'hash_sha1'
            elif entities['hashes']['md5']:
                structured['target'] = entities['hashes']['md5'][0]
                structured['target_type'] = 'hash_md5'

        elif intent == 'action':
            structured['action_type'] = self._determine_action_type(query)
            if entities['ips']:
                structured['target'] = entities['ips'][0]
                structured['target_type'] = 'ip'
            elif entities['domains']:
                structured['target'] = entities['domains'][0]
                structured['target_type'] = 'domain'

        elif intent == 'report':
            structured['report_type'] = self._determine_report_type(query)
            if entities['time_range']:
                structured['time_range'] = entities['time_range']

        return structured

    def _determine_search_type(self, entities: Dict, query: str) -> str:
        """Determine type of search based on entities and query"""
        query_lower = query.lower()

        if entities['threat_types']:
            return 'threat_search'
        if 'ip' in query_lower or entities['ips']:
            return 'ip_search'
        if 'domain' in query_lower or 'alan' in query_lower or entities['domains']:
            return 'domain_search'
        if 'log' in query_lower or 'kayit' in query_lower:
            return 'log_search'
        if 'anomali' in query_lower or 'anormal' in query_lower:
            return 'anomaly_search'

        return 'general_search'

    def _determine_action_type(self, query: str) -> str:
        """Determine action type from query"""
        query_lower = query.lower()

        if any(w in query_lower for w in ['engelle', 'blokla', 'block', 'yasakla']):
            return 'block'
        if any(w in query_lower for w in ['kaldır', 'kaldir', 'unblock', 'serbest']):
            return 'unblock'
        if any(w in query_lower for w in ['alarm', 'uyar', 'alert']):
            return 'alert'
        if any(w in query_lower for w in ['karantina', 'quarantine', 'izole']):
            return 'quarantine'
        if any(w in query_lower for w in ['tara', 'scan']):
            return 'scan'

        return 'unknown'

    def _determine_report_type(self, query: str) -> str:
        """Determine report type from query"""
        query_lower = query.lower()

        if 'hafta' in query_lower or 'weekly' in query_lower:
            return 'weekly'
        if 'gun' in query_lower or 'gün' in query_lower or 'daily' in query_lower:
            return 'daily'
        if 'ay' in query_lower or 'monthly' in query_lower:
            return 'monthly'
        if 'tehdit' in query_lower or 'threat' in query_lower:
            return 'threat'
        if 'guvenlik' in query_lower or 'güvenlik' in query_lower or 'security' in query_lower:
            return 'security'

        return 'general'

    def _determine_integration(self, intent: str, entities: Dict,
                                query: str) -> str:
        """Determine which module should handle this query"""
        query_lower = query.lower()

        # OSINT keywords
        if any(w in query_lower for w in ['osint', 'arastir', 'araştır', 'sosyal medya',
                                           'email', 'kullanici', 'kullanıcı']):
            return 'osint'

        # SIGINT keywords
        if any(w in query_lower for w in ['wifi', 'bluetooth', 'sinyal', 'sigint',
                                           'kablosuz', 'ag', 'ağ', 'network']):
            return 'sigint'

        # Threat Intel keywords
        if any(w in query_lower for w in ['tehdit', 'threat', 'apt', 'ioc', 'mitre',
                                           'saldırı', 'saldiri', 'attack']):
            return 'threat_intel'

        # SOAR for actions
        if intent == 'action':
            return 'soar'

        # Email analysis -> OSINT
        if entities.get('emails'):
            return 'osint'

        return 'internal'

    def _extract_soar_actions(self, intent: str, entities: Dict,
                               query: str) -> List[Dict[str, Any]]:
        """Extract SOAR automation actions from query"""
        actions = []

        if intent != 'action':
            return actions

        action_type = self._determine_action_type(query)

        # Build action object
        action = {
            'type': action_type,
            'targets': [],
            'auto_execute': False
        }

        # Add targets
        if entities['ips']:
            for ip in entities['ips']:
                action['targets'].append({'type': 'ip', 'value': ip})
        if entities['domains']:
            for domain in entities['domains']:
                action['targets'].append({'type': 'domain', 'value': domain})

        if action['targets']:
            actions.append(action)

        # Check for compound actions (e.g., "engelle ve rapor olustur")
        query_lower = query.lower()
        if 've' in query_lower or 'and' in query_lower:
            if any(w in query_lower for w in ['rapor', 'report']):
                actions.append({
                    'type': 'report',
                    'targets': action['targets'].copy(),
                    'auto_execute': False
                })

        return actions

    # ============================================================
    # Response Generation
    # ============================================================

    def generate_response(self, intent: str, results: Optional[Dict] = None,
                          error: Optional[str] = None, language: str = 'tr') -> str:
        """
        Generate natural language response from structured results.

        Args:
            intent: Query intent type
            results: Structured results data
            error: Error message if any
            language: Response language (tr/en)

        Returns:
            Natural language response string
        """
        if error:
            return RESPONSE_TEMPLATES['search_results']['error'].format(error=error)

        if results is None:
            return "Sonuc bulunamadi."

        response_parts = []

        if intent == 'search':
            count = results.get('count', 0)
            if count > 0:
                response_parts.append(
                    RESPONSE_TEMPLATES['search_results']['found'].format(count=count)
                )

                # Add item summaries
                items = results.get('items', [])
                for item in items[:5]:  # Limit to 5 items
                    if 'ip' in item:
                        level = item.get('threat_level', 'unknown')
                        response_parts.append(f"  - {item['ip']}: {level} seviye")
            else:
                response_parts.append(RESPONSE_TEMPLATES['search_results']['not_found'])

        elif intent == 'analyze':
            target = results.get('target', 'Hedef')
            score = results.get('threat_score', 0)

            if score >= 0.8:
                response_parts.append(
                    RESPONSE_TEMPLATES['analysis_results']['high_threat'].format(
                        target=target, score=score
                    )
                )
                response_parts.append(
                    RESPONSE_TEMPLATES['recommendations']['block'].format(target=target)
                )
            elif score >= 0.5:
                response_parts.append(
                    RESPONSE_TEMPLATES['analysis_results']['medium_threat'].format(
                        target=target, score=score
                    )
                )
                response_parts.append(
                    RESPONSE_TEMPLATES['recommendations']['monitor'].format(target=target)
                )
            elif score >= 0.2:
                response_parts.append(
                    RESPONSE_TEMPLATES['analysis_results']['low_threat'].format(
                        target=target, score=score
                    )
                )
            else:
                response_parts.append(
                    RESPONSE_TEMPLATES['analysis_results']['clean'].format(target=target)
                )

            # Add categories if present
            categories = results.get('categories', [])
            if categories:
                response_parts.append(f"Kategoriler: {', '.join(categories)}")

        elif intent == 'action':
            action = results.get('action', 'Islem')
            target = results.get('target', 'hedef')
            success = results.get('success', False)

            if success:
                response_parts.append(
                    RESPONSE_TEMPLATES['action_results']['success'].format(
                        action=action.capitalize(), target=target
                    )
                )
            else:
                error_msg = results.get('error', 'Bilinmeyen hata')
                response_parts.append(
                    RESPONSE_TEMPLATES['action_results']['failed'].format(
                        action=action.capitalize(), target=target, error=error_msg
                    )
                )

        elif intent == 'report':
            response_parts.append("Rapor olusturuldu.")
            if 'summary' in results:
                response_parts.append(results['summary'])

        return '\n'.join(response_parts)

    # ============================================================
    # Query Suggestions
    # ============================================================

    def get_suggestions(self, partial_query: str = "",
                        context: Optional[Dict] = None) -> List[str]:
        """
        Get query suggestions based on partial input and context.

        Args:
            partial_query: Partial query string
            context: Optional context from previous interactions

        Returns:
            List of suggested queries
        """
        suggestions = []
        partial_lower = partial_query.lower()

        # Time-based suggestions
        if any(w in partial_lower for w in ['son', 'saat', 'gun', 'gün']):
            suggestions.extend([
                "Son 24 saatte supheli IP'leri goster",
                "Son 7 gunde tespit edilen tehditler",
                "Son 1 saatte gelen alarmlari listele",
            ])

        # IP-based suggestions - check if query contains an IP address
        has_ip = self.patterns['ipv4'].search(partial_query)
        if 'ip' in partial_lower or has_ip:
            suggestions.extend([
                "Bu IP'yi analiz et",
                "IP adresi hakkinda bilgi ver",
                "IP'yi engelle",
                "IP aktivite gecmisini goster",
            ])
            # If it's just an IP address, add more specific suggestions
            if has_ip:
                suggestions.extend([
                    "IP adresini analiz et",
                    "Bu IP hakkinda bilgi topla",
                ])

        # Domain-based suggestions
        if 'domain' in partial_lower or 'alan' in partial_lower:
            suggestions.extend([
                "Domain analizi yap",
                "Domain WHOIS bilgisi",
                "Domain DNS kayitlari",
            ])

        # Threat-based suggestions
        if any(w in partial_lower for w in ['tehdit', 'threat', 'saldiri', 'attack']):
            suggestions.extend([
                "Kritik tehditler neler?",
                "Aktif saldirilar var mi?",
                "Tehdit ozetini goster",
            ])

        # Context-aware suggestions
        if context:
            last_intent = context.get('last_intent')
            if last_intent == 'search':
                suggestions.extend([
                    "Sonuclari detayli goster",
                    "Rapor olarak kaydet",
                    "Filtreyi genislet",
                ])
            elif last_intent == 'analyze':
                suggestions.extend([
                    "Iliskili IP'leri goster",
                    "Benzer tehditler",
                    "Engelleme onerisi",
                ])

        # Default suggestions if empty
        if not suggestions:
            suggestions = [
                "Son 24 saatte supheli aktiviteler",
                "Kritik tehditler neler?",
                "Guvenlik durumu nasil?",
                "Haftalik rapor olustur",
                "Anomali tespit et",
            ]

        # Filter based on partial query - but skip filtering if we detected an entity
        # (e.g., if user typed an IP address, show IP-related suggestions)
        has_entity = (self.patterns['ipv4'].search(partial_query) or
                      self.patterns['domain'].search(partial_query) or
                      self.patterns['email'].search(partial_query))

        if partial_query and not has_entity:
            # Only filter for text-based partial queries, not entity inputs
            filtered = [s for s in suggestions if partial_lower in s.lower() or
                       any(w in s.lower() for w in partial_lower.split())]
            if filtered:
                suggestions = filtered

        return suggestions[:10]  # Limit to 10 suggestions

    # ============================================================
    # API Interface Methods
    # ============================================================

    def process_api_request(self, request_data: Dict) -> Dict[str, Any]:
        """
        Process API request for query endpoint.

        Args:
            request_data: Dict with 'query', 'language', 'context'

        Returns:
            Dict with 'success', 'parsed_query', 'response'
        """
        query = request_data.get('query', '')
        language = request_data.get('language', 'tr')
        context = request_data.get('context', {})

        try:
            parsed = self.parse_query(query)

            # Generate response based on parsed query
            # In real implementation, this would execute the query
            response = f"Sorgu ayristirildi: {parsed['intent']} niyeti algilandi."

            return {
                'success': True,
                'parsed_query': parsed,
                'response': response,
                'suggestions': self.get_suggestions(query, context)
            }

        except Exception as e:
            self.logger.error(f"API request processing error: {e}")
            return {
                'success': False,
                'error': str(e),
                'parsed_query': None,
                'response': f"Sorgu islenirken hata olustu: {e}"
            }

    def get_suggestions_api(self, request_data: Dict) -> Dict[str, Any]:
        """
        Process API request for suggestions endpoint.

        Args:
            request_data: Dict with 'partial_query', 'context'

        Returns:
            Dict with 'suggestions'
        """
        partial = request_data.get('partial_query', '')
        context = request_data.get('context', {})

        suggestions = self.get_suggestions(partial, context)

        return {
            'suggestions': suggestions
        }

    def generate_report_api(self, request_data: Dict) -> Dict[str, Any]:
        """
        Process API request for report generation endpoint.

        Args:
            request_data: Dict with 'report_type', 'time_range', 'language'

        Returns:
            Dict with 'success', 'report'
        """
        report_type = request_data.get('report_type', 'general')
        time_range = request_data.get('time_range', 'last_24h')
        language = request_data.get('language', 'tr')

        try:
            # In real implementation, this would query data and generate report
            report = {
                'type': report_type,
                'time_range': time_range,
                'generated_at': datetime.now().isoformat(),
                'summary': f"{report_type.capitalize()} raporu olusturuldu.",
                'sections': [
                    {
                        'title': 'Genel Bakis',
                        'content': 'Rapor icerigi burada yer alacak.'
                    }
                ]
            }

            return {
                'success': True,
                'report': report
            }

        except Exception as e:
            self.logger.error(f"Report generation error: {e}")
            return {
                'success': False,
                'error': str(e),
                'report': None
            }

    # ============================================================
    # Pattern Access
    # ============================================================

    def get_patterns(self) -> Dict[str, str]:
        """Return raw pattern strings for testing"""
        return PATTERNS.copy()


# ============================================================
# Flask API Routes (for integration with dalga_web.py)
# ============================================================

def register_nlp_routes(app):
    """
    Register NLP API routes with Flask app.

    Args:
        app: Flask application instance
    """
    from flask import request, jsonify

    nlp_engine = NLPQueryEngine()

    @app.route('/api/v1/nlp/query', methods=['POST'])
    def nlp_query():
        """Process natural language query"""
        data = request.get_json(silent=True) or {}
        result = nlp_engine.process_api_request(data)
        return jsonify(result)

    @app.route('/api/v1/nlp/suggestions', methods=['GET'])
    def nlp_suggestions():
        """Get query suggestions"""
        partial = request.args.get('q', '')
        result = nlp_engine.get_suggestions_api({
            'partial_query': partial,
            'context': {}
        })
        return jsonify(result)

    @app.route('/api/v1/nlp/report', methods=['POST'])
    def nlp_report():
        """Generate natural language report"""
        data = request.get_json(silent=True) or {}
        result = nlp_engine.generate_report_api(data)
        return jsonify(result)

    return nlp_engine


# ============================================================
# CLI Interface
# ============================================================

def main():
    """CLI interface for NLP query engine"""
    import argparse

    parser = argparse.ArgumentParser(
        description='DALGA NLP - Turkish Natural Language Query Interface'
    )
    parser.add_argument('query', nargs='?', help='Natural language query')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--suggestions', action='store_true',
                       help='Get query suggestions')

    args = parser.parse_args()

    engine = NLPQueryEngine()

    if args.suggestions:
        suggestions = engine.get_suggestions(args.query or '')
        if args.json:
            print(json.dumps({'suggestions': suggestions}, ensure_ascii=False, indent=2))
        else:
            print("Onerilen sorgular:")
            for i, s in enumerate(suggestions, 1):
                print(f"  {i}. {s}")
        return

    if not args.query:
        print("Kullanim: dalga_nlp.py <sorgu>")
        print("Ornek: dalga_nlp.py \"Son 24 saatte supheli IP'leri goster\"")
        return

    result = engine.parse_query(args.query)

    if args.json:
        # Convert datetime objects to strings for JSON serialization
        def serialize(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj

        output = json.dumps(result, default=serialize, ensure_ascii=False, indent=2)
        print(output)
    else:
        print(f"\nSorgu: {result['original_query']}")
        print(f"Niyet: {result['intent']} (guven: {result['confidence']:.2f})")
        print(f"Entegrasyon: {result['integration']}")

        entities = result['entities']
        if entities['ips']:
            print(f"IP Adresleri: {', '.join(entities['ips'])}")
        if entities['domains']:
            print(f"Domainler: {', '.join(entities['domains'])}")
        if entities['emails']:
            print(f"E-postalar: {', '.join(entities['emails'])}")
        if entities['threat_types']:
            print(f"Tehdit Turleri: {', '.join(entities['threat_types'])}")
        if entities['time_range']:
            tr = entities['time_range']
            print(f"Zaman Araligi: {tr.get('type', 'bilinmiyor')}")


if __name__ == '__main__':
    main()
