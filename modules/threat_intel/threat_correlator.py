#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Threat Correlator v5.0
    Real-time Threat Correlation and Alerting
================================================================================

    Features:
    - Match incoming traffic/logs against threat indicators
    - Score threats by severity and confidence
    - Generate real-time alerts
    - Correlate multiple indicators for campaign detection
    - Rate limiting and caching for performance

================================================================================
"""

import os
import re
import json
import time
import hashlib
import logging
import threading
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set, Callable, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from pathlib import Path

from .stix_taxii_client import get_stix_client, STIXTAXIIClient
from .stix_parser import STIXParser, ParsedIndicator, MITREMapper

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"  # 90-100
    HIGH = "high"          # 70-89
    MEDIUM = "medium"      # 40-69
    LOW = "low"            # 20-39
    INFO = "info"          # 0-19


class AlertStatus(Enum):
    """Alert status"""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


@dataclass
class ThreatAlert:
    """Threat alert"""
    id: str
    indicator_type: str
    indicator_value: str
    severity: ThreatSeverity
    score: float
    confidence: float
    sources: List[str]
    matched_at: datetime
    context: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    related_indicators: List[str] = field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    analyst_notes: str = ""
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            'id': self.id,
            'indicator_type': self.indicator_type,
            'indicator_value': self.indicator_value,
            'severity': self.severity.value,
            'score': self.score,
            'confidence': self.confidence,
            'sources': self.sources,
            'matched_at': self.matched_at.isoformat() if self.matched_at else None,
            'context': self.context,
            'mitre_techniques': self.mitre_techniques,
            'related_indicators': self.related_indicators,
            'status': self.status.value,
            'analyst_notes': self.analyst_notes,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None
        }


@dataclass
class CorrelationResult:
    """Result of threat correlation"""
    is_threat: bool
    indicator_type: str
    indicator_value: str
    score: float
    confidence: float
    severity: ThreatSeverity
    sources: List[str]
    matched_indicators: List[dict]
    mitre_techniques: List[str]
    recommendations: List[str]
    check_time_ms: float

    def to_dict(self) -> dict:
        return {
            'is_threat': self.is_threat,
            'indicator_type': self.indicator_type,
            'indicator_value': self.indicator_value,
            'score': self.score,
            'confidence': self.confidence,
            'severity': self.severity.value,
            'sources': self.sources,
            'matched_indicators': self.matched_indicators,
            'mitre_techniques': self.mitre_techniques,
            'recommendations': self.recommendations,
            'check_time_ms': self.check_time_ms
        }


class IndicatorIndex:
    """Fast index for indicator lookups"""

    def __init__(self):
        self.ips: Dict[str, List[dict]] = {}
        self.ip_networks: List[Tuple[ipaddress.IPv4Network, dict]] = []
        self.domains: Dict[str, List[dict]] = {}
        self.domain_patterns: List[Tuple[str, dict]] = []  # Wildcard domains
        self.urls: Dict[str, List[dict]] = {}
        self.hashes: Dict[str, List[dict]] = {}  # All hash types
        self.emails: Dict[str, List[dict]] = {}
        self.cves: Dict[str, List[dict]] = {}
        self._lock = threading.RLock()
        self._stats = defaultdict(int)

    def add_indicator(self, indicator: dict) -> None:
        """Add indicator to index"""
        with self._lock:
            ind_type = indicator.get('type', '').lower()
            value = indicator.get('value', '').lower().strip()

            if not value:
                return

            if ind_type in ('ip', 'ipv4', 'ipv6', 'ipv4-addr', 'ipv6-addr'):
                self._add_ip(value, indicator)
            elif ind_type in ('domain', 'domain-name', 'hostname'):
                self._add_domain(value, indicator)
            elif ind_type in ('url', 'uri'):
                self._add_url(value, indicator)
            elif ind_type in ('hash', 'hash_md5', 'hash_sha1', 'hash_sha256', 'md5', 'sha1', 'sha256',
                             'file:hashes.md5', 'file:hashes.sha-1', 'file:hashes.sha-256'):
                self._add_hash(value, indicator)
            elif ind_type in ('email', 'email-addr'):
                self._add_email(value, indicator)
            elif ind_type in ('cve', 'vulnerability'):
                self._add_cve(value.upper(), indicator)

            self._stats['total'] += 1
            self._stats[ind_type] += 1

    def _add_ip(self, value: str, indicator: dict) -> None:
        """Add IP to index"""
        try:
            # Check if CIDR
            if '/' in value:
                network = ipaddress.ip_network(value, strict=False)
                self.ip_networks.append((network, indicator))
            else:
                if value not in self.ips:
                    self.ips[value] = []
                self.ips[value].append(indicator)
        except ValueError:
            pass

    def _add_domain(self, value: str, indicator: dict) -> None:
        """Add domain to index"""
        # Handle wildcard domains
        if value.startswith('*.'):
            self.domain_patterns.append((value[2:], indicator))
        else:
            if value not in self.domains:
                self.domains[value] = []
            self.domains[value].append(indicator)

    def _add_url(self, value: str, indicator: dict) -> None:
        """Add URL to index"""
        # Normalize URL
        if not value.startswith(('http://', 'https://')):
            value = 'http://' + value
        if value not in self.urls:
            self.urls[value] = []
        self.urls[value].append(indicator)

    def _add_hash(self, value: str, indicator: dict) -> None:
        """Add hash to index"""
        if value not in self.hashes:
            self.hashes[value] = []
        self.hashes[value].append(indicator)

    def _add_email(self, value: str, indicator: dict) -> None:
        """Add email to index"""
        if value not in self.emails:
            self.emails[value] = []
        self.emails[value].append(indicator)

    def _add_cve(self, value: str, indicator: dict) -> None:
        """Add CVE to index"""
        if value not in self.cves:
            self.cves[value] = []
        self.cves[value].append(indicator)

    def lookup_ip(self, ip: str) -> List[dict]:
        """Lookup IP in index"""
        with self._lock:
            results = []
            ip_lower = ip.lower().strip()

            # Direct match
            if ip_lower in self.ips:
                results.extend(self.ips[ip_lower])

            # CIDR match
            try:
                ip_obj = ipaddress.ip_address(ip_lower)
                for network, indicator in self.ip_networks:
                    if ip_obj in network:
                        results.append({**indicator, 'matched_network': str(network)})
            except ValueError:
                pass

            return results

    def lookup_domain(self, domain: str) -> List[dict]:
        """Lookup domain in index"""
        with self._lock:
            results = []
            domain_lower = domain.lower().strip()

            # Direct match
            if domain_lower in self.domains:
                results.extend(self.domains[domain_lower])

            # Wildcard match
            for pattern, indicator in self.domain_patterns:
                if domain_lower.endswith(pattern) or domain_lower == pattern:
                    results.append({**indicator, 'matched_pattern': f'*.{pattern}'})

            return results

    def lookup_url(self, url: str) -> List[dict]:
        """Lookup URL in index"""
        with self._lock:
            results = []
            url_lower = url.lower().strip()

            # Normalize
            if not url_lower.startswith(('http://', 'https://')):
                url_lower = 'http://' + url_lower

            # Direct match
            if url_lower in self.urls:
                results.extend(self.urls[url_lower])

            # Also check https variant
            if url_lower.startswith('http://'):
                https_url = 'https://' + url_lower[7:]
                if https_url in self.urls:
                    results.extend(self.urls[https_url])

            return results

    def lookup_hash(self, hash_value: str) -> List[dict]:
        """Lookup hash in index"""
        with self._lock:
            hash_lower = hash_value.lower().strip()
            return self.hashes.get(hash_lower, [])

    def lookup_email(self, email: str) -> List[dict]:
        """Lookup email in index"""
        with self._lock:
            email_lower = email.lower().strip()
            return self.emails.get(email_lower, [])

    def lookup_cve(self, cve: str) -> List[dict]:
        """Lookup CVE in index"""
        with self._lock:
            cve_upper = cve.upper().strip()
            return self.cves.get(cve_upper, [])

    def clear(self) -> None:
        """Clear all indices"""
        with self._lock:
            self.ips.clear()
            self.ip_networks.clear()
            self.domains.clear()
            self.domain_patterns.clear()
            self.urls.clear()
            self.hashes.clear()
            self.emails.clear()
            self.cves.clear()
            self._stats.clear()

    def get_stats(self) -> dict:
        """Get index statistics"""
        with self._lock:
            return {
                'total': self._stats.get('total', 0),
                'ips': len(self.ips),
                'ip_networks': len(self.ip_networks),
                'domains': len(self.domains),
                'domain_patterns': len(self.domain_patterns),
                'urls': len(self.urls),
                'hashes': len(self.hashes),
                'emails': len(self.emails),
                'cves': len(self.cves),
                'by_type': dict(self._stats)
            }


class ThreatCorrelator:
    """
    Real-time Threat Correlator

    Matches incoming indicators against threat intelligence
    and generates scored alerts.
    """

    # Severity score thresholds
    SEVERITY_THRESHOLDS = {
        ThreatSeverity.CRITICAL: 90,
        ThreatSeverity.HIGH: 70,
        ThreatSeverity.MEDIUM: 40,
        ThreatSeverity.LOW: 20,
        ThreatSeverity.INFO: 0
    }

    # Source confidence weights
    SOURCE_WEIGHTS = {
        'abuse_ch_urlhaus': 0.9,
        'abuse_ch_malwarebazaar': 0.95,
        'abuse_ch_threatfox': 0.9,
        'abuse_ch_feodo': 0.95,
        'abuse_ch_sslbl': 0.85,
        'cisa_kev': 0.99,
        'alienvault_otx': 0.8,
        'emerging_threats': 0.75,
        'blocklist_de': 0.7,
        'misp': 0.85,
        'default': 0.6
    }

    # Indicator type base scores
    TYPE_SCORES = {
        'ip': 50,
        'ipv4': 50,
        'ipv6': 50,
        'domain': 60,
        'url': 70,
        'hash': 80,
        'hash_md5': 75,
        'hash_sha1': 78,
        'hash_sha256': 80,
        'email': 40,
        'cve': 90
    }

    def __init__(self, stix_client: Optional[STIXTAXIIClient] = None):
        """Initialize correlator"""
        self.stix_client = stix_client or get_stix_client()
        self.parser = STIXParser()
        self.index = IndicatorIndex()
        self.alerts: List[ThreatAlert] = []
        self.alert_callbacks: List[Callable[[ThreatAlert], None]] = []

        self._lock = threading.RLock()
        self._last_update = None
        self._check_count = 0
        self._match_count = 0

        # Load indicators on startup
        self._load_indicators()

        logger.info("[CORRELATOR] Threat correlator initialized")

    def _load_indicators(self) -> None:
        """Load indicators from STIX client"""
        try:
            all_indicators = self.stix_client.fetch_all_feeds()

            for source, indicators in all_indicators.items():
                for ind in indicators:
                    self.index.add_indicator(ind)

            self._last_update = datetime.now()
            logger.info(f"[CORRELATOR] Loaded {self.index.get_stats()['total']} indicators")

        except Exception as e:
            logger.error(f"[CORRELATOR] Failed to load indicators: {e}")

    def refresh_indicators(self, force: bool = False) -> dict:
        """Refresh indicator index from feeds"""
        try:
            self.index.clear()
            all_indicators = self.stix_client.fetch_all_feeds(force=force)

            total = 0
            for source, indicators in all_indicators.items():
                for ind in indicators:
                    self.index.add_indicator(ind)
                total += len(indicators)

            self._last_update = datetime.now()

            return {
                'success': True,
                'indicators_loaded': total,
                'index_stats': self.index.get_stats(),
                'updated_at': self._last_update.isoformat()
            }

        except Exception as e:
            logger.error(f"[CORRELATOR] Refresh failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def check_indicator(self, value: str, indicator_type: Optional[str] = None) -> CorrelationResult:
        """
        Check if an indicator matches known threats

        Args:
            value: Indicator value (IP, domain, hash, etc.)
            indicator_type: Optional type hint

        Returns:
            CorrelationResult with threat score and details
        """
        start_time = time.time()

        with self._lock:
            self._check_count += 1

        # Auto-detect type if not specified
        if not indicator_type:
            indicator_type = self._detect_type(value)

        # Lookup based on type
        matches = self._lookup(value, indicator_type)

        # Calculate score
        score, confidence, sources = self._calculate_score(matches, indicator_type)

        # Determine severity
        severity = self._get_severity(score)

        # Get MITRE techniques
        mitre_techniques = self._get_mitre_techniques(matches, indicator_type)

        # Generate recommendations
        recommendations = self._get_recommendations(severity, indicator_type)

        is_threat = score > 0 and len(matches) > 0

        if is_threat:
            with self._lock:
                self._match_count += 1

        check_time = (time.time() - start_time) * 1000

        result = CorrelationResult(
            is_threat=is_threat,
            indicator_type=indicator_type,
            indicator_value=value,
            score=score,
            confidence=confidence,
            severity=severity,
            sources=sources,
            matched_indicators=matches[:10],  # Limit for response size
            mitre_techniques=mitre_techniques,
            recommendations=recommendations,
            check_time_ms=round(check_time, 2)
        )

        # Generate alert if high severity
        if is_threat and severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH):
            self._create_alert(result)

        return result

    def check_batch(self, indicators: List[dict]) -> List[CorrelationResult]:
        """
        Check multiple indicators at once

        Args:
            indicators: List of {'value': str, 'type': str} dicts

        Returns:
            List of CorrelationResults
        """
        results = []

        for ind in indicators:
            value = ind.get('value', '')
            ind_type = ind.get('type')

            if value:
                result = self.check_indicator(value, ind_type)
                results.append(result)

        return results

    def check_ip(self, ip: str) -> CorrelationResult:
        """Check IP address"""
        return self.check_indicator(ip, 'ip')

    def check_domain(self, domain: str) -> CorrelationResult:
        """Check domain"""
        return self.check_indicator(domain, 'domain')

    def check_url(self, url: str) -> CorrelationResult:
        """Check URL"""
        return self.check_indicator(url, 'url')

    def check_hash(self, hash_value: str) -> CorrelationResult:
        """Check file hash"""
        return self.check_indicator(hash_value, 'hash')

    def _detect_type(self, value: str) -> str:
        """Auto-detect indicator type"""
        value = value.strip()

        # IP address
        try:
            ipaddress.ip_address(value)
            return 'ip'
        except ValueError:
            pass

        # CIDR
        if '/' in value:
            try:
                ipaddress.ip_network(value, strict=False)
                return 'ip'
            except ValueError:
                pass

        # URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return 'url'

        # Email
        if '@' in value and '.' in value:
            return 'email'

        # CVE
        if value.upper().startswith('CVE-'):
            return 'cve'

        # Hash (by length)
        if value.replace('-', '').isalnum():
            length = len(value)
            if length == 32:
                return 'hash_md5'
            elif length == 40:
                return 'hash_sha1'
            elif length == 64:
                return 'hash_sha256'

        # Domain (default for anything with dots)
        if '.' in value:
            return 'domain'

        return 'unknown'

    def _lookup(self, value: str, indicator_type: str) -> List[dict]:
        """Lookup indicator in index"""
        if indicator_type in ('ip', 'ipv4', 'ipv6'):
            return self.index.lookup_ip(value)
        elif indicator_type == 'domain':
            return self.index.lookup_domain(value)
        elif indicator_type == 'url':
            return self.index.lookup_url(value)
        elif indicator_type in ('hash', 'hash_md5', 'hash_sha1', 'hash_sha256'):
            return self.index.lookup_hash(value)
        elif indicator_type == 'email':
            return self.index.lookup_email(value)
        elif indicator_type == 'cve':
            return self.index.lookup_cve(value)
        else:
            # Try all lookups
            results = []
            results.extend(self.index.lookup_ip(value))
            results.extend(self.index.lookup_domain(value))
            results.extend(self.index.lookup_url(value))
            results.extend(self.index.lookup_hash(value))
            return results

    def _calculate_score(self, matches: List[dict], indicator_type: str) -> Tuple[float, float, List[str]]:
        """Calculate threat score from matches"""
        if not matches:
            return (0.0, 0.0, [])

        sources = set()
        confidences = []
        source_scores = []

        for match in matches:
            source = match.get('source', 'default')
            sources.add(source)

            # Get source weight
            weight = self.SOURCE_WEIGHTS.get(source, self.SOURCE_WEIGHTS['default'])
            source_scores.append(weight)

            # Get indicator confidence if available
            conf = match.get('confidence', 0)
            if isinstance(conf, (int, float)):
                if conf > 1:  # Normalize if percentage
                    conf = conf / 100
                confidences.append(conf)
            else:
                confidences.append(weight)

        # Base score from indicator type
        base_score = self.TYPE_SCORES.get(indicator_type, 50)

        # Adjust by number of sources (more sources = higher confidence)
        source_bonus = min(len(sources) * 5, 20)

        # Adjust by source weights
        avg_source_weight = sum(source_scores) / len(source_scores) if source_scores else 0.5

        # Calculate final score
        score = base_score * avg_source_weight + source_bonus
        score = min(score, 100)  # Cap at 100

        # Calculate confidence
        confidence = sum(confidences) / len(confidences) if confidences else 0.5

        return (round(score, 2), round(confidence, 2), list(sources))

    def _get_severity(self, score: float) -> ThreatSeverity:
        """Get severity level from score"""
        if score >= self.SEVERITY_THRESHOLDS[ThreatSeverity.CRITICAL]:
            return ThreatSeverity.CRITICAL
        elif score >= self.SEVERITY_THRESHOLDS[ThreatSeverity.HIGH]:
            return ThreatSeverity.HIGH
        elif score >= self.SEVERITY_THRESHOLDS[ThreatSeverity.MEDIUM]:
            return ThreatSeverity.MEDIUM
        elif score >= self.SEVERITY_THRESHOLDS[ThreatSeverity.LOW]:
            return ThreatSeverity.LOW
        else:
            return ThreatSeverity.INFO

    def _get_mitre_techniques(self, matches: List[dict], indicator_type: str) -> List[str]:
        """Get associated MITRE techniques"""
        techniques = set()

        # From indicator type
        type_techniques = MITREMapper.get_techniques_for_indicator(indicator_type)
        techniques.update(type_techniques)

        # From matches
        for match in matches:
            if 'malware' in match:
                malware_type = match.get('malware', '').lower()
                mal_techniques = MITREMapper.get_techniques_for_malware([malware_type])
                techniques.update(mal_techniques)

            if 'threat_type' in match:
                threat_type = match.get('threat_type', '').lower()
                if 'botnet' in threat_type:
                    techniques.update(['T1071', 'T1095', 'T1219'])
                elif 'ransomware' in threat_type:
                    techniques.update(['T1486', 'T1490', 'T1489'])
                elif 'c2' in threat_type or 'c&c' in threat_type:
                    techniques.update(['T1071', 'T1095', 'T1573'])

        return sorted(list(techniques))

    def _get_recommendations(self, severity: ThreatSeverity, indicator_type: str) -> List[str]:
        """Get response recommendations"""
        recommendations = []

        if severity == ThreatSeverity.CRITICAL:
            recommendations = [
                "IMMEDIATE: Isolate affected systems from network",
                "Initiate incident response procedures",
                "Block indicator at perimeter firewall",
                "Preserve forensic evidence",
                "Notify security operations center (SOC)",
                "Consider reporting to law enforcement"
            ]
        elif severity == ThreatSeverity.HIGH:
            recommendations = [
                "Block indicator at firewall/proxy",
                "Review logs for related activity",
                "Scan affected systems for compromise",
                "Update detection rules",
                "Document findings for threat intel"
            ]
        elif severity == ThreatSeverity.MEDIUM:
            recommendations = [
                "Add to watchlist for monitoring",
                "Review associated network traffic",
                "Check for related indicators",
                "Consider blocking based on context"
            ]
        elif severity == ThreatSeverity.LOW:
            recommendations = [
                "Monitor for additional activity",
                "Log for baseline analysis",
                "Review if repeated"
            ]

        # Type-specific recommendations
        if indicator_type == 'ip':
            recommendations.append("Check geo-location and ASN information")
        elif indicator_type == 'domain':
            recommendations.append("Review DNS records and WHOIS data")
        elif indicator_type == 'url':
            recommendations.append("Check URL reputation services")
        elif indicator_type in ('hash', 'hash_md5', 'hash_sha1', 'hash_sha256'):
            recommendations.append("Submit to malware analysis sandbox")
        elif indicator_type == 'cve':
            recommendations.append("Verify patch status on affected systems")

        return recommendations

    def _create_alert(self, result: CorrelationResult) -> ThreatAlert:
        """Create and store alert"""
        alert_id = f"alert-{hashlib.md5(f'{result.indicator_value}-{datetime.now().isoformat()}'.encode()).hexdigest()[:16]}"

        alert = ThreatAlert(
            id=alert_id,
            indicator_type=result.indicator_type,
            indicator_value=result.indicator_value,
            severity=result.severity,
            score=result.score,
            confidence=result.confidence,
            sources=result.sources,
            matched_at=datetime.now(),
            mitre_techniques=result.mitre_techniques
        )

        with self._lock:
            self.alerts.append(alert)

            # Keep only last 1000 alerts
            if len(self.alerts) > 1000:
                self.alerts = self.alerts[-1000:]

        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"[CORRELATOR] Callback error: {e}")

        return alert

    def register_alert_callback(self, callback: Callable[[ThreatAlert], None]) -> None:
        """Register callback for new alerts"""
        self.alert_callbacks.append(callback)

    def get_alerts(self,
                   severity: Optional[ThreatSeverity] = None,
                   status: Optional[AlertStatus] = None,
                   limit: int = 100) -> List[ThreatAlert]:
        """Get alerts with optional filters"""
        with self._lock:
            alerts = list(self.alerts)

        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        if status:
            alerts = [a for a in alerts if a.status == status]

        # Sort by matched_at descending
        alerts.sort(key=lambda a: a.matched_at, reverse=True)

        return alerts[:limit]

    def update_alert_status(self, alert_id: str, status: AlertStatus, notes: str = "") -> bool:
        """Update alert status"""
        with self._lock:
            for alert in self.alerts:
                if alert.id == alert_id:
                    alert.status = status
                    if notes:
                        alert.analyst_notes = notes
                    if status == AlertStatus.RESOLVED:
                        alert.resolved_at = datetime.now()
                    return True
        return False

    def get_statistics(self) -> dict:
        """Get correlator statistics"""
        with self._lock:
            alert_by_severity = defaultdict(int)
            alert_by_status = defaultdict(int)

            for alert in self.alerts:
                alert_by_severity[alert.severity.value] += 1
                alert_by_status[alert.status.value] += 1

            return {
                'index_stats': self.index.get_stats(),
                'total_checks': self._check_count,
                'total_matches': self._match_count,
                'match_rate': round(self._match_count / self._check_count * 100, 2) if self._check_count > 0 else 0,
                'total_alerts': len(self.alerts),
                'alerts_by_severity': dict(alert_by_severity),
                'alerts_by_status': dict(alert_by_status),
                'last_update': self._last_update.isoformat() if self._last_update else None,
                'feed_status': self.stix_client.get_feed_status()
            }


# Singleton instance
_correlator: Optional[ThreatCorrelator] = None


def get_correlator() -> ThreatCorrelator:
    """Get singleton correlator instance"""
    global _correlator
    if _correlator is None:
        _correlator = ThreatCorrelator()
    return _correlator
