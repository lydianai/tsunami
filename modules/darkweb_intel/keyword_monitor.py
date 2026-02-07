#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Keyword Monitoring System
    Monitor for organization mentions, brand abuse, and executive name monitoring
================================================================================
"""

import os
import re
import time
import json
import hashlib
import logging
import threading
from typing import Optional, Dict, Any, List, Set, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class MonitoringCategory(Enum):
    """Categories for monitoring rules"""
    ORGANIZATION = "organization"
    BRAND = "brand"
    EXECUTIVE = "executive"
    PRODUCT = "product"
    DOMAIN = "domain"
    EMAIL = "email"
    CUSTOM = "custom"


class AlertSource(Enum):
    """Sources where alerts can originate"""
    PASTE_SITE = "paste_site"
    BREACH_DATABASE = "breach_database"
    THREAT_FEED = "threat_feed"
    SOCIAL_MEDIA = "social_media"
    SEARCH_ENGINE = "search_engine"
    DARK_WEB = "dark_web"
    CUSTOM = "custom"


@dataclass
class MonitoringRule:
    """A single monitoring rule configuration"""
    rule_id: str
    name: str
    category: MonitoringCategory
    keywords: List[str]
    regex_patterns: List[str] = field(default_factory=list)
    enabled: bool = True
    severity_boost: int = 0  # Add to base severity
    notify_on_match: bool = True
    notify_emails: List[str] = field(default_factory=list)
    notify_webhooks: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    match_count: int = 0
    last_match: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Alert:
    """An alert generated from keyword monitoring"""
    alert_id: str
    rule_id: str
    rule_name: str
    category: MonitoringCategory
    severity: AlertSeverity
    source: AlertSource
    matched_keywords: List[str]
    matched_content: str
    content_preview: str
    source_url: Optional[str] = None
    source_title: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    false_positive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class KeywordMatcher:
    """
    Efficient keyword and pattern matching engine
    """

    def __init__(self):
        self._keyword_sets: Dict[str, Set[str]] = {}
        self._regex_patterns: Dict[str, List[re.Pattern]] = {}

    def add_rule(self, rule: MonitoringRule):
        """Add a rule's patterns to the matcher"""
        # Normalize keywords
        self._keyword_sets[rule.rule_id] = set(kw.lower() for kw in rule.keywords)

        # Compile regex patterns
        compiled = []
        for pattern in rule.regex_patterns:
            try:
                compiled.append(re.compile(pattern, re.IGNORECASE))
            except re.error as e:
                logger.error(f"[MATCHER] Invalid regex '{pattern}': {e}")
        self._regex_patterns[rule.rule_id] = compiled

    def remove_rule(self, rule_id: str):
        """Remove a rule from the matcher"""
        self._keyword_sets.pop(rule_id, None)
        self._regex_patterns.pop(rule_id, None)

    def match(self, content: str, rule_id: str) -> List[str]:
        """
        Find all matches for a rule in content

        Returns list of matched keywords/patterns
        """
        matches = []
        content_lower = content.lower()

        # Check keywords
        keywords = self._keyword_sets.get(rule_id, set())
        for keyword in keywords:
            if keyword in content_lower:
                matches.append(keyword)

        # Check regex patterns
        patterns = self._regex_patterns.get(rule_id, [])
        for pattern in patterns:
            regex_matches = pattern.findall(content)
            matches.extend(regex_matches)

        return list(set(matches))  # Deduplicate

    def match_all(self, content: str) -> Dict[str, List[str]]:
        """
        Match content against all rules

        Returns dict of rule_id -> matched keywords
        """
        results = {}
        for rule_id in self._keyword_sets:
            matches = self.match(content, rule_id)
            if matches:
                results[rule_id] = matches
        return results


class NotificationManager:
    """
    Handles alert notifications via email and webhooks
    """

    def __init__(self):
        self._email_enabled = bool(os.getenv("SMTP_HOST"))
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "TSUNAMI-AlertNotifier/5.0",
            "Content-Type": "application/json"
        })

    def send_webhook(self, webhook_url: str, alert: Alert) -> bool:
        """Send alert to webhook"""
        try:
            payload = {
                "alert_id": alert.alert_id,
                "rule_name": alert.rule_name,
                "category": alert.category.value,
                "severity": alert.severity.value,
                "source": alert.source.value,
                "matched_keywords": alert.matched_keywords,
                "content_preview": alert.content_preview[:500],
                "source_url": alert.source_url,
                "timestamp": alert.created_at.isoformat()
            }

            response = self._session.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            response.raise_for_status()

            logger.info(f"[NOTIFY] Webhook sent to {webhook_url}")
            return True

        except Exception as e:
            logger.error(f"[NOTIFY] Webhook failed: {e}")
            return False

    def send_email(self, recipients: List[str], alert: Alert) -> bool:
        """Send alert via email"""
        if not self._email_enabled:
            logger.warning("[NOTIFY] Email not configured")
            return False

        try:
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart

            smtp_host = os.getenv("SMTP_HOST")
            smtp_port = int(os.getenv("SMTP_PORT", 587))
            smtp_user = os.getenv("SMTP_USER")
            smtp_pass = os.getenv("SMTP_PASS")
            from_email = os.getenv("SMTP_FROM", smtp_user)

            # Create message
            msg = MIMEMultipart()
            msg["Subject"] = f"[{alert.severity.value.upper()}] {alert.rule_name} - TSUNAMI Alert"
            msg["From"] = from_email
            msg["To"] = ", ".join(recipients)

            body = f"""
TSUNAMI Dark Web Intelligence Alert

Severity: {alert.severity.value.upper()}
Rule: {alert.rule_name}
Category: {alert.category.value}
Source: {alert.source.value}

Matched Keywords: {', '.join(alert.matched_keywords)}

Content Preview:
{alert.content_preview[:1000]}

Source URL: {alert.source_url or 'N/A'}
Timestamp: {alert.created_at.isoformat()}

---
This is an automated alert from TSUNAMI v5.0 Dark Web Intelligence Module.
"""
            msg.attach(MIMEText(body, "plain"))

            # Send email
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                if smtp_user and smtp_pass:
                    server.login(smtp_user, smtp_pass)
                server.sendmail(from_email, recipients, msg.as_string())

            logger.info(f"[NOTIFY] Email sent to {len(recipients)} recipients")
            return True

        except Exception as e:
            logger.error(f"[NOTIFY] Email failed: {e}")
            return False


class KeywordMonitor:
    """
    Main keyword monitoring system

    Features:
    - Multi-category keyword monitoring
    - Regex pattern support
    - Severity-based alerting
    - Webhook and email notifications
    - Alert acknowledgment tracking
    - False positive marking
    """

    def __init__(self):
        self.rules: Dict[str, MonitoringRule] = {}
        self.alerts: List[Alert] = []
        self.matcher = KeywordMatcher()
        self.notifier = NotificationManager()
        self._callbacks: List[Callable[[Alert], None]] = []
        self._running = False
        self._lock = threading.Lock()
        self._alert_counter = 0

        logger.info("[KEYWORD-MONITOR] Initialized")

    def _generate_rule_id(self) -> str:
        """Generate unique rule ID"""
        return hashlib.sha256(
            f"{datetime.now().isoformat()}:{len(self.rules)}".encode()
        ).hexdigest()[:12]

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        self._alert_counter += 1
        return hashlib.sha256(
            f"{datetime.now().isoformat()}:{self._alert_counter}".encode()
        ).hexdigest()[:16]

    def add_rule(self, rule: MonitoringRule) -> str:
        """
        Add a monitoring rule

        Returns:
            Rule ID
        """
        if not rule.rule_id:
            rule.rule_id = self._generate_rule_id()

        with self._lock:
            self.rules[rule.rule_id] = rule
            self.matcher.add_rule(rule)

        logger.info(f"[KEYWORD-MONITOR] Added rule: {rule.name} ({rule.rule_id})")
        return rule.rule_id

    def create_rule(self,
                   name: str,
                   keywords: List[str],
                   category: MonitoringCategory = MonitoringCategory.CUSTOM,
                   regex_patterns: Optional[List[str]] = None,
                   severity_boost: int = 0,
                   notify_emails: Optional[List[str]] = None,
                   notify_webhooks: Optional[List[str]] = None) -> str:
        """
        Create and add a new monitoring rule

        Args:
            name: Rule name
            keywords: List of keywords to monitor
            category: Monitoring category
            regex_patterns: Optional regex patterns
            severity_boost: Severity boost (0-2)
            notify_emails: Email addresses for notifications
            notify_webhooks: Webhook URLs for notifications

        Returns:
            Rule ID
        """
        rule = MonitoringRule(
            rule_id="",
            name=name,
            category=category,
            keywords=keywords,
            regex_patterns=regex_patterns or [],
            severity_boost=severity_boost,
            notify_emails=notify_emails or [],
            notify_webhooks=notify_webhooks or []
        )
        return self.add_rule(rule)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a monitoring rule"""
        with self._lock:
            if rule_id in self.rules:
                del self.rules[rule_id]
                self.matcher.remove_rule(rule_id)
                logger.info(f"[KEYWORD-MONITOR] Removed rule: {rule_id}")
                return True
        return False

    def enable_rule(self, rule_id: str):
        """Enable a rule"""
        with self._lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = True

    def disable_rule(self, rule_id: str):
        """Disable a rule"""
        with self._lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = False

    def get_rule(self, rule_id: str) -> Optional[MonitoringRule]:
        """Get a rule by ID"""
        return self.rules.get(rule_id)

    def list_rules(self, category: Optional[MonitoringCategory] = None) -> List[MonitoringRule]:
        """List all rules, optionally filtered by category"""
        rules = list(self.rules.values())
        if category:
            rules = [r for r in rules if r.category == category]
        return rules

    def register_callback(self, callback: Callable[[Alert], None]):
        """Register callback for new alerts"""
        self._callbacks.append(callback)

    def process_content(self,
                       content: str,
                       source: AlertSource,
                       source_url: Optional[str] = None,
                       source_title: Optional[str] = None,
                       base_severity: AlertSeverity = AlertSeverity.MEDIUM) -> List[Alert]:
        """
        Process content against all active rules

        Args:
            content: Content to analyze
            source: Source of the content
            source_url: URL where content was found
            source_title: Title of the source
            base_severity: Base severity level

        Returns:
            List of generated alerts
        """
        alerts = []

        # Get all matches
        all_matches = self.matcher.match_all(content)

        for rule_id, matched_keywords in all_matches.items():
            rule = self.rules.get(rule_id)

            if not rule or not rule.enabled:
                continue

            # Calculate severity
            severity_order = [
                AlertSeverity.INFO,
                AlertSeverity.LOW,
                AlertSeverity.MEDIUM,
                AlertSeverity.HIGH,
                AlertSeverity.CRITICAL
            ]
            base_idx = severity_order.index(base_severity)
            boosted_idx = min(base_idx + rule.severity_boost, len(severity_order) - 1)
            final_severity = severity_order[boosted_idx]

            # Create alert
            alert = Alert(
                alert_id=self._generate_alert_id(),
                rule_id=rule_id,
                rule_name=rule.name,
                category=rule.category,
                severity=final_severity,
                source=source,
                matched_keywords=matched_keywords,
                matched_content=content,
                content_preview=content[:500],
                source_url=source_url,
                source_title=source_title
            )

            # Store alert
            with self._lock:
                self.alerts.append(alert)
                rule.match_count += 1
                rule.last_match = datetime.now()

                # Limit stored alerts
                if len(self.alerts) > 10000:
                    self.alerts = self.alerts[-10000:]

            alerts.append(alert)

            # Send notifications
            if rule.notify_on_match:
                self._send_notifications(alert, rule)

            # Notify callbacks
            for callback in self._callbacks:
                try:
                    callback(alert)
                except Exception as e:
                    logger.error(f"[KEYWORD-MONITOR] Callback error: {e}")

        return alerts

    def _send_notifications(self, alert: Alert, rule: MonitoringRule):
        """Send notifications for an alert"""
        # Send webhooks
        for webhook in rule.notify_webhooks:
            threading.Thread(
                target=self.notifier.send_webhook,
                args=(webhook, alert),
                daemon=True
            ).start()

        # Send emails
        if rule.notify_emails:
            threading.Thread(
                target=self.notifier.send_email,
                args=(rule.notify_emails, alert),
                daemon=True
            ).start()

    def acknowledge_alert(self, alert_id: str, acknowledged_by: Optional[str] = None) -> bool:
        """Acknowledge an alert"""
        with self._lock:
            for alert in self.alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    alert.acknowledged_at = datetime.now()
                    alert.acknowledged_by = acknowledged_by
                    return True
        return False

    def mark_false_positive(self, alert_id: str) -> bool:
        """Mark an alert as false positive"""
        with self._lock:
            for alert in self.alerts:
                if alert.alert_id == alert_id:
                    alert.false_positive = True
                    alert.acknowledged = True
                    alert.acknowledged_at = datetime.now()
                    return True
        return False

    def get_alerts(self,
                  severity: Optional[AlertSeverity] = None,
                  category: Optional[MonitoringCategory] = None,
                  source: Optional[AlertSource] = None,
                  acknowledged: Optional[bool] = None,
                  limit: int = 100,
                  offset: int = 0) -> List[Alert]:
        """
        Get alerts with optional filters

        Args:
            severity: Filter by severity
            category: Filter by category
            source: Filter by source
            acknowledged: Filter by acknowledgment status
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of alerts
        """
        with self._lock:
            alerts = self.alerts.copy()

        # Apply filters
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if category:
            alerts = [a for a in alerts if a.category == category]
        if source:
            alerts = [a for a in alerts if a.source == source]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]

        # Sort by creation time, newest first
        alerts.sort(key=lambda x: x.created_at, reverse=True)

        return alerts[offset:offset + limit]

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get a specific alert"""
        with self._lock:
            for alert in self.alerts:
                if alert.alert_id == alert_id:
                    return alert
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get monitoring statistics"""
        with self._lock:
            alerts_copy = self.alerts.copy()
            rules_copy = list(self.rules.values())

        stats = {
            "total_rules": len(rules_copy),
            "active_rules": len([r for r in rules_copy if r.enabled]),
            "total_alerts": len(alerts_copy),
            "unacknowledged_alerts": len([a for a in alerts_copy if not a.acknowledged]),
            "false_positives": len([a for a in alerts_copy if a.false_positive]),
            "alerts_by_severity": {},
            "alerts_by_category": {},
            "alerts_by_source": {},
            "top_triggered_rules": [],
            "recent_alerts": []
        }

        # Count by severity
        for alert in alerts_copy:
            sev = alert.severity.value
            stats["alerts_by_severity"][sev] = stats["alerts_by_severity"].get(sev, 0) + 1

            cat = alert.category.value
            stats["alerts_by_category"][cat] = stats["alerts_by_category"].get(cat, 0) + 1

            src = alert.source.value
            stats["alerts_by_source"][src] = stats["alerts_by_source"].get(src, 0) + 1

        # Top triggered rules
        sorted_rules = sorted(rules_copy, key=lambda x: x.match_count, reverse=True)[:5]
        stats["top_triggered_rules"] = [
            {"rule_id": r.rule_id, "name": r.name, "match_count": r.match_count}
            for r in sorted_rules
        ]

        # Recent alerts
        recent = sorted(alerts_copy, key=lambda x: x.created_at, reverse=True)[:5]
        stats["recent_alerts"] = [
            {
                "alert_id": a.alert_id,
                "rule_name": a.rule_name,
                "severity": a.severity.value,
                "matched_keywords": a.matched_keywords[:3],
                "created_at": a.created_at.isoformat()
            }
            for a in recent
        ]

        return stats


# Convenience functions
_keyword_monitor: Optional[KeywordMonitor] = None

def get_keyword_monitor() -> KeywordMonitor:
    """Get or create global keyword monitor instance"""
    global _keyword_monitor
    if _keyword_monitor is None:
        _keyword_monitor = KeywordMonitor()
    return _keyword_monitor


def create_organization_monitor(org_name: str,
                                domains: List[str],
                                executives: Optional[List[str]] = None,
                                products: Optional[List[str]] = None,
                                notify_webhook: Optional[str] = None) -> List[str]:
    """
    Convenience function to create a full organization monitoring setup

    Args:
        org_name: Organization name
        domains: Organization domains
        executives: Executive names to monitor
        products: Product names to monitor
        notify_webhook: Optional webhook for notifications

    Returns:
        List of created rule IDs
    """
    monitor = get_keyword_monitor()
    rule_ids = []

    webhooks = [notify_webhook] if notify_webhook else []

    # Organization name rule
    rule_id = monitor.create_rule(
        name=f"{org_name} - Organization Mention",
        keywords=[org_name, org_name.lower(), org_name.upper()],
        category=MonitoringCategory.ORGANIZATION,
        severity_boost=1,
        notify_webhooks=webhooks
    )
    rule_ids.append(rule_id)

    # Domain rules
    for domain in domains:
        rule_id = monitor.create_rule(
            name=f"{org_name} - Domain ({domain})",
            keywords=[domain, f"@{domain}"],
            regex_patterns=[rf'\b[\w.-]+@{re.escape(domain)}\b'],
            category=MonitoringCategory.DOMAIN,
            severity_boost=1,
            notify_webhooks=webhooks
        )
        rule_ids.append(rule_id)

    # Executive rules
    if executives:
        for exec_name in executives:
            rule_id = monitor.create_rule(
                name=f"{org_name} - Executive ({exec_name})",
                keywords=[exec_name],
                category=MonitoringCategory.EXECUTIVE,
                severity_boost=2,  # Higher severity for executives
                notify_webhooks=webhooks
            )
            rule_ids.append(rule_id)

    # Product rules
    if products:
        for product in products:
            rule_id = monitor.create_rule(
                name=f"{org_name} - Product ({product})",
                keywords=[product],
                category=MonitoringCategory.PRODUCT,
                notify_webhooks=webhooks
            )
            rule_ids.append(rule_id)

    logger.info(f"[KEYWORD-MONITOR] Created {len(rule_ids)} rules for {org_name}")
    return rule_ids
