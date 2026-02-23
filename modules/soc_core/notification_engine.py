#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI SOC - Multi-Channel Notification Engine
    Production-Grade Alert Notification System
================================================================================

    Channels:
    - Email (SMTP with TLS)
    - Slack (Webhook + API)
    - Telegram (Bot API)
    - PagerDuty (Events API v2)
    - Microsoft Teams (Webhook)
    - Webhook (Generic HTTP POST)

    Features:
    - Priority-based routing (P1 → PagerDuty+All, P4 → Email only)
    - Rate limiting per channel
    - Template engine with Jinja2-like variable substitution
    - Notification history (SQLite persistence)
    - Retry with exponential backoff
    - Digest mode (batch notifications)
    - Thread-safe operations

================================================================================
"""

import hashlib
import json
import logging
import os
import re
import smtplib
import sqlite3
import ssl
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logger = logging.getLogger("soc.notifications")


# ============================================================================
# Enums & Config
# ============================================================================

class NotificationChannel(Enum):
    EMAIL = "email"
    SLACK = "slack"
    TELEGRAM = "telegram"
    PAGERDUTY = "pagerduty"
    TEAMS = "teams"
    WEBHOOK = "webhook"


class NotificationPriority(Enum):
    P1_CRITICAL = 1     # All channels, immediate
    P2_HIGH = 2         # Slack + Email + PagerDuty
    P3_MEDIUM = 3       # Slack + Email
    P4_LOW = 4          # Email only
    P5_INFO = 5         # Digest only (batched)


class NotificationStatus(Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    RETRYING = "retrying"
    SUPPRESSED = "suppressed"  # Rate-limited


# Default routing rules: priority → channels
DEFAULT_ROUTING = {
    NotificationPriority.P1_CRITICAL: {
        NotificationChannel.PAGERDUTY, NotificationChannel.SLACK,
        NotificationChannel.TELEGRAM, NotificationChannel.EMAIL,
        NotificationChannel.TEAMS,
    },
    NotificationPriority.P2_HIGH: {
        NotificationChannel.SLACK, NotificationChannel.EMAIL,
        NotificationChannel.PAGERDUTY, NotificationChannel.TEAMS,
    },
    NotificationPriority.P3_MEDIUM: {
        NotificationChannel.SLACK, NotificationChannel.EMAIL,
    },
    NotificationPriority.P4_LOW: {
        NotificationChannel.EMAIL,
    },
    NotificationPriority.P5_INFO: set(),  # Digest only
}


@dataclass
class ChannelConfig:
    """Configuration for a notification channel."""
    channel: NotificationChannel
    enabled: bool = False
    config: Dict[str, Any] = field(default_factory=dict)
    rate_limit_per_minute: int = 30
    rate_limit_per_hour: int = 200


@dataclass
class Notification:
    """A notification to be sent."""
    notification_id: str
    title: str
    message: str
    priority: NotificationPriority
    channel: NotificationChannel
    status: NotificationStatus = NotificationStatus.PENDING
    metadata: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    sent_at: Optional[datetime] = None
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'notification_id': self.notification_id,
            'title': self.title,
            'message': self.message[:500],
            'priority': self.priority.name,
            'channel': self.channel.value,
            'status': self.status.value,
            'retry_count': self.retry_count,
            'created_at': self.created_at.isoformat(),
            'sent_at': self.sent_at.isoformat() if self.sent_at else None,
            'error': self.error,
        }


# ============================================================================
# Template Engine (Simple variable substitution)
# ============================================================================

class TemplateEngine:
    """Simple template engine for notification messages."""

    # Default templates
    TEMPLATES = {
        'alert_new': {
            'title': '[{severity}] {title}',
            'message': (
                '🚨 *New Alert*\n'
                '━━━━━━━━━━━━━━━━━━━\n'
                '*ID:* {alert_id}\n'
                '*Severity:* {severity}\n'
                '*Title:* {title}\n'
                '*Source:* {source}\n'
                '*Category:* {category}\n'
                '*Source IP:* {src_ip}\n'
                '*Dest IP:* {dst_ip}\n'
                '*Hostname:* {hostname}\n'
                '*CVSS:* {cvss_score}\n'
                '*Priority Score:* {priority_score}\n'
                '*MITRE:* {mitre_techniques}\n'
                '*SLA Deadline:* {sla_deadline}\n'
                '━━━━━━━━━━━━━━━━━━━\n'
                '_TSUNAMI SOC_'
            ),
        },
        'sla_breach': {
            'title': '⏰ SLA BREACH: {title}',
            'message': (
                '⏰ *SLA Breach Alert*\n'
                '━━━━━━━━━━━━━━━━━━━\n'
                '*Alert:* {alert_id}\n'
                '*Title:* {title}\n'
                '*Severity:* {severity}\n'
                '*SLA Deadline:* {sla_deadline}\n'
                '*Assigned To:* {assigned_to}\n'
                '━━━━━━━━━━━━━━━━━━━\n'
                '⚠️ Immediate action required!'
            ),
        },
        'incident_created': {
            'title': '🔴 Incident: {title}',
            'message': (
                '🔴 *New Incident*\n'
                '━━━━━━━━━━━━━━━━━━━\n'
                '*ID:* {incident_id}\n'
                '*Title:* {title}\n'
                '*Severity:* {severity}\n'
                '*Commander:* {commander}\n'
                '*Related Alerts:* {alert_count}\n'
                '━━━━━━━━━━━━━━━━━━━'
            ),
        },
        'digest': {
            'title': '📊 SOC Daily Digest',
            'message': (
                '📊 *SOC Daily Digest*\n'
                '━━━━━━━━━━━━━━━━━━━\n'
                '*New Alerts:* {new_count}\n'
                '*Resolved:* {resolved_count}\n'
                '*Active Critical:* {critical_count}\n'
                '*SLA Breaches:* {sla_breach_count}\n'
                '*MTTD:* {mttd}\n'
                '*MTTR:* {mttr}\n'
                '━━━━━━━━━━━━━━━━━━━\n'
                '_Generated {timestamp}_'
            ),
        },
    }

    @classmethod
    def render(cls, template_name: str, variables: Dict[str, Any],
               custom_templates: Optional[Dict] = None) -> Tuple[str, str]:
        """Render a template with variables. Returns (title, message)."""
        templates = custom_templates or cls.TEMPLATES
        template = templates.get(template_name, {
            'title': '{title}',
            'message': '{message}',
        })

        # Safe variable substitution
        def _sub(text: str) -> str:
            def replacer(match):
                key = match.group(1)
                val = variables.get(key, '')
                if isinstance(val, (list, dict)):
                    return json.dumps(val, default=str)
                return str(val) if val else 'N/A'
            return re.sub(r'\{(\w+)\}', replacer, text)

        title = _sub(template.get('title', ''))
        message = _sub(template.get('message', ''))
        return title, message


# ============================================================================
# Channel Senders
# ============================================================================

class EmailSender:
    """Send notifications via SMTP."""

    @staticmethod
    def send(config: Dict[str, Any], title: str, message: str,
             recipients: Optional[List[str]] = None) -> bool:
        """
        Config keys: smtp_host, smtp_port, smtp_user, smtp_password,
                     from_address, to_addresses (list), use_tls
        """
        host = config.get('smtp_host', os.getenv('SMTP_HOST', ''))
        port = int(config.get('smtp_port', os.getenv('SMTP_PORT', '587')))
        user = config.get('smtp_user', os.getenv('SMTP_USER', ''))
        password = config.get('smtp_password', os.getenv('SMTP_PASSWORD', ''))
        from_addr = config.get('from_address', os.getenv('SMTP_FROM', user))
        to_addrs = recipients or config.get('to_addresses', [])
        use_tls = config.get('use_tls', True)

        if not host or not to_addrs:
            logger.warning("[EMAIL] Not configured (missing host or recipients)")
            return False

        msg = MIMEMultipart('alternative')
        msg['Subject'] = title
        msg['From'] = from_addr
        msg['To'] = ', '.join(to_addrs)

        # Plain text
        msg.attach(MIMEText(message, 'plain', 'utf-8'))

        # HTML version
        html = f"""
        <div style="font-family: monospace; background: #1a1a2e; color: #e0e0e0; padding: 20px; border-radius: 8px;">
            <h2 style="color: #00b4ff; margin: 0 0 15px 0;">{title}</h2>
            <pre style="white-space: pre-wrap; font-size: 13px;">{message}</pre>
            <hr style="border-color: #333;">
            <small style="color: #666;">TSUNAMI SOC Notification Engine</small>
        </div>
        """
        msg.attach(MIMEText(html, 'html', 'utf-8'))

        try:
            ctx = ssl.create_default_context()
            if use_tls:
                server = smtplib.SMTP(host, port, timeout=15)
                server.starttls(context=ctx)
            else:
                server = smtplib.SMTP_SSL(host, port, timeout=15, context=ctx)

            if user and password:
                server.login(user, password)

            server.sendmail(from_addr, to_addrs, msg.as_string())
            server.quit()
            logger.info(f"[EMAIL] Sent: {title} → {len(to_addrs)} recipients")
            return True

        except Exception as e:
            logger.error(f"[EMAIL] Send failed: {e}")
            raise


class SlackSender:
    """Send notifications via Slack Webhook or API."""

    @staticmethod
    def send(config: Dict[str, Any], title: str, message: str) -> bool:
        """
        Config keys: webhook_url OR (api_token + channel)
        """
        webhook_url = config.get('webhook_url', os.getenv('SLACK_WEBHOOK_URL', ''))

        if not webhook_url:
            logger.warning("[SLACK] Not configured (no webhook_url)")
            return False

        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title[:150]}
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": message[:3000]}
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn",
                         "text": f"🌊 TSUNAMI SOC | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"}
                    ]
                }
            ]
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = Request(webhook_url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')

            with urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    logger.info(f"[SLACK] Sent: {title}")
                    return True
                else:
                    raise Exception(f"HTTP {resp.status}")

        except Exception as e:
            logger.error(f"[SLACK] Send failed: {e}")
            raise


class TelegramSender:
    """Send notifications via Telegram Bot API."""

    @staticmethod
    def send(config: Dict[str, Any], title: str, message: str) -> bool:
        """
        Config keys: bot_token, chat_id
        """
        bot_token = config.get('bot_token', os.getenv('TELEGRAM_BOT_TOKEN', ''))
        chat_id = config.get('chat_id', os.getenv('TELEGRAM_CHAT_ID', ''))

        if not bot_token or not chat_id:
            logger.warning("[TELEGRAM] Not configured (missing bot_token or chat_id)")
            return False

        text = f"*{title}*\n\n{message}"
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"

        payload = {
            'chat_id': chat_id,
            'text': text[:4096],
            'parse_mode': 'Markdown',
            'disable_web_page_preview': True,
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')

            with urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                if result.get('ok'):
                    logger.info(f"[TELEGRAM] Sent: {title}")
                    return True
                else:
                    raise Exception(result.get('description', 'Unknown error'))

        except Exception as e:
            logger.error(f"[TELEGRAM] Send failed: {e}")
            raise


class PagerDutySender:
    """Send notifications via PagerDuty Events API v2."""

    SEVERITY_MAP = {
        NotificationPriority.P1_CRITICAL: 'critical',
        NotificationPriority.P2_HIGH: 'error',
        NotificationPriority.P3_MEDIUM: 'warning',
        NotificationPriority.P4_LOW: 'info',
        NotificationPriority.P5_INFO: 'info',
    }

    @staticmethod
    def send(config: Dict[str, Any], title: str, message: str,
             priority: NotificationPriority = NotificationPriority.P2_HIGH,
             dedup_key: str = "") -> bool:
        """
        Config keys: routing_key (integration key)
        """
        routing_key = config.get('routing_key', os.getenv('PAGERDUTY_ROUTING_KEY', ''))

        if not routing_key:
            logger.warning("[PAGERDUTY] Not configured (no routing_key)")
            return False

        severity = PagerDutySender.SEVERITY_MAP.get(priority, 'warning')

        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key or hashlib.md5(title.encode()).hexdigest(),
            "payload": {
                "summary": title[:1024],
                "severity": severity,
                "source": "TSUNAMI SOC",
                "component": "alert_queue",
                "custom_details": {
                    "message": message[:2000],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            }
        }

        try:
            url = "https://events.pagerduty.com/v2/enqueue"
            data = json.dumps(payload).encode('utf-8')
            req = Request(url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')

            with urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                if result.get('status') == 'success':
                    logger.info(f"[PAGERDUTY] Triggered: {title}")
                    return True
                else:
                    raise Exception(result.get('message', 'Unknown error'))

        except Exception as e:
            logger.error(f"[PAGERDUTY] Send failed: {e}")
            raise


class TeamsSender:
    """Send notifications via Microsoft Teams Webhook."""

    @staticmethod
    def send(config: Dict[str, Any], title: str, message: str) -> bool:
        """
        Config keys: webhook_url
        """
        webhook_url = config.get('webhook_url', os.getenv('TEAMS_WEBHOOK_URL', ''))

        if not webhook_url:
            logger.warning("[TEAMS] Not configured (no webhook_url)")
            return False

        # Adaptive Card format
        payload = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": title,
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Attention",
                        },
                        {
                            "type": "TextBlock",
                            "text": message[:2000],
                            "wrap": True,
                            "fontType": "Monospace",
                            "size": "Small",
                        },
                        {
                            "type": "TextBlock",
                            "text": f"🌊 TSUNAMI SOC | {datetime.now(timezone.utc).strftime('%H:%M UTC')}",
                            "size": "Small",
                            "isSubtle": True,
                        }
                    ]
                }
            }]
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = Request(webhook_url, data=data, method='POST')
            req.add_header('Content-Type', 'application/json')

            with urlopen(req, timeout=10) as resp:
                if resp.status in (200, 202):
                    logger.info(f"[TEAMS] Sent: {title}")
                    return True
                else:
                    raise Exception(f"HTTP {resp.status}")

        except Exception as e:
            logger.error(f"[TEAMS] Send failed: {e}")
            raise


class WebhookSender:
    """Send notifications via generic HTTP webhook."""

    @staticmethod
    def send(config: Dict[str, Any], title: str, message: str,
             metadata: Optional[Dict] = None) -> bool:
        """
        Config keys: url, headers (dict), method (POST/PUT)
        """
        url = config.get('url', '')
        headers = config.get('headers', {})
        method = config.get('method', 'POST')

        if not url:
            logger.warning("[WEBHOOK] Not configured (no url)")
            return False

        payload = {
            'title': title,
            'message': message,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'source': 'TSUNAMI SOC',
            'metadata': metadata or {},
        }

        try:
            data = json.dumps(payload).encode('utf-8')
            req = Request(url, data=data, method=method)
            req.add_header('Content-Type', 'application/json')
            for k, v in headers.items():
                req.add_header(k, v)

            with urlopen(req, timeout=15) as resp:
                if resp.status < 300:
                    logger.info(f"[WEBHOOK] Sent to {url}: {title}")
                    return True
                else:
                    raise Exception(f"HTTP {resp.status}")

        except Exception as e:
            logger.error(f"[WEBHOOK] Send failed: {e}")
            raise


# ============================================================================
# Rate Limiter
# ============================================================================

class RateLimiter:
    """Token bucket rate limiter for notification channels."""

    def __init__(self):
        self._counters: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, channel: str, per_minute: int = 30, per_hour: int = 200) -> bool:
        """Check if sending is allowed under rate limits."""
        now = time.time()

        with self._lock:
            if channel not in self._counters:
                self._counters[channel] = []

            # Clean old entries
            self._counters[channel] = [
                t for t in self._counters[channel]
                if now - t < 3600
            ]

            timestamps = self._counters[channel]

            # Check per-minute
            recent_minute = sum(1 for t in timestamps if now - t < 60)
            if recent_minute >= per_minute:
                return False

            # Check per-hour
            if len(timestamps) >= per_hour:
                return False

            # Record
            self._counters[channel].append(now)
            return True

    def get_counts(self) -> Dict[str, Dict[str, int]]:
        """Get current rate limit counters."""
        now = time.time()
        result = {}
        with self._lock:
            for ch, timestamps in self._counters.items():
                minute_count = sum(1 for t in timestamps if now - t < 60)
                hour_count = sum(1 for t in timestamps if now - t < 3600)
                result[ch] = {'per_minute': minute_count, 'per_hour': hour_count}
        return result


# ============================================================================
# Notification Engine
# ============================================================================

class NotificationEngine:
    """
    Central notification engine managing all channels,
    routing, rate limiting, and delivery.
    """

    SENDERS = {
        NotificationChannel.EMAIL: EmailSender,
        NotificationChannel.SLACK: SlackSender,
        NotificationChannel.TELEGRAM: TelegramSender,
        NotificationChannel.PAGERDUTY: PagerDutySender,
        NotificationChannel.TEAMS: TeamsSender,
        NotificationChannel.WEBHOOK: WebhookSender,
    }

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            db_dir = Path.home() / '.dalga'
            db_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(db_dir / 'soc_notifications.db')

        self.db_path = db_path
        self._channels: Dict[NotificationChannel, ChannelConfig] = {}
        self._routing = dict(DEFAULT_ROUTING)
        self._rate_limiter = RateLimiter()
        self._template_engine = TemplateEngine()
        self._lock = threading.Lock()
        self._digest_buffer: List[Dict[str, Any]] = []
        self._retry_thread: Optional[threading.Thread] = None
        self._running = False

        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        conn = self._get_conn()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS notification_log (
                    notification_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    message TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    channel TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    retry_count INTEGER DEFAULT 0,
                    error TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    sent_at TEXT,
                    metadata TEXT DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_notif_status ON notification_log(status);
                CREATE INDEX IF NOT EXISTS idx_notif_created ON notification_log(created_at);
                CREATE INDEX IF NOT EXISTS idx_notif_channel ON notification_log(channel);
            """)
            conn.commit()
        finally:
            conn.close()

    # ---- Channel Configuration ----

    def configure_channel(self, channel: NotificationChannel, config: Dict[str, Any],
                          enabled: bool = True, rate_limit_per_minute: int = 30,
                          rate_limit_per_hour: int = 200):
        """Configure a notification channel."""
        self._channels[channel] = ChannelConfig(
            channel=channel,
            enabled=enabled,
            config=config,
            rate_limit_per_minute=rate_limit_per_minute,
            rate_limit_per_hour=rate_limit_per_hour,
        )
        logger.info(f"[NOTIFY] Channel configured: {channel.value} (enabled={enabled})")

    def set_routing(self, priority: NotificationPriority,
                    channels: Set[NotificationChannel]):
        """Override routing for a priority level."""
        self._routing[priority] = channels

    def is_channel_configured(self, channel: NotificationChannel) -> bool:
        """Check if a channel is configured and enabled."""
        cfg = self._channels.get(channel)
        return cfg is not None and cfg.enabled

    # ---- Core Send ----

    def notify(self, template_name: str, variables: Dict[str, Any],
               priority: NotificationPriority = NotificationPriority.P3_MEDIUM,
               channels: Optional[Set[NotificationChannel]] = None,
               force: bool = False) -> List[Notification]:
        """
        Send notification using template and routing rules.

        Args:
            template_name: Template to use (e.g., 'alert_new', 'sla_breach')
            variables: Template variables
            priority: Notification priority (determines routing if channels not specified)
            channels: Override auto-routing, send to specific channels
            force: Bypass rate limiting

        Returns:
            List of Notification results
        """
        title, message = self._template_engine.render(template_name, variables)

        # Determine target channels
        target_channels = channels or self._routing.get(priority, set())

        results = []
        for channel in target_channels:
            notif = self._send_to_channel(channel, title, message, priority, force)
            results.append(notif)

        return results

    def send_raw(self, channel: NotificationChannel, title: str, message: str,
                 priority: NotificationPriority = NotificationPriority.P3_MEDIUM,
                 force: bool = False) -> Notification:
        """Send a raw (non-templated) notification to a specific channel."""
        return self._send_to_channel(channel, title, message, priority, force)

    def _send_to_channel(self, channel: NotificationChannel, title: str, message: str,
                         priority: NotificationPriority,
                         force: bool = False) -> Notification:
        """Send to a single channel with rate limiting and retry."""
        notif = Notification(
            notification_id=f"notif_{uuid.uuid4().hex[:16]}",
            title=title,
            message=message,
            priority=priority,
            channel=channel,
        )

        # Check if channel is configured
        cfg = self._channels.get(channel)
        if not cfg or not cfg.enabled:
            notif.status = NotificationStatus.SUPPRESSED
            notif.error = f"Channel {channel.value} not configured or disabled"
            self._log_notification(notif)
            return notif

        # Rate limiting
        if not force and not self._rate_limiter.is_allowed(
            channel.value, cfg.rate_limit_per_minute, cfg.rate_limit_per_hour
        ):
            notif.status = NotificationStatus.SUPPRESSED
            notif.error = "Rate limited"
            self._log_notification(notif)
            logger.warning(f"[NOTIFY] Rate limited: {channel.value}")
            return notif

        # Send
        try:
            sender_class = self.SENDERS.get(channel)
            if not sender_class:
                raise ValueError(f"No sender for channel: {channel.value}")

            if channel == NotificationChannel.PAGERDUTY:
                sender_class.send(cfg.config, title, message, priority)
            else:
                sender_class.send(cfg.config, title, message)

            notif.status = NotificationStatus.SENT
            notif.sent_at = datetime.now(timezone.utc)

        except Exception as e:
            notif.status = NotificationStatus.FAILED
            notif.error = str(e)[:500]
            logger.error(f"[NOTIFY] Failed {channel.value}: {e}")

        self._log_notification(notif)
        return notif

    def _log_notification(self, notif: Notification):
        """Log notification to database."""
        try:
            conn = self._get_conn()
            conn.execute(
                """INSERT OR REPLACE INTO notification_log
                   (notification_id, title, message, priority, channel, status,
                    retry_count, error, created_at, sent_at, metadata)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (notif.notification_id, notif.title, notif.message[:1000],
                 notif.priority.name, notif.channel.value, notif.status.value,
                 notif.retry_count, notif.error,
                 notif.created_at.isoformat(),
                 notif.sent_at.isoformat() if notif.sent_at else None,
                 json.dumps(notif.metadata))
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"[NOTIFY] Log error: {e}")

    # ---- Digest Mode ----

    def add_to_digest(self, variables: Dict[str, Any]):
        """Add an item to the digest buffer for batched sending."""
        with self._lock:
            self._digest_buffer.append({
                **variables,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })

    def send_digest(self, channels: Optional[Set[NotificationChannel]] = None) -> List[Notification]:
        """Send accumulated digest as a single notification."""
        with self._lock:
            if not self._digest_buffer:
                return []
            items = list(self._digest_buffer)
            self._digest_buffer.clear()

        # Summarize
        variables = {
            'new_count': len(items),
            'resolved_count': sum(1 for i in items if i.get('status') == 'resolved'),
            'critical_count': sum(1 for i in items if i.get('severity') == 'CRITICAL'),
            'sla_breach_count': sum(1 for i in items if i.get('sla_breached')),
            'mttd': 'N/A',
            'mttr': 'N/A',
            'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        }

        return self.notify('digest', variables,
                          priority=NotificationPriority.P4_LOW,
                          channels=channels)

    # ---- Retry Engine ----

    def start_retry_engine(self):
        """Start background retry thread for failed notifications."""
        if self._running:
            return
        self._running = True
        self._retry_thread = threading.Thread(target=self._retry_loop, daemon=True)
        self._retry_thread.start()
        logger.info("[NOTIFY] Retry engine started")

    def stop_retry_engine(self):
        self._running = False
        if self._retry_thread:
            self._retry_thread.join(timeout=5)

    def _retry_loop(self):
        """Retry failed notifications with exponential backoff."""
        while self._running:
            try:
                conn = self._get_conn()
                rows = conn.execute(
                    """SELECT * FROM notification_log
                       WHERE status = 'failed' AND retry_count < 3
                       ORDER BY created_at LIMIT 10"""
                ).fetchall()
                conn.close()

                for row in rows:
                    channel = NotificationChannel(row['channel'])
                    cfg = self._channels.get(channel)
                    if not cfg or not cfg.enabled:
                        continue

                    # Exponential backoff
                    retry = row['retry_count']
                    backoff_seconds = (2 ** retry) * 30  # 30s, 60s, 120s
                    created = datetime.fromisoformat(row['created_at'])
                    if (datetime.now(timezone.utc) - created).total_seconds() < backoff_seconds:
                        continue

                    try:
                        sender_class = self.SENDERS.get(channel)
                        if sender_class:
                            sender_class.send(cfg.config, row['title'], row['message'])

                            conn2 = self._get_conn()
                            conn2.execute(
                                """UPDATE notification_log
                                   SET status = 'sent', sent_at = ?, retry_count = ?
                                   WHERE notification_id = ?""",
                                (datetime.now(timezone.utc).isoformat(),
                                 retry + 1, row['notification_id'])
                            )
                            conn2.commit()
                            conn2.close()
                            logger.info(f"[NOTIFY] Retry success: {row['notification_id']}")

                    except Exception as e:
                        conn2 = self._get_conn()
                        conn2.execute(
                            """UPDATE notification_log
                               SET retry_count = ?, error = ?
                               WHERE notification_id = ?""",
                            (retry + 1, str(e)[:500], row['notification_id'])
                        )
                        conn2.commit()
                        conn2.close()

            except Exception as e:
                logger.error(f"[NOTIFY] Retry loop error: {e}")

            time.sleep(30)

    # ---- Statistics ----

    def get_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get notification statistics."""
        try:
            conn = self._get_conn()
            since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

            total = conn.execute(
                "SELECT COUNT(*) FROM notification_log WHERE created_at >= ?", (since,)
            ).fetchone()[0]

            by_status = {}
            for status in NotificationStatus:
                cnt = conn.execute(
                    "SELECT COUNT(*) FROM notification_log WHERE status = ? AND created_at >= ?",
                    (status.value, since)
                ).fetchone()[0]
                by_status[status.value] = cnt

            by_channel = {}
            for ch in NotificationChannel:
                cnt = conn.execute(
                    "SELECT COUNT(*) FROM notification_log WHERE channel = ? AND created_at >= ?",
                    (ch.value, since)
                ).fetchone()[0]
                by_channel[ch.value] = cnt

            conn.close()

            rate_limits = self._rate_limiter.get_counts()

            return {
                'total': total,
                'by_status': by_status,
                'by_channel': by_channel,
                'rate_limits': rate_limits,
                'configured_channels': [
                    ch.value for ch, cfg in self._channels.items() if cfg.enabled
                ],
            }
        except sqlite3.OperationalError:
            return {'total': 0, 'by_status': {}, 'by_channel': {},
                    'rate_limits': {}, 'configured_channels': []}

    def get_history(self, limit: int = 50, channel: Optional[str] = None,
                    status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get notification history."""
        try:
            conn = self._get_conn()
            query = "SELECT * FROM notification_log WHERE 1=1"
            params = []

            if channel:
                query += " AND channel = ?"
                params.append(channel)
            if status:
                query += " AND status = ?"
                params.append(status)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            conn.close()

            return [dict(r) for r in rows]
        except sqlite3.OperationalError:
            return []


# ============================================================================
# Flask Blueprint
# ============================================================================

def create_notification_blueprint(engine: Optional[NotificationEngine] = None):
    """Create Flask Blueprint for notification API."""
    try:
        from flask import Blueprint, jsonify, request
    except ImportError:
        return None

    if engine is None:
        engine = NotificationEngine()

    bp = Blueprint('soc_notifications', __name__, url_prefix='/api/v1/soc/notifications')

    @bp.route('/send', methods=['POST'])
    def send_notification():
        """Send a notification."""
        data = request.get_json(force=True)
        template = data.get('template', 'alert_new')
        variables = data.get('variables', {})
        priority_str = data.get('priority', 'P3_MEDIUM')

        try:
            priority = NotificationPriority[priority_str]
        except KeyError:
            return jsonify({'success': False, 'error': 'Gecersiz oncelik'}), 400

        channels = None
        if 'channels' in data:
            channels = set()
            for ch_name in data['channels']:
                try:
                    channels.add(NotificationChannel(ch_name))
                except ValueError:
                    pass

        results = engine.notify(template, variables, priority, channels)
        return jsonify({
            'success': True,
            'notifications': [n.to_dict() for n in results],
        })

    @bp.route('/stats', methods=['GET'])
    def notification_stats():
        """Get notification statistics."""
        hours = request.args.get('hours', 24, type=int)
        return jsonify({'success': True, 'data': engine.get_stats(hours)})

    @bp.route('/history', methods=['GET'])
    def notification_history():
        """Get notification history."""
        limit = min(request.args.get('limit', 50, type=int), 200)
        channel = request.args.get('channel')
        status = request.args.get('status')
        return jsonify({'success': True, 'data': engine.get_history(limit, channel, status)})

    @bp.route('/channels', methods=['GET'])
    def list_channels():
        """List configured channels."""
        channels = []
        for ch in NotificationChannel:
            cfg = engine._channels.get(ch)
            channels.append({
                'channel': ch.value,
                'enabled': cfg.enabled if cfg else False,
                'configured': cfg is not None,
            })
        return jsonify({'success': True, 'data': channels})

    @bp.route('/test/<channel_name>', methods=['POST'])
    def test_channel(channel_name):
        """Send a test notification to a channel."""
        try:
            channel = NotificationChannel(channel_name)
        except ValueError:
            return jsonify({'success': False, 'error': 'Gecersiz kanal'}), 400

        result = engine.send_raw(
            channel, '🧪 TSUNAMI SOC Test',
            'Bu bir test bildirimidir. Bildirim sistemi çalışıyor.',
            force=True,
        )
        return jsonify({'success': True, 'notification': result.to_dict()})

    @bp.route('/digest', methods=['POST'])
    def send_digest():
        """Send accumulated digest."""
        results = engine.send_digest()
        return jsonify({
            'success': True,
            'notifications': [n.to_dict() for n in results],
        })

    return bp


# ============================================================================
# Global Instance
# ============================================================================

_notification_engine: Optional[NotificationEngine] = None
_ne_lock = threading.Lock()


def get_notification_engine() -> NotificationEngine:
    global _notification_engine
    if _notification_engine is None:
        with _ne_lock:
            if _notification_engine is None:
                _notification_engine = NotificationEngine()
    return _notification_engine


__all__ = [
    'NotificationChannel', 'NotificationPriority', 'NotificationStatus',
    'ChannelConfig', 'Notification', 'TemplateEngine',
    'EmailSender', 'SlackSender', 'TelegramSender',
    'PagerDutySender', 'TeamsSender', 'WebhookSender',
    'RateLimiter', 'NotificationEngine',
    'create_notification_blueprint', 'get_notification_engine',
]
