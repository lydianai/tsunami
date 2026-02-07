#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI v5.0 - Dark Web & Deep Web Intelligence Module
    Real-time monitoring of dark web, paste sites, and breach databases
================================================================================

    Components:
    - tor_client: Tor network integration and .onion access
    - paste_monitor: Clearnet paste site monitoring
    - breach_checker: HaveIBeenPwned and breach database integration
    - threat_feed_aggregator: Aggregate multiple threat feeds (abuse.ch, etc.)
    - keyword_monitor: Organization and brand monitoring
    - api_routes: Flask API endpoints

================================================================================
"""

from .tor_client import TorClient, TorCircuitManager
from .paste_monitor import PasteMonitor, PasteSite, PasteResult
from .breach_checker import BreachChecker, BreachResult, PasswordChecker
from .threat_feed_aggregator import ThreatFeedAggregator, ThreatFeed, ThreatIOC
from .keyword_monitor import KeywordMonitor, MonitoringRule, Alert

__version__ = "5.0.0"
__all__ = [
    "TorClient",
    "TorCircuitManager",
    "PasteMonitor",
    "PasteSite",
    "PasteResult",
    "BreachChecker",
    "BreachResult",
    "PasswordChecker",
    "ThreatFeedAggregator",
    "ThreatFeed",
    "ThreatIOC",
    "KeywordMonitor",
    "MonitoringRule",
    "Alert",
]
