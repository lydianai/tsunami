#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI STIX 2.1 / TAXII 2.1 Threat Intelligence Module v5.0
================================================================================

    Real threat intelligence integration with:
    - AlienVault OTX
    - Abuse.ch (URLhaus, MalwareBazaar, ThreatFox)
    - CISA Known Exploited Vulnerabilities
    - MISP Threat Sharing

================================================================================
"""

from .stix_taxii_client import (
    STIXTAXIIClient,
    ThreatFeedConfig,
    get_stix_client
)

from .stix_parser import (
    STIXParser,
    ParsedIndicator,
    ParsedMalware,
    ParsedAttackPattern,
    MITREMapper
)

from .threat_correlator import (
    ThreatCorrelator,
    ThreatAlert,
    CorrelationResult,
    ThreatSeverity,
    AlertStatus,
    get_correlator
)

from .api_routes import threat_intel_bp

__version__ = "5.0.0"
__all__ = [
    # Client
    'STIXTAXIIClient',
    'ThreatFeedConfig',
    'get_stix_client',
    # Parser
    'STIXParser',
    'ParsedIndicator',
    'ParsedMalware',
    'ParsedAttackPattern',
    'MITREMapper',
    # Correlator
    'ThreatCorrelator',
    'ThreatAlert',
    'CorrelationResult',
    'ThreatSeverity',
    'AlertStatus',
    'get_correlator',
    # API
    'threat_intel_bp'
]
