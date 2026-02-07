#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Live Threat Intelligence Module v1.0
================================================================================

Real-time cyber threat data aggregation for Turkey and surrounding regions.

Features:
    - Multiple free threat intelligence sources (AbuseIPDB, OTX, GreyNoise, Shodan)
    - 5-minute caching to respect API rate limits
    - GeoJSON format for map visualization
    - Turkish CERT simulation data
    - Mock data fallback for demo/offline use

Usage:
    from modules.threat_intelligence import (
        ThreatIntelligenceManager,
        get_live_threats,
        get_threat_stats,
        get_threats_by_region,
        simulate_attack_data
    )

    # Get live threats
    threats = get_live_threats()

    # Get statistics
    stats = get_threat_stats()

    # Get Turkey-focused threats
    turkey_threats = get_threats_by_region("TR")

    # Simulate attacks for demo
    demo_data = simulate_attack_data(50)

================================================================================
"""

from .live_threats import (
    # Main Manager
    ThreatIntelligenceManager,
    get_threat_intelligence_manager,

    # Convenience functions
    get_live_threats,
    get_threat_stats,
    get_threats_by_region,
    simulate_attack_data,

    # Data classes
    ThreatIndicator,
    ThreatStats,
    GeoLocation,

    # Enums
    ThreatCategory,
    ThreatSeverity,
    ThreatStatus,

    # Sources
    ThreatSource,
    AbuseIPDBSource,
    AlienVaultOTXSource,
    GreyNoiseSource,
    ShodanSource,
    TurkishCERTSource,

    # Mock generator
    MockThreatGenerator,

    # Cache
    ThreatCache,
    CacheEntry
)

__version__ = "1.0.0"
__author__ = "TSUNAMI Team"

__all__ = [
    # Main Manager
    "ThreatIntelligenceManager",
    "get_threat_intelligence_manager",

    # Convenience functions
    "get_live_threats",
    "get_threat_stats",
    "get_threats_by_region",
    "simulate_attack_data",

    # Data classes
    "ThreatIndicator",
    "ThreatStats",
    "GeoLocation",

    # Enums
    "ThreatCategory",
    "ThreatSeverity",
    "ThreatStatus",

    # Sources
    "ThreatSource",
    "AbuseIPDBSource",
    "AlienVaultOTXSource",
    "GreyNoiseSource",
    "ShodanSource",
    "TurkishCERTSource",

    # Mock generator
    "MockThreatGenerator",

    # Cache
    "ThreatCache",
    "CacheEntry"
]
