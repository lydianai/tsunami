#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI MITRE ATT&CK Integration Module v5.0
    Enterprise Attack Framework Integration
================================================================================

    Features:
    - Real MITRE ATT&CK v18 Data Integration
    - D3FEND Defensive Framework Integration
    - Technique-to-Event Mapping
    - ATT&CK Navigator Layer Generation
    - Defense Coverage Analysis
    - CVE-to-Technique Correlation

    Data Sources:
    - MITRE ATT&CK Enterprise: https://attack.mitre.org/
    - MITRE D3FEND: https://d3fend.mitre.org/
    - MITRE CTI STIX: https://github.com/mitre/cti

================================================================================
"""

from .attack_data import (
    MITREAttackData,
    Technique,
    Tactic,
    Mitigation,
    Group,
    Software,
    DataSource,
    get_attack_data,
    ATTACK_DATA_URL,
    D3FEND_DATA_URL
)

from .technique_mapper import (
    TechniqueMapper,
    TechniqueMatch,
    EventMapping,
    get_technique_mapper
)

from .defense_analyzer import (
    DefenseAnalyzer,
    DefenseCoverage,
    DefenseGap,
    MitigationRecommendation,
    get_defense_analyzer
)

from .attack_navigator import (
    NavigatorLayer,
    TechniqueScore,
    NavigatorGenerator,
    get_navigator_generator
)

__version__ = "5.0.0"
__author__ = "TSUNAMI Security Team"

__all__ = [
    # Data Module
    'MITREAttackData',
    'Technique',
    'Tactic',
    'Mitigation',
    'Group',
    'Software',
    'DataSource',
    'get_attack_data',
    'ATTACK_DATA_URL',
    'D3FEND_DATA_URL',

    # Mapper Module
    'TechniqueMapper',
    'TechniqueMatch',
    'EventMapping',
    'get_technique_mapper',

    # Defense Module
    'DefenseAnalyzer',
    'DefenseCoverage',
    'DefenseGap',
    'MitigationRecommendation',
    'get_defense_analyzer',

    # Navigator Module
    'NavigatorLayer',
    'TechniqueScore',
    'NavigatorGenerator',
    'get_navigator_generator',
]
