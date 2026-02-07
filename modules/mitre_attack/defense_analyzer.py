#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    MITRE D3FEND Defense Analyzer
    Defense Coverage Analysis and Gap Detection
================================================================================

    Features:
    - D3FEND framework integration
    - Defense-to-technique mapping
    - Gap analysis for detected techniques
    - Mitigation recommendations
    - Defense coverage scoring

    Data Source:
    - https://d3fend.mitre.org/ontologies/d3fend.json

================================================================================
"""

import os
import json
import hashlib
import threading
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import urllib.request
import urllib.error

from .attack_data import (
    MITREAttackData, Technique, Mitigation, get_attack_data,
    CACHE_DIR, D3FEND_DATA_URL
)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DefenseCategory(Enum):
    """D3FEND defense categories"""
    HARDEN = "Harden"
    DETECT = "Detect"
    ISOLATE = "Isolate"
    DECEIVE = "Deceive"
    EVICT = "Evict"


class DefensePriority(Enum):
    """Defense implementation priority"""
    CRITICAL = "critical"  # Must implement
    HIGH = "high"          # Should implement
    MEDIUM = "medium"      # Consider implementing
    LOW = "low"            # Optional
    INFO = "info"          # Informational


@dataclass
class Defense:
    """D3FEND defensive technique"""
    id: str  # D3-xxx
    name: str
    description: str
    category: DefenseCategory
    subcategory: str = ""
    techniques_countered: List[str] = field(default_factory=list)  # ATT&CK technique IDs
    digital_artifacts: List[str] = field(default_factory=list)
    implementation_notes: str = ""
    kb_url: str = ""

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description[:500] if self.description else "",
            'category': self.category.value,
            'subcategory': self.subcategory,
            'techniques_countered': self.techniques_countered,
            'digital_artifacts': self.digital_artifacts,
            'implementation_notes': self.implementation_notes,
            'kb_url': self.kb_url
        }


@dataclass
class DefenseCoverage:
    """Defense coverage analysis for a technique"""
    technique_id: str
    technique_name: str
    defenses: List[Defense] = field(default_factory=list)
    mitigations: List[Mitigation] = field(default_factory=list)
    coverage_score: float = 0.0  # 0.0 - 1.0
    gaps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'defenses': [d.to_dict() for d in self.defenses],
            'mitigations': [m.to_dict() for m in self.mitigations],
            'coverage_score': self.coverage_score,
            'gaps': self.gaps,
            'is_covered': self.coverage_score >= 0.5
        }


@dataclass
class DefenseGap:
    """Identified defense gap"""
    technique_id: str
    technique_name: str
    tactics: List[str]
    gap_type: str  # "no_defense", "partial_defense", "detection_only"
    severity: DefensePriority
    affected_platforms: List[str]
    recommended_defenses: List[str]
    recommended_mitigations: List[str]

    def to_dict(self) -> Dict:
        return {
            'technique_id': self.technique_id,
            'technique_name': self.technique_name,
            'tactics': self.tactics,
            'gap_type': self.gap_type,
            'severity': self.severity.value,
            'affected_platforms': self.affected_platforms,
            'recommended_defenses': self.recommended_defenses,
            'recommended_mitigations': self.recommended_mitigations
        }


@dataclass
class MitigationRecommendation:
    """Recommended mitigation action"""
    priority: DefensePriority
    mitigation_id: str
    mitigation_name: str
    description: str
    techniques_addressed: List[str]
    implementation_steps: List[str] = field(default_factory=list)
    estimated_effort: str = "medium"  # low, medium, high

    def to_dict(self) -> Dict:
        return {
            'priority': self.priority.value,
            'mitigation_id': self.mitigation_id,
            'mitigation_name': self.mitigation_name,
            'description': self.description[:500] if self.description else "",
            'techniques_addressed': self.techniques_addressed,
            'implementation_steps': self.implementation_steps,
            'estimated_effort': self.estimated_effort
        }


class DefenseAnalyzer:
    """
    Analyzes defense coverage against ATT&CK techniques

    Integrates D3FEND framework and ATT&CK mitigations to identify
    defense gaps and recommend improvements.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> 'DefenseAnalyzer':
        """Get singleton instance"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._attack_data: Optional[MITREAttackData] = None
        self._defenses: Dict[str, Defense] = {}
        self._defense_by_technique: Dict[str, List[str]] = {}  # technique_id -> [defense_ids]
        self._technique_by_defense: Dict[str, List[str]] = {}  # defense_id -> [technique_ids]
        self._d3fend_loaded: bool = False

        # Built-in D3FEND mappings (subset - full data from API)
        self._init_builtin_defenses()

        logger.info("[DEFENSE-ANALYZER] Analyzer initialized")

    def _init_builtin_defenses(self):
        """Initialize built-in D3FEND defensive techniques"""
        # These are core D3FEND techniques with ATT&CK mappings

        # Harden Category
        self._add_defense(Defense(
            id='D3-ACH',
            name='Application Configuration Hardening',
            description='Configuring application settings to reduce the attack surface',
            category=DefenseCategory.HARDEN,
            subcategory='Application Hardening',
            techniques_countered=['T1059', 'T1059.001', 'T1059.003', 'T1059.005', 'T1059.007'],
            implementation_notes='Disable unnecessary features, enforce secure defaults'
        ))

        self._add_defense(Defense(
            id='D3-ANET',
            name='Authentication Network Segmentation',
            description='Segmenting authentication services on the network',
            category=DefenseCategory.HARDEN,
            subcategory='Network Isolation',
            techniques_countered=['T1021', 'T1021.001', 'T1021.002', 'T1021.004', 'T1021.006'],
            implementation_notes='Isolate domain controllers, limit lateral movement'
        ))

        self._add_defense(Defense(
            id='D3-ANCI',
            name='Application Whitelisting',
            description='Restricting execution to approved applications only',
            category=DefenseCategory.HARDEN,
            subcategory='Execution Restriction',
            techniques_countered=['T1059', 'T1218', 'T1204', 'T1106', 'T1053'],
            implementation_notes='Use AppLocker, WDAC, or SELinux policies'
        ))

        self._add_defense(Defense(
            id='D3-CBAN',
            name='Credential Based Access Denial',
            description='Denying access based on credential characteristics',
            category=DefenseCategory.HARDEN,
            subcategory='Credential Hardening',
            techniques_countered=['T1078', 'T1110', 'T1003', 'T1558'],
            implementation_notes='Implement MFA, conditional access policies'
        ))

        self._add_defense(Defense(
            id='D3-PSMD',
            name='Platform Security Monitoring Detection',
            description='Monitoring platform security events for threats',
            category=DefenseCategory.DETECT,
            subcategory='Platform Monitoring',
            techniques_countered=['T1055', 'T1574', 'T1547', 'T1543'],
            implementation_notes='Enable EDR, monitor process creation, DLL loading'
        ))

        # Detect Category
        self._add_defense(Defense(
            id='D3-NTA',
            name='Network Traffic Analysis',
            description='Analyzing network traffic for suspicious patterns',
            category=DefenseCategory.DETECT,
            subcategory='Network Analysis',
            techniques_countered=['T1071', 'T1090', 'T1572', 'T1573', 'T1008'],
            implementation_notes='Deploy NDR, analyze DNS, TLS, and protocol anomalies'
        ))

        self._add_defense(Defense(
            id='D3-PA',
            name='Process Analysis',
            description='Analyzing process behavior for malicious activity',
            category=DefenseCategory.DETECT,
            subcategory='Process Monitoring',
            techniques_countered=['T1055', 'T1059', 'T1106', 'T1204', 'T1027'],
            implementation_notes='Monitor process trees, command lines, parent-child relationships'
        ))

        self._add_defense(Defense(
            id='D3-FA',
            name='File Analysis',
            description='Analyzing files for malicious content or behavior',
            category=DefenseCategory.DETECT,
            subcategory='File Monitoring',
            techniques_countered=['T1027', 'T1036', 'T1105', 'T1204.002'],
            implementation_notes='Scan files with AV, analyze entropy, verify signatures'
        ))

        self._add_defense(Defense(
            id='D3-UAM',
            name='User Account Monitoring',
            description='Monitoring user account activity for anomalies',
            category=DefenseCategory.DETECT,
            subcategory='User Behavior',
            techniques_countered=['T1078', 'T1087', 'T1136', 'T1098'],
            implementation_notes='Track logons, privilege use, account modifications'
        ))

        self._add_defense(Defense(
            id='D3-SDM',
            name='System Daemon Monitoring',
            description='Monitoring system services and daemons',
            category=DefenseCategory.DETECT,
            subcategory='System Monitoring',
            techniques_countered=['T1543.003', 'T1569.002', 'T1053'],
            implementation_notes='Monitor service creation, modification, suspicious service behavior'
        ))

        # Isolate Category
        self._add_defense(Defense(
            id='D3-EH',
            name='Execution Isolation',
            description='Running code in isolated environments',
            category=DefenseCategory.ISOLATE,
            subcategory='Execution Isolation',
            techniques_countered=['T1059', 'T1204', 'T1203', 'T1027'],
            implementation_notes='Use sandboxes, containers, VMs for untrusted code'
        ))

        self._add_defense(Defense(
            id='D3-NI',
            name='Network Isolation',
            description='Isolating network segments to contain threats',
            category=DefenseCategory.ISOLATE,
            subcategory='Network Isolation',
            techniques_countered=['T1021', 'T1210', 'T1071'],
            implementation_notes='Implement VLANs, microsegmentation, firewalls'
        ))

        self._add_defense(Defense(
            id='D3-BA',
            name='Browser Activity Isolation',
            description='Isolating browser activity from the system',
            category=DefenseCategory.ISOLATE,
            subcategory='Browser Isolation',
            techniques_countered=['T1189', 'T1566.002', 'T1204.001'],
            implementation_notes='Use remote browser isolation, containerized browsers'
        ))

        # Deceive Category
        self._add_defense(Defense(
            id='D3-DEN',
            name='Decoy Environment',
            description='Creating decoy systems to detect and divert attackers',
            category=DefenseCategory.DECEIVE,
            subcategory='Deception',
            techniques_countered=['T1018', 'T1046', 'T1135', 'T1210'],
            implementation_notes='Deploy honeypots, honeytokens, decoy credentials'
        ))

        self._add_defense(Defense(
            id='D3-DCF',
            name='Decoy File',
            description='Creating decoy files to detect unauthorized access',
            category=DefenseCategory.DECEIVE,
            subcategory='Deception',
            techniques_countered=['T1083', 'T1005', 'T1039', 'T1119'],
            implementation_notes='Place canary files in sensitive directories'
        ))

        self._add_defense(Defense(
            id='D3-DCA',
            name='Decoy Account',
            description='Creating decoy accounts to detect credential attacks',
            category=DefenseCategory.DECEIVE,
            subcategory='Deception',
            techniques_countered=['T1078', 'T1110', 'T1087'],
            implementation_notes='Create honeypot accounts, monitor for any usage'
        ))

        # Evict Category
        self._add_defense(Defense(
            id='D3-PT',
            name='Process Termination',
            description='Terminating malicious processes',
            category=DefenseCategory.EVICT,
            subcategory='Process Eviction',
            techniques_countered=['T1059', 'T1055', 'T1106'],
            implementation_notes='EDR process kill, automated response'
        ))

        self._add_defense(Defense(
            id='D3-QF',
            name='File Quarantine',
            description='Quarantining malicious files',
            category=DefenseCategory.EVICT,
            subcategory='File Eviction',
            techniques_countered=['T1027', 'T1105', 'T1204'],
            implementation_notes='AV quarantine, automated file removal'
        ))

        self._add_defense(Defense(
            id='D3-AC',
            name='Account Credential Revocation',
            description='Revoking compromised credentials',
            category=DefenseCategory.EVICT,
            subcategory='Credential Eviction',
            techniques_countered=['T1078', 'T1003', 'T1558'],
            implementation_notes='Password reset, token revocation, session termination'
        ))

    def _add_defense(self, defense: Defense):
        """Add a defense and update indexes"""
        self._defenses[defense.id] = defense
        self._technique_by_defense[defense.id] = defense.techniques_countered

        for tech_id in defense.techniques_countered:
            if tech_id not in self._defense_by_technique:
                self._defense_by_technique[tech_id] = []
            if defense.id not in self._defense_by_technique[tech_id]:
                self._defense_by_technique[tech_id].append(defense.id)

    def load_d3fend_data(self, force_refresh: bool = False) -> bool:
        """
        Load D3FEND data from cache or download

        Note: D3FEND API may have rate limits. Built-in mappings are used as fallback.
        """
        cache_file = CACHE_DIR / "d3fend.json"
        cache_meta = CACHE_DIR / "d3fend.meta.json"

        # Check cache
        use_cache = False
        if not force_refresh and cache_file.exists() and cache_meta.exists():
            try:
                with open(cache_meta, 'r') as f:
                    meta = json.load(f)
                cache_time = datetime.fromisoformat(meta.get('downloaded', '2000-01-01'))
                if datetime.now() - cache_time < timedelta(hours=24):
                    use_cache = True
            except Exception:
                pass

        if not use_cache:
            if not self._download_d3fend(cache_file, cache_meta):
                logger.warning("[DEFENSE-ANALYZER] Using built-in D3FEND data")
                return False

        # Parse D3FEND data
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                d3fend_data = json.load(f)
            self._parse_d3fend(d3fend_data)
            self._d3fend_loaded = True
            return True
        except Exception as e:
            logger.error(f"[DEFENSE-ANALYZER] D3FEND parse error: {e}")
            return False

    def _download_d3fend(self, cache_file: Path, cache_meta: Path) -> bool:
        """Download D3FEND data"""
        logger.info(f"[DEFENSE-ANALYZER] Downloading D3FEND from {D3FEND_DATA_URL}")

        try:
            req = urllib.request.Request(
                D3FEND_DATA_URL,
                headers={
                    'User-Agent': 'TSUNAMI-D3FEND-Integration/5.0',
                    'Accept': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=60) as response:
                data = response.read()

            # Validate JSON
            json.loads(data)

            with open(cache_file, 'wb') as f:
                f.write(data)

            meta = {
                'downloaded': datetime.now().isoformat(),
                'url': D3FEND_DATA_URL,
                'size': len(data)
            }
            with open(cache_meta, 'w') as f:
                json.dump(meta, f)

            return True
        except Exception as e:
            logger.error(f"[DEFENSE-ANALYZER] D3FEND download failed: {e}")
            return False

    def _parse_d3fend(self, data: Dict):
        """Parse D3FEND JSON-LD ontology data"""
        # D3FEND data is in OWL/JSON-LD format
        # Extract defensive techniques and their ATT&CK mappings

        if '@graph' not in data:
            logger.warning("[DEFENSE-ANALYZER] No @graph in D3FEND data")
            return

        for node in data.get('@graph', []):
            node_type = node.get('@type', [])
            if isinstance(node_type, str):
                node_type = [node_type]

            # Look for defensive technique classes
            if any('DefensiveTechnique' in t for t in node_type):
                node_id = node.get('@id', '')
                if node_id.startswith('d3f:'):
                    defense_id = node_id.replace('d3f:', 'D3-')

                    # Skip if already have built-in
                    if defense_id in self._defenses:
                        continue

                    name = node.get('rdfs:label', node_id)
                    if isinstance(name, dict):
                        name = name.get('@value', node_id)

                    description = node.get('rdfs:comment', '')
                    if isinstance(description, dict):
                        description = description.get('@value', '')

                    # Determine category from type
                    category = DefenseCategory.DETECT
                    for t in node_type:
                        if 'Harden' in t:
                            category = DefenseCategory.HARDEN
                        elif 'Isolate' in t:
                            category = DefenseCategory.ISOLATE
                        elif 'Deceive' in t:
                            category = DefenseCategory.DECEIVE
                        elif 'Evict' in t:
                            category = DefenseCategory.EVICT

                    # Extract ATT&CK technique references
                    counters = node.get('d3f:counters', [])
                    if isinstance(counters, dict):
                        counters = [counters]

                    technique_ids = []
                    for counter in counters:
                        if isinstance(counter, dict):
                            tech_ref = counter.get('@id', '')
                        else:
                            tech_ref = str(counter)
                        # Extract technique ID
                        if 'attack' in tech_ref.lower():
                            # Parse "attack:T1059" style
                            parts = tech_ref.split(':')
                            if len(parts) >= 2:
                                tech_id = parts[-1].upper()
                                if tech_id.startswith('T'):
                                    technique_ids.append(tech_id)

                    if technique_ids:
                        defense = Defense(
                            id=defense_id,
                            name=name,
                            description=description[:1000],
                            category=category,
                            techniques_countered=technique_ids
                        )
                        self._add_defense(defense)

    def set_attack_data(self, attack_data: MITREAttackData):
        """Set the ATT&CK data source"""
        self._attack_data = attack_data

    def get_defense(self, defense_id: str) -> Optional[Defense]:
        """Get defense by ID"""
        return self._defenses.get(defense_id)

    def list_defenses(self, category: Optional[DefenseCategory] = None) -> List[Defense]:
        """List all defenses, optionally filtered by category"""
        defenses = list(self._defenses.values())
        if category:
            defenses = [d for d in defenses if d.category == category]
        return sorted(defenses, key=lambda d: d.name)

    def get_defenses_for_technique(self, technique_id: str) -> List[Defense]:
        """Get all defenses that counter a technique"""
        defense_ids = self._defense_by_technique.get(technique_id, [])
        return [self._defenses[did] for did in defense_ids if did in self._defenses]

    def analyze_coverage(self, technique_id: str) -> DefenseCoverage:
        """
        Analyze defense coverage for a specific technique

        Args:
            technique_id: ATT&CK technique ID

        Returns:
            DefenseCoverage with defenses, mitigations, and gaps
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        technique = self._attack_data.get_technique(technique_id)
        if not technique:
            return DefenseCoverage(
                technique_id=technique_id,
                technique_name='Unknown',
                coverage_score=0.0,
                gaps=['Technique not found in ATT&CK data']
            )

        # Get defenses
        defenses = self.get_defenses_for_technique(technique_id)

        # Get mitigations from ATT&CK
        mitigations = self._attack_data.get_mitigations_for_technique(technique_id)

        # Calculate coverage score
        # Weights: D3FEND defense = 0.5, ATT&CK mitigation = 0.5
        defense_score = min(len(defenses) * 0.2, 0.5)  # Max 0.5 from defenses
        mitigation_score = min(len(mitigations) * 0.15, 0.5)  # Max 0.5 from mitigations
        coverage_score = defense_score + mitigation_score

        # Identify gaps
        gaps = []
        if not defenses:
            gaps.append('No D3FEND defensive techniques mapped')
        if not mitigations:
            gaps.append('No ATT&CK mitigations mapped')

        # Check defense categories coverage
        categories_present = set(d.category for d in defenses)
        missing_categories = set(DefenseCategory) - categories_present
        for cat in missing_categories:
            if cat != DefenseCategory.DECEIVE:  # Deception is often optional
                gaps.append(f'No {cat.value} defenses')

        return DefenseCoverage(
            technique_id=technique_id,
            technique_name=technique.name,
            defenses=defenses,
            mitigations=mitigations,
            coverage_score=round(coverage_score, 2),
            gaps=gaps
        )

    def analyze_gaps(self, technique_ids: List[str]) -> List[DefenseGap]:
        """
        Analyze defense gaps across multiple techniques

        Args:
            technique_ids: List of ATT&CK technique IDs to analyze

        Returns:
            List of identified gaps sorted by severity
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        gaps = []

        for tech_id in technique_ids:
            technique = self._attack_data.get_technique(tech_id)
            if not technique:
                continue

            coverage = self.analyze_coverage(tech_id)

            if coverage.coverage_score < 0.3:
                gap_type = 'no_defense'
                severity = DefensePriority.CRITICAL
            elif coverage.coverage_score < 0.5:
                gap_type = 'partial_defense'
                severity = DefensePriority.HIGH
            elif not coverage.defenses and coverage.mitigations:
                gap_type = 'detection_only'
                severity = DefensePriority.MEDIUM
            else:
                continue  # Adequate coverage

            # Get recommended defenses
            all_defenses = list(self._defenses.values())
            recommended_defenses = []
            for defense in all_defenses:
                if tech_id in defense.techniques_countered:
                    continue  # Already mapped
                # Check if defense category is missing
                existing_categories = set(d.category for d in coverage.defenses)
                if defense.category not in existing_categories:
                    # Check if defense targets similar tactics
                    if any(t in technique.tactics for t in ['execution', 'persistence', 'defense-evasion']):
                        if defense.category in [DefenseCategory.DETECT, DefenseCategory.HARDEN]:
                            recommended_defenses.append(defense.name)

            recommended_defenses = recommended_defenses[:5]  # Limit to top 5

            # Get recommended mitigations
            recommended_mitigations = []
            for mit in self._attack_data.list_mitigations():
                if mit.id in [m.id for m in coverage.mitigations]:
                    continue  # Already mapped
                # Simple heuristic: mitigations with techniques in same tactics
                for mit_tech_id in mit.techniques[:5]:
                    mit_tech = self._attack_data.get_technique(mit_tech_id)
                    if mit_tech and any(t in technique.tactics for t in mit_tech.tactics):
                        recommended_mitigations.append(f"{mit.id}: {mit.name}")
                        break

            recommended_mitigations = recommended_mitigations[:3]  # Limit to top 3

            gap = DefenseGap(
                technique_id=tech_id,
                technique_name=technique.name,
                tactics=technique.tactics,
                gap_type=gap_type,
                severity=severity,
                affected_platforms=technique.platforms,
                recommended_defenses=recommended_defenses,
                recommended_mitigations=recommended_mitigations
            )
            gaps.append(gap)

        # Sort by severity
        severity_order = {
            DefensePriority.CRITICAL: 0,
            DefensePriority.HIGH: 1,
            DefensePriority.MEDIUM: 2,
            DefensePriority.LOW: 3,
            DefensePriority.INFO: 4
        }
        gaps.sort(key=lambda g: severity_order.get(g.severity, 5))

        return gaps

    def recommend_mitigations(self, technique_ids: List[str],
                             max_recommendations: int = 10) -> List[MitigationRecommendation]:
        """
        Generate prioritized mitigation recommendations

        Args:
            technique_ids: Techniques to mitigate
            max_recommendations: Maximum number of recommendations

        Returns:
            Prioritized list of mitigation recommendations
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        # Count technique coverage by mitigation
        mitigation_coverage: Dict[str, Set[str]] = {}  # mit_id -> {tech_ids}

        for tech_id in technique_ids:
            mitigations = self._attack_data.get_mitigations_for_technique(tech_id)
            for mit in mitigations:
                if mit.id not in mitigation_coverage:
                    mitigation_coverage[mit.id] = set()
                mitigation_coverage[mit.id].add(tech_id)

        # Build recommendations
        recommendations = []

        for mit_id, covered_techs in mitigation_coverage.items():
            mitigation = self._attack_data.get_mitigation(mit_id)
            if not mitigation:
                continue

            # Determine priority based on coverage
            coverage_ratio = len(covered_techs) / len(technique_ids)
            if coverage_ratio >= 0.5:
                priority = DefensePriority.CRITICAL
            elif coverage_ratio >= 0.3:
                priority = DefensePriority.HIGH
            elif coverage_ratio >= 0.1:
                priority = DefensePriority.MEDIUM
            else:
                priority = DefensePriority.LOW

            # Generate implementation steps from description
            impl_steps = []
            if mitigation.description:
                # Extract action items from description
                sentences = mitigation.description.split('.')
                for sentence in sentences[:5]:
                    sentence = sentence.strip()
                    if any(word in sentence.lower() for word in
                           ['implement', 'use', 'enable', 'configure', 'restrict',
                            'disable', 'deploy', 'monitor', 'ensure']):
                        impl_steps.append(sentence)

            # Estimate effort
            if len(covered_techs) >= 10:
                effort = 'high'  # Complex, many techniques
            elif len(impl_steps) >= 3:
                effort = 'medium'
            else:
                effort = 'low'

            rec = MitigationRecommendation(
                priority=priority,
                mitigation_id=mitigation.id,
                mitigation_name=mitigation.name,
                description=mitigation.description,
                techniques_addressed=list(covered_techs),
                implementation_steps=impl_steps[:5],
                estimated_effort=effort
            )
            recommendations.append(rec)

        # Sort by priority and coverage
        priority_order = {
            DefensePriority.CRITICAL: 0,
            DefensePriority.HIGH: 1,
            DefensePriority.MEDIUM: 2,
            DefensePriority.LOW: 3,
            DefensePriority.INFO: 4
        }
        recommendations.sort(key=lambda r: (
            priority_order.get(r.priority, 5),
            -len(r.techniques_addressed)
        ))

        return recommendations[:max_recommendations]

    def generate_gap_report(self, technique_ids: List[str]) -> Dict[str, Any]:
        """
        Generate comprehensive defense gap analysis report

        Args:
            technique_ids: Techniques to analyze

        Returns:
            Complete gap analysis report
        """
        if not self._attack_data:
            self._attack_data = get_attack_data()

        # Analyze all techniques
        coverages = [self.analyze_coverage(tid) for tid in technique_ids]
        gaps = self.analyze_gaps(technique_ids)
        recommendations = self.recommend_mitigations(technique_ids)

        # Calculate summary statistics
        avg_coverage = sum(c.coverage_score for c in coverages) / len(coverages) if coverages else 0
        fully_covered = sum(1 for c in coverages if c.coverage_score >= 0.7)
        partially_covered = sum(1 for c in coverages if 0.3 <= c.coverage_score < 0.7)
        not_covered = sum(1 for c in coverages if c.coverage_score < 0.3)

        # Group gaps by severity
        gaps_by_severity = {
            'critical': [g for g in gaps if g.severity == DefensePriority.CRITICAL],
            'high': [g for g in gaps if g.severity == DefensePriority.HIGH],
            'medium': [g for g in gaps if g.severity == DefensePriority.MEDIUM],
            'low': [g for g in gaps if g.severity == DefensePriority.LOW]
        }

        # Top missing defenses
        missing_defense_categories: Dict[str, int] = {}
        for coverage in coverages:
            for gap in coverage.gaps:
                missing_defense_categories[gap] = missing_defense_categories.get(gap, 0) + 1

        report = {
            'generated_at': datetime.now().isoformat(),
            'total_techniques_analyzed': len(technique_ids),
            'summary': {
                'average_coverage_score': round(avg_coverage, 2),
                'fully_covered': fully_covered,
                'partially_covered': partially_covered,
                'not_covered': not_covered,
                'total_gaps': len(gaps),
                'critical_gaps': len(gaps_by_severity['critical']),
                'high_gaps': len(gaps_by_severity['high'])
            },
            'coverage_details': [c.to_dict() for c in coverages],
            'gaps_by_severity': {
                severity: [g.to_dict() for g in gap_list]
                for severity, gap_list in gaps_by_severity.items()
            },
            'top_recommendations': [r.to_dict() for r in recommendations],
            'missing_defense_categories': dict(
                sorted(missing_defense_categories.items(), key=lambda x: -x[1])[:10]
            ),
            'defense_categories_used': {
                cat.value: sum(1 for c in coverages for d in c.defenses if d.category == cat)
                for cat in DefenseCategory
            }
        }

        return report

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return {
            'total_defenses': len(self._defenses),
            'd3fend_loaded': self._d3fend_loaded,
            'defense_by_category': {
                cat.value: sum(1 for d in self._defenses.values() if d.category == cat)
                for cat in DefenseCategory
            },
            'technique_mappings': len(self._defense_by_technique),
            'attack_data_loaded': self._attack_data.is_loaded() if self._attack_data else False
        }


# Singleton accessor
def get_defense_analyzer() -> DefenseAnalyzer:
    """Get the global defense analyzer instance"""
    analyzer = DefenseAnalyzer.get_instance()
    if not analyzer._attack_data:
        analyzer.set_attack_data(get_attack_data())
    return analyzer
