#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    MITRE ATT&CK Data Module
    Real ATT&CK Enterprise v18 Data Fetching and Parsing
================================================================================

    Downloads and parses REAL ATT&CK STIX 2.1 data from:
    - https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

    Features:
    - Full technique/tactic/mitigation parsing
    - Searchable index with fuzzy matching
    - Local caching with automatic updates
    - Relationship mapping (mitigations, groups, software)

================================================================================
"""

import os
import json
import hashlib
import threading
import re
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
import urllib.request
import urllib.error

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Data URLs
ATTACK_DATA_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
D3FEND_DATA_URL = "https://d3fend.mitre.org/ontologies/d3fend.json"
ATTACK_MOBILE_URL = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
ATTACK_ICS_URL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"

# Cache directory
CACHE_DIR = Path.home() / ".dalga" / "mitre_cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)


class Platform(Enum):
    """Target platforms"""
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "macOS"
    CLOUD = "Cloud"
    AZURE_AD = "Azure AD"
    OFFICE_365 = "Office 365"
    SAAS = "SaaS"
    IaaS = "IaaS"
    GOOGLE_WORKSPACE = "Google Workspace"
    CONTAINERS = "Containers"
    NETWORK = "Network"
    PRE = "PRE"


class TacticPhase(Enum):
    """Kill chain phases (MITRE ATT&CK Tactics)"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class Tactic:
    """ATT&CK Tactic (Kill Chain Phase)"""
    id: str  # TAxxxx
    stix_id: str  # x-mitre-tactic--uuid
    name: str
    description: str
    shortname: str  # URL slug
    external_references: List[Dict] = field(default_factory=list)
    created: Optional[datetime] = None
    modified: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description,
            'shortname': self.shortname,
            'created': self.created.isoformat() if self.created else None,
            'modified': self.modified.isoformat() if self.modified else None
        }


@dataclass
class Technique:
    """ATT&CK Technique or Sub-technique"""
    id: str  # Txxxx or Txxxx.xxx
    stix_id: str  # attack-pattern--uuid
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)  # Tactic shortnames
    platforms: List[str] = field(default_factory=list)
    permissions_required: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection: str = ""
    is_subtechnique: bool = False
    parent_id: Optional[str] = None  # Parent technique ID for subtechniques
    subtechniques: List[str] = field(default_factory=list)  # Child IDs
    mitigations: List[str] = field(default_factory=list)  # Mitigation IDs
    groups: List[str] = field(default_factory=list)  # Group IDs
    software: List[str] = field(default_factory=list)  # Software IDs
    external_references: List[Dict] = field(default_factory=list)
    kill_chain_phases: List[Dict] = field(default_factory=list)
    x_mitre_version: str = ""
    x_mitre_deprecated: bool = False
    x_mitre_is_subtechnique: bool = False
    x_mitre_detection: str = ""
    x_mitre_platforms: List[str] = field(default_factory=list)
    x_mitre_data_sources: List[str] = field(default_factory=list)
    x_mitre_defense_bypassed: List[str] = field(default_factory=list)
    x_mitre_permissions_required: List[str] = field(default_factory=list)
    x_mitre_impact_type: List[str] = field(default_factory=list)
    created: Optional[datetime] = None
    modified: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description[:500] if self.description else "",
            'tactics': self.tactics,
            'platforms': self.platforms,
            'permissions_required': self.permissions_required,
            'data_sources': self.data_sources,
            'detection': self.detection[:500] if self.detection else "",
            'is_subtechnique': self.is_subtechnique,
            'parent_id': self.parent_id,
            'subtechniques': self.subtechniques,
            'mitigations': self.mitigations,
            'groups': self.groups,
            'software': self.software,
            'deprecated': self.x_mitre_deprecated,
            'version': self.x_mitre_version,
            'created': self.created.isoformat() if self.created else None,
            'modified': self.modified.isoformat() if self.modified else None
        }


@dataclass
class Mitigation:
    """ATT&CK Mitigation"""
    id: str  # Mxxxx
    stix_id: str  # course-of-action--uuid
    name: str
    description: str
    techniques: List[str] = field(default_factory=list)  # Technique IDs this mitigates
    external_references: List[Dict] = field(default_factory=list)
    x_mitre_deprecated: bool = False
    created: Optional[datetime] = None
    modified: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description[:500] if self.description else "",
            'techniques': self.techniques,
            'deprecated': self.x_mitre_deprecated,
            'created': self.created.isoformat() if self.created else None,
            'modified': self.modified.isoformat() if self.modified else None
        }


@dataclass
class Group:
    """ATT&CK Threat Group (APT)"""
    id: str  # Gxxxx
    stix_id: str  # intrusion-set--uuid
    name: str
    description: str
    aliases: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)
    external_references: List[Dict] = field(default_factory=list)
    x_mitre_deprecated: bool = False
    created: Optional[datetime] = None
    modified: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description[:500] if self.description else "",
            'aliases': self.aliases,
            'techniques': self.techniques,
            'software': self.software,
            'deprecated': self.x_mitre_deprecated,
            'created': self.created.isoformat() if self.created else None,
            'modified': self.modified.isoformat() if self.modified else None
        }


@dataclass
class Software:
    """ATT&CK Software (Malware/Tool)"""
    id: str  # Sxxxx
    stix_id: str  # malware--uuid or tool--uuid
    name: str
    description: str
    type: str  # "malware" or "tool"
    aliases: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    external_references: List[Dict] = field(default_factory=list)
    x_mitre_deprecated: bool = False
    created: Optional[datetime] = None
    modified: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description[:500] if self.description else "",
            'type': self.type,
            'aliases': self.aliases,
            'platforms': self.platforms,
            'techniques': self.techniques,
            'groups': self.groups,
            'deprecated': self.x_mitre_deprecated,
            'created': self.created.isoformat() if self.created else None,
            'modified': self.modified.isoformat() if self.modified else None
        }


@dataclass
class DataSource:
    """ATT&CK Data Source"""
    id: str  # DSxxxx
    stix_id: str
    name: str
    description: str
    platforms: List[str] = field(default_factory=list)
    collection_layers: List[str] = field(default_factory=list)
    data_components: List[Dict] = field(default_factory=list)
    external_references: List[Dict] = field(default_factory=list)
    created: Optional[datetime] = None
    modified: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'stix_id': self.stix_id,
            'name': self.name,
            'description': self.description[:500] if self.description else "",
            'platforms': self.platforms,
            'collection_layers': self.collection_layers,
            'data_components': self.data_components,
            'created': self.created.isoformat() if self.created else None,
            'modified': self.modified.isoformat() if self.modified else None
        }


class MITREAttackData:
    """
    MITRE ATT&CK Data Manager

    Downloads, parses, and indexes real ATT&CK Enterprise data from MITRE CTI.
    Provides searchable access to techniques, tactics, mitigations, groups, and software.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> 'MITREAttackData':
        """Get singleton instance"""
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        # Data stores
        self._tactics: Dict[str, Tactic] = {}
        self._techniques: Dict[str, Technique] = {}
        self._mitigations: Dict[str, Mitigation] = {}
        self._groups: Dict[str, Group] = {}
        self._software: Dict[str, Software] = {}
        self._data_sources: Dict[str, DataSource] = {}

        # Indexes for fast lookups
        self._technique_by_stix: Dict[str, str] = {}  # stix_id -> technique_id
        self._technique_by_tactic: Dict[str, List[str]] = {}  # tactic -> [technique_ids]
        self._technique_by_platform: Dict[str, List[str]] = {}  # platform -> [technique_ids]
        self._technique_by_datasource: Dict[str, List[str]] = {}  # datasource -> [technique_ids]
        self._mitigation_by_technique: Dict[str, List[str]] = {}  # technique_id -> [mitigation_ids]
        self._group_by_technique: Dict[str, List[str]] = {}  # technique_id -> [group_ids]
        self._software_by_technique: Dict[str, List[str]] = {}  # technique_id -> [software_ids]

        # Search index
        self._search_index: Dict[str, Set[str]] = {}  # word -> {technique_ids}

        # Metadata
        self._version: str = ""
        self._last_update: Optional[datetime] = None
        self._data_loaded: bool = False

        # Raw STIX data
        self._raw_data: Optional[Dict] = None

        logger.info("[MITRE-ATT&CK] Data manager initialized")

    def load_data(self, force_refresh: bool = False) -> bool:
        """
        Load ATT&CK data from cache or download fresh

        Args:
            force_refresh: Force download even if cache exists

        Returns:
            True if data loaded successfully
        """
        cache_file = CACHE_DIR / "enterprise-attack.json"
        cache_meta = CACHE_DIR / "enterprise-attack.meta.json"

        # Check cache validity
        use_cache = False
        if not force_refresh and cache_file.exists() and cache_meta.exists():
            try:
                with open(cache_meta, 'r') as f:
                    meta = json.load(f)
                cache_time = datetime.fromisoformat(meta.get('downloaded', '2000-01-01'))
                # Cache valid for 24 hours
                if datetime.now() - cache_time < timedelta(hours=24):
                    use_cache = True
                    logger.info("[MITRE-ATT&CK] Using cached data")
            except Exception as e:
                logger.warning(f"[MITRE-ATT&CK] Cache metadata error: {e}")

        # Download if needed
        if not use_cache:
            if not self._download_data(cache_file, cache_meta):
                # Try to use existing cache even if expired
                if not cache_file.exists():
                    logger.error("[MITRE-ATT&CK] No data available")
                    return False
                logger.warning("[MITRE-ATT&CK] Using expired cache")

        # Parse data
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                self._raw_data = json.load(f)
            self._parse_stix_data()
            self._build_indexes()
            self._data_loaded = True
            logger.info(f"[MITRE-ATT&CK] Loaded {len(self._techniques)} techniques, "
                       f"{len(self._tactics)} tactics, {len(self._mitigations)} mitigations, "
                       f"{len(self._groups)} groups, {len(self._software)} software")
            return True
        except Exception as e:
            logger.error(f"[MITRE-ATT&CK] Parse error: {e}")
            return False

    def _download_data(self, cache_file: Path, cache_meta: Path) -> bool:
        """Download fresh ATT&CK data from MITRE CTI"""
        logger.info(f"[MITRE-ATT&CK] Downloading from {ATTACK_DATA_URL}")

        try:
            # Create request with headers
            req = urllib.request.Request(
                ATTACK_DATA_URL,
                headers={
                    'User-Agent': 'TSUNAMI-MITRE-Integration/5.0',
                    'Accept': 'application/json'
                }
            )

            with urllib.request.urlopen(req, timeout=60) as response:
                data = response.read()

            # Validate JSON
            json.loads(data)

            # Save to cache
            with open(cache_file, 'wb') as f:
                f.write(data)

            # Save metadata
            meta = {
                'downloaded': datetime.now().isoformat(),
                'url': ATTACK_DATA_URL,
                'size': len(data),
                'checksum': hashlib.sha256(data).hexdigest()
            }
            with open(cache_meta, 'w') as f:
                json.dump(meta, f)

            self._last_update = datetime.now()
            logger.info(f"[MITRE-ATT&CK] Downloaded {len(data)} bytes")
            return True

        except urllib.error.URLError as e:
            logger.error(f"[MITRE-ATT&CK] Download failed: {e}")
            return False
        except Exception as e:
            logger.error(f"[MITRE-ATT&CK] Download error: {e}")
            return False

    def _parse_stix_data(self):
        """Parse STIX 2.1 bundle into typed objects"""
        if not self._raw_data:
            return

        objects = self._raw_data.get('objects', [])

        # First pass: collect all objects by type
        attack_patterns = []
        course_of_actions = []
        intrusion_sets = []
        malwares = []
        tools = []
        x_mitre_tactics = []
        x_mitre_data_sources = []
        relationships = []

        for obj in objects:
            obj_type = obj.get('type', '')
            if obj_type == 'attack-pattern':
                attack_patterns.append(obj)
            elif obj_type == 'course-of-action':
                course_of_actions.append(obj)
            elif obj_type == 'intrusion-set':
                intrusion_sets.append(obj)
            elif obj_type == 'malware':
                malwares.append(obj)
            elif obj_type == 'tool':
                tools.append(obj)
            elif obj_type == 'x-mitre-tactic':
                x_mitre_tactics.append(obj)
            elif obj_type == 'x-mitre-data-source':
                x_mitre_data_sources.append(obj)
            elif obj_type == 'relationship':
                relationships.append(obj)

        # Parse tactics
        for obj in x_mitre_tactics:
            tactic = self._parse_tactic(obj)
            if tactic:
                self._tactics[tactic.id] = tactic

        # Parse techniques
        for obj in attack_patterns:
            technique = self._parse_technique(obj)
            if technique:
                self._techniques[technique.id] = technique
                self._technique_by_stix[technique.stix_id] = technique.id

        # Parse mitigations
        for obj in course_of_actions:
            mitigation = self._parse_mitigation(obj)
            if mitigation:
                self._mitigations[mitigation.id] = mitigation

        # Parse groups
        for obj in intrusion_sets:
            group = self._parse_group(obj)
            if group:
                self._groups[group.id] = group

        # Parse software (malware + tools)
        for obj in malwares:
            software = self._parse_software(obj, 'malware')
            if software:
                self._software[software.id] = software

        for obj in tools:
            software = self._parse_software(obj, 'tool')
            if software:
                self._software[software.id] = software

        # Parse data sources
        for obj in x_mitre_data_sources:
            ds = self._parse_data_source(obj)
            if ds:
                self._data_sources[ds.id] = ds

        # Process relationships
        self._process_relationships(relationships)

        # Link subtechniques to parents
        self._link_subtechniques()

    def _get_external_id(self, obj: Dict) -> Optional[str]:
        """Extract ATT&CK ID from external references"""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                return ref.get('external_id')
        return None

    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO datetime string"""
        if not dt_str:
            return None
        try:
            # Handle various formats
            dt_str = dt_str.replace('Z', '+00:00')
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except Exception:
            return None

    def _parse_tactic(self, obj: Dict) -> Optional[Tactic]:
        """Parse STIX x-mitre-tactic object"""
        tactic_id = self._get_external_id(obj)
        if not tactic_id:
            return None

        return Tactic(
            id=tactic_id,
            stix_id=obj.get('id', ''),
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            shortname=obj.get('x_mitre_shortname', ''),
            external_references=obj.get('external_references', []),
            created=self._parse_datetime(obj.get('created')),
            modified=self._parse_datetime(obj.get('modified'))
        )

    def _parse_technique(self, obj: Dict) -> Optional[Technique]:
        """Parse STIX attack-pattern object"""
        tech_id = self._get_external_id(obj)
        if not tech_id:
            return None

        # Extract tactics from kill chain phases
        tactics = []
        for phase in obj.get('kill_chain_phases', []):
            if phase.get('kill_chain_name') == 'mitre-attack':
                tactics.append(phase.get('phase_name', ''))

        # Check if subtechnique
        is_sub = obj.get('x_mitre_is_subtechnique', False) or '.' in tech_id

        return Technique(
            id=tech_id,
            stix_id=obj.get('id', ''),
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            tactics=tactics,
            platforms=obj.get('x_mitre_platforms', []),
            permissions_required=obj.get('x_mitre_permissions_required', []),
            data_sources=obj.get('x_mitre_data_sources', []),
            detection=obj.get('x_mitre_detection', ''),
            is_subtechnique=is_sub,
            parent_id=tech_id.split('.')[0] if is_sub else None,
            external_references=obj.get('external_references', []),
            kill_chain_phases=obj.get('kill_chain_phases', []),
            x_mitre_version=obj.get('x_mitre_version', ''),
            x_mitre_deprecated=obj.get('x_mitre_deprecated', False),
            x_mitre_is_subtechnique=is_sub,
            x_mitre_detection=obj.get('x_mitre_detection', ''),
            x_mitre_platforms=obj.get('x_mitre_platforms', []),
            x_mitre_data_sources=obj.get('x_mitre_data_sources', []),
            x_mitre_defense_bypassed=obj.get('x_mitre_defense_bypassed', []),
            x_mitre_permissions_required=obj.get('x_mitre_permissions_required', []),
            x_mitre_impact_type=obj.get('x_mitre_impact_type', []),
            created=self._parse_datetime(obj.get('created')),
            modified=self._parse_datetime(obj.get('modified'))
        )

    def _parse_mitigation(self, obj: Dict) -> Optional[Mitigation]:
        """Parse STIX course-of-action object"""
        mit_id = self._get_external_id(obj)
        if not mit_id:
            return None

        return Mitigation(
            id=mit_id,
            stix_id=obj.get('id', ''),
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            external_references=obj.get('external_references', []),
            x_mitre_deprecated=obj.get('x_mitre_deprecated', False),
            created=self._parse_datetime(obj.get('created')),
            modified=self._parse_datetime(obj.get('modified'))
        )

    def _parse_group(self, obj: Dict) -> Optional[Group]:
        """Parse STIX intrusion-set object"""
        group_id = self._get_external_id(obj)
        if not group_id:
            return None

        return Group(
            id=group_id,
            stix_id=obj.get('id', ''),
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            aliases=obj.get('aliases', []),
            external_references=obj.get('external_references', []),
            x_mitre_deprecated=obj.get('x_mitre_deprecated', False),
            created=self._parse_datetime(obj.get('created')),
            modified=self._parse_datetime(obj.get('modified'))
        )

    def _parse_software(self, obj: Dict, software_type: str) -> Optional[Software]:
        """Parse STIX malware or tool object"""
        soft_id = self._get_external_id(obj)
        if not soft_id:
            return None

        return Software(
            id=soft_id,
            stix_id=obj.get('id', ''),
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            type=software_type,
            aliases=obj.get('x_mitre_aliases', []),
            platforms=obj.get('x_mitre_platforms', []),
            external_references=obj.get('external_references', []),
            x_mitre_deprecated=obj.get('x_mitre_deprecated', False),
            created=self._parse_datetime(obj.get('created')),
            modified=self._parse_datetime(obj.get('modified'))
        )

    def _parse_data_source(self, obj: Dict) -> Optional[DataSource]:
        """Parse STIX x-mitre-data-source object"""
        ds_id = self._get_external_id(obj)
        if not ds_id:
            return None

        return DataSource(
            id=ds_id,
            stix_id=obj.get('id', ''),
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            platforms=obj.get('x_mitre_platforms', []),
            collection_layers=obj.get('x_mitre_collection_layers', []),
            external_references=obj.get('external_references', []),
            created=self._parse_datetime(obj.get('created')),
            modified=self._parse_datetime(obj.get('modified'))
        )

    def _process_relationships(self, relationships: List[Dict]):
        """Process STIX relationships to link objects"""
        for rel in relationships:
            rel_type = rel.get('relationship_type', '')
            source_ref = rel.get('source_ref', '')
            target_ref = rel.get('target_ref', '')

            # Mitigation -> Technique
            if rel_type == 'mitigates':
                tech_id = self._technique_by_stix.get(target_ref)
                mit_stix = source_ref
                if tech_id:
                    # Find mitigation by stix_id
                    for mit in self._mitigations.values():
                        if mit.stix_id == mit_stix:
                            if tech_id not in mit.techniques:
                                mit.techniques.append(tech_id)
                            if mit.id not in self._techniques[tech_id].mitigations:
                                self._techniques[tech_id].mitigations.append(mit.id)
                            break

            # Group -> Technique (uses)
            elif rel_type == 'uses':
                # Could be group->technique, group->software, or software->technique
                if 'intrusion-set' in source_ref:
                    tech_id = self._technique_by_stix.get(target_ref)
                    if tech_id:
                        for group in self._groups.values():
                            if group.stix_id == source_ref:
                                if tech_id not in group.techniques:
                                    group.techniques.append(tech_id)
                                if group.id not in self._techniques[tech_id].groups:
                                    self._techniques[tech_id].groups.append(group.id)
                                break

                # Software -> Technique
                elif 'malware' in source_ref or 'tool' in source_ref:
                    tech_id = self._technique_by_stix.get(target_ref)
                    if tech_id:
                        for soft in self._software.values():
                            if soft.stix_id == source_ref:
                                if tech_id not in soft.techniques:
                                    soft.techniques.append(tech_id)
                                if soft.id not in self._techniques[tech_id].software:
                                    self._techniques[tech_id].software.append(soft.id)
                                break

    def _link_subtechniques(self):
        """Link subtechniques to their parent techniques"""
        for tech_id, tech in self._techniques.items():
            if tech.is_subtechnique and tech.parent_id:
                parent = self._techniques.get(tech.parent_id)
                if parent and tech_id not in parent.subtechniques:
                    parent.subtechniques.append(tech_id)

    def _build_indexes(self):
        """Build search and lookup indexes"""
        # Clear existing indexes
        self._technique_by_tactic.clear()
        self._technique_by_platform.clear()
        self._technique_by_datasource.clear()
        self._mitigation_by_technique.clear()
        self._group_by_technique.clear()
        self._software_by_technique.clear()
        self._search_index.clear()

        for tech_id, tech in self._techniques.items():
            if tech.x_mitre_deprecated:
                continue

            # Index by tactic
            for tactic in tech.tactics:
                if tactic not in self._technique_by_tactic:
                    self._technique_by_tactic[tactic] = []
                self._technique_by_tactic[tactic].append(tech_id)

            # Index by platform
            for platform in tech.platforms:
                if platform not in self._technique_by_platform:
                    self._technique_by_platform[platform] = []
                self._technique_by_platform[platform].append(tech_id)

            # Index by data source
            for ds in tech.data_sources:
                if ds not in self._technique_by_datasource:
                    self._technique_by_datasource[ds] = []
                self._technique_by_datasource[ds].append(tech_id)

            # Build search index from name, description
            words = set()
            words.update(self._tokenize(tech.name))
            words.update(self._tokenize(tech.description[:500]))
            words.add(tech_id.lower())

            for word in words:
                if word not in self._search_index:
                    self._search_index[word] = set()
                self._search_index[word].add(tech_id)

        # Index mitigations by technique
        for mit in self._mitigations.values():
            for tech_id in mit.techniques:
                if tech_id not in self._mitigation_by_technique:
                    self._mitigation_by_technique[tech_id] = []
                if mit.id not in self._mitigation_by_technique[tech_id]:
                    self._mitigation_by_technique[tech_id].append(mit.id)

        # Index groups by technique
        for group in self._groups.values():
            for tech_id in group.techniques:
                if tech_id not in self._group_by_technique:
                    self._group_by_technique[tech_id] = []
                if group.id not in self._group_by_technique[tech_id]:
                    self._group_by_technique[tech_id].append(group.id)

        # Index software by technique
        for soft in self._software.values():
            for tech_id in soft.techniques:
                if tech_id not in self._software_by_technique:
                    self._software_by_technique[tech_id] = []
                if soft.id not in self._software_by_technique[tech_id]:
                    self._software_by_technique[tech_id].append(soft.id)

    def _tokenize(self, text: str) -> Set[str]:
        """Tokenize text for search indexing"""
        if not text:
            return set()
        # Lowercase and split on non-alphanumeric
        words = re.findall(r'\b[a-z0-9]+\b', text.lower())
        # Filter short words
        return {w for w in words if len(w) > 2}

    # ==================== PUBLIC API ====================

    def is_loaded(self) -> bool:
        """Check if data is loaded"""
        return self._data_loaded

    def get_technique(self, technique_id: str) -> Optional[Technique]:
        """Get technique by ID (e.g., T1059, T1059.001)"""
        return self._techniques.get(technique_id)

    def get_tactic(self, tactic_id: str) -> Optional[Tactic]:
        """Get tactic by ID (e.g., TA0001) or shortname"""
        # Try direct lookup
        if tactic_id in self._tactics:
            return self._tactics[tactic_id]
        # Try by shortname
        for tactic in self._tactics.values():
            if tactic.shortname == tactic_id:
                return tactic
        return None

    def get_mitigation(self, mitigation_id: str) -> Optional[Mitigation]:
        """Get mitigation by ID (e.g., M1047)"""
        return self._mitigations.get(mitigation_id)

    def get_group(self, group_id: str) -> Optional[Group]:
        """Get group by ID (e.g., G0016) or name"""
        if group_id in self._groups:
            return self._groups[group_id]
        # Try by name
        for group in self._groups.values():
            if group.name.lower() == group_id.lower():
                return group
            if group_id.lower() in [a.lower() for a in group.aliases]:
                return group
        return None

    def get_software(self, software_id: str) -> Optional[Software]:
        """Get software by ID (e.g., S0154) or name"""
        if software_id in self._software:
            return self._software[software_id]
        # Try by name
        for soft in self._software.values():
            if soft.name.lower() == software_id.lower():
                return soft
        return None

    def get_data_source(self, ds_id: str) -> Optional[DataSource]:
        """Get data source by ID (e.g., DS0009)"""
        return self._data_sources.get(ds_id)

    def list_techniques(self, include_subtechniques: bool = True,
                       include_deprecated: bool = False) -> List[Technique]:
        """List all techniques"""
        result = []
        for tech in self._techniques.values():
            if not include_deprecated and tech.x_mitre_deprecated:
                continue
            if not include_subtechniques and tech.is_subtechnique:
                continue
            result.append(tech)
        return sorted(result, key=lambda t: t.id)

    def list_tactics(self) -> List[Tactic]:
        """List all tactics in kill chain order"""
        order = [
            'reconnaissance', 'resource-development', 'initial-access',
            'execution', 'persistence', 'privilege-escalation',
            'defense-evasion', 'credential-access', 'discovery',
            'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact'
        ]
        tactics = list(self._tactics.values())
        return sorted(tactics, key=lambda t: order.index(t.shortname)
                     if t.shortname in order else 99)

    def list_mitigations(self, include_deprecated: bool = False) -> List[Mitigation]:
        """List all mitigations"""
        result = []
        for mit in self._mitigations.values():
            if not include_deprecated and mit.x_mitre_deprecated:
                continue
            result.append(mit)
        return sorted(result, key=lambda m: m.id)

    def list_groups(self, include_deprecated: bool = False) -> List[Group]:
        """List all threat groups"""
        result = []
        for group in self._groups.values():
            if not include_deprecated and group.x_mitre_deprecated:
                continue
            result.append(group)
        return sorted(result, key=lambda g: g.name)

    def list_software(self, software_type: Optional[str] = None,
                     include_deprecated: bool = False) -> List[Software]:
        """List all software (optionally filter by type: 'malware' or 'tool')"""
        result = []
        for soft in self._software.values():
            if not include_deprecated and soft.x_mitre_deprecated:
                continue
            if software_type and soft.type != software_type:
                continue
            result.append(soft)
        return sorted(result, key=lambda s: s.name)

    def list_data_sources(self) -> List[DataSource]:
        """List all data sources"""
        return sorted(self._data_sources.values(), key=lambda d: d.name)

    def get_techniques_by_tactic(self, tactic: str) -> List[Technique]:
        """Get all techniques for a tactic"""
        tech_ids = self._technique_by_tactic.get(tactic, [])
        return [self._techniques[tid] for tid in tech_ids if tid in self._techniques]

    def get_techniques_by_platform(self, platform: str) -> List[Technique]:
        """Get all techniques for a platform"""
        tech_ids = self._technique_by_platform.get(platform, [])
        return [self._techniques[tid] for tid in tech_ids if tid in self._techniques]

    def get_mitigations_for_technique(self, technique_id: str) -> List[Mitigation]:
        """Get all mitigations for a technique"""
        mit_ids = self._mitigation_by_technique.get(technique_id, [])
        return [self._mitigations[mid] for mid in mit_ids if mid in self._mitigations]

    def get_groups_using_technique(self, technique_id: str) -> List[Group]:
        """Get all groups using a technique"""
        group_ids = self._group_by_technique.get(technique_id, [])
        return [self._groups[gid] for gid in group_ids if gid in self._groups]

    def get_software_using_technique(self, technique_id: str) -> List[Software]:
        """Get all software using a technique"""
        soft_ids = self._software_by_technique.get(technique_id, [])
        return [self._software[sid] for sid in soft_ids if sid in self._software]

    def search_techniques(self, query: str, limit: int = 20) -> List[Tuple[Technique, float]]:
        """
        Search techniques by keyword

        Args:
            query: Search query
            limit: Maximum results

        Returns:
            List of (Technique, relevance_score) tuples
        """
        if not query:
            return []

        query_words = self._tokenize(query)
        if not query_words:
            return []

        # Score each technique
        scores: Dict[str, float] = {}
        for word in query_words:
            # Exact match
            if word in self._search_index:
                for tech_id in self._search_index[word]:
                    scores[tech_id] = scores.get(tech_id, 0) + 1.0

            # Prefix match
            for index_word, tech_ids in self._search_index.items():
                if index_word.startswith(word) and index_word != word:
                    for tech_id in tech_ids:
                        scores[tech_id] = scores.get(tech_id, 0) + 0.5

        # Normalize scores
        max_score = max(scores.values()) if scores else 1
        results = []
        for tech_id, score in scores.items():
            tech = self._techniques.get(tech_id)
            if tech and not tech.x_mitre_deprecated:
                results.append((tech, score / max_score))

        # Sort by score descending
        results.sort(key=lambda x: (-x[1], x[0].id))
        return results[:limit]

    def get_statistics(self) -> Dict[str, Any]:
        """Get data statistics"""
        active_techniques = sum(1 for t in self._techniques.values() if not t.x_mitre_deprecated)
        subtechniques = sum(1 for t in self._techniques.values() if t.is_subtechnique)
        active_mitigations = sum(1 for m in self._mitigations.values() if not m.x_mitre_deprecated)
        active_groups = sum(1 for g in self._groups.values() if not g.x_mitre_deprecated)
        active_software = sum(1 for s in self._software.values() if not s.x_mitre_deprecated)

        return {
            'version': self._version,
            'last_update': self._last_update.isoformat() if self._last_update else None,
            'data_loaded': self._data_loaded,
            'counts': {
                'tactics': len(self._tactics),
                'techniques': active_techniques,
                'subtechniques': subtechniques,
                'mitigations': active_mitigations,
                'groups': active_groups,
                'software': active_software,
                'data_sources': len(self._data_sources),
            },
            'platforms': list(self._technique_by_platform.keys()),
            'tactics': [t.shortname for t in self.list_tactics()]
        }


# Singleton accessor
def get_attack_data() -> MITREAttackData:
    """Get the global ATT&CK data instance"""
    instance = MITREAttackData.get_instance()
    if not instance.is_loaded():
        instance.load_data()
    return instance
