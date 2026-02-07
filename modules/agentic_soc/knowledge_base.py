#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Agentic SOC - Knowledge Base v5.0
================================================================================

    SOC knowledge management:
    - Store investigation patterns
    - Learn from past incidents
    - Threat actor profiles
    - TTP mappings
    - Playbook recommendations

================================================================================
"""

import json
import logging
import sqlite3
import hashlib
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Types of investigation patterns"""
    ATTACK_PATTERN = "attack_pattern"
    DETECTION_PATTERN = "detection_pattern"
    RESPONSE_PATTERN = "response_pattern"
    FALSE_POSITIVE_PATTERN = "false_positive_pattern"


class ThreatActorType(Enum):
    """Types of threat actors"""
    APT = "apt"
    CYBERCRIME = "cybercrime"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    NATION_STATE = "nation_state"
    UNKNOWN = "unknown"


@dataclass
class IncidentPattern:
    """Pattern learned from past incidents"""
    id: str
    name: str
    pattern_type: PatternType
    description: str
    indicators: List[str]
    mitre_techniques: List[str]
    detection_signatures: List[str]
    response_steps: List[str]
    false_positive_indicators: List[str]
    confidence: float
    occurrences: int
    first_seen: datetime
    last_seen: datetime
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'pattern_type': self.pattern_type.value,
            'description': self.description,
            'indicators': self.indicators,
            'mitre_techniques': self.mitre_techniques,
            'detection_signatures': self.detection_signatures,
            'response_steps': self.response_steps,
            'false_positive_indicators': self.false_positive_indicators,
            'confidence': self.confidence,
            'occurrences': self.occurrences,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'tags': self.tags
        }


@dataclass
class ThreatActorProfile:
    """Threat actor profile"""
    id: str
    name: str
    aliases: List[str]
    actor_type: ThreatActorType
    description: str
    motivation: str
    sophistication: str  # low, medium, high, advanced
    target_sectors: List[str]
    target_regions: List[str]
    known_ttps: List[str]  # MITRE ATT&CK technique IDs
    known_tools: List[str]
    known_infrastructure: List[str]
    first_seen: datetime
    last_seen: datetime
    confidence: float
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'name': self.name,
            'aliases': self.aliases,
            'actor_type': self.actor_type.value,
            'description': self.description,
            'motivation': self.motivation,
            'sophistication': self.sophistication,
            'target_sectors': self.target_sectors,
            'target_regions': self.target_regions,
            'known_ttps': self.known_ttps,
            'known_tools': self.known_tools,
            'known_infrastructure': self.known_infrastructure,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'confidence': self.confidence,
            'references': self.references
        }


@dataclass
class PlaybookRecommendation:
    """Playbook recommendation"""
    playbook_id: str
    playbook_name: str
    description: str
    relevance_score: float
    matching_indicators: List[str]
    steps: List[Dict[str, Any]]
    estimated_time_minutes: int
    automation_level: str  # manual, semi-automated, fully-automated
    required_permissions: List[str]
    prerequisites: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'playbook_id': self.playbook_id,
            'playbook_name': self.playbook_name,
            'description': self.description,
            'relevance_score': self.relevance_score,
            'matching_indicators': self.matching_indicators,
            'steps': self.steps,
            'estimated_time_minutes': self.estimated_time_minutes,
            'automation_level': self.automation_level,
            'required_permissions': self.required_permissions,
            'prerequisites': self.prerequisites
        }


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique"""
    technique_id: str
    name: str
    tactic: str
    description: str
    platforms: List[str]
    detection_methods: List[str]
    mitigations: List[str]
    data_sources: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'technique_id': self.technique_id,
            'name': self.name,
            'tactic': self.tactic,
            'description': self.description,
            'platforms': self.platforms,
            'detection_methods': self.detection_methods,
            'mitigations': self.mitigations,
            'data_sources': self.data_sources
        }


class KnowledgeBase:
    """SOC knowledge management system"""

    # Pre-populated MITRE techniques (subset)
    MITRE_TECHNIQUES = {
        'T1059': MITRETechnique(
            'T1059', 'Command and Scripting Interpreter', 'Execution',
            'Adversaries may abuse command and script interpreters to execute commands',
            ['Windows', 'Linux', 'macOS'],
            ['Process monitoring', 'Command line logging'],
            ['Execution Prevention', 'Disable or Remove Feature'],
            ['Process: Process Creation', 'Command: Command Execution']
        ),
        'T1059.001': MITRETechnique(
            'T1059.001', 'PowerShell', 'Execution',
            'Adversaries may abuse PowerShell commands and scripts for execution',
            ['Windows'],
            ['Script Block Logging', 'Module Logging', 'Transcription'],
            ['Disable PowerShell', 'Code Signing'],
            ['Script: Script Execution', 'Process: Process Creation']
        ),
        'T1071': MITRETechnique(
            'T1071', 'Application Layer Protocol', 'Command and Control',
            'Adversaries may communicate using application layer protocols',
            ['Windows', 'Linux', 'macOS'],
            ['Network traffic analysis', 'Packet inspection'],
            ['Network Intrusion Prevention', 'SSL/TLS Inspection'],
            ['Network Traffic: Network Traffic Content']
        ),
        'T1486': MITRETechnique(
            'T1486', 'Data Encrypted for Impact', 'Impact',
            'Adversaries may encrypt data on target systems to interrupt availability',
            ['Windows', 'Linux', 'macOS'],
            ['File monitoring', 'Process monitoring'],
            ['Data Backup', 'Behavior Prevention'],
            ['File: File Modification', 'Process: Process Creation']
        ),
        'T1003': MITRETechnique(
            'T1003', 'OS Credential Dumping', 'Credential Access',
            'Adversaries may attempt to dump credentials from the operating system',
            ['Windows', 'Linux', 'macOS'],
            ['Process monitoring', 'API monitoring'],
            ['Privileged Account Management', 'Operating System Configuration'],
            ['Process: Process Access', 'Command: Command Execution']
        ),
        'T1078': MITRETechnique(
            'T1078', 'Valid Accounts', 'Defense Evasion',
            'Adversaries may obtain and abuse credentials of existing accounts',
            ['Windows', 'Linux', 'macOS', 'Cloud'],
            ['Logon session monitoring', 'User account monitoring'],
            ['Multi-factor Authentication', 'Privileged Account Management'],
            ['Logon Session: Logon Session Creation', 'User Account: User Account Authentication']
        ),
        'T1021': MITRETechnique(
            'T1021', 'Remote Services', 'Lateral Movement',
            'Adversaries may use remote services to access systems',
            ['Windows', 'Linux', 'macOS'],
            ['Network connection monitoring', 'Authentication logs'],
            ['Multi-factor Authentication', 'Network Segmentation'],
            ['Logon Session: Logon Session Creation', 'Network Traffic: Network Connection Creation']
        ),
        'T1048': MITRETechnique(
            'T1048', 'Exfiltration Over Alternative Protocol', 'Exfiltration',
            'Adversaries may steal data by exfiltrating it over a different protocol',
            ['Windows', 'Linux', 'macOS'],
            ['Network traffic analysis', 'DNS monitoring'],
            ['Network Intrusion Prevention', 'Data Loss Prevention'],
            ['Network Traffic: Network Traffic Content', 'File: File Access']
        ),
    }

    # Pre-populated playbooks
    PLAYBOOKS = [
        {
            'id': 'PB001',
            'name': 'Malware Incident Response',
            'description': 'Standard response procedure for malware detection',
            'triggers': ['malware', 'virus', 'trojan', 'ransomware'],
            'steps': [
                {'order': 1, 'action': 'isolate', 'description': 'Isolate affected endpoint', 'automated': True},
                {'order': 2, 'action': 'collect', 'description': 'Collect malware sample', 'automated': True},
                {'order': 3, 'action': 'analyze', 'description': 'Analyze malware behavior', 'automated': False},
                {'order': 4, 'action': 'contain', 'description': 'Block C2 communication', 'automated': True},
                {'order': 5, 'action': 'eradicate', 'description': 'Remove malware', 'automated': True},
                {'order': 6, 'action': 'recover', 'description': 'Restore from backup if needed', 'automated': False},
            ],
            'estimated_time': 120,
            'automation_level': 'semi-automated',
            'permissions': ['endpoint_isolation', 'file_quarantine'],
            'prerequisites': ['EDR agent', 'Network isolation capability']
        },
        {
            'id': 'PB002',
            'name': 'Credential Compromise Response',
            'description': 'Response procedure for credential theft/compromise',
            'triggers': ['credential', 'password', 'brute force', 'mimikatz', 'pass the hash'],
            'steps': [
                {'order': 1, 'action': 'reset', 'description': 'Reset compromised credentials', 'automated': True},
                {'order': 2, 'action': 'revoke', 'description': 'Revoke active sessions', 'automated': True},
                {'order': 3, 'action': 'audit', 'description': 'Audit account activity', 'automated': False},
                {'order': 4, 'action': 'hunt', 'description': 'Hunt for lateral movement', 'automated': False},
                {'order': 5, 'action': 'harden', 'description': 'Implement MFA', 'automated': False},
            ],
            'estimated_time': 60,
            'automation_level': 'semi-automated',
            'permissions': ['password_reset', 'session_revocation'],
            'prerequisites': ['IAM integration', 'Active Directory access']
        },
        {
            'id': 'PB003',
            'name': 'Data Exfiltration Response',
            'description': 'Response procedure for data exfiltration attempts',
            'triggers': ['exfiltration', 'data theft', 'data leak', 'upload'],
            'steps': [
                {'order': 1, 'action': 'block', 'description': 'Block exfiltration destination', 'automated': True},
                {'order': 2, 'action': 'isolate', 'description': 'Isolate source system', 'automated': True},
                {'order': 3, 'action': 'identify', 'description': 'Identify exfiltrated data', 'automated': False},
                {'order': 4, 'action': 'assess', 'description': 'Assess data sensitivity', 'automated': False},
                {'order': 5, 'action': 'notify', 'description': 'Notify stakeholders', 'automated': True},
                {'order': 6, 'action': 'report', 'description': 'File regulatory report if needed', 'automated': False},
            ],
            'estimated_time': 180,
            'automation_level': 'semi-automated',
            'permissions': ['network_block', 'endpoint_isolation', 'notification'],
            'prerequisites': ['DLP integration', 'Legal team contact']
        },
        {
            'id': 'PB004',
            'name': 'Phishing Response',
            'description': 'Response procedure for phishing attacks',
            'triggers': ['phishing', 'spear phishing', 'suspicious email', 'credential harvest'],
            'steps': [
                {'order': 1, 'action': 'quarantine', 'description': 'Quarantine phishing email', 'automated': True},
                {'order': 2, 'action': 'block', 'description': 'Block sender/domain', 'automated': True},
                {'order': 3, 'action': 'identify', 'description': 'Identify recipients', 'automated': True},
                {'order': 4, 'action': 'check', 'description': 'Check for credential compromise', 'automated': False},
                {'order': 5, 'action': 'notify', 'description': 'Notify affected users', 'automated': True},
                {'order': 6, 'action': 'train', 'description': 'Send security awareness reminder', 'automated': True},
            ],
            'estimated_time': 45,
            'automation_level': 'semi-automated',
            'permissions': ['email_quarantine', 'mail_block'],
            'prerequisites': ['Email gateway integration', 'User notification system']
        },
        {
            'id': 'PB005',
            'name': 'Ransomware Response',
            'description': 'Critical response procedure for ransomware attacks',
            'triggers': ['ransomware', 'encryption', 'ransom'],
            'steps': [
                {'order': 1, 'action': 'isolate', 'description': 'Immediately isolate affected systems', 'automated': True},
                {'order': 2, 'action': 'preserve', 'description': 'Preserve evidence', 'automated': False},
                {'order': 3, 'action': 'identify', 'description': 'Identify ransomware variant', 'automated': False},
                {'order': 4, 'action': 'assess', 'description': 'Assess backup availability', 'automated': False},
                {'order': 5, 'action': 'notify', 'description': 'Notify leadership', 'automated': True},
                {'order': 6, 'action': 'engage', 'description': 'Engage incident response team', 'automated': True},
                {'order': 7, 'action': 'recover', 'description': 'Begin recovery from backups', 'automated': False},
            ],
            'estimated_time': 480,
            'automation_level': 'manual',
            'permissions': ['endpoint_isolation', 'executive_notification'],
            'prerequisites': ['Backup system', 'IR team', 'Legal counsel']
        },
    ]

    # Pre-populated threat actors
    THREAT_ACTORS = [
        ThreatActorProfile(
            id='TA001', name='APT29', aliases=['Cozy Bear', 'The Dukes'],
            actor_type=ThreatActorType.NATION_STATE,
            description='Russian state-sponsored threat actor',
            motivation='Espionage',
            sophistication='advanced',
            target_sectors=['Government', 'Think Tanks', 'Healthcare'],
            target_regions=['North America', 'Europe'],
            known_ttps=['T1059.001', 'T1078', 'T1003'],
            known_tools=['Cobalt Strike', 'Mimikatz', 'WellMess'],
            known_infrastructure=['Compromised servers', 'Cloud services'],
            first_seen=datetime(2008, 1, 1),
            last_seen=datetime.utcnow(),
            confidence=0.95,
            references=['https://attack.mitre.org/groups/G0016/']
        ),
        ThreatActorProfile(
            id='TA002', name='APT28', aliases=['Fancy Bear', 'Sofacy'],
            actor_type=ThreatActorType.NATION_STATE,
            description='Russian state-sponsored threat actor',
            motivation='Espionage, Influence Operations',
            sophistication='advanced',
            target_sectors=['Government', 'Military', 'Media'],
            target_regions=['North America', 'Europe', 'Middle East'],
            known_ttps=['T1059', 'T1071', 'T1048'],
            known_tools=['X-Agent', 'Seduploader', 'Zebrocy'],
            known_infrastructure=['Spear phishing domains', 'C2 servers'],
            first_seen=datetime(2004, 1, 1),
            last_seen=datetime.utcnow(),
            confidence=0.95,
            references=['https://attack.mitre.org/groups/G0007/']
        ),
        ThreatActorProfile(
            id='TA003', name='FIN7', aliases=['Carbanak', 'Navigator Group'],
            actor_type=ThreatActorType.CYBERCRIME,
            description='Financially motivated cybercrime group',
            motivation='Financial gain',
            sophistication='high',
            target_sectors=['Retail', 'Hospitality', 'Finance'],
            target_regions=['North America', 'Europe'],
            known_ttps=['T1059.001', 'T1078', 'T1021'],
            known_tools=['Carbanak', 'Bateleur', 'Griffon'],
            known_infrastructure=['Spear phishing', 'Malicious documents'],
            first_seen=datetime(2013, 1, 1),
            last_seen=datetime.utcnow(),
            confidence=0.90,
            references=['https://attack.mitre.org/groups/G0046/']
        ),
        ThreatActorProfile(
            id='TA004', name='Lazarus Group', aliases=['Hidden Cobra', 'Zinc'],
            actor_type=ThreatActorType.NATION_STATE,
            description='North Korean state-sponsored threat actor',
            motivation='Financial gain, Espionage',
            sophistication='advanced',
            target_sectors=['Finance', 'Cryptocurrency', 'Defense'],
            target_regions=['Global'],
            known_ttps=['T1059', 'T1486', 'T1071'],
            known_tools=['Ratankba', 'Fallchill', 'AppleJeus'],
            known_infrastructure=['Watering holes', 'Fake cryptocurrency apps'],
            first_seen=datetime(2009, 1, 1),
            last_seen=datetime.utcnow(),
            confidence=0.90,
            references=['https://attack.mitre.org/groups/G0032/']
        ),
    ]

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize knowledge base"""
        self.db_path = db_path or Path('/tmp/tsunami_soc_kb.db')
        self._init_database()

        # Pattern matching
        self.vectorizer = TfidfVectorizer(max_features=500, ngram_range=(1, 2))
        self._pattern_vectors: Optional[np.ndarray] = None
        self._pattern_ids: List[str] = []

        # Load pre-populated data
        self._load_initial_data()

    def _init_database(self):
        """Initialize SQLite database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        # Patterns table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS patterns (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                pattern_type TEXT NOT NULL,
                description TEXT,
                indicators TEXT,
                mitre_techniques TEXT,
                detection_signatures TEXT,
                response_steps TEXT,
                false_positive_indicators TEXT,
                confidence REAL,
                occurrences INTEGER,
                first_seen TEXT,
                last_seen TEXT,
                tags TEXT
            )
        ''')

        # Incidents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                alert_id TEXT,
                classification TEXT,
                investigation TEXT,
                decision TEXT,
                outcome TEXT,
                analyst_feedback TEXT,
                created_at TEXT,
                closed_at TEXT
            )
        ''')

        # Threat actors table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_actors (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                aliases TEXT,
                actor_type TEXT,
                description TEXT,
                motivation TEXT,
                sophistication TEXT,
                target_sectors TEXT,
                target_regions TEXT,
                known_ttps TEXT,
                known_tools TEXT,
                known_infrastructure TEXT,
                first_seen TEXT,
                last_seen TEXT,
                confidence REAL,
                references TEXT
            )
        ''')

        # Playbooks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS playbooks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                triggers TEXT,
                steps TEXT,
                estimated_time INTEGER,
                automation_level TEXT,
                permissions TEXT,
                prerequisites TEXT
            )
        ''')

        conn.commit()
        conn.close()

    def _load_initial_data(self):
        """Load pre-populated data into database"""
        # Load threat actors
        for actor in self.THREAT_ACTORS:
            self._store_threat_actor(actor)

        # Load playbooks
        for playbook in self.PLAYBOOKS:
            self._store_playbook(playbook)

        logger.info(f"Knowledge base initialized with {len(self.THREAT_ACTORS)} threat actors and {len(self.PLAYBOOKS)} playbooks")

    def _store_threat_actor(self, actor: ThreatActorProfile):
        """Store threat actor in database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO threat_actors
            (id, name, aliases, actor_type, description, motivation, sophistication,
             target_sectors, target_regions, known_ttps, known_tools,
             known_infrastructure, first_seen, last_seen, confidence, references)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            actor.id, actor.name, json.dumps(actor.aliases), actor.actor_type.value,
            actor.description, actor.motivation, actor.sophistication,
            json.dumps(actor.target_sectors), json.dumps(actor.target_regions),
            json.dumps(actor.known_ttps), json.dumps(actor.known_tools),
            json.dumps(actor.known_infrastructure),
            actor.first_seen.isoformat(), actor.last_seen.isoformat(),
            actor.confidence, json.dumps(actor.references)
        ))

        conn.commit()
        conn.close()

    def _store_playbook(self, playbook: Dict[str, Any]):
        """Store playbook in database"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('''
            INSERT OR REPLACE INTO playbooks
            (id, name, description, triggers, steps, estimated_time,
             automation_level, permissions, prerequisites)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            playbook['id'], playbook['name'], playbook['description'],
            json.dumps(playbook['triggers']), json.dumps(playbook['steps']),
            playbook['estimated_time'], playbook['automation_level'],
            json.dumps(playbook['permissions']), json.dumps(playbook['prerequisites'])
        ))

        conn.commit()
        conn.close()

    def store_incident(
        self,
        alert_id: str,
        classification: Dict[str, Any],
        investigation: Dict[str, Any],
        decision: Dict[str, Any],
        outcome: str,
        analyst_feedback: Optional[str] = None
    ):
        """Store incident for learning"""
        incident_id = hashlib.md5(f"{alert_id}:{datetime.utcnow().isoformat()}".encode()).hexdigest()

        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO incidents
            (id, alert_id, classification, investigation, decision, outcome,
             analyst_feedback, created_at, closed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id, alert_id,
            json.dumps(classification), json.dumps(investigation),
            json.dumps(decision), outcome, analyst_feedback,
            datetime.utcnow().isoformat(), None
        ))

        conn.commit()
        conn.close()

        # Extract and store pattern
        self._extract_pattern(classification, investigation, decision, outcome)

    def _extract_pattern(
        self,
        classification: Dict[str, Any],
        investigation: Dict[str, Any],
        decision: Dict[str, Any],
        outcome: str
    ):
        """Extract pattern from incident"""
        category = classification.get('category', 'unknown')
        mitre_techniques = investigation.get('mitre_techniques', [])

        # Create pattern ID
        pattern_id = hashlib.md5(f"{category}:{':'.join(mitre_techniques)}".encode()).hexdigest()[:16]

        # Check if pattern exists
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('SELECT occurrences FROM patterns WHERE id = ?', (pattern_id,))
        existing = cursor.fetchone()

        if existing:
            # Update existing pattern
            cursor.execute('''
                UPDATE patterns
                SET occurrences = occurrences + 1, last_seen = ?
                WHERE id = ?
            ''', (datetime.utcnow().isoformat(), pattern_id))
        else:
            # Create new pattern
            pattern_type = PatternType.ATTACK_PATTERN if outcome == 'true_positive' else PatternType.FALSE_POSITIVE_PATTERN

            cursor.execute('''
                INSERT INTO patterns
                (id, name, pattern_type, description, indicators, mitre_techniques,
                 detection_signatures, response_steps, false_positive_indicators,
                 confidence, occurrences, first_seen, last_seen, tags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern_id,
                f"{category} pattern",
                pattern_type.value,
                f"Pattern identified from {category} incidents",
                json.dumps(investigation.get('indicators', [])),
                json.dumps(mitre_techniques),
                json.dumps([]),
                json.dumps(decision.get('recommended_actions', [])),
                json.dumps([]),
                0.5,  # Initial confidence
                1,
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
                json.dumps([category])
            ))

        conn.commit()
        conn.close()

    def get_similar_incidents(
        self,
        alert_data: Dict[str, Any],
        classification: Dict[str, Any],
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Find similar past incidents"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        category = classification.get('category', 'unknown')

        cursor.execute('''
            SELECT * FROM incidents
            WHERE classification LIKE ?
            ORDER BY created_at DESC
            LIMIT ?
        ''', (f'%"{category}"%', limit * 2))

        rows = cursor.fetchall()
        conn.close()

        # Parse and score similarity
        similar = []
        for row in rows:
            try:
                incident = {
                    'id': row[0],
                    'alert_id': row[1],
                    'classification': json.loads(row[2]),
                    'investigation': json.loads(row[3]),
                    'decision': json.loads(row[4]),
                    'outcome': row[5],
                    'created_at': row[7]
                }

                # Calculate similarity score
                score = self._calculate_similarity(alert_data, classification, incident)
                incident['similarity_score'] = score
                similar.append(incident)
            except Exception:
                continue

        # Sort by similarity and return top results
        similar.sort(key=lambda x: x['similarity_score'], reverse=True)
        return similar[:limit]

    def _calculate_similarity(
        self,
        alert_data: Dict[str, Any],
        classification: Dict[str, Any],
        incident: Dict[str, Any]
    ) -> float:
        """Calculate similarity between current alert and past incident"""
        score = 0.0

        # Category match
        if classification.get('category') == incident['classification'].get('category'):
            score += 0.4

        # Severity match
        if classification.get('severity') == incident['classification'].get('severity'):
            score += 0.2

        # MITRE techniques overlap
        current_ttps = set(alert_data.get('mitre_techniques', []))
        incident_ttps = set(incident['investigation'].get('mitre_techniques', []))
        if current_ttps and incident_ttps:
            overlap = len(current_ttps & incident_ttps) / len(current_ttps | incident_ttps)
            score += 0.3 * overlap

        # Source match
        if alert_data.get('source') == incident['classification'].get('source'):
            score += 0.1

        return min(1.0, score)

    def get_playbook_recommendations(
        self,
        alert_data: Dict[str, Any],
        classification: Dict[str, Any],
        investigation: Dict[str, Any]
    ) -> List[PlaybookRecommendation]:
        """Get playbook recommendations for an incident"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM playbooks')
        rows = cursor.fetchall()
        conn.close()

        recommendations = []

        # Get text to match against
        search_text = f"{alert_data.get('title', '')} {alert_data.get('description', '')} {classification.get('category', '')}".lower()

        for row in rows:
            playbook = {
                'id': row[0],
                'name': row[1],
                'description': row[2],
                'triggers': json.loads(row[3]),
                'steps': json.loads(row[4]),
                'estimated_time': row[5],
                'automation_level': row[6],
                'permissions': json.loads(row[7]),
                'prerequisites': json.loads(row[8])
            }

            # Calculate relevance score
            matching_triggers = [t for t in playbook['triggers'] if t.lower() in search_text]
            if matching_triggers:
                relevance_score = len(matching_triggers) / len(playbook['triggers'])

                recommendations.append(PlaybookRecommendation(
                    playbook_id=playbook['id'],
                    playbook_name=playbook['name'],
                    description=playbook['description'],
                    relevance_score=relevance_score,
                    matching_indicators=matching_triggers,
                    steps=playbook['steps'],
                    estimated_time_minutes=playbook['estimated_time'],
                    automation_level=playbook['automation_level'],
                    required_permissions=playbook['permissions'],
                    prerequisites=playbook['prerequisites']
                ))

        # Sort by relevance
        recommendations.sort(key=lambda x: x.relevance_score, reverse=True)
        return recommendations[:3]

    def get_mitre_techniques(
        self,
        technique_ids: List[str]
    ) -> List[MITRETechnique]:
        """Get MITRE technique details"""
        techniques = []
        for tid in technique_ids:
            if tid in self.MITRE_TECHNIQUES:
                techniques.append(self.MITRE_TECHNIQUES[tid])
        return techniques

    def map_to_mitre(
        self,
        alert_data: Dict[str, Any],
        classification: Dict[str, Any]
    ) -> List[str]:
        """Map alert to MITRE ATT&CK techniques"""
        mapped_techniques = []

        category = classification.get('category', '').lower()
        description = f"{alert_data.get('title', '')} {alert_data.get('description', '')}".lower()

        # Category-based mapping
        category_mappings = {
            'malware': ['T1059', 'T1486'],
            'credential_theft': ['T1003', 'T1078'],
            'lateral_movement': ['T1021'],
            'command_and_control': ['T1071'],
            'data_exfiltration': ['T1048'],
            'intrusion': ['T1059', 'T1078'],
        }

        if category in category_mappings:
            mapped_techniques.extend(category_mappings[category])

        # Keyword-based mapping
        keyword_mappings = {
            'powershell': 'T1059.001',
            'mimikatz': 'T1003',
            'ransomware': 'T1486',
            'rdp': 'T1021',
            'valid account': 'T1078',
        }

        for keyword, technique in keyword_mappings.items():
            if keyword in description:
                if technique not in mapped_techniques:
                    mapped_techniques.append(technique)

        return mapped_techniques

    def get_threat_actor_matches(
        self,
        indicators: List[str],
        mitre_techniques: List[str]
    ) -> List[ThreatActorProfile]:
        """Find matching threat actors based on indicators and TTPs"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM threat_actors')
        rows = cursor.fetchall()
        conn.close()

        matches = []

        for row in rows:
            actor = ThreatActorProfile(
                id=row[0],
                name=row[1],
                aliases=json.loads(row[2]),
                actor_type=ThreatActorType(row[3]),
                description=row[4],
                motivation=row[5],
                sophistication=row[6],
                target_sectors=json.loads(row[7]),
                target_regions=json.loads(row[8]),
                known_ttps=json.loads(row[9]),
                known_tools=json.loads(row[10]),
                known_infrastructure=json.loads(row[11]),
                first_seen=datetime.fromisoformat(row[12]),
                last_seen=datetime.fromisoformat(row[13]),
                confidence=row[14],
                references=json.loads(row[15])
            )

            # Check TTP overlap
            actor_ttps = set(actor.known_ttps)
            alert_ttps = set(mitre_techniques)
            ttp_overlap = actor_ttps & alert_ttps

            if ttp_overlap:
                match_confidence = len(ttp_overlap) / len(actor_ttps) * actor.confidence
                if match_confidence > 0.2:
                    matches.append((actor, match_confidence))

        # Sort by confidence
        matches.sort(key=lambda x: x[1], reverse=True)
        return [m[0] for m in matches[:3]]

    def get_patterns(self, pattern_type: Optional[PatternType] = None, limit: int = 20) -> List[IncidentPattern]:
        """Get stored patterns"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        if pattern_type:
            cursor.execute('''
                SELECT * FROM patterns WHERE pattern_type = ?
                ORDER BY occurrences DESC LIMIT ?
            ''', (pattern_type.value, limit))
        else:
            cursor.execute('''
                SELECT * FROM patterns ORDER BY occurrences DESC LIMIT ?
            ''', (limit,))

        rows = cursor.fetchall()
        conn.close()

        patterns = []
        for row in rows:
            patterns.append(IncidentPattern(
                id=row[0],
                name=row[1],
                pattern_type=PatternType(row[2]),
                description=row[3],
                indicators=json.loads(row[4]) if row[4] else [],
                mitre_techniques=json.loads(row[5]) if row[5] else [],
                detection_signatures=json.loads(row[6]) if row[6] else [],
                response_steps=json.loads(row[7]) if row[7] else [],
                false_positive_indicators=json.loads(row[8]) if row[8] else [],
                confidence=row[9] or 0.5,
                occurrences=row[10] or 1,
                first_seen=datetime.fromisoformat(row[11]) if row[11] else datetime.utcnow(),
                last_seen=datetime.fromisoformat(row[12]) if row[12] else datetime.utcnow(),
                tags=json.loads(row[13]) if row[13] else []
            ))

        return patterns

    def get_stats(self) -> Dict[str, Any]:
        """Get knowledge base statistics"""
        conn = sqlite3.connect(str(self.db_path))
        cursor = conn.cursor()

        cursor.execute('SELECT COUNT(*) FROM patterns')
        pattern_count = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM incidents')
        incident_count = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM threat_actors')
        actor_count = cursor.fetchone()[0]

        cursor.execute('SELECT COUNT(*) FROM playbooks')
        playbook_count = cursor.fetchone()[0]

        conn.close()

        return {
            'patterns': pattern_count,
            'incidents': incident_count,
            'threat_actors': actor_count,
            'playbooks': playbook_count,
            'mitre_techniques': len(self.MITRE_TECHNIQUES)
        }


# Global knowledge base instance
_knowledge_base: Optional[KnowledgeBase] = None


def get_knowledge_base() -> KnowledgeBase:
    """Get or create the global knowledge base instance"""
    global _knowledge_base
    if _knowledge_base is None:
        _knowledge_base = KnowledgeBase()
    return _knowledge_base
