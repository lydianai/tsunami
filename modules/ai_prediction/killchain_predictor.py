#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI KILL CHAIN PREDICTOR v5.0
    Attack Progression Prediction & Kill Chain Analysis
================================================================================

    Features:
    - MITRE ATT&CK Kill Chain Stage Prediction
    - Attack Path Probability Modeling
    - Next-Stage Attack Prediction
    - Real-time Kill Chain Tracking
    - Attack Campaign Correlation

================================================================================
"""

import os
import json
import logging
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict
from enum import Enum, IntEnum
from collections import defaultdict, deque
import hashlib
import threading
from pathlib import Path

# ML Libraries
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KillChainStage(IntEnum):
    """
    MITRE ATT&CK-based Kill Chain Stages

    Order represents typical attack progression
    """
    RECONNAISSANCE = 1      # TA0043 - Information gathering
    RESOURCE_DEVELOPMENT = 2  # TA0042 - Acquiring infrastructure
    INITIAL_ACCESS = 3      # TA0001 - Getting in
    EXECUTION = 4           # TA0002 - Running malicious code
    PERSISTENCE = 5         # TA0003 - Maintaining foothold
    PRIVILEGE_ESCALATION = 6  # TA0004 - Getting higher access
    DEFENSE_EVASION = 7     # TA0005 - Avoiding detection
    CREDENTIAL_ACCESS = 8   # TA0006 - Stealing credentials
    DISCOVERY = 9           # TA0007 - Learning the environment
    LATERAL_MOVEMENT = 10   # TA0008 - Moving through network
    COLLECTION = 11         # TA0009 - Gathering data
    COMMAND_AND_CONTROL = 12  # TA0011 - Communicating with malware
    EXFILTRATION = 13       # TA0010 - Stealing data
    IMPACT = 14             # TA0040 - Causing damage


class AttackTechnique(Enum):
    """Common MITRE ATT&CK Techniques"""
    # Reconnaissance
    ACTIVE_SCANNING = "T1595"
    GATHER_VICTIM_INFO = "T1589"
    SEARCH_VICTIM_NETWORKS = "T1590"

    # Initial Access
    DRIVE_BY_COMPROMISE = "T1189"
    EXPLOIT_PUBLIC_APP = "T1190"
    PHISHING = "T1566"
    SUPPLY_CHAIN = "T1195"
    VALID_ACCOUNTS = "T1078"

    # Execution
    COMMAND_SCRIPT = "T1059"
    SCHEDULED_TASK = "T1053"
    USER_EXECUTION = "T1204"

    # Persistence
    ACCOUNT_MANIPULATION = "T1098"
    CREATE_ACCOUNT = "T1136"
    BOOT_AUTOSTART = "T1547"

    # Privilege Escalation
    EXPLOITATION_PRIV = "T1068"
    PROCESS_INJECTION = "T1055"
    SUDO_ABUSE = "T1548"

    # Defense Evasion
    MASQUERADING = "T1036"
    OBFUSCATION = "T1027"
    DISABLE_SECURITY = "T1562"

    # Credential Access
    BRUTE_FORCE = "T1110"
    CREDENTIAL_DUMPING = "T1003"
    KEYLOGGER = "T1056"

    # Discovery
    ACCOUNT_DISCOVERY = "T1087"
    NETWORK_SCANNING = "T1046"
    SYSTEM_INFO = "T1082"

    # Lateral Movement
    REMOTE_SERVICES = "T1021"
    LATERAL_TOOL = "T1570"
    PASS_THE_HASH = "T1550"

    # Collection
    DATA_FROM_LOCAL = "T1005"
    DATA_STAGED = "T1074"
    SCREEN_CAPTURE = "T1113"

    # C2
    APP_LAYER_PROTOCOL = "T1071"
    ENCRYPTED_CHANNEL = "T1573"
    PROXY = "T1090"

    # Exfiltration
    EXFIL_C2 = "T1041"
    EXFIL_WEB = "T1567"
    AUTOMATED_EXFIL = "T1020"

    # Impact
    DATA_DESTRUCTION = "T1485"
    RANSOMWARE = "T1486"
    SERVICE_STOP = "T1489"


@dataclass
class AttackEvent:
    """Individual attack event/indicator"""
    event_id: str
    timestamp: datetime
    stage: KillChainStage
    technique: Optional[AttackTechnique] = None
    technique_id: Optional[str] = None
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None
    target_asset: Optional[str] = None
    confidence: float = 0.8
    raw_data: Dict = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)


@dataclass
class AttackPath:
    """Predicted or observed attack path"""
    path_id: str
    campaign_id: Optional[str] = None
    stages_observed: List[KillChainStage] = field(default_factory=list)
    stages_predicted: List[KillChainStage] = field(default_factory=list)
    current_stage: Optional[KillChainStage] = None
    next_stage_probability: Dict[str, float] = field(default_factory=dict)
    overall_progress: float = 0.0  # 0.0 to 1.0
    risk_score: float = 0.0
    affected_assets: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    events: List[AttackEvent] = field(default_factory=list)


@dataclass
class KillChainPrediction:
    """Kill chain stage prediction result"""
    prediction_id: str
    timestamp: datetime
    current_stage: KillChainStage
    current_stage_confidence: float
    next_stage: Optional[KillChainStage]
    next_stage_probability: float
    time_to_next_stage_hours: Optional[float]
    attack_path: AttackPath
    risk_level: str  # critical, high, medium, low
    recommended_mitigations: List[str]
    detection_gaps: List[str]


class KillChainPredictor:
    """
    Kill Chain Attack Prediction Engine

    Uses ML to:
    - Classify current attack stage from indicators
    - Predict next likely attack phase
    - Estimate time to progression
    - Calculate attack path probabilities
    """

    # Stage transition probabilities (Markov model baseline)
    BASELINE_TRANSITIONS = {
        KillChainStage.RECONNAISSANCE: {
            KillChainStage.RESOURCE_DEVELOPMENT: 0.3,
            KillChainStage.INITIAL_ACCESS: 0.5,
            KillChainStage.RECONNAISSANCE: 0.2
        },
        KillChainStage.RESOURCE_DEVELOPMENT: {
            KillChainStage.INITIAL_ACCESS: 0.7,
            KillChainStage.RECONNAISSANCE: 0.2,
            KillChainStage.RESOURCE_DEVELOPMENT: 0.1
        },
        KillChainStage.INITIAL_ACCESS: {
            KillChainStage.EXECUTION: 0.6,
            KillChainStage.PERSISTENCE: 0.3,
            KillChainStage.INITIAL_ACCESS: 0.1
        },
        KillChainStage.EXECUTION: {
            KillChainStage.PERSISTENCE: 0.4,
            KillChainStage.PRIVILEGE_ESCALATION: 0.3,
            KillChainStage.DEFENSE_EVASION: 0.2,
            KillChainStage.DISCOVERY: 0.1
        },
        KillChainStage.PERSISTENCE: {
            KillChainStage.PRIVILEGE_ESCALATION: 0.35,
            KillChainStage.DEFENSE_EVASION: 0.25,
            KillChainStage.DISCOVERY: 0.25,
            KillChainStage.CREDENTIAL_ACCESS: 0.15
        },
        KillChainStage.PRIVILEGE_ESCALATION: {
            KillChainStage.CREDENTIAL_ACCESS: 0.35,
            KillChainStage.DISCOVERY: 0.3,
            KillChainStage.LATERAL_MOVEMENT: 0.25,
            KillChainStage.DEFENSE_EVASION: 0.1
        },
        KillChainStage.DEFENSE_EVASION: {
            KillChainStage.CREDENTIAL_ACCESS: 0.3,
            KillChainStage.DISCOVERY: 0.3,
            KillChainStage.LATERAL_MOVEMENT: 0.2,
            KillChainStage.COMMAND_AND_CONTROL: 0.2
        },
        KillChainStage.CREDENTIAL_ACCESS: {
            KillChainStage.LATERAL_MOVEMENT: 0.5,
            KillChainStage.DISCOVERY: 0.3,
            KillChainStage.PRIVILEGE_ESCALATION: 0.2
        },
        KillChainStage.DISCOVERY: {
            KillChainStage.LATERAL_MOVEMENT: 0.4,
            KillChainStage.COLLECTION: 0.3,
            KillChainStage.CREDENTIAL_ACCESS: 0.2,
            KillChainStage.COMMAND_AND_CONTROL: 0.1
        },
        KillChainStage.LATERAL_MOVEMENT: {
            KillChainStage.COLLECTION: 0.35,
            KillChainStage.DISCOVERY: 0.25,
            KillChainStage.COMMAND_AND_CONTROL: 0.25,
            KillChainStage.CREDENTIAL_ACCESS: 0.15
        },
        KillChainStage.COLLECTION: {
            KillChainStage.COMMAND_AND_CONTROL: 0.35,
            KillChainStage.EXFILTRATION: 0.4,
            KillChainStage.LATERAL_MOVEMENT: 0.15,
            KillChainStage.IMPACT: 0.1
        },
        KillChainStage.COMMAND_AND_CONTROL: {
            KillChainStage.EXFILTRATION: 0.45,
            KillChainStage.COLLECTION: 0.25,
            KillChainStage.LATERAL_MOVEMENT: 0.2,
            KillChainStage.IMPACT: 0.1
        },
        KillChainStage.EXFILTRATION: {
            KillChainStage.IMPACT: 0.4,
            KillChainStage.EXFILTRATION: 0.3,
            KillChainStage.COLLECTION: 0.2,
            KillChainStage.COMMAND_AND_CONTROL: 0.1
        },
        KillChainStage.IMPACT: {
            KillChainStage.IMPACT: 0.7,
            KillChainStage.EXFILTRATION: 0.2,
            KillChainStage.COMMAND_AND_CONTROL: 0.1
        }
    }

    # Technique to stage mapping
    TECHNIQUE_STAGE_MAP = {
        # Reconnaissance
        'T1595': KillChainStage.RECONNAISSANCE,
        'T1589': KillChainStage.RECONNAISSANCE,
        'T1590': KillChainStage.RECONNAISSANCE,
        # Initial Access
        'T1189': KillChainStage.INITIAL_ACCESS,
        'T1190': KillChainStage.INITIAL_ACCESS,
        'T1566': KillChainStage.INITIAL_ACCESS,
        'T1195': KillChainStage.INITIAL_ACCESS,
        'T1078': KillChainStage.INITIAL_ACCESS,
        # Execution
        'T1059': KillChainStage.EXECUTION,
        'T1053': KillChainStage.EXECUTION,
        'T1204': KillChainStage.EXECUTION,
        # Persistence
        'T1098': KillChainStage.PERSISTENCE,
        'T1136': KillChainStage.PERSISTENCE,
        'T1547': KillChainStage.PERSISTENCE,
        # Privilege Escalation
        'T1068': KillChainStage.PRIVILEGE_ESCALATION,
        'T1055': KillChainStage.PRIVILEGE_ESCALATION,
        'T1548': KillChainStage.PRIVILEGE_ESCALATION,
        # Defense Evasion
        'T1036': KillChainStage.DEFENSE_EVASION,
        'T1027': KillChainStage.DEFENSE_EVASION,
        'T1562': KillChainStage.DEFENSE_EVASION,
        # Credential Access
        'T1110': KillChainStage.CREDENTIAL_ACCESS,
        'T1003': KillChainStage.CREDENTIAL_ACCESS,
        'T1056': KillChainStage.CREDENTIAL_ACCESS,
        # Discovery
        'T1087': KillChainStage.DISCOVERY,
        'T1046': KillChainStage.DISCOVERY,
        'T1082': KillChainStage.DISCOVERY,
        # Lateral Movement
        'T1021': KillChainStage.LATERAL_MOVEMENT,
        'T1570': KillChainStage.LATERAL_MOVEMENT,
        'T1550': KillChainStage.LATERAL_MOVEMENT,
        # Collection
        'T1005': KillChainStage.COLLECTION,
        'T1074': KillChainStage.COLLECTION,
        'T1113': KillChainStage.COLLECTION,
        # C2
        'T1071': KillChainStage.COMMAND_AND_CONTROL,
        'T1573': KillChainStage.COMMAND_AND_CONTROL,
        'T1090': KillChainStage.COMMAND_AND_CONTROL,
        # Exfiltration
        'T1041': KillChainStage.EXFILTRATION,
        'T1567': KillChainStage.EXFILTRATION,
        'T1020': KillChainStage.EXFILTRATION,
        # Impact
        'T1485': KillChainStage.IMPACT,
        'T1486': KillChainStage.IMPACT,
        'T1489': KillChainStage.IMPACT,
    }

    # Average time between stages (hours)
    STAGE_DWELL_TIMES = {
        KillChainStage.RECONNAISSANCE: (24, 168),      # 1-7 days
        KillChainStage.RESOURCE_DEVELOPMENT: (24, 720),  # 1-30 days
        KillChainStage.INITIAL_ACCESS: (1, 24),         # 1-24 hours
        KillChainStage.EXECUTION: (0.1, 4),             # Minutes to hours
        KillChainStage.PERSISTENCE: (0.5, 12),          # 30 min to 12 hours
        KillChainStage.PRIVILEGE_ESCALATION: (0.5, 48),  # 30 min to 2 days
        KillChainStage.DEFENSE_EVASION: (0.1, 24),      # Continuous
        KillChainStage.CREDENTIAL_ACCESS: (1, 72),      # 1 hour to 3 days
        KillChainStage.DISCOVERY: (2, 168),             # 2 hours to 7 days
        KillChainStage.LATERAL_MOVEMENT: (2, 720),      # 2 hours to 30 days
        KillChainStage.COLLECTION: (4, 720),            # 4 hours to 30 days
        KillChainStage.COMMAND_AND_CONTROL: (0.1, 8760),  # Continuous
        KillChainStage.EXFILTRATION: (1, 720),          # 1 hour to 30 days
        KillChainStage.IMPACT: (0.1, 24),               # Minutes to 1 day
    }

    def __init__(
        self,
        model_path: Optional[str] = None,
        adaptive_transitions: bool = True
    ):
        """
        Initialize Kill Chain Predictor

        Args:
            model_path: Path to save/load models
            adaptive_transitions: Enable learning of transition probabilities
        """
        self.model_path = model_path or "/tmp/tsunami_killchain_models"
        self.adaptive_transitions = adaptive_transitions

        # Stage classifier
        self.stage_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )

        # Next-stage predictor
        self.transition_predictor = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        )

        # Label encoders
        self.stage_encoder = LabelEncoder()
        self.technique_encoder = LabelEncoder()

        # Learned transition probabilities
        self.learned_transitions = self.BASELINE_TRANSITIONS.copy()
        self.transition_counts: Dict[KillChainStage, Dict[KillChainStage, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Active attack paths
        self.active_paths: Dict[str, AttackPath] = {}
        self.completed_paths: deque = deque(maxlen=1000)

        # Event history
        self.event_history: deque = deque(maxlen=100000)

        # State
        self.is_trained = False

        # Thread safety
        self._lock = threading.RLock()

        # Initialize stage encoder with all stages
        self.stage_encoder.fit([s.name for s in KillChainStage])

    def _generate_id(self, prefix: str = "") -> str:
        """Generate unique ID"""
        content = f"{prefix}{datetime.now().isoformat()}{os.urandom(8)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _extract_event_features(self, event: AttackEvent) -> np.ndarray:
        """Extract features from attack event"""
        features = []

        # Stage as numeric
        features.append(float(event.stage.value))

        # Technique ID (hashed to numeric)
        if event.technique_id:
            technique_hash = int(hashlib.md5(event.technique_id.encode()).hexdigest()[:8], 16)
            features.append(technique_hash % 1000)
        else:
            features.append(0)

        # Temporal features
        features.append(event.timestamp.hour)
        features.append(event.timestamp.weekday())
        features.append(1 if event.timestamp.weekday() >= 5 else 0)

        # Confidence
        features.append(event.confidence)

        # Number of indicators
        features.append(len(event.indicators))

        # Has source IP
        features.append(1 if event.source_ip else 0)

        # Has target IP
        features.append(1 if event.target_ip else 0)

        return np.array(features)

    def _extract_path_features(self, path: AttackPath) -> np.ndarray:
        """Extract features from attack path for next-stage prediction"""
        features = []

        # Current stage
        if path.current_stage:
            features.append(float(path.current_stage.value))
        else:
            features.append(0)

        # Stages observed (binary vector)
        for stage in KillChainStage:
            features.append(1 if stage in path.stages_observed else 0)

        # Number of stages observed
        features.append(len(path.stages_observed))

        # Progress
        features.append(path.overall_progress)

        # Time since first event
        if path.events:
            time_span = (path.last_seen - path.first_seen).total_seconds() / 3600  # hours
            features.append(time_span)
        else:
            features.append(0)

        # Number of techniques used
        features.append(len(path.techniques_used))

        # Number of affected assets
        features.append(len(path.affected_assets))

        # Risk score
        features.append(path.risk_score)

        return np.array(features)

    def map_indicator_to_stage(
        self,
        indicator: Dict[str, Any]
    ) -> Tuple[Optional[KillChainStage], float]:
        """
        Map an indicator/event to a kill chain stage

        Args:
            indicator: Dictionary containing indicator data

        Returns:
            Tuple of (stage, confidence)
        """
        # Check for technique ID
        technique_id = indicator.get('technique_id') or indicator.get('mitre_technique')
        if technique_id and technique_id in self.TECHNIQUE_STAGE_MAP:
            return self.TECHNIQUE_STAGE_MAP[technique_id], 0.9

        # Keyword-based mapping
        indicator_type = indicator.get('type', '').lower()
        description = indicator.get('description', '').lower()

        keyword_stage_map = {
            'scan': (KillChainStage.RECONNAISSANCE, 0.7),
            'recon': (KillChainStage.RECONNAISSANCE, 0.8),
            'phishing': (KillChainStage.INITIAL_ACCESS, 0.85),
            'exploit': (KillChainStage.INITIAL_ACCESS, 0.8),
            'execute': (KillChainStage.EXECUTION, 0.7),
            'script': (KillChainStage.EXECUTION, 0.6),
            'persist': (KillChainStage.PERSISTENCE, 0.75),
            'autostart': (KillChainStage.PERSISTENCE, 0.8),
            'privilege': (KillChainStage.PRIVILEGE_ESCALATION, 0.75),
            'escalat': (KillChainStage.PRIVILEGE_ESCALATION, 0.75),
            'evasion': (KillChainStage.DEFENSE_EVASION, 0.7),
            'obfuscat': (KillChainStage.DEFENSE_EVASION, 0.7),
            'credential': (KillChainStage.CREDENTIAL_ACCESS, 0.8),
            'password': (KillChainStage.CREDENTIAL_ACCESS, 0.7),
            'brute': (KillChainStage.CREDENTIAL_ACCESS, 0.85),
            'discover': (KillChainStage.DISCOVERY, 0.7),
            'enum': (KillChainStage.DISCOVERY, 0.7),
            'lateral': (KillChainStage.LATERAL_MOVEMENT, 0.85),
            'remote': (KillChainStage.LATERAL_MOVEMENT, 0.6),
            'collect': (KillChainStage.COLLECTION, 0.7),
            'stage': (KillChainStage.COLLECTION, 0.65),
            'c2': (KillChainStage.COMMAND_AND_CONTROL, 0.85),
            'beacon': (KillChainStage.COMMAND_AND_CONTROL, 0.8),
            'exfil': (KillChainStage.EXFILTRATION, 0.85),
            'upload': (KillChainStage.EXFILTRATION, 0.6),
            'ransom': (KillChainStage.IMPACT, 0.9),
            'encrypt': (KillChainStage.IMPACT, 0.7),
            'destruct': (KillChainStage.IMPACT, 0.85),
        }

        combined_text = f"{indicator_type} {description}"

        for keyword, (stage, conf) in keyword_stage_map.items():
            if keyword in combined_text:
                return stage, conf

        return None, 0.0

    def process_event(
        self,
        event_data: Dict[str, Any],
        campaign_id: Optional[str] = None
    ) -> Tuple[AttackEvent, Optional[AttackPath]]:
        """
        Process a security event and update kill chain tracking

        Args:
            event_data: Event data dictionary
            campaign_id: Optional campaign to associate with

        Returns:
            Tuple of (AttackEvent, AttackPath if updated)
        """
        with self._lock:
            # Map to stage
            stage, confidence = self.map_indicator_to_stage(event_data)

            if stage is None:
                # Can't determine stage, use ML classifier if trained
                if self.is_trained:
                    # Use default stage based on event type
                    stage = KillChainStage.RECONNAISSANCE
                    confidence = 0.5
                else:
                    stage = KillChainStage.RECONNAISSANCE
                    confidence = 0.3

            # Create event
            event = AttackEvent(
                event_id=self._generate_id("evt_"),
                timestamp=event_data.get('timestamp', datetime.now()),
                stage=stage,
                technique_id=event_data.get('technique_id'),
                source_ip=event_data.get('source_ip') or event_data.get('src_ip'),
                target_ip=event_data.get('target_ip') or event_data.get('dest_ip'),
                target_asset=event_data.get('target_asset') or event_data.get('host'),
                confidence=confidence,
                raw_data=event_data,
                indicators=event_data.get('indicators', [])
            )

            # Store in history
            self.event_history.append(event)

            # Update or create attack path
            path = self._update_attack_path(event, campaign_id)

            return event, path

    def _update_attack_path(
        self,
        event: AttackEvent,
        campaign_id: Optional[str] = None
    ) -> Optional[AttackPath]:
        """Update or create attack path based on event"""
        # Try to find existing path for this source/target
        path_key = campaign_id or f"{event.source_ip}_{event.target_ip}"

        if path_key in self.active_paths:
            path = self.active_paths[path_key]
        else:
            # Create new path
            path = AttackPath(
                path_id=self._generate_id("path_"),
                campaign_id=campaign_id,
                first_seen=event.timestamp,
            )
            self.active_paths[path_key] = path

        # Update path
        if event.stage not in path.stages_observed:
            # Record transition
            if path.current_stage:
                self.transition_counts[path.current_stage][event.stage] += 1

            path.stages_observed.append(event.stage)

        path.current_stage = event.stage
        path.last_seen = event.timestamp
        path.events.append(event)

        if event.technique_id and event.technique_id not in path.techniques_used:
            path.techniques_used.append(event.technique_id)

        if event.target_asset and event.target_asset not in path.affected_assets:
            path.affected_assets.append(event.target_asset)

        # Calculate progress
        max_stage = max(s.value for s in path.stages_observed)
        path.overall_progress = max_stage / len(KillChainStage)

        # Calculate risk score
        path.risk_score = self._calculate_path_risk(path)

        # Predict next stage
        path.next_stage_probability = self._predict_next_stage_probabilities(path)
        path.stages_predicted = self._predict_likely_path(path)

        return path

    def _calculate_path_risk(self, path: AttackPath) -> float:
        """Calculate risk score for an attack path"""
        risk = 0.0

        # Base risk from progress
        risk += path.overall_progress * 0.5

        # Risk from critical stages
        critical_stages = {
            KillChainStage.LATERAL_MOVEMENT,
            KillChainStage.COMMAND_AND_CONTROL,
            KillChainStage.EXFILTRATION,
            KillChainStage.IMPACT
        }

        for stage in path.stages_observed:
            if stage in critical_stages:
                risk += 0.15

        # Risk from number of affected assets
        risk += min(len(path.affected_assets) * 0.05, 0.3)

        # Time-based risk (faster = more aggressive)
        if path.events and len(path.events) > 1:
            time_span = (path.last_seen - path.first_seen).total_seconds() / 3600
            stages_per_hour = len(path.stages_observed) / max(time_span, 1)
            if stages_per_hour > 0.5:  # More than 1 stage every 2 hours
                risk += 0.2

        return min(risk, 1.0)

    def _predict_next_stage_probabilities(
        self,
        path: AttackPath
    ) -> Dict[str, float]:
        """Predict probabilities for next kill chain stage"""
        if not path.current_stage:
            return {}

        # Get baseline transitions
        if path.current_stage in self.learned_transitions:
            transitions = self.learned_transitions[path.current_stage].copy()
        else:
            transitions = {}

        # Adjust based on observed patterns (if adaptive)
        if self.adaptive_transitions and path.current_stage in self.transition_counts:
            counts = self.transition_counts[path.current_stage]
            total = sum(counts.values())

            if total > 10:  # Only if sufficient data
                for next_stage, count in counts.items():
                    learned_prob = count / total
                    # Blend with baseline
                    if next_stage.name in transitions:
                        transitions[next_stage.name] = (
                            transitions[next_stage.name] * 0.3 + learned_prob * 0.7
                        )
                    else:
                        transitions[next_stage.name] = learned_prob

        # Convert to stage names
        result = {}
        for stage, prob in transitions.items():
            if isinstance(stage, KillChainStage):
                result[stage.name] = prob
            else:
                result[stage] = prob

        return result

    def _predict_likely_path(self, path: AttackPath) -> List[KillChainStage]:
        """Predict likely future stages based on current path"""
        predicted = []
        current = path.current_stage

        if not current:
            return predicted

        # Simulate up to 5 future stages
        for _ in range(5):
            if current in self.learned_transitions:
                transitions = self.learned_transitions[current]
                if transitions:
                    # Get most likely next stage
                    next_stage = max(transitions.items(), key=lambda x: x[1])[0]
                    if isinstance(next_stage, str):
                        next_stage = KillChainStage[next_stage]
                    predicted.append(next_stage)
                    current = next_stage
                else:
                    break
            else:
                break

        return predicted

    def predict(
        self,
        events: List[Dict[str, Any]],
        campaign_id: Optional[str] = None
    ) -> KillChainPrediction:
        """
        Generate kill chain prediction from events

        Args:
            events: List of security events
            campaign_id: Optional campaign identifier

        Returns:
            KillChainPrediction with current state and predictions
        """
        with self._lock:
            # Process all events
            attack_path = None
            for event_data in events:
                _, attack_path = self.process_event(event_data, campaign_id)

            if attack_path is None:
                # Create minimal path
                attack_path = AttackPath(
                    path_id=self._generate_id("path_"),
                    campaign_id=campaign_id,
                    current_stage=KillChainStage.RECONNAISSANCE
                )

            # Get next stage prediction
            next_stage_probs = attack_path.next_stage_probability
            if next_stage_probs:
                next_stage_name = max(next_stage_probs.items(), key=lambda x: x[1])[0]
                next_stage = KillChainStage[next_stage_name]
                next_stage_prob = next_stage_probs[next_stage_name]
            else:
                next_stage = None
                next_stage_prob = 0.0

            # Estimate time to next stage
            time_to_next = None
            if attack_path.current_stage and attack_path.current_stage in self.STAGE_DWELL_TIMES:
                min_time, max_time = self.STAGE_DWELL_TIMES[attack_path.current_stage]
                time_to_next = (min_time + max_time) / 2  # Average

            # Determine risk level
            if attack_path.risk_score > 0.8:
                risk_level = 'critical'
            elif attack_path.risk_score > 0.6:
                risk_level = 'high'
            elif attack_path.risk_score > 0.3:
                risk_level = 'medium'
            else:
                risk_level = 'low'

            # Generate mitigations
            mitigations = self._generate_mitigations(attack_path)

            # Identify detection gaps
            gaps = self._identify_detection_gaps(attack_path)

            # Create prediction
            prediction = KillChainPrediction(
                prediction_id=self._generate_id("pred_"),
                timestamp=datetime.now(),
                current_stage=attack_path.current_stage or KillChainStage.RECONNAISSANCE,
                current_stage_confidence=attack_path.events[-1].confidence if attack_path.events else 0.5,
                next_stage=next_stage,
                next_stage_probability=next_stage_prob,
                time_to_next_stage_hours=time_to_next,
                attack_path=attack_path,
                risk_level=risk_level,
                recommended_mitigations=mitigations,
                detection_gaps=gaps
            )

            return prediction

    def _generate_mitigations(self, path: AttackPath) -> List[str]:
        """Generate recommended mitigations based on attack path"""
        mitigations = []

        # Stage-specific mitigations
        stage_mitigations = {
            KillChainStage.RECONNAISSANCE: [
                "Rate limit external scanning attempts",
                "Review and minimize public information exposure"
            ],
            KillChainStage.INITIAL_ACCESS: [
                "Enable MFA on all external-facing services",
                "Patch known vulnerabilities immediately",
                "Enhance email filtering for phishing"
            ],
            KillChainStage.EXECUTION: [
                "Enable application whitelisting",
                "Restrict PowerShell/script execution",
                "Monitor process creation events"
            ],
            KillChainStage.PERSISTENCE: [
                "Monitor scheduled tasks and startup items",
                "Audit service installations",
                "Review account creation logs"
            ],
            KillChainStage.PRIVILEGE_ESCALATION: [
                "Apply principle of least privilege",
                "Patch privilege escalation vulnerabilities",
                "Monitor for unusual privilege usage"
            ],
            KillChainStage.LATERAL_MOVEMENT: [
                "Segment network to limit lateral movement",
                "Monitor for unusual SMB/RDP traffic",
                "Implement host-based firewalls"
            ],
            KillChainStage.COMMAND_AND_CONTROL: [
                "Block known C2 domains and IPs",
                "Monitor for unusual outbound traffic",
                "Inspect encrypted traffic at perimeter"
            ],
            KillChainStage.EXFILTRATION: [
                "Enable DLP controls",
                "Monitor large data transfers",
                "Restrict cloud storage access"
            ],
            KillChainStage.IMPACT: [
                "Ensure offline backups are available",
                "Implement ransomware protection",
                "Prepare incident response procedures"
            ]
        }

        # Add mitigations for current and predicted stages
        if path.current_stage:
            mitigations.extend(stage_mitigations.get(path.current_stage, []))

        for predicted_stage in path.stages_predicted[:2]:  # Next 2 predicted stages
            mitigations.extend(stage_mitigations.get(predicted_stage, []))

        # Deduplicate
        return list(dict.fromkeys(mitigations))[:6]

    def _identify_detection_gaps(self, path: AttackPath) -> List[str]:
        """Identify detection gaps based on attack path"""
        gaps = []

        # Check for missing detections between stages
        if len(path.stages_observed) > 1:
            for i in range(len(path.stages_observed) - 1):
                current = path.stages_observed[i]
                next_obs = path.stages_observed[i + 1]

                # Check for skipped stages
                if next_obs.value - current.value > 2:
                    gaps.append(
                        f"Missing visibility between {current.name} and {next_obs.name}"
                    )

        # Check for commonly missed stages
        common_blind_spots = {
            KillChainStage.DEFENSE_EVASION: "Defense evasion techniques may be evading detection",
            KillChainStage.CREDENTIAL_ACCESS: "Credential theft may be occurring undetected",
            KillChainStage.DISCOVERY: "Internal reconnaissance may not be monitored"
        }

        for stage, gap_msg in common_blind_spots.items():
            if stage not in path.stages_observed and path.overall_progress > 0.3:
                gaps.append(gap_msg)

        return gaps[:5]

    def get_active_paths(self) -> List[AttackPath]:
        """Get all active attack paths"""
        return list(self.active_paths.values())

    def get_high_risk_paths(self, threshold: float = 0.6) -> List[AttackPath]:
        """Get attack paths with risk above threshold"""
        return [
            path for path in self.active_paths.values()
            if path.risk_score >= threshold
        ]

    def get_path_by_id(self, path_id: str) -> Optional[AttackPath]:
        """Get attack path by ID"""
        for path in self.active_paths.values():
            if path.path_id == path_id:
                return path
        return None

    def get_kill_chain_status(self) -> Dict[str, Any]:
        """Get overall kill chain status"""
        stage_counts = defaultdict(int)
        for path in self.active_paths.values():
            if path.current_stage:
                stage_counts[path.current_stage.name] += 1

        return {
            'active_attacks': len(self.active_paths),
            'high_risk_attacks': len(self.get_high_risk_paths()),
            'stages_active': dict(stage_counts),
            'recent_events': len([
                e for e in self.event_history
                if (datetime.now() - e.timestamp).total_seconds() < 3600
            ]),
            'completed_attacks': len(self.completed_paths)
        }

    def train_on_historical_data(
        self,
        attack_sequences: List[List[Dict]]
    ) -> Dict[str, Any]:
        """
        Train predictor on historical attack sequences

        Args:
            attack_sequences: List of attack sequences, each a list of events

        Returns:
            Training metrics
        """
        with self._lock:
            logger.info(f"Training Kill Chain Predictor on {len(attack_sequences)} sequences...")

            # Learn transition probabilities
            for sequence in attack_sequences:
                path = None
                for event_data in sequence:
                    _, path = self.process_event(event_data)

                if path:
                    self.completed_paths.append(path)

            # Update learned transitions based on counts
            for current_stage, next_counts in self.transition_counts.items():
                total = sum(next_counts.values())
                if total > 0:
                    self.learned_transitions[current_stage] = {
                        next_stage: count / total
                        for next_stage, count in next_counts.items()
                    }

            self.is_trained = True

            metrics = {
                'sequences_processed': len(attack_sequences),
                'unique_paths': len(self.active_paths) + len(self.completed_paths),
                'transitions_learned': sum(
                    len(v) for v in self.learned_transitions.values()
                ),
                'trained_at': datetime.now().isoformat()
            }

            # Save state
            self.save_state()

            return metrics

    def save_state(self):
        """Save predictor state to disk"""
        os.makedirs(self.model_path, exist_ok=True)

        state = {
            'learned_transitions': {
                k.name if isinstance(k, KillChainStage) else k: {
                    k2.name if isinstance(k2, KillChainStage) else k2: v2
                    for k2, v2 in v.items()
                }
                for k, v in self.learned_transitions.items()
            },
            'is_trained': self.is_trained,
            'saved_at': datetime.now().isoformat()
        }

        joblib.dump(state, os.path.join(self.model_path, 'killchain_state.pkl'))
        logger.info(f"Kill chain state saved to {self.model_path}")

    def load_state(self) -> bool:
        """Load predictor state from disk"""
        state_file = os.path.join(self.model_path, 'killchain_state.pkl')

        if not os.path.exists(state_file):
            return False

        try:
            state = joblib.load(state_file)

            # Reconstruct learned transitions
            self.learned_transitions = {}
            for k, v in state['learned_transitions'].items():
                stage_key = KillChainStage[k] if k in KillChainStage.__members__ else k
                self.learned_transitions[stage_key] = {
                    KillChainStage[k2] if k2 in KillChainStage.__members__ else k2: v2
                    for k2, v2 in v.items()
                }

            self.is_trained = state['is_trained']

            logger.info(f"Kill chain state loaded from {state_file}")
            return True

        except Exception as e:
            logger.error(f"Error loading state: {e}")
            return False


if __name__ == "__main__":
    # Demo usage
    print("Creating Kill Chain Predictor...")
    predictor = KillChainPredictor()

    # Simulate an attack sequence
    attack_events = [
        {
            'type': 'scan',
            'technique_id': 'T1595',
            'source_ip': '203.0.113.50',
            'target_ip': '10.0.0.0/24',
            'description': 'Port scanning detected',
            'timestamp': datetime.now() - timedelta(hours=5)
        },
        {
            'type': 'exploit',
            'technique_id': 'T1190',
            'source_ip': '203.0.113.50',
            'target_ip': '10.0.0.15',
            'description': 'Web application exploit attempt',
            'timestamp': datetime.now() - timedelta(hours=4)
        },
        {
            'type': 'execute',
            'technique_id': 'T1059',
            'target_ip': '10.0.0.15',
            'description': 'PowerShell execution detected',
            'timestamp': datetime.now() - timedelta(hours=3)
        },
        {
            'type': 'credential',
            'technique_id': 'T1003',
            'target_ip': '10.0.0.15',
            'target_asset': 'WEB-SERVER-01',
            'description': 'Credential dumping attempt',
            'timestamp': datetime.now() - timedelta(hours=2)
        },
        {
            'type': 'lateral',
            'technique_id': 'T1021',
            'source_ip': '10.0.0.15',
            'target_ip': '10.0.0.50',
            'description': 'RDP lateral movement',
            'timestamp': datetime.now() - timedelta(hours=1)
        }
    ]

    # Get prediction
    prediction = predictor.predict(attack_events, campaign_id="ATTACK_001")

    print(f"\n=== Kill Chain Prediction ===")
    print(f"Current Stage: {prediction.current_stage.name}")
    print(f"Confidence: {prediction.current_stage_confidence:.2%}")
    print(f"Risk Level: {prediction.risk_level.upper()}")
    print(f"\nNext Stage: {prediction.next_stage.name if prediction.next_stage else 'N/A'}")
    print(f"Next Stage Probability: {prediction.next_stage_probability:.2%}")
    print(f"Estimated Time: {prediction.time_to_next_stage_hours:.1f} hours")

    print(f"\nAttack Progress: {prediction.attack_path.overall_progress:.0%}")
    print(f"Stages Observed: {[s.name for s in prediction.attack_path.stages_observed]}")
    print(f"Predicted Path: {[s.name for s in prediction.attack_path.stages_predicted]}")

    print(f"\nRecommended Mitigations:")
    for mit in prediction.recommended_mitigations:
        print(f"  - {mit}")

    print(f"\nDetection Gaps:")
    for gap in prediction.detection_gaps:
        print(f"  - {gap}")

    # Get status
    status = predictor.get_kill_chain_status()
    print(f"\n=== Kill Chain Status ===")
    print(json.dumps(status, indent=2))
