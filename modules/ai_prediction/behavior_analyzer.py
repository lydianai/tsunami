#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI BEHAVIOR ANALYZER v5.0
    Real-Time Behavioral Analysis & Anomaly Detection
================================================================================

    Features:
    - Baseline normal behavior patterns
    - Real-time deviation detection
    - Entity behavior tracking over time
    - Anomaly severity scoring
    - Adaptive threshold learning

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
from enum import Enum
from collections import defaultdict, deque
import hashlib
import threading
from pathlib import Path
import pickle

# ML Libraries
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.neighbors import LocalOutlierFactor
from scipy import stats
from scipy.spatial.distance import mahalanobis
import joblib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EntityType(Enum):
    """Types of entities that can be tracked"""
    USER = "user"
    HOST = "host"
    IP_ADDRESS = "ip_address"
    SERVICE = "service"
    APPLICATION = "application"
    NETWORK_SEGMENT = "network_segment"


class BehaviorCategory(Enum):
    """Categories of behavioral patterns"""
    AUTHENTICATION = "authentication"
    NETWORK_ACCESS = "network_access"
    DATA_ACCESS = "data_access"
    RESOURCE_USAGE = "resource_usage"
    COMMUNICATION = "communication"
    PRIVILEGE_USAGE = "privilege_usage"
    FILE_OPERATIONS = "file_operations"


class AnomalySeverity(Enum):
    """Severity levels for detected anomalies"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class BehaviorMetrics:
    """Metrics for a specific behavior category"""
    category: BehaviorCategory
    count: int = 0
    success_rate: float = 1.0
    avg_duration: float = 0.0
    peak_hour: int = 12
    weekday_ratio: float = 0.8
    unique_targets: int = 0
    volume_bytes: int = 0
    error_rate: float = 0.0
    last_seen: Optional[datetime] = None


@dataclass
class BehaviorBaseline:
    """Statistical baseline for an entity's behavior"""
    entity_id: str
    entity_type: EntityType
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    sample_count: int = 0

    # Statistical baselines per category
    metrics: Dict[str, BehaviorMetrics] = field(default_factory=dict)

    # Time-based patterns
    hourly_activity: List[float] = field(default_factory=lambda: [0.0] * 24)
    daily_activity: List[float] = field(default_factory=lambda: [0.0] * 7)

    # Feature statistics (mean, std for each feature)
    feature_means: Dict[str, float] = field(default_factory=dict)
    feature_stds: Dict[str, float] = field(default_factory=dict)
    feature_mins: Dict[str, float] = field(default_factory=dict)
    feature_maxs: Dict[str, float] = field(default_factory=dict)

    # Covariance matrix for Mahalanobis distance
    covariance_matrix: Optional[np.ndarray] = None

    # Clusters of normal behavior
    behavior_clusters: List[np.ndarray] = field(default_factory=list)


@dataclass
class EntityProfile:
    """Complete behavioral profile for an entity"""
    entity_id: str
    entity_type: EntityType
    first_seen: datetime
    last_seen: datetime
    baseline: BehaviorBaseline
    risk_score: float = 0.0
    anomaly_count: int = 0
    last_anomaly: Optional[datetime] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorAnomaly:
    """Detected behavioral anomaly"""
    anomaly_id: str
    entity_id: str
    entity_type: EntityType
    timestamp: datetime
    severity: AnomalySeverity
    category: BehaviorCategory
    description: str
    deviation_score: float  # How far from normal (z-score or similar)
    confidence: float
    observed_values: Dict[str, Any]
    expected_values: Dict[str, Any]
    contributing_factors: List[str]
    is_confirmed: bool = False
    false_positive: bool = False


class BehaviorAnalyzer:
    """
    Real-Time Behavioral Analysis Engine

    Uses multiple detection methods:
    - Statistical deviation detection (z-scores)
    - Isolation Forest for multivariate anomalies
    - Local Outlier Factor for density-based detection
    - Temporal pattern analysis
    - Peer group comparison
    """

    # Default feature names for behavior analysis
    BEHAVIOR_FEATURES = [
        'login_count',
        'failed_login_count',
        'unique_src_ips',
        'unique_dest_ips',
        'unique_services',
        'data_volume_mb',
        'session_duration_avg',
        'request_count',
        'error_count',
        'privilege_escalations',
        'file_access_count',
        'file_modify_count',
        'file_delete_count',
        'network_connections',
        'external_connections',
        'hour_of_day',
        'is_weekend',
        'is_business_hours'
    ]

    def __init__(
        self,
        baseline_window_days: int = 30,
        anomaly_threshold_sigma: float = 3.0,
        min_samples_for_baseline: int = 100,
        model_path: Optional[str] = None
    ):
        """
        Initialize Behavior Analyzer

        Args:
            baseline_window_days: Days of history to use for baseline
            anomaly_threshold_sigma: Standard deviations for anomaly threshold
            min_samples_for_baseline: Minimum samples before baseline is valid
            model_path: Path to save/load models
        """
        self.baseline_window_days = baseline_window_days
        self.anomaly_threshold_sigma = anomaly_threshold_sigma
        self.min_samples_for_baseline = min_samples_for_baseline
        self.model_path = model_path or "/tmp/tsunami_behavior_models"

        # Entity profiles storage
        self.profiles: Dict[str, EntityProfile] = {}

        # Anomaly detection models per entity type
        self.isolation_forests: Dict[EntityType, IsolationForest] = {}
        self.lof_models: Dict[EntityType, LocalOutlierFactor] = {}
        self.scalers: Dict[EntityType, StandardScaler] = {}

        # Peer group models
        self.peer_groups: Dict[EntityType, Dict[str, List[str]]] = defaultdict(dict)
        self.peer_group_models: Dict[str, KMeans] = {}

        # Event buffers
        self.event_buffers: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.anomaly_history: deque = deque(maxlen=50000)

        # Thread safety
        self._lock = threading.RLock()

        # Initialize models for each entity type
        for entity_type in EntityType:
            self._init_models_for_type(entity_type)

    def _init_models_for_type(self, entity_type: EntityType):
        """Initialize ML models for an entity type"""
        self.isolation_forests[entity_type] = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
            n_jobs=-1
        )

        self.lof_models[entity_type] = LocalOutlierFactor(
            n_neighbors=20,
            contamination=0.05,
            novelty=True,
            n_jobs=-1
        )

        self.scalers[entity_type] = StandardScaler()

    def _generate_anomaly_id(self, entity_id: str, timestamp: datetime) -> str:
        """Generate unique anomaly ID"""
        content = f"{entity_id}{timestamp.isoformat()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def _extract_behavior_features(
        self,
        events: List[Dict[str, Any]],
        timestamp: Optional[datetime] = None
    ) -> np.ndarray:
        """
        Extract behavioral features from events

        Args:
            events: List of event dictionaries
            timestamp: Reference timestamp for temporal features

        Returns:
            Feature array
        """
        if not events:
            return np.zeros(len(self.BEHAVIOR_FEATURES))

        timestamp = timestamp or datetime.now()

        # Aggregate metrics
        login_events = [e for e in events if e.get('type') == 'login']
        auth_events = [e for e in events if e.get('type') in ('login', 'logout', 'auth')]
        network_events = [e for e in events if e.get('type') in ('connection', 'request', 'network')]
        file_events = [e for e in events if e.get('type') in ('file_access', 'file_modify', 'file_delete')]

        features = {
            'login_count': len(login_events),
            'failed_login_count': sum(1 for e in login_events if not e.get('success', True)),
            'unique_src_ips': len(set(e.get('src_ip', '') for e in events)),
            'unique_dest_ips': len(set(e.get('dest_ip', '') for e in events)),
            'unique_services': len(set(e.get('service', '') for e in events)),
            'data_volume_mb': sum(e.get('bytes', 0) for e in events) / (1024 * 1024),
            'session_duration_avg': np.mean([e.get('duration', 0) for e in events]) if events else 0,
            'request_count': len(events),
            'error_count': sum(1 for e in events if e.get('error') or e.get('status', 200) >= 400),
            'privilege_escalations': sum(1 for e in events if e.get('privilege_escalation')),
            'file_access_count': sum(1 for e in file_events if e.get('type') == 'file_access'),
            'file_modify_count': sum(1 for e in file_events if e.get('type') == 'file_modify'),
            'file_delete_count': sum(1 for e in file_events if e.get('type') == 'file_delete'),
            'network_connections': len(network_events),
            'external_connections': sum(1 for e in network_events if e.get('external', False)),
            'hour_of_day': timestamp.hour,
            'is_weekend': 1 if timestamp.weekday() >= 5 else 0,
            'is_business_hours': 1 if 9 <= timestamp.hour <= 17 and timestamp.weekday() < 5 else 0
        }

        return np.array([features.get(name, 0) for name in self.BEHAVIOR_FEATURES])

    def create_or_update_baseline(
        self,
        entity_id: str,
        entity_type: EntityType,
        events: List[Dict[str, Any]]
    ) -> BehaviorBaseline:
        """
        Create or update behavioral baseline for an entity

        Args:
            entity_id: Unique entity identifier
            entity_type: Type of entity
            events: Historical events for baseline creation

        Returns:
            Updated BehaviorBaseline
        """
        with self._lock:
            # Get or create profile
            if entity_id not in self.profiles:
                baseline = BehaviorBaseline(
                    entity_id=entity_id,
                    entity_type=entity_type
                )
                profile = EntityProfile(
                    entity_id=entity_id,
                    entity_type=entity_type,
                    first_seen=datetime.now(),
                    last_seen=datetime.now(),
                    baseline=baseline
                )
                self.profiles[entity_id] = profile
            else:
                profile = self.profiles[entity_id]
                baseline = profile.baseline

            # Extract features from events
            if not events:
                return baseline

            # Group events by time window (hourly)
            hourly_features = []
            events_sorted = sorted(events, key=lambda e: e.get('timestamp', datetime.now()))

            # Process in hourly windows
            current_window = []
            window_start = None

            for event in events_sorted:
                event_time = event.get('timestamp', datetime.now())
                if isinstance(event_time, str):
                    event_time = datetime.fromisoformat(event_time)

                if window_start is None:
                    window_start = event_time

                if (event_time - window_start).total_seconds() < 3600:
                    current_window.append(event)
                else:
                    if current_window:
                        features = self._extract_behavior_features(current_window, window_start)
                        hourly_features.append(features)
                    current_window = [event]
                    window_start = event_time

            # Process last window
            if current_window:
                features = self._extract_behavior_features(current_window, window_start)
                hourly_features.append(features)

            if not hourly_features:
                return baseline

            feature_matrix = np.array(hourly_features)

            # Update feature statistics
            for i, name in enumerate(self.BEHAVIOR_FEATURES):
                values = feature_matrix[:, i]
                baseline.feature_means[name] = float(np.mean(values))
                baseline.feature_stds[name] = float(np.std(values)) if len(values) > 1 else 0.1
                baseline.feature_mins[name] = float(np.min(values))
                baseline.feature_maxs[name] = float(np.max(values))

            # Calculate covariance matrix for Mahalanobis distance
            if feature_matrix.shape[0] > feature_matrix.shape[1]:
                try:
                    baseline.covariance_matrix = np.cov(feature_matrix.T)
                except Exception as e:
                    logger.warning(f"Could not calculate covariance matrix: {e}")

            # Update hourly activity pattern
            for event in events:
                event_time = event.get('timestamp', datetime.now())
                if isinstance(event_time, str):
                    event_time = datetime.fromisoformat(event_time)
                baseline.hourly_activity[event_time.hour] += 1
                baseline.daily_activity[event_time.weekday()] += 1

            # Normalize activity patterns
            total_hourly = sum(baseline.hourly_activity) or 1
            baseline.hourly_activity = [h / total_hourly for h in baseline.hourly_activity]

            total_daily = sum(baseline.daily_activity) or 1
            baseline.daily_activity = [d / total_daily for d in baseline.daily_activity]

            # Update metrics
            baseline.sample_count += len(hourly_features)
            baseline.updated_at = datetime.now()

            # Fit entity-type specific models if enough samples
            if baseline.sample_count >= self.min_samples_for_baseline:
                self._fit_anomaly_models(entity_type, feature_matrix)

            # Update profile
            profile.baseline = baseline
            profile.last_seen = datetime.now()
            self.profiles[entity_id] = profile

            logger.info(f"Updated baseline for {entity_id} with {len(hourly_features)} samples")

            return baseline

    def _fit_anomaly_models(
        self,
        entity_type: EntityType,
        feature_matrix: np.ndarray
    ):
        """Fit anomaly detection models on feature matrix"""
        try:
            # Scale features
            scaled_features = self.scalers[entity_type].fit_transform(feature_matrix)

            # Fit Isolation Forest
            self.isolation_forests[entity_type].fit(scaled_features)

            # Fit LOF
            self.lof_models[entity_type].fit(scaled_features)

            logger.info(f"Fitted anomaly models for {entity_type.value}")

        except Exception as e:
            logger.error(f"Error fitting models for {entity_type.value}: {e}")

    def analyze_behavior(
        self,
        entity_id: str,
        events: List[Dict[str, Any]],
        entity_type: Optional[EntityType] = None
    ) -> List[BehaviorAnomaly]:
        """
        Analyze behavior and detect anomalies

        Args:
            entity_id: Entity to analyze
            events: Recent events to analyze
            entity_type: Type of entity (inferred if not provided)

        Returns:
            List of detected anomalies
        """
        with self._lock:
            anomalies = []

            # Get or create profile
            if entity_id not in self.profiles:
                if entity_type is None:
                    entity_type = EntityType.USER  # Default
                # Create minimal baseline
                self.create_or_update_baseline(entity_id, entity_type, events)

            profile = self.profiles[entity_id]
            baseline = profile.baseline
            entity_type = profile.entity_type

            if not events:
                return anomalies

            # Store events in buffer
            self.event_buffers[entity_id].extend(events)

            # Extract current features
            current_features = self._extract_behavior_features(events)

            # 1. Statistical deviation detection (z-scores)
            statistical_anomalies = self._detect_statistical_anomalies(
                entity_id, current_features, baseline
            )
            anomalies.extend(statistical_anomalies)

            # 2. ML-based detection (Isolation Forest)
            ml_anomalies = self._detect_ml_anomalies(
                entity_id, entity_type, current_features, events
            )
            anomalies.extend(ml_anomalies)

            # 3. Temporal pattern analysis
            temporal_anomalies = self._detect_temporal_anomalies(
                entity_id, events, baseline
            )
            anomalies.extend(temporal_anomalies)

            # 4. Mahalanobis distance for multivariate anomalies
            if baseline.covariance_matrix is not None:
                mahal_anomalies = self._detect_mahalanobis_anomalies(
                    entity_id, current_features, baseline
                )
                anomalies.extend(mahal_anomalies)

            # Update profile
            if anomalies:
                profile.anomaly_count += len(anomalies)
                profile.last_anomaly = datetime.now()

                # Update risk score (exponential decay + new anomalies)
                time_since_last = (datetime.now() - (profile.last_anomaly or datetime.now())).total_seconds()
                decay_factor = np.exp(-time_since_last / (24 * 3600))  # 24h half-life
                profile.risk_score = min(1.0, profile.risk_score * decay_factor + len(anomalies) * 0.1)

            profile.last_seen = datetime.now()
            self.profiles[entity_id] = profile

            # Store in history
            self.anomaly_history.extend(anomalies)

            return anomalies

    def _detect_statistical_anomalies(
        self,
        entity_id: str,
        features: np.ndarray,
        baseline: BehaviorBaseline
    ) -> List[BehaviorAnomaly]:
        """Detect anomalies using statistical z-score analysis"""
        anomalies = []

        if baseline.sample_count < self.min_samples_for_baseline:
            return anomalies

        for i, name in enumerate(self.BEHAVIOR_FEATURES):
            mean = baseline.feature_means.get(name, 0)
            std = baseline.feature_stds.get(name, 1)

            if std == 0:
                std = 0.1  # Avoid division by zero

            z_score = abs(features[i] - mean) / std

            if z_score > self.anomaly_threshold_sigma:
                # Determine severity based on z-score
                if z_score > 5:
                    severity = AnomalySeverity.CRITICAL
                elif z_score > 4:
                    severity = AnomalySeverity.HIGH
                elif z_score > 3:
                    severity = AnomalySeverity.MEDIUM
                else:
                    severity = AnomalySeverity.LOW

                # Determine category based on feature name
                category = self._feature_to_category(name)

                anomaly = BehaviorAnomaly(
                    anomaly_id=self._generate_anomaly_id(entity_id, datetime.now()),
                    entity_id=entity_id,
                    entity_type=baseline.entity_type,
                    timestamp=datetime.now(),
                    severity=severity,
                    category=category,
                    description=f"Statistical anomaly in {name}: {z_score:.2f} sigma deviation",
                    deviation_score=float(z_score),
                    confidence=min(0.99, 1 - stats.norm.sf(z_score)),
                    observed_values={name: float(features[i])},
                    expected_values={name: float(mean), f"{name}_std": float(std)},
                    contributing_factors=[f"{name} is {z_score:.1f}x standard deviation from mean"]
                )
                anomalies.append(anomaly)

        return anomalies

    def _detect_ml_anomalies(
        self,
        entity_id: str,
        entity_type: EntityType,
        features: np.ndarray,
        events: List[Dict]
    ) -> List[BehaviorAnomaly]:
        """Detect anomalies using ML models"""
        anomalies = []

        try:
            # Scale features
            if not hasattr(self.scalers[entity_type], 'mean_'):
                return anomalies

            scaled = self.scalers[entity_type].transform(features.reshape(1, -1))

            # Isolation Forest score
            if_score = self.isolation_forests[entity_type].score_samples(scaled)[0]

            # LOF score
            lof_score = self.lof_models[entity_type].score_samples(scaled)[0]

            # Combined anomaly detection
            if if_score < -0.5 or lof_score < -1.5:
                severity = AnomalySeverity.HIGH if if_score < -0.7 else AnomalySeverity.MEDIUM

                anomaly = BehaviorAnomaly(
                    anomaly_id=self._generate_anomaly_id(entity_id, datetime.now()),
                    entity_id=entity_id,
                    entity_type=entity_type,
                    timestamp=datetime.now(),
                    severity=severity,
                    category=BehaviorCategory.NETWORK_ACCESS,  # General category
                    description=f"ML-detected behavioral anomaly (IF: {if_score:.3f}, LOF: {lof_score:.3f})",
                    deviation_score=float(abs(min(if_score, lof_score))),
                    confidence=0.85 if if_score < -0.7 else 0.70,
                    observed_values={
                        'isolation_forest_score': float(if_score),
                        'lof_score': float(lof_score)
                    },
                    expected_values={
                        'isolation_forest_score': 0.0,
                        'lof_score': 0.0
                    },
                    contributing_factors=[
                        f"Isolation Forest anomaly score: {if_score:.3f}",
                        f"Local Outlier Factor score: {lof_score:.3f}"
                    ]
                )
                anomalies.append(anomaly)

        except Exception as e:
            logger.debug(f"ML detection error for {entity_id}: {e}")

        return anomalies

    def _detect_temporal_anomalies(
        self,
        entity_id: str,
        events: List[Dict],
        baseline: BehaviorBaseline
    ) -> List[BehaviorAnomaly]:
        """Detect anomalies in temporal patterns"""
        anomalies = []

        if baseline.sample_count < self.min_samples_for_baseline:
            return anomalies

        for event in events:
            event_time = event.get('timestamp', datetime.now())
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time)

            hour = event_time.hour
            day = event_time.weekday()

            # Check hourly pattern
            expected_hourly = baseline.hourly_activity[hour]
            if expected_hourly < 0.01:  # Less than 1% activity expected
                severity = AnomalySeverity.MEDIUM
                if not (9 <= hour <= 17):  # Outside business hours
                    severity = AnomalySeverity.HIGH

                anomaly = BehaviorAnomaly(
                    anomaly_id=self._generate_anomaly_id(entity_id, event_time),
                    entity_id=entity_id,
                    entity_type=baseline.entity_type,
                    timestamp=event_time,
                    severity=severity,
                    category=BehaviorCategory.AUTHENTICATION,
                    description=f"Activity at unusual hour ({hour:02d}:00) - only {expected_hourly:.1%} of normal activity",
                    deviation_score=1 / max(expected_hourly, 0.001),
                    confidence=0.75,
                    observed_values={'hour': hour, 'activity_level': 1},
                    expected_values={'expected_activity_ratio': float(expected_hourly)},
                    contributing_factors=[f"Hour {hour} has only {expected_hourly:.1%} of baseline activity"]
                )
                anomalies.append(anomaly)
                break  # Only one temporal anomaly per batch

        return anomalies

    def _detect_mahalanobis_anomalies(
        self,
        entity_id: str,
        features: np.ndarray,
        baseline: BehaviorBaseline
    ) -> List[BehaviorAnomaly]:
        """Detect multivariate anomalies using Mahalanobis distance"""
        anomalies = []

        try:
            # Calculate mean vector
            mean_vector = np.array([
                baseline.feature_means.get(name, 0)
                for name in self.BEHAVIOR_FEATURES
            ])

            # Calculate Mahalanobis distance
            cov_inv = np.linalg.pinv(baseline.covariance_matrix)
            m_distance = mahalanobis(features, mean_vector, cov_inv)

            # Chi-square distribution threshold (p=0.001)
            threshold = stats.chi2.ppf(0.999, df=len(self.BEHAVIOR_FEATURES))

            if m_distance > np.sqrt(threshold):
                severity = AnomalySeverity.HIGH if m_distance > np.sqrt(threshold) * 1.5 else AnomalySeverity.MEDIUM

                anomaly = BehaviorAnomaly(
                    anomaly_id=self._generate_anomaly_id(entity_id, datetime.now()),
                    entity_id=entity_id,
                    entity_type=baseline.entity_type,
                    timestamp=datetime.now(),
                    severity=severity,
                    category=BehaviorCategory.NETWORK_ACCESS,
                    description=f"Multivariate behavioral anomaly (Mahalanobis distance: {m_distance:.2f})",
                    deviation_score=float(m_distance),
                    confidence=float(1 - stats.chi2.sf(m_distance**2, df=len(self.BEHAVIOR_FEATURES))),
                    observed_values={
                        'mahalanobis_distance': float(m_distance),
                        'threshold': float(np.sqrt(threshold))
                    },
                    expected_values={'expected_distance': 0.0},
                    contributing_factors=[
                        f"Combined feature deviation: Mahalanobis distance = {m_distance:.2f}",
                        f"Threshold (p=0.001): {np.sqrt(threshold):.2f}"
                    ]
                )
                anomalies.append(anomaly)

        except Exception as e:
            logger.debug(f"Mahalanobis detection error for {entity_id}: {e}")

        return anomalies

    def _feature_to_category(self, feature_name: str) -> BehaviorCategory:
        """Map feature name to behavior category"""
        category_map = {
            'login_count': BehaviorCategory.AUTHENTICATION,
            'failed_login_count': BehaviorCategory.AUTHENTICATION,
            'unique_src_ips': BehaviorCategory.NETWORK_ACCESS,
            'unique_dest_ips': BehaviorCategory.NETWORK_ACCESS,
            'unique_services': BehaviorCategory.NETWORK_ACCESS,
            'data_volume_mb': BehaviorCategory.DATA_ACCESS,
            'session_duration_avg': BehaviorCategory.RESOURCE_USAGE,
            'request_count': BehaviorCategory.NETWORK_ACCESS,
            'error_count': BehaviorCategory.NETWORK_ACCESS,
            'privilege_escalations': BehaviorCategory.PRIVILEGE_USAGE,
            'file_access_count': BehaviorCategory.FILE_OPERATIONS,
            'file_modify_count': BehaviorCategory.FILE_OPERATIONS,
            'file_delete_count': BehaviorCategory.FILE_OPERATIONS,
            'network_connections': BehaviorCategory.NETWORK_ACCESS,
            'external_connections': BehaviorCategory.COMMUNICATION,
        }
        return category_map.get(feature_name, BehaviorCategory.NETWORK_ACCESS)

    def get_entity_profile(self, entity_id: str) -> Optional[EntityProfile]:
        """Get entity profile"""
        return self.profiles.get(entity_id)

    def get_all_profiles(self) -> List[EntityProfile]:
        """Get all entity profiles"""
        return list(self.profiles.values())

    def get_high_risk_entities(self, threshold: float = 0.5) -> List[EntityProfile]:
        """Get entities with high risk scores"""
        return [
            profile for profile in self.profiles.values()
            if profile.risk_score >= threshold
        ]

    def get_recent_anomalies(
        self,
        entity_id: Optional[str] = None,
        hours: int = 24,
        min_severity: AnomalySeverity = AnomalySeverity.LOW
    ) -> List[BehaviorAnomaly]:
        """Get recent anomalies"""
        cutoff = datetime.now() - timedelta(hours=hours)

        anomalies = [
            a for a in self.anomaly_history
            if a.timestamp >= cutoff
            and a.severity.value >= min_severity.value
            and (entity_id is None or a.entity_id == entity_id)
        ]

        return sorted(anomalies, key=lambda a: a.timestamp, reverse=True)

    def calculate_anomaly_score(
        self,
        entity_id: str,
        features: np.ndarray
    ) -> Dict[str, float]:
        """
        Calculate comprehensive anomaly score for features

        Returns dict with individual and combined scores
        """
        if entity_id not in self.profiles:
            return {'combined_score': 0.0, 'is_anomalous': False}

        profile = self.profiles[entity_id]
        baseline = profile.baseline

        scores = {}

        # Z-score based score
        z_scores = []
        for i, name in enumerate(self.BEHAVIOR_FEATURES):
            mean = baseline.feature_means.get(name, 0)
            std = baseline.feature_stds.get(name, 1) or 0.1
            z_scores.append(abs(features[i] - mean) / std)

        scores['max_z_score'] = float(max(z_scores))
        scores['mean_z_score'] = float(np.mean(z_scores))

        # ML scores
        entity_type = profile.entity_type
        try:
            if hasattr(self.scalers[entity_type], 'mean_'):
                scaled = self.scalers[entity_type].transform(features.reshape(1, -1))
                scores['isolation_forest_score'] = float(
                    self.isolation_forests[entity_type].score_samples(scaled)[0]
                )
                scores['lof_score'] = float(
                    self.lof_models[entity_type].score_samples(scaled)[0]
                )
        except Exception:
            pass

        # Combined score (normalized 0-1)
        combined = 0.0
        if scores.get('max_z_score', 0) > self.anomaly_threshold_sigma:
            combined += 0.4
        if scores.get('isolation_forest_score', 0) < -0.5:
            combined += 0.3
        if scores.get('lof_score', 0) < -1.5:
            combined += 0.3

        scores['combined_score'] = combined
        scores['is_anomalous'] = combined > 0.5

        return scores

    def save_state(self):
        """Save analyzer state to disk"""
        os.makedirs(self.model_path, exist_ok=True)

        state = {
            'profiles': {
                k: asdict(v) for k, v in self.profiles.items()
            },
            'isolation_forests': self.isolation_forests,
            'lof_models': self.lof_models,
            'scalers': self.scalers,
            'saved_at': datetime.now().isoformat()
        }

        # Convert numpy arrays in profiles
        for entity_id, profile_dict in state['profiles'].items():
            if profile_dict['baseline']['covariance_matrix'] is not None:
                profile_dict['baseline']['covariance_matrix'] = profile_dict['baseline']['covariance_matrix'].tolist()

        joblib.dump(state, os.path.join(self.model_path, 'behavior_analyzer.pkl'))
        logger.info(f"Behavior analyzer state saved to {self.model_path}")

    def load_state(self) -> bool:
        """Load analyzer state from disk"""
        state_file = os.path.join(self.model_path, 'behavior_analyzer.pkl')

        if not os.path.exists(state_file):
            logger.warning(f"No saved state found at {state_file}")
            return False

        try:
            state = joblib.load(state_file)

            # Reconstruct profiles
            for entity_id, profile_dict in state['profiles'].items():
                baseline_dict = profile_dict['baseline']

                # Reconstruct baseline
                baseline = BehaviorBaseline(
                    entity_id=baseline_dict['entity_id'],
                    entity_type=EntityType(baseline_dict['entity_type']),
                    created_at=datetime.fromisoformat(baseline_dict['created_at']),
                    updated_at=datetime.fromisoformat(baseline_dict['updated_at']),
                    sample_count=baseline_dict['sample_count'],
                    metrics=baseline_dict['metrics'],
                    hourly_activity=baseline_dict['hourly_activity'],
                    daily_activity=baseline_dict['daily_activity'],
                    feature_means=baseline_dict['feature_means'],
                    feature_stds=baseline_dict['feature_stds'],
                    feature_mins=baseline_dict['feature_mins'],
                    feature_maxs=baseline_dict['feature_maxs']
                )

                if baseline_dict['covariance_matrix']:
                    baseline.covariance_matrix = np.array(baseline_dict['covariance_matrix'])

                # Reconstruct profile
                profile = EntityProfile(
                    entity_id=profile_dict['entity_id'],
                    entity_type=EntityType(profile_dict['entity_type']),
                    first_seen=datetime.fromisoformat(profile_dict['first_seen']),
                    last_seen=datetime.fromisoformat(profile_dict['last_seen']),
                    baseline=baseline,
                    risk_score=profile_dict['risk_score'],
                    anomaly_count=profile_dict['anomaly_count'],
                    tags=profile_dict['tags'],
                    metadata=profile_dict['metadata']
                )

                if profile_dict['last_anomaly']:
                    profile.last_anomaly = datetime.fromisoformat(profile_dict['last_anomaly'])

                self.profiles[entity_id] = profile

            self.isolation_forests = state['isolation_forests']
            self.lof_models = state['lof_models']
            self.scalers = state['scalers']

            logger.info(f"Behavior analyzer state loaded from {state_file}")
            return True

        except Exception as e:
            logger.error(f"Error loading state: {e}")
            return False

    def get_statistics(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return {
            'total_entities': len(self.profiles),
            'entities_by_type': {
                etype.value: sum(1 for p in self.profiles.values() if p.entity_type == etype)
                for etype in EntityType
            },
            'total_anomalies_tracked': len(self.anomaly_history),
            'high_risk_entities': len(self.get_high_risk_entities()),
            'recent_anomalies_24h': len(self.get_recent_anomalies(hours=24)),
            'baseline_window_days': self.baseline_window_days,
            'anomaly_threshold_sigma': self.anomaly_threshold_sigma
        }


if __name__ == "__main__":
    # Demo usage
    print("Creating Behavior Analyzer...")
    analyzer = BehaviorAnalyzer()

    # Generate sample events
    sample_events = []
    for i in range(200):
        sample_events.append({
            'type': 'login',
            'timestamp': datetime.now() - timedelta(hours=i),
            'src_ip': f'192.168.1.{np.random.randint(1, 255)}',
            'dest_ip': '10.0.0.1',
            'success': np.random.random() > 0.1,
            'service': 'ssh',
            'duration': np.random.exponential(60)
        })

    # Create baseline
    baseline = analyzer.create_or_update_baseline(
        entity_id='user_001',
        entity_type=EntityType.USER,
        events=sample_events
    )

    print(f"\nBaseline created with {baseline.sample_count} samples")
    print(f"Feature means: {dict(list(baseline.feature_means.items())[:5])}")

    # Analyze new (potentially anomalous) behavior
    anomalous_events = [
        {
            'type': 'login',
            'timestamp': datetime.now(),
            'src_ip': '203.0.113.100',  # External IP
            'dest_ip': '10.0.0.1',
            'success': False,
            'service': 'ssh',
            'duration': 0.5
        }
    ] * 50  # 50 rapid failed logins

    anomalies = analyzer.analyze_behavior('user_001', anomalous_events)

    print(f"\nDetected {len(anomalies)} anomalies:")
    for anomaly in anomalies[:3]:
        print(f"  - {anomaly.severity.name}: {anomaly.description}")

    stats = analyzer.get_statistics()
    print(f"\nAnalyzer Statistics: {json.dumps(stats, indent=2)}")
