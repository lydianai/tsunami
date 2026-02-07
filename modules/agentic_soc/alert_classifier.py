#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Agentic SOC - Alert Classifier v5.0
================================================================================

    ML-based alert classification system:
    - Alert categorization with pre-trained models
    - False positive detection
    - Severity adjustment based on context
    - Priority scoring
    - Duplicate detection

================================================================================
"""

import json
import hashlib
import logging
import pickle
from enum import Enum
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
import joblib

logger = logging.getLogger(__name__)


class AlertCategory(Enum):
    """Alert category types"""
    MALWARE = "malware"
    INTRUSION = "intrusion"
    DATA_EXFILTRATION = "data_exfiltration"
    CREDENTIAL_THEFT = "credential_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RECONNAISSANCE = "reconnaissance"
    COMMAND_AND_CONTROL = "command_and_control"
    DENIAL_OF_SERVICE = "denial_of_service"
    PHISHING = "phishing"
    POLICY_VIOLATION = "policy_violation"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"


class SeverityLevel(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class Alert:
    """Security alert data structure"""
    id: str
    title: str
    description: str
    source: str
    timestamp: datetime
    raw_data: Dict[str, Any]

    # Network-related fields
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None

    # User-related fields
    username: Optional[str] = None
    hostname: Optional[str] = None
    domain: Optional[str] = None

    # Threat indicators
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Initial classification from source
    initial_severity: Optional[str] = None
    initial_category: Optional[str] = None


@dataclass
class ClassificationResult:
    """Result of alert classification"""
    alert_id: str
    category: AlertCategory
    severity: SeverityLevel
    confidence: float
    priority_score: float
    is_false_positive: bool
    false_positive_probability: float
    is_duplicate: bool
    duplicate_of: Optional[str] = None
    severity_adjustment_reason: Optional[str] = None
    features_used: Dict[str, float] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'alert_id': self.alert_id,
            'category': self.category.value,
            'severity': self.severity.value,
            'confidence': self.confidence,
            'priority_score': self.priority_score,
            'is_false_positive': self.is_false_positive,
            'false_positive_probability': self.false_positive_probability,
            'is_duplicate': self.is_duplicate,
            'duplicate_of': self.duplicate_of,
            'severity_adjustment_reason': self.severity_adjustment_reason,
            'features_used': self.features_used,
            'timestamp': self.timestamp.isoformat()
        }


class AlertClassifier:
    """ML-based alert classification engine"""

    # Category keywords for initial classification
    CATEGORY_KEYWORDS = {
        AlertCategory.MALWARE: [
            'malware', 'virus', 'trojan', 'ransomware', 'worm', 'backdoor',
            'rootkit', 'keylogger', 'spyware', 'adware', 'cryptominer',
            'dropper', 'loader', 'executable', 'payload', 'infection'
        ],
        AlertCategory.INTRUSION: [
            'intrusion', 'breach', 'unauthorized access', 'exploit',
            'vulnerability', 'cve', 'buffer overflow', 'injection',
            'remote code execution', 'rce', 'zero day', '0day'
        ],
        AlertCategory.DATA_EXFILTRATION: [
            'exfiltration', 'data theft', 'data leak', 'data loss',
            'outbound transfer', 'unusual upload', 'sensitive data',
            'pii', 'credit card', 'ssn', 'encryption tunnel'
        ],
        AlertCategory.CREDENTIAL_THEFT: [
            'credential', 'password', 'authentication', 'brute force',
            'password spray', 'credential stuffing', 'pass the hash',
            'kerberoasting', 'mimikatz', 'lsass', 'sam dump'
        ],
        AlertCategory.LATERAL_MOVEMENT: [
            'lateral movement', 'psexec', 'wmi', 'winrm', 'rdp',
            'smb', 'admin share', 'remote execution', 'pivot',
            'internal scan', 'east-west traffic'
        ],
        AlertCategory.PRIVILEGE_ESCALATION: [
            'privilege escalation', 'elevation', 'admin', 'root',
            'sudo', 'uac bypass', 'token manipulation', 'impersonation',
            'setuid', 'capability', 'permission'
        ],
        AlertCategory.RECONNAISSANCE: [
            'reconnaissance', 'scan', 'enumeration', 'discovery',
            'port scan', 'network scan', 'directory traversal',
            'information gathering', 'fingerprint', 'probe'
        ],
        AlertCategory.COMMAND_AND_CONTROL: [
            'command and control', 'c2', 'c&c', 'beacon', 'callback',
            'cobalt strike', 'empire', 'metasploit', 'dns tunnel',
            'https beacon', 'encrypted channel'
        ],
        AlertCategory.DENIAL_OF_SERVICE: [
            'denial of service', 'dos', 'ddos', 'flood', 'syn flood',
            'amplification', 'reflection', 'resource exhaustion',
            'slowloris', 'ping of death'
        ],
        AlertCategory.PHISHING: [
            'phishing', 'spear phishing', 'social engineering',
            'malicious link', 'suspicious email', 'credential harvest',
            'fake login', 'impersonation', 'spoofed'
        ],
        AlertCategory.POLICY_VIOLATION: [
            'policy violation', 'compliance', 'unauthorized software',
            'shadow it', 'prohibited', 'blocked site', 'dlp',
            'acceptable use', 'terms of service'
        ]
    }

    # Severity indicators
    SEVERITY_INDICATORS = {
        SeverityLevel.CRITICAL: [
            'critical', 'emergency', 'immediate', 'active breach',
            'ransomware', 'data exfiltration', 'privileged account',
            'domain admin', 'executive', 'pci', 'hipaa', 'production'
        ],
        SeverityLevel.HIGH: [
            'high', 'severe', 'urgent', 'malware detected',
            'successful exploit', 'credential compromise',
            'lateral movement', 'persistence', 'c2 communication'
        ],
        SeverityLevel.MEDIUM: [
            'medium', 'moderate', 'suspicious', 'potential',
            'anomaly', 'unusual', 'policy violation', 'scan detected'
        ],
        SeverityLevel.LOW: [
            'low', 'minor', 'informational', 'blocked',
            'quarantined', 'false positive likely'
        ]
    }

    # False positive indicators
    FALSE_POSITIVE_INDICATORS = [
        'test', 'scanner', 'vulnerability assessment', 'pentest',
        'nessus', 'qualys', 'rapid7', 'tenable', 'known good',
        'approved', 'whitelisted', 'scheduled', 'maintenance',
        'backup', 'update', 'patch', 'legitimate'
    ]

    def __init__(self, model_path: Optional[Path] = None):
        """Initialize the classifier"""
        self.model_path = model_path or Path('/tmp/tsunami_soc_models')
        self.model_path.mkdir(parents=True, exist_ok=True)

        # ML Models
        self.category_classifier: Optional[RandomForestClassifier] = None
        self.severity_classifier: Optional[GradientBoostingClassifier] = None
        self.false_positive_classifier: Optional[RandomForestClassifier] = None

        # Feature extractors
        self.text_vectorizer: Optional[TfidfVectorizer] = None
        self.category_encoder: Optional[LabelEncoder] = None
        self.severity_encoder: Optional[LabelEncoder] = None
        self.feature_scaler: Optional[StandardScaler] = None

        # Duplicate detection
        self.alert_hashes: Dict[str, Tuple[str, datetime]] = {}
        self.alert_vectors: Dict[str, np.ndarray] = {}
        self.duplicate_threshold = 0.85

        # Training data storage
        self.training_data: List[Dict[str, Any]] = []

        # Initialize or load models
        self._initialize_models()

    def _initialize_models(self):
        """Initialize or load ML models"""
        category_model_path = self.model_path / 'category_classifier.joblib'
        severity_model_path = self.model_path / 'severity_classifier.joblib'
        fp_model_path = self.model_path / 'false_positive_classifier.joblib'
        vectorizer_path = self.model_path / 'text_vectorizer.joblib'

        # Try to load existing models
        if all(p.exists() for p in [category_model_path, severity_model_path, vectorizer_path]):
            try:
                self.category_classifier = joblib.load(category_model_path)
                self.severity_classifier = joblib.load(severity_model_path)
                self.text_vectorizer = joblib.load(vectorizer_path)
                if fp_model_path.exists():
                    self.false_positive_classifier = joblib.load(fp_model_path)
                logger.info("Loaded existing ML models")
                return
            except Exception as e:
                logger.warning(f"Failed to load models: {e}")

        # Initialize new models with pre-trained state
        self._create_pretrained_models()

    def _create_pretrained_models(self):
        """Create pre-trained models with synthetic training data"""
        logger.info("Creating pre-trained classification models")

        # Generate synthetic training data
        training_samples = self._generate_synthetic_training_data()

        if len(training_samples) < 100:
            logger.warning("Insufficient training data, using rule-based classification")
            return

        # Extract features
        texts = [s['text'] for s in training_samples]
        categories = [s['category'] for s in training_samples]
        severities = [s['severity'] for s in training_samples]
        is_fp = [s['is_false_positive'] for s in training_samples]
        numeric_features = [s['features'] for s in training_samples]

        # Initialize and fit text vectorizer
        self.text_vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            stop_words='english'
        )
        text_features = self.text_vectorizer.fit_transform(texts)

        # Combine text and numeric features
        numeric_array = np.array(numeric_features)
        self.feature_scaler = StandardScaler()
        numeric_scaled = self.feature_scaler.fit_transform(numeric_array)

        combined_features = np.hstack([text_features.toarray(), numeric_scaled])

        # Train category classifier
        self.category_encoder = LabelEncoder()
        category_labels = self.category_encoder.fit_transform(categories)

        self.category_classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.category_classifier.fit(combined_features, category_labels)

        # Train severity classifier
        self.severity_encoder = LabelEncoder()
        severity_labels = self.severity_encoder.fit_transform(severities)

        self.severity_classifier = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            random_state=42
        )
        self.severity_classifier.fit(combined_features, severity_labels)

        # Train false positive classifier
        self.false_positive_classifier = RandomForestClassifier(
            n_estimators=50,
            max_depth=8,
            random_state=42
        )
        self.false_positive_classifier.fit(combined_features, is_fp)

        # Save models
        self._save_models()
        logger.info("Pre-trained models created successfully")

    def _generate_synthetic_training_data(self) -> List[Dict[str, Any]]:
        """Generate synthetic training data for model initialization"""
        samples = []

        # Generate samples for each category
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            for i in range(50):  # 50 samples per category
                # Generate text
                selected_keywords = np.random.choice(keywords, size=min(3, len(keywords)), replace=False)
                text = f"Alert: {' '.join(selected_keywords)} detected on system"

                # Determine severity based on category
                if category in [AlertCategory.MALWARE, AlertCategory.DATA_EXFILTRATION, AlertCategory.INTRUSION]:
                    severity = np.random.choice(['critical', 'high'], p=[0.3, 0.7])
                elif category in [AlertCategory.CREDENTIAL_THEFT, AlertCategory.LATERAL_MOVEMENT]:
                    severity = np.random.choice(['high', 'medium'], p=[0.6, 0.4])
                elif category in [AlertCategory.RECONNAISSANCE, AlertCategory.POLICY_VIOLATION]:
                    severity = np.random.choice(['medium', 'low'], p=[0.5, 0.5])
                else:
                    severity = np.random.choice(['medium', 'low', 'informational'], p=[0.3, 0.4, 0.3])

                # Generate numeric features
                features = [
                    np.random.randint(0, 65535),  # port
                    np.random.randint(0, 1000),   # event count
                    np.random.random(),           # anomaly score
                    np.random.randint(0, 24),     # hour of day
                    np.random.randint(0, 7),      # day of week
                    1 if severity in ['critical', 'high'] else 0,  # high priority flag
                    np.random.randint(0, 10),     # affected assets
                    np.random.random()            # risk score
                ]

                # False positive probability
                is_fp = np.random.random() < 0.15  # 15% false positive rate

                samples.append({
                    'text': text,
                    'category': category.value,
                    'severity': severity,
                    'is_false_positive': is_fp,
                    'features': features
                })

        # Add false positive samples
        for _ in range(100):
            fp_text = f"Alert: {np.random.choice(self.FALSE_POSITIVE_INDICATORS)} activity"
            samples.append({
                'text': fp_text,
                'category': AlertCategory.FALSE_POSITIVE.value,
                'severity': 'low',
                'is_false_positive': True,
                'features': [
                    np.random.randint(0, 65535),
                    np.random.randint(0, 100),
                    np.random.random() * 0.3,
                    np.random.randint(0, 24),
                    np.random.randint(0, 7),
                    0,
                    1,
                    np.random.random() * 0.2
                ]
            })

        return samples

    def _save_models(self):
        """Save models to disk"""
        try:
            joblib.dump(self.category_classifier, self.model_path / 'category_classifier.joblib')
            joblib.dump(self.severity_classifier, self.model_path / 'severity_classifier.joblib')
            joblib.dump(self.text_vectorizer, self.model_path / 'text_vectorizer.joblib')
            if self.false_positive_classifier:
                joblib.dump(self.false_positive_classifier, self.model_path / 'false_positive_classifier.joblib')
            if self.feature_scaler:
                joblib.dump(self.feature_scaler, self.model_path / 'feature_scaler.joblib')
            logger.info("Models saved successfully")
        except Exception as e:
            logger.error(f"Failed to save models: {e}")

    def _extract_features(self, alert: Alert) -> Tuple[np.ndarray, Dict[str, float]]:
        """Extract features from an alert"""
        # Text features
        text = f"{alert.title} {alert.description}"
        text_vector = self.text_vectorizer.transform([text]).toarray() if self.text_vectorizer else np.zeros((1, 100))

        # Numeric features
        numeric = [
            alert.dest_port or 0,
            len(alert.indicators),
            len(alert.mitre_techniques),
            alert.timestamp.hour,
            alert.timestamp.weekday(),
            1 if alert.initial_severity in ['critical', 'high'] else 0,
            1 if alert.source_ip else 0,
            1 if alert.username else 0
        ]

        numeric_array = np.array([numeric])
        if self.feature_scaler:
            numeric_scaled = self.feature_scaler.transform(numeric_array)
        else:
            numeric_scaled = numeric_array

        combined = np.hstack([text_vector, numeric_scaled])

        feature_dict = {
            'dest_port': alert.dest_port or 0,
            'indicator_count': len(alert.indicators),
            'mitre_count': len(alert.mitre_techniques),
            'hour_of_day': alert.timestamp.hour,
            'day_of_week': alert.timestamp.weekday(),
            'initial_high_severity': 1 if alert.initial_severity in ['critical', 'high'] else 0
        }

        return combined, feature_dict

    def _calculate_alert_hash(self, alert: Alert) -> str:
        """Calculate a hash for duplicate detection"""
        # Use key fields for hashing
        hash_data = f"{alert.source}:{alert.title}:{alert.source_ip}:{alert.dest_ip}"
        return hashlib.md5(hash_data.encode()).hexdigest()

    def _check_duplicate(self, alert: Alert) -> Tuple[bool, Optional[str]]:
        """Check if alert is a duplicate"""
        # Check exact hash match
        alert_hash = self._calculate_alert_hash(alert)

        if alert_hash in self.alert_hashes:
            orig_id, orig_time = self.alert_hashes[alert_hash]
            # Consider duplicate if within 1 hour
            if (alert.timestamp - orig_time) < timedelta(hours=1):
                return True, orig_id

        # Check semantic similarity
        if self.text_vectorizer and self.alert_vectors:
            text = f"{alert.title} {alert.description}"
            alert_vector = self.text_vectorizer.transform([text]).toarray()

            for existing_id, existing_vector in list(self.alert_vectors.items())[-100:]:  # Check last 100
                similarity = cosine_similarity(alert_vector, existing_vector)[0][0]
                if similarity > self.duplicate_threshold:
                    return True, existing_id

            # Store vector for future comparisons
            self.alert_vectors[alert.id] = alert_vector

        # Store hash
        self.alert_hashes[alert_hash] = (alert.id, alert.timestamp)

        return False, None

    def _classify_by_rules(self, alert: Alert) -> Tuple[AlertCategory, SeverityLevel, float]:
        """Rule-based classification fallback"""
        text_lower = f"{alert.title} {alert.description}".lower()

        # Find best matching category
        best_category = AlertCategory.UNKNOWN
        best_score = 0

        for category, keywords in self.CATEGORY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text_lower)
            if score > best_score:
                best_score = score
                best_category = category

        # Determine severity
        severity = SeverityLevel.MEDIUM
        for sev_level, indicators in self.SEVERITY_INDICATORS.items():
            if any(ind in text_lower for ind in indicators):
                severity = sev_level
                break

        # Use initial severity if provided and we're uncertain
        if best_score == 0 and alert.initial_severity:
            severity_map = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW,
                'info': SeverityLevel.INFORMATIONAL,
                'informational': SeverityLevel.INFORMATIONAL
            }
            severity = severity_map.get(alert.initial_severity.lower(), SeverityLevel.MEDIUM)

        confidence = min(0.9, 0.3 + (best_score * 0.15))

        return best_category, severity, confidence

    def _check_false_positive(self, alert: Alert, features: np.ndarray) -> Tuple[bool, float]:
        """Check if alert is likely a false positive"""
        text_lower = f"{alert.title} {alert.description}".lower()

        # Rule-based check
        fp_score = sum(1 for ind in self.FALSE_POSITIVE_INDICATORS if ind in text_lower)
        rule_fp_prob = min(0.9, fp_score * 0.15)

        # ML-based check
        ml_fp_prob = 0.0
        if self.false_positive_classifier:
            try:
                probs = self.false_positive_classifier.predict_proba(features)
                ml_fp_prob = probs[0][1]  # Probability of being false positive
            except Exception:
                pass

        # Combine probabilities
        combined_prob = (rule_fp_prob + ml_fp_prob) / 2 if ml_fp_prob > 0 else rule_fp_prob

        return combined_prob > 0.6, combined_prob

    def _calculate_priority_score(
        self,
        category: AlertCategory,
        severity: SeverityLevel,
        alert: Alert,
        is_fp: bool
    ) -> float:
        """Calculate priority score (0-100)"""
        # Base score from severity
        severity_scores = {
            SeverityLevel.CRITICAL: 90,
            SeverityLevel.HIGH: 70,
            SeverityLevel.MEDIUM: 50,
            SeverityLevel.LOW: 30,
            SeverityLevel.INFORMATIONAL: 10
        }
        score = severity_scores.get(severity, 50)

        # Adjust for category
        high_priority_categories = [
            AlertCategory.DATA_EXFILTRATION,
            AlertCategory.CREDENTIAL_THEFT,
            AlertCategory.MALWARE,
            AlertCategory.INTRUSION
        ]
        if category in high_priority_categories:
            score += 10

        # Adjust for indicators
        if alert.mitre_techniques:
            score += min(10, len(alert.mitre_techniques) * 2)

        # Adjust for affected assets
        if alert.hostname:
            # Check if critical asset (simplified)
            if any(kw in alert.hostname.lower() for kw in ['dc', 'ad', 'sql', 'db', 'prod', 'exec']):
                score += 15

        # Reduce for false positives
        if is_fp:
            score *= 0.3

        return min(100, max(0, score))

    def _adjust_severity(
        self,
        initial_severity: SeverityLevel,
        alert: Alert,
        category: AlertCategory
    ) -> Tuple[SeverityLevel, Optional[str]]:
        """Adjust severity based on context"""
        adjusted = initial_severity
        reason = None

        # Escalate for critical assets
        critical_keywords = ['domain controller', 'exchange', 'ceo', 'cfo', 'executive', 'production']
        text_lower = f"{alert.title} {alert.description} {alert.hostname or ''}".lower()

        if any(kw in text_lower for kw in critical_keywords):
            if initial_severity == SeverityLevel.MEDIUM:
                adjusted = SeverityLevel.HIGH
                reason = "Escalated due to critical asset involvement"
            elif initial_severity == SeverityLevel.HIGH:
                adjusted = SeverityLevel.CRITICAL
                reason = "Escalated to critical due to high-value target"

        # Escalate for data exfiltration with PII
        if category == AlertCategory.DATA_EXFILTRATION:
            if any(kw in text_lower for kw in ['pii', 'credit card', 'ssn', 'password']):
                if initial_severity != SeverityLevel.CRITICAL:
                    adjusted = SeverityLevel.CRITICAL
                    reason = "Escalated due to sensitive data involvement"

        # De-escalate for blocked/quarantined
        if any(kw in text_lower for kw in ['blocked', 'quarantined', 'prevented', 'denied']):
            if initial_severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                adjusted = SeverityLevel.MEDIUM
                reason = "De-escalated because threat was blocked"

        return adjusted, reason

    def classify(self, alert: Alert) -> ClassificationResult:
        """Classify an alert"""
        # Check for duplicates
        is_duplicate, duplicate_of = self._check_duplicate(alert)

        # Extract features
        features, feature_dict = self._extract_features(alert)

        # ML classification if models available
        if self.category_classifier and self.text_vectorizer:
            try:
                # Category prediction
                category_pred = self.category_classifier.predict(features)[0]
                category_probs = self.category_classifier.predict_proba(features)[0]
                category = AlertCategory(self.category_encoder.inverse_transform([category_pred])[0])
                category_confidence = max(category_probs)

                # Severity prediction
                severity_pred = self.severity_classifier.predict(features)[0]
                severity_probs = self.severity_classifier.predict_proba(features)[0]
                severity = SeverityLevel(self.severity_encoder.inverse_transform([severity_pred])[0])
                severity_confidence = max(severity_probs)

                confidence = (category_confidence + severity_confidence) / 2
            except Exception as e:
                logger.warning(f"ML classification failed: {e}, falling back to rules")
                category, severity, confidence = self._classify_by_rules(alert)
        else:
            category, severity, confidence = self._classify_by_rules(alert)

        # Adjust severity based on context
        adjusted_severity, adjustment_reason = self._adjust_severity(severity, alert, category)

        # Check false positive
        is_fp, fp_probability = self._check_false_positive(alert, features)

        # Calculate priority
        priority_score = self._calculate_priority_score(category, adjusted_severity, alert, is_fp)

        return ClassificationResult(
            alert_id=alert.id,
            category=category,
            severity=adjusted_severity,
            confidence=confidence,
            priority_score=priority_score,
            is_false_positive=is_fp,
            false_positive_probability=fp_probability,
            is_duplicate=is_duplicate,
            duplicate_of=duplicate_of,
            severity_adjustment_reason=adjustment_reason,
            features_used=feature_dict
        )

    def learn_from_feedback(
        self,
        alert: Alert,
        correct_category: AlertCategory,
        correct_severity: SeverityLevel,
        was_false_positive: bool
    ):
        """Learn from analyst feedback"""
        features, _ = self._extract_features(alert)

        self.training_data.append({
            'features': features.tolist(),
            'category': correct_category.value,
            'severity': correct_severity.value,
            'is_false_positive': was_false_positive,
            'timestamp': datetime.utcnow().isoformat()
        })

        # Retrain if enough new data
        if len(self.training_data) >= 50:
            self._retrain_models()

    def _retrain_models(self):
        """Retrain models with new feedback data"""
        if len(self.training_data) < 50:
            return

        logger.info(f"Retraining models with {len(self.training_data)} new samples")

        try:
            # Prepare training data
            features = np.array([d['features'] for d in self.training_data])
            categories = [d['category'] for d in self.training_data]
            severities = [d['severity'] for d in self.training_data]
            false_positives = [d['is_false_positive'] for d in self.training_data]

            # Partial fit or retrain
            category_labels = self.category_encoder.transform(categories)
            self.category_classifier.fit(features, category_labels)

            severity_labels = self.severity_encoder.transform(severities)
            self.severity_classifier.fit(features, severity_labels)

            self.false_positive_classifier.fit(features, false_positives)

            # Save updated models
            self._save_models()

            # Clear processed training data
            self.training_data = []

            logger.info("Model retraining completed")
        except Exception as e:
            logger.error(f"Model retraining failed: {e}")

    def get_stats(self) -> Dict[str, Any]:
        """Get classifier statistics"""
        return {
            'models_loaded': {
                'category': self.category_classifier is not None,
                'severity': self.severity_classifier is not None,
                'false_positive': self.false_positive_classifier is not None,
                'vectorizer': self.text_vectorizer is not None
            },
            'cached_alerts': len(self.alert_hashes),
            'cached_vectors': len(self.alert_vectors),
            'pending_training_samples': len(self.training_data),
            'duplicate_threshold': self.duplicate_threshold
        }


# Global classifier instance
_classifier: Optional[AlertClassifier] = None


def get_classifier() -> AlertClassifier:
    """Get or create the global classifier instance"""
    global _classifier
    if _classifier is None:
        _classifier = AlertClassifier()
    return _classifier
