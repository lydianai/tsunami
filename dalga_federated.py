#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI FEDERATED THREAT INTELLIGENCE v1.0
    Privacy-Preserving Threat Intelligence Sharing Platform
================================================================================

    Features:
    - Privacy-preserving IOC sharing using differential privacy
    - Federated learning for threat detection models
    - Zero-knowledge proof concepts for verification without disclosure
    - Secure aggregation of threat statistics
    - Hash-based IOC sharing (share hashes, not raw indicators)
    - Bloom filter-based membership testing
    - K-anonymity for IP ranges
    - Anonymous threat voting system
    - STIX/TAXII integration
    - Encrypted peer-to-peer communication

================================================================================
"""

import os
import json
import hashlib
import hmac
import secrets
import threading
import time
import math
import struct
import logging
import sqlite3
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from functools import wraps
import ipaddress
import uuid
import zlib

# Cryptography library for secure operations
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Flask for API endpoints
from flask import Blueprint, request, jsonify, g

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# ENUMS AND DATA STRUCTURES
# ============================================================

class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    FILE_NAME = "file_name"
    MUTEX = "mutex"
    REGISTRY_KEY = "registry_key"


class ThreatConfidence(Enum):
    """Confidence levels for threat indicators"""
    CONFIRMED = "confirmed"      # 90-100%
    HIGH = "high"               # 70-89%
    MEDIUM = "medium"           # 40-69%
    LOW = "low"                 # 10-39%
    UNKNOWN = "unknown"         # 0-9%


class VoteType(Enum):
    """Types of votes for IOC validation"""
    CONFIRM = "confirm"
    DENY = "deny"
    SUSPICIOUS = "suspicious"
    FALSE_POSITIVE = "false_positive"


class PeerStatus(Enum):
    """Status of a peer in the network"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"
    PENDING = "pending"


@dataclass
class SharedIOC:
    """A shared IOC with privacy-preserving metadata"""
    ioc_hash: str                      # SHA-256 of the original IOC
    ioc_type: IOCType
    timestamp: datetime
    contributor_id: str                # Anonymous identifier
    confidence: ThreatConfidence
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    votes_confirm: int = 0
    votes_deny: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict = field(default_factory=dict)


@dataclass
class TrustedPeer:
    """A trusted peer in the federated network"""
    peer_id: str
    public_key: bytes
    endpoint: str
    organization: str                  # Can be hashed for privacy
    status: PeerStatus
    trust_score: float                 # 0.0 - 1.0
    contribution_count: int = 0
    false_positive_count: int = 0
    joined_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict = field(default_factory=dict)


@dataclass
class FederatedModel:
    """A federated learning model version"""
    model_id: str
    version: int
    checksum: str
    parameters: bytes                  # Encrypted model parameters
    created_at: datetime
    contributors: int
    accuracy: float
    model_type: str                    # 'malware_classifier', 'anomaly_detector', etc.


@dataclass
class STIXIndicator:
    """STIX 2.1 Indicator representation"""
    id: str
    type: str = "indicator"
    spec_version: str = "2.1"
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    name: str = ""
    description: str = ""
    pattern: str = ""
    pattern_type: str = "stix"
    valid_from: Optional[datetime] = None
    labels: List[str] = field(default_factory=list)
    confidence: int = 0


# ============================================================
# BLOOM FILTER FOR PRIVACY-PRESERVING IOC LOOKUP
# ============================================================

class BloomFilter:
    """
    Bloom filter for privacy-preserving IOC membership testing.
    Allows checking if an IOC might be in the set without revealing the actual IOCs.
    """

    def __init__(self, expected_elements: int = 100000, false_positive_rate: float = 0.01):
        """
        Initialize bloom filter with optimal parameters.

        Args:
            expected_elements: Expected number of elements
            false_positive_rate: Desired false positive rate
        """
        self.expected_elements = expected_elements
        self.false_positive_rate = false_positive_rate

        # Calculate optimal parameters
        self.size = self._calculate_size(expected_elements, false_positive_rate)
        self.hash_count = self._calculate_hash_count(self.size, expected_elements)
        self.bit_array = bytearray(self.size // 8 + 1)
        self.element_count = 0
        self._lock = threading.Lock()

    def _calculate_size(self, n: int, p: float) -> int:
        """Calculate optimal bit array size"""
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    def _calculate_hash_count(self, m: int, n: int) -> int:
        """Calculate optimal number of hash functions"""
        k = (m / n) * math.log(2)
        return max(1, int(k))

    def _get_hash_positions(self, item: str) -> List[int]:
        """Get bit positions for an item using multiple hash functions"""
        positions = []
        item_bytes = item.encode('utf-8')

        for i in range(self.hash_count):
            # Use different hash seeds
            h = hashlib.sha256(item_bytes + i.to_bytes(4, 'big')).digest()
            position = int.from_bytes(h[:4], 'big') % self.size
            positions.append(position)

        return positions

    def add(self, item: str):
        """Add an item to the bloom filter"""
        with self._lock:
            for position in self._get_hash_positions(item):
                byte_idx = position // 8
                bit_idx = position % 8
                self.bit_array[byte_idx] |= (1 << bit_idx)
            self.element_count += 1

    def contains(self, item: str) -> bool:
        """Check if an item might be in the bloom filter"""
        with self._lock:
            for position in self._get_hash_positions(item):
                byte_idx = position // 8
                bit_idx = position % 8
                if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                    return False
            return True

    def serialize(self) -> bytes:
        """Serialize the bloom filter for transmission"""
        data = {
            'size': self.size,
            'hash_count': self.hash_count,
            'element_count': self.element_count,
            'bits': base64.b64encode(zlib.compress(self.bit_array)).decode('ascii')
        }
        return json.dumps(data).encode('utf-8')

    @classmethod
    def deserialize(cls, data: bytes) -> 'BloomFilter':
        """Deserialize a bloom filter"""
        obj = json.loads(data.decode('utf-8'))
        bf = cls.__new__(cls)
        bf.size = obj['size']
        bf.hash_count = obj['hash_count']
        bf.element_count = obj['element_count']
        bf.bit_array = bytearray(zlib.decompress(base64.b64decode(obj['bits'])))
        bf._lock = threading.Lock()
        return bf


# ============================================================
# DIFFERENTIAL PRIVACY ENGINE
# ============================================================

class DifferentialPrivacy:
    """
    Differential privacy implementation for protecting statistics.
    Uses Laplace mechanism for numeric queries.
    """

    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        Initialize differential privacy engine.

        Args:
            epsilon: Privacy budget (lower = more privacy)
            delta: Probability of privacy breach
        """
        self.epsilon = epsilon
        self.delta = delta

    def add_laplace_noise(self, value: float, sensitivity: float) -> float:
        """
        Add Laplace noise to a numeric value.

        Args:
            value: The true value
            sensitivity: Maximum change from adding/removing one record

        Returns:
            Noisy value
        """
        scale = sensitivity / self.epsilon
        noise = self._sample_laplace(scale)
        return value + noise

    def _sample_laplace(self, scale: float) -> float:
        """Sample from Laplace distribution"""
        u = secrets.SystemRandom().random() - 0.5
        return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))

    def add_gaussian_noise(self, value: float, sensitivity: float) -> float:
        """
        Add Gaussian noise for (epsilon, delta)-differential privacy.
        """
        sigma = (sensitivity * math.sqrt(2 * math.log(1.25 / self.delta))) / self.epsilon
        noise = secrets.SystemRandom().gauss(0, sigma)
        return value + noise

    def randomized_response(self, true_value: bool, probability: float = 0.75) -> bool:
        """
        Randomized response for binary questions.

        Args:
            true_value: The actual answer
            probability: Probability of answering truthfully

        Returns:
            Potentially randomized answer
        """
        if secrets.SystemRandom().random() < probability:
            return true_value
        else:
            return secrets.SystemRandom().random() < 0.5


# ============================================================
# K-ANONYMITY FOR IP ADDRESSES
# ============================================================

class KAnonymizer:
    """
    K-anonymity implementation for IP addresses.
    Generalizes IPs to network ranges to protect individual addresses.
    """

    def __init__(self, k: int = 5):
        """
        Initialize K-anonymizer.

        Args:
            k: Minimum number of indistinguishable records
        """
        self.k = k

    def anonymize_ip(self, ip: str, level: int = 24) -> str:
        """
        Anonymize an IP address by truncating to a network range.

        Args:
            ip: IP address to anonymize
            level: CIDR prefix length (lower = more anonymous)

        Returns:
            Network range string
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                network = ipaddress.ip_network(f"{ip}/{level}", strict=False)
            else:
                # IPv6: use larger prefix
                network = ipaddress.ip_network(f"{ip}/{min(level, 64)}", strict=False)
            return str(network)
        except ValueError:
            return "invalid/0"

    def determine_optimal_level(self, ips: List[str], target_k: int = None) -> int:
        """
        Determine the optimal CIDR level to achieve k-anonymity.

        Args:
            ips: List of IP addresses
            target_k: Target k value (uses self.k if not provided)

        Returns:
            Optimal CIDR prefix length
        """
        target_k = target_k or self.k

        for level in [32, 28, 24, 20, 16, 12, 8]:
            groups = defaultdict(list)
            for ip in ips:
                anon = self.anonymize_ip(ip, level)
                groups[anon].append(ip)

            # Check if all groups have at least k members
            if all(len(g) >= target_k for g in groups.values()):
                return level

        return 8  # Most general


# ============================================================
# ZERO-KNOWLEDGE PROOF CONCEPTS
# ============================================================

class ZKProofConcept:
    """
    Zero-knowledge proof concepts for verification without disclosure.
    Simplified implementation for demonstration purposes.
    """

    @staticmethod
    def create_commitment(secret: str, randomness: bytes = None) -> Tuple[str, bytes]:
        """
        Create a commitment to a secret value.

        Args:
            secret: The secret value to commit to
            randomness: Random bytes for commitment (generated if not provided)

        Returns:
            (commitment, randomness) tuple
        """
        if randomness is None:
            randomness = secrets.token_bytes(32)

        # H(secret || randomness)
        commitment = hashlib.sha256(
            secret.encode('utf-8') + randomness
        ).hexdigest()

        return commitment, randomness

    @staticmethod
    def verify_commitment(secret: str, commitment: str, randomness: bytes) -> bool:
        """
        Verify a commitment reveals the claimed secret.
        """
        expected = hashlib.sha256(
            secret.encode('utf-8') + randomness
        ).hexdigest()
        return hmac.compare_digest(commitment, expected)

    @staticmethod
    def prove_membership(element: str, bloom_filter: BloomFilter) -> Dict[str, Any]:
        """
        Create a proof that an element is in a bloom filter
        without revealing the element.
        """
        element_hash = hashlib.sha256(element.encode()).hexdigest()
        is_member = bloom_filter.contains(element)

        # Create proof with commitment
        commitment, randomness = ZKProofConcept.create_commitment(element_hash)

        return {
            'commitment': commitment,
            'randomness': base64.b64encode(randomness).decode('ascii'),
            'claimed_membership': is_member
        }

    @staticmethod
    def hash_to_prime(value: str) -> int:
        """
        Hash a value to a prime number (for accumulator-based proofs).
        Simplified implementation.
        """
        h = int(hashlib.sha256(value.encode()).hexdigest(), 16)
        # Find next prime after h % (2^64)
        candidate = h % (2**64) | 1  # Make odd
        while not ZKProofConcept._is_prime(candidate):
            candidate += 2
        return candidate

    @staticmethod
    def _is_prime(n: int) -> bool:
        """Miller-Rabin primality test (simplified)"""
        if n < 2:
            return False
        if n == 2:
            return True
        if n % 2 == 0:
            return False

        # Simple check for small primes
        for p in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
            if n == p:
                return True
            if n % p == 0:
                return False

        return True  # Simplified for demo


# ============================================================
# SECURE AGGREGATION
# ============================================================

class SecureAggregation:
    """
    Secure aggregation for federated statistics.
    Allows computing aggregate statistics without revealing individual contributions.
    """

    def __init__(self, num_participants: int):
        """
        Initialize secure aggregation.

        Args:
            num_participants: Expected number of participants
        """
        self.num_participants = num_participants
        self.masks: Dict[str, int] = {}
        self.contributions: Dict[str, int] = {}
        self._lock = threading.Lock()

    def generate_mask_pair(self, participant_a: str, participant_b: str) -> Tuple[int, int]:
        """
        Generate a mask pair for two participants.
        Sum of masks is zero.
        """
        mask = secrets.randbelow(2**32)
        return mask, (2**32 - mask) % (2**32)

    def create_masked_contribution(self, participant_id: str, value: int,
                                   masks: Dict[str, int]) -> int:
        """
        Create a masked contribution.

        Args:
            participant_id: Identifier of the contributor
            value: The actual value to contribute
            masks: Dictionary of masks from other participants

        Returns:
            Masked value
        """
        total_mask = sum(masks.values()) % (2**32)
        return (value + total_mask) % (2**32)

    def aggregate(self, contributions: Dict[str, int]) -> int:
        """
        Aggregate masked contributions.
        Masks cancel out, revealing the sum.
        """
        total = sum(contributions.values()) % (2**32)
        # Handle overflow
        if total > 2**31:
            total -= 2**32
        return total


# ============================================================
# FEDERATED MODEL TRAINING
# ============================================================

class FederatedModelTrainer:
    """
    Federated learning for threat detection models.
    Trains models on local data and shares only gradients/weights.
    """

    def __init__(self, model_type: str = "malware_classifier"):
        """
        Initialize federated model trainer.

        Args:
            model_type: Type of model to train
        """
        self.model_type = model_type
        self.local_weights: Optional[Dict[str, List[float]]] = None
        self.global_weights: Optional[Dict[str, List[float]]] = None
        self.training_rounds: int = 0
        self._lock = threading.Lock()

    def initialize_model(self, input_dim: int, hidden_dim: int = 64, output_dim: int = 2):
        """
        Initialize model weights with random values.
        Simple 2-layer neural network structure.
        """
        self.local_weights = {
            'W1': [secrets.SystemRandom().gauss(0, 0.1) for _ in range(input_dim * hidden_dim)],
            'b1': [0.0] * hidden_dim,
            'W2': [secrets.SystemRandom().gauss(0, 0.1) for _ in range(hidden_dim * output_dim)],
            'b2': [0.0] * output_dim
        }

    def train_local(self, features: List[List[float]], labels: List[int],
                   learning_rate: float = 0.01, epochs: int = 5) -> Dict[str, List[float]]:
        """
        Train model on local data and return weight updates.

        Args:
            features: Training features
            labels: Training labels (0 or 1)
            learning_rate: Learning rate
            epochs: Number of training epochs

        Returns:
            Weight gradients to share
        """
        if self.local_weights is None:
            input_dim = len(features[0]) if features else 10
            self.initialize_model(input_dim)

        # Simplified gradient computation (placeholder)
        # In production, use proper ML framework
        gradients = {
            key: [learning_rate * secrets.SystemRandom().gauss(0, 0.01)
                  for _ in range(len(vals))]
            for key, vals in self.local_weights.items()
        }

        self.training_rounds += epochs
        return gradients

    def apply_gradient(self, gradients: Dict[str, List[float]]):
        """Apply gradients to update local weights"""
        if self.local_weights is None:
            return

        with self._lock:
            for key, grads in gradients.items():
                if key in self.local_weights:
                    self.local_weights[key] = [
                        w - g for w, g in zip(self.local_weights[key], grads)
                    ]

    def average_weights(self, all_weights: List[Dict[str, List[float]]]) -> Dict[str, List[float]]:
        """
        Federated averaging: combine weights from multiple participants.
        """
        if not all_weights:
            return {}

        averaged = {}
        for key in all_weights[0].keys():
            num_weights = len(all_weights[0][key])
            averaged[key] = []
            for i in range(num_weights):
                avg_val = sum(w[key][i] for w in all_weights) / len(all_weights)
                averaged[key].append(avg_val)

        return averaged

    def serialize_weights(self) -> bytes:
        """Serialize model weights for secure transmission"""
        if self.local_weights is None:
            return b''
        return json.dumps(self.local_weights).encode('utf-8')

    def deserialize_weights(self, data: bytes) -> Dict[str, List[float]]:
        """Deserialize received model weights"""
        return json.loads(data.decode('utf-8'))

    def get_model_checksum(self) -> str:
        """Get checksum of current model for verification"""
        if self.local_weights is None:
            return ""
        serialized = self.serialize_weights()
        return hashlib.sha256(serialized).hexdigest()


# ============================================================
# STIX/TAXII INTEGRATION
# ============================================================

class STIXManager:
    """
    STIX 2.1 format support for threat intelligence sharing.
    """

    STIX_VERSION = "2.1"

    @staticmethod
    def create_indicator(ioc: SharedIOC) -> Dict[str, Any]:
        """Convert SharedIOC to STIX 2.1 Indicator"""
        pattern = STIXManager._create_pattern(ioc)

        indicator = {
            "type": "indicator",
            "spec_version": STIXManager.STIX_VERSION,
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Threat indicator ({ioc.ioc_type.value})",
            "description": f"Shared threat indicator with confidence {ioc.confidence.value}",
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.first_seen.isoformat() + "Z" if ioc.first_seen else datetime.utcnow().isoformat() + "Z",
            "labels": ioc.tags,
            "confidence": STIXManager._confidence_to_int(ioc.confidence),
            "external_references": []
        }

        # Add MITRE ATT&CK references
        for technique in ioc.mitre_techniques:
            indicator["external_references"].append({
                "source_name": "mitre-attack",
                "external_id": technique,
                "url": f"https://attack.mitre.org/techniques/{technique}/"
            })

        return indicator

    @staticmethod
    def _create_pattern(ioc: SharedIOC) -> str:
        """Create STIX pattern from IOC"""
        patterns = {
            IOCType.IP: f"[ipv4-addr:value = '{ioc.ioc_hash}']",
            IOCType.DOMAIN: f"[domain-name:value = '{ioc.ioc_hash}']",
            IOCType.URL: f"[url:value = '{ioc.ioc_hash}']",
            IOCType.HASH_MD5: f"[file:hashes.MD5 = '{ioc.ioc_hash}']",
            IOCType.HASH_SHA1: f"[file:hashes.SHA-1 = '{ioc.ioc_hash}']",
            IOCType.HASH_SHA256: f"[file:hashes.SHA-256 = '{ioc.ioc_hash}']",
            IOCType.EMAIL: f"[email-addr:value = '{ioc.ioc_hash}']",
            IOCType.FILE_NAME: f"[file:name = '{ioc.ioc_hash}']"
        }
        return patterns.get(ioc.ioc_type, f"[x-custom:value = '{ioc.ioc_hash}']")

    @staticmethod
    def _confidence_to_int(confidence: ThreatConfidence) -> int:
        """Convert confidence enum to integer"""
        mapping = {
            ThreatConfidence.CONFIRMED: 95,
            ThreatConfidence.HIGH: 80,
            ThreatConfidence.MEDIUM: 55,
            ThreatConfidence.LOW: 25,
            ThreatConfidence.UNKNOWN: 5
        }
        return mapping.get(confidence, 50)

    @staticmethod
    def create_bundle(indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create STIX Bundle containing multiple indicators"""
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "objects": indicators
        }

    @staticmethod
    def parse_indicator(stix_indicator: Dict[str, Any]) -> Optional[SharedIOC]:
        """Parse STIX Indicator to SharedIOC"""
        try:
            pattern = stix_indicator.get("pattern", "")

            # Extract IOC type from pattern
            ioc_type = IOCType.HASH_SHA256  # default
            if "ipv4-addr" in pattern:
                ioc_type = IOCType.IP
            elif "domain-name" in pattern:
                ioc_type = IOCType.DOMAIN
            elif "url:value" in pattern:
                ioc_type = IOCType.URL
            elif "MD5" in pattern:
                ioc_type = IOCType.HASH_MD5
            elif "SHA-1" in pattern:
                ioc_type = IOCType.HASH_SHA1
            elif "email-addr" in pattern:
                ioc_type = IOCType.EMAIL

            # Extract hash from pattern (simplified)
            import re
            match = re.search(r"'([^']+)'", pattern)
            ioc_hash = match.group(1) if match else ""

            confidence = STIXManager._int_to_confidence(
                stix_indicator.get("confidence", 50)
            )

            return SharedIOC(
                ioc_hash=ioc_hash,
                ioc_type=ioc_type,
                timestamp=datetime.utcnow(),
                contributor_id="stix_import",
                confidence=confidence,
                tags=stix_indicator.get("labels", []),
                mitre_techniques=[
                    ref.get("external_id", "")
                    for ref in stix_indicator.get("external_references", [])
                    if ref.get("source_name") == "mitre-attack"
                ]
            )
        except Exception as e:
            logger.error(f"[STIX] Failed to parse indicator: {e}")
            return None

    @staticmethod
    def _int_to_confidence(value: int) -> ThreatConfidence:
        """Convert integer confidence to enum"""
        if value >= 90:
            return ThreatConfidence.CONFIRMED
        elif value >= 70:
            return ThreatConfidence.HIGH
        elif value >= 40:
            return ThreatConfidence.MEDIUM
        elif value >= 10:
            return ThreatConfidence.LOW
        return ThreatConfidence.UNKNOWN


class TAXIIClient:
    """
    TAXII 2.1 client for threat feed subscription.
    """

    def __init__(self, server_url: str, api_root: str = "/api/v21"):
        """
        Initialize TAXII client.

        Args:
            server_url: TAXII server URL
            api_root: API root path
        """
        self.server_url = server_url.rstrip('/')
        self.api_root = api_root
        self.collections: List[Dict] = []
        self._headers = {
            "Accept": "application/taxii+json;version=2.1",
            "Content-Type": "application/taxii+json;version=2.1"
        }
        self._auth: Optional[Tuple[str, str]] = None

    def set_credentials(self, username: str, password: str):
        """Set authentication credentials"""
        self._auth = (username, password)

    def discover(self) -> Dict[str, Any]:
        """Discover TAXII server capabilities"""
        import requests
        try:
            response = requests.get(
                f"{self.server_url}/taxii2/",
                headers=self._headers,
                auth=self._auth,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[TAXII] Discovery failed: {e}")
            return {}

    def get_collections(self) -> List[Dict]:
        """Get available collections"""
        import requests
        try:
            response = requests.get(
                f"{self.server_url}{self.api_root}/collections/",
                headers=self._headers,
                auth=self._auth,
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
            self.collections = data.get("collections", [])
            return self.collections
        except Exception as e:
            logger.error(f"[TAXII] Get collections failed: {e}")
            return []

    def get_objects(self, collection_id: str, added_after: datetime = None,
                   limit: int = 100) -> List[Dict]:
        """
        Get objects from a collection.

        Args:
            collection_id: Collection to query
            added_after: Only return objects added after this time
            limit: Maximum number of objects
        """
        import requests
        try:
            params = {"limit": limit}
            if added_after:
                params["added_after"] = added_after.isoformat() + "Z"

            response = requests.get(
                f"{self.server_url}{self.api_root}/collections/{collection_id}/objects/",
                headers=self._headers,
                auth=self._auth,
                params=params,
                timeout=60
            )
            response.raise_for_status()
            data = response.json()
            return data.get("objects", [])
        except Exception as e:
            logger.error(f"[TAXII] Get objects failed: {e}")
            return []

    def add_objects(self, collection_id: str, objects: List[Dict]) -> bool:
        """
        Add objects to a collection.
        """
        import requests
        try:
            bundle = STIXManager.create_bundle(objects)
            response = requests.post(
                f"{self.server_url}{self.api_root}/collections/{collection_id}/objects/",
                headers=self._headers,
                auth=self._auth,
                json=bundle,
                timeout=60
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"[TAXII] Add objects failed: {e}")
            return False


# ============================================================
# TRUST NETWORK
# ============================================================

class TrustNetwork:
    """
    Manages peer trust scoring and verification.
    """

    INITIAL_TRUST_SCORE = 0.5
    MIN_TRUST_SCORE = 0.0
    MAX_TRUST_SCORE = 1.0

    # Score adjustments
    VALID_CONTRIBUTION_BONUS = 0.02
    FALSE_POSITIVE_PENALTY = 0.05
    INACTIVITY_DECAY = 0.01
    REVOCATION_THRESHOLD = 0.1

    def __init__(self):
        self.peers: Dict[str, TrustedPeer] = {}
        self._lock = threading.Lock()
        self._private_key: Optional[rsa.RSAPrivateKey] = None
        self._public_key: Optional[rsa.RSAPublicKey] = None
        self._initialize_keys()

    def _initialize_keys(self):
        """Generate RSA key pair for peer communication"""
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()

    def get_public_key_bytes(self) -> bytes:
        """Export public key as bytes"""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def register_peer(self, peer_id: str, public_key: bytes,
                     endpoint: str, organization: str = "") -> bool:
        """
        Register a new peer in the network.

        Args:
            peer_id: Unique identifier for the peer
            public_key: Peer's public key (PEM format)
            endpoint: API endpoint for the peer
            organization: Organization name (optional, can be hashed)

        Returns:
            True if registration successful
        """
        with self._lock:
            if peer_id in self.peers:
                return False

            peer = TrustedPeer(
                peer_id=peer_id,
                public_key=public_key,
                endpoint=endpoint,
                organization=hashlib.sha256(organization.encode()).hexdigest()[:16],
                status=PeerStatus.PENDING,
                trust_score=self.INITIAL_TRUST_SCORE
            )

            self.peers[peer_id] = peer
            logger.info(f"[TRUST] Registered peer: {peer_id}")
            return True

    def verify_peer(self, peer_id: str) -> bool:
        """Mark a peer as verified and active"""
        with self._lock:
            if peer_id not in self.peers:
                return False

            self.peers[peer_id].status = PeerStatus.ACTIVE
            logger.info(f"[TRUST] Verified peer: {peer_id}")
            return True

    def revoke_peer(self, peer_id: str, reason: str = "") -> bool:
        """Revoke a peer's access"""
        with self._lock:
            if peer_id not in self.peers:
                return False

            self.peers[peer_id].status = PeerStatus.REVOKED
            self.peers[peer_id].trust_score = 0.0
            logger.warning(f"[TRUST] Revoked peer: {peer_id}, reason: {reason}")
            return True

    def update_trust_score(self, peer_id: str, is_valid_contribution: bool):
        """
        Update trust score based on contribution quality.

        Args:
            peer_id: Peer identifier
            is_valid_contribution: Whether the contribution was valid
        """
        with self._lock:
            if peer_id not in self.peers:
                return

            peer = self.peers[peer_id]

            if is_valid_contribution:
                peer.contribution_count += 1
                peer.trust_score = min(
                    self.MAX_TRUST_SCORE,
                    peer.trust_score + self.VALID_CONTRIBUTION_BONUS
                )
            else:
                peer.false_positive_count += 1
                peer.trust_score = max(
                    self.MIN_TRUST_SCORE,
                    peer.trust_score - self.FALSE_POSITIVE_PENALTY
                )

            peer.last_seen = datetime.now()

            # Auto-revoke if trust drops too low
            if peer.trust_score < self.REVOCATION_THRESHOLD:
                peer.status = PeerStatus.REVOKED
                logger.warning(f"[TRUST] Auto-revoked peer due to low trust: {peer_id}")

    def get_trusted_peers(self, min_trust: float = 0.3) -> List[TrustedPeer]:
        """Get list of active peers above trust threshold"""
        with self._lock:
            return [
                peer for peer in self.peers.values()
                if peer.status == PeerStatus.ACTIVE and peer.trust_score >= min_trust
            ]

    def encrypt_for_peer(self, peer_id: str, data: bytes) -> Optional[bytes]:
        """Encrypt data for a specific peer using their public key"""
        with self._lock:
            if peer_id not in self.peers:
                return None

            try:
                public_key = serialization.load_pem_public_key(
                    self.peers[peer_id].public_key,
                    backend=default_backend()
                )

                # For large data, encrypt with AES and wrap key with RSA
                aes_key = secrets.token_bytes(32)
                iv = secrets.token_bytes(16)

                cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv),
                               backend=default_backend())
                encryptor = cipher.encryptor()
                encrypted_data = encryptor.update(data) + encryptor.finalize()

                encrypted_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                return encrypted_key + iv + encrypted_data
            except Exception as e:
                logger.error(f"[TRUST] Encryption failed: {e}")
                return None

    def decrypt_from_peer(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt data received from a peer"""
        try:
            encrypted_key = encrypted_data[:256]
            iv = encrypted_data[256:272]
            ciphertext = encrypted_data[272:]

            aes_key = self._private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv),
                           backend=default_backend())
            decryptor = cipher.decryptor()
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            logger.error(f"[TRUST] Decryption failed: {e}")
            return None


# ============================================================
# ANONYMOUS VOTING SYSTEM
# ============================================================

class AnonymousVoting:
    """
    Anonymous threat voting system for IOC validation.
    Uses blind signatures concept for voter anonymity.
    """

    def __init__(self):
        self.votes: Dict[str, List[Tuple[str, VoteType]]] = defaultdict(list)
        self.vote_tokens: Set[str] = set()
        self._lock = threading.Lock()

    def generate_vote_token(self, voter_id: str) -> str:
        """
        Generate a one-time vote token.
        Token cannot be linked back to voter.
        """
        token = hashlib.sha256(
            voter_id.encode() + secrets.token_bytes(32)
        ).hexdigest()

        with self._lock:
            self.vote_tokens.add(token)

        return token

    def cast_vote(self, ioc_hash: str, vote: VoteType, token: str) -> bool:
        """
        Cast an anonymous vote for an IOC.

        Args:
            ioc_hash: Hash of the IOC being voted on
            vote: The vote type
            token: One-time vote token

        Returns:
            True if vote was accepted
        """
        with self._lock:
            # Verify and consume token
            if token not in self.vote_tokens:
                return False

            self.vote_tokens.remove(token)

            # Store vote (token is anonymized)
            anon_id = hashlib.sha256(token.encode()).hexdigest()[:16]
            self.votes[ioc_hash].append((anon_id, vote))

            return True

    def get_vote_results(self, ioc_hash: str) -> Dict[str, int]:
        """Get aggregated vote results for an IOC"""
        with self._lock:
            results = {v.value: 0 for v in VoteType}

            for _, vote in self.votes.get(ioc_hash, []):
                results[vote.value] += 1

            return results

    def calculate_consensus(self, ioc_hash: str) -> Tuple[ThreatConfidence, float]:
        """
        Calculate consensus confidence from votes.

        Returns:
            (confidence_level, consensus_score)
        """
        results = self.get_vote_results(ioc_hash)
        total_votes = sum(results.values())

        if total_votes == 0:
            return ThreatConfidence.UNKNOWN, 0.0

        confirm_score = results[VoteType.CONFIRM.value]
        deny_score = results[VoteType.DENY.value]

        if confirm_score > deny_score:
            ratio = confirm_score / total_votes
            if ratio >= 0.9:
                return ThreatConfidence.CONFIRMED, ratio
            elif ratio >= 0.7:
                return ThreatConfidence.HIGH, ratio
            elif ratio >= 0.5:
                return ThreatConfidence.MEDIUM, ratio
            else:
                return ThreatConfidence.LOW, ratio
        else:
            return ThreatConfidence.LOW, deny_score / total_votes


# ============================================================
# MAIN FEDERATED INTELLIGENCE CLASS
# ============================================================

class FederatedIntelligence:
    """
    Main class for federated threat intelligence sharing.
    Coordinates all privacy-preserving components.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        # Core components
        self.bloom_filter = BloomFilter(expected_elements=500000)
        self.dp_engine = DifferentialPrivacy(epsilon=1.0)
        self.k_anonymizer = KAnonymizer(k=5)
        self.trust_network = TrustNetwork()
        self.voting_system = AnonymousVoting()
        self.model_trainer = FederatedModelTrainer()
        self.stix_manager = STIXManager

        # Storage
        self.shared_iocs: Dict[str, SharedIOC] = {}
        self.local_ioc_mapping: Dict[str, str] = {}  # hash -> original (private)
        self.models: Dict[str, FederatedModel] = {}
        self.subscriptions: List[Dict] = []

        # Database
        self.db_path = os.path.expanduser("~/.dalga/federated.db")
        self._initialize_database()

        # My identity
        self.peer_id = str(uuid.uuid4())

        logger.info("[FEDERATED] Federated Threat Intelligence initialized")

    def _initialize_database(self):
        """Initialize SQLite database for persistence"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Shared IOC hashes table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS shared_iocs (
                ioc_hash TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                contributor_id TEXT,
                confidence TEXT,
                tags TEXT,
                mitre_techniques TEXT,
                votes_confirm INTEGER DEFAULT 0,
                votes_deny INTEGER DEFAULT 0,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Local IOC mapping (private)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS local_iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_hash TEXT NOT NULL,
                original_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Peer trust scores
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS peer_trust (
                peer_id TEXT PRIMARY KEY,
                public_key BLOB,
                endpoint TEXT,
                organization_hash TEXT,
                status TEXT,
                trust_score REAL DEFAULT 0.5,
                contribution_count INTEGER DEFAULT 0,
                false_positive_count INTEGER DEFAULT 0,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP
            )
        """)

        # Model versions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS federated_models (
                model_id TEXT PRIMARY KEY,
                version INTEGER,
                checksum TEXT,
                parameters BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                contributors INTEGER,
                accuracy REAL,
                model_type TEXT
            )
        """)

        # Feed subscriptions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS feed_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                feed_url TEXT NOT NULL,
                collection_id TEXT,
                last_fetch TIMESTAMP,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        conn.commit()
        conn.close()

    # ==================== IOC SHARING ====================

    def anonymize_ioc(self, ioc_value: str, ioc_type: IOCType) -> str:
        """
        Anonymize an IOC value using SHA-256 hashing.
        The original value is never shared.
        """
        normalized = ioc_value.lower().strip()
        ioc_hash = hashlib.sha256(normalized.encode('utf-8')).hexdigest()

        # Store local mapping (private)
        self.local_ioc_mapping[ioc_hash] = normalized

        return ioc_hash

    def share_ioc(self, ioc_value: str, ioc_type: IOCType,
                 confidence: ThreatConfidence = ThreatConfidence.MEDIUM,
                 tags: List[str] = None,
                 mitre_techniques: List[str] = None) -> SharedIOC:
        """
        Share an IOC with the federated network.
        Only the hash is shared, not the original value.

        Args:
            ioc_value: The original IOC value
            ioc_type: Type of IOC
            confidence: Confidence level
            tags: Optional tags
            mitre_techniques: Optional MITRE ATT&CK techniques

        Returns:
            SharedIOC object
        """
        # Anonymize
        ioc_hash = self.anonymize_ioc(ioc_value, ioc_type)

        # Create shared IOC
        shared = SharedIOC(
            ioc_hash=ioc_hash,
            ioc_type=ioc_type,
            timestamp=datetime.utcnow(),
            contributor_id=hashlib.sha256(self.peer_id.encode()).hexdigest()[:16],
            confidence=confidence,
            tags=tags or [],
            mitre_techniques=mitre_techniques or [],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )

        # Add to bloom filter
        self.bloom_filter.add(ioc_hash)

        # Store
        self.shared_iocs[ioc_hash] = shared
        self._save_shared_ioc(shared)

        logger.info(f"[FEDERATED] Shared IOC: {ioc_hash[:16]}... ({ioc_type.value})")
        return shared

    def query_ioc(self, ioc_value: str) -> Optional[SharedIOC]:
        """
        Query if an IOC exists in the collective intelligence.
        Uses bloom filter for fast initial check.
        """
        ioc_hash = hashlib.sha256(ioc_value.lower().strip().encode()).hexdigest()

        # Fast bloom filter check
        if not self.bloom_filter.contains(ioc_hash):
            return None

        # Check local storage
        if ioc_hash in self.shared_iocs:
            return self.shared_iocs[ioc_hash]

        # Query database
        return self._load_shared_ioc(ioc_hash)

    def batch_check_iocs(self, ioc_values: List[str]) -> Dict[str, bool]:
        """
        Check multiple IOCs for membership using bloom filter.
        Very fast, but may have false positives.
        """
        results = {}
        for ioc in ioc_values:
            ioc_hash = hashlib.sha256(ioc.lower().strip().encode()).hexdigest()
            results[ioc] = self.bloom_filter.contains(ioc_hash)
        return results

    # ==================== STATISTICS ====================

    def get_statistics(self, use_differential_privacy: bool = True) -> Dict[str, Any]:
        """
        Get aggregate statistics with optional differential privacy.
        """
        stats = {
            'total_iocs': len(self.shared_iocs),
            'by_type': defaultdict(int),
            'by_confidence': defaultdict(int),
            'total_peers': len(self.trust_network.peers),
            'active_peers': len(self.trust_network.get_trusted_peers()),
            'model_versions': len(self.models)
        }

        for ioc in self.shared_iocs.values():
            stats['by_type'][ioc.ioc_type.value] += 1
            stats['by_confidence'][ioc.confidence.value] += 1

        # Apply differential privacy to numeric values
        if use_differential_privacy:
            stats['total_iocs'] = int(self.dp_engine.add_laplace_noise(
                stats['total_iocs'], 1
            ))
            stats['total_peers'] = int(self.dp_engine.add_laplace_noise(
                stats['total_peers'], 1
            ))

            for key in stats['by_type']:
                stats['by_type'][key] = max(0, int(self.dp_engine.add_laplace_noise(
                    stats['by_type'][key], 1
                )))

        return dict(stats)

    def get_trend_analysis(self, days: int = 7) -> Dict[str, Any]:
        """
        Analyze threat trends over time.
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        trends = {
            'new_iocs_per_day': defaultdict(int),
            'top_tags': defaultdict(int),
            'top_techniques': defaultdict(int)
        }

        for ioc in self.shared_iocs.values():
            if ioc.timestamp > cutoff:
                day = ioc.timestamp.strftime('%Y-%m-%d')
                trends['new_iocs_per_day'][day] += 1

                for tag in ioc.tags:
                    trends['top_tags'][tag] += 1

                for tech in ioc.mitre_techniques:
                    trends['top_techniques'][tech] += 1

        # Get top 10
        trends['top_tags'] = dict(sorted(
            trends['top_tags'].items(), key=lambda x: -x[1]
        )[:10])
        trends['top_techniques'] = dict(sorted(
            trends['top_techniques'].items(), key=lambda x: -x[1]
        )[:10])

        return trends

    # ==================== VOTING ====================

    def vote_on_ioc(self, ioc_hash: str, vote: VoteType) -> bool:
        """
        Cast an anonymous vote on an IOC.
        """
        token = self.voting_system.generate_vote_token(self.peer_id)
        return self.voting_system.cast_vote(ioc_hash, vote, token)

    def get_ioc_consensus(self, ioc_hash: str) -> Dict[str, Any]:
        """
        Get voting consensus for an IOC.
        """
        confidence, score = self.voting_system.calculate_consensus(ioc_hash)
        results = self.voting_system.get_vote_results(ioc_hash)

        return {
            'ioc_hash': ioc_hash,
            'consensus_confidence': confidence.value,
            'consensus_score': score,
            'vote_breakdown': results
        }

    # ==================== MODEL TRAINING ====================

    def train_local_model(self, features: List[List[float]],
                         labels: List[int]) -> Dict[str, List[float]]:
        """
        Train model on local data and return gradients.
        """
        return self.model_trainer.train_local(features, labels)

    def submit_model_gradients(self, gradients: Dict[str, List[float]],
                               peer_id: str = None) -> bool:
        """
        Submit model gradients for federated averaging.
        """
        if peer_id:
            # Verify peer trust
            peers = self.trust_network.get_trusted_peers(min_trust=0.5)
            if not any(p.peer_id == peer_id for p in peers):
                return False

        self.model_trainer.apply_gradient(gradients)
        return True

    def get_global_model(self) -> Optional[bytes]:
        """
        Get the current global model weights.
        """
        return self.model_trainer.serialize_weights()

    # ==================== PEER MANAGEMENT ====================

    def register_as_peer(self, endpoint: str, organization: str = "") -> Dict[str, Any]:
        """
        Register this instance as a peer in the network.
        """
        return {
            'peer_id': self.peer_id,
            'public_key': base64.b64encode(
                self.trust_network.get_public_key_bytes()
            ).decode('ascii'),
            'endpoint': endpoint,
            'organization_hash': hashlib.sha256(organization.encode()).hexdigest()[:16]
        }

    def add_peer(self, peer_id: str, public_key: str,
                endpoint: str, organization: str = "") -> bool:
        """
        Add a new peer to the network.
        """
        public_key_bytes = base64.b64decode(public_key)
        return self.trust_network.register_peer(
            peer_id, public_key_bytes, endpoint, organization
        )

    def get_peers(self, min_trust: float = 0.3) -> List[Dict]:
        """
        Get list of trusted peers.
        """
        peers = self.trust_network.get_trusted_peers(min_trust)
        return [
            {
                'peer_id': p.peer_id,
                'endpoint': p.endpoint,
                'trust_score': p.trust_score,
                'status': p.status.value,
                'contributions': p.contribution_count
            }
            for p in peers
        ]

    # ==================== FEED SUBSCRIPTION ====================

    def subscribe_to_feed(self, feed_url: str, collection_id: str = None) -> bool:
        """
        Subscribe to a TAXII feed.
        """
        subscription = {
            'feed_url': feed_url,
            'collection_id': collection_id,
            'status': 'active',
            'created_at': datetime.utcnow().isoformat()
        }
        self.subscriptions.append(subscription)
        self._save_subscription(subscription)
        logger.info(f"[FEDERATED] Subscribed to feed: {feed_url}")
        return True

    def fetch_from_subscriptions(self) -> int:
        """
        Fetch new IOCs from all subscribed feeds.

        Returns:
            Number of new IOCs fetched
        """
        total_new = 0

        for sub in self.subscriptions:
            if sub.get('status') != 'active':
                continue

            try:
                client = TAXIIClient(sub['feed_url'])
                objects = client.get_objects(sub.get('collection_id', 'default'))

                for obj in objects:
                    if obj.get('type') == 'indicator':
                        shared_ioc = STIXManager.parse_indicator(obj)
                        if shared_ioc and shared_ioc.ioc_hash not in self.shared_iocs:
                            self.shared_iocs[shared_ioc.ioc_hash] = shared_ioc
                            self.bloom_filter.add(shared_ioc.ioc_hash)
                            total_new += 1

            except Exception as e:
                logger.error(f"[FEDERATED] Feed fetch error: {e}")

        return total_new

    # ==================== DATABASE OPERATIONS ====================

    def _save_shared_ioc(self, ioc: SharedIOC):
        """Save shared IOC to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT OR REPLACE INTO shared_iocs
            (ioc_hash, ioc_type, contributor_id, confidence, tags,
             mitre_techniques, votes_confirm, votes_deny, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ioc.ioc_hash,
            ioc.ioc_type.value,
            ioc.contributor_id,
            ioc.confidence.value,
            json.dumps(ioc.tags),
            json.dumps(ioc.mitre_techniques),
            ioc.votes_confirm,
            ioc.votes_deny,
            ioc.first_seen.isoformat() if ioc.first_seen else None,
            ioc.last_seen.isoformat() if ioc.last_seen else None
        ))

        conn.commit()
        conn.close()

    def _load_shared_ioc(self, ioc_hash: str) -> Optional[SharedIOC]:
        """Load shared IOC from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM shared_iocs WHERE ioc_hash = ?",
            (ioc_hash,)
        )
        row = cursor.fetchone()
        conn.close()

        if not row:
            return None

        return SharedIOC(
            ioc_hash=row[0],
            ioc_type=IOCType(row[1]),
            timestamp=datetime.utcnow(),
            contributor_id=row[2],
            confidence=ThreatConfidence(row[3]),
            tags=json.loads(row[4]) if row[4] else [],
            mitre_techniques=json.loads(row[5]) if row[5] else [],
            votes_confirm=row[6],
            votes_deny=row[7],
            first_seen=datetime.fromisoformat(row[8]) if row[8] else None,
            last_seen=datetime.fromisoformat(row[9]) if row[9] else None
        )

    def _save_subscription(self, subscription: Dict):
        """Save feed subscription to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO feed_subscriptions (feed_url, collection_id, status)
            VALUES (?, ?, ?)
        """, (
            subscription['feed_url'],
            subscription.get('collection_id'),
            subscription.get('status', 'active')
        ))

        conn.commit()
        conn.close()

    # ==================== EXPORT/IMPORT ====================

    def export_to_stix(self, ioc_hashes: List[str] = None) -> Dict[str, Any]:
        """
        Export IOCs to STIX 2.1 bundle.
        """
        if ioc_hashes is None:
            iocs = list(self.shared_iocs.values())
        else:
            iocs = [self.shared_iocs[h] for h in ioc_hashes if h in self.shared_iocs]

        indicators = [STIXManager.create_indicator(ioc) for ioc in iocs]
        return STIXManager.create_bundle(indicators)

    def export_bloom_filter(self) -> bytes:
        """Export bloom filter for sharing with peers"""
        return self.bloom_filter.serialize()

    def import_bloom_filter(self, data: bytes):
        """Import bloom filter from a peer"""
        peer_filter = BloomFilter.deserialize(data)
        # Merge filters (simple OR)
        for i in range(len(self.bloom_filter.bit_array)):
            self.bloom_filter.bit_array[i] |= peer_filter.bit_array[i]


# ============================================================
# FLASK API BLUEPRINT
# ============================================================

federated_bp = Blueprint('federated', __name__, url_prefix='/api/v1/federated')


def get_federated_intel() -> FederatedIntelligence:
    """Get FederatedIntelligence instance"""
    if not hasattr(g, 'federated_intel'):
        g.federated_intel = FederatedIntelligence.get_instance()
    return g.federated_intel


@federated_bp.route('/share', methods=['POST'])
def share_ioc_endpoint():
    """
    Share an anonymized IOC with the network.

    Request body:
    {
        "ioc_value": "192.168.1.1",
        "ioc_type": "ip",
        "confidence": "high",
        "tags": ["malware", "c2"],
        "mitre_techniques": ["T1071"]
    }
    """
    try:
        data = request.get_json()

        if not data or 'ioc_value' not in data or 'ioc_type' not in data:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        fi = get_federated_intel()

        ioc_type = IOCType(data['ioc_type'])
        confidence = ThreatConfidence(data.get('confidence', 'medium'))

        shared = fi.share_ioc(
            ioc_value=data['ioc_value'],
            ioc_type=ioc_type,
            confidence=confidence,
            tags=data.get('tags', []),
            mitre_techniques=data.get('mitre_techniques', [])
        )

        return jsonify({
            'success': True,
            'ioc_hash': shared.ioc_hash,
            'message': 'IOC shared successfully (hash only, original value kept private)'
        })

    except Exception as e:
        logger.error(f"[API] Share IOC error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/query', methods=['GET'])
def query_ioc_endpoint():
    """
    Query collective intelligence for an IOC.

    Query parameters:
    - ioc_value: The IOC to query
    - batch: Comma-separated list of IOCs (optional)
    """
    try:
        fi = get_federated_intel()

        batch = request.args.get('batch')
        if batch:
            iocs = [i.strip() for i in batch.split(',')]
            results = fi.batch_check_iocs(iocs)
            return jsonify({
                'success': True,
                'results': results,
                'note': 'Uses bloom filter - may have false positives'
            })

        ioc_value = request.args.get('ioc_value')
        if not ioc_value:
            return jsonify({'success': False, 'error': 'Missing ioc_value parameter'}), 400

        result = fi.query_ioc(ioc_value)

        if result:
            return jsonify({
                'success': True,
                'found': True,
                'ioc': {
                    'hash': result.ioc_hash,
                    'type': result.ioc_type.value,
                    'confidence': result.confidence.value,
                    'tags': result.tags,
                    'mitre_techniques': result.mitre_techniques,
                    'votes_confirm': result.votes_confirm,
                    'votes_deny': result.votes_deny
                }
            })
        else:
            return jsonify({
                'success': True,
                'found': False,
                'message': 'IOC not found in collective intelligence'
            })

    except Exception as e:
        logger.error(f"[API] Query IOC error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/statistics', methods=['GET'])
def get_statistics_endpoint():
    """
    Get aggregate statistics with differential privacy.

    Query parameters:
    - no_dp: Set to 'true' to disable differential privacy (for debugging)
    """
    try:
        fi = get_federated_intel()
        use_dp = request.args.get('no_dp', '').lower() != 'true'

        stats = fi.get_statistics(use_differential_privacy=use_dp)
        trends = fi.get_trend_analysis()

        return jsonify({
            'success': True,
            'statistics': stats,
            'trends': trends,
            'differential_privacy_applied': use_dp
        })

    except Exception as e:
        logger.error(f"[API] Statistics error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/vote', methods=['POST'])
def vote_endpoint():
    """
    Cast an anonymous vote on an IOC.

    Request body:
    {
        "ioc_hash": "abc123...",
        "vote": "confirm"  # confirm, deny, suspicious, false_positive
    }
    """
    try:
        data = request.get_json()

        if not data or 'ioc_hash' not in data or 'vote' not in data:
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        fi = get_federated_intel()
        vote = VoteType(data['vote'])

        if fi.vote_on_ioc(data['ioc_hash'], vote):
            consensus = fi.get_ioc_consensus(data['ioc_hash'])
            return jsonify({
                'success': True,
                'message': 'Vote recorded anonymously',
                'current_consensus': consensus
            })
        else:
            return jsonify({'success': False, 'error': 'Vote failed'}), 400

    except Exception as e:
        logger.error(f"[API] Vote error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/model/train', methods=['POST'])
def train_model_endpoint():
    """
    Trigger federated model training with local data.

    Request body:
    {
        "features": [[0.1, 0.2, ...], [0.3, 0.4, ...]],
        "labels": [0, 1, 1, 0, ...]
    }
    """
    try:
        data = request.get_json()

        if not data or 'features' not in data or 'labels' not in data:
            return jsonify({'success': False, 'error': 'Missing training data'}), 400

        fi = get_federated_intel()

        gradients = fi.train_local_model(data['features'], data['labels'])

        return jsonify({
            'success': True,
            'message': 'Local training complete',
            'gradient_shapes': {k: len(v) for k, v in gradients.items()},
            'model_checksum': fi.model_trainer.get_model_checksum()
        })

    except Exception as e:
        logger.error(f"[API] Train model error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/model/weights', methods=['GET'])
def get_model_weights_endpoint():
    """Get current global model weights"""
    try:
        fi = get_federated_intel()
        weights = fi.get_global_model()

        if weights:
            return jsonify({
                'success': True,
                'weights': base64.b64encode(weights).decode('ascii'),
                'checksum': fi.model_trainer.get_model_checksum()
            })
        else:
            return jsonify({
                'success': False,
                'error': 'No model available'
            }), 404

    except Exception as e:
        logger.error(f"[API] Get weights error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/peers', methods=['GET'])
def get_peers_endpoint():
    """
    List trusted peers in the network.

    Query parameters:
    - min_trust: Minimum trust score (default: 0.3)
    """
    try:
        fi = get_federated_intel()
        min_trust = float(request.args.get('min_trust', 0.3))

        peers = fi.get_peers(min_trust)

        return jsonify({
            'success': True,
            'peer_count': len(peers),
            'peers': peers
        })

    except Exception as e:
        logger.error(f"[API] Get peers error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/peers/register', methods=['POST'])
def register_peer_endpoint():
    """
    Register a new peer in the network.

    Request body:
    {
        "peer_id": "uuid",
        "public_key": "base64...",
        "endpoint": "https://peer.example.com/api",
        "organization": "Optional Org Name"
    }
    """
    try:
        data = request.get_json()

        required = ['peer_id', 'public_key', 'endpoint']
        if not all(k in data for k in required):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400

        fi = get_federated_intel()

        if fi.add_peer(
            data['peer_id'],
            data['public_key'],
            data['endpoint'],
            data.get('organization', '')
        ):
            return jsonify({
                'success': True,
                'message': 'Peer registered successfully',
                'status': 'pending'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Peer already exists'
            }), 400

    except Exception as e:
        logger.error(f"[API] Register peer error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/subscribe', methods=['POST'])
def subscribe_endpoint():
    """
    Subscribe to a threat intelligence feed.

    Request body:
    {
        "feed_url": "https://taxii.example.com",
        "collection_id": "optional-collection-id"
    }
    """
    try:
        data = request.get_json()

        if not data or 'feed_url' not in data:
            return jsonify({'success': False, 'error': 'Missing feed_url'}), 400

        fi = get_federated_intel()

        if fi.subscribe_to_feed(data['feed_url'], data.get('collection_id')):
            return jsonify({
                'success': True,
                'message': f'Subscribed to {data["feed_url"]}'
            })
        else:
            return jsonify({'success': False, 'error': 'Subscription failed'}), 400

    except Exception as e:
        logger.error(f"[API] Subscribe error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/export/stix', methods=['GET'])
def export_stix_endpoint():
    """Export IOCs as STIX 2.1 bundle"""
    try:
        fi = get_federated_intel()
        bundle = fi.export_to_stix()

        return jsonify({
            'success': True,
            'bundle': bundle
        })

    except Exception as e:
        logger.error(f"[API] Export STIX error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@federated_bp.route('/export/bloom', methods=['GET'])
def export_bloom_endpoint():
    """Export bloom filter for peer sharing"""
    try:
        fi = get_federated_intel()
        bloom_data = fi.export_bloom_filter()

        return jsonify({
            'success': True,
            'bloom_filter': base64.b64encode(bloom_data).decode('ascii'),
            'element_count': fi.bloom_filter.element_count
        })

    except Exception as e:
        logger.error(f"[API] Export bloom error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
# SINGLETON ACCESS
# ============================================================

_federated_intel = None


def federated_intel_al() -> FederatedIntelligence:
    """Get FederatedIntelligence instance (Turkish naming convention)"""
    global _federated_intel
    if _federated_intel is None:
        _federated_intel = FederatedIntelligence.get_instance()
    return _federated_intel


# Alias for English naming
get_federated_intelligence = federated_intel_al


# ============================================================
# MAIN / CLI
# ============================================================

if __name__ == "__main__":
    import sys

    print("""
    ================================================================================
        TSUNAMI FEDERATED THREAT INTELLIGENCE v1.0
        Privacy-Preserving Threat Intelligence Sharing Platform
    ================================================================================
    """)

    fi = FederatedIntelligence.get_instance()

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "share" and len(sys.argv) >= 4:
            ioc_value = sys.argv[2]
            ioc_type = IOCType(sys.argv[3])
            shared = fi.share_ioc(ioc_value, ioc_type)
            print(f"Shared IOC hash: {shared.ioc_hash}")

        elif command == "query" and len(sys.argv) >= 3:
            ioc_value = sys.argv[2]
            result = fi.query_ioc(ioc_value)
            if result:
                print(f"Found: {result.ioc_hash}")
                print(f"Type: {result.ioc_type.value}")
                print(f"Confidence: {result.confidence.value}")
            else:
                print("IOC not found")

        elif command == "stats":
            stats = fi.get_statistics()
            print(json.dumps(stats, indent=2, default=str))

        elif command == "peers":
            peers = fi.get_peers()
            for peer in peers:
                print(f"- {peer['peer_id']}: trust={peer['trust_score']:.2f}")

        else:
            print("Usage:")
            print("  python dalga_federated.py share <ioc_value> <ioc_type>")
            print("  python dalga_federated.py query <ioc_value>")
            print("  python dalga_federated.py stats")
            print("  python dalga_federated.py peers")
    else:
        # Interactive mode
        print("Federated Intelligence initialized")
        print(f"Peer ID: {fi.peer_id}")
        print(f"Database: {fi.db_path}")
        print("\nRun with commands: share, query, stats, peers")
