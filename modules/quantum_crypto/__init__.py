"""
TSUNAMI v5.0 Quantum-Resistant Cryptography Module

This module provides post-quantum cryptographic primitives using NIST-standardized algorithms:
- ML-KEM (Kyber) for Key Encapsulation
- ML-DSA (Dilithium) for Digital Signatures
- Hybrid mode combining classical and post-quantum cryptography

All implementations use real cryptographic operations via the pqcrypto library.
"""

from .pqc_algorithms import (
    PQCAlgorithms,
    SecurityLevel,
    KeyPair,
    EncapsulationResult,
    SignatureResult,
)
from .secure_channel import SecureChannel, ChannelState, HandshakeResult
from .key_manager import KeyManager, KeyMetadata, KeyRotationPolicy
from .message_crypto import MessageCrypto, EncryptedMessage, SignedMessage
from .crypto_audit import CryptoAudit, AuditEvent, ComplianceReport

__version__ = "5.0.0"
__all__ = [
    "PQCAlgorithms",
    "SecurityLevel",
    "KeyPair",
    "EncapsulationResult",
    "SignatureResult",
    "SecureChannel",
    "ChannelState",
    "HandshakeResult",
    "KeyManager",
    "KeyMetadata",
    "KeyRotationPolicy",
    "MessageCrypto",
    "EncryptedMessage",
    "SignedMessage",
    "CryptoAudit",
    "AuditEvent",
    "ComplianceReport",
]
