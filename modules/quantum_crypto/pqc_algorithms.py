"""
Post-Quantum Cryptography Algorithms

Implements NIST-standardized post-quantum cryptographic primitives:
- ML-KEM (formerly Kyber) for Key Encapsulation Mechanism
- ML-DSA (formerly Dilithium) for Digital Signatures
- Hybrid mode combining classical ECDH/ECDSA with PQC

Uses the pqcrypto library for REAL cryptographic operations.
"""

import os
import hashlib
import secrets
from enum import Enum
from dataclasses import dataclass, field
from typing import Tuple, Optional, Dict, Any
from datetime import datetime, timezone

# Post-Quantum Cryptography imports
from pqcrypto.kem import ml_kem_512, ml_kem_768, ml_kem_1024
from pqcrypto.sign import ml_dsa_44, ml_dsa_65, ml_dsa_87

# Classical cryptography for hybrid mode
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class SecurityLevel(Enum):
    """
    NIST Security Levels for post-quantum cryptography.

    Level 1: At least as hard to break as AES-128
    Level 3: At least as hard to break as AES-192
    Level 5: At least as hard to break as AES-256
    """
    LEVEL_1 = 1  # ML-KEM-512, ML-DSA-44 (128-bit security)
    LEVEL_3 = 3  # ML-KEM-768, ML-DSA-65 (192-bit security)
    LEVEL_5 = 5  # ML-KEM-1024, ML-DSA-87 (256-bit security)


@dataclass
class KeyPair:
    """Cryptographic key pair with metadata."""
    public_key: bytes
    secret_key: bytes
    algorithm: str
    security_level: SecurityLevel
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    key_id: str = field(default_factory=lambda: secrets.token_hex(16))

    def public_key_fingerprint(self) -> str:
        """Generate SHA-256 fingerprint of the public key."""
        return hashlib.sha256(self.public_key).hexdigest()

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        """Serialize key pair to dictionary."""
        result = {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "security_level": self.security_level.value,
            "created_at": self.created_at.isoformat(),
            "public_key": self.public_key.hex(),
            "public_key_fingerprint": self.public_key_fingerprint(),
            "public_key_size": len(self.public_key),
            "secret_key_size": len(self.secret_key),
        }
        if include_secret:
            result["secret_key"] = self.secret_key.hex()
        return result


@dataclass
class EncapsulationResult:
    """Result of a key encapsulation operation."""
    ciphertext: bytes
    shared_secret: bytes
    algorithm: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ciphertext": self.ciphertext.hex(),
            "ciphertext_size": len(self.ciphertext),
            "shared_secret_size": len(self.shared_secret),
            "algorithm": self.algorithm,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class SignatureResult:
    """Result of a signing operation."""
    signature: bytes
    message_hash: bytes
    algorithm: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signature": self.signature.hex(),
            "signature_size": len(self.signature),
            "message_hash": self.message_hash.hex(),
            "algorithm": self.algorithm,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HybridKeyPair:
    """Combined classical + post-quantum key pair."""
    pqc_keypair: KeyPair
    classical_public_key: bytes
    classical_secret_key: bytes
    classical_algorithm: str

    def to_dict(self, include_secret: bool = False) -> Dict[str, Any]:
        result = {
            "pqc": self.pqc_keypair.to_dict(include_secret),
            "classical": {
                "algorithm": self.classical_algorithm,
                "public_key": self.classical_public_key.hex(),
                "public_key_size": len(self.classical_public_key),
            }
        }
        if include_secret:
            result["classical"]["secret_key"] = self.classical_secret_key.hex()
        return result


class PQCAlgorithms:
    """
    Post-Quantum Cryptography Algorithm Provider

    Provides NIST-standardized post-quantum cryptographic operations:
    - Key generation for ML-KEM and ML-DSA at various security levels
    - Key encapsulation/decapsulation (KEM)
    - Digital signature generation/verification
    - Hybrid mode combining classical + PQC for defense-in-depth
    """

    # Algorithm mappings for KEM (Key Encapsulation Mechanism)
    KEM_ALGORITHMS = {
        SecurityLevel.LEVEL_1: ml_kem_512,
        SecurityLevel.LEVEL_3: ml_kem_768,
        SecurityLevel.LEVEL_5: ml_kem_1024,
    }

    # Algorithm mappings for Digital Signatures
    SIGN_ALGORITHMS = {
        SecurityLevel.LEVEL_1: ml_dsa_44,
        SecurityLevel.LEVEL_3: ml_dsa_65,
        SecurityLevel.LEVEL_5: ml_dsa_87,
    }

    # Algorithm names for metadata
    KEM_NAMES = {
        SecurityLevel.LEVEL_1: "ML-KEM-512",
        SecurityLevel.LEVEL_3: "ML-KEM-768",
        SecurityLevel.LEVEL_5: "ML-KEM-1024",
    }

    SIGN_NAMES = {
        SecurityLevel.LEVEL_1: "ML-DSA-44",
        SecurityLevel.LEVEL_3: "ML-DSA-65",
        SecurityLevel.LEVEL_5: "ML-DSA-87",
    }

    def __init__(self, default_security_level: SecurityLevel = SecurityLevel.LEVEL_3):
        """
        Initialize PQC algorithms provider.

        Args:
            default_security_level: Default NIST security level to use
        """
        self.default_security_level = default_security_level

    # ==================== KEY GENERATION ====================

    def generate_kem_keypair(
        self,
        security_level: Optional[SecurityLevel] = None
    ) -> KeyPair:
        """
        Generate a ML-KEM key pair for key encapsulation.

        Args:
            security_level: NIST security level (1, 3, or 5)

        Returns:
            KeyPair containing public and secret keys
        """
        level = security_level or self.default_security_level
        algorithm = self.KEM_ALGORITHMS[level]

        public_key, secret_key = algorithm.generate_keypair()

        return KeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm=self.KEM_NAMES[level],
            security_level=level,
        )

    def generate_sign_keypair(
        self,
        security_level: Optional[SecurityLevel] = None
    ) -> KeyPair:
        """
        Generate a ML-DSA key pair for digital signatures.

        Args:
            security_level: NIST security level (1, 3, or 5)

        Returns:
            KeyPair containing public and secret keys
        """
        level = security_level or self.default_security_level
        algorithm = self.SIGN_ALGORITHMS[level]

        public_key, secret_key = algorithm.generate_keypair()

        return KeyPair(
            public_key=public_key,
            secret_key=secret_key,
            algorithm=self.SIGN_NAMES[level],
            security_level=level,
        )

    # ==================== KEY ENCAPSULATION ====================

    def encapsulate(
        self,
        public_key: bytes,
        security_level: Optional[SecurityLevel] = None
    ) -> EncapsulationResult:
        """
        Encapsulate a shared secret using ML-KEM.

        This creates a random shared secret and encrypts it with the recipient's
        public key. Only the holder of the corresponding secret key can decrypt it.

        Args:
            public_key: Recipient's ML-KEM public key
            security_level: Security level of the public key

        Returns:
            EncapsulationResult with ciphertext and shared secret
        """
        level = security_level or self.default_security_level
        algorithm = self.KEM_ALGORITHMS[level]

        ciphertext, shared_secret = algorithm.encrypt(public_key)

        return EncapsulationResult(
            ciphertext=ciphertext,
            shared_secret=shared_secret,
            algorithm=self.KEM_NAMES[level],
        )

    def decapsulate(
        self,
        secret_key: bytes,
        ciphertext: bytes,
        security_level: Optional[SecurityLevel] = None
    ) -> bytes:
        """
        Decapsulate a shared secret using ML-KEM.

        Decrypts the ciphertext using the secret key to recover the shared secret.

        Args:
            secret_key: ML-KEM secret key
            ciphertext: Ciphertext from encapsulation
            security_level: Security level of the keys

        Returns:
            The decapsulated shared secret
        """
        level = security_level or self.default_security_level
        algorithm = self.KEM_ALGORITHMS[level]

        return algorithm.decrypt(secret_key, ciphertext)

    # ==================== DIGITAL SIGNATURES ====================

    def sign(
        self,
        secret_key: bytes,
        message: bytes,
        security_level: Optional[SecurityLevel] = None
    ) -> SignatureResult:
        """
        Sign a message using ML-DSA.

        Args:
            secret_key: ML-DSA secret key
            message: Message to sign
            security_level: Security level of the key

        Returns:
            SignatureResult containing the signature
        """
        level = security_level or self.default_security_level
        algorithm = self.SIGN_ALGORITHMS[level]

        # Hash the message for metadata (signature is on raw message)
        message_hash = hashlib.sha256(message).digest()

        signature = algorithm.sign(secret_key, message)

        return SignatureResult(
            signature=signature,
            message_hash=message_hash,
            algorithm=self.SIGN_NAMES[level],
        )

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
        security_level: Optional[SecurityLevel] = None
    ) -> bool:
        """
        Verify a ML-DSA signature.

        Args:
            public_key: ML-DSA public key
            message: Original message
            signature: Signature to verify
            security_level: Security level of the key

        Returns:
            True if signature is valid, False otherwise
        """
        level = security_level or self.default_security_level
        algorithm = self.SIGN_ALGORITHMS[level]

        try:
            return algorithm.verify(public_key, message, signature)
        except Exception:
            return False

    # ==================== HYBRID MODE ====================

    def generate_hybrid_kem_keypair(
        self,
        security_level: Optional[SecurityLevel] = None
    ) -> HybridKeyPair:
        """
        Generate a hybrid key pair combining X25519 (classical) with ML-KEM (PQC).

        This provides defense-in-depth: the combined key is secure as long as
        at least one of the underlying algorithms remains secure.

        Args:
            security_level: NIST security level for the PQC component

        Returns:
            HybridKeyPair with both classical and PQC keys
        """
        # Generate PQC keys
        pqc_keypair = self.generate_kem_keypair(security_level)

        # Generate classical X25519 keys
        classical_private = x25519.X25519PrivateKey.generate()
        classical_public = classical_private.public_key()

        # Serialize classical keys
        classical_public_bytes = classical_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        classical_secret_bytes = classical_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        return HybridKeyPair(
            pqc_keypair=pqc_keypair,
            classical_public_key=classical_public_bytes,
            classical_secret_key=classical_secret_bytes,
            classical_algorithm="X25519",
        )

    def hybrid_encapsulate(
        self,
        pqc_public_key: bytes,
        classical_public_key: bytes,
        security_level: Optional[SecurityLevel] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Perform hybrid key encapsulation using both X25519 and ML-KEM.

        The shared secrets from both algorithms are combined using HKDF to produce
        the final shared secret.

        Args:
            pqc_public_key: ML-KEM public key
            classical_public_key: X25519 public key
            security_level: NIST security level for ML-KEM

        Returns:
            Tuple of (pqc_ciphertext, classical_ciphertext, combined_shared_secret)
        """
        # PQC encapsulation
        pqc_result = self.encapsulate(pqc_public_key, security_level)

        # Classical X25519 key exchange
        ephemeral_private = x25519.X25519PrivateKey.generate()
        ephemeral_public = ephemeral_private.public_key()

        peer_public = x25519.X25519PublicKey.from_public_bytes(classical_public_key)
        classical_shared = ephemeral_private.exchange(peer_public)

        classical_ciphertext = ephemeral_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Combine shared secrets using HKDF
        combined_input = pqc_result.shared_secret + classical_shared
        combined_shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"TSUNAMI-HYBRID-KEM-v5",
            backend=default_backend()
        ).derive(combined_input)

        return pqc_result.ciphertext, classical_ciphertext, combined_shared_secret

    def hybrid_decapsulate(
        self,
        pqc_secret_key: bytes,
        classical_secret_key: bytes,
        pqc_ciphertext: bytes,
        classical_ciphertext: bytes,
        security_level: Optional[SecurityLevel] = None
    ) -> bytes:
        """
        Perform hybrid key decapsulation.

        Args:
            pqc_secret_key: ML-KEM secret key
            classical_secret_key: X25519 secret key
            pqc_ciphertext: PQC encapsulation ciphertext
            classical_ciphertext: Ephemeral X25519 public key
            security_level: NIST security level for ML-KEM

        Returns:
            Combined shared secret
        """
        # PQC decapsulation
        pqc_shared = self.decapsulate(pqc_secret_key, pqc_ciphertext, security_level)

        # Classical X25519 decapsulation
        private_key = x25519.X25519PrivateKey.from_private_bytes(classical_secret_key)
        peer_public = x25519.X25519PublicKey.from_public_bytes(classical_ciphertext)
        classical_shared = private_key.exchange(peer_public)

        # Combine shared secrets using HKDF
        combined_input = pqc_shared + classical_shared
        combined_shared_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"TSUNAMI-HYBRID-KEM-v5",
            backend=default_backend()
        ).derive(combined_input)

        return combined_shared_secret

    def generate_hybrid_sign_keypair(
        self,
        security_level: Optional[SecurityLevel] = None
    ) -> HybridKeyPair:
        """
        Generate a hybrid signing key pair combining Ed25519 (classical) with ML-DSA (PQC).

        Args:
            security_level: NIST security level for the PQC component

        Returns:
            HybridKeyPair with both classical and PQC signing keys
        """
        # Generate PQC signing keys
        pqc_keypair = self.generate_sign_keypair(security_level)

        # Generate classical Ed25519 keys
        classical_private = ed25519.Ed25519PrivateKey.generate()
        classical_public = classical_private.public_key()

        # Serialize classical keys
        classical_public_bytes = classical_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        classical_secret_bytes = classical_private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        return HybridKeyPair(
            pqc_keypair=pqc_keypair,
            classical_public_key=classical_public_bytes,
            classical_secret_key=classical_secret_bytes,
            classical_algorithm="Ed25519",
        )

    def hybrid_sign(
        self,
        pqc_secret_key: bytes,
        classical_secret_key: bytes,
        message: bytes,
        security_level: Optional[SecurityLevel] = None
    ) -> Tuple[bytes, bytes]:
        """
        Create a hybrid signature using both Ed25519 and ML-DSA.

        Args:
            pqc_secret_key: ML-DSA secret key
            classical_secret_key: Ed25519 secret key
            message: Message to sign
            security_level: NIST security level for ML-DSA

        Returns:
            Tuple of (pqc_signature, classical_signature)
        """
        # PQC signature
        pqc_result = self.sign(pqc_secret_key, message, security_level)

        # Classical Ed25519 signature
        classical_private = ed25519.Ed25519PrivateKey.from_private_bytes(classical_secret_key)
        classical_signature = classical_private.sign(message)

        return pqc_result.signature, classical_signature

    def hybrid_verify(
        self,
        pqc_public_key: bytes,
        classical_public_key: bytes,
        message: bytes,
        pqc_signature: bytes,
        classical_signature: bytes,
        security_level: Optional[SecurityLevel] = None,
        require_both: bool = True
    ) -> bool:
        """
        Verify a hybrid signature.

        Args:
            pqc_public_key: ML-DSA public key
            classical_public_key: Ed25519 public key
            message: Original message
            pqc_signature: ML-DSA signature
            classical_signature: Ed25519 signature
            security_level: NIST security level for ML-DSA
            require_both: If True, both signatures must verify. If False, at least one.

        Returns:
            True if verification passes according to require_both setting
        """
        # Verify PQC signature
        pqc_valid = self.verify(pqc_public_key, message, pqc_signature, security_level)

        # Verify classical signature
        try:
            classical_public = ed25519.Ed25519PublicKey.from_public_bytes(classical_public_key)
            classical_public.verify(classical_signature, message)
            classical_valid = True
        except Exception:
            classical_valid = False

        if require_both:
            return pqc_valid and classical_valid
        else:
            return pqc_valid or classical_valid

    # ==================== UTILITY METHODS ====================

    @staticmethod
    def get_algorithm_info(security_level: SecurityLevel) -> Dict[str, Any]:
        """Get information about algorithms at a security level."""
        kem_algo = PQCAlgorithms.KEM_ALGORITHMS[security_level]
        sign_algo = PQCAlgorithms.SIGN_ALGORITHMS[security_level]

        return {
            "security_level": security_level.value,
            "kem": {
                "name": PQCAlgorithms.KEM_NAMES[security_level],
                "public_key_size": kem_algo.PUBLIC_KEY_SIZE,
                "secret_key_size": kem_algo.SECRET_KEY_SIZE,
                "ciphertext_size": kem_algo.CIPHERTEXT_SIZE,
                "shared_secret_size": kem_algo.PLAINTEXT_SIZE,
            },
            "sign": {
                "name": PQCAlgorithms.SIGN_NAMES[security_level],
                "public_key_size": sign_algo.PUBLIC_KEY_SIZE,
                "secret_key_size": sign_algo.SECRET_KEY_SIZE,
                "signature_size": sign_algo.SIGNATURE_SIZE,
            },
        }

    @staticmethod
    def list_available_algorithms() -> Dict[str, Any]:
        """List all available PQC algorithms and their parameters."""
        return {
            level.name: PQCAlgorithms.get_algorithm_info(level)
            for level in SecurityLevel
        }
