"""
Secure Messaging with Post-Quantum Cryptography

Provides message-level encryption and signing:
- Hybrid encryption combining classical and PQC
- Digital signatures with ML-DSA
- Timestamps and non-repudiation
- Envelope format for secure message transport
"""

import json
import secrets
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, Union
from datetime import datetime, timezone
from enum import Enum

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .pqc_algorithms import PQCAlgorithms, SecurityLevel
from .key_manager import KeyManager, KeyType


class EncryptionAlgorithm(Enum):
    """Symmetric encryption algorithms for message content."""
    AES_256_GCM = "AES-256-GCM"
    CHACHA20_POLY1305 = "ChaCha20-Poly1305"


@dataclass
class EncryptedMessage:
    """An encrypted message with all necessary components for decryption."""
    message_id: str
    sender_key_id: Optional[str]
    recipient_key_id: str
    algorithm: str
    security_level: int
    is_hybrid: bool
    pqc_ciphertext: bytes
    classical_ciphertext: Optional[bytes]
    encrypted_content: bytes
    nonce: bytes
    timestamp: datetime
    content_hash: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "sender_key_id": self.sender_key_id,
            "recipient_key_id": self.recipient_key_id,
            "algorithm": self.algorithm,
            "security_level": self.security_level,
            "is_hybrid": self.is_hybrid,
            "pqc_ciphertext": self.pqc_ciphertext.hex(),
            "classical_ciphertext": self.classical_ciphertext.hex() if self.classical_ciphertext else None,
            "encrypted_content": self.encrypted_content.hex(),
            "nonce": self.nonce.hex(),
            "timestamp": self.timestamp.isoformat(),
            "content_hash": self.content_hash.hex(),
        }

    def to_bytes(self) -> bytes:
        """Serialize to bytes for transport."""
        return json.dumps(self.to_dict()).encode()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptedMessage":
        return cls(
            message_id=data["message_id"],
            sender_key_id=data.get("sender_key_id"),
            recipient_key_id=data["recipient_key_id"],
            algorithm=data["algorithm"],
            security_level=data["security_level"],
            is_hybrid=data["is_hybrid"],
            pqc_ciphertext=bytes.fromhex(data["pqc_ciphertext"]),
            classical_ciphertext=bytes.fromhex(data["classical_ciphertext"]) if data.get("classical_ciphertext") else None,
            encrypted_content=bytes.fromhex(data["encrypted_content"]),
            nonce=bytes.fromhex(data["nonce"]),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            content_hash=bytes.fromhex(data["content_hash"]),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "EncryptedMessage":
        return cls.from_dict(json.loads(data.decode()))


@dataclass
class SignedMessage:
    """A signed message with signature and verification data."""
    message_id: str
    signer_key_id: str
    algorithm: str
    security_level: int
    is_hybrid: bool
    content: bytes
    content_hash: bytes
    pqc_signature: bytes
    classical_signature: Optional[bytes]
    timestamp: datetime
    expiration: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "signer_key_id": self.signer_key_id,
            "algorithm": self.algorithm,
            "security_level": self.security_level,
            "is_hybrid": self.is_hybrid,
            "content": self.content.hex(),
            "content_hash": self.content_hash.hex(),
            "pqc_signature": self.pqc_signature.hex(),
            "classical_signature": self.classical_signature.hex() if self.classical_signature else None,
            "timestamp": self.timestamp.isoformat(),
            "expiration": self.expiration.isoformat() if self.expiration else None,
        }

    def to_bytes(self) -> bytes:
        """Serialize to bytes for transport."""
        return json.dumps(self.to_dict()).encode()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SignedMessage":
        return cls(
            message_id=data["message_id"],
            signer_key_id=data["signer_key_id"],
            algorithm=data["algorithm"],
            security_level=data["security_level"],
            is_hybrid=data["is_hybrid"],
            content=bytes.fromhex(data["content"]),
            content_hash=bytes.fromhex(data["content_hash"]),
            pqc_signature=bytes.fromhex(data["pqc_signature"]),
            classical_signature=bytes.fromhex(data["classical_signature"]) if data.get("classical_signature") else None,
            timestamp=datetime.fromisoformat(data["timestamp"]),
            expiration=datetime.fromisoformat(data["expiration"]) if data.get("expiration") else None,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedMessage":
        return cls.from_dict(json.loads(data.decode()))


@dataclass
class SecureEnvelope:
    """A complete secure message envelope with encryption and signature."""
    envelope_id: str
    encrypted_message: EncryptedMessage
    signature: Optional[SignedMessage]
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "encrypted_message": self.encrypted_message.to_dict(),
            "signature": self.signature.to_dict() if self.signature else None,
            "metadata": self.metadata,
        }

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict()).encode()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecureEnvelope":
        return cls(
            envelope_id=data["envelope_id"],
            encrypted_message=EncryptedMessage.from_dict(data["encrypted_message"]),
            signature=SignedMessage.from_dict(data["signature"]) if data.get("signature") else None,
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SecureEnvelope":
        return cls.from_dict(json.loads(data.decode()))


class MessageCrypto:
    """
    Secure Message Encryption and Signing

    Provides high-level message security using post-quantum cryptography:
    - Encrypt messages to a recipient's public key
    - Sign messages for authentication and non-repudiation
    - Hybrid mode for defense-in-depth
    - Timestamp binding for freshness
    """

    # Context strings for key derivation
    KDF_CONTEXT_ENCRYPT = b"TSUNAMI-v5-message-encrypt"
    KDF_CONTEXT_MAC = b"TSUNAMI-v5-message-mac"

    def __init__(
        self,
        key_manager: Optional[KeyManager] = None,
        security_level: SecurityLevel = SecurityLevel.LEVEL_3,
        use_hybrid: bool = True,
        symmetric_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM
    ):
        """
        Initialize message crypto provider.

        Args:
            key_manager: KeyManager instance for key retrieval
            security_level: Default NIST security level
            use_hybrid: Whether to use hybrid classical+PQC mode
            symmetric_algorithm: Symmetric cipher for content encryption
        """
        self.pqc = PQCAlgorithms(security_level)
        self.key_manager = key_manager
        self.security_level = security_level
        self.use_hybrid = use_hybrid
        self.symmetric_algorithm = symmetric_algorithm

    def _generate_message_id(self) -> str:
        """Generate a unique message identifier."""
        return secrets.token_hex(16)

    def _derive_content_key(
        self,
        shared_secret: bytes,
        message_id: str
    ) -> bytes:
        """Derive a content encryption key from the shared secret."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=message_id.encode(),
            info=self.KDF_CONTEXT_ENCRYPT,
            backend=default_backend()
        ).derive(shared_secret)

    def _get_cipher(self, key: bytes):
        """Get the appropriate cipher based on configuration."""
        if self.symmetric_algorithm == EncryptionAlgorithm.AES_256_GCM:
            return AESGCM(key)
        elif self.symmetric_algorithm == EncryptionAlgorithm.CHACHA20_POLY1305:
            return ChaCha20Poly1305(key)
        else:
            return AESGCM(key)

    # ==================== ENCRYPTION ====================

    def encrypt(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
        recipient_key_id: str,
        sender_key_id: Optional[str] = None,
        classical_public_key: Optional[bytes] = None,
        associated_data: Optional[bytes] = None
    ) -> EncryptedMessage:
        """
        Encrypt a message for a recipient.

        Uses hybrid encryption: PQC for key encapsulation, symmetric for content.

        Args:
            plaintext: Message content to encrypt
            recipient_public_key: Recipient's PQC public key
            recipient_key_id: Identifier for recipient's key
            sender_key_id: Optional sender key identifier
            classical_public_key: Classical public key for hybrid mode
            associated_data: Additional authenticated data

        Returns:
            EncryptedMessage with all components needed for decryption
        """
        message_id = self._generate_message_id()
        timestamp = datetime.now(timezone.utc)

        # Hash the plaintext for integrity verification
        content_hash = hashlib.sha256(plaintext).digest()

        # Perform key encapsulation
        if self.use_hybrid and classical_public_key:
            pqc_ct, classical_ct, shared_secret = self.pqc.hybrid_encapsulate(
                recipient_public_key,
                classical_public_key,
                self.security_level
            )
        else:
            result = self.pqc.encapsulate(recipient_public_key, self.security_level)
            pqc_ct = result.ciphertext
            classical_ct = None
            shared_secret = result.shared_secret

        # Derive content encryption key
        content_key = self._derive_content_key(shared_secret, message_id)

        # Encrypt content
        nonce = secrets.token_bytes(12)
        cipher = self._get_cipher(content_key)

        # Build AAD: message_id | timestamp | recipient_key_id
        aad = (
            message_id.encode() +
            timestamp.isoformat().encode() +
            recipient_key_id.encode()
        )
        if associated_data:
            aad += associated_data

        encrypted_content = cipher.encrypt(nonce, plaintext, aad)

        return EncryptedMessage(
            message_id=message_id,
            sender_key_id=sender_key_id,
            recipient_key_id=recipient_key_id,
            algorithm=self.symmetric_algorithm.value,
            security_level=self.security_level.value,
            is_hybrid=self.use_hybrid and classical_ct is not None,
            pqc_ciphertext=pqc_ct,
            classical_ciphertext=classical_ct,
            encrypted_content=encrypted_content,
            nonce=nonce,
            timestamp=timestamp,
            content_hash=content_hash,
        )

    def encrypt_with_key_manager(
        self,
        plaintext: bytes,
        recipient_key_id: str,
        sender_key_id: Optional[str] = None,
        associated_data: Optional[bytes] = None
    ) -> Optional[EncryptedMessage]:
        """
        Encrypt a message using keys from the key manager.

        Args:
            plaintext: Message content to encrypt
            recipient_key_id: Recipient's key ID in the key manager
            sender_key_id: Optional sender key ID
            associated_data: Additional authenticated data

        Returns:
            EncryptedMessage or None if key not found
        """
        if not self.key_manager:
            return None

        metadata = self.key_manager.get_metadata(recipient_key_id)
        if not metadata:
            return None

        # Get appropriate keys based on key type
        if metadata.key_type == KeyType.HYBRID_KEM:
            result = self.key_manager.get_hybrid_keypair(recipient_key_id)
            if not result:
                return None
            pqc_pk, _, classical_pk, _ = result
            return self.encrypt(
                plaintext=plaintext,
                recipient_public_key=pqc_pk,
                recipient_key_id=recipient_key_id,
                sender_key_id=sender_key_id,
                classical_public_key=classical_pk,
                associated_data=associated_data,
            )
        else:
            public_key = self.key_manager.get_public_key(recipient_key_id)
            if not public_key:
                return None
            return self.encrypt(
                plaintext=plaintext,
                recipient_public_key=public_key,
                recipient_key_id=recipient_key_id,
                sender_key_id=sender_key_id,
                associated_data=associated_data,
            )

    # ==================== DECRYPTION ====================

    def decrypt(
        self,
        encrypted_message: EncryptedMessage,
        recipient_secret_key: bytes,
        classical_secret_key: Optional[bytes] = None,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bool]:
        """
        Decrypt an encrypted message.

        Args:
            encrypted_message: The encrypted message
            recipient_secret_key: Recipient's PQC secret key
            classical_secret_key: Classical secret key for hybrid mode
            associated_data: Additional authenticated data

        Returns:
            Tuple of (plaintext, integrity_verified)
        """
        try:
            security_level = SecurityLevel(encrypted_message.security_level)

            # Decapsulate shared secret
            if encrypted_message.is_hybrid and encrypted_message.classical_ciphertext and classical_secret_key:
                shared_secret = self.pqc.hybrid_decapsulate(
                    recipient_secret_key,
                    classical_secret_key,
                    encrypted_message.pqc_ciphertext,
                    encrypted_message.classical_ciphertext,
                    security_level
                )
            else:
                shared_secret = self.pqc.decapsulate(
                    recipient_secret_key,
                    encrypted_message.pqc_ciphertext,
                    security_level
                )

            # Derive content decryption key
            content_key = self._derive_content_key(
                shared_secret,
                encrypted_message.message_id
            )

            # Build AAD
            aad = (
                encrypted_message.message_id.encode() +
                encrypted_message.timestamp.isoformat().encode() +
                encrypted_message.recipient_key_id.encode()
            )
            if associated_data:
                aad += associated_data

            # Decrypt content
            cipher = self._get_cipher(content_key)
            plaintext = cipher.decrypt(
                encrypted_message.nonce,
                encrypted_message.encrypted_content,
                aad
            )

            # Verify content hash
            computed_hash = hashlib.sha256(plaintext).digest()
            integrity_verified = computed_hash == encrypted_message.content_hash

            return plaintext, integrity_verified

        except Exception:
            return b"", False

    def decrypt_with_key_manager(
        self,
        encrypted_message: EncryptedMessage,
        associated_data: Optional[bytes] = None
    ) -> Tuple[bytes, bool]:
        """
        Decrypt a message using keys from the key manager.

        Args:
            encrypted_message: The encrypted message
            associated_data: Additional authenticated data

        Returns:
            Tuple of (plaintext, integrity_verified)
        """
        if not self.key_manager:
            return b"", False

        recipient_key_id = encrypted_message.recipient_key_id
        metadata = self.key_manager.get_metadata(recipient_key_id)
        if not metadata:
            return b"", False

        # Get appropriate keys
        if encrypted_message.is_hybrid or metadata.key_type == KeyType.HYBRID_KEM:
            result = self.key_manager.get_hybrid_keypair(recipient_key_id)
            if not result:
                return b"", False
            _, pqc_sk, _, classical_sk = result
            return self.decrypt(
                encrypted_message=encrypted_message,
                recipient_secret_key=pqc_sk,
                classical_secret_key=classical_sk,
                associated_data=associated_data,
            )
        else:
            secret_key = self.key_manager.get_secret_key(recipient_key_id)
            if not secret_key:
                return b"", False
            return self.decrypt(
                encrypted_message=encrypted_message,
                recipient_secret_key=secret_key,
                associated_data=associated_data,
            )

    # ==================== SIGNING ====================

    def sign(
        self,
        content: bytes,
        signer_secret_key: bytes,
        signer_key_id: str,
        classical_secret_key: Optional[bytes] = None,
        expiration_seconds: Optional[int] = None
    ) -> SignedMessage:
        """
        Sign a message for authentication and non-repudiation.

        Args:
            content: Content to sign
            signer_secret_key: Signer's PQC secret key
            signer_key_id: Identifier for signer's key
            classical_secret_key: Classical secret key for hybrid mode
            expiration_seconds: Optional signature expiration time

        Returns:
            SignedMessage with signature data
        """
        message_id = self._generate_message_id()
        timestamp = datetime.now(timezone.utc)
        expiration = None
        if expiration_seconds:
            expiration = timestamp + timezone.utc.timedelta(seconds=expiration_seconds)

        # Compute content hash
        content_hash = hashlib.sha256(content).digest()

        # Build signing data: content_hash | timestamp | message_id
        signing_data = (
            content_hash +
            timestamp.isoformat().encode() +
            message_id.encode()
        )
        if expiration:
            signing_data += expiration.isoformat().encode()

        # Sign with PQC and optionally classical
        if self.use_hybrid and classical_secret_key:
            pqc_sig, classical_sig = self.pqc.hybrid_sign(
                signer_secret_key,
                classical_secret_key,
                signing_data,
                self.security_level
            )
        else:
            result = self.pqc.sign(signer_secret_key, signing_data, self.security_level)
            pqc_sig = result.signature
            classical_sig = None

        return SignedMessage(
            message_id=message_id,
            signer_key_id=signer_key_id,
            algorithm=self.pqc.SIGN_NAMES[self.security_level],
            security_level=self.security_level.value,
            is_hybrid=self.use_hybrid and classical_sig is not None,
            content=content,
            content_hash=content_hash,
            pqc_signature=pqc_sig,
            classical_signature=classical_sig,
            timestamp=timestamp,
            expiration=expiration,
        )

    def sign_with_key_manager(
        self,
        content: bytes,
        signer_key_id: str,
        expiration_seconds: Optional[int] = None
    ) -> Optional[SignedMessage]:
        """
        Sign a message using keys from the key manager.

        Args:
            content: Content to sign
            signer_key_id: Signer's key ID in the key manager
            expiration_seconds: Optional signature expiration

        Returns:
            SignedMessage or None if key not found
        """
        if not self.key_manager:
            return None

        metadata = self.key_manager.get_metadata(signer_key_id)
        if not metadata:
            return None

        # Get appropriate keys
        if metadata.key_type == KeyType.HYBRID_SIGN:
            result = self.key_manager.get_hybrid_keypair(signer_key_id)
            if not result:
                return None
            _, pqc_sk, _, classical_sk = result
            return self.sign(
                content=content,
                signer_secret_key=pqc_sk,
                signer_key_id=signer_key_id,
                classical_secret_key=classical_sk,
                expiration_seconds=expiration_seconds,
            )
        else:
            secret_key = self.key_manager.get_secret_key(signer_key_id)
            if not secret_key:
                return None
            return self.sign(
                content=content,
                signer_secret_key=secret_key,
                signer_key_id=signer_key_id,
                expiration_seconds=expiration_seconds,
            )

    # ==================== VERIFICATION ====================

    def verify(
        self,
        signed_message: SignedMessage,
        signer_public_key: bytes,
        classical_public_key: Optional[bytes] = None,
        require_both: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a signed message.

        Args:
            signed_message: The signed message to verify
            signer_public_key: Signer's PQC public key
            classical_public_key: Classical public key for hybrid mode
            require_both: Whether both signatures must verify in hybrid mode

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Check expiration
            if signed_message.expiration:
                if datetime.now(timezone.utc) > signed_message.expiration:
                    return False, "Signature has expired"

            # Verify content hash
            computed_hash = hashlib.sha256(signed_message.content).digest()
            if computed_hash != signed_message.content_hash:
                return False, "Content hash mismatch"

            # Rebuild signing data
            security_level = SecurityLevel(signed_message.security_level)
            signing_data = (
                signed_message.content_hash +
                signed_message.timestamp.isoformat().encode() +
                signed_message.message_id.encode()
            )
            if signed_message.expiration:
                signing_data += signed_message.expiration.isoformat().encode()

            # Verify signatures
            if signed_message.is_hybrid and signed_message.classical_signature and classical_public_key:
                is_valid = self.pqc.hybrid_verify(
                    signer_public_key,
                    classical_public_key,
                    signing_data,
                    signed_message.pqc_signature,
                    signed_message.classical_signature,
                    security_level,
                    require_both=require_both
                )
            else:
                is_valid = self.pqc.verify(
                    signer_public_key,
                    signing_data,
                    signed_message.pqc_signature,
                    security_level
                )

            if is_valid:
                return True, None
            else:
                return False, "Signature verification failed"

        except Exception as e:
            return False, str(e)

    def verify_with_key_manager(
        self,
        signed_message: SignedMessage,
        require_both: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Verify a signed message using keys from the key manager.

        Args:
            signed_message: The signed message to verify
            require_both: Whether both signatures must verify in hybrid mode

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.key_manager:
            return False, "Key manager not configured"

        signer_key_id = signed_message.signer_key_id
        metadata = self.key_manager.get_metadata(signer_key_id)
        if not metadata:
            return False, f"Unknown signer key: {signer_key_id}"

        # Get appropriate keys
        if signed_message.is_hybrid or metadata.key_type == KeyType.HYBRID_SIGN:
            result = self.key_manager.get_hybrid_keypair(signer_key_id)
            if not result:
                return False, "Failed to retrieve hybrid keypair"
            pqc_pk, _, classical_pk, _ = result
            return self.verify(
                signed_message=signed_message,
                signer_public_key=pqc_pk,
                classical_public_key=classical_pk,
                require_both=require_both,
            )
        else:
            public_key = self.key_manager.get_public_key(signer_key_id)
            if not public_key:
                return False, "Failed to retrieve public key"
            return self.verify(
                signed_message=signed_message,
                signer_public_key=public_key,
            )

    # ==================== SECURE ENVELOPE ====================

    def create_secure_envelope(
        self,
        plaintext: bytes,
        recipient_public_key: bytes,
        recipient_key_id: str,
        signer_secret_key: Optional[bytes] = None,
        signer_key_id: Optional[str] = None,
        classical_recipient_key: Optional[bytes] = None,
        classical_signer_key: Optional[bytes] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> SecureEnvelope:
        """
        Create a complete secure envelope with encryption and optional signature.

        Args:
            plaintext: Message content
            recipient_public_key: Recipient's PQC public key
            recipient_key_id: Recipient's key identifier
            signer_secret_key: Optional signer's secret key for authentication
            signer_key_id: Optional signer's key identifier
            classical_recipient_key: Classical key for hybrid encryption
            classical_signer_key: Classical key for hybrid signing
            metadata: Additional envelope metadata

        Returns:
            Complete SecureEnvelope
        """
        # Encrypt the message
        encrypted_message = self.encrypt(
            plaintext=plaintext,
            recipient_public_key=recipient_public_key,
            recipient_key_id=recipient_key_id,
            sender_key_id=signer_key_id,
            classical_public_key=classical_recipient_key,
        )

        # Optionally sign the encrypted message
        signature = None
        if signer_secret_key and signer_key_id:
            # Sign the encrypted content (sign-then-encrypt pattern alternative)
            signature = self.sign(
                content=encrypted_message.to_bytes(),
                signer_secret_key=signer_secret_key,
                signer_key_id=signer_key_id,
                classical_secret_key=classical_signer_key,
            )

        return SecureEnvelope(
            envelope_id=secrets.token_hex(16),
            encrypted_message=encrypted_message,
            signature=signature,
            metadata=metadata or {},
        )

    def open_secure_envelope(
        self,
        envelope: SecureEnvelope,
        recipient_secret_key: bytes,
        signer_public_key: Optional[bytes] = None,
        classical_recipient_key: Optional[bytes] = None,
        classical_signer_key: Optional[bytes] = None
    ) -> Tuple[bytes, bool, bool]:
        """
        Open a secure envelope and verify its contents.

        Args:
            envelope: The secure envelope to open
            recipient_secret_key: Recipient's PQC secret key
            signer_public_key: Signer's public key for verification
            classical_recipient_key: Classical secret key for hybrid decryption
            classical_signer_key: Classical public key for hybrid verification

        Returns:
            Tuple of (plaintext, decryption_success, signature_valid)
        """
        signature_valid = True

        # Verify signature if present
        if envelope.signature and signer_public_key:
            signature_valid, _ = self.verify(
                signed_message=envelope.signature,
                signer_public_key=signer_public_key,
                classical_public_key=classical_signer_key,
            )

        # Decrypt message
        plaintext, integrity_verified = self.decrypt(
            encrypted_message=envelope.encrypted_message,
            recipient_secret_key=recipient_secret_key,
            classical_secret_key=classical_recipient_key,
        )

        return plaintext, integrity_verified, signature_valid
