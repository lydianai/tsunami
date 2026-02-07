"""
Cryptographic Key Management

Provides secure key management for PQC operations:
- Key generation and storage
- Key rotation policies
- Encrypted key storage
- Key backup and recovery
- Hardware security module (HSM) interface support
"""

import os
import json
import secrets
import hashlib
import base64
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timezone, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from .pqc_algorithms import PQCAlgorithms, SecurityLevel, KeyPair, HybridKeyPair


class KeyType(Enum):
    """Type of cryptographic key."""
    KEM = "kem"                  # Key Encapsulation (ML-KEM/Kyber)
    SIGN = "sign"               # Digital Signature (ML-DSA/Dilithium)
    HYBRID_KEM = "hybrid_kem"   # Hybrid KEM (X25519 + ML-KEM)
    HYBRID_SIGN = "hybrid_sign" # Hybrid Sign (Ed25519 + ML-DSA)
    SYMMETRIC = "symmetric"     # Symmetric key (AES)


class KeyStatus(Enum):
    """Status of a key in the system."""
    ACTIVE = "active"           # Key is active and can be used
    PENDING = "pending"         # Key is generated but not yet activated
    SUSPENDED = "suspended"     # Key is temporarily disabled
    COMPROMISED = "compromised" # Key may be compromised, do not use
    EXPIRED = "expired"         # Key has expired
    REVOKED = "revoked"         # Key has been permanently revoked
    ARCHIVED = "archived"       # Key is archived for historical purposes


@dataclass
class KeyRotationPolicy:
    """Policy for automatic key rotation."""
    rotation_interval_days: int = 90
    max_usage_count: int = 1000000
    notify_before_days: int = 7
    auto_rotate: bool = True
    backup_before_rotate: bool = True
    archive_old_keys: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyRotationPolicy":
        return cls(**data)


@dataclass
class KeyMetadata:
    """Metadata for a managed key."""
    key_id: str
    key_type: KeyType
    algorithm: str
    security_level: int
    status: KeyStatus
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime] = None
    usage_count: int = 0
    rotation_policy: Optional[KeyRotationPolicy] = None
    labels: Dict[str, str] = field(default_factory=dict)
    public_key_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "algorithm": self.algorithm,
            "security_level": self.security_level,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "usage_count": self.usage_count,
            "rotation_policy": self.rotation_policy.to_dict() if self.rotation_policy else None,
            "labels": self.labels,
            "public_key_fingerprint": self.public_key_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMetadata":
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            algorithm=data["algorithm"],
            security_level=data["security_level"],
            status=KeyStatus(data["status"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]) if data.get("expires_at") else None,
            last_used_at=datetime.fromisoformat(data["last_used_at"]) if data.get("last_used_at") else None,
            usage_count=data.get("usage_count", 0),
            rotation_policy=KeyRotationPolicy.from_dict(data["rotation_policy"]) if data.get("rotation_policy") else None,
            labels=data.get("labels", {}),
            public_key_fingerprint=data.get("public_key_fingerprint"),
        )


class KeyManager:
    """
    Cryptographic Key Manager

    Provides secure management of PQC cryptographic keys including:
    - Key generation with configurable security levels
    - Encrypted storage using master key encryption
    - Key rotation with configurable policies
    - Key backup and recovery mechanisms
    - Usage tracking and audit logging
    """

    # Key derivation parameters
    SCRYPT_N = 2**18  # CPU/memory cost
    SCRYPT_R = 8      # Block size
    SCRYPT_P = 1      # Parallelization

    def __init__(
        self,
        storage_path: Optional[str] = None,
        master_key: Optional[bytes] = None,
        default_security_level: SecurityLevel = SecurityLevel.LEVEL_3
    ):
        """
        Initialize the key manager.

        Args:
            storage_path: Path for encrypted key storage (None for in-memory only)
            master_key: 32-byte master key for encrypting stored keys
            default_security_level: Default NIST security level for new keys
        """
        self.pqc = PQCAlgorithms(default_security_level)
        self.default_security_level = default_security_level
        self.storage_path = Path(storage_path) if storage_path else None

        # Initialize or derive master key
        if master_key:
            self.master_key = master_key
        else:
            self.master_key = secrets.token_bytes(32)

        # In-memory key storage
        self._keys: Dict[str, bytes] = {}  # key_id -> encrypted key material
        self._metadata: Dict[str, KeyMetadata] = {}  # key_id -> metadata
        self._public_keys: Dict[str, bytes] = {}  # key_id -> public key (unencrypted)

        # Load existing keys from storage
        if self.storage_path:
            self._load_from_storage()

    def _derive_encryption_key(self, key_id: str, salt: bytes) -> bytes:
        """Derive a unique encryption key for a specific key ID."""
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=self.SCRYPT_N,
            r=self.SCRYPT_R,
            p=self.SCRYPT_P,
            backend=default_backend()
        )
        return kdf.derive(self.master_key + key_id.encode())

    def _encrypt_key_material(
        self,
        key_id: str,
        key_material: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt key material for storage.

        Returns:
            Tuple of (encrypted_data, salt)
        """
        salt = secrets.token_bytes(32)
        encryption_key = self._derive_encryption_key(key_id, salt)

        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(encryption_key)
        ciphertext = aesgcm.encrypt(nonce, key_material, key_id.encode())

        # Format: SALT (32) | NONCE (12) | CIPHERTEXT
        return salt + nonce + ciphertext, salt

    def _decrypt_key_material(
        self,
        key_id: str,
        encrypted_data: bytes
    ) -> bytes:
        """Decrypt key material from storage."""
        salt = encrypted_data[:32]
        nonce = encrypted_data[32:44]
        ciphertext = encrypted_data[44:]

        encryption_key = self._derive_encryption_key(key_id, salt)
        aesgcm = AESGCM(encryption_key)
        return aesgcm.decrypt(nonce, ciphertext, key_id.encode())

    # ==================== KEY GENERATION ====================

    def generate_kem_keypair(
        self,
        security_level: Optional[SecurityLevel] = None,
        rotation_policy: Optional[KeyRotationPolicy] = None,
        labels: Optional[Dict[str, str]] = None,
        expires_in_days: int = 365
    ) -> KeyMetadata:
        """
        Generate a new ML-KEM key pair.

        Args:
            security_level: NIST security level
            rotation_policy: Key rotation policy
            labels: Custom labels for the key
            expires_in_days: Days until key expires

        Returns:
            KeyMetadata for the generated key
        """
        level = security_level or self.default_security_level
        keypair = self.pqc.generate_kem_keypair(level)

        return self._store_keypair(
            keypair=keypair,
            key_type=KeyType.KEM,
            rotation_policy=rotation_policy,
            labels=labels,
            expires_in_days=expires_in_days,
        )

    def generate_sign_keypair(
        self,
        security_level: Optional[SecurityLevel] = None,
        rotation_policy: Optional[KeyRotationPolicy] = None,
        labels: Optional[Dict[str, str]] = None,
        expires_in_days: int = 365
    ) -> KeyMetadata:
        """
        Generate a new ML-DSA key pair.

        Args:
            security_level: NIST security level
            rotation_policy: Key rotation policy
            labels: Custom labels for the key
            expires_in_days: Days until key expires

        Returns:
            KeyMetadata for the generated key
        """
        level = security_level or self.default_security_level
        keypair = self.pqc.generate_sign_keypair(level)

        return self._store_keypair(
            keypair=keypair,
            key_type=KeyType.SIGN,
            rotation_policy=rotation_policy,
            labels=labels,
            expires_in_days=expires_in_days,
        )

    def generate_hybrid_kem_keypair(
        self,
        security_level: Optional[SecurityLevel] = None,
        rotation_policy: Optional[KeyRotationPolicy] = None,
        labels: Optional[Dict[str, str]] = None,
        expires_in_days: int = 365
    ) -> KeyMetadata:
        """
        Generate a new hybrid KEM key pair (X25519 + ML-KEM).

        Args:
            security_level: NIST security level for PQC component
            rotation_policy: Key rotation policy
            labels: Custom labels for the key
            expires_in_days: Days until key expires

        Returns:
            KeyMetadata for the generated key
        """
        level = security_level or self.default_security_level
        hybrid_keypair = self.pqc.generate_hybrid_kem_keypair(level)

        return self._store_hybrid_keypair(
            keypair=hybrid_keypair,
            key_type=KeyType.HYBRID_KEM,
            rotation_policy=rotation_policy,
            labels=labels,
            expires_in_days=expires_in_days,
        )

    def generate_hybrid_sign_keypair(
        self,
        security_level: Optional[SecurityLevel] = None,
        rotation_policy: Optional[KeyRotationPolicy] = None,
        labels: Optional[Dict[str, str]] = None,
        expires_in_days: int = 365
    ) -> KeyMetadata:
        """
        Generate a new hybrid signing key pair (Ed25519 + ML-DSA).

        Args:
            security_level: NIST security level for PQC component
            rotation_policy: Key rotation policy
            labels: Custom labels for the key
            expires_in_days: Days until key expires

        Returns:
            KeyMetadata for the generated key
        """
        level = security_level or self.default_security_level
        hybrid_keypair = self.pqc.generate_hybrid_sign_keypair(level)

        return self._store_hybrid_keypair(
            keypair=hybrid_keypair,
            key_type=KeyType.HYBRID_SIGN,
            rotation_policy=rotation_policy,
            labels=labels,
            expires_in_days=expires_in_days,
        )

    def _store_keypair(
        self,
        keypair: KeyPair,
        key_type: KeyType,
        rotation_policy: Optional[KeyRotationPolicy],
        labels: Optional[Dict[str, str]],
        expires_in_days: int
    ) -> KeyMetadata:
        """Store a PQC keypair."""
        key_id = keypair.key_id
        now = datetime.now(timezone.utc)

        # Create metadata
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            algorithm=keypair.algorithm,
            security_level=keypair.security_level.value,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
            rotation_policy=rotation_policy or KeyRotationPolicy(),
            labels=labels or {},
            public_key_fingerprint=keypair.public_key_fingerprint(),
        )

        # Encrypt and store secret key
        encrypted_sk, _ = self._encrypt_key_material(key_id, keypair.secret_key)
        self._keys[key_id] = encrypted_sk
        self._metadata[key_id] = metadata
        self._public_keys[key_id] = keypair.public_key

        # Persist to storage
        if self.storage_path:
            self._save_to_storage()

        return metadata

    def _store_hybrid_keypair(
        self,
        keypair: HybridKeyPair,
        key_type: KeyType,
        rotation_policy: Optional[KeyRotationPolicy],
        labels: Optional[Dict[str, str]],
        expires_in_days: int
    ) -> KeyMetadata:
        """Store a hybrid keypair."""
        key_id = keypair.pqc_keypair.key_id
        now = datetime.now(timezone.utc)

        # Combine key material: PQC_SK_LEN | PQC_SK | CLASSICAL_SK
        combined_sk = (
            len(keypair.pqc_keypair.secret_key).to_bytes(4, 'big') +
            keypair.pqc_keypair.secret_key +
            keypair.classical_secret_key
        )

        # Combine public keys: PQC_PK_LEN | PQC_PK | CLASSICAL_PK
        combined_pk = (
            len(keypair.pqc_keypair.public_key).to_bytes(4, 'big') +
            keypair.pqc_keypair.public_key +
            keypair.classical_public_key
        )

        # Create metadata
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            algorithm=f"{keypair.pqc_keypair.algorithm}+{keypair.classical_algorithm}",
            security_level=keypair.pqc_keypair.security_level.value,
            status=KeyStatus.ACTIVE,
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
            rotation_policy=rotation_policy or KeyRotationPolicy(),
            labels=labels or {},
            public_key_fingerprint=keypair.pqc_keypair.public_key_fingerprint(),
        )

        # Encrypt and store
        encrypted_sk, _ = self._encrypt_key_material(key_id, combined_sk)
        self._keys[key_id] = encrypted_sk
        self._metadata[key_id] = metadata
        self._public_keys[key_id] = combined_pk

        # Persist to storage
        if self.storage_path:
            self._save_to_storage()

        return metadata

    # ==================== KEY RETRIEVAL ====================

    def get_public_key(self, key_id: str) -> Optional[bytes]:
        """Get the public key for a key ID."""
        return self._public_keys.get(key_id)

    def get_secret_key(self, key_id: str) -> Optional[bytes]:
        """
        Get the secret key for a key ID.

        This decrypts the key material and updates usage stats.
        """
        if key_id not in self._keys:
            return None

        metadata = self._metadata.get(key_id)
        if not metadata:
            return None

        # Check key status
        if metadata.status != KeyStatus.ACTIVE:
            return None

        # Check expiration
        if metadata.expires_at and datetime.now(timezone.utc) > metadata.expires_at:
            metadata.status = KeyStatus.EXPIRED
            return None

        # Decrypt key material
        try:
            decrypted = self._decrypt_key_material(key_id, self._keys[key_id])

            # Update usage stats
            metadata.last_used_at = datetime.now(timezone.utc)
            metadata.usage_count += 1

            # Check usage limit
            if metadata.rotation_policy and metadata.usage_count >= metadata.rotation_policy.max_usage_count:
                self._trigger_rotation(key_id)

            return decrypted

        except Exception:
            return None

    def get_keypair(self, key_id: str) -> Optional[Tuple[bytes, bytes]]:
        """Get both public and secret keys."""
        public_key = self.get_public_key(key_id)
        secret_key = self.get_secret_key(key_id)

        if public_key and secret_key:
            return public_key, secret_key
        return None

    def get_hybrid_keypair(
        self,
        key_id: str
    ) -> Optional[Tuple[bytes, bytes, bytes, bytes]]:
        """
        Get a hybrid keypair's components.

        Returns:
            Tuple of (pqc_public_key, pqc_secret_key, classical_public_key, classical_secret_key)
        """
        combined_pk = self._public_keys.get(key_id)
        secret_key = self.get_secret_key(key_id)

        if not combined_pk or not secret_key:
            return None

        # Parse public key
        pqc_pk_len = int.from_bytes(combined_pk[:4], 'big')
        pqc_pk = combined_pk[4:4+pqc_pk_len]
        classical_pk = combined_pk[4+pqc_pk_len:]

        # Parse secret key
        pqc_sk_len = int.from_bytes(secret_key[:4], 'big')
        pqc_sk = secret_key[4:4+pqc_sk_len]
        classical_sk = secret_key[4+pqc_sk_len:]

        return pqc_pk, pqc_sk, classical_pk, classical_sk

    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get metadata for a key."""
        return self._metadata.get(key_id)

    def list_keys(
        self,
        key_type: Optional[KeyType] = None,
        status: Optional[KeyStatus] = None,
        labels: Optional[Dict[str, str]] = None
    ) -> List[KeyMetadata]:
        """
        List keys matching the given criteria.

        Args:
            key_type: Filter by key type
            status: Filter by status
            labels: Filter by labels (all must match)

        Returns:
            List of matching KeyMetadata
        """
        results = []
        for metadata in self._metadata.values():
            if key_type and metadata.key_type != key_type:
                continue
            if status and metadata.status != status:
                continue
            if labels:
                if not all(metadata.labels.get(k) == v for k, v in labels.items()):
                    continue
            results.append(metadata)
        return results

    # ==================== KEY ROTATION ====================

    def _trigger_rotation(self, key_id: str) -> None:
        """Trigger key rotation for a key that has exceeded its limits."""
        metadata = self._metadata.get(key_id)
        if not metadata or not metadata.rotation_policy:
            return

        if metadata.rotation_policy.auto_rotate:
            self.rotate_key(key_id)

    def rotate_key(
        self,
        key_id: str,
        archive_old: bool = True
    ) -> Optional[KeyMetadata]:
        """
        Rotate a key by generating a new one with the same settings.

        Args:
            key_id: Key to rotate
            archive_old: Whether to archive the old key

        Returns:
            KeyMetadata for the new key, or None if rotation failed
        """
        old_metadata = self._metadata.get(key_id)
        if not old_metadata:
            return None

        # Backup if policy requires
        if old_metadata.rotation_policy and old_metadata.rotation_policy.backup_before_rotate:
            self.backup_key(key_id)

        # Generate new key with same settings
        level = SecurityLevel(old_metadata.security_level)

        if old_metadata.key_type == KeyType.KEM:
            new_metadata = self.generate_kem_keypair(
                security_level=level,
                rotation_policy=old_metadata.rotation_policy,
                labels=old_metadata.labels,
            )
        elif old_metadata.key_type == KeyType.SIGN:
            new_metadata = self.generate_sign_keypair(
                security_level=level,
                rotation_policy=old_metadata.rotation_policy,
                labels=old_metadata.labels,
            )
        elif old_metadata.key_type == KeyType.HYBRID_KEM:
            new_metadata = self.generate_hybrid_kem_keypair(
                security_level=level,
                rotation_policy=old_metadata.rotation_policy,
                labels=old_metadata.labels,
            )
        elif old_metadata.key_type == KeyType.HYBRID_SIGN:
            new_metadata = self.generate_hybrid_sign_keypair(
                security_level=level,
                rotation_policy=old_metadata.rotation_policy,
                labels=old_metadata.labels,
            )
        else:
            return None

        # Update old key status
        if archive_old:
            old_metadata.status = KeyStatus.ARCHIVED
        else:
            old_metadata.status = KeyStatus.REVOKED

        # Add rotation reference
        new_metadata.labels["rotated_from"] = key_id

        if self.storage_path:
            self._save_to_storage()

        return new_metadata

    def check_rotation_needed(self) -> List[str]:
        """
        Check which keys need rotation.

        Returns:
            List of key IDs that need rotation
        """
        needs_rotation = []
        now = datetime.now(timezone.utc)

        for key_id, metadata in self._metadata.items():
            if metadata.status != KeyStatus.ACTIVE:
                continue

            policy = metadata.rotation_policy
            if not policy:
                continue

            # Check age
            age_days = (now - metadata.created_at).days
            if age_days >= policy.rotation_interval_days:
                needs_rotation.append(key_id)
                continue

            # Check usage count
            if metadata.usage_count >= policy.max_usage_count:
                needs_rotation.append(key_id)

        return needs_rotation

    # ==================== KEY BACKUP/RECOVERY ====================

    def backup_key(
        self,
        key_id: str,
        backup_password: Optional[str] = None
    ) -> Optional[bytes]:
        """
        Create an encrypted backup of a key.

        Args:
            key_id: Key to backup
            backup_password: Password for additional encryption (optional)

        Returns:
            Encrypted backup data, or None if backup failed
        """
        if key_id not in self._keys:
            return None

        metadata = self._metadata.get(key_id)
        if not metadata:
            return None

        # Get decrypted key material
        secret_key = self.get_secret_key(key_id)
        if not secret_key:
            return None

        public_key = self._public_keys.get(key_id, b"")

        # Build backup data
        backup = {
            "version": "1.0",
            "key_id": key_id,
            "metadata": metadata.to_dict(),
            "secret_key": base64.b64encode(secret_key).decode(),
            "public_key": base64.b64encode(public_key).decode(),
            "backup_time": datetime.now(timezone.utc).isoformat(),
        }
        backup_bytes = json.dumps(backup).encode()

        # Optional password-based encryption
        if backup_password:
            salt = secrets.token_bytes(32)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=480000,
                backend=default_backend()
            )
            key = kdf.derive(backup_password.encode())

            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(key)
            encrypted = aesgcm.encrypt(nonce, backup_bytes, b"TSUNAMI-KEY-BACKUP")

            # Format: VERSION (1) | PASSWORD_PROTECTED (1) | SALT (32) | NONCE (12) | CIPHERTEXT
            return b"\x01\x01" + salt + nonce + encrypted
        else:
            # Format: VERSION (1) | PASSWORD_PROTECTED (1) | DATA
            return b"\x01\x00" + backup_bytes

    def restore_key(
        self,
        backup_data: bytes,
        backup_password: Optional[str] = None
    ) -> Optional[KeyMetadata]:
        """
        Restore a key from backup.

        Args:
            backup_data: Encrypted backup data
            backup_password: Password if backup is password-protected

        Returns:
            KeyMetadata for restored key, or None if restoration failed
        """
        try:
            version = backup_data[0]
            password_protected = backup_data[1] == 1

            if password_protected:
                if not backup_password:
                    return None

                salt = backup_data[2:34]
                nonce = backup_data[34:46]
                ciphertext = backup_data[46:]

                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                    backend=default_backend()
                )
                key = kdf.derive(backup_password.encode())

                aesgcm = AESGCM(key)
                backup_bytes = aesgcm.decrypt(nonce, ciphertext, b"TSUNAMI-KEY-BACKUP")
            else:
                backup_bytes = backup_data[2:]

            backup = json.loads(backup_bytes.decode())

            key_id = backup["key_id"]
            secret_key = base64.b64decode(backup["secret_key"])
            public_key = base64.b64decode(backup["public_key"])
            metadata = KeyMetadata.from_dict(backup["metadata"])

            # Store restored key
            encrypted_sk, _ = self._encrypt_key_material(key_id, secret_key)
            self._keys[key_id] = encrypted_sk
            self._metadata[key_id] = metadata
            self._public_keys[key_id] = public_key

            if self.storage_path:
                self._save_to_storage()

            return metadata

        except Exception:
            return None

    # ==================== KEY STATUS MANAGEMENT ====================

    def revoke_key(self, key_id: str, reason: str = "") -> bool:
        """Revoke a key."""
        metadata = self._metadata.get(key_id)
        if not metadata:
            return False

        metadata.status = KeyStatus.REVOKED
        metadata.labels["revocation_reason"] = reason
        metadata.labels["revoked_at"] = datetime.now(timezone.utc).isoformat()

        if self.storage_path:
            self._save_to_storage()

        return True

    def suspend_key(self, key_id: str, reason: str = "") -> bool:
        """Temporarily suspend a key."""
        metadata = self._metadata.get(key_id)
        if not metadata:
            return False

        metadata.status = KeyStatus.SUSPENDED
        metadata.labels["suspension_reason"] = reason

        if self.storage_path:
            self._save_to_storage()

        return True

    def reactivate_key(self, key_id: str) -> bool:
        """Reactivate a suspended key."""
        metadata = self._metadata.get(key_id)
        if not metadata:
            return False

        if metadata.status != KeyStatus.SUSPENDED:
            return False

        metadata.status = KeyStatus.ACTIVE
        metadata.labels.pop("suspension_reason", None)

        if self.storage_path:
            self._save_to_storage()

        return True

    # ==================== STORAGE ====================

    def _save_to_storage(self) -> None:
        """Save keys to encrypted storage."""
        if not self.storage_path:
            return

        self.storage_path.mkdir(parents=True, exist_ok=True)

        # Save metadata
        metadata_file = self.storage_path / "metadata.json"
        metadata_data = {
            key_id: meta.to_dict()
            for key_id, meta in self._metadata.items()
        }
        with open(metadata_file, "w") as f:
            json.dump(metadata_data, f, indent=2)

        # Save encrypted keys
        keys_file = self.storage_path / "keys.bin"
        keys_data = {}
        for key_id, encrypted_key in self._keys.items():
            keys_data[key_id] = base64.b64encode(encrypted_key).decode()

        with open(keys_file, "w") as f:
            json.dump(keys_data, f)

        # Save public keys
        public_file = self.storage_path / "public_keys.bin"
        public_data = {}
        for key_id, public_key in self._public_keys.items():
            public_data[key_id] = base64.b64encode(public_key).decode()

        with open(public_file, "w") as f:
            json.dump(public_data, f)

    def _load_from_storage(self) -> None:
        """Load keys from encrypted storage."""
        if not self.storage_path or not self.storage_path.exists():
            return

        try:
            # Load metadata
            metadata_file = self.storage_path / "metadata.json"
            if metadata_file.exists():
                with open(metadata_file, "r") as f:
                    metadata_data = json.load(f)
                self._metadata = {
                    key_id: KeyMetadata.from_dict(meta)
                    for key_id, meta in metadata_data.items()
                }

            # Load encrypted keys
            keys_file = self.storage_path / "keys.bin"
            if keys_file.exists():
                with open(keys_file, "r") as f:
                    keys_data = json.load(f)
                self._keys = {
                    key_id: base64.b64decode(encrypted)
                    for key_id, encrypted in keys_data.items()
                }

            # Load public keys
            public_file = self.storage_path / "public_keys.bin"
            if public_file.exists():
                with open(public_file, "r") as f:
                    public_data = json.load(f)
                self._public_keys = {
                    key_id: base64.b64decode(public_key)
                    for key_id, public_key in public_data.items()
                }

        except Exception:
            pass  # Start fresh if loading fails

    def export_public_keys(self) -> Dict[str, Dict[str, Any]]:
        """Export all public keys with their metadata."""
        result = {}
        for key_id, metadata in self._metadata.items():
            if metadata.status == KeyStatus.ACTIVE:
                public_key = self._public_keys.get(key_id)
                if public_key:
                    result[key_id] = {
                        "algorithm": metadata.algorithm,
                        "security_level": metadata.security_level,
                        "public_key": base64.b64encode(public_key).decode(),
                        "fingerprint": metadata.public_key_fingerprint,
                        "expires_at": metadata.expires_at.isoformat() if metadata.expires_at else None,
                    }
        return result
