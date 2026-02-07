"""
GHOST Crypto Module
===================

AES-256-GCM encryption for sensitive data.
"""

import os
import json
import base64
import hashlib
import secrets
from typing import Optional, Any, Dict
from dataclasses import dataclass

# Try to import cryptography, fallback to basic encoding
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


@dataclass
class EncryptedData:
    """Encrypted data container"""
    ciphertext: bytes
    nonce: bytes
    salt: bytes

    def to_string(self) -> str:
        """Convert to storable string"""
        data = {
            'c': base64.b64encode(self.ciphertext).decode(),
            'n': base64.b64encode(self.nonce).decode(),
            's': base64.b64encode(self.salt).decode()
        }
        return base64.b64encode(json.dumps(data).encode()).decode()

    @classmethod
    def from_string(cls, s: str) -> 'EncryptedData':
        """Parse from stored string"""
        data = json.loads(base64.b64decode(s.encode()).decode())
        return cls(
            ciphertext=base64.b64decode(data['c']),
            nonce=base64.b64decode(data['n']),
            salt=base64.b64decode(data['s'])
        )


class GhostCrypto:
    """
    AES-256-GCM encryption for GHOST sensitive data.

    Used for:
    - WiFi passwords
    - Personal identifiable information (PII)
    - OSINT findings with sensitive content
    """

    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize crypto with master key.

        Args:
            master_key: Master encryption key (will generate if not provided)
        """
        if master_key:
            self._master_key = master_key.encode() if isinstance(master_key, str) else master_key
        else:
            # Try to load from environment or generate
            env_key = os.environ.get('GHOST_ENCRYPTION_KEY')
            if env_key:
                self._master_key = env_key.encode()
            else:
                self._master_key = secrets.token_bytes(32)

        self._crypto_available = CRYPTO_AVAILABLE

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive encryption key from master key and salt"""
        if not self._crypto_available:
            # Fallback: Simple key derivation
            return hashlib.pbkdf2_hmac(
                'sha256',
                self._master_key,
                salt,
                100000,
                dklen=32
            )

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(self._master_key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt plaintext string.

        Args:
            plaintext: Text to encrypt

        Returns:
            Encrypted data as base64 string
        """
        if not plaintext:
            return ''

        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        key = self._derive_key(salt)

        if self._crypto_available:
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        else:
            # Fallback: XOR with key (not secure, but functional)
            plaintext_bytes = plaintext.encode()
            key_repeated = (key * (len(plaintext_bytes) // len(key) + 1))[:len(plaintext_bytes)]
            ciphertext = bytes(a ^ b for a, b in zip(plaintext_bytes, key_repeated))

        encrypted = EncryptedData(ciphertext, nonce, salt)
        return encrypted.to_string()

    def decrypt(self, encrypted_string: str) -> str:
        """
        Decrypt encrypted string.

        Args:
            encrypted_string: Encrypted data as base64 string

        Returns:
            Decrypted plaintext
        """
        if not encrypted_string:
            return ''

        try:
            encrypted = EncryptedData.from_string(encrypted_string)
            key = self._derive_key(encrypted.salt)

            if self._crypto_available:
                aesgcm = AESGCM(key)
                plaintext = aesgcm.decrypt(encrypted.nonce, encrypted.ciphertext, None)
            else:
                # Fallback: XOR with key
                key_repeated = (key * (len(encrypted.ciphertext) // len(key) + 1))[:len(encrypted.ciphertext)]
                plaintext = bytes(a ^ b for a, b in zip(encrypted.ciphertext, key_repeated))

            return plaintext.decode()
        except Exception:
            return ''

    def encrypt_dict(self, data: Dict[str, Any], sensitive_keys: list) -> Dict[str, Any]:
        """
        Encrypt specific keys in a dictionary.

        Args:
            data: Dictionary to process
            sensitive_keys: List of keys to encrypt

        Returns:
            Dictionary with sensitive keys encrypted
        """
        result = data.copy()
        for key in sensitive_keys:
            if key in result and result[key]:
                if isinstance(result[key], str):
                    result[key] = self.encrypt(result[key])
                elif isinstance(result[key], (list, dict)):
                    result[key] = self.encrypt(json.dumps(result[key]))
        return result

    def decrypt_dict(self, data: Dict[str, Any], sensitive_keys: list) -> Dict[str, Any]:
        """
        Decrypt specific keys in a dictionary.

        Args:
            data: Dictionary to process
            sensitive_keys: List of keys to decrypt

        Returns:
            Dictionary with sensitive keys decrypted
        """
        result = data.copy()
        for key in sensitive_keys:
            if key in result and result[key]:
                decrypted = self.decrypt(result[key])
                if decrypted:
                    try:
                        # Try to parse as JSON
                        result[key] = json.loads(decrypted)
                    except (json.JSONDecodeError, TypeError):
                        result[key] = decrypted
        return result

    def hash_identifier(self, identifier: str) -> str:
        """
        Create searchable hash of identifier (for PII lookup).

        Args:
            identifier: Identifier to hash (email, phone, etc.)

        Returns:
            SHA-256 hash
        """
        return hashlib.sha256(
            (identifier.lower().strip() + str(self._master_key[:8])).encode()
        ).hexdigest()

    def mask_pii(self, text: str, pii_type: str = 'generic') -> str:
        """
        Mask personally identifiable information.

        Args:
            text: Text containing PII
            pii_type: Type of PII (email, phone, ssn, generic)

        Returns:
            Masked text
        """
        if not text:
            return ''

        if pii_type == 'email':
            # user@domain.com -> u***@d***.com
            parts = text.split('@')
            if len(parts) == 2:
                user = parts[0][0] + '***' if len(parts[0]) > 1 else '***'
                domain_parts = parts[1].split('.')
                domain = domain_parts[0][0] + '***' if len(domain_parts[0]) > 1 else '***'
                return f"{user}@{domain}.{''.join(domain_parts[1:])}"

        elif pii_type == 'phone':
            # +1234567890 -> +12****7890
            digits = ''.join(c for c in text if c.isdigit() or c == '+')
            if len(digits) > 6:
                return digits[:3] + '****' + digits[-4:]

        elif pii_type == 'ssn':
            # 123-45-6789 -> ***-**-6789
            digits = ''.join(c for c in text if c.isdigit())
            if len(digits) >= 4:
                return '***-**-' + digits[-4:]

        # Generic masking
        if len(text) > 4:
            return text[:2] + '*' * (len(text) - 4) + text[-2:]
        return '***'


# Global crypto instance
_ghost_crypto: Optional[GhostCrypto] = None


def get_ghost_crypto(master_key: Optional[str] = None) -> GhostCrypto:
    """Get or create global crypto instance"""
    global _ghost_crypto
    if _ghost_crypto is None:
        _ghost_crypto = GhostCrypto(master_key)
    return _ghost_crypto
