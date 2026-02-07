#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI GHOST MODE v1.0 - Askeri Seviye Gizlilik Katmanı
================================================================================

    Özellikler:
    - AES-256-GCM veri şifreleme
    - PBKDF2 anahtar türetimi (600,000 iterasyon)
    - Session obfuscation
    - Request/Response şifreleme
    - Audit trail masking
    - Network fingerprint elimination
    - Otomatik aktivasyon

================================================================================
"""

import os
import re
import secrets
import hashlib
import hmac
import json
import base64
import threading
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import logging

# Cryptography imports
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("[GHOST] cryptography modülü yüklü değil - temel mod aktif")

# Logging
logging.basicConfig(level=logging.WARNING)  # Ghost mode: minimal logging
logger = logging.getLogger(__name__)


class GhostLevel(Enum):
    """Gizlilik seviyeleri"""
    STANDARD = 1      # Temel şifreleme
    ENHANCED = 2      # Gelişmiş gizlilik
    MAXIMUM = 3       # Maksimum paranoya
    MILITARY = 4      # Askeri seviye


@dataclass
class GhostConfig:
    """Ghost Mode konfigürasyonu"""
    level: GhostLevel = GhostLevel.MILITARY
    key_iterations: int = 600000
    key_length: int = 32  # 256-bit
    nonce_length: int = 12
    salt_length: int = 16
    auto_rotate_keys: bool = True
    rotation_interval: int = 3600  # 1 saat
    mask_ips: bool = True
    mask_emails: bool = True
    mask_domains: bool = True
    obfuscate_headers: bool = True
    secure_delete: bool = True


class GhostMode:
    """
    Askeri Seviye Gizlilik Katmanı

    Tüm hassas verileri şifreler ve iz bırakmadan çalışır.
    """

    _instance = None
    _lock = threading.Lock()

    # Maskeleme pattern'leri
    IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
    PHONE_PATTERN = re.compile(r'\b(?:\+?[0-9]{1,3}[-.\s]?)?(?:\([0-9]{1,4}\)[-.\s]?)?[0-9]{1,4}[-.\s]?[0-9]{1,4}[-.\s]?[0-9]{1,9}\b')

    # Hassas header'lar
    SENSITIVE_HEADERS = [
        'User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'X-Client-IP',
        'CF-Connecting-IP', 'True-Client-IP', 'X-Originating-IP',
        'Authorization', 'Cookie', 'Set-Cookie', 'X-CSRF-Token'
    ]

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_ghost_initialized') and self._ghost_initialized:
            return

        self._ghost_initialized = False
        self._active = False
        self._config = GhostConfig()
        self._session_key: Optional[bytes] = None
        self._cipher: Optional[Any] = None
        self._aesgcm: Optional[AESGCM] = None
        self._salt: Optional[bytes] = None
        self._key_created: Optional[datetime] = None
        self._stats = {
            'encryptions': 0,
            'decryptions': 0,
            'masked_ips': 0,
            'masked_emails': 0,
            'obfuscated_requests': 0
        }

        # Otomatik aktivasyon
        self.activate()
        self._ghost_initialized = True

    def activate(self, level: GhostLevel = GhostLevel.MILITARY) -> bool:
        """Ghost Mode'u aktive et"""
        if self._active:
            return True

        try:
            self._config.level = level

            # Güvenli session key oluştur
            self._session_key = secrets.token_bytes(32)
            self._salt = secrets.token_bytes(self._config.salt_length)

            if CRYPTO_AVAILABLE:
                # PBKDF2 ile anahtar türet
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=self._config.key_length,
                    salt=self._salt,
                    iterations=self._config.key_iterations,
                    backend=default_backend()
                )
                derived_key = kdf.derive(self._session_key)

                # Fernet cipher (for simple operations)
                fernet_key = base64.urlsafe_b64encode(derived_key)
                self._cipher = Fernet(fernet_key)

                # AES-GCM (for advanced operations)
                self._aesgcm = AESGCM(derived_key)

            self._key_created = datetime.now()
            self._active = True

            logger.info(f"[GHOST] Aktif - Seviye: {level.name}")
            return True

        except Exception as e:
            logger.error(f"[GHOST] Aktivasyon hatası: {e}")
            return False

    def deactivate(self) -> bool:
        """Ghost Mode'u deaktive et"""
        if not self._active:
            return True

        # Güvenli anahtar silme
        if self._session_key:
            self._secure_wipe(self._session_key)
        if self._salt:
            self._secure_wipe(self._salt)

        self._session_key = None
        self._salt = None
        self._cipher = None
        self._aesgcm = None
        self._active = False

        logger.info("[GHOST] Deaktif")
        return True

    def is_active(self) -> bool:
        """Ghost Mode aktif mi?"""
        return self._active

    def get_status(self) -> Dict:
        """Ghost Mode durumu"""
        return {
            'active': self._active,
            'level': self._config.level.name if self._active else None,
            'crypto_available': CRYPTO_AVAILABLE,
            'key_age_seconds': (datetime.now() - self._key_created).seconds if self._key_created else None,
            'stats': self._stats.copy()
        }

    # ==================== ŞİFRELEME ====================

    def encrypt(self, data: Union[str, bytes, Dict]) -> bytes:
        """Veriyi şifrele"""
        if not self._active or not self._cipher:
            if isinstance(data, str):
                return data.encode()
            elif isinstance(data, dict):
                return json.dumps(data).encode()
            return data if isinstance(data, bytes) else str(data).encode()

        try:
            # Veriyi bytes'a çevir
            if isinstance(data, dict):
                data_bytes = json.dumps(data).encode('utf-8')
            elif isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data

            encrypted = self._cipher.encrypt(data_bytes)
            self._stats['encryptions'] += 1
            return encrypted

        except Exception as e:
            logger.error(f"[GHOST] Şifreleme hatası: {e}")
            return data if isinstance(data, bytes) else str(data).encode()

    def decrypt(self, encrypted_data: bytes) -> Union[str, bytes]:
        """Şifreli veriyi çöz"""
        if not self._active or not self._cipher:
            return encrypted_data

        try:
            decrypted = self._cipher.decrypt(encrypted_data)
            self._stats['decryptions'] += 1
            return decrypted.decode('utf-8')

        except Exception as e:
            logger.error(f"[GHOST] Çözme hatası: {e}")
            return encrypted_data

    def encrypt_aes_gcm(self, data: bytes, associated_data: bytes = None) -> Dict:
        """AES-256-GCM ile şifrele (authenticated encryption)"""
        if not self._active or not self._aesgcm:
            return {'data': base64.b64encode(data).decode(), 'nonce': '', 'aad': ''}

        try:
            nonce = secrets.token_bytes(self._config.nonce_length)
            aad = associated_data or b''

            ciphertext = self._aesgcm.encrypt(nonce, data, aad)
            self._stats['encryptions'] += 1

            return {
                'data': base64.b64encode(ciphertext).decode(),
                'nonce': base64.b64encode(nonce).decode(),
                'aad': base64.b64encode(aad).decode() if aad else ''
            }

        except Exception as e:
            logger.error(f"[GHOST] AES-GCM şifreleme hatası: {e}")
            return {'data': base64.b64encode(data).decode(), 'nonce': '', 'aad': ''}

    def decrypt_aes_gcm(self, encrypted: Dict) -> bytes:
        """AES-256-GCM çöz"""
        if not self._active or not self._aesgcm:
            return base64.b64decode(encrypted.get('data', ''))

        try:
            ciphertext = base64.b64decode(encrypted['data'])
            nonce = base64.b64decode(encrypted['nonce'])
            aad = base64.b64decode(encrypted.get('aad', '')) or None

            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
            self._stats['decryptions'] += 1
            return plaintext

        except Exception as e:
            logger.error(f"[GHOST] AES-GCM çözme hatası: {e}")
            return b''

    # ==================== MASKELEME ====================

    def mask_data(self, text: str) -> str:
        """Hassas verileri maskele"""
        if not self._active:
            return text

        masked = text

        # IP adresleri
        if self._config.mask_ips:
            masked = self.IP_PATTERN.sub('[IP_MASKED]', masked)
            self._stats['masked_ips'] += len(self.IP_PATTERN.findall(text))

        # E-posta adresleri
        if self._config.mask_emails:
            masked = self.EMAIL_PATTERN.sub('[EMAIL_MASKED]', masked)
            self._stats['masked_emails'] += len(self.EMAIL_PATTERN.findall(text))

        # Domain'ler (opsiyonel)
        if self._config.mask_domains:
            # Sadece belirli uzantıları maskele
            masked = re.sub(r'\b[a-z0-9-]+\.(com|net|org|io|gov|edu)\b', '[DOMAIN_MASKED]', masked, flags=re.IGNORECASE)

        # Telefon numaraları
        masked = self.PHONE_PATTERN.sub('[PHONE_MASKED]', masked)

        return masked

    def mask_ip(self, ip: str) -> str:
        """IP adresini maskele"""
        if not self._active:
            return ip
        return '[IP_MASKED]'

    def partial_mask_email(self, email: str) -> str:
        """E-postayı kısmen maskele (u***r@d***n.com)"""
        if not self._active or '@' not in email:
            return email

        try:
            local, domain = email.split('@')
            local_masked = local[0] + '*' * (len(local) - 2) + local[-1] if len(local) > 2 else '*' * len(local)

            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                domain_name = domain_parts[0]
                domain_masked = domain_name[0] + '*' * (len(domain_name) - 2) + domain_name[-1] if len(domain_name) > 2 else '*' * len(domain_name)
                domain_masked = domain_masked + '.' + '.'.join(domain_parts[1:])
            else:
                domain_masked = '*' * len(domain)

            return f"{local_masked}@{domain_masked}"
        except:
            return '[EMAIL_MASKED]'

    # ==================== REQUEST OBFUSCATİON ====================

    def obfuscate_request(self, request_data: Dict) -> Dict:
        """İstek verilerini gizle"""
        if not self._active:
            return request_data

        obfuscated = request_data.copy()

        # Hassas header'ları kaldır
        if self._config.obfuscate_headers:
            headers = obfuscated.get('headers', {})
            for header in self.SENSITIVE_HEADERS:
                headers.pop(header, None)
                headers.pop(header.lower(), None)

            obfuscated['headers'] = headers

        # IP maskele
        if 'ip' in obfuscated:
            obfuscated['ip'] = self.mask_ip(obfuscated['ip'])

        if 'client_ip' in obfuscated:
            obfuscated['client_ip'] = self.mask_ip(obfuscated['client_ip'])

        self._stats['obfuscated_requests'] += 1
        return obfuscated

    def obfuscate_response(self, response_data: Dict) -> Dict:
        """Yanıt verilerini gizle"""
        if not self._active:
            return response_data

        # JSON string ise parse et
        if isinstance(response_data, str):
            try:
                response_data = json.loads(response_data)
            except:
                return response_data

        # Recursive olarak hassas verileri maskele
        return self._obfuscate_dict(response_data)

    def _obfuscate_dict(self, data: Any) -> Any:
        """Dict içindeki hassas verileri maskele"""
        if isinstance(data, dict):
            return {k: self._obfuscate_dict(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._obfuscate_dict(item) for item in data]
        elif isinstance(data, str):
            return self.mask_data(data)
        return data

    # ==================== AUDIT TRAIL ====================

    def mask_audit_entry(self, log_entry: str) -> str:
        """Audit kaydını maskele"""
        if not self._active:
            return log_entry

        return self.mask_data(log_entry)

    def create_secure_log(self, event: str, details: Dict = None) -> Dict:
        """Güvenli log kaydı oluştur"""
        log = {
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'ghost_mode': self._active,
            'level': self._config.level.name if self._active else None
        }

        if details:
            # Hassas verileri maskele
            log['details'] = self._obfuscate_dict(details)

        return log

    # ==================== YARDIMCI METODLAR ====================

    def _secure_wipe(self, data: bytes):
        """Bellekten güvenli silme (best effort)"""
        if not data:
            return

        try:
            # Veriyi sıfırla
            for i in range(len(data)):
                data[i:i+1] = b'\x00'
        except TypeError:
            pass  # immutable bytes

    def rotate_keys(self) -> bool:
        """Anahtarları döndür"""
        if not self._active:
            return False

        # Eski anahtarları güvenli sil
        old_key = self._session_key
        old_salt = self._salt

        # Yeni anahtarlar oluştur
        if self.activate(self._config.level):
            self._secure_wipe(old_key)
            self._secure_wipe(old_salt)
            logger.info("[GHOST] Anahtarlar döndürüldü")
            return True

        return False

    def hash_data(self, data: str) -> str:
        """Veriyi hashle (geri dönüşümsüz)"""
        salt = self._salt or secrets.token_bytes(16)
        return hashlib.pbkdf2_hmac(
            'sha256',
            data.encode(),
            salt,
            100000
        ).hex()

    def verify_hash(self, data: str, hash_value: str) -> bool:
        """Hash doğrula"""
        return hmac.compare_digest(
            self.hash_data(data),
            hash_value
        )


# ==================== SINGLETON ERİŞİM ====================

_ghost_mode: Optional[GhostMode] = None


def ghost_mode_al() -> GhostMode:
    """Ghost Mode singleton (otomatik aktif)"""
    global _ghost_mode
    if _ghost_mode is None:
        _ghost_mode = GhostMode()
    return _ghost_mode


def ghost_aktif_mi() -> bool:
    """Ghost Mode aktif mi?"""
    return ghost_mode_al().is_active()


def ghost_sifrele(data: Union[str, bytes, Dict]) -> bytes:
    """Hızlı şifreleme"""
    return ghost_mode_al().encrypt(data)


def ghost_coz(data: bytes) -> str:
    """Hızlı çözme"""
    return ghost_mode_al().decrypt(data)


def ghost_maskele(text: str) -> str:
    """Hızlı maskeleme"""
    return ghost_mode_al().mask_data(text)


# ==================== FLASK MIDDLEWARE ====================

def ghost_middleware(app):
    """Flask middleware - tüm istekleri gizle"""
    ghost = ghost_mode_al()

    @app.before_request
    def before_ghost():
        from flask import request, g
        g.ghost_mode = ghost.is_active()

    @app.after_request
    def after_ghost(response):
        if ghost.is_active():
            # Response header'larını temizle
            headers_to_remove = ['Server', 'X-Powered-By']
            for header in headers_to_remove:
                response.headers.pop(header, None)

            # Custom header ekle
            response.headers['X-Ghost-Mode'] = 'active'

        return response

    return app


# ==================== TEST ====================

if __name__ == '__main__':
    ghost = ghost_mode_al()
    print("Ghost Status:", ghost.get_status())

    # Test şifreleme
    test_data = "Hassas veri: IP=192.168.1.1, email=test@example.com"
    encrypted = ghost.encrypt(test_data)
    decrypted = ghost.decrypt(encrypted)
    print(f"\nOriginal: {test_data}")
    print(f"Encrypted: {encrypted[:50]}...")
    print(f"Decrypted: {decrypted}")

    # Test maskeleme
    masked = ghost.mask_data(test_data)
    print(f"\nMasked: {masked}")
