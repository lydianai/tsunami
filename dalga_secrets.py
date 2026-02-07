#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Secrets Manager v1.0
============================

Güvenli API key ve secret yönetimi.
- Environment variable'lardan okuma
- Varsayılan değerler (development için)
- Secret validation
- Audit logging

KULLANIM:
    from dalga_secrets import SecretsManager
    secrets = SecretsManager()
    shodan_key = secrets.get('SHODAN_API_KEY')
"""

import os
import secrets
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache

logger = logging.getLogger(__name__)


def _generate_secure_key(length: int = 32) -> str:
    """Kriptografik olarak güvenli anahtar oluştur"""
    return secrets.token_hex(length)


@dataclass
class SecretConfig:
    """Secret konfigürasyonu"""
    name: str
    required: bool = False
    default: Optional[str] = None
    description: str = ""
    masked_log: bool = True  # Log'da maskele


# Tüm TSUNAMI API key'leri ve secret'ları
SECRETS_REGISTRY: Dict[str, SecretConfig] = {
    # IoT & Ağ İstihbaratı
    'SHODAN_API_KEY': SecretConfig(
        name='SHODAN_API_KEY',
        required=False,
        default=None,
        description='Shodan IoT arama API key'
    ),

    # Baz İstasyonu / Hücresel Ağ
    'OPENCELLID_API_KEY': SecretConfig(
        name='OPENCELLID_API_KEY',
        required=False,
        default=None,
        description='OpenCellID baz istasyonu API key'
    ),

    # Uydu Takibi
    'N2YO_API_KEY': SecretConfig(
        name='N2YO_API_KEY',
        required=False,
        default=None,
        description='N2YO uydu takip API key'
    ),

    # Hava Sahası
    'OPENSKY_USERNAME': SecretConfig(
        name='OPENSKY_USERNAME',
        required=False,
        default=None,
        description='OpenSky Network kullanıcı adı'
    ),
    'OPENSKY_PASSWORD': SecretConfig(
        name='OPENSKY_PASSWORD',
        required=False,
        default=None,
        description='OpenSky Network şifresi',
        masked_log=True
    ),

    # OSINT API'leri
    'HIBP_API_KEY': SecretConfig(
        name='HIBP_API_KEY',
        required=False,
        default=None,
        description='Have I Been Pwned API key'
    ),
    'IPQS_API_KEY': SecretConfig(
        name='IPQS_API_KEY',
        required=False,
        default=None,
        description='IP Quality Score API key'
    ),
    'HUNTER_API_KEY': SecretConfig(
        name='HUNTER_API_KEY',
        required=False,
        default=None,
        description='Hunter.io email finder API key'
    ),

    # Tehdit İstihbaratı
    'OTX_KEY': SecretConfig(
        name='OTX_KEY',
        required=False,
        default=None,
        description='AlienVault OTX API key'
    ),
    'ABUSEIPDB_KEY': SecretConfig(
        name='ABUSEIPDB_KEY',
        required=False,
        default=None,
        description='AbuseIPDB API key'
    ),
    'VIRUSTOTAL_API_KEY': SecretConfig(
        name='VIRUSTOTAL_API_KEY',
        required=False,
        default=None,
        description='VirusTotal API key'
    ),

    # AI/LLM
    'GROQ_API_KEY': SecretConfig(
        name='GROQ_API_KEY',
        required=False,
        default=None,
        description='Groq AI API key'
    ),
    'OPENAI_API_KEY': SecretConfig(
        name='OPENAI_API_KEY',
        required=False,
        default=None,
        description='OpenAI API key'
    ),

    # Database
    'DATABASE_URL': SecretConfig(
        name='DATABASE_URL',
        required=False,
        default='sqlite:///tsunami.db',
        description='Veritabanı bağlantı URL'
    ),
    'REDIS_URL': SecretConfig(
        name='REDIS_URL',
        required=False,
        default='redis://localhost:6379/0',
        description='Redis bağlantı URL'
    ),
    'MONGODB_URL': SecretConfig(
        name='MONGODB_URL',
        required=False,
        default='mongodb://localhost:27017/tsunami',
        description='MongoDB bağlantı URL'
    ),

    # Session & Security
    'SECRET_KEY': SecretConfig(
        name='SECRET_KEY',
        required=True,
        default=None,
        description='Flask session secret key',
        masked_log=True
    ),
    'JWT_SECRET_KEY': SecretConfig(
        name='JWT_SECRET_KEY',
        required=False,
        default=None,
        description='JWT token secret key',
        masked_log=True
    ),

    # CORS
    'ALLOWED_ORIGINS': SecretConfig(
        name='ALLOWED_ORIGINS',
        required=False,
        default='http://localhost:8080,http://127.0.0.1:8080',
        description="İzin verilen CORS origin'leri"
    ),
}


class SecretsManager:
    """
    Güvenli secrets yönetimi.

    Kullanım:
        secrets = SecretsManager()
        api_key = secrets.get('SHODAN_API_KEY')

        # Required kontrolü ile
        api_key = secrets.get('SECRET_KEY', required=True)
    """

    _instance = None
    _initialized = False

    def __new__(cls):
        """Singleton pattern"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._secrets: Dict[str, Optional[str]] = {}
        self._access_log: list = []
        self._load_secrets()
        self._initialized = True

    def _load_secrets(self):
        """Environment variable'lardan secret'ları yükle"""
        loaded_count = 0
        missing_required = []

        for name, config in SECRETS_REGISTRY.items():
            value = os.environ.get(name, config.default)

            # SECRET_KEY için özel kontrol - güvenlik kritik
            if name == 'SECRET_KEY':
                value = self._validate_secret_key(value)
            elif name == 'JWT_SECRET_KEY':
                value = self._validate_jwt_secret_key(value)

            self._secrets[name] = value

            if value:
                loaded_count += 1
                if config.masked_log:
                    logger.debug(f"[SECRETS] {name} yüklendi: ***masked***")
                else:
                    logger.debug(f"[SECRETS] {name} yüklendi")
            elif config.required:
                missing_required.append(name)
                logger.warning(f"[SECRETS] {name} ZORUNLU ama bulunamadı!")

        logger.info(f"[SECRETS] {loaded_count}/{len(SECRETS_REGISTRY)} secret yüklendi")

        if missing_required:
            logger.error(f"[SECRETS] Eksik zorunlu secret'lar: {missing_required}")

    def _validate_secret_key(self, value: Optional[str]) -> str:
        """SECRET_KEY doğrula ve gerekirse güvenli anahtar oluştur"""
        insecure_patterns = [
            'dev-', 'test-', 'change-in-production', '$(', 'your-secret',
            'secret-key-here', 'changeme', 'password', '123456'
        ]

        if not value:
            logger.critical("[SECRETS] SECRET_KEY bulunamadı! Geçici anahtar oluşturuluyor...")
            logger.critical("[SECRETS] ÖNEMLİ: .env dosyasına kalıcı SECRET_KEY ekleyin!")
            return _generate_secure_key(32)

        # Güvensiz pattern kontrolü
        value_lower = value.lower()
        for pattern in insecure_patterns:
            if pattern in value_lower:
                logger.critical(f"[SECRETS] GÜVENSİZ SECRET_KEY tespit edildi (pattern: {pattern})")
                logger.critical("[SECRETS] Güvenli geçici anahtar oluşturuluyor...")
                logger.critical("[SECRETS] ÖNEMLİ: .env dosyasını güncelleyin!")
                return _generate_secure_key(32)

        # Minimum uzunluk kontrolü (256-bit = 64 hex karakter veya 32 byte)
        if len(value) < 32:
            logger.warning(f"[SECRETS] SECRET_KEY çok kısa ({len(value)} karakter). Minimum 32 karakter önerilir.")

        return value

    def _validate_jwt_secret_key(self, value: Optional[str]) -> Optional[str]:
        """JWT_SECRET_KEY doğrula"""
        insecure_patterns = [
            'dev-', 'test-', 'change-in-production', '$(', 'your-jwt',
            'secret-key-here', 'changeme', 'password', '123456'
        ]

        if not value:
            return None

        value_lower = value.lower()
        for pattern in insecure_patterns:
            if pattern in value_lower:
                logger.critical(f"[SECRETS] GÜVENSİZ JWT_SECRET_KEY tespit edildi (pattern: {pattern})")
                logger.critical("[SECRETS] Güvenli geçici anahtar oluşturuluyor...")
                return _generate_secure_key(32)

        return value

    def get(self, name: str, required: bool = False, default: Any = None) -> Optional[str]:
        """
        Secret değerini al.

        Args:
            name: Secret adı
            required: Zorunlu mu?
            default: Varsayılan değer

        Returns:
            Secret değeri veya None
        """
        # Önce environment'tan dene (runtime override için)
        value = os.environ.get(name)

        if value is None:
            value = self._secrets.get(name)

        if value is None:
            value = default

        # Erişim logla (audit trail)
        self._log_access(name, found=value is not None)

        if required and value is None:
            logger.error(f"[SECRETS] Zorunlu secret bulunamadı: {name}")
            raise ValueError(f"Zorunlu secret bulunamadı: {name}")

        return value

    def _log_access(self, name: str, found: bool):
        """Secret erişimini logla (audit trail)"""
        self._access_log.append({
            'timestamp': datetime.now().isoformat(),
            'secret': name,
            'found': found
        })

        # Son 1000 kaydı tut
        if len(self._access_log) > 1000:
            self._access_log = self._access_log[-1000:]

    def get_access_log(self) -> list:
        """Erişim logunu döndür"""
        return self._access_log.copy()

    def is_available(self, name: str) -> bool:
        """Secret mevcut mu?"""
        return self.get(name) is not None

    def get_status(self) -> Dict[str, Any]:
        """Tüm secret'ların durumu"""
        status = {
            'total': len(SECRETS_REGISTRY),
            'loaded': 0,
            'missing': [],
            'available': [],
            'secrets': {}
        }

        for name, config in SECRETS_REGISTRY.items():
            is_set = self._secrets.get(name) is not None

            if is_set:
                status['loaded'] += 1
                status['available'].append(name)
            else:
                status['missing'].append(name)

            status['secrets'][name] = {
                'available': is_set,
                'required': config.required,
                'description': config.description
            }

        return status

    def mask_value(self, value: str, show_chars: int = 4) -> str:
        """Değeri maskele (logging için)"""
        if not value or len(value) <= show_chars:
            return '***'
        return value[:show_chars] + '*' * (len(value) - show_chars)

    def validate_all(self) -> tuple[bool, list]:
        """Tüm zorunlu secret'ları doğrula"""
        missing = []

        for name, config in SECRETS_REGISTRY.items():
            if config.required and not self._secrets.get(name):
                missing.append(name)

        return len(missing) == 0, missing


# Global instance
_secrets_manager: Optional[SecretsManager] = None


def get_secrets_manager() -> SecretsManager:
    """Global SecretsManager instance'ı al"""
    global _secrets_manager
    if _secrets_manager is None:
        _secrets_manager = SecretsManager()
    return _secrets_manager


# Kısa yol fonksiyonları
def get_secret(name: str, required: bool = False, default: Any = None) -> Optional[str]:
    """Secret al (kısa yol)"""
    return get_secrets_manager().get(name, required, default)


def secret_available(name: str) -> bool:
    """Secret mevcut mu? (kısa yol)"""
    return get_secrets_manager().is_available(name)


# API Key'ler için özel fonksiyonlar
@lru_cache(maxsize=1)
def get_shodan_api_key() -> Optional[str]:
    """Shodan API key"""
    return get_secret('SHODAN_API_KEY')


@lru_cache(maxsize=1)
def get_opencellid_api_key() -> Optional[str]:
    """OpenCellID API key"""
    return get_secret('OPENCELLID_API_KEY')


@lru_cache(maxsize=1)
def get_n2yo_api_key() -> Optional[str]:
    """N2YO API key"""
    return get_secret('N2YO_API_KEY')


@lru_cache(maxsize=1)
def get_groq_api_key() -> Optional[str]:
    """Groq API key"""
    return get_secret('GROQ_API_KEY')


@lru_cache(maxsize=1)
def get_virustotal_api_key() -> Optional[str]:
    """VirusTotal API key"""
    return get_secret('VIRUSTOTAL_API_KEY')


# CLI için test
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    sm = SecretsManager()
    status = sm.get_status()

    print("\n=== TSUNAMI Secrets Status ===")
    print(f"Toplam: {status['total']}")
    print(f"Yüklendi: {status['loaded']}")
    print(f"\nMevcut: {status['available']}")
    print(f"Eksik: {status['missing']}")
