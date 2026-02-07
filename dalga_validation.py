#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Input Validation v1.0
=============================

Pydantic tabanlı input validation.
- SQL Injection koruması
- SSRF koruması
- XSS koruması
- Type validation

KULLANIM:
    from dalga_validation import validate_request, IPScanRequest

    @app.route('/api/scan', methods=['POST'])
    @validate_request(IPScanRequest)
    def scan_ip(validated_data):
        ip = validated_data.ip
        ...
"""

import re
import ipaddress
import logging
from typing import Optional, List, Any, Callable
from functools import wraps
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator
from flask import request, jsonify

logger = logging.getLogger(__name__)


# ============================================================
# Tehlikeli Pattern'ler
# ============================================================

# SQL Injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\-\-|;|\/\*|\*\/)",  # SQL yorumları
    r"(\bUNION\b|\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b)",  # SQL anahtar kelimeleri
    r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+",  # OR 1=1 tarzı
    r"['\"](\s*OR\s*|\s*AND\s*)['\"]",  # String-based injection
    r"WAITFOR\s+DELAY",  # Time-based injection
    r"BENCHMARK\s*\(",  # MySQL time-based
]

# XSS patterns
XSS_PATTERNS = [
    r"<script[^>]*>",  # Script tag
    r"javascript:",  # JavaScript URL
    r"on\w+\s*=",  # Event handlers (onclick, onerror, etc)
    r"<iframe[^>]*>",  # iframe injection
    r"<img[^>]+onerror",  # Image with error handler
    r"expression\s*\(",  # CSS expression
]

# Path traversal patterns
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",  # Directory traversal
    r"\.\.\\",  # Windows directory traversal
    r"%2e%2e",  # URL encoded traversal
    r"%252e%252e",  # Double URL encoded
]

# SSRF koruması için izin verilen IP aralıkları
ALLOWED_PRIVATE_RANGES = False  # Production'da False olmalı


# ============================================================
# Yardımcı Fonksiyonlar
# ============================================================

def is_safe_string(value: str) -> tuple[bool, str]:
    """String'in güvenli olup olmadığını kontrol et"""
    value_lower = value.lower()

    # SQL Injection kontrolü
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return False, f"SQL injection riski tespit edildi"

    # XSS kontrolü
    for pattern in XSS_PATTERNS:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return False, f"XSS riski tespit edildi"

    # Path traversal kontrolü
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return False, f"Path traversal riski tespit edildi"

    return True, ""


def sanitize_string(value: str, max_length: int = 1000) -> str:
    """String'i temizle"""
    if not value:
        return ""

    # Uzunluk limiti
    value = value[:max_length]

    # HTML entities encode
    value = value.replace("&", "&amp;")
    value = value.replace("<", "&lt;")
    value = value.replace(">", "&gt;")
    value = value.replace('"', "&quot;")
    value = value.replace("'", "&#x27;")

    return value


def is_valid_ip(ip: str) -> bool:
    """Geçerli IP adresi mi?"""
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Private IP kontrolü (SSRF koruması)
        if not ALLOWED_PRIVATE_RANGES:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                return False

        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    """Geçerli domain mi?"""
    if not domain:
        return False

    # Domain pattern
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    if not re.match(domain_pattern, domain):
        return False

    # Localhost ve internal domain kontrolü (SSRF koruması)
    blocked_domains = ['localhost', '127.0.0.1', '0.0.0.0', 'internal', 'local']
    domain_lower = domain.lower()

    for blocked in blocked_domains:
        if blocked in domain_lower:
            return False

    return True


def is_valid_url(url: str) -> bool:
    """Geçerli URL mi?"""
    try:
        parsed = urlparse(url)

        # Scheme kontrolü
        if parsed.scheme not in ['http', 'https']:
            return False

        # Netloc kontrolü
        if not parsed.netloc:
            return False

        # SSRF koruması
        if not is_valid_domain(parsed.netloc.split(':')[0]):
            # Domain değilse IP olabilir
            try:
                ip = parsed.netloc.split(':')[0]
                if not is_valid_ip(ip):
                    return False
            except:
                return False

        return True
    except:
        return False


def is_valid_mac(mac: str) -> bool:
    """Geçerli MAC adresi mi?"""
    # MAC address formatları: XX:XX:XX:XX:XX:XX veya XX-XX-XX-XX-XX-XX
    mac_pattern = r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$'
    return bool(re.match(mac_pattern, mac))


def is_valid_email(email: str) -> bool:
    """Geçerli email mi?"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))


def is_valid_hash(hash_value: str) -> bool:
    """Geçerli hash mi? (MD5, SHA1, SHA256)"""
    # MD5: 32 hex, SHA1: 40 hex, SHA256: 64 hex
    hash_pattern = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    return bool(re.match(hash_pattern, hash_value))


# ============================================================
# Pydantic Modeller
# ============================================================

class SafeString(str):
    """SQL injection ve XSS korumalı string"""

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if not isinstance(v, str):
            raise ValueError('String olmalı')

        is_safe, error = is_safe_string(v)
        if not is_safe:
            raise ValueError(error)

        return cls(v)


class BaseRequestModel(BaseModel):
    """Temel request modeli"""

    class Config:
        str_strip_whitespace = True
        str_max_length = 10000


class IPAddressRequest(BaseRequestModel):
    """IP adresi içeren request"""
    ip: str = Field(..., description="IP adresi")

    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v):
        if not is_valid_ip(v):
            raise ValueError('Geçersiz veya engelli IP adresi')
        return v


class DomainRequest(BaseRequestModel):
    """Domain içeren request"""
    domain: str = Field(..., description="Domain adı")

    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v):
        if not is_valid_domain(v):
            raise ValueError('Geçersiz veya engelli domain')
        return v


class URLRequest(BaseRequestModel):
    """URL içeren request"""
    url: str = Field(..., description="URL")

    @field_validator('url')
    @classmethod
    def validate_url(cls, v):
        if not is_valid_url(v):
            raise ValueError('Geçersiz veya engelli URL')
        return v


class PortScanRequest(BaseRequestModel):
    """Port tarama request"""
    hedef: str = Field(..., description="Hedef IP veya domain")
    port_araligi: Optional[str] = Field("1-1000", description="Port aralığı (örn: 1-1000)")

    @field_validator('hedef')
    @classmethod
    def validate_hedef(cls, v):
        # IP veya domain olabilir
        if is_valid_ip(v):
            return v
        if is_valid_domain(v):
            return v
        raise ValueError('Geçersiz hedef (IP veya domain olmalı)')

    @field_validator('port_araligi')
    @classmethod
    def validate_port_araligi(cls, v):
        if not v:
            return "1-1000"

        # Port aralığı formatı: START-END veya tek port
        pattern = r'^(\d{1,5})(-(\d{1,5}))?$'
        match = re.match(pattern, v)

        if not match:
            raise ValueError('Geçersiz port aralığı formatı (örn: 1-1000)')

        start = int(match.group(1))
        end = int(match.group(3)) if match.group(3) else start

        if not (1 <= start <= 65535) or not (1 <= end <= 65535):
            raise ValueError('Port 1-65535 arasında olmalı')

        if start > end:
            raise ValueError('Başlangıç portu bitiş portundan büyük olamaz')

        return v


class WiFiScanRequest(BaseRequestModel):
    """WiFi tarama request"""
    interface: Optional[str] = Field("wlan0", description="Ağ arayüzü")
    timeout: Optional[int] = Field(30, ge=1, le=300, description="Timeout (saniye)")


class BluetoothScanRequest(BaseRequestModel):
    """Bluetooth tarama request"""
    timeout: Optional[int] = Field(10, ge=1, le=60, description="Timeout (saniye)")


class OSINTSearchRequest(BaseRequestModel):
    """OSINT arama request"""
    hedef: str = Field(..., description="Arama hedefi (IP, domain, email, hash)")
    tip: Optional[str] = Field("auto", description="Arama tipi")

    @field_validator('hedef')
    @classmethod
    def validate_hedef(cls, v):
        is_safe, error = is_safe_string(v)
        if not is_safe:
            raise ValueError(error)

        # En az bir geçerli format olmalı
        if (is_valid_ip(v) or is_valid_domain(v) or
            is_valid_email(v) or is_valid_hash(v) or
            len(v) >= 3):  # Username vb. için minimum uzunluk
            return v

        raise ValueError('Geçersiz arama hedefi')

    @field_validator('tip')
    @classmethod
    def validate_tip(cls, v):
        allowed = ['auto', 'ip', 'domain', 'email', 'hash', 'username', 'phone']
        if v not in allowed:
            raise ValueError(f'Geçersiz tip. İzin verilenler: {allowed}')
        return v


class KonumAraRequest(BaseRequestModel):
    """Konum arama request"""
    ip: str = Field(..., description="IP adresi")

    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v):
        # Basit IP validation (private IP'lere de izin ver - geolocation için)
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Geçersiz IP adresi')


class MACLookupRequest(BaseRequestModel):
    """MAC adresi lookup request"""
    mac: str = Field(..., description="MAC adresi")

    @field_validator('mac')
    @classmethod
    def validate_mac(cls, v):
        if not is_valid_mac(v):
            raise ValueError('Geçersiz MAC adresi formatı')
        return v


class APIKeyUpdateRequest(BaseRequestModel):
    """API key güncelleme request"""
    key_name: str = Field(..., description="API key adı")
    key_value: str = Field(..., description="API key değeri")

    @field_validator('key_name')
    @classmethod
    def validate_key_name(cls, v):
        allowed_keys = [
            'SHODAN_API_KEY', 'OPENCELLID_API_KEY', 'N2YO_API_KEY',
            'HIBP_API_KEY', 'VIRUSTOTAL_API_KEY', 'OTX_KEY', 'GROQ_API_KEY'
        ]
        if v not in allowed_keys:
            raise ValueError(f'Geçersiz key adı. İzin verilenler: {allowed_keys}')
        return v

    @field_validator('key_value')
    @classmethod
    def validate_key_value(cls, v):
        is_safe, error = is_safe_string(v)
        if not is_safe:
            raise ValueError(error)

        if len(v) < 10 or len(v) > 200:
            raise ValueError('API key uzunluğu 10-200 karakter olmalı')

        return v


class LoginRequest(BaseRequestModel):
    """Login request"""
    kullanici: str = Field(..., min_length=3, max_length=50, description="Kullanıcı adı")
    sifre: str = Field(..., min_length=6, max_length=100, description="Şifre")

    @field_validator('kullanici')
    @classmethod
    def validate_kullanici(cls, v):
        # Sadece alfanumerik ve alt çizgi
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Kullanıcı adı sadece harf, rakam ve _ içerebilir')
        return v


class ExportRequest(BaseRequestModel):
    """Export request"""
    format: str = Field(..., description="Export formatı")

    @field_validator('format')
    @classmethod
    def validate_format(cls, v):
        allowed = ['json', 'csv', 'pdf', 'xlsx', 'html']
        if v.lower() not in allowed:
            raise ValueError(f'Geçersiz format. İzin verilenler: {allowed}')
        return v.lower()


# ============================================================
# Flask Decorator
# ============================================================

def validate_request(model: type[BaseModel]):
    """
    Flask route'ları için Pydantic validation decorator.

    Kullanım:
        @app.route('/api/scan', methods=['POST'])
        @validate_request(PortScanRequest)
        def scan(validated_data):
            hedef = validated_data.hedef
            ...
    """
    def decorator(f: Callable):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                # JSON data al
                data = request.get_json(force=True, silent=True) or {}

                # Pydantic validation
                validated = model(**data)

                # Validated data'yı fonksiyona geç
                return f(validated, *args, **kwargs)

            except Exception as e:
                error_msg = str(e)
                logger.warning(f"[VALIDATION] Hata: {error_msg}")

                return jsonify({
                    'success': False,
                    'error': 'Validation hatası',
                    'details': error_msg
                }), 400

        return wrapper
    return decorator


def validate_query_params(model: type[BaseModel]):
    """
    Flask GET request query parametreleri için validation decorator.
    """
    def decorator(f: Callable):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                # Query parameters al
                data = request.args.to_dict()

                # Pydantic validation
                validated = model(**data)

                return f(validated, *args, **kwargs)

            except Exception as e:
                error_msg = str(e)
                logger.warning(f"[VALIDATION] Query param hatası: {error_msg}")

                return jsonify({
                    'success': False,
                    'error': 'Validation hatası',
                    'details': error_msg
                }), 400

        return wrapper
    return decorator


# ============================================================
# Test
# ============================================================

if __name__ == '__main__':
    # Test cases
    print("=== Validation Tests ===\n")

    # IP test
    print("IP Validation:")
    print(f"  8.8.8.8: {is_valid_ip('8.8.8.8')}")
    print(f"  192.168.1.1: {is_valid_ip('192.168.1.1')}")  # Private - blocked
    print(f"  invalid: {is_valid_ip('invalid')}")

    # Domain test
    print("\nDomain Validation:")
    print(f"  google.com: {is_valid_domain('google.com')}")
    print(f"  localhost: {is_valid_domain('localhost')}")  # Blocked

    # Safe string test
    print("\nSafe String:")
    print(f"  Normal text: {is_safe_string('Hello World')}")
    print(f"  SQL injection: {is_safe_string(chr(39) + ' OR 1=1 --')}")
    print(f"  XSS: {is_safe_string('<script>alert(1)</script>')}")

    # Pydantic model test
    print("\nPydantic Models:")
    try:
        req = PortScanRequest(hedef="8.8.8.8", port_araligi="1-1000")
        print(f"  PortScanRequest: OK - {req.hedef}")
    except Exception as e:
        print(f"  PortScanRequest: FAIL - {e}")

    try:
        req = OSINTSearchRequest(hedef="test@example.com", tip="email")
        print(f"  OSINTSearchRequest: OK - {req.hedef}")
    except Exception as e:
        print(f"  OSINTSearchRequest: FAIL - {e}")
