#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DALGA OSINT ORCHESTRATOR - Ultra Gizli Global OSINT Sistemi
Tüm 614+ OSINT aracı entegre - Türkçe doğal dil desteği
"""

import asyncio
import aiohttp
import hashlib
import json
import re
import socket
import ssl
import subprocess
import time
import random
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, quote_plus
import base64

# ==================== GIZLILIK KATMANI ====================

class StealthLevel(Enum):
    """Gizlilik seviyeleri"""
    NORMAL = 1      # Standart
    STEALTH = 2     # Gizli
    GHOST = 3       # Hayalet
    PHANTOM = 4     # Fantom (maksimum gizlilik)

@dataclass
class StealthConfig:
    """Gizlilik yapılandırması"""
    level: StealthLevel = StealthLevel.PHANTOM
    use_tor: bool = True
    rotate_user_agent: bool = True
    random_delays: bool = True
    min_delay: float = 0.5
    max_delay: float = 3.0
    spoof_headers: bool = True
    dns_over_https: bool = True

# Rastgele User-Agent havuzu
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]

# ==================== TÜRKÇE DOĞAL DİL İŞLEME ====================

# Türkçe komut kalıpları
TURKISH_PATTERNS = {
    # IP araştırma
    r'(ip|adres)\s*(ara|bul|tara|analiz|incele|kontrol)': 'ip_investigation',
    r'(bu|şu)\s*ip.*?(kim|nerede|neresi|bilgi)': 'ip_investigation',
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})': 'ip_investigation',

    # Domain araştırma
    r'(domain|alan\s*adı|site|website)\s*(ara|bul|tara|analiz|incele)': 'domain_investigation',
    r'(whois|dns|subdomain)': 'domain_investigation',
    r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})': 'domain_investigation',

    # Email araştırma
    r'(e-?mail|eposta|mail)\s*(ara|bul|tara|analiz|kontrol)': 'email_investigation',
    r'(veri\s*ihlal|breach|leak|sızıntı)': 'email_investigation',
    r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})': 'email_investigation',

    # Kullanıcı adı araştırma
    r'(kullanıcı|user|hesap|profil).*?(ara|bul|tara|araştır|incele)': 'username_investigation',
    r'(sosyal\s*medya|social)': 'username_investigation',
    r'@\w+': 'username_investigation',

    # Telefon araştırma
    r'(telefon|numara|gsm|cep)\s*(ara|bul|tara|kime\s*ait)': 'phone_investigation',
    r'(\+?\d{10,15})': 'phone_investigation',

    # Konum araştırma
    r'(konum|lokasyon|nerede|neresi|adres)\s*(bul|ara)': 'location_investigation',
    r'(harita|koordinat|gps)': 'location_investigation',

    # Şirket araştırma
    r'(şirket|firma|company|kurum)\s*(ara|bul|bilgi)': 'company_investigation',
    r'(çalışan|employee|personel)': 'company_investigation',

    # Tehdit istihbaratı
    r'(tehdit|threat|malware|zararlı|virüs)': 'threat_intelligence',
    r'(saldırı|attack|hack|ihlal)': 'threat_intelligence',

    # Kripto araştırma
    r'(kripto|bitcoin|btc|ethereum|eth|wallet|cüzdan)': 'crypto_investigation',
    r'(blockchain|transaction|işlem)': 'crypto_investigation',

    # Araç plaka
    r'(plaka|araç|vehicle)\s*(ara|bul|sorgula)': 'vehicle_investigation',
    r'(\d{2}\s*[A-Z]{1,3}\s*\d{2,4})': 'vehicle_investigation',

    # Görsel analiz
    r'(görsel|resim|fotoğraf|image)\s*(ara|analiz|reverse)': 'image_investigation',
    r'(yüz|face|kişi\s*bul)': 'image_investigation',

    # Dark web
    r'(dark\s*web|onion|tor|deep\s*web)': 'darkweb_investigation',
    r'(gizli\s*site|hidden)': 'darkweb_investigation',

    # Genel arama
    r'(ara|bul|tara|analiz|incele|araştır)': 'general_investigation',
}

# Türkçe hedef çıkarma kalıpları
TARGET_PATTERNS = {
    'ip': r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    'domain': r'([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)',
    'email': r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
    'phone': r'(\+?[\d\s-]{10,20})',
    'username': r'@([a-zA-Z0-9_]+)',
    'hash': r'([a-fA-F0-9]{32,64})',
    'btc_wallet': r'([13][a-km-zA-HJ-NP-Z1-9]{25,34})',
    'eth_wallet': r'(0x[a-fA-F0-9]{40})',
}

# ==================== OSINT ARAÇ VERİTABANI ====================

# Gerçek çalışan OSINT API'leri ve araçları
OSINT_TOOLS = {
    # ===== IP ARAŞTIRMA =====
    'ip_investigation': {
        'apis': [
            {'name': 'IPInfo', 'url': 'https://ipinfo.io/{target}/json', 'free': True},
            {'name': 'IP-API', 'url': 'http://ip-api.com/json/{target}', 'free': True},
            {'name': 'IPGeolocation', 'url': 'https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={target}', 'free': True},
            {'name': 'AbuseIPDB', 'url': 'https://api.abuseipdb.com/api/v2/check', 'free': True, 'requires_key': True},
            {'name': 'GreyNoise', 'url': 'https://api.greynoise.io/v3/community/{target}', 'free': True},
            {'name': 'Shodan', 'url': 'https://api.shodan.io/shodan/host/{target}', 'requires_key': True},
            {'name': 'VirusTotal', 'url': 'https://www.virustotal.com/api/v3/ip_addresses/{target}', 'requires_key': True},
            {'name': 'AlienVault OTX', 'url': 'https://otx.alienvault.com/api/v1/indicators/IPv4/{target}', 'free': True},
            {'name': 'IPVoid', 'url': 'https://www.ipvoid.com/ip-blacklist-check/', 'scrape': True},
            {'name': 'Censys', 'url': 'https://search.censys.io/api/v2/hosts/{target}', 'requires_key': True},
            {'name': 'SecurityTrails', 'url': 'https://api.securitytrails.com/v1/ips/{target}', 'requires_key': True},
            {'name': 'BGPView', 'url': 'https://api.bgpview.io/ip/{target}', 'free': True},
            {'name': 'IPData', 'url': 'https://api.ipdata.co/{target}', 'free': True},
            {'name': 'IPStack', 'url': 'http://api.ipstack.com/{target}', 'requires_key': True},
            {'name': 'DB-IP', 'url': 'https://api.db-ip.com/v2/free/{target}', 'free': True},
        ],
        'tools': [
            'nmap', 'masscan', 'whois', 'traceroute', 'dig', 'host'
        ]
    },

    # ===== DOMAIN ARAŞTIRMA =====
    'domain_investigation': {
        'apis': [
            {'name': 'WhoisXML', 'url': 'https://www.whoisxmlapi.com/whoisserver/WhoisService', 'requires_key': True},
            {'name': 'SecurityTrails', 'url': 'https://api.securitytrails.com/v1/domain/{target}', 'requires_key': True},
            {'name': 'VirusTotal', 'url': 'https://www.virustotal.com/api/v3/domains/{target}', 'requires_key': True},
            {'name': 'URLScan', 'url': 'https://urlscan.io/api/v1/search/?q=domain:{target}', 'free': True},
            {'name': 'CRT.sh', 'url': 'https://crt.sh/?q={target}&output=json', 'free': True},
            {'name': 'DNSDumpster', 'url': 'https://dnsdumpster.com/', 'scrape': True},
            {'name': 'Subfinder', 'url': 'https://api.subfinder.io/domains/{target}', 'free': True},
            {'name': 'Archive.org', 'url': 'https://archive.org/wayback/available?url={target}', 'free': True},
            {'name': 'BuiltWith', 'url': 'https://api.builtwith.com/v20/api.json', 'requires_key': True},
            {'name': 'Wappalyzer', 'url': 'https://api.wappalyzer.com/v2/lookup/', 'requires_key': True},
            {'name': 'RiskIQ', 'url': 'https://api.riskiq.net/pt/v2/dns/passive', 'requires_key': True},
            {'name': 'DomainTools', 'url': 'https://api.domaintools.com/v1/{target}/whois', 'requires_key': True},
            {'name': 'Hunter.io', 'url': 'https://api.hunter.io/v2/domain-search', 'requires_key': True},
            {'name': 'Shodan', 'url': 'https://api.shodan.io/dns/domain/{target}', 'requires_key': True},
        ],
        'tools': [
            'whois', 'dig', 'nslookup', 'host', 'subfinder', 'amass', 'dnsrecon', 'fierce'
        ]
    },

    # ===== EMAIL ARAŞTIRMA =====
    'email_investigation': {
        'apis': [
            {'name': 'Hunter.io', 'url': 'https://api.hunter.io/v2/email-verifier', 'requires_key': True},
            {'name': 'EmailRep', 'url': 'https://emailrep.io/{target}', 'free': True},
            {'name': 'Have I Been Pwned', 'url': 'https://haveibeenpwned.com/api/v3/breachedaccount/{target}', 'requires_key': True},
            {'name': 'Dehashed', 'url': 'https://api.dehashed.com/search', 'requires_key': True},
            {'name': 'Intelligence X', 'url': 'https://2.intelx.io/intelligent/search', 'requires_key': True},
            {'name': 'Snov.io', 'url': 'https://api.snov.io/v1/get-emails-from-url', 'requires_key': True},
            {'name': 'Clearbit', 'url': 'https://person.clearbit.com/v2/people/find', 'requires_key': True},
            {'name': 'FullContact', 'url': 'https://api.fullcontact.com/v3/person.enrich', 'requires_key': True},
            {'name': 'Pipl', 'url': 'https://api.pipl.com/search/', 'requires_key': True},
            {'name': 'LeakCheck', 'url': 'https://leakcheck.io/api/public', 'requires_key': True},
        ],
        'tools': [
            'theHarvester', 'holehe', 'h8mail', 'infoga'
        ]
    },

    # ===== KULLANICI ADI ARAŞTIRMA =====
    'username_investigation': {
        'apis': [
            {'name': 'Namechk', 'url': 'https://namechk.com/api/', 'scrape': True},
            {'name': 'KnowEm', 'url': 'https://knowem.com/', 'scrape': True},
            {'name': 'WhatsMyName', 'url': 'https://whatsmyname.app/', 'scrape': True},
            {'name': 'SocialSearcher', 'url': 'https://www.social-searcher.com/api/', 'requires_key': True},
        ],
        'tools': [
            'sherlock', 'maigret', 'whatsmyname', 'social-analyzer', 'socialscan'
        ],
        'platforms': [
            'twitter', 'instagram', 'facebook', 'linkedin', 'github', 'reddit',
            'tiktok', 'youtube', 'pinterest', 'tumblr', 'flickr', 'medium',
            'twitch', 'steam', 'spotify', 'snapchat', 'telegram', 'discord',
            'keybase', 'hackernews', 'producthunt', 'dribbble', 'behance',
            'deviantart', '500px', 'vk', 'ok.ru', 'weibo', 'douyin'
        ]
    },

    # ===== TELEFON ARAŞTIRMA =====
    'phone_investigation': {
        'apis': [
            {'name': 'NumVerify', 'url': 'http://apilayer.net/api/validate', 'requires_key': True},
            {'name': 'Twilio Lookup', 'url': 'https://lookups.twilio.com/v1/PhoneNumbers/{target}', 'requires_key': True},
            {'name': 'NumLookup', 'url': 'https://api.numlookupapi.com/v1/validate/{target}', 'requires_key': True},
            {'name': 'CallerID', 'url': 'https://api.apilayer.com/number_verification/validate', 'requires_key': True},
            {'name': 'TrueCaller', 'url': 'https://api.truecaller.com/', 'requires_key': True},
        ],
        'tools': [
            'phoneinfoga', 'ignorant'
        ]
    },

    # ===== KONUM ARAŞTIRMA =====
    'location_investigation': {
        'apis': [
            {'name': 'Nominatim', 'url': 'https://nominatim.openstreetmap.org/search', 'free': True},
            {'name': 'Photon', 'url': 'https://photon.komoot.io/api/', 'free': True},
            {'name': 'Google Maps', 'url': 'https://maps.googleapis.com/maps/api/geocode/json', 'requires_key': True},
            {'name': 'OpenCage', 'url': 'https://api.opencagedata.com/geocode/v1/json', 'requires_key': True},
            {'name': 'Here Maps', 'url': 'https://geocode.search.hereapi.com/v1/geocode', 'requires_key': True},
            {'name': 'Mapbox', 'url': 'https://api.mapbox.com/geocoding/v5/mapbox.places/', 'requires_key': True},
            {'name': 'WiGLE', 'url': 'https://api.wigle.net/api/v2/network/search', 'requires_key': True},
            {'name': 'OpenCellID', 'url': 'https://opencellid.org/cell/get', 'requires_key': True},
        ],
        'tools': [
            'creepy', 'tinfoleak', 'geostalker'
        ]
    },

    # ===== ŞİRKET ARAŞTIRMA =====
    'company_investigation': {
        'apis': [
            {'name': 'Clearbit', 'url': 'https://company.clearbit.com/v2/companies/find', 'requires_key': True},
            {'name': 'LinkedIn', 'url': 'https://api.linkedin.com/v2/companies/', 'requires_key': True},
            {'name': 'Crunchbase', 'url': 'https://api.crunchbase.com/v3.1/organizations/', 'requires_key': True},
            {'name': 'OpenCorporates', 'url': 'https://api.opencorporates.com/v0.4/companies/search', 'free': True},
            {'name': 'Hunter.io', 'url': 'https://api.hunter.io/v2/domain-search', 'requires_key': True},
            {'name': 'FullContact', 'url': 'https://api.fullcontact.com/v3/company.enrich', 'requires_key': True},
            {'name': 'ZoomInfo', 'url': 'https://api.zoominfo.com/', 'requires_key': True},
        ],
        'tools': [
            'theHarvester', 'recon-ng', 'maltego'
        ]
    },

    # ===== TEHDİT İSTİHBARATI =====
    'threat_intelligence': {
        'apis': [
            {'name': 'VirusTotal', 'url': 'https://www.virustotal.com/api/v3/', 'requires_key': True},
            {'name': 'AbuseIPDB', 'url': 'https://api.abuseipdb.com/api/v2/', 'requires_key': True},
            {'name': 'AlienVault OTX', 'url': 'https://otx.alienvault.com/api/v1/', 'free': True},
            {'name': 'ThreatCrowd', 'url': 'https://www.threatcrowd.org/searchApi/v2/', 'free': True},
            {'name': 'MalwareBazaar', 'url': 'https://mb-api.abuse.ch/api/v1/', 'free': True},
            {'name': 'URLhaus', 'url': 'https://urlhaus-api.abuse.ch/v1/', 'free': True},
            {'name': 'ThreatFox', 'url': 'https://threatfox-api.abuse.ch/api/v1/', 'free': True},
            {'name': 'Pulsedive', 'url': 'https://pulsedive.com/api/', 'requires_key': True},
            {'name': 'IBM X-Force', 'url': 'https://api.xforce.ibmcloud.com/', 'requires_key': True},
            {'name': 'Recorded Future', 'url': 'https://api.recordedfuture.com/v2/', 'requires_key': True},
            {'name': 'CrowdStrike', 'url': 'https://api.crowdstrike.com/', 'requires_key': True},
        ],
        'tools': [
            'yara', 'clamav', 'maldet', 'rkhunter'
        ]
    },

    # ===== KRİPTO ARAŞTIRMA =====
    'crypto_investigation': {
        'apis': [
            {'name': 'Blockchain.com', 'url': 'https://blockchain.info/rawaddr/{target}', 'free': True},
            {'name': 'BlockCypher', 'url': 'https://api.blockcypher.com/v1/btc/main/addrs/{target}', 'free': True},
            {'name': 'Etherscan', 'url': 'https://api.etherscan.io/api', 'requires_key': True},
            {'name': 'Chainalysis', 'url': 'https://api.chainalysis.com/', 'requires_key': True},
            {'name': 'CoinGecko', 'url': 'https://api.coingecko.com/api/v3/', 'free': True},
            {'name': 'CryptoCompare', 'url': 'https://min-api.cryptocompare.com/', 'free': True},
            {'name': 'Whale Alert', 'url': 'https://api.whale-alert.io/v1/', 'requires_key': True},
        ],
        'tools': [
            'bitcoin-cli', 'geth'
        ]
    },

    # ===== GÖRSEL ANALİZ =====
    'image_investigation': {
        'apis': [
            {'name': 'Google Vision', 'url': 'https://vision.googleapis.com/v1/images:annotate', 'requires_key': True},
            {'name': 'TinEye', 'url': 'https://api.tineye.com/rest/search/', 'requires_key': True},
            {'name': 'Pimeyes', 'url': 'https://pimeyes.com/api/', 'requires_key': True},
            {'name': 'FaceCheck', 'url': 'https://facecheck.id/api/', 'requires_key': True},
            {'name': 'Yandex Images', 'url': 'https://yandex.com/images/search', 'scrape': True},
            {'name': 'Bing Visual Search', 'url': 'https://api.bing.microsoft.com/v7.0/images/visualsearch', 'requires_key': True},
            {'name': 'Clarifai', 'url': 'https://api.clarifai.com/v2/', 'requires_key': True},
        ],
        'tools': [
            'exiftool', 'feh', 'imagemagick'
        ]
    },

    # ===== DARK WEB =====
    'darkweb_investigation': {
        'apis': [
            {'name': 'OnionScan', 'url': 'local', 'local': True},
            {'name': 'Ahmia', 'url': 'https://ahmia.fi/search/', 'free': True},
            {'name': 'DarkSearch', 'url': 'https://darksearch.io/api/search', 'requires_key': True},
            {'name': 'Intelligence X', 'url': 'https://2.intelx.io/', 'requires_key': True},
            {'name': 'Hunchly', 'url': 'local', 'local': True},
        ],
        'tools': [
            'tor', 'torsocks', 'onionscan'
        ]
    },

    # ===== GENEL ARAŞTIRMA =====
    'general_investigation': {
        'apis': [
            {'name': 'Google Custom Search', 'url': 'https://www.googleapis.com/customsearch/v1', 'requires_key': True},
            {'name': 'Bing Search', 'url': 'https://api.bing.microsoft.com/v7.0/search', 'requires_key': True},
            {'name': 'DuckDuckGo', 'url': 'https://api.duckduckgo.com/', 'free': True},
            {'name': 'Archive.org', 'url': 'https://archive.org/wayback/available', 'free': True},
            {'name': 'CommonCrawl', 'url': 'https://index.commoncrawl.org/', 'free': True},
        ],
        'tools': [
            'googler', 'ddgr', 'buster'
        ]
    }
}

# ==================== OSINT ORCHESTRATOR ====================

class OSINTOrchestrator:
    """
    OSINT Orkestratör - Tüm araçları yöneten ana sınıf
    Türkçe doğal dil desteği ile otomatik araç seçimi ve çalıştırma
    """

    def __init__(self, stealth_config: StealthConfig = None):
        self.stealth = stealth_config or StealthConfig()
        self.session = None
        self.results_cache = {}
        self.api_keys = {}
        self._load_api_keys()

    def _load_api_keys(self):
        """API anahtarlarını yükle"""
        try:
            # Vault'tan yükle
            from dalga_vault import Vault
            vault = Vault()

            key_mappings = {
                'SHODAN_API_KEY': 'shodan',
                'VIRUSTOTAL_API_KEY': 'virustotal',
                'HUNTER_API_KEY': 'hunter',
                'ABUSEIPDB_API_KEY': 'abuseipdb',
                'SECURITYTRAILS_API_KEY': 'securitytrails',
                'HIBP_API_KEY': 'haveibeenpwned',
                'IPINFO_API_KEY': 'ipinfo',
                'CENSYS_API_KEY': 'censys',
            }

            for env_key, api_name in key_mappings.items():
                key = vault.get(env_key)
                if key:
                    self.api_keys[api_name] = key

        except Exception as e:
            print(f"[OSINTOrchestrator] API key yükleme hatası: {e}")

    async def _get_session(self) -> aiohttp.ClientSession:
        """Gizli HTTP oturumu oluştur"""
        if self.session is None or self.session.closed:
            # SSL ayarları
            ssl_context = ssl.create_default_context()

            # Connector
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=50,
                ttl_dns_cache=300
            )

            # Varsayılan headers
            headers = self._get_stealth_headers()

            self.session = aiohttp.ClientSession(
                connector=connector,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30)
            )

        return self.session

    def _get_stealth_headers(self) -> Dict[str, str]:
        """Gizlilik başlıkları oluştur"""
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,tr;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        }

        if self.stealth.rotate_user_agent:
            headers['User-Agent'] = random.choice(USER_AGENTS)
        else:
            headers['User-Agent'] = USER_AGENTS[0]

        return headers

    async def _stealth_delay(self):
        """Gizlilik için rastgele gecikme"""
        if self.stealth.random_delays:
            delay = random.uniform(self.stealth.min_delay, self.stealth.max_delay)
            await asyncio.sleep(delay)

    def analyze_query(self, query: str) -> Dict[str, Any]:
        """
        Türkçe sorguyu analiz et ve araştırma tipini belirle
        """
        query_lower = query.lower()

        # Araştırma tipini belirle
        investigation_type = 'general_investigation'
        confidence = 0.0

        for pattern, inv_type in TURKISH_PATTERNS.items():
            if re.search(pattern, query_lower):
                investigation_type = inv_type
                confidence = 0.8
                break

        # Hedefleri çıkar
        targets = []
        target_types = []

        for target_type, pattern in TARGET_PATTERNS.items():
            matches = re.findall(pattern, query)
            for match in matches:
                if match not in targets:
                    targets.append(match)
                    target_types.append(target_type)

                    # Hedef tipine göre araştırma tipini güncelle
                    if target_type == 'ip':
                        investigation_type = 'ip_investigation'
                        confidence = 0.95
                    elif target_type == 'domain':
                        investigation_type = 'domain_investigation'
                        confidence = 0.95
                    elif target_type == 'email':
                        investigation_type = 'email_investigation'
                        confidence = 0.95
                    elif target_type == 'phone':
                        investigation_type = 'phone_investigation'
                        confidence = 0.95

        return {
            'original_query': query,
            'investigation_type': investigation_type,
            'targets': targets,
            'target_types': target_types,
            'confidence': confidence,
            'tools': OSINT_TOOLS.get(investigation_type, {})
        }

    async def investigate(self, query: str) -> Dict[str, Any]:
        """
        Ana araştırma fonksiyonu - Türkçe sorgu al, tüm araçları çalıştır
        """
        start_time = time.time()

        # Sorguyu analiz et
        analysis = self.analyze_query(query)

        if not analysis['targets']:
            # Hedef bulunamadıysa, sorgunun kendisini hedef olarak kullan
            words = query.split()
            potential_targets = [w for w in words if len(w) > 3 and not w.lower() in ['ara', 'bul', 'tara', 'analiz', 'et', 'yap', 'kim', 'nerede', 'bilgi']]
            if potential_targets:
                analysis['targets'] = potential_targets[:1]

        results = {
            'query': query,
            'analysis': analysis,
            'timestamp': datetime.now().isoformat(),
            'stealth_level': self.stealth.level.name,
            'sources': {},
            'summary': {},
            'raw_data': {},
            'errors': [],
            'execution_time': 0
        }

        if not analysis['targets']:
            results['errors'].append('Hedef bulunamadı. Lütfen IP, domain, email veya kullanıcı adı belirtin.')
            return results

        target = analysis['targets'][0]
        inv_type = analysis['investigation_type']
        tools_config = analysis['tools']

        # API'leri paralel çalıştır
        tasks = []
        for api_config in tools_config.get('apis', []):
            if api_config.get('requires_key') and api_config['name'].lower() not in self.api_keys:
                continue
            if api_config.get('scrape'):
                continue  # Scrape işlemlerini şimdilik atla
            if api_config.get('local'):
                continue  # Lokal araçları şimdilik atla

            tasks.append(self._query_api(api_config, target))

        # Tüm API'leri çalıştır
        if tasks:
            api_results = await asyncio.gather(*tasks, return_exceptions=True)

            for api_config, result in zip(tools_config.get('apis', []), api_results):
                if isinstance(result, Exception):
                    results['errors'].append(f"{api_config['name']}: {str(result)}")
                elif result:
                    results['sources'][api_config['name']] = result
                    results['raw_data'][api_config['name']] = result

        # Lokal araçları çalıştır (varsa)
        for tool in tools_config.get('tools', [])[:3]:  # İlk 3 araç
            try:
                tool_result = await self._run_local_tool(tool, target, inv_type)
                if tool_result:
                    results['sources'][f'tool_{tool}'] = tool_result
            except Exception as e:
                results['errors'].append(f"{tool}: {str(e)}")

        # Özet oluştur
        results['summary'] = self._create_summary(results, target, inv_type)
        results['execution_time'] = time.time() - start_time

        return results

    async def _query_api(self, api_config: Dict, target: str) -> Optional[Dict]:
        """API'yi sorgula"""
        await self._stealth_delay()

        try:
            session = await self._get_session()

            url = api_config['url'].format(target=target, api_key=self.api_keys.get(api_config['name'].lower(), ''))

            headers = self._get_stealth_headers()

            # API-specific headers
            if api_config['name'] == 'AbuseIPDB':
                headers['Key'] = self.api_keys.get('abuseipdb', '')
                headers['Accept'] = 'application/json'
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={target}&maxAgeInDays=90"
            elif api_config['name'] == 'VirusTotal':
                headers['x-apikey'] = self.api_keys.get('virustotal', '')
            elif api_config['name'] == 'Shodan':
                if 'shodan' in self.api_keys:
                    url = f"{url}?key={self.api_keys['shodan']}"

            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                if response.status == 200:
                    try:
                        data = await response.json()
                        return {
                            'success': True,
                            'source': api_config['name'],
                            'data': data
                        }
                    except:
                        text = await response.text()
                        return {
                            'success': True,
                            'source': api_config['name'],
                            'data': text[:1000]
                        }
                else:
                    return None

        except asyncio.TimeoutError:
            return None
        except Exception as e:
            return None

    async def _run_local_tool(self, tool: str, target: str, inv_type: str) -> Optional[Dict]:
        """Lokal OSINT aracını çalıştır - dalga_osint_tools_runner entegrasyonu"""
        try:
            # Tool runner'ı import et
            from dalga_osint_tools_runner import get_runner, ToolStatus

            runner = get_runner()

            # Araç tipine göre çalıştır
            if tool == 'sherlock' and inv_type == 'username_investigation':
                result = await runner.run_sherlock(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:3000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'maigret' and inv_type == 'username_investigation':
                result = await runner.run_maigret(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:3000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'holehe' and inv_type == 'email_investigation':
                result = await runner.run_holehe(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:2000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'theHarvester' and inv_type == 'domain_investigation':
                result = await runner.run_theharvester(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:3000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'dnsrecon' and inv_type == 'domain_investigation':
                result = await runner.run_dnsrecon(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:2000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'whois':
                result = await runner.run_whois(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:2000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'dig':
                result = await runner.run_dig(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output,
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'nmap' and inv_type == 'ip_investigation':
                result = await runner.run_nmap(target, ports="22,80,443,8080,8443")
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:3000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            elif tool == 'sublist3r' and inv_type == 'domain_investigation':
                result = await runner.run_sublist3r(target)
                if result.status == ToolStatus.COMPLETED:
                    return {
                        'success': True,
                        'tool': tool,
                        'output': result.output[:2000],
                        'data': result.data,
                        'execution_time': result.execution_time
                    }

            # Fallback: basit subprocess çağrısı
            elif tool == 'host':
                proc = await asyncio.create_subprocess_exec(
                    'host', target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if stdout:
                    return {'success': True, 'tool': tool, 'output': stdout.decode('utf-8', errors='ignore')}

            elif tool == 'nslookup':
                proc = await asyncio.create_subprocess_exec(
                    'nslookup', target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
                if stdout:
                    return {'success': True, 'tool': tool, 'output': stdout.decode('utf-8', errors='ignore')}

            elif tool == 'traceroute':
                proc = await asyncio.create_subprocess_exec(
                    'traceroute', '-m', '15', target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                if stdout:
                    return {'success': True, 'tool': tool, 'output': stdout.decode('utf-8', errors='ignore')}

        except ImportError:
            # Tool runner import edilemezse basit subprocess kullan
            pass
        except asyncio.TimeoutError:
            return None
        except FileNotFoundError:
            return None
        except Exception as e:
            return {'success': False, 'tool': tool, 'error': str(e)}

        return None

    def _create_summary(self, results: Dict, target: str, inv_type: str) -> Dict:
        """Sonuçlardan özet oluştur"""
        summary = {
            'target': target,
            'type': inv_type,
            'sources_queried': len(results['sources']),
            'successful_sources': len([s for s in results['sources'].values() if s and s.get('success')]),
        }

        # IP araştırması özeti
        if inv_type == 'ip_investigation':
            for source_name, source_data in results['sources'].items():
                if not source_data or not source_data.get('data'):
                    continue

                data = source_data['data']

                if isinstance(data, dict):
                    # Konum bilgisi
                    if 'country' in data:
                        summary['country'] = data.get('country')
                    if 'city' in data:
                        summary['city'] = data.get('city')
                    if 'org' in data:
                        summary['organization'] = data.get('org')
                    if 'isp' in data:
                        summary['isp'] = data.get('isp')
                    if 'as' in data:
                        summary['asn'] = data.get('as')

                    # Abuse bilgisi
                    if 'abuseConfidenceScore' in data:
                        summary['abuse_score'] = data.get('abuseConfidenceScore')

                    # Tehdit bilgisi
                    if 'classification' in data:
                        summary['classification'] = data.get('classification')
                    if 'malicious' in data:
                        summary['malicious'] = data.get('malicious')

        # Domain araştırması özeti
        elif inv_type == 'domain_investigation':
            for source_name, source_data in results['sources'].items():
                if not source_data or not source_data.get('data'):
                    continue

                data = source_data['data']

                if isinstance(data, dict):
                    if 'registrar' in data:
                        summary['registrar'] = data.get('registrar')
                    if 'creation_date' in data:
                        summary['creation_date'] = data.get('creation_date')
                    if 'name_servers' in data:
                        summary['name_servers'] = data.get('name_servers')

        # Email araştırması özeti
        elif inv_type == 'email_investigation':
            for source_name, source_data in results['sources'].items():
                if not source_data or not source_data.get('data'):
                    continue

                data = source_data['data']

                if isinstance(data, dict):
                    if 'reputation' in data:
                        summary['reputation'] = data.get('reputation')
                    if 'suspicious' in data:
                        summary['suspicious'] = data.get('suspicious')
                    if 'breaches' in data:
                        summary['breaches'] = len(data.get('breaches', []))

        return summary

    async def close(self):
        """Oturumu kapat"""
        if self.session and not self.session.closed:
            await self.session.close()


# ==================== GLOBAL INSTANCE ====================

_orchestrator_instance = None

def get_orchestrator() -> OSINTOrchestrator:
    """Global orchestrator instance"""
    global _orchestrator_instance
    if _orchestrator_instance is None:
        _orchestrator_instance = OSINTOrchestrator(StealthConfig(level=StealthLevel.PHANTOM))
    return _orchestrator_instance


async def investigate(query: str) -> Dict[str, Any]:
    """
    Ana araştırma fonksiyonu - Türkçe sorgu ile OSINT araştırması yap

    Örnek kullanım:
        result = await investigate("8.8.8.8 ip adresini araştır")
        result = await investigate("example.com domain bilgilerini bul")
        result = await investigate("test@example.com email sızıntı kontrolü")
    """
    orchestrator = get_orchestrator()
    return await orchestrator.investigate(query)


# ==================== TEST ====================

if __name__ == '__main__':
    async def test():
        print("OSINT Orchestrator Test")
        print("=" * 50)

        queries = [
            "8.8.8.8 ip adresini araştır",
            "google.com domain bilgilerini bul",
        ]

        for query in queries:
            print(f"\nSorgu: {query}")
            result = await investigate(query)
            print(f"Analiz: {result['analysis']['investigation_type']}")
            print(f"Hedefler: {result['analysis']['targets']}")
            print(f"Kaynaklar: {list(result['sources'].keys())}")
            print(f"Özet: {result['summary']}")
            print(f"Süre: {result['execution_time']:.2f}s")

    asyncio.run(test())
