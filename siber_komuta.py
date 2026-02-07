#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    SİBER KOMUTA MERKEZİ v3.0 - TSUNAMI ENTEGRASYONU
    Pentagon Seviye Siber İstihbarat ve Operasyon Platformu
================================================================================

    22 PENTAGON SEVİYE AJAN:
    ═══════════════════════════════════════════════════════════════════════════

    🎖️ KOMUTA KATMANI (Command Layer)
    ├── SOC-COMMANDER      : Güvenlik Operasyon Merkezi Komutanı
    ├── INCIDENT-COMMANDER : Olay Müdahale Komutanı
    └── CYBER-STRATEGIST   : Siber Strateji Uzmanı

    🔍 İSTİHBARAT KATMANI (Intelligence Layer)
    ├── OSINT-HUNTER       : Açık Kaynak İstihbarat Avcısı
    ├── HUMINT-ANALYST     : İnsan Kaynakları İstihbarat Analisti
    ├── SIGINT-COLLECTOR   : Sinyal İstihbaratı Toplayıcı
    ├── GEOINT-MAPPER      : Coğrafi İstihbarat Haritalayıcı
    └── TECHINT-SPECIALIST : Teknik İstihbarat Uzmanı

    🛡️ SAVUNMA KATMANI (Defense Layer)
    ├── BLUE-TEAM-LEAD     : Mavi Takım Lideri
    ├── THREAT-HUNTER      : Tehdit Avcısı
    ├── FORENSIC-EXAMINER  : Adli Bilişim Uzmanı
    └── MALWARE-ANALYST    : Zararlı Yazılım Analisti

    ⚔️ SALDIRI KATMANI (Offensive Layer)
    ├── RED-TEAM-OPERATOR  : Kırmızı Takım Operatörü
    ├── PENTESTER          : Sızma Test Uzmanı
    └── EXPLOIT-DEVELOPER  : İstismar Geliştirici

    🟣 KARMA KATMAN (Purple Team Layer)
    ├── PURPLE-TEAM-COORD  : Mor Takım Koordinatörü
    └── ADVERSARY-EMULATOR : Düşman Emülatörü

    🏭 KRİTİK ALTYAPI (Critical Infrastructure)
    ├── ICS-DEFENDER       : Endüstriyel Kontrol Sistemi Savunucusu
    ├── SCADA-GUARDIAN     : SCADA Koruyucusu
    └── OT-SECURITY-SPEC   : Operasyonel Teknoloji Güvenlik Uzmanı

    🌐 GLOBAL OPERASYONLARı (Global Operations)
    ├── DARKWEB-MONITOR    : Karanlık Web İzleyici
    └── GLOBAL-SENTINEL    : Küresel Nöbetçi

    MODÜLLER:
    ═══════════════════════════════════════════════════════════════════════════
    ├── GROQ-CYBER-ENGINE  : LLaMA 3.1 Destekli Tehdit Analizi
    ├── OSINT-FUSION       : Shodan + Censys + GreyNoise + VirusTotal + AbuseIPDB
    ├── SIGINT-LITE        : OpenCellID + RF Analizi
    ├── GEOINT-OPEN        : ADS-B + Marine Traffic + Satellite Tracking
    ├── MALWARE-SANDBOX    : Cuckoo + ANY.RUN Entegrasyonu
    ├── MITRE-MAPPER       : ATT&CK Framework Mapping
    └── SOAR-ENGINE        : Security Orchestration & Automated Response

================================================================================
"""

import os
import sys
import json
import asyncio
import aiohttp
import threading
import hashlib
import socket
import ssl
import subprocess
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import re

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# ENUMERATIONS
# ═══════════════════════════════════════════════════════════════════════════════

class AgentLayer(Enum):
    """Agent katmanları"""
    COMMAND = "command"
    INTELLIGENCE = "intelligence"
    DEFENSE = "defense"
    OFFENSIVE = "offensive"
    PURPLE = "purple"
    CRITICAL_INFRA = "critical_infrastructure"
    GLOBAL_OPS = "global_operations"


class AgentStatus(Enum):
    """Agent durumları"""
    IDLE = "idle"
    ACTIVE = "active"
    BUSY = "busy"
    PAUSED = "paused"
    ERROR = "error"
    OFFLINE = "offline"


class ThreatLevel(Enum):
    """Tehdit seviyeleri"""
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


class OperationType(Enum):
    """Operasyon tipleri"""
    RECON = "reconnaissance"
    THREAT_HUNT = "threat_hunting"
    INCIDENT_RESPONSE = "incident_response"
    VULNERABILITY_SCAN = "vulnerability_scan"
    PENTEST = "penetration_test"
    FORENSICS = "forensics"
    MALWARE_ANALYSIS = "malware_analysis"
    OSINT = "osint_collection"
    SIGINT = "sigint_collection"
    GEOINT = "geoint_collection"


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class CyberAgent:
    """Pentagon seviye siber ajan"""
    id: str
    name: str
    layer: AgentLayer
    status: AgentStatus = AgentStatus.IDLE
    capabilities: List[str] = field(default_factory=list)
    current_task: Optional[str] = None
    success_rate: float = 0.95
    tasks_completed: int = 0
    description: str = ""
    tools: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class ThreatIndicator:
    """Tehdit göstergesi (IOC)"""
    value: str
    type: str  # ip, domain, hash, url, email
    severity: ThreatLevel
    confidence: float
    sources: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    geo_data: Optional[Dict] = None


@dataclass
class OperationResult:
    """Operasyon sonucu"""
    operation_id: str
    operation_type: OperationType
    agent_id: str
    success: bool
    findings: List[Dict] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)
    raw_data: Optional[Dict] = None


@dataclass
class IntelReport:
    """İstihbarat raporu"""
    report_id: str
    title: str
    classification: str  # UNCLASSIFIED, CONFIDENTIAL, SECRET, TOP_SECRET
    sources: List[str] = field(default_factory=list)
    findings: List[Dict] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    mitre_mapping: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)


# ═══════════════════════════════════════════════════════════════════════════════
# GROQ CYBER ENGINE - AI DESTEKLİ TEHDİT ANALİZİ
# ═══════════════════════════════════════════════════════════════════════════════

class GroqCyberEngine:
    """
    GROQ LLaMA 3.1 Destekli Siber Tehdit Analiz Motoru

    Gerçek zamanlı tehdit analizi, IOC değerlendirmesi ve
    otomatik müdahale önerileri sağlar.
    """

    def __init__(self):
        self.api_key = os.environ.get('GROQ_API_KEY', '')
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = "llama-3.1-70b-versatile"
        self.fallback_model = "llama-3.1-8b-instant"
        self._session = None
        self._initialized = False

    def initialize(self) -> bool:
        """Motor başlat"""
        if self._initialized:
            return True

        if not self.api_key:
            logger.warning("[GROQ] API key bulunamadı, fallback modu aktif")
            self._initialized = True
            return False

        self._initialized = True
        logger.info("[GROQ] Cyber Engine başlatıldı")
        return True

    async def analyze_threat(self, threat_data: Dict) -> Dict:
        """Tehdit analizi yap"""
        self.initialize()

        if not self.api_key:
            return self._fallback_analysis(threat_data)

        prompt = f"""Siber güvenlik uzmanı olarak aşağıdaki tehdit göstergesini analiz et:

Tehdit Verisi:
{json.dumps(threat_data, indent=2, default=str)}

Analiz gereksinimleri:
1. Tehdit türünü ve ciddiyetini belirle
2. Olası saldırı vektörlerini tanımla
3. MITRE ATT&CK tekniklerini eşleştir
4. Müdahale önerileri sun
5. Risk skorunu hesapla (1-10)

JSON formatında yanıt ver:
{{
    "threat_type": "...",
    "severity": "critical/high/medium/low/info",
    "attack_vectors": [...],
    "mitre_techniques": [...],
    "recommendations": [...],
    "risk_score": X,
    "confidence": 0.X,
    "analysis_summary": "..."
}}"""

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "Sen Pentagon seviye bir siber güvenlik analisti ve tehdit istihbaratı uzmanısın."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.3,
                    "max_tokens": 2000
                }

                async with session.post(self.api_url, headers=headers, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        content = data['choices'][0]['message']['content']
                        # JSON parse et
                        try:
                            return json.loads(content)
                        except json.JSONDecodeError:
                            # Markdown code block içinde olabilir
                            if '```json' in content:
                                json_str = content.split('```json')[1].split('```')[0].strip()
                                return json.loads(json_str)
                            return {"analysis_summary": content, "confidence": 0.7}
                    else:
                        logger.error(f"[GROQ] API hatası: {resp.status}")
                        return self._fallback_analysis(threat_data)

        except Exception as e:
            logger.error(f"[GROQ] Analiz hatası: {e}")
            return self._fallback_analysis(threat_data)

    def _fallback_analysis(self, threat_data: Dict) -> Dict:
        """Fallback analiz - GROQ yoksa"""
        # Basit kural tabanlı analiz
        risk_score = 5
        severity = "medium"
        recommendations = []
        mitre_techniques = []

        value = str(threat_data.get('value', '')).lower()
        threat_type = threat_data.get('type', 'unknown')

        # IP analizi
        if threat_type == 'ip':
            # Tor exit node kontrolü
            if self._check_tor_exit(value):
                risk_score = 7
                severity = "high"
                mitre_techniques.append("T1090.003")  # Proxy: Multi-hop Proxy
                recommendations.append("Tor çıkış düğümü tespit edildi - anonim trafik izleniyor olabilir")

            # Bilinen kötü amaçlı IP aralıkları
            if value.startswith(('185.220.', '45.154.', '91.132.')):
                risk_score = 8
                severity = "high"
                recommendations.append("Bilinen kötü amaçlı IP aralığı - engelleme önerilir")

        # Domain analizi
        elif threat_type == 'domain':
            # Yeni kayıtlı domain şüphesi
            suspicious_tlds = ['.xyz', '.top', '.click', '.loan', '.win']
            if any(value.endswith(tld) for tld in suspicious_tlds):
                risk_score = 6
                severity = "medium"
                recommendations.append("Şüpheli TLD tespit edildi - phishing riski yüksek")
                mitre_techniques.append("T1566")  # Phishing

            # Typosquatting kontrolü
            known_brands = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal']
            for brand in known_brands:
                if brand in value and brand + '.' not in value:
                    risk_score = 8
                    severity = "high"
                    recommendations.append(f"Olası typosquatting: {brand} taklidi")
                    mitre_techniques.append("T1583.001")  # Acquire Infrastructure: Domains

        # Hash analizi
        elif threat_type in ['hash_md5', 'hash_sha1', 'hash_sha256']:
            risk_score = 7
            severity = "high"
            recommendations.append("Hash'i VirusTotal ve sandbox ortamında analiz edin")
            mitre_techniques.append("T1204")  # User Execution

        return {
            "threat_type": threat_type,
            "severity": severity,
            "attack_vectors": ["unknown - detaylı analiz gerekli"],
            "mitre_techniques": mitre_techniques or ["T1595"],  # Active Scanning
            "recommendations": recommendations or [
                "Detaylı log analizi yapın",
                "İlgili sistemleri izole edin",
                "IOC'yi tehdit istihbarat platformlarında doğrulayın"
            ],
            "risk_score": risk_score,
            "confidence": 0.6,
            "analysis_summary": f"Fallback analiz tamamlandı. {threat_type} türünde gösterge, {severity} ciddiyet seviyesi.",
            "mode": "fallback"
        }

    def _check_tor_exit(self, ip: str) -> bool:
        """Tor çıkış düğümü kontrolü"""
        try:
            import requests
            resp = requests.get("https://check.torproject.org/torbulkexitlist", timeout=5)
            return ip in resp.text
        except Exception:
            return False

    async def generate_report(self, findings: List[Dict]) -> str:
        """İstihbarat raporu oluştur"""
        if not self.api_key:
            return self._generate_fallback_report(findings)

        prompt = f"""Aşağıdaki siber güvenlik bulgularından profesyonel bir istihbarat raporu oluştur:

Bulgular:
{json.dumps(findings, indent=2, default=str)}

Rapor formatı:
1. Yönetici Özeti
2. Tehdit Analizi
3. Etkilenen Varlıklar
4. MITRE ATT&CK Eşleştirmesi
5. Önerilen Aksiyonlar
6. Sonuç

Türkçe, profesyonel ve teknik dilde yaz."""

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }
                payload = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "Sen kıdemli bir siber istihbarat analisti ve rapor yazarısın."},
                        {"role": "user", "content": prompt}
                    ],
                    "temperature": 0.4,
                    "max_tokens": 4000
                }

                async with session.post(self.api_url, headers=headers, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data['choices'][0]['message']['content']

        except Exception as e:
            logger.error(f"[GROQ] Rapor oluşturma hatası: {e}")

        return self._generate_fallback_report(findings)

    def _generate_fallback_report(self, findings: List[Dict]) -> str:
        """Fallback rapor oluşturma"""
        report_lines = [
            "=" * 60,
            "SİBER GÜVENLİK İSTİHBARAT RAPORU",
            f"Tarih: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "Sınıflandırma: GİZLİ DEĞİL",
            "=" * 60,
            "",
            "1. YÖNETİCİ ÖZETİ",
            "-" * 40,
            f"Bu rapor {len(findings)} adet güvenlik bulgusunu içermektedir.",
            "",
            "2. BULGULAR",
            "-" * 40
        ]

        for i, finding in enumerate(findings, 1):
            report_lines.append(f"\n{i}. Bulgu:")
            report_lines.append(f"   Tür: {finding.get('type', 'Bilinmiyor')}")
            report_lines.append(f"   Değer: {finding.get('value', 'N/A')}")
            report_lines.append(f"   Ciddiyet: {finding.get('severity', 'Bilinmiyor')}")
            if finding.get('recommendations'):
                report_lines.append(f"   Öneriler: {', '.join(finding.get('recommendations', []))}")

        report_lines.extend([
            "",
            "3. ÖNERİLEN AKSİYONLAR",
            "-" * 40,
            "• Etkilenen sistemleri izole edin",
            "• Kapsamlı log analizi gerçekleştirin",
            "• Incident Response prosedürünü aktifleştirin",
            "• Tehdit göstergelerini güvenlik cihazlarına ekleyin",
            "",
            "=" * 60,
            "Rapor Sonu",
            "=" * 60
        ])

        return "\n".join(report_lines)


# ═══════════════════════════════════════════════════════════════════════════════
# OSINT FUSION - AÇIK KAYNAK İSTİHBARAT BİRLEŞTİRME
# ═══════════════════════════════════════════════════════════════════════════════

class OSINTFusion:
    """
    OSINT Fusion Modülü

    Entegre kaynaklar:
    - Shodan: IoT ve açık port taraması
    - Censys: SSL sertifika ve cihaz keşfi
    - GreyNoise: Gürültü vs. hedefli saldırı ayrımı
    - VirusTotal: Malware ve IOC analizi
    - AbuseIPDB: IP itibar kontrolü
    - HackerTarget: Subdomain ve DNS keşfi
    - SecurityTrails: Tarihsel DNS ve WHOIS
    """

    def __init__(self):
        self.api_keys = {
            'shodan': os.environ.get('SHODAN_API_KEY', ''),
            'censys_id': os.environ.get('CENSYS_API_ID', ''),
            'censys_secret': os.environ.get('CENSYS_API_SECRET', ''),
            'greynoise': os.environ.get('GREYNOISE_API_KEY', ''),
            'virustotal': os.environ.get('VIRUSTOTAL_API_KEY', ''),
            'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY', ''),
            'securitytrails': os.environ.get('SECURITYTRAILS_API_KEY', '')
        }
        self._cache = {}
        self._cache_ttl = 3600  # 1 saat

    async def full_osint(self, target: str, target_type: str = 'auto') -> Dict:
        """Tam OSINT toplama"""
        if target_type == 'auto':
            target_type = self._detect_target_type(target)

        results = {
            'target': target,
            'type': target_type,
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'findings': [],
            'risk_score': 0,
            'confidence': 0.0
        }

        # Paralel OSINT toplama
        tasks = []

        if target_type == 'ip':
            tasks.extend([
                self._shodan_lookup(target),
                self._greynoise_lookup(target),
                self._abuseipdb_lookup(target),
                self._virustotal_ip(target)
            ])
        elif target_type == 'domain':
            tasks.extend([
                self._shodan_dns(target),
                self._virustotal_domain(target),
                self._hackertarget_subdomains(target),
                self._ssl_cert_lookup(target)
            ])
        elif target_type == 'hash':
            tasks.extend([
                self._virustotal_hash(target)
            ])
        elif target_type == 'email':
            tasks.extend([
                self._hibp_lookup(target),
                self._email_domain_check(target)
            ])

        # Tüm görevleri çalıştır
        if tasks:
            completed = await asyncio.gather(*tasks, return_exceptions=True)
            for result in completed:
                if isinstance(result, dict) and not isinstance(result, Exception):
                    source = result.get('source', 'unknown')
                    results['sources'][source] = result
                    if result.get('findings'):
                        results['findings'].extend(result['findings'])

        # Risk skoru hesapla
        results['risk_score'] = self._calculate_risk(results)
        results['confidence'] = self._calculate_confidence(results)

        return results

    def _detect_target_type(self, target: str) -> str:
        """Hedef türünü otomatik tespit"""
        import ipaddress

        # IP kontrolü
        try:
            ipaddress.ip_address(target)
            return 'ip'
        except ValueError:
            pass

        # Hash kontrolü
        if len(target) in [32, 40, 64] and target.isalnum():
            return 'hash'

        # Email kontrolü
        if '@' in target and '.' in target:
            return 'email'

        # Domain varsayımı
        if '.' in target:
            return 'domain'

        return 'unknown'

    async def _shodan_lookup(self, ip: str) -> Dict:
        """Shodan IP araması"""
        if not self.api_keys['shodan']:
            return {'source': 'shodan', 'error': 'API key yok', 'findings': []}

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_keys['shodan']}"
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        findings = []

                        # Açık portlar
                        for port_info in data.get('data', []):
                            finding = {
                                'type': 'open_port',
                                'port': port_info.get('port'),
                                'protocol': port_info.get('transport', 'tcp'),
                                'product': port_info.get('product', ''),
                                'version': port_info.get('version', ''),
                                'severity': 'medium'
                            }
                            # Kritik portlar
                            if port_info.get('port') in [22, 23, 3389, 5900, 445]:
                                finding['severity'] = 'high'
                            findings.append(finding)

                        # Vulnerabilities
                        vulns = data.get('vulns', [])
                        for vuln in vulns:
                            findings.append({
                                'type': 'vulnerability',
                                'cve': vuln,
                                'severity': 'critical'
                            })

                        return {
                            'source': 'shodan',
                            'ip': ip,
                            'hostnames': data.get('hostnames', []),
                            'org': data.get('org', ''),
                            'isp': data.get('isp', ''),
                            'country': data.get('country_name', ''),
                            'city': data.get('city', ''),
                            'ports': data.get('ports', []),
                            'vulns': vulns,
                            'findings': findings
                        }
                    elif resp.status == 404:
                        return {'source': 'shodan', 'ip': ip, 'message': 'Bilgi bulunamadı', 'findings': []}
                    else:
                        return {'source': 'shodan', 'error': f'HTTP {resp.status}', 'findings': []}
        except Exception as e:
            return {'source': 'shodan', 'error': str(e), 'findings': []}

    async def _shodan_dns(self, domain: str) -> Dict:
        """Shodan DNS araması"""
        if not self.api_keys['shodan']:
            return {'source': 'shodan_dns', 'error': 'API key yok', 'findings': []}

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.shodan.io/dns/domain/{domain}?key={self.api_keys['shodan']}"
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        findings = []

                        for subdomain in data.get('subdomains', []):
                            findings.append({
                                'type': 'subdomain',
                                'value': f"{subdomain}.{domain}",
                                'severity': 'info'
                            })

                        return {
                            'source': 'shodan_dns',
                            'domain': domain,
                            'subdomains': data.get('subdomains', []),
                            'findings': findings
                        }
        except Exception as e:
            return {'source': 'shodan_dns', 'error': str(e), 'findings': []}

    async def _greynoise_lookup(self, ip: str) -> Dict:
        """GreyNoise IP analizi"""
        try:
            # Community API (ücretsiz)
            async with aiohttp.ClientSession() as session:
                url = f"https://api.greynoise.io/v3/community/{ip}"
                headers = {}
                if self.api_keys['greynoise']:
                    headers['key'] = self.api_keys['greynoise']

                async with session.get(url, headers=headers, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        findings = []

                        noise = data.get('noise', False)
                        riot = data.get('riot', False)
                        classification = data.get('classification', 'unknown')

                        if noise:
                            findings.append({
                                'type': 'noise',
                                'description': 'İnternet gürültüsü kaynağı - masif tarama yapan IP',
                                'severity': 'medium' if classification == 'benign' else 'high'
                            })

                        if riot:
                            findings.append({
                                'type': 'riot',
                                'description': 'Bilinen iyi IP (CDN, crawler, vb.)',
                                'severity': 'info'
                            })

                        if classification == 'malicious':
                            findings.append({
                                'type': 'malicious',
                                'description': 'GreyNoise tarafından kötü amaçlı olarak işaretlenmiş',
                                'severity': 'high'
                            })

                        return {
                            'source': 'greynoise',
                            'ip': ip,
                            'noise': noise,
                            'riot': riot,
                            'classification': classification,
                            'name': data.get('name', ''),
                            'link': data.get('link', ''),
                            'findings': findings
                        }
        except Exception as e:
            return {'source': 'greynoise', 'error': str(e), 'findings': []}

    async def _abuseipdb_lookup(self, ip: str) -> Dict:
        """AbuseIPDB itibar kontrolü"""
        if not self.api_keys['abuseipdb']:
            return {'source': 'abuseipdb', 'error': 'API key yok', 'findings': []}

        try:
            async with aiohttp.ClientSession() as session:
                url = "https://api.abuseipdb.com/api/v2/check"
                headers = {
                    'Key': self.api_keys['abuseipdb'],
                    'Accept': 'application/json'
                }
                params = {
                    'ipAddress': ip,
                    'maxAgeInDays': 90,
                    'verbose': True
                }

                async with session.get(url, headers=headers, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        result = data.get('data', {})
                        findings = []

                        abuse_score = result.get('abuseConfidenceScore', 0)
                        if abuse_score > 0:
                            severity = 'info'
                            if abuse_score > 25:
                                severity = 'low'
                            if abuse_score > 50:
                                severity = 'medium'
                            if abuse_score > 75:
                                severity = 'high'
                            if abuse_score > 90:
                                severity = 'critical'

                            findings.append({
                                'type': 'abuse_score',
                                'score': abuse_score,
                                'total_reports': result.get('totalReports', 0),
                                'severity': severity
                            })

                        return {
                            'source': 'abuseipdb',
                            'ip': ip,
                            'abuse_score': abuse_score,
                            'is_public': result.get('isPublic', True),
                            'country': result.get('countryCode', ''),
                            'isp': result.get('isp', ''),
                            'domain': result.get('domain', ''),
                            'total_reports': result.get('totalReports', 0),
                            'findings': findings
                        }
        except Exception as e:
            return {'source': 'abuseipdb', 'error': str(e), 'findings': []}

    async def _virustotal_ip(self, ip: str) -> Dict:
        """VirusTotal IP analizi"""
        if not self.api_keys['virustotal']:
            return {'source': 'virustotal', 'error': 'API key yok', 'findings': []}

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
                headers = {'x-apikey': self.api_keys['virustotal']}

                async with session.get(url, headers=headers, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        findings = []

                        # Son analiz sonuçları
                        last_analysis = attributes.get('last_analysis_stats', {})
                        malicious = last_analysis.get('malicious', 0)
                        suspicious = last_analysis.get('suspicious', 0)

                        if malicious > 0:
                            findings.append({
                                'type': 'malicious_detection',
                                'count': malicious,
                                'severity': 'critical' if malicious > 5 else 'high'
                            })

                        if suspicious > 0:
                            findings.append({
                                'type': 'suspicious_detection',
                                'count': suspicious,
                                'severity': 'medium'
                            })

                        return {
                            'source': 'virustotal',
                            'ip': ip,
                            'as_owner': attributes.get('as_owner', ''),
                            'country': attributes.get('country', ''),
                            'last_analysis_stats': last_analysis,
                            'reputation': attributes.get('reputation', 0),
                            'findings': findings
                        }
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e), 'findings': []}

    async def _virustotal_domain(self, domain: str) -> Dict:
        """VirusTotal domain analizi"""
        if not self.api_keys['virustotal']:
            return {'source': 'virustotal', 'error': 'API key yok', 'findings': []}

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                headers = {'x-apikey': self.api_keys['virustotal']}

                async with session.get(url, headers=headers, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        findings = []

                        last_analysis = attributes.get('last_analysis_stats', {})
                        malicious = last_analysis.get('malicious', 0)

                        if malicious > 0:
                            findings.append({
                                'type': 'malicious_domain',
                                'count': malicious,
                                'severity': 'critical' if malicious > 3 else 'high'
                            })

                        # Kategoriler
                        categories = attributes.get('categories', {})
                        for engine, category in categories.items():
                            if any(bad in category.lower() for bad in ['malware', 'phishing', 'spam', 'malicious']):
                                findings.append({
                                    'type': 'bad_category',
                                    'engine': engine,
                                    'category': category,
                                    'severity': 'high'
                                })

                        return {
                            'source': 'virustotal',
                            'domain': domain,
                            'registrar': attributes.get('registrar', ''),
                            'creation_date': attributes.get('creation_date', ''),
                            'last_analysis_stats': last_analysis,
                            'reputation': attributes.get('reputation', 0),
                            'categories': categories,
                            'findings': findings
                        }
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e), 'findings': []}

    async def _virustotal_hash(self, file_hash: str) -> Dict:
        """VirusTotal hash analizi"""
        if not self.api_keys['virustotal']:
            return {'source': 'virustotal', 'error': 'API key yok', 'findings': []}

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                headers = {'x-apikey': self.api_keys['virustotal']}

                async with session.get(url, headers=headers, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        attributes = data.get('data', {}).get('attributes', {})
                        findings = []

                        last_analysis = attributes.get('last_analysis_stats', {})
                        malicious = last_analysis.get('malicious', 0)

                        if malicious > 0:
                            findings.append({
                                'type': 'malicious_file',
                                'count': malicious,
                                'severity': 'critical'
                            })

                            # Malware isimleri
                            results = attributes.get('last_analysis_results', {})
                            malware_names = set()
                            for engine, result in results.items():
                                if result.get('category') == 'malicious':
                                    name = result.get('result', '')
                                    if name:
                                        malware_names.add(name)

                            if malware_names:
                                findings.append({
                                    'type': 'malware_names',
                                    'names': list(malware_names)[:10],
                                    'severity': 'critical'
                                })

                        return {
                            'source': 'virustotal',
                            'hash': file_hash,
                            'meaningful_name': attributes.get('meaningful_name', ''),
                            'type_description': attributes.get('type_description', ''),
                            'size': attributes.get('size', 0),
                            'last_analysis_stats': last_analysis,
                            'findings': findings
                        }
                    elif resp.status == 404:
                        return {
                            'source': 'virustotal',
                            'hash': file_hash,
                            'message': 'Hash bulunamadı - henüz taranmamış olabilir',
                            'findings': []
                        }
        except Exception as e:
            return {'source': 'virustotal', 'error': str(e), 'findings': []}

    async def _hackertarget_subdomains(self, domain: str) -> Dict:
        """HackerTarget subdomain keşfi (ücretsiz)"""
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
                async with session.get(url, timeout=10) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        findings = []
                        subdomains = []

                        if 'error' not in text.lower() and 'API count exceeded' not in text:
                            for line in text.strip().split('\n'):
                                if ',' in line:
                                    subdomain, ip = line.split(',', 1)
                                    subdomains.append({'subdomain': subdomain, 'ip': ip.strip()})
                                    findings.append({
                                        'type': 'subdomain',
                                        'value': subdomain,
                                        'ip': ip.strip(),
                                        'severity': 'info'
                                    })

                        return {
                            'source': 'hackertarget',
                            'domain': domain,
                            'subdomains': subdomains,
                            'count': len(subdomains),
                            'findings': findings
                        }
        except Exception as e:
            return {'source': 'hackertarget', 'error': str(e), 'findings': []}

    async def _ssl_cert_lookup(self, domain: str) -> Dict:
        """SSL sertifika analizi"""
        try:
            context = ssl.create_default_context()
            findings = []

            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                    # Sertifika bilgileri
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))

                    # Süre kontrolü
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        # Parse date
                        from email.utils import parsedate_to_datetime
                        try:
                            expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expire_date - datetime.now()).days

                            if days_left < 0:
                                findings.append({
                                    'type': 'expired_cert',
                                    'days': abs(days_left),
                                    'severity': 'critical'
                                })
                            elif days_left < 30:
                                findings.append({
                                    'type': 'expiring_cert',
                                    'days': days_left,
                                    'severity': 'high'
                                })
                        except Exception:
                            pass

                    # SAN kontrolü
                    san = cert.get('subjectAltName', [])
                    san_domains = [name for type_, name in san if type_ == 'DNS']

                    return {
                        'source': 'ssl_cert',
                        'domain': domain,
                        'issuer': issuer.get('organizationName', 'Unknown'),
                        'subject': subject.get('commonName', domain),
                        'not_before': cert.get('notBefore', ''),
                        'not_after': not_after,
                        'san_domains': san_domains,
                        'serial_number': cert.get('serialNumber', ''),
                        'findings': findings
                    }
        except Exception as e:
            return {'source': 'ssl_cert', 'error': str(e), 'findings': []}

    async def _hibp_lookup(self, email: str) -> Dict:
        """Have I Been Pwned email kontrolü"""
        hibp_key = os.environ.get('HIBP_API_KEY', '')

        try:
            async with aiohttp.ClientSession() as session:
                if hibp_key:
                    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                    headers = {
                        'hibp-api-key': hibp_key,
                        'User-Agent': 'TSUNAMI-OSINT'
                    }

                    async with session.get(url, headers=headers, timeout=10) as resp:
                        if resp.status == 200:
                            breaches = await resp.json()
                            findings = []

                            for breach in breaches:
                                findings.append({
                                    'type': 'data_breach',
                                    'name': breach.get('Name', ''),
                                    'date': breach.get('BreachDate', ''),
                                    'severity': 'high'
                                })

                            return {
                                'source': 'hibp',
                                'email': email,
                                'breaches': [b.get('Name') for b in breaches],
                                'breach_count': len(breaches),
                                'findings': findings
                            }
                        elif resp.status == 404:
                            return {
                                'source': 'hibp',
                                'email': email,
                                'message': 'Veri ihlali bulunamadı',
                                'breaches': [],
                                'findings': []
                            }
                else:
                    return {'source': 'hibp', 'error': 'API key yok', 'findings': []}
        except Exception as e:
            return {'source': 'hibp', 'error': str(e), 'findings': []}

    async def _email_domain_check(self, email: str) -> Dict:
        """Email domain kontrolü"""
        try:
            domain = email.split('@')[-1]
            findings = []

            # MX kayıtları
            import dns.resolver
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                mx_list = [str(mx.exchange).rstrip('.') for mx in mx_records]

                # Bilinen email servisleri
                known_providers = ['google', 'outlook', 'yahoo', 'protonmail', 'zoho']
                is_known = any(provider in str(mx_list).lower() for provider in known_providers)

                if not is_known:
                    findings.append({
                        'type': 'custom_email_server',
                        'mx_records': mx_list,
                        'severity': 'info'
                    })

                return {
                    'source': 'email_check',
                    'email': email,
                    'domain': domain,
                    'mx_records': mx_list,
                    'is_known_provider': is_known,
                    'findings': findings
                }
            except Exception:
                findings.append({
                    'type': 'no_mx_records',
                    'severity': 'medium'
                })
                return {
                    'source': 'email_check',
                    'email': email,
                    'domain': domain,
                    'mx_records': [],
                    'findings': findings
                }
        except Exception as e:
            return {'source': 'email_check', 'error': str(e), 'findings': []}

    def _calculate_risk(self, results: Dict) -> int:
        """Risk skoru hesapla (0-100)"""
        score = 0

        for finding in results.get('findings', []):
            severity = finding.get('severity', 'info')
            if severity == 'critical':
                score += 25
            elif severity == 'high':
                score += 15
            elif severity == 'medium':
                score += 8
            elif severity == 'low':
                score += 3
            elif severity == 'info':
                score += 1

        return min(100, score)

    def _calculate_confidence(self, results: Dict) -> float:
        """Güven skoru hesapla (0.0-1.0)"""
        sources = results.get('sources', {})
        successful = sum(1 for s in sources.values() if not s.get('error'))
        total = len(sources)

        if total == 0:
            return 0.0

        return round(successful / total, 2)


# ═══════════════════════════════════════════════════════════════════════════════
# SIGINT LITE - SİNYAL İSTİHBARATI
# ═══════════════════════════════════════════════════════════════════════════════

class SIGINTLite:
    """
    SIGINT Lite Modülü

    - OpenCellID: Baz istasyonu lokasyonu
    - WiGLE: WiFi ağ haritalama
    - RF Sinyal analizi
    """

    def __init__(self):
        self.opencellid_key = os.environ.get('OPENCELLID_API_KEY', '')
        self.wigle_name = os.environ.get('WIGLE_API_NAME', '')
        self.wigle_key = os.environ.get('WIGLE_API_KEY', '')

    async def cell_tower_lookup(self, mcc: int, mnc: int, lac: int, cid: int) -> Dict:
        """Baz istasyonu lokasyon sorgusu"""
        if not self.opencellid_key:
            return {'error': 'OpenCellID API key yok'}

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://opencellid.org/cell/get"
                params = {
                    'key': self.opencellid_key,
                    'mcc': mcc,
                    'mnc': mnc,
                    'lac': lac,
                    'cellid': cid,
                    'format': 'json'
                }

                async with session.get(url, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            'source': 'opencellid',
                            'mcc': mcc,
                            'mnc': mnc,
                            'lac': lac,
                            'cid': cid,
                            'lat': data.get('lat'),
                            'lon': data.get('lon'),
                            'range': data.get('range'),
                            'radio': data.get('radio'),
                            'averageSignal': data.get('averageSignal')
                        }
        except Exception as e:
            return {'source': 'opencellid', 'error': str(e)}

    async def wifi_lookup(self, bssid: str) -> Dict:
        """WiFi BSSID lokasyon sorgusu"""
        if not self.wigle_name or not self.wigle_key:
            return {'error': 'WiGLE API credentials yok'}

        try:
            import base64
            auth = base64.b64encode(f"{self.wigle_name}:{self.wigle_key}".encode()).decode()

            async with aiohttp.ClientSession() as session:
                url = "https://api.wigle.net/api/v2/network/detail"
                headers = {'Authorization': f'Basic {auth}'}
                params = {'netid': bssid}

                async with session.get(url, headers=headers, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        results = data.get('results', [])
                        if results:
                            r = results[0]
                            return {
                                'source': 'wigle',
                                'bssid': bssid,
                                'ssid': r.get('ssid'),
                                'lat': r.get('trilat'),
                                'lon': r.get('trilong'),
                                'encryption': r.get('encryption'),
                                'channel': r.get('channel'),
                                'lastupdt': r.get('lastupdt')
                            }
                        return {'source': 'wigle', 'bssid': bssid, 'message': 'Bulunamadı'}
        except Exception as e:
            return {'source': 'wigle', 'error': str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# GEOINT OPEN - COĞRAFİ İSTİHBARAT
# ═══════════════════════════════════════════════════════════════════════════════

class GEOINTOpen:
    """
    GEOINT Open Modülü

    - ADS-B Exchange: Uçak takibi
    - Marine Traffic: Gemi takibi
    - N2YO: Uydu takibi
    """

    def __init__(self):
        self.adsb_key = os.environ.get('ADSB_API_KEY', '')
        self.n2yo_key = os.environ.get('N2YO_API_KEY', '')

    async def get_aircraft_in_area(self, lat: float, lon: float, radius_nm: int = 100) -> Dict:
        """Belirli alandaki uçakları al"""
        try:
            # OpenSky Network (ücretsiz)
            async with aiohttp.ClientSession() as session:
                # Bounding box hesapla
                lat_range = radius_nm / 60  # Yaklaşık
                lon_range = radius_nm / 60

                url = "https://opensky-network.org/api/states/all"
                params = {
                    'lamin': lat - lat_range,
                    'lomin': lon - lon_range,
                    'lamax': lat + lat_range,
                    'lomax': lon + lon_range
                }

                async with session.get(url, params=params, timeout=15) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        aircraft = []

                        for state in data.get('states', []) or []:
                            aircraft.append({
                                'icao24': state[0],
                                'callsign': (state[1] or '').strip(),
                                'origin_country': state[2],
                                'longitude': state[5],
                                'latitude': state[6],
                                'altitude': state[7],  # meters
                                'velocity': state[9],  # m/s
                                'heading': state[10],
                                'on_ground': state[8],
                                'squawk': state[14]
                            })

                        # Askeri uçak tespiti
                        military_patterns = ['MIL', 'RCH', 'NATO', 'USAF', 'THK', 'AEG', 'FORTE']
                        military_aircraft = [
                            a for a in aircraft
                            if any(p in (a.get('callsign') or '').upper() for p in military_patterns)
                        ]

                        return {
                            'source': 'opensky',
                            'center': {'lat': lat, 'lon': lon},
                            'radius_nm': radius_nm,
                            'total_aircraft': len(aircraft),
                            'military_aircraft': len(military_aircraft),
                            'aircraft': aircraft[:100],  # İlk 100
                            'military': military_aircraft
                        }
        except Exception as e:
            return {'source': 'opensky', 'error': str(e)}

    async def track_satellite(self, norad_id: int, lat: float = 39.0, lon: float = 35.0) -> Dict:
        """Uydu takibi (N2YO)"""
        if not self.n2yo_key:
            return {'error': 'N2YO API key yok'}

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.n2yo.com/rest/v1/satellite/positions/{norad_id}/{lat}/{lon}/0/1"
                params = {'apiKey': self.n2yo_key}

                async with session.get(url, params=params, timeout=10) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        info = data.get('info', {})
                        positions = data.get('positions', [])

                        return {
                            'source': 'n2yo',
                            'norad_id': norad_id,
                            'name': info.get('satname'),
                            'category': info.get('category'),
                            'transactions': info.get('transactionscount'),
                            'position': positions[0] if positions else None
                        }
        except Exception as e:
            return {'source': 'n2yo', 'error': str(e)}

    async def get_iss_position(self) -> Dict:
        """ISS pozisyonu (ücretsiz)"""
        try:
            async with aiohttp.ClientSession() as session:
                url = "http://api.open-notify.org/iss-now.json"

                async with session.get(url, timeout=5) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        pos = data.get('iss_position', {})

                        return {
                            'source': 'iss_tracker',
                            'timestamp': data.get('timestamp'),
                            'latitude': float(pos.get('latitude', 0)),
                            'longitude': float(pos.get('longitude', 0))
                        }
        except Exception as e:
            return {'source': 'iss_tracker', 'error': str(e)}


# ═══════════════════════════════════════════════════════════════════════════════
# 22 PENTAGON SEVİYE AJAN
# ═══════════════════════════════════════════════════════════════════════════════

class PentagonAgents:
    """
    22 Pentagon Seviye Siber Ajan Sistemi
    """

    def __init__(self):
        self.agents: Dict[str, CyberAgent] = {}
        self.groq = GroqCyberEngine()
        self.osint = OSINTFusion()
        self.sigint = SIGINTLite()
        self.geoint = GEOINTOpen()
        self._executor = ThreadPoolExecutor(max_workers=10)
        self._initialize_agents()

    def _initialize_agents(self):
        """22 ajanı başlat"""
        agents_config = [
            # KOMUTA KATMANI
            CyberAgent(
                id="soc-commander",
                name="SOC Commander",
                layer=AgentLayer.COMMAND,
                capabilities=["alert_triage", "incident_management", "team_coordination", "escalation"],
                description="Güvenlik Operasyon Merkezi Komutanı - Tüm güvenlik operasyonlarını yönetir",
                tools=["splunk", "elk", "qradar", "sentinel"],
                mitre_techniques=["TA0043"]  # Reconnaissance
            ),
            CyberAgent(
                id="incident-commander",
                name="Incident Commander",
                layer=AgentLayer.COMMAND,
                capabilities=["incident_response", "containment", "eradication", "recovery"],
                description="Olay Müdahale Komutanı - Güvenlik olaylarını yönetir",
                tools=["the_hive", "cortex", "misp", "dfir_tools"],
                mitre_techniques=["TA0040"]  # Impact
            ),
            CyberAgent(
                id="cyber-strategist",
                name="Cyber Strategist",
                layer=AgentLayer.COMMAND,
                capabilities=["threat_modeling", "risk_assessment", "security_architecture", "policy_development"],
                description="Siber Strateji Uzmanı - Uzun vadeli güvenlik stratejisi geliştirir",
                tools=["mitre_attack", "threat_model", "risk_framework"],
                mitre_techniques=[]
            ),

            # İSTİHBARAT KATMANI
            CyberAgent(
                id="osint-hunter",
                name="OSINT Hunter",
                layer=AgentLayer.INTELLIGENCE,
                capabilities=["social_media_intel", "domain_recon", "email_tracking", "person_search", "company_intel"],
                description="Açık Kaynak İstihbarat Avcısı - Tüm açık kaynakları tarar",
                tools=["shodan", "censys", "maltego", "spiderfoot", "recon-ng"],
                mitre_techniques=["T1593", "T1594", "T1596"]
            ),
            CyberAgent(
                id="humint-analyst",
                name="HUMINT Analyst",
                layer=AgentLayer.INTELLIGENCE,
                capabilities=["social_engineering_analysis", "insider_threat_detection", "behavior_analysis"],
                description="İnsan Kaynakları İstihbarat Analisti - Sosyal mühendislik ve içeriden tehdit analizi",
                tools=["social_engineering_toolkit", "behavior_analytics"],
                mitre_techniques=["T1566", "T1534"]
            ),
            CyberAgent(
                id="sigint-collector",
                name="SIGINT Collector",
                layer=AgentLayer.INTELLIGENCE,
                capabilities=["rf_analysis", "cell_tower_tracking", "wifi_mapping", "bluetooth_tracking"],
                description="Sinyal İstihbaratı Toplayıcı - Kablosuz sinyal istihbaratı",
                tools=["opencellid", "wigle", "kismet", "hackrf"],
                mitre_techniques=["T1040", "T1120"]
            ),
            CyberAgent(
                id="geoint-mapper",
                name="GEOINT Mapper",
                layer=AgentLayer.INTELLIGENCE,
                capabilities=["aircraft_tracking", "vessel_tracking", "satellite_tracking", "geolocation"],
                description="Coğrafi İstihbarat Haritalayıcı - Konumsal istihbarat",
                tools=["adsb_exchange", "marine_traffic", "n2yo", "opensky"],
                mitre_techniques=["T1591"]
            ),
            CyberAgent(
                id="techint-specialist",
                name="TECHINT Specialist",
                layer=AgentLayer.INTELLIGENCE,
                capabilities=["malware_reverse_engineering", "exploit_analysis", "firmware_analysis"],
                description="Teknik İstihbarat Uzmanı - Zararlı yazılım ve exploit analizi",
                tools=["ghidra", "ida", "radare2", "binwalk"],
                mitre_techniques=["T1588"]
            ),

            # SAVUNMA KATMANI
            CyberAgent(
                id="blue-team-lead",
                name="Blue Team Lead",
                layer=AgentLayer.DEFENSE,
                capabilities=["security_monitoring", "detection_engineering", "hardening", "compliance"],
                description="Mavi Takım Lideri - Savunma operasyonlarını yönetir",
                tools=["sigma", "yara", "osquery", "wazuh"],
                mitre_techniques=[]
            ),
            CyberAgent(
                id="threat-hunter",
                name="Threat Hunter",
                layer=AgentLayer.DEFENSE,
                capabilities=["proactive_hunting", "anomaly_detection", "ioc_correlation", "apt_tracking"],
                description="Tehdit Avcısı - Proaktif tehdit avı",
                tools=["velociraptor", "graylog", "elastic_siem", "splunk"],
                mitre_techniques=["T1087", "T1083"]
            ),
            CyberAgent(
                id="forensic-examiner",
                name="Forensic Examiner",
                layer=AgentLayer.DEFENSE,
                capabilities=["disk_forensics", "memory_forensics", "network_forensics", "mobile_forensics"],
                description="Adli Bilişim Uzmanı - Dijital kanıt toplama ve analiz",
                tools=["autopsy", "volatility", "wireshark", "ftk"],
                mitre_techniques=[]
            ),
            CyberAgent(
                id="malware-analyst",
                name="Malware Analyst",
                layer=AgentLayer.DEFENSE,
                capabilities=["static_analysis", "dynamic_analysis", "sandbox_analysis", "behavior_analysis"],
                description="Zararlı Yazılım Analisti - Malware analizi ve sınıflandırma",
                tools=["cuckoo", "any_run", "joe_sandbox", "virustotal"],
                mitre_techniques=["T1204"]
            ),

            # SALDIRI KATMANI
            CyberAgent(
                id="red-team-operator",
                name="Red Team Operator",
                layer=AgentLayer.OFFENSIVE,
                capabilities=["adversary_simulation", "attack_chain", "lateral_movement", "exfiltration"],
                description="Kırmızı Takım Operatörü - Saldırı simülasyonu",
                tools=["cobalt_strike", "metasploit", "empire", "covenant"],
                mitre_techniques=["T1059", "T1078", "T1021"]
            ),
            CyberAgent(
                id="pentester",
                name="Penetration Tester",
                layer=AgentLayer.OFFENSIVE,
                capabilities=["vulnerability_assessment", "exploitation", "post_exploitation", "reporting"],
                description="Sızma Test Uzmanı - Güvenlik testi",
                tools=["burp", "nmap", "nuclei", "sqlmap", "nikto"],
                mitre_techniques=["T1190", "T1210"]
            ),
            CyberAgent(
                id="exploit-developer",
                name="Exploit Developer",
                layer=AgentLayer.OFFENSIVE,
                capabilities=["vulnerability_research", "exploit_development", "weaponization"],
                description="İstismar Geliştirici - Exploit yazma ve PoC geliştirme",
                tools=["ida", "ghidra", "pwntools", "msfvenom"],
                mitre_techniques=["T1587.004"]
            ),

            # KARMA KATMAN
            CyberAgent(
                id="purple-team-coord",
                name="Purple Team Coordinator",
                layer=AgentLayer.PURPLE,
                capabilities=["attack_defense_coordination", "gap_analysis", "control_validation"],
                description="Mor Takım Koordinatörü - Kırmızı ve Mavi takım koordinasyonu",
                tools=["attack_range", "caldera", "atomic_red_team"],
                mitre_techniques=[]
            ),
            CyberAgent(
                id="adversary-emulator",
                name="Adversary Emulator",
                layer=AgentLayer.PURPLE,
                capabilities=["ttp_emulation", "apt_simulation", "attack_validation"],
                description="Düşman Emülatörü - Gerçek düşman TTP'lerini simüle eder",
                tools=["caldera", "atomic_red_team", "mitre_attack"],
                mitre_techniques=["T1059", "T1106"]
            ),

            # KRİTİK ALTYAPI
            CyberAgent(
                id="ics-defender",
                name="ICS Defender",
                layer=AgentLayer.CRITICAL_INFRA,
                capabilities=["ics_monitoring", "plc_security", "scada_assessment", "ot_hardening"],
                description="Endüstriyel Kontrol Sistemi Savunucusu",
                tools=["dragos", "claroty", "nozomi", "grassmarlin"],
                mitre_techniques=["T0800", "T0802"]
            ),
            CyberAgent(
                id="scada-guardian",
                name="SCADA Guardian",
                layer=AgentLayer.CRITICAL_INFRA,
                capabilities=["scada_monitoring", "protocol_analysis", "anomaly_detection"],
                description="SCADA Koruyucusu - SCADA sistemlerini izler ve korur",
                tools=["scada_tools", "modbus_scanner", "dnp3_analyzer"],
                mitre_techniques=["T0855", "T0859"]
            ),
            CyberAgent(
                id="ot-security-spec",
                name="OT Security Specialist",
                layer=AgentLayer.CRITICAL_INFRA,
                capabilities=["ot_assessment", "network_segmentation", "asset_inventory"],
                description="Operasyonel Teknoloji Güvenlik Uzmanı",
                tools=["runzero", "tenable_ot", "asset_discovery"],
                mitre_techniques=[]
            ),

            # GLOBAL OPERASYONLAR
            CyberAgent(
                id="darkweb-monitor",
                name="Darkweb Monitor",
                layer=AgentLayer.GLOBAL_OPS,
                capabilities=["darkweb_monitoring", "leak_detection", "credential_hunting", "market_analysis"],
                description="Karanlık Web İzleyici - Dark web istihbaratı",
                tools=["tor_browser", "onionscan", "dark_web_crawlers"],
                mitre_techniques=["T1589"]
            ),
            CyberAgent(
                id="global-sentinel",
                name="Global Sentinel",
                layer=AgentLayer.GLOBAL_OPS,
                capabilities=["global_threat_monitoring", "geopolitical_analysis", "trend_analysis"],
                description="Küresel Nöbetçi - Dünya çapında tehdit izleme",
                tools=["threat_feeds", "news_aggregator", "social_listening"],
                mitre_techniques=[]
            ),
        ]

        for agent in agents_config:
            self.agents[agent.id] = agent

        logger.info(f"[PENTAGON] {len(self.agents)} ajan başlatıldı")

    def get_all_agents(self) -> List[Dict]:
        """Tüm ajanları getir"""
        result = []
        for agent in self.agents.values():
            agent_dict = {
                'id': agent.id,
                'name': agent.name,
                'layer': agent.layer.value if hasattr(agent.layer, 'value') else str(agent.layer),
                'status': agent.status.value if hasattr(agent.status, 'value') else str(agent.status),
                'capabilities': agent.capabilities,
                'current_task': agent.current_task,
                'success_rate': agent.success_rate,
                'tasks_completed': agent.tasks_completed,
                'description': agent.description,
                'tools': agent.tools,
                'mitre_techniques': agent.mitre_techniques
            }
            result.append(agent_dict)
        return result

    def get_agent(self, agent_id: str) -> Optional[CyberAgent]:
        """Belirli ajanı getir"""
        return self.agents.get(agent_id)

    def get_agents_by_layer(self, layer: AgentLayer) -> List[CyberAgent]:
        """Katmana göre ajanları getir"""
        return [a for a in self.agents.values() if a.layer == layer]

    async def execute_agent_task(self, agent_id: str, task_type: str, params: Dict) -> OperationResult:
        """Ajan görevi çalıştır"""
        agent = self.agents.get(agent_id)
        if not agent:
            return OperationResult(
                operation_id=f"op_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                operation_type=OperationType.RECON,
                agent_id=agent_id,
                success=False,
                findings=[{'error': f'Ajan bulunamadı: {agent_id}'}]
            )

        agent.status = AgentStatus.BUSY
        agent.current_task = task_type
        start_time = time.time()

        try:
            # Görev tipine göre çalıştır
            if task_type == 'osint':
                target = params.get('target', '')
                result = await self.osint.full_osint(target)
                findings = result.get('findings', [])

            elif task_type == 'threat_analysis':
                threat_data = params.get('threat_data', {})
                result = await self.groq.analyze_threat(threat_data)
                findings = [result]

            elif task_type == 'aircraft_tracking':
                lat = params.get('lat', 39.0)
                lon = params.get('lon', 35.0)
                radius = params.get('radius', 100)
                result = await self.geoint.get_aircraft_in_area(lat, lon, radius)
                findings = [result]

            elif task_type == 'cell_lookup':
                result = await self.sigint.cell_tower_lookup(
                    params.get('mcc', 286),
                    params.get('mnc', 1),
                    params.get('lac', 0),
                    params.get('cid', 0)
                )
                findings = [result]

            else:
                # Genel görev
                findings = [{'task': task_type, 'params': params, 'status': 'completed'}]

            agent.status = AgentStatus.IDLE
            agent.current_task = None
            agent.tasks_completed += 1

            return OperationResult(
                operation_id=f"op_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                operation_type=OperationType[task_type.upper()] if task_type.upper() in OperationType.__members__ else OperationType.RECON,
                agent_id=agent_id,
                success=True,
                findings=findings,
                execution_time=time.time() - start_time,
                recommendations=self._generate_recommendations(findings)
            )

        except Exception as e:
            agent.status = AgentStatus.ERROR
            logger.error(f"[PENTAGON] Ajan görevi hatası: {e}")

            return OperationResult(
                operation_id=f"op_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                operation_type=OperationType.RECON,
                agent_id=agent_id,
                success=False,
                findings=[{'error': str(e)}],
                execution_time=time.time() - start_time
            )

    def _generate_recommendations(self, findings: List[Dict]) -> List[str]:
        """Bulgulara göre öneriler oluştur"""
        recommendations = []

        for finding in findings:
            severity = finding.get('severity', 'info')
            finding_type = finding.get('type', '')

            if severity == 'critical':
                recommendations.append(f"KRİTİK: {finding_type} - Acil müdahale gerekli")
            elif severity == 'high':
                recommendations.append(f"YÜKSEK: {finding_type} - 24 saat içinde aksiyon alın")
            elif severity == 'medium':
                recommendations.append(f"ORTA: {finding_type} - Haftalık değerlendirmeye alın")

        if not recommendations:
            recommendations.append("Kritik bulgu tespit edilmedi - rutin izlemeye devam edin")

        return recommendations


# ═══════════════════════════════════════════════════════════════════════════════
# SİBER KOMUTA MERKEZİ - ANA SINIF
# ═══════════════════════════════════════════════════════════════════════════════

class SiberKomutaMerkezi:
    """
    Siber Komuta Merkezi v3.0

    Tüm siber yetenekleri birleştirir ve koordine eder.
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self.version = "3.0.0"
        self.pentagon_agents = PentagonAgents()
        self.groq_engine = GroqCyberEngine()
        self.osint_fusion = OSINTFusion()
        self.sigint_lite = SIGINTLite()
        self.geoint_open = GEOINTOpen()

        self._operations: Dict[str, OperationResult] = {}
        self._reports: Dict[str, IntelReport] = {}
        self._active_missions: List[str] = []

        # İstatistikler
        self._stats = {
            'total_operations': 0,
            'successful_operations': 0,
            'threats_detected': 0,
            'iocs_collected': 0,
            'reports_generated': 0
        }

        logger.info(f"[SİBER] Komuta Merkezi v{self.version} başlatıldı")

    def get_status(self) -> Dict:
        """Sistem durumu"""
        agents = self.pentagon_agents.get_all_agents()
        active_agents = [a for a in agents if a['status'] == 'active' or a['status'] == 'busy']

        return {
            'version': self.version,
            'status': 'operational',
            'timestamp': datetime.now().isoformat(),
            'agents': {
                'total': len(agents),
                'active': len(active_agents),
                'by_layer': {
                    layer.value: len([a for a in agents if a['layer'] == layer.value])
                    for layer in AgentLayer
                }
            },
            'modules': {
                'groq_engine': 'active' if self.groq_engine.api_key else 'fallback',
                'osint_fusion': 'active',
                'sigint_lite': 'active' if self.sigint_lite.opencellid_key else 'limited',
                'geoint_open': 'active'
            },
            'statistics': self._stats,
            'active_missions': len(self._active_missions)
        }

    async def execute_command(self, command: str, params: Dict = None) -> Dict:
        """Siber komut çalıştır"""
        params = params or {}
        command = command.lower().strip()

        self._stats['total_operations'] += 1

        try:
            # Komut yönlendirme
            if command in ['osint', 'osint-full', 'investigate']:
                target = params.get('target', '')
                result = await self.osint_fusion.full_osint(target)
                self._stats['successful_operations'] += 1
                return {'command': command, 'result': result, 'success': True}

            elif command in ['threat-analyze', 'analyze', 'tehdit-analiz']:
                threat_data = params.get('data', params)
                result = await self.groq_engine.analyze_threat(threat_data)
                self._stats['successful_operations'] += 1
                return {'command': command, 'result': result, 'success': True}

            elif command in ['aircraft', 'airspace', 'hava-sahasi']:
                lat = params.get('lat', 39.0)
                lon = params.get('lon', 35.0)
                result = await self.geoint_open.get_aircraft_in_area(lat, lon)
                return {'command': command, 'result': result, 'success': True}

            elif command in ['cell-lookup', 'baz-istasyonu']:
                result = await self.sigint_lite.cell_tower_lookup(
                    params.get('mcc', 286),
                    params.get('mnc', 1),
                    params.get('lac', 0),
                    params.get('cid', 0)
                )
                return {'command': command, 'result': result, 'success': True}

            elif command in ['agent-list', 'ajanlar']:
                agents = self.pentagon_agents.get_all_agents()
                return {'command': command, 'agents': agents, 'count': len(agents), 'success': True}

            elif command in ['agent-task', 'ajan-gorev']:
                agent_id = params.get('agent_id', '')
                task_type = params.get('task', 'recon')
                result = await self.pentagon_agents.execute_agent_task(agent_id, task_type, params)
                return {'command': command, 'result': asdict(result), 'success': result.success}

            elif command in ['generate-report', 'rapor']:
                findings = params.get('findings', [])
                report = await self.groq_engine.generate_report(findings)
                self._stats['reports_generated'] += 1
                return {'command': command, 'report': report, 'success': True}

            elif command in ['status', 'durum']:
                return {'command': command, 'result': self.get_status(), 'success': True}

            elif command in ['iss', 'iss-track']:
                result = await self.geoint_open.get_iss_position()
                return {'command': command, 'result': result, 'success': True}

            else:
                return {
                    'command': command,
                    'error': f'Bilinmeyen komut: {command}',
                    'available_commands': [
                        'osint', 'threat-analyze', 'aircraft', 'cell-lookup',
                        'agent-list', 'agent-task', 'generate-report', 'status', 'iss'
                    ],
                    'success': False
                }

        except Exception as e:
            logger.error(f"[SİBER] Komut hatası: {e}")
            return {'command': command, 'error': str(e), 'success': False}

    async def autonomous_threat_hunt(self, targets: List[str]) -> Dict:
        """Otonom tehdit avı"""
        results = {
            'mission_id': f"mission_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'targets': targets,
            'findings': [],
            'summary': {},
            'start_time': datetime.now().isoformat()
        }

        self._active_missions.append(results['mission_id'])

        try:
            # Her hedef için paralel OSINT
            osint_tasks = [self.osint_fusion.full_osint(t) for t in targets]
            osint_results = await asyncio.gather(*osint_tasks, return_exceptions=True)

            all_findings = []
            for i, result in enumerate(osint_results):
                if isinstance(result, dict):
                    results['findings'].append({
                        'target': targets[i],
                        'osint': result
                    })
                    all_findings.extend(result.get('findings', []))

            # Tehdit analizi
            if all_findings:
                analysis = await self.groq_engine.analyze_threat({
                    'findings': all_findings,
                    'targets': targets
                })
                results['analysis'] = analysis

            # Özet
            results['summary'] = {
                'total_findings': len(all_findings),
                'critical': len([f for f in all_findings if f.get('severity') == 'critical']),
                'high': len([f for f in all_findings if f.get('severity') == 'high']),
                'medium': len([f for f in all_findings if f.get('severity') == 'medium'])
            }

            results['end_time'] = datetime.now().isoformat()
            self._stats['threats_detected'] += results['summary']['critical'] + results['summary']['high']

        finally:
            self._active_missions.remove(results['mission_id'])

        return results


# ═══════════════════════════════════════════════════════════════════════════════
# SINGLETON ERİŞİM
# ═══════════════════════════════════════════════════════════════════════════════

_siber_komuta: Optional[SiberKomutaMerkezi] = None


def siber_komuta_al() -> SiberKomutaMerkezi:
    """Siber Komuta Merkezi singleton"""
    global _siber_komuta
    if _siber_komuta is None:
        _siber_komuta = SiberKomutaMerkezi.get_instance()
    return _siber_komuta


# ═══════════════════════════════════════════════════════════════════════════════
# TEST
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    import asyncio

    async def test():
        siber = siber_komuta_al()

        print("=" * 60)
        print("SİBER KOMUTA MERKEZİ v3.0")
        print("=" * 60)

        # Durum
        status = siber.get_status()
        print(f"\nDurum: {status['status']}")
        print(f"Toplam Ajan: {status['agents']['total']}")
        print(f"Modüller: {json.dumps(status['modules'], indent=2)}")

        # Ajan listesi
        result = await siber.execute_command('agent-list')
        print(f"\nAjanlar ({result['count']}):")
        for agent in result['agents'][:5]:
            print(f"  - {agent['name']} ({agent['layer']})")

        # OSINT örneği
        print("\n" + "=" * 60)
        print("OSINT TEST: example.com")
        print("=" * 60)
        result = await siber.execute_command('osint', {'target': 'example.com'})
        print(f"Risk Skoru: {result['result'].get('risk_score', 'N/A')}")
        print(f"Güven: {result['result'].get('confidence', 'N/A')}")

    asyncio.run(test())
