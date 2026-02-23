#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI DECEPTION & HONEYPOT SYSTEM v1.0
    Aldatma ve Bal Kuzusu Sistemi - Siber Tuzak Orkestrasyonu
================================================================================

    Ozellikler:
    - Dinamik honeypot dagitimi (SSH, HTTP, FTP, SMB, RDP)
    - Honeytoken uretimi (sahte kimlik bilgileri, API anahtarlari, belgeler)
    - Kimlik canary'leri (kullanildiginda alarm veren sahte sifreler)
    - Gercekci gorunen sahte dosya sistemleri
    - Saldirgan izleme yollarinda breadcrumb birakma
    - TTP (Taktik, Teknik, Prosedur) cikarimi
    - Saldirgan parmak izi analizi
    - Oturum kaydi ve tekrar oynatma
    - MITRE ATT&CK haritalaması
    - Gercek zamanli alarm sistemi
    - SOAR entegrasyonu

    Turkce yorumlar ve tip ipuclari ile kurumsal seviye guvenlik modulu.

================================================================================
"""

import os
import json
import hashlib
import secrets
import threading
import asyncio
import time
import re
import socket
import uuid
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict
from abc import ABC, abstractmethod
import base64

# Flask entegrasyonu
try:
    from flask import Blueprint, request, jsonify, g
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

# Loglama yapilandirmasi
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================================
# ENUM TANIMLARI
# ============================================================================

class HoneypotTipi(Enum):
    """Honeypot turleri"""
    SSH = "ssh"
    HTTP = "http"
    FTP = "ftp"
    SMB = "smb"
    RDP = "rdp"
    MYSQL = "mysql"
    TELNET = "telnet"
    DNS = "dns"
    SMTP = "smtp"
    HTTPS = "https"


class HoneytokenTipi(Enum):
    """Honeytoken turleri"""
    CREDENTIAL = "credential"           # Sahte kullanici/sifre
    API_KEY = "api_key"                 # Sahte API anahtari
    AWS_KEY = "aws_key"                 # Sahte AWS anahtari
    DATABASE = "database"               # Sahte veritabani baglantisi
    DOCUMENT = "document"               # Sahte belge
    URL = "url"                         # Sahte URL/endpoint
    EMAIL = "email"                     # Sahte email adresi
    COOKIE = "cookie"                   # Sahte session cookie
    SSH_KEY = "ssh_key"                 # Sahte SSH anahtari
    BITCOIN_WALLET = "bitcoin_wallet"   # Sahte Bitcoin cuzdan


class AlarmSeviyesi(Enum):
    """Alarm ciddiyet seviyeleri"""
    KRITIK = "kritik"       # Aninda mudahale gerekli
    YUKSEK = "yuksek"       # Acil inceleme gerekli
    ORTA = "orta"           # Normal inceleme
    DUSUK = "dusuk"         # Bilgi amacli
    BILGI = "bilgi"         # Sadece kayit


class SaldirganDavranisi(Enum):
    """Saldirgan davranis kaliplari"""
    KEŞIF = "kesif"                     # Reconnaissance
    TARAMA = "tarama"                   # Scanning
    ERISIM_DENEMESI = "erisim_denemesi" # Access attempt
    LATERAL_HAREKET = "lateral_hareket" # Lateral movement
    VERI_SIZINTISI = "veri_sizintisi"   # Data exfiltration
    KALICILIK = "kalicilik"             # Persistence


# ============================================================================
# DATACLASS TANIMLARI
# ============================================================================

@dataclass
class Honeypot:
    """Honeypot yapilandirmasi"""
    id: str
    tip: HoneypotTipi
    ip: str
    port: int
    aktif: bool = True
    olusturma_zamani: datetime = field(default_factory=datetime.now)
    son_etkilesim: Optional[datetime] = None
    toplam_etkilesim: int = 0
    yapilandirma: Dict[str, Any] = field(default_factory=dict)
    etiketler: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Sozluge donustur"""
        return {
            'id': self.id,
            'tip': self.tip.value,
            'ip': self.ip,
            'port': self.port,
            'aktif': self.aktif,
            'olusturma_zamani': self.olusturma_zamani.isoformat() if self.olusturma_zamani else None,
            'son_etkilesim': self.son_etkilesim.isoformat() if self.son_etkilesim else None,
            'toplam_etkilesim': self.toplam_etkilesim,
            'yapilandirma': self.yapilandirma,
            'etiketler': self.etiketler
        }


@dataclass
class Honeytoken:
    """Honeytoken (tuzak veri) yapilandirmasi"""
    id: str
    tip: HoneytokenTipi
    deger: str
    aciklama: str
    olusturma_zamani: datetime = field(default_factory=datetime.now)
    son_erisim: Optional[datetime] = None
    erisim_sayisi: int = 0
    kaynak_konum: str = ""  # Token nereye yerlestirildi
    aktif: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        """Sozluge donustur"""
        return {
            'id': self.id,
            'tip': self.tip.value,
            'deger': self.deger[:50] + '...' if len(self.deger) > 50 else self.deger,
            'aciklama': self.aciklama,
            'olusturma_zamani': self.olusturma_zamani.isoformat() if self.olusturma_zamani else None,
            'son_erisim': self.son_erisim.isoformat() if self.son_erisim else None,
            'erisim_sayisi': self.erisim_sayisi,
            'kaynak_konum': self.kaynak_konum,
            'aktif': self.aktif
        }


@dataclass
class SaldirganProfili:
    """Saldirgan profil bilgisi"""
    id: str
    ip_adresi: str
    ilk_gorulme: datetime = field(default_factory=datetime.now)
    son_gorulme: datetime = field(default_factory=datetime.now)
    toplam_etkilesim: int = 0
    kullanilan_honeypotlar: List[str] = field(default_factory=list)
    erişilen_honeytokenlar: List[str] = field(default_factory=list)
    davranis_kaliplari: List[SaldirganDavranisi] = field(default_factory=list)
    mitre_teknikleri: List[str] = field(default_factory=list)
    araclar: List[str] = field(default_factory=list)
    parmak_izi: Dict[str, Any] = field(default_factory=dict)
    user_agent_listesi: List[str] = field(default_factory=list)
    risk_skoru: float = 0.0
    ulke: str = ""
    asn: str = ""
    notlar: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Sozluge donustur"""
        return {
            'id': self.id,
            'ip_adresi': self.ip_adresi,
            'ilk_gorulme': self.ilk_gorulme.isoformat() if self.ilk_gorulme else None,
            'son_gorulme': self.son_gorulme.isoformat() if self.son_gorulme else None,
            'toplam_etkilesim': self.toplam_etkilesim,
            'kullanilan_honeypotlar': self.kullanilan_honeypotlar,
            'davranis_kaliplari': [d.value for d in self.davranis_kaliplari],
            'mitre_teknikleri': self.mitre_teknikleri,
            'araclar': self.araclar,
            'risk_skoru': self.risk_skoru,
            'ulke': self.ulke
        }


@dataclass
class DeceptionAlarm:
    """Aldatma sistemi alarmi"""
    id: str
    tip: str
    kaynak_ip: str
    hedef: str  # Honeypot/Honeytoken ID
    seviye: AlarmSeviyesi
    mesaj: str
    zaman: datetime = field(default_factory=datetime.now)
    detaylar: Dict[str, Any] = field(default_factory=dict)
    islendi: bool = False
    soar_tetiklendi: bool = False

    def to_dict(self) -> Dict:
        """Sozluge donustur"""
        return {
            'id': self.id,
            'tip': self.tip,
            'kaynak_ip': self.kaynak_ip,
            'hedef': self.hedef,
            'seviye': self.seviye.value,
            'mesaj': self.mesaj,
            'zaman': self.zaman.isoformat() if self.zaman else None,
            'detaylar': self.detaylar,
            'islendi': self.islendi
        }


@dataclass
class OturumKaydi:
    """Saldirgan oturum kaydi"""
    id: str
    saldirgan_ip: str
    honeypot_id: str
    baslangic: datetime = field(default_factory=datetime.now)
    bitis: Optional[datetime] = None
    komutlar: List[Dict[str, Any]] = field(default_factory=list)
    dosya_transferleri: List[Dict[str, Any]] = field(default_factory=list)
    network_aktivite: List[Dict[str, Any]] = field(default_factory=list)
    ham_veri: bytes = field(default_factory=bytes)


# ============================================================================
# MITRE ATT&CK HARITALAMA
# ============================================================================

class MitreAttackMapper:
    """
    MITRE ATT&CK Framework haritalayicisi.
    Gozlemlenen davranislari ATT&CK tekniklerine esler.
    """

    # Taktik ve teknik haritasi
    TAKTIKLER = {
        'TA0043': 'Reconnaissance',
        'TA0042': 'Resource Development',
        'TA0001': 'Initial Access',
        'TA0002': 'Execution',
        'TA0003': 'Persistence',
        'TA0004': 'Privilege Escalation',
        'TA0005': 'Defense Evasion',
        'TA0006': 'Credential Access',
        'TA0007': 'Discovery',
        'TA0008': 'Lateral Movement',
        'TA0009': 'Collection',
        'TA0011': 'Command and Control',
        'TA0010': 'Exfiltration',
        'TA0040': 'Impact'
    }

    # Davranis -> Teknik haritasi
    DAVRANIS_TEKNIK_HARITASI = {
        # SSH honeypot davranislari
        'ssh_brute_force': ['T1110.001', 'T1110.003'],  # Brute Force
        'ssh_login_success': ['T1078'],                 # Valid Accounts
        'ssh_command_exec': ['T1059.004'],              # Unix Shell
        'ssh_file_transfer': ['T1105'],                 # Ingress Tool Transfer
        'ssh_port_forward': ['T1572'],                  # Protocol Tunneling

        # HTTP honeypot davranislari
        'http_scan': ['T1595.002'],                     # Active Scanning
        'http_dir_traversal': ['T1083'],               # File and Directory Discovery
        'http_sql_injection': ['T1190'],               # Exploit Public-Facing App
        'http_xss': ['T1189'],                         # Drive-by Compromise
        'http_file_upload': ['T1105'],                 # Ingress Tool Transfer
        'http_admin_access': ['T1078'],                # Valid Accounts

        # FTP honeypot davranislari
        'ftp_brute_force': ['T1110.001'],
        'ftp_anonymous': ['T1078.001'],                # Default Accounts
        'ftp_file_download': ['T1083', 'T1005'],       # Data from Local System
        'ftp_file_upload': ['T1105'],

        # SMB honeypot davranislari
        'smb_enum': ['T1135'],                         # Network Share Discovery
        'smb_brute_force': ['T1110.001'],
        'smb_lateral': ['T1021.002'],                  # SMB/Windows Admin Shares
        'smb_psexec': ['T1569.002'],                   # Service Execution

        # RDP honeypot davranislari
        'rdp_brute_force': ['T1110.001'],
        'rdp_login': ['T1021.001'],                    # Remote Desktop Protocol
        'rdp_clipboard': ['T1115'],                    # Clipboard Data

        # Genel davranislar
        'port_scan': ['T1046'],                        # Network Service Discovery
        'credential_dump': ['T1003'],                  # OS Credential Dumping
        'data_staging': ['T1074'],                     # Data Staged
        'c2_beacon': ['T1071'],                        # Application Layer Protocol
    }

    @classmethod
    def davranis_haritalama(cls, davranis: str) -> List[str]:
        """Davranisi MITRE ATT&CK tekniklerine haritalandir"""
        return cls.DAVRANIS_TEKNIK_HARITASI.get(davranis, [])

    @classmethod
    def taktik_getir(cls, teknik_id: str) -> str:
        """Teknik ID'sinden taktigi getir"""
        # Basitlestirilmis haritalama
        taktik_haritasi = {
            'T1110': 'TA0006',  # Credential Access
            'T1078': 'TA0001',  # Initial Access
            'T1059': 'TA0002',  # Execution
            'T1105': 'TA0011',  # Command and Control
            'T1083': 'TA0007',  # Discovery
            'T1190': 'TA0001',  # Initial Access
            'T1046': 'TA0007',  # Discovery
            'T1021': 'TA0008',  # Lateral Movement
            'T1135': 'TA0007',  # Discovery
        }

        # Teknik prefixi al
        prefix = teknik_id.split('.')[0]
        return cls.TAKTIKLER.get(
            taktik_haritasi.get(prefix, ''),
            'Unknown'
        )


# ============================================================================
# HONEYTOKEN URETICI
# ============================================================================

class HoneytokenGenerator:
    """
    Honeytoken (tuzak veri) uretici.
    Gercekci gorunen sahte kimlik bilgileri, API anahtarlari ve belgeler uretir.
    """

    # Gercekci kullanici adlari
    KULLANICI_ADLARI = [
        'admin', 'administrator', 'root', 'user', 'test', 'backup',
        'service', 'deploy', 'jenkins', 'gitlab', 'docker', 'kubernetes',
        'mysql', 'postgres', 'oracle', 'redis', 'mongodb', 'elastic',
        'api_user', 'api_service', 'readonly', 'developer', 'devops',
        'sysadmin', 'netadmin', 'dbadmin', 'secadmin', 'webmaster',
        'ftpuser', 'sftpuser', 'guest', 'demo', 'support', 'helpdesk',
        'monitor', 'prometheus', 'grafana', 'nagios', 'zabbix'
    ]

    # Gercekci sifre kaliplari
    SIFRE_KALIPLARI = [
        '{word}{year}!',
        '{word}_{number}',
        '{Word}@{year}',
        '{word}{number}#{year}',
        'P@ss{word}{number}',
        '{Company}{year}!',
        '{word}123!',
        '{Word}_{Company}_{year}',
        'Admin{year}!',
        '{word}!{year}'
    ]

    # API anahtar formatlari
    API_FORMATLARI = {
        'generic': 'sk_{random_32}',
        'stripe': 'sk_live_{random_24}',
        'github': 'ghp_{random_36}',
        'slack': 'xoxb-{number}-{number}-{random_24}',
        'sendgrid': 'SG.{random_22}.{random_43}',
        'twilio': 'SK{random_32}',
        'mailgun': 'key-{random_32}',
        'datadog': '{random_32}'
    }

    # AWS anahtar formati
    AWS_ACCESS_KEY_PREFIX = 'AKIA'
    AWS_SECRET_LENGTH = 40

    def __init__(self):
        self._uretilen_tokenlar: Dict[str, Honeytoken] = {}

    def credential_uret(self, kullanici_adi: str = None) -> Honeytoken:
        """Sahte kimlik bilgisi uret"""
        if not kullanici_adi:
            kullanici_adi = secrets.choice(self.KULLANICI_ADLARI)

        # Gercekci sifre olustur
        kalip = secrets.choice(self.SIFRE_KALIPLARI)
        kelimeler = ['Summer', 'Winter', 'Spring', 'Autumn', 'Admin', 'User',
                    'Password', 'Secure', 'System', 'Database', 'Server']
        sirketler = ['Corp', 'Tech', 'Systems', 'Data', 'Cloud', 'Net']

        sifre = kalip.format(
            word=secrets.choice(kelimeler).lower(),
            Word=secrets.choice(kelimeler),
            year=str(datetime.now().year),
            number=secrets.randbelow(1000),
            Company=secrets.choice(sirketler)
        )

        token_id = f"cred_{secrets.token_hex(8)}"
        deger = f"{kullanici_adi}:{sifre}"

        token = Honeytoken(
            id=token_id,
            tip=HoneytokenTipi.CREDENTIAL,
            deger=deger,
            aciklama=f"Sahte kimlik bilgisi: {kullanici_adi}",
            metadata={
                'kullanici_adi': kullanici_adi,
                'sifre': sifre,
                'hash': hashlib.sha256(sifre.encode()).hexdigest()
            }
        )

        self._uretilen_tokenlar[token_id] = token
        return token

    def api_key_uret(self, servis: str = 'generic') -> Honeytoken:
        """Sahte API anahtari uret"""
        format_str = self.API_FORMATLARI.get(servis, self.API_FORMATLARI['generic'])

        # Formati doldur
        def rastgele_degistir(match):
            param = match.group(1)
            if param.startswith('random_'):
                uzunluk = int(param.split('_')[1])
                return secrets.token_hex(uzunluk // 2)
            elif param == 'number':
                return str(secrets.randbelow(999999999999))
            return match.group(0)

        anahtar = re.sub(r'\{(\w+)\}', rastgele_degistir, format_str)

        token_id = f"api_{secrets.token_hex(8)}"
        token = Honeytoken(
            id=token_id,
            tip=HoneytokenTipi.API_KEY,
            deger=anahtar,
            aciklama=f"Sahte {servis} API anahtari",
            metadata={
                'servis': servis,
                'format': format_str
            }
        )

        self._uretilen_tokenlar[token_id] = token
        return token

    def aws_key_uret(self) -> Honeytoken:
        """Sahte AWS anahtari uret"""
        # Access Key ID (AKIA ile baslar, 20 karakter)
        access_key = self.AWS_ACCESS_KEY_PREFIX + secrets.token_hex(8).upper()

        # Secret Access Key (40 karakter, base64-like)
        charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        secret_key = ''.join(secrets.choice(charset) for _ in range(self.AWS_SECRET_LENGTH))

        token_id = f"aws_{secrets.token_hex(8)}"
        token = Honeytoken(
            id=token_id,
            tip=HoneytokenTipi.AWS_KEY,
            deger=f"AWS_ACCESS_KEY_ID={access_key}\nAWS_SECRET_ACCESS_KEY={secret_key}",
            aciklama="Sahte AWS kimlik bilgileri",
            metadata={
                'access_key_id': access_key,
                'secret_access_key': secret_key,
                'region': 'us-east-1'
            }
        )

        self._uretilen_tokenlar[token_id] = token
        return token

    def database_connection_uret(self, db_tipi: str = 'mysql') -> Honeytoken:
        """Sahte veritabani baglanti bilgisi uret"""
        host = f"db-{secrets.token_hex(4)}.internal.corp"
        port_map = {'mysql': 3306, 'postgres': 5432, 'mongodb': 27017, 'redis': 6379}
        port = port_map.get(db_tipi, 3306)

        kullanici = secrets.choice(['db_admin', 'app_user', 'readonly', 'replication'])
        sifre = secrets.token_urlsafe(16)

        connection_string = {
            'mysql': f"mysql://{kullanici}:{sifre}@{host}:{port}/production",
            'postgres': f"postgresql://{kullanici}:{sifre}@{host}:{port}/production",
            'mongodb': f"mongodb://{kullanici}:{sifre}@{host}:{port}/admin",
            'redis': f"redis://:{sifre}@{host}:{port}/0"
        }

        token_id = f"db_{secrets.token_hex(8)}"
        token = Honeytoken(
            id=token_id,
            tip=HoneytokenTipi.DATABASE,
            deger=connection_string.get(db_tipi, connection_string['mysql']),
            aciklama=f"Sahte {db_tipi} veritabani baglantisi",
            metadata={
                'db_tipi': db_tipi,
                'host': host,
                'port': port,
                'kullanici': kullanici
            }
        )

        self._uretilen_tokenlar[token_id] = token
        return token

    def ssh_key_uret(self) -> Honeytoken:
        """Sahte SSH private key uret"""
        # Basitlestirilmis sahte SSH key (gercek format ama gecersiz)
        fake_key = f"""-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEA{secrets.token_hex(64)}
{secrets.token_hex(64)}
{secrets.token_hex(64)}
{secrets.token_hex(32)}
-----END OPENSSH PRIVATE KEY-----"""

        token_id = f"ssh_{secrets.token_hex(8)}"
        token = Honeytoken(
            id=token_id,
            tip=HoneytokenTipi.SSH_KEY,
            deger=fake_key,
            aciklama="Sahte SSH private key",
            metadata={
                'key_type': 'rsa',
                'bits': 2048,
                'comment': 'admin@server.internal'
            }
        )

        self._uretilen_tokenlar[token_id] = token
        return token

    def document_uret(self, baslik: str = None) -> Honeytoken:
        """Sahte belge icerigi uret"""
        if not baslik:
            basliklar = [
                'Gizli_Proje_Detaylari',
                'Finansal_Rapor_2024',
                'Musteri_Veritabani_Yedek',
                'Sistem_Sifreleri',
                'VPN_Konfigurasyonu',
                'Sunucu_Erisim_Bilgileri',
                'API_Dokumantasyonu_Internal'
            ]
            baslik = secrets.choice(basliklar)

        # Sahte belge icerigi
        icerik = f"""# {baslik}
## Gizli - Sadece Yetkili Personel

Olusturma Tarihi: {datetime.now().strftime('%Y-%m-%d')}
Siniflandirma: GIZLI

### Erisim Bilgileri
- Sunucu: svr-prod-{secrets.token_hex(4)}.internal
- Kullanici: admin_{secrets.token_hex(4)}
- Sifre: {secrets.token_urlsafe(16)}

### Notlar
Bu belge sirket ici kullanim icindir.
Yetkisiz paylasim yasaktir.
"""

        token_id = f"doc_{secrets.token_hex(8)}"
        token = Honeytoken(
            id=token_id,
            tip=HoneytokenTipi.DOCUMENT,
            deger=icerik,
            aciklama=f"Sahte belge: {baslik}",
            metadata={
                'baslik': baslik,
                'format': 'markdown',
                'boyut': len(icerik)
            }
        )

        self._uretilen_tokenlar[token_id] = token
        return token

    def bitcoin_wallet_uret(self) -> Honeytoken:
        """Sahte Bitcoin cuzdan bilgisi uret"""
        # Sahte seed phrase (12 kelime)
        kelimeler = [
            'abandon', 'ability', 'able', 'about', 'above', 'absent',
            'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
            'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire',
            'across', 'act', 'action', 'actor', 'actress', 'actual'
        ]
        seed = ' '.join(secrets.choice(kelimeler) for _ in range(12))

        # Sahte Bitcoin adresi
        adres = '1' + secrets.token_hex(16)[:33]

        token_id = f"btc_{secrets.token_hex(8)}"
        token = Honeytoken(
            id=token_id,
            tip=HoneytokenTipi.BITCOIN_WALLET,
            deger=f"Seed: {seed}\nAddress: {adres}",
            aciklama="Sahte Bitcoin cuzdan bilgileri",
            metadata={
                'seed_phrase': seed,
                'address': adres,
                'network': 'mainnet'
            }
        )

        self._uretilen_tokenlar[token_id] = token
        return token

    def toplu_uret(self, adet: int = 10) -> List[Honeytoken]:
        """Karisik honeytokenlar uret"""
        tokenlar = []
        ureticiler = [
            self.credential_uret,
            self.api_key_uret,
            self.aws_key_uret,
            self.database_connection_uret,
            self.ssh_key_uret,
            self.document_uret
        ]

        for _ in range(adet):
            uretici = secrets.choice(ureticiler)
            token = uretici()
            tokenlar.append(token)

        return tokenlar

    def tum_tokenlar(self) -> Dict[str, Honeytoken]:
        """Uretilmis tum tokenlari getir"""
        return self._uretilen_tokenlar.copy()


# ============================================================================
# SAHTE DOSYA SISTEMI
# ============================================================================

class DecoyFileSystem:
    """
    Gercekci gorunen sahte dosya sistemi.
    Saldirganlari cekecek tuzak dosyalar ve dizinler.
    """

    # Cezbedici dosya adlari
    CEZBEDICI_DOSYALAR = {
        'credentials': [
            'passwords.txt', 'credentials.csv', '.passwd', 'shadow.bak',
            'logins.xlsx', 'secrets.json', '.htpasswd', 'users.sql'
        ],
        'config': [
            'config.yml', '.env', 'settings.ini', 'database.yml',
            'wp-config.php.bak', 'web.config.old', 'app.config'
        ],
        'keys': [
            'id_rsa', 'private.key', 'server.key', '.ssh/id_rsa',
            'ssl.pem', 'jwt_secret.key', 'api_keys.txt'
        ],
        'database': [
            'backup.sql', 'dump.sql', 'users.db', 'data.sqlite',
            'production.sql.gz', 'customers.csv'
        ],
        'documents': [
            'budget_2024.xlsx', 'salaries.csv', 'contracts.pdf',
            'strategic_plan.docx', 'merger_details.pptx'
        ]
    }

    # Cezbedici dizin adlari
    CEZBEDICI_DIZINLER = [
        'backup', 'backups', 'old', 'archive', 'temp', 'tmp',
        'private', 'secret', 'confidential', 'admin', 'root',
        'config', 'configs', '.git', '.svn', 'logs', 'data',
        'database', 'db', 'sql', 'uploads', 'files'
    ]

    def __init__(self, temel_dizin: str = "/tmp/honeypot_fs"):
        self.temel_dizin = temel_dizin
        self._dosya_haritasi: Dict[str, str] = {}  # dosya_yolu -> token_id
        self._token_generator = HoneytokenGenerator()

    def olustur(self) -> Dict[str, Any]:
        """Sahte dosya sistemi olustur"""
        import shutil

        # Temiz baslangic
        if os.path.exists(self.temel_dizin):
            shutil.rmtree(self.temel_dizin)
        os.makedirs(self.temel_dizin, mode=0o755)

        olusturulan = {
            'dizinler': [],
            'dosyalar': [],
            'tokenlar': []
        }

        # Cezbedici dizinleri olustur
        for dizin in secrets.SystemRandom().sample(self.CEZBEDICI_DIZINLER, 5):
            dizin_yolu = os.path.join(self.temel_dizin, dizin)
            os.makedirs(dizin_yolu, mode=0o755, exist_ok=True)
            olusturulan['dizinler'].append(dizin_yolu)

            # Her dizine dosyalar ekle
            for kategori, dosyalar in self.CEZBEDICI_DOSYALAR.items():
                secilen_dosya = secrets.choice(dosyalar)
                dosya_yolu = os.path.join(dizin_yolu, secilen_dosya)

                # Token olustur ve dosya icerigini ayarla
                if kategori == 'credentials':
                    token = self._token_generator.credential_uret()
                    icerik = self._credential_dosyasi_olustur()
                elif kategori == 'keys':
                    token = self._token_generator.ssh_key_uret()
                    icerik = token.deger
                elif kategori == 'config':
                    token = self._token_generator.database_connection_uret()
                    icerik = self._config_dosyasi_olustur(token)
                else:
                    token = self._token_generator.document_uret()
                    icerik = token.deger

                # Dosyayi yaz
                with open(dosya_yolu, 'w') as f:
                    f.write(icerik)

                self._dosya_haritasi[dosya_yolu] = token.id
                olusturulan['dosyalar'].append(dosya_yolu)
                olusturulan['tokenlar'].append(token.id)

        return olusturulan

    def _credential_dosyasi_olustur(self) -> str:
        """Sahte credential dosyasi icerigi"""
        satirlar = []
        for _ in range(10):
            token = self._token_generator.credential_uret()
            satirlar.append(token.deger)
        return '\n'.join(satirlar)

    def _config_dosyasi_olustur(self, token: Honeytoken) -> str:
        """Sahte config dosyasi icerigi"""
        return f"""# Uygulama Konfigurasyonu
# DIKKAT: Bu dosya hassas bilgiler icerir

[database]
connection_string = {token.deger}

[api]
secret_key = {secrets.token_hex(32)}
admin_password = {secrets.token_urlsafe(16)}

[aws]
access_key = AKIA{secrets.token_hex(8).upper()}
secret_key = {secrets.token_urlsafe(40)}
region = eu-west-1
"""

    def dosya_erisim_kontrol(self, dosya_yolu: str) -> Optional[str]:
        """Dosya erisimi kontrol et ve token ID dondur"""
        return self._dosya_haritasi.get(dosya_yolu)

    def breadcrumb_birak(self, konum: str, hedef: str) -> str:
        """Saldirgan yolunda breadcrumb (izleme parcasi) birak"""
        breadcrumb = f"""# Dikkat
# Daha fazla bilgi icin: {hedef}
# Erisim: ssh admin@{hedef}
# Sifre: {secrets.token_urlsafe(12)}
"""
        dosya_yolu = os.path.join(konum, '.notes.txt')
        with open(dosya_yolu, 'w') as f:
            f.write(breadcrumb)

        return dosya_yolu


# ============================================================================
# HONEYPOT ORKESTRATORU
# ============================================================================

class HoneypotOrchestrator:
    """
    Dinamik honeypot yonetim sistemi.
    SSH, HTTP, FTP, SMB, RDP gibi servisleri simule eder.
    """

    # Varsayilan port yapilandirmalari
    VARSAYILAN_PORTLAR = {
        HoneypotTipi.SSH: 22,
        HoneypotTipi.HTTP: 80,
        HoneypotTipi.HTTPS: 443,
        HoneypotTipi.FTP: 21,
        HoneypotTipi.SMB: 445,
        HoneypotTipi.RDP: 3389,
        HoneypotTipi.MYSQL: 3306,
        HoneypotTipi.TELNET: 23,
        HoneypotTipi.DNS: 53,
        HoneypotTipi.SMTP: 25
    }

    def __init__(self):
        self._honeypotlar: Dict[str, Honeypot] = {}
        self._etkilesim_loglari: List[Dict] = []
        self._alarm_callback: Optional[Callable] = None
        self._kilit = threading.Lock()
        self._calistiriliyor = False
        self._socketler: Dict[str, socket.socket] = {}

        # Alt sistemler
        self._token_generator = HoneytokenGenerator()
        self._decoy_fs = DecoyFileSystem()

        logger.info("[DECEPTION] Honeypot Orkestratoru baslatildi")

    def alarm_callback_ayarla(self, callback: Callable):
        """Alarm callback fonksiyonunu ayarla"""
        self._alarm_callback = callback

    def honeypot_dagit(self,
                       tip: HoneypotTipi,
                       ip: str = "0.0.0.0",
                       port: int = None,
                       yapilandirma: Dict = None) -> Honeypot:
        """
        Yeni honeypot dagit.

        Args:
            tip: Honeypot tipi (SSH, HTTP, FTP, vb.)
            ip: Dinlenecek IP adresi
            port: Port numarasi (varsayilan tip'e gore)
            yapilandirma: Ek yapilandirma parametreleri

        Returns:
            Olusturulan Honeypot nesnesi
        """
        if port is None:
            port = self.VARSAYILAN_PORTLAR.get(tip, 8080)

        honeypot_id = f"hp_{tip.value}_{secrets.token_hex(4)}"

        honeypot = Honeypot(
            id=honeypot_id,
            tip=tip,
            ip=ip,
            port=port,
            yapilandirma=yapilandirma or {},
            etiketler=[tip.value, 'auto-deployed']
        )

        with self._kilit:
            self._honeypotlar[honeypot_id] = honeypot

        logger.info(f"[DECEPTION] Honeypot dagitildi: {tip.value} @ {ip}:{port}")

        # Honeypot'u baslat
        self._honeypot_baslat(honeypot)

        return honeypot

    def get_stats(self) -> Dict[str, Any]:
        """Honeypot istatistikleri (dalga_web.py uyumlulugu)"""
        active = sum(1 for hp in self._honeypotlar.values() if hp.aktif)
        total_interactions = sum(hp.toplam_etkilesim for hp in self._honeypotlar.values())
        unique_ips = set(log.get('kaynak_ip') for log in self._etkilesim_loglari)

        cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
        recent = [log for log in self._etkilesim_loglari
                  if log.get('zaman', '') > cutoff]

        tip_counts = {}
        for hp in self._honeypotlar.values():
            tip_counts[hp.tip.value] = tip_counts.get(hp.tip.value, 0) + hp.toplam_etkilesim
        most_targeted = max(tip_counts, key=tip_counts.get) if tip_counts else 'none'

        return {
            'active_honeypots': active,
            'total_interactions': total_interactions,
            'unique_attackers': len(unique_ips),
            'last_24h_interactions': len(recent),
            'most_targeted_service': most_targeted
        }

    def get_attacker_locations(self, limit: int = 200) -> List[Dict]:
        """Saldirgan konum bilgileri (dalga_web.py uyumlulugu)"""
        ip_data = {}
        for log in self._etkilesim_loglari:
            ip = log.get('kaynak_ip', '')
            if not ip:
                continue
            if ip not in ip_data:
                ip_data[ip] = {
                    'ip': ip,
                    'first_seen': log.get('zaman', ''),
                    'last_seen': log.get('zaman', ''),
                    'count': 0,
                    'services': set()
                }
            ip_data[ip]['last_seen'] = log.get('zaman', '')
            ip_data[ip]['count'] += 1
            ip_data[ip]['services'].add(log.get('honeypot_tip', ''))

        result = []
        for data in sorted(ip_data.values(), key=lambda x: x['count'], reverse=True)[:limit]:
            result.append({
                'lat': 0.0,
                'lng': 0.0,
                'ip': data['ip'],
                'country': '',
                'city': '',
                'targeted_service': ', '.join(data['services']),
                'risk_score': min(data['count'] / 10.0, 1.0),
                'first_seen': data['first_seen'],
                'last_seen': data['last_seen'],
                'interaction_count': data['count']
            })
        return result

    def _honeypot_baslat(self, honeypot: Honeypot):
        """Honeypot servisini baslat"""
        try:
            # Basit TCP listener olustur (gercek implementasyonda
            # her tip icin ozel handler gerekir)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(1.0)

            try:
                sock.bind((honeypot.ip, honeypot.port))
                sock.listen(5)
                self._socketler[honeypot.id] = sock

                # Baglanti kabul thread'i
                thread = threading.Thread(
                    target=self._baglanti_kabul_dongusu,
                    args=(honeypot,),
                    daemon=True
                )
                thread.start()

            except OSError as e:
                logger.warning(f"[DECEPTION] Port {honeypot.port} kullanimda: {e}")
                honeypot.aktif = False

        except Exception as e:
            logger.error(f"[DECEPTION] Honeypot baslatilamadi: {e}")
            honeypot.aktif = False

    def _baglanti_kabul_dongusu(self, honeypot: Honeypot):
        """Baglantilari kabul et"""
        sock = self._socketler.get(honeypot.id)
        if not sock:
            return

        while honeypot.aktif and self._calistiriliyor:
            try:
                client_sock, client_addr = sock.accept()
                client_ip = client_addr[0]

                # Etkilesim kaydet
                self._etkilesim_kaydet(honeypot, client_ip)

                # Tip'e gore yanit ver
                self._honeypot_yanit(honeypot, client_sock, client_ip)

                client_sock.close()

            except socket.timeout:
                continue
            except Exception as e:
                if honeypot.aktif:
                    logger.debug(f"[DECEPTION] Baglanti hatasi: {e}")

    def _honeypot_yanit(self, honeypot: Honeypot, client_sock: socket.socket, client_ip: str):
        """Honeypot tipine gore yanit ver"""
        try:
            # Veri al (timeout ile)
            client_sock.settimeout(5.0)
            data = client_sock.recv(4096)

            if honeypot.tip == HoneypotTipi.SSH:
                # SSH banner gonder
                client_sock.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")

            elif honeypot.tip == HoneypotTipi.HTTP:
                # HTTP yaniti
                response = b"""HTTP/1.1 200 OK\r
Server: Apache/2.4.41 (Ubuntu)\r
Content-Type: text/html\r
\r
<html><head><title>Welcome</title></head>
<body><h1>Under Construction</h1></body></html>"""
                client_sock.send(response)

            elif honeypot.tip == HoneypotTipi.FTP:
                client_sock.send(b"220 FTP Server Ready\r\n")

            elif honeypot.tip == HoneypotTipi.TELNET:
                client_sock.send(b"Ubuntu 20.04.3 LTS\r\nlogin: ")

            elif honeypot.tip == HoneypotTipi.SMTP:
                client_sock.send(b"220 mail.example.com ESMTP Postfix\r\n")

            # Gelen veriyi logla
            if data:
                self._veri_analiz(honeypot, client_ip, data)

        except Exception as e:
            logger.debug(f"[DECEPTION] Yanit hatasi: {e}")

    def _etkilesim_kaydet(self, honeypot: Honeypot, client_ip: str):
        """Honeypot etkilesimi kaydet"""
        with self._kilit:
            honeypot.toplam_etkilesim += 1
            honeypot.son_etkilesim = datetime.now()

            log_kaydi = {
                'zaman': datetime.now().isoformat(),
                'honeypot_id': honeypot.id,
                'honeypot_tip': honeypot.tip.value,
                'kaynak_ip': client_ip,
                'port': honeypot.port
            }
            self._etkilesim_loglari.append(log_kaydi)

            # Son 10000 kayit tut
            if len(self._etkilesim_loglari) > 10000:
                self._etkilesim_loglari = self._etkilesim_loglari[-10000:]

        # Alarm olustur
        self._alarm_olustur(
            tip='honeypot_erisim',
            kaynak_ip=client_ip,
            hedef=honeypot.id,
            seviye=AlarmSeviyesi.ORTA,
            mesaj=f"{honeypot.tip.value} honeypot'a erisim: {client_ip}",
            detaylar={'honeypot_tip': honeypot.tip.value, 'port': honeypot.port}
        )

    def _veri_analiz(self, honeypot: Honeypot, client_ip: str, data: bytes):
        """Gelen veriyi analiz et"""
        try:
            veri_str = data.decode('utf-8', errors='ignore')

            # SSH brute force tespiti
            if honeypot.tip == HoneypotTipi.SSH and 'password' in veri_str.lower():
                self._alarm_olustur(
                    tip='ssh_brute_force',
                    kaynak_ip=client_ip,
                    hedef=honeypot.id,
                    seviye=AlarmSeviyesi.YUKSEK,
                    mesaj=f"SSH brute force denemesi: {client_ip}",
                    detaylar={'data_preview': veri_str[:100]}
                )

            # HTTP saldiri tespiti
            if honeypot.tip == HoneypotTipi.HTTP:
                if '../' in veri_str or '..\\' in veri_str:
                    self._alarm_olustur(
                        tip='http_dir_traversal',
                        kaynak_ip=client_ip,
                        hedef=honeypot.id,
                        seviye=AlarmSeviyesi.YUKSEK,
                        mesaj=f"Directory traversal denemesi: {client_ip}",
                        detaylar={'payload': veri_str[:200]}
                    )

                if "'" in veri_str or '"' in veri_str:
                    sql_patterns = ['union', 'select', 'drop', 'insert', '--', 'or 1=1']
                    if any(p in veri_str.lower() for p in sql_patterns):
                        self._alarm_olustur(
                            tip='http_sql_injection',
                            kaynak_ip=client_ip,
                            hedef=honeypot.id,
                            seviye=AlarmSeviyesi.KRITIK,
                            mesaj=f"SQL injection denemesi: {client_ip}",
                            detaylar={'payload': veri_str[:200]}
                        )

        except Exception as e:
            logger.debug(f"[DECEPTION] Veri analiz hatasi: {e}")

    def _alarm_olustur(self,
                       tip: str,
                       kaynak_ip: str,
                       hedef: str,
                       seviye: AlarmSeviyesi,
                       mesaj: str,
                       detaylar: Dict = None):
        """Alarm olustur ve callback'i cagir"""
        alarm = DeceptionAlarm(
            id=f"alrm_{secrets.token_hex(6)}",
            tip=tip,
            kaynak_ip=kaynak_ip,
            hedef=hedef,
            seviye=seviye,
            mesaj=mesaj,
            detaylar=detaylar or {}
        )

        if self._alarm_callback:
            try:
                self._alarm_callback(alarm)
            except Exception as e:
                logger.error(f"[DECEPTION] Alarm callback hatasi: {e}")

        logger.info(f"[DECEPTION] ALARM [{seviye.value}]: {mesaj}")

        return alarm

    def honeypot_listele(self) -> List[Dict]:
        """Aktif honeypotlari listele"""
        with self._kilit:
            return [hp.to_dict() for hp in self._honeypotlar.values()]

    def honeypot_kaldir(self, honeypot_id: str) -> bool:
        """Honeypot'u kaldir"""
        with self._kilit:
            if honeypot_id not in self._honeypotlar:
                return False

            honeypot = self._honeypotlar[honeypot_id]
            honeypot.aktif = False

            # Socket'i kapat
            if honeypot_id in self._socketler:
                try:
                    self._socketler[honeypot_id].close()
                except Exception:
                    pass
                del self._socketler[honeypot_id]

            del self._honeypotlar[honeypot_id]

        logger.info(f"[DECEPTION] Honeypot kaldirildi: {honeypot_id}")
        return True

    def honeytoken_olustur(self, tip: HoneytokenTipi, **kwargs) -> Honeytoken:
        """Yeni honeytoken olustur"""
        if tip == HoneytokenTipi.CREDENTIAL:
            return self._token_generator.credential_uret(kwargs.get('kullanici_adi'))
        elif tip == HoneytokenTipi.API_KEY:
            return self._token_generator.api_key_uret(kwargs.get('servis', 'generic'))
        elif tip == HoneytokenTipi.AWS_KEY:
            return self._token_generator.aws_key_uret()
        elif tip == HoneytokenTipi.DATABASE:
            return self._token_generator.database_connection_uret(kwargs.get('db_tipi', 'mysql'))
        elif tip == HoneytokenTipi.SSH_KEY:
            return self._token_generator.ssh_key_uret()
        elif tip == HoneytokenTipi.DOCUMENT:
            return self._token_generator.document_uret(kwargs.get('baslik'))
        elif tip == HoneytokenTipi.BITCOIN_WALLET:
            return self._token_generator.bitcoin_wallet_uret()
        else:
            return self._token_generator.credential_uret()

    def honeytoken_kontrol(self, deger: str) -> Optional[Honeytoken]:
        """Degerin bir honeytoken olup olmadigini kontrol et"""
        for token in self._token_generator.tum_tokenlar().values():
            if deger in token.deger or token.deger in deger:
                # Erisim kaydet
                token.erisim_sayisi += 1
                token.son_erisim = datetime.now()

                # Alarm
                self._alarm_olustur(
                    tip='honeytoken_erisim',
                    kaynak_ip='unknown',
                    hedef=token.id,
                    seviye=AlarmSeviyesi.KRITIK,
                    mesaj=f"Honeytoken erisimldi: {token.tip.value}",
                    detaylar={'token_tip': token.tip.value}
                )

                return token

        return None

    def decoy_fs_olustur(self) -> Dict[str, Any]:
        """Sahte dosya sistemi olustur"""
        return self._decoy_fs.olustur()

    def baslat(self):
        """Orkestratoru baslat"""
        self._calistiriliyor = True
        logger.info("[DECEPTION] Honeypot Orkestratoru calistiriliyor")

    def durdur(self):
        """Orkestratoru durdur"""
        self._calistiriliyor = False

        # Tum socketleri kapat
        for hp_id, sock in self._socketler.items():
            try:
                sock.close()
            except Exception:
                pass

        # Honeypotlari pasif yap
        for hp in self._honeypotlar.values():
            hp.aktif = False

        self._socketler.clear()
        logger.info("[DECEPTION] Honeypot Orkestratoru durduruldu")

    def etkilesim_loglari(self, limit: int = 100) -> List[Dict]:
        """Son etkilesim loglarini getir"""
        with self._kilit:
            return self._etkilesim_loglari[-limit:]


# ============================================================================
# SALDIRGAN PROFILLEME
# ============================================================================

class AttackerProfiler:
    """
    Saldirgan profilleme ve TTP cikarim motoru.
    Honeypot etkilesimlerinden saldirgan parmak izi cikarir.
    """

    def __init__(self):
        self._profiller: Dict[str, SaldirganProfili] = {}
        self._oturum_kayitlari: Dict[str, OturumKaydi] = {}
        self._mitre_mapper = MitreAttackMapper()
        self._kilit = threading.Lock()

    def etkilesim_isle(self,
                       kaynak_ip: str,
                       honeypot_id: str,
                       honeypot_tip: str,
                       veri: Dict[str, Any] = None) -> SaldirganProfili:
        """
        Honeypot etkilesimini isle ve profili guncelle.

        Args:
            kaynak_ip: Saldirganin IP adresi
            honeypot_id: Etkilesilen honeypot ID'si
            honeypot_tip: Honeypot tipi
            veri: Etkilesim verisi

        Returns:
            Guncellenmis saldirgan profili
        """
        veri = veri or {}

        with self._kilit:
            # Profil var mi kontrol et
            if kaynak_ip not in self._profiller:
                self._profiller[kaynak_ip] = SaldirganProfili(
                    id=f"atk_{secrets.token_hex(6)}",
                    ip_adresi=kaynak_ip
                )

            profil = self._profiller[kaynak_ip]

            # Profili guncelle
            profil.son_gorulme = datetime.now()
            profil.toplam_etkilesim += 1

            if honeypot_id not in profil.kullanilan_honeypotlar:
                profil.kullanilan_honeypotlar.append(honeypot_id)

            # User-Agent kaydet
            user_agent = veri.get('user_agent', '')
            if user_agent and user_agent not in profil.user_agent_listesi:
                profil.user_agent_listesi.append(user_agent)

            # Davranis analizi
            self._davranis_analiz(profil, honeypot_tip, veri)

            # Risk skoru guncelle
            profil.risk_skoru = self._risk_skoru_hesapla(profil)

            return profil

    def _davranis_analiz(self, profil: SaldirganProfili, honeypot_tip: str, veri: Dict):
        """Saldirgan davranisini analiz et"""
        davranis = None
        mitre_teknikler = []

        # Honeypot tipine gore davranis belirle
        if honeypot_tip == 'ssh':
            if veri.get('brute_force'):
                davranis = SaldirganDavranisi.ERISIM_DENEMESI
                mitre_teknikler = self._mitre_mapper.davranis_haritalama('ssh_brute_force')
            elif veri.get('komut_calistirma'):
                davranis = SaldirganDavranisi.LATERAL_HAREKET
                mitre_teknikler = self._mitre_mapper.davranis_haritalama('ssh_command_exec')

        elif honeypot_tip == 'http':
            if veri.get('tarama'):
                davranis = SaldirganDavranisi.KEŞIF
                mitre_teknikler = self._mitre_mapper.davranis_haritalama('http_scan')
            elif veri.get('sql_injection'):
                davranis = SaldirganDavranisi.ERISIM_DENEMESI
                mitre_teknikler = self._mitre_mapper.davranis_haritalama('http_sql_injection')

        elif honeypot_tip == 'smb':
            if veri.get('enumeration'):
                davranis = SaldirganDavranisi.KEŞIF
                mitre_teknikler = self._mitre_mapper.davranis_haritalama('smb_enum')

        # Davranis ve teknikleri kaydet
        if davranis and davranis not in profil.davranis_kaliplari:
            profil.davranis_kaliplari.append(davranis)

        for teknik in mitre_teknikler:
            if teknik not in profil.mitre_teknikleri:
                profil.mitre_teknikleri.append(teknik)

        # Arac tespiti (User-Agent'tan)
        user_agent = veri.get('user_agent', '').lower()
        arac_imzalari = {
            'nmap': 'nmap',
            'nikto': 'nikto',
            'sqlmap': 'sqlmap',
            'burp': 'burp_suite',
            'gobuster': 'gobuster',
            'dirb': 'dirb',
            'masscan': 'masscan',
            'hydra': 'hydra',
            'metasploit': 'metasploit',
            'curl': 'curl',
            'wget': 'wget',
            'python-requests': 'python_requests'
        }

        for imza, arac in arac_imzalari.items():
            if imza in user_agent and arac not in profil.araclar:
                profil.araclar.append(arac)

    def _risk_skoru_hesapla(self, profil: SaldirganProfili) -> float:
        """Saldirgan risk skorunu hesapla (0.0 - 1.0)"""
        skor = 0.0

        # Etkilesim sayisina gore
        skor += min(profil.toplam_etkilesim / 100, 0.3)

        # Kullanilan honeypot sayisina gore
        skor += min(len(profil.kullanilan_honeypotlar) / 5, 0.2)

        # Davranis cesitliligine gore
        skor += min(len(profil.davranis_kaliplari) / 5, 0.2)

        # MITRE teknik sayisina gore
        skor += min(len(profil.mitre_teknikleri) / 10, 0.2)

        # Arac kullanimi
        skor += min(len(profil.araclar) / 5, 0.1)

        return min(skor, 1.0)

    def oturum_baslat(self, kaynak_ip: str, honeypot_id: str) -> str:
        """Yeni saldirgan oturumu baslat"""
        oturum_id = f"ses_{secrets.token_hex(8)}"

        oturum = OturumKaydi(
            id=oturum_id,
            saldirgan_ip=kaynak_ip,
            honeypot_id=honeypot_id
        )

        with self._kilit:
            self._oturum_kayitlari[oturum_id] = oturum

        return oturum_id

    def oturum_komut_ekle(self, oturum_id: str, komut: str, cikti: str = ""):
        """Oturuma komut kaydi ekle"""
        with self._kilit:
            if oturum_id in self._oturum_kayitlari:
                self._oturum_kayitlari[oturum_id].komutlar.append({
                    'zaman': datetime.now().isoformat(),
                    'komut': komut,
                    'cikti': cikti
                })

    def oturum_bitir(self, oturum_id: str):
        """Oturumu sonlandir"""
        with self._kilit:
            if oturum_id in self._oturum_kayitlari:
                self._oturum_kayitlari[oturum_id].bitis = datetime.now()

    def parmak_izi_cikar(self, kaynak_ip: str) -> Dict[str, Any]:
        """Saldirgan parmak izi cikar"""
        with self._kilit:
            if kaynak_ip not in self._profiller:
                return {}

            profil = self._profiller[kaynak_ip]

            return {
                'ip': kaynak_ip,
                'toplam_etkilesim': profil.toplam_etkilesim,
                'ilk_gorulme': profil.ilk_gorulme.isoformat(),
                'son_gorulme': profil.son_gorulme.isoformat(),
                'honeypotlar': profil.kullanilan_honeypotlar,
                'davranislar': [d.value for d in profil.davranis_kaliplari],
                'mitre_teknikleri': profil.mitre_teknikleri,
                'araclar': profil.araclar,
                'user_agents': profil.user_agent_listesi,
                'risk_skoru': profil.risk_skoru,
                'ttp_ozeti': self._ttp_ozeti_olustur(profil)
            }

    def _ttp_ozeti_olustur(self, profil: SaldirganProfili) -> Dict[str, Any]:
        """TTP (Taktik, Teknik, Prosedur) ozeti olustur"""
        taktikler = set()
        for teknik in profil.mitre_teknikleri:
            taktik = self._mitre_mapper.taktik_getir(teknik)
            if taktik != 'Unknown':
                taktikler.add(taktik)

        return {
            'taktikler': list(taktikler),
            'teknikler': profil.mitre_teknikleri,
            'prosedurler': profil.araclar,
            'davranis_kaliplari': [d.value for d in profil.davranis_kaliplari]
        }

    def tum_profiller(self) -> List[Dict]:
        """Tum saldirgan profillerini listele"""
        with self._kilit:
            return [p.to_dict() for p in self._profiller.values()]

    def profil_getir(self, ip_adresi: str) -> Optional[Dict]:
        """IP adresine gore profil getir"""
        with self._kilit:
            if ip_adresi in self._profiller:
                return self._profiller[ip_adresi].to_dict()
        return None

    def oturum_tekrar_oynat(self, oturum_id: str) -> List[Dict]:
        """Oturum kaydini tekrar oynat (komut gecmisi)"""
        with self._kilit:
            if oturum_id in self._oturum_kayitlari:
                return self._oturum_kayitlari[oturum_id].komutlar
        return []


# ============================================================================
# ALARM SISTEMI
# ============================================================================

class DeceptionAlertSystem:
    """
    Aldatma sistemi alarm yonetimi.
    Gercek zamanli bildirimler ve SOAR entegrasyonu.
    """

    def __init__(self):
        self._alarmlar: List[DeceptionAlarm] = []
        self._soar_endpoint: Optional[str] = None
        self._webhook_url: Optional[str] = None
        self._kilit = threading.Lock()
        self._beyin_callback: Optional[Callable] = None

    def beyin_callback_ayarla(self, callback: Callable):
        """TSUNAMI Beyin callback'ini ayarla"""
        self._beyin_callback = callback

    def soar_ayarla(self, endpoint: str):
        """SOAR endpoint ayarla"""
        self._soar_endpoint = endpoint

    def webhook_ayarla(self, url: str):
        """Webhook URL ayarla"""
        self._webhook_url = url

    def alarm_isle(self, alarm: DeceptionAlarm):
        """Alarmi isle ve bildirimleri gonder"""
        with self._kilit:
            self._alarmlar.append(alarm)

            # Son 5000 alarm tut
            if len(self._alarmlar) > 5000:
                self._alarmlar = self._alarmlar[-5000:]

        # Ciddiyet seviyesine gore islem
        if alarm.seviye in [AlarmSeviyesi.KRITIK, AlarmSeviyesi.YUKSEK]:
            self._acil_bildirim(alarm)

        # SOAR entegrasyonu
        if self._soar_endpoint and alarm.seviye == AlarmSeviyesi.KRITIK:
            self._soar_tetikle(alarm)

        # TSUNAMI Beyin bildirimi
        if self._beyin_callback:
            try:
                self._beyin_callback(alarm)
            except Exception as e:
                logger.error(f"[DECEPTION] Beyin callback hatasi: {e}")

        # Webhook bildirimi
        if self._webhook_url:
            self._webhook_gonder(alarm)

    def _acil_bildirim(self, alarm: DeceptionAlarm):
        """Acil durum bildirimi"""
        logger.warning(f"[DECEPTION] ACIL ALARM: {alarm.mesaj}")
        # Burada SMS, email veya diger bildirim mekanizmalari tetiklenebilir

    def _soar_tetikle(self, alarm: DeceptionAlarm):
        """SOAR playbook tetikle"""
        if not self._soar_endpoint:
            return

        import urllib.request
        import urllib.error

        try:
            veri = json.dumps(alarm.to_dict()).encode()
            istek = urllib.request.Request(
                self._soar_endpoint,
                data=veri,
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(istek, timeout=10)
            alarm.soar_tetiklendi = True
            logger.info(f"[DECEPTION] SOAR playbook tetiklendi: {alarm.id}")
        except Exception as e:
            logger.error(f"[DECEPTION] SOAR tetikleme hatasi: {e}")

    def _webhook_gonder(self, alarm: DeceptionAlarm):
        """Webhook bildirimi gonder"""
        if not self._webhook_url:
            return

        import urllib.request
        import urllib.error

        try:
            veri = json.dumps({
                'source': 'TSUNAMI_DECEPTION',
                'alarm': alarm.to_dict(),
                'timestamp': datetime.now().isoformat()
            }).encode()

            istek = urllib.request.Request(
                self._webhook_url,
                data=veri,
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(istek, timeout=10)
        except Exception as e:
            logger.debug(f"[DECEPTION] Webhook hatasi: {e}")

    def alarmlar_listele(self,
                         seviye: AlarmSeviyesi = None,
                         limit: int = 100) -> List[Dict]:
        """Alarmlari listele"""
        with self._kilit:
            sonuclar = []
            for alarm in reversed(self._alarmlar):
                if seviye and alarm.seviye != seviye:
                    continue
                sonuclar.append(alarm.to_dict())
                if len(sonuclar) >= limit:
                    break
            return sonuclar

    def alarm_isaretle(self, alarm_id: str) -> bool:
        """Alarmi islenmis olarak isaretle"""
        with self._kilit:
            for alarm in self._alarmlar:
                if alarm.id == alarm_id:
                    alarm.islendi = True
                    return True
        return False

    def istatistikler(self) -> Dict[str, Any]:
        """Alarm istatistikleri"""
        with self._kilit:
            seviye_sayilari = defaultdict(int)
            tip_sayilari = defaultdict(int)

            for alarm in self._alarmlar:
                seviye_sayilari[alarm.seviye.value] += 1
                tip_sayilari[alarm.tip] += 1

            return {
                'toplam': len(self._alarmlar),
                'islenmemis': sum(1 for a in self._alarmlar if not a.islendi),
                'seviye_dagilimi': dict(seviye_sayilari),
                'tip_dagilimi': dict(tip_sayilari),
                'son_alarm': self._alarmlar[-1].to_dict() if self._alarmlar else None
            }


# ============================================================================
# ANA DECEPTION SISTEMI
# ============================================================================

class DeceptionSystem:
    """
    TSUNAMI Deception (Aldatma) Ana Sistemi.
    Tum alt sistemleri koordine eden merkezi sinif.
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
        # Alt sistemler
        self.orchestrator = HoneypotOrchestrator()
        self.profiler = AttackerProfiler()
        self.alert_system = DeceptionAlertSystem()
        self.token_generator = HoneytokenGenerator()
        self.decoy_fs = DecoyFileSystem()

        # Alarm callback'i ayarla
        self.orchestrator.alarm_callback_ayarla(self.alert_system.alarm_isle)

        # TSUNAMI Beyin entegrasyonu
        self._beyin = None
        self._socketio = None

        logger.info("[DECEPTION] TSUNAMI Deception Sistemi baslatildi")

    def beyin_bagla(self, beyin):
        """TSUNAMI Beyin sistemine baglan"""
        self._beyin = beyin

        # Beyin callback'i ayarla
        def beyin_alarm_handler(alarm: DeceptionAlarm):
            if self._beyin:
                # Tehdit skorunu guncelle
                ciddiyet_skor = {
                    AlarmSeviyesi.KRITIK: 0.95,
                    AlarmSeviyesi.YUKSEK: 0.75,
                    AlarmSeviyesi.ORTA: 0.50,
                    AlarmSeviyesi.DUSUK: 0.25,
                    AlarmSeviyesi.BILGI: 0.10
                }
                skor = ciddiyet_skor.get(alarm.seviye, 0.25)

                self._beyin.tehdit_bildir('deception', {
                    'saldiri': {
                        'tip': alarm.tip,
                        'ciddiyet': alarm.seviye.value,
                        'port': alarm.detaylar.get('port', 0),
                        'protokol': 'TCP'
                    },
                    'kaynak': {
                        'ip': alarm.kaynak_ip,
                        'ulke': 'Unknown'
                    },
                    'hedef': {
                        'sehir': 'Istanbul',
                        'ip': '127.0.0.1'
                    },
                    'zaman': alarm.zaman.isoformat()
                })

        self.alert_system.beyin_callback_ayarla(beyin_alarm_handler)

    def socketio_bagla(self, socketio):
        """Socket.IO bagla"""
        self._socketio = socketio

    def baslat(self):
        """Sistemi baslat"""
        self.orchestrator.baslat()

        # Varsayilan honeypotlari dagit
        try:
            self.orchestrator.honeypot_dagit(HoneypotTipi.SSH, port=2222)
            self.orchestrator.honeypot_dagit(HoneypotTipi.HTTP, port=8080)
            self.orchestrator.honeypot_dagit(HoneypotTipi.FTP, port=2121)
        except Exception as e:
            logger.warning(f"[DECEPTION] Varsayilan honeypot dagitim hatasi: {e}")

        logger.info("[DECEPTION] Sistem calistiriliyor")

    def durdur(self):
        """Sistemi durdur"""
        self.orchestrator.durdur()
        logger.info("[DECEPTION] Sistem durduruldu")

    def durum_ozeti(self) -> Dict[str, Any]:
        """Sistem durum ozeti"""
        return {
            'aktif': self.orchestrator._calistiriliyor,
            'honeypotlar': len(self.orchestrator._honeypotlar),
            'honeytokenlar': len(self.token_generator.tum_tokenlar()),
            'saldirgan_profilleri': len(self.profiler._profiller),
            'toplam_etkilesim': sum(hp.toplam_etkilesim for hp in self.orchestrator._honeypotlar.values()),
            'alarm_istatistikleri': self.alert_system.istatistikler(),
            'son_guncelleme': datetime.now().isoformat()
        }


# ============================================================================
# FLASK API BLUEPRINT
# ============================================================================

if FLASK_AVAILABLE:
    deception_bp = Blueprint('deception', __name__, url_prefix='/api/v1/deception')

    def _deception_al():
        """Deception sistemi instance'i al"""
        return DeceptionSystem.get_instance()

    @deception_bp.route('/honeypots', methods=['GET'])
    def honeypot_listele():
        """Aktif honeypotlari listele"""
        sistem = _deception_al()
        return jsonify({
            'basarili': True,
            'honeypotlar': sistem.orchestrator.honeypot_listele()
        })

    @deception_bp.route('/deploy', methods=['POST'])
    def honeypot_dagit():
        """Yeni honeypot dagit"""
        sistem = _deception_al()
        data = request.get_json() or {}

        tip_str = data.get('tip', 'http')
        try:
            tip = HoneypotTipi(tip_str)
        except ValueError:
            return jsonify({
                'basarili': False,
                'hata': f'Gecersiz honeypot tipi: {tip_str}'
            }), 400

        ip = data.get('ip', '0.0.0.0')
        port = data.get('port')
        yapilandirma = data.get('yapilandirma', {})

        try:
            honeypot = sistem.orchestrator.honeypot_dagit(
                tip=tip,
                ip=ip,
                port=port,
                yapilandirma=yapilandirma
            )
            return jsonify({
                'basarili': True,
                'honeypot': honeypot.to_dict()
            })
        except Exception as e:
            return jsonify({
                'basarili': False,
                'hata': str(e)
            }), 500

    @deception_bp.route('/honeypots/<honeypot_id>', methods=['DELETE'])
    def honeypot_kaldir(honeypot_id):
        """Honeypot kaldir"""
        sistem = _deception_al()

        if sistem.orchestrator.honeypot_kaldir(honeypot_id):
            return jsonify({'basarili': True})
        else:
            return jsonify({
                'basarili': False,
                'hata': 'Honeypot bulunamadi'
            }), 404

    @deception_bp.route('/alerts', methods=['GET'])
    def alarm_listele():
        """Son alarmlari listele"""
        sistem = _deception_al()
        limit = request.args.get('limit', 100, type=int)
        seviye = request.args.get('seviye')

        seviye_enum = None
        if seviye:
            try:
                seviye_enum = AlarmSeviyesi(seviye)
            except ValueError:
                pass

        return jsonify({
            'basarili': True,
            'alarmlar': sistem.alert_system.alarmlar_listele(seviye_enum, limit),
            'istatistikler': sistem.alert_system.istatistikler()
        })

    @deception_bp.route('/alerts/<alarm_id>/mark', methods=['POST'])
    def alarm_isaretle(alarm_id):
        """Alarmi islenmis olarak isaretle"""
        sistem = _deception_al()

        if sistem.alert_system.alarm_isaretle(alarm_id):
            return jsonify({'basarili': True})
        else:
            return jsonify({
                'basarili': False,
                'hata': 'Alarm bulunamadi'
            }), 404

    @deception_bp.route('/attackers', methods=['GET'])
    def saldirgan_listele():
        """Profillenmis saldirganlari listele"""
        sistem = _deception_al()
        return jsonify({
            'basarili': True,
            'saldirganlar': sistem.profiler.tum_profiller()
        })

    @deception_bp.route('/attackers/<ip_adresi>', methods=['GET'])
    def saldirgan_detay(ip_adresi):
        """Saldirgan profil detayi"""
        sistem = _deception_al()
        profil = sistem.profiler.profil_getir(ip_adresi)

        if profil:
            parmak_izi = sistem.profiler.parmak_izi_cikar(ip_adresi)
            return jsonify({
                'basarili': True,
                'profil': profil,
                'parmak_izi': parmak_izi
            })
        else:
            return jsonify({
                'basarili': False,
                'hata': 'Saldirgan profili bulunamadi'
            }), 404

    @deception_bp.route('/honeytokens', methods=['POST'])
    def honeytoken_olustur():
        """Yeni honeytoken olustur"""
        sistem = _deception_al()
        data = request.get_json() or {}

        tip_str = data.get('tip', 'credential')
        try:
            tip = HoneytokenTipi(tip_str)
        except ValueError:
            return jsonify({
                'basarili': False,
                'hata': f'Gecersiz honeytoken tipi: {tip_str}'
            }), 400

        token = sistem.orchestrator.honeytoken_olustur(tip, **data)
        return jsonify({
            'basarili': True,
            'honeytoken': token.to_dict()
        })

    @deception_bp.route('/honeytokens', methods=['GET'])
    def honeytoken_listele():
        """Honeytokenlari listele"""
        sistem = _deception_al()
        tokenlar = sistem.token_generator.tum_tokenlar()
        return jsonify({
            'basarili': True,
            'honeytokenlar': [t.to_dict() for t in tokenlar.values()]
        })

    @deception_bp.route('/honeytokens/check', methods=['POST'])
    def honeytoken_kontrol():
        """Deger honeytoken mi kontrol et"""
        sistem = _deception_al()
        data = request.get_json() or {}
        deger = data.get('deger', '')

        token = sistem.orchestrator.honeytoken_kontrol(deger)
        if token:
            return jsonify({
                'basarili': True,
                'honeytoken': True,
                'detay': token.to_dict()
            })
        else:
            return jsonify({
                'basarili': True,
                'honeytoken': False
            })

    @deception_bp.route('/decoy-fs', methods=['POST'])
    def decoy_fs_olustur():
        """Sahte dosya sistemi olustur"""
        sistem = _deception_al()

        sonuc = sistem.decoy_fs.olustur()
        return jsonify({
            'basarili': True,
            'sonuc': sonuc
        })

    @deception_bp.route('/status', methods=['GET'])
    def durum():
        """Sistem durumu"""
        sistem = _deception_al()
        return jsonify({
            'basarili': True,
            'durum': sistem.durum_ozeti()
        })

    @deception_bp.route('/interactions', methods=['GET'])
    def etkilesim_listele():
        """Honeypot etkilesim loglarini listele"""
        sistem = _deception_al()
        limit = request.args.get('limit', 100, type=int)

        return jsonify({
            'basarili': True,
            'etkilesimler': sistem.orchestrator.etkilesim_loglari(limit)
        })


# ============================================================================
# SINGLETON ERISIM
# ============================================================================

_deception_system = None

def deception_al() -> DeceptionSystem:
    """Deception sistemi instance'i al"""
    global _deception_system
    if _deception_system is None:
        _deception_system = DeceptionSystem.get_instance()
    return _deception_system


# ============================================================================
# CLI TEST
# ============================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser(description="TSUNAMI Deception System")
    parser.add_argument('--demo', action='store_true', help='Demo modu calistir')
    args = parser.parse_args()

    if args.demo:
        print("\n" + "="*60)
        print("TSUNAMI DECEPTION SYSTEM - Demo")
        print("="*60 + "\n")

        sistem = deception_al()

        # Honeypot dagit
        print("[1] Honeypot dagitimi...")
        hp = sistem.orchestrator.honeypot_dagit(HoneypotTipi.HTTP, port=18080)
        print(f"    Dagitildi: {hp.id} @ port {hp.port}")

        # Honeytoken olustur
        print("\n[2] Honeytoken uretimi...")
        cred = sistem.token_generator.credential_uret()
        print(f"    Credential: {cred.id}")

        aws = sistem.token_generator.aws_key_uret()
        print(f"    AWS Key: {aws.id}")

        api = sistem.token_generator.api_key_uret('github')
        print(f"    API Key: {api.id}")

        # Sahte dosya sistemi
        print("\n[3] Decoy dosya sistemi olusturma...")
        fs_sonuc = sistem.decoy_fs.olustur()
        print(f"    Dizinler: {len(fs_sonuc['dizinler'])}")
        print(f"    Dosyalar: {len(fs_sonuc['dosyalar'])}")

        # Durum ozeti
        print("\n[4] Sistem durumu:")
        durum = sistem.durum_ozeti()
        print(f"    Honeypotlar: {durum['honeypotlar']}")
        print(f"    Honeytokenlar: {durum['honeytokenlar']}")

        print("\n" + "="*60)
        print("Demo tamamlandi. Ctrl+C ile cikis yapin.")
        print("="*60)

        # Calistir
        sistem.baslat()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nDurduruluyor...")
            sistem.durdur()
