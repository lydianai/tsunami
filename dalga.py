#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██████╗  █████╗ ██╗      ██████╗  █████╗                                   ║
║   ██╔══██╗██╔══██╗██║     ██╔════╝ ██╔══██╗                                  ║
║   ██║  ██║███████║██║     ██║  ███╗███████║                                  ║
║   ██║  ██║██╔══██║██║     ██║   ██║██╔══██║                                  ║
║   ██████╔╝██║  ██║███████╗╚██████╔╝██║  ██║                                  ║
║   ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝                                  ║
║                                                                              ║
║   🌊 DALGA v1.0 - Kablosuz Sinyal İstihbarat Platformu                       ║
║   📡 Pasif OSINT | WiFi | Bluetooth | Hücresel | IoT                         ║
║                                                                              ║
║   ⚠️  SADECE ETİK VE YASAL KULLANIM İÇİN                                     ║
║   📜 Orijinal Türk Yazılımı - AILYDIAN Projesi                               ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

DALGA - Kablosuz Sinyal İstihbarat ve Analiz Platformu

Özellikler:
- WiFi ağ tarama ve haritalama (yerel + API)
- Bluetooth cihaz tespiti
- Baz istasyonu analizi
- IoT cihaz sınıflandırma
- Pasif sinyal toplama
- Şifreli veri depolama
- Türkçe arayüz
- CLI + Web arayüzü

Gereksinimler:
- Linux (Ubuntu/Debian/Kali)
- Python 3.8+
- iwlist, iw, hcitool (opsiyonel)
- Flask (web arayüzü için)

Lisans: Özel kullanım - AILYDIAN
"""

import os
import sys
import json
import sqlite3
import hashlib
import secrets
import subprocess
import threading
import time
import re
import socket
import struct
import base64
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
import urllib.request
import urllib.parse
import ssl

# ==================== YAPILANDIRMA ====================
DALGA_VERSION = "1.0.0"
DALGA_CODENAME = "Tsunami"

# Dizinler
DALGA_HOME = Path.home() / ".dalga"
DALGA_DB = DALGA_HOME / "dalga.db"
DALGA_LOGS = DALGA_HOME / "logs"
DALGA_EXPORTS = DALGA_HOME / "exports"
DALGA_KEYS = DALGA_HOME / ".keys"

# ==================== RENKLER ====================
class Renk:
    """Terminal renk kodları"""
    KIRMIZI = '\033[91m'
    YESIL = '\033[92m'
    SARI = '\033[93m'
    MAVI = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    BEYAZ = '\033[97m'
    KALIN = '\033[1m'
    SOLUK = '\033[2m'
    ALTI_CIZILI = '\033[4m'
    SIFIRLA = '\033[0m'

    # Readline uyumlu
    RL_CYAN = '\001\033[96m\002'
    RL_YESIL = '\001\033[92m\002'
    RL_SIFIRLA = '\001\033[0m\002'

# ==================== GÜVENLİK ====================
class GuvenlikYoneticisi:
    """Şifreleme ve güvenlik işlemleri"""

    def __init__(self):
        self.anahtar_dosya = DALGA_KEYS / "master.key"
        self._anahtar: Optional[bytes] = None
        self._hazirla()

    def _hazirla(self):
        """Güvenlik altyapısını hazırla"""
        DALGA_KEYS.mkdir(parents=True, exist_ok=True)
        os.chmod(DALGA_KEYS, 0o700)

        if not self.anahtar_dosya.exists():
            anahtar = secrets.token_bytes(32)
            self.anahtar_dosya.write_bytes(anahtar)
            os.chmod(self.anahtar_dosya, 0o600)

    @property
    def anahtar(self) -> bytes:
        """Ana şifreleme anahtarı"""
        if self._anahtar is None:
            self._anahtar = self.anahtar_dosya.read_bytes()
        return self._anahtar

    def sifrele(self, veri: str) -> str:
        """Basit XOR şifreleme (demo için)"""
        if not veri:
            return ""
        veri_bytes = veri.encode('utf-8')
        anahtar_genisletilmis = (self.anahtar * ((len(veri_bytes) // 32) + 1))[:len(veri_bytes)]
        sifreli = bytes(a ^ b for a, b in zip(veri_bytes, anahtar_genisletilmis))
        return base64.b64encode(sifreli).decode('ascii')

    def coz(self, sifreli: str) -> str:
        """Şifre çözme"""
        if not sifreli:
            return ""
        try:
            sifreli_bytes = base64.b64decode(sifreli.encode('ascii'))
            anahtar_genisletilmis = (self.anahtar * ((len(sifreli_bytes) // 32) + 1))[:len(sifreli_bytes)]
            cozulmus = bytes(a ^ b for a, b in zip(sifreli_bytes, anahtar_genisletilmis))
            return cozulmus.decode('utf-8')
        except Exception:
            return ""

    def hash_olustur(self, veri: str) -> str:
        """SHA-256 hash"""
        return hashlib.sha256(veri.encode()).hexdigest()

# ==================== VERİTABANI ====================
class DalgaVeritabani:
    """SQLite veritabanı yönetimi"""

    def __init__(self, db_yolu: Path = DALGA_DB):
        self.db_yolu = db_yolu
        self.db_yolu.parent.mkdir(parents=True, exist_ok=True)
        self._baglanti: Optional[sqlite3.Connection] = None
        self._tablolari_olustur()

    @property
    def baglanti(self) -> sqlite3.Connection:
        if self._baglanti is None:
            self._baglanti = sqlite3.connect(str(self.db_yolu), check_same_thread=False)
            self._baglanti.row_factory = sqlite3.Row
        return self._baglanti

    def _tablolari_olustur(self):
        """Veritabanı tablolarını oluştur"""
        cursor = self.baglanti.cursor()

        # WiFi ağlar tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS wifi_aglar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bssid TEXT UNIQUE NOT NULL,
                ssid TEXT,
                kanal INTEGER,
                sinyal_gucu INTEGER,
                sifreleme TEXT,
                satici TEXT,
                ilk_gorulme TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                son_gorulme TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                enlem REAL,
                boylam REAL,
                notlar TEXT
            )
        """)

        # Bluetooth cihazlar tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS bluetooth_cihazlar (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_adresi TEXT UNIQUE NOT NULL,
                cihaz_adi TEXT,
                cihaz_tipi TEXT,
                sinif TEXT,
                sinyal_gucu INTEGER,
                ilk_gorulme TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                son_gorulme TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                kategori TEXT,
                notlar TEXT
            )
        """)

        # Baz istasyonları tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS baz_istasyonlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cell_id TEXT UNIQUE NOT NULL,
                lac INTEGER,
                mcc INTEGER,
                mnc INTEGER,
                radyo_tipi TEXT,
                sinyal_gucu INTEGER,
                enlem REAL,
                boylam REAL,
                operator TEXT,
                ilk_gorulme TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                son_gorulme TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Tarama geçmişi
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tarama_gecmisi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tarama_tipi TEXT NOT NULL,
                tarih TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                bulunan_cihaz_sayisi INTEGER,
                sure_saniye REAL,
                parametreler TEXT,
                durum TEXT
            )
        """)

        # API anahtarları (şifreli)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_anahtarlari (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                servis_adi TEXT UNIQUE NOT NULL,
                api_anahtar TEXT,
                api_secret TEXT,
                son_kullanim TIMESTAMP,
                aktif INTEGER DEFAULT 1
            )
        """)

        self.baglanti.commit()

    def wifi_kaydet(self, wifi_veri: Dict) -> int:
        """WiFi ağını kaydet veya güncelle"""
        cursor = self.baglanti.cursor()
        cursor.execute("""
            INSERT INTO wifi_aglar (bssid, ssid, kanal, sinyal_gucu, sifreleme, satici, enlem, boylam)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bssid) DO UPDATE SET
                ssid = excluded.ssid,
                kanal = excluded.kanal,
                sinyal_gucu = excluded.sinyal_gucu,
                son_gorulme = CURRENT_TIMESTAMP
        """, (
            wifi_veri.get('bssid'),
            wifi_veri.get('ssid'),
            wifi_veri.get('kanal'),
            wifi_veri.get('sinyal'),
            wifi_veri.get('sifreleme'),
            wifi_veri.get('satici'),
            wifi_veri.get('enlem'),
            wifi_veri.get('boylam')
        ))
        self.baglanti.commit()
        return cursor.lastrowid

    def bluetooth_kaydet(self, bt_veri: Dict) -> int:
        """Bluetooth cihazını kaydet veya güncelle"""
        cursor = self.baglanti.cursor()
        cursor.execute("""
            INSERT INTO bluetooth_cihazlar (mac_adresi, cihaz_adi, cihaz_tipi, sinif, sinyal_gucu, kategori)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac_adresi) DO UPDATE SET
                cihaz_adi = excluded.cihaz_adi,
                sinyal_gucu = excluded.sinyal_gucu,
                son_gorulme = CURRENT_TIMESTAMP
        """, (
            bt_veri.get('mac'),
            bt_veri.get('ad'),
            bt_veri.get('tip'),
            bt_veri.get('sinif'),
            bt_veri.get('sinyal'),
            bt_veri.get('kategori')
        ))
        self.baglanti.commit()
        return cursor.lastrowid

    def tum_wifi_getir(self, limit: int = 100) -> List[Dict]:
        """Kayıtlı WiFi ağlarını getir"""
        cursor = self.baglanti.cursor()
        cursor.execute("""
            SELECT * FROM wifi_aglar
            ORDER BY son_gorulme DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def tum_bluetooth_getir(self, limit: int = 100) -> List[Dict]:
        """Kayıtlı Bluetooth cihazlarını getir"""
        cursor = self.baglanti.cursor()
        cursor.execute("""
            SELECT * FROM bluetooth_cihazlar
            ORDER BY son_gorulme DESC
            LIMIT ?
        """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def api_anahtari_kaydet(self, servis: str, anahtar: str, secret: str = None, guvenlik: GuvenlikYoneticisi = None):
        """API anahtarını şifreli kaydet"""
        if guvenlik:
            anahtar = guvenlik.sifrele(anahtar)
            if secret:
                secret = guvenlik.sifrele(secret)

        cursor = self.baglanti.cursor()
        cursor.execute("""
            INSERT INTO api_anahtarlari (servis_adi, api_anahtar, api_secret)
            VALUES (?, ?, ?)
            ON CONFLICT(servis_adi) DO UPDATE SET
                api_anahtar = excluded.api_anahtar,
                api_secret = excluded.api_secret
        """, (servis, anahtar, secret))
        self.baglanti.commit()

    def api_anahtari_getir(self, servis: str, guvenlik: GuvenlikYoneticisi = None) -> Tuple[str, str]:
        """API anahtarını getir ve çöz"""
        cursor = self.baglanti.cursor()
        cursor.execute("SELECT api_anahtar, api_secret FROM api_anahtarlari WHERE servis_adi = ? AND aktif = 1", (servis,))
        row = cursor.fetchone()
        if row:
            anahtar = row['api_anahtar']
            secret = row['api_secret']
            if guvenlik:
                anahtar = guvenlik.coz(anahtar) if anahtar else ""
                secret = guvenlik.coz(secret) if secret else ""
            return (anahtar, secret)
        return ("", "")

    def istatistikler(self) -> Dict:
        """Veritabanı istatistikleri"""
        cursor = self.baglanti.cursor()

        cursor.execute("SELECT COUNT(*) FROM wifi_aglar")
        wifi_sayisi = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM bluetooth_cihazlar")
        bt_sayisi = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM baz_istasyonlari")
        baz_sayisi = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM tarama_gecmisi")
        tarama_sayisi = cursor.fetchone()[0]

        return {
            'wifi_ag_sayisi': wifi_sayisi,
            'bluetooth_cihaz_sayisi': bt_sayisi,
            'baz_istasyonu_sayisi': baz_sayisi,
            'toplam_tarama': tarama_sayisi
        }

# ==================== CİHAZ SINIFLANDIRICI ====================
class CihazSiniflandirici:
    """Cihazları isim ve özelliklerine göre sınıflandır"""

    KATEGORILER = {
        'arac': [
            'tesla', 'ford', 'bmw', 'audi', 'mercedes', 'vw', 'volkswagen',
            'toyota', 'honda', 'sync', 'carplay', 'android auto', 'obd',
            'dashcam', '70mai', 'viofo', 'garmin dash', 'nexar', 'car'
        ],
        'televizyon': [
            'bravia', 'vizio', 'samsung tv', 'lg tv', 'roku', 'fire tv',
            'chromecast', 'apple tv', 'android tv', 'smart tv', 'webos',
            'tizen', 'philips tv', 'tcl', 'hisense'
        ],
        'kulaklik': [
            'airpods', 'bose', 'sony wh', 'sony wf', 'beats', 'jbl',
            'sennheiser', 'jabra', 'galaxy buds', 'pixel buds', 'earbuds',
            'headphone', 'earphone', 'headset'
        ],
        'kamera': [
            'nest cam', 'ring', 'arlo', 'hikvision', 'dahua', 'wyze',
            'blink', 'eufy', 'reolink', 'amcrest', 'ip cam', 'ipcam',
            'cctv', 'security cam', 'webcam', 'gopro'
        ],
        'iot': [
            'fitbit', 'garmin', 'whoop', 'mi band', 'amazfit', 'smartwatch',
            'apple watch', 'galaxy watch', 'nest', 'ring doorbell', 'ecobee',
            'philips hue', 'lifx', 'smart plug', 'alexa', 'echo', 'homepod',
            'google home', 'sonos', 'smart speaker'
        ],
        'bilgisayar': [
            'macbook', 'imac', 'dell', 'hp', 'lenovo', 'asus', 'acer',
            'thinkpad', 'surface', 'chromebook', 'laptop', 'desktop'
        ],
        'telefon': [
            'iphone', 'galaxy', 'pixel', 'oneplus', 'xiaomi', 'huawei',
            'oppo', 'vivo', 'realme', 'redmi', 'android', 'ios'
        ],
        'yazici': [
            'hp printer', 'canon', 'epson', 'brother', 'xerox', 'printer',
            'print', 'scan', 'mfp'
        ],
        'ag_cihazi': [
            'router', 'access point', 'ap', 'mesh', 'extender', 'repeater',
            'switch', 'gateway', 'modem', 'nas', 'synology', 'qnap'
        ]
    }

    SATICI_ONEKLERI = {
        '00:50:56': 'VMware',
        '00:0C:29': 'VMware',
        '00:1A:11': 'Google',
        '7C:D1:C3': 'Apple',
        'F4:5C:89': 'Apple',
        '00:17:88': 'Philips',
        'B8:27:EB': 'Raspberry Pi',
        'DC:A6:32': 'Raspberry Pi',
        '00:1E:C0': 'Microchip',
        '00:04:4B': 'Nvidia',
        '00:1B:63': 'Apple',
        '3C:06:30': 'Apple',
        '00:1F:F3': 'Apple',
        'AC:BC:32': 'Apple',
        '00:26:BB': 'Apple',
        'D4:F4:6F': 'Apple',
        '00:23:12': 'Apple',
        '70:56:81': 'Apple',
        '00:25:00': 'Apple',
        'BC:52:B7': 'Apple',
        '18:AF:61': 'Apple',
        '00:03:93': 'Apple',
        '00:16:CB': 'Apple',
        '00:19:E3': 'Apple',
        '00:1D:4F': 'Apple',
        '00:21:E9': 'Apple',
        '00:22:41': 'Apple',
        '00:24:36': 'Apple',
        '00:25:BC': 'Apple',
        '00:26:08': 'Apple',
        'F8:1E:DF': 'Apple',
        '54:AE:27': 'Apple',
        '00:CD:FE': 'Apple',
        '98:D6:BB': 'Apple',
        'E0:B9:BA': 'Apple',
        '28:6A:BA': 'Apple',
        '00:88:65': 'Apple',
        '00:03:FF': 'Microsoft',
        '00:12:5A': 'Microsoft',
        '00:15:5D': 'Microsoft',
        '00:17:FA': 'Microsoft',
        '00:1D:D8': 'Microsoft',
        '00:22:48': 'Microsoft',
        '00:25:AE': 'Microsoft',
        '00:50:F2': 'Microsoft',
        '28:18:78': 'Microsoft',
        '30:59:B7': 'Microsoft',
        '50:1A:C5': 'Microsoft',
        '58:82:A8': 'Microsoft',
        '60:45:BD': 'Microsoft',
        '7C:1E:52': 'Microsoft',
        '7C:ED:8D': 'Microsoft',
        '00:0D:3A': 'Microsoft',
        '00:0A:F7': 'Intel',
        '00:02:B3': 'Intel',
        '00:03:47': 'Intel',
        '00:04:23': 'Intel',
        '00:07:E9': 'Intel',
        '00:0C:F1': 'Intel',
        '00:0E:0C': 'Intel',
        '00:0E:35': 'Intel',
        '00:11:11': 'Intel',
        '00:12:F0': 'Intel',
        '00:13:02': 'Intel',
        '00:13:20': 'Intel',
        '00:13:CE': 'Intel',
        '00:13:E8': 'Intel',
        '00:15:00': 'Intel',
        '00:15:17': 'Intel',
        '00:16:6F': 'Intel',
        '00:16:76': 'Intel',
        '00:16:EA': 'Intel',
        '00:16:EB': 'Intel',
        '00:18:DE': 'Intel',
        '00:19:D1': 'Intel',
        '00:19:D2': 'Intel',
        '00:1B:21': 'Intel',
        '00:1B:77': 'Intel',
        '00:1C:BF': 'Intel',
        '00:1C:C0': 'Intel',
        '00:1D:E0': 'Intel',
        '00:1D:E1': 'Intel',
        '00:1E:64': 'Intel',
        '00:1E:65': 'Intel',
        '00:1E:67': 'Intel',
        '00:1F:3B': 'Intel',
        '00:1F:3C': 'Intel',
        '00:20:E0': 'Intel',
        '00:21:5C': 'Intel',
        '00:21:5D': 'Intel',
        '00:21:6A': 'Intel',
        '00:21:6B': 'Intel',
        '00:22:FA': 'Intel',
        '00:22:FB': 'Intel',
        '00:23:14': 'Intel',
        '00:23:15': 'Intel',
        '00:24:D6': 'Intel',
        '00:24:D7': 'Intel',
        '00:26:C6': 'Intel',
        '00:26:C7': 'Intel',
        '00:27:10': 'Intel',
        '24:77:03': 'Intel',
        '34:02:86': 'Intel',
        '3C:A9:F4': 'Intel',
        '40:25:C2': 'Intel',
        '4C:34:88': 'Intel',
        '5C:51:4F': 'Intel',
        '5C:D9:98': 'Intel',
        '60:57:18': 'Intel',
        '64:80:99': 'Intel',
        '68:05:CA': 'Intel',
        '6C:88:14': 'Intel',
        '78:92:9C': 'Intel',
        '7C:5C:F8': 'Intel',
        '84:3A:4B': 'Intel',
        '8C:70:5A': 'Intel',
        '94:65:9C': 'Intel',
        'A0:A8:CD': 'Intel',
        'A4:02:B9': 'Intel',
        'A4:4E:31': 'Intel',
        'A4:C4:94': 'Intel',
        'AC:7B:A1': 'Intel',
        'B4:B6:76': 'Intel',
        'B8:08:CF': 'Intel',
        'BC:77:37': 'Intel',
        'C4:85:08': 'Intel',
        'C8:0A:A9': 'Intel',
        'CC:3D:82': 'Intel',
        'D4:BE:D9': 'Intel',
        'D8:FC:93': 'Intel',
        'DC:53:60': 'Intel',
        'E0:94:67': 'Intel',
        'E4:B3:18': 'Intel',
        'EC:0E:C4': 'Intel',
        'F4:06:69': 'Intel',
        'F8:16:54': 'Intel',
        'F8:63:3F': 'Intel',
    }

    @classmethod
    def siniflandir(cls, cihaz_adi: str, orijinal_tip: str = None) -> str:
        """Cihazı kategorize et"""
        if not cihaz_adi:
            return orijinal_tip or 'bilinmeyen'

        ad_kucuk = cihaz_adi.lower()

        for kategori, anahtar_kelimeler in cls.KATEGORILER.items():
            for kelime in anahtar_kelimeler:
                if kelime in ad_kucuk:
                    return kategori

        return orijinal_tip or 'diger'

    @classmethod
    def satici_bul(cls, mac_adresi: str) -> str:
        """MAC adresinden satıcıyı bul"""
        if not mac_adresi:
            return 'Bilinmeyen'

        # İlk 3 oktet (OUI)
        mac_temiz = mac_adresi.upper().replace('-', ':')
        oui = ':'.join(mac_temiz.split(':')[:3])

        return cls.SATICI_ONEKLERI.get(oui, 'Bilinmeyen')

# ==================== YEREL TARAYICILAR ====================
class WiFiTarayici:
    """Yerel WiFi ağ tarayıcı (iwlist/iw kullanır)"""

    def __init__(self, arayuz: str = None):
        self.arayuz = arayuz or self._arayuz_bul()
        self.sonuclar: List[Dict] = []

    def _arayuz_bul(self) -> str:
        """Kablosuz arayüzü otomatik bul"""
        try:
            # iw ile kontrol
            sonuc = subprocess.run(
                ['iw', 'dev'],
                capture_output=True,
                text=True,
                timeout=5
            )

            if sonuc.returncode == 0:
                for satir in sonuc.stdout.split('\n'):
                    if 'Interface' in satir:
                        return satir.split()[-1]

            # /sys/class/net ile kontrol
            net_dizin = Path('/sys/class/net')
            for arayuz in net_dizin.iterdir():
                wireless_dizin = arayuz / 'wireless'
                if wireless_dizin.exists():
                    return arayuz.name

            # Varsayılan
            return 'wlan0'

        except Exception:
            return 'wlan0'

    def tara(self, sure_saniye: int = 10) -> List[Dict]:
        """WiFi ağlarını tara"""
        self.sonuclar = []

        # Önce iwlist dene
        try:
            sonuc = subprocess.run(
                ['sudo', 'iwlist', self.arayuz, 'scan'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if sonuc.returncode == 0:
                self.sonuclar = self._iwlist_parse(sonuc.stdout)
                return self.sonuclar
        except Exception:
            pass

        # iw ile dene
        try:
            sonuc = subprocess.run(
                ['sudo', 'iw', self.arayuz, 'scan'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if sonuc.returncode == 0:
                self.sonuclar = self._iw_parse(sonuc.stdout)
                return self.sonuclar
        except Exception:
            pass

        # nmcli ile dene
        try:
            sonuc = subprocess.run(
                ['nmcli', '-t', '-f', 'SSID,BSSID,CHAN,SIGNAL,SECURITY', 'dev', 'wifi', 'list'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if sonuc.returncode == 0:
                self.sonuclar = self._nmcli_parse(sonuc.stdout)
                return self.sonuclar
        except Exception:
            pass

        return self.sonuclar

    def _iwlist_parse(self, cikti: str) -> List[Dict]:
        """iwlist çıktısını parse et"""
        aglar = []
        mevcut_ag = {}

        for satir in cikti.split('\n'):
            satir = satir.strip()

            if 'Cell' in satir and 'Address:' in satir:
                if mevcut_ag:
                    aglar.append(mevcut_ag)
                mevcut_ag = {
                    'bssid': satir.split('Address:')[1].strip()
                }

            elif 'ESSID:' in satir:
                ssid = satir.split('ESSID:')[1].strip().strip('"')
                mevcut_ag['ssid'] = ssid if ssid else '<Gizli>'

            elif 'Channel:' in satir:
                try:
                    mevcut_ag['kanal'] = int(satir.split('Channel:')[1].strip())
                except ValueError:
                    pass

            elif 'Quality=' in satir:
                try:
                    quality_str = satir.split('Quality=')[1].split()[0]
                    if '/' in quality_str:
                        num, den = quality_str.split('/')
                        mevcut_ag['sinyal'] = int((int(num) / int(den)) * 100)
                except (ValueError, IndexError):
                    pass

            elif 'Signal level=' in satir:
                try:
                    level_str = satir.split('Signal level=')[1].split()[0]
                    mevcut_ag['sinyal_dbm'] = int(level_str)
                except (ValueError, IndexError):
                    pass

            elif 'Encryption key:' in satir:
                mevcut_ag['sifreleme'] = 'on' in satir.lower()

            elif 'IE: IEEE 802.11i/WPA2' in satir:
                mevcut_ag['sifreleme_tipi'] = 'WPA2'

            elif 'IE: WPA Version' in satir:
                if mevcut_ag.get('sifreleme_tipi') != 'WPA2':
                    mevcut_ag['sifreleme_tipi'] = 'WPA'

        if mevcut_ag:
            aglar.append(mevcut_ag)

        # Satıcı bilgisi ekle
        for ag in aglar:
            ag['satici'] = CihazSiniflandirici.satici_bul(ag.get('bssid', ''))

        return aglar

    def _iw_parse(self, cikti: str) -> List[Dict]:
        """iw scan çıktısını parse et"""
        aglar = []
        mevcut_ag = {}

        for satir in cikti.split('\n'):
            if satir.startswith('BSS '):
                if mevcut_ag:
                    aglar.append(mevcut_ag)
                bssid = satir.split()[1].split('(')[0]
                mevcut_ag = {'bssid': bssid}

            elif 'SSID:' in satir:
                ssid = satir.split('SSID:')[1].strip()
                mevcut_ag['ssid'] = ssid if ssid else '<Gizli>'

            elif 'signal:' in satir:
                try:
                    signal_str = satir.split('signal:')[1].strip().split()[0]
                    mevcut_ag['sinyal_dbm'] = float(signal_str)
                    # dBm'i yüzdeye çevir (yaklaşık)
                    dbm = float(signal_str)
                    if dbm >= -50:
                        mevcut_ag['sinyal'] = 100
                    elif dbm <= -100:
                        mevcut_ag['sinyal'] = 0
                    else:
                        mevcut_ag['sinyal'] = int(2 * (dbm + 100))
                except (ValueError, IndexError):
                    pass

            elif 'freq:' in satir:
                try:
                    freq = int(satir.split('freq:')[1].strip())
                    # Frekansı kanala çevir
                    if 2400 <= freq <= 2500:
                        mevcut_ag['kanal'] = (freq - 2407) // 5
                    elif 5000 <= freq <= 6000:
                        mevcut_ag['kanal'] = (freq - 5000) // 5
                except (ValueError, IndexError):
                    pass

            elif 'RSN:' in satir or 'WPA:' in satir:
                mevcut_ag['sifreleme'] = True
                if 'RSN:' in satir:
                    mevcut_ag['sifreleme_tipi'] = 'WPA2'
                else:
                    mevcut_ag['sifreleme_tipi'] = 'WPA'

        if mevcut_ag:
            aglar.append(mevcut_ag)

        # Satıcı bilgisi ekle
        for ag in aglar:
            ag['satici'] = CihazSiniflandirici.satici_bul(ag.get('bssid', ''))

        return aglar

    def _nmcli_parse(self, cikti: str) -> List[Dict]:
        """nmcli çıktısını parse et"""
        aglar = []

        for satir in cikti.strip().split('\n'):
            if not satir:
                continue

            parcalar = satir.split(':')
            if len(parcalar) >= 5:
                ssid = parcalar[0] if parcalar[0] else '<Gizli>'
                bssid = parcalar[1].replace('\\:', ':')

                try:
                    kanal = int(parcalar[2])
                except ValueError:
                    kanal = 0

                try:
                    sinyal = int(parcalar[3])
                except ValueError:
                    sinyal = 0

                sifreleme = parcalar[4]

                aglar.append({
                    'ssid': ssid,
                    'bssid': bssid,
                    'kanal': kanal,
                    'sinyal': sinyal,
                    'sifreleme_tipi': sifreleme if sifreleme else 'Açık',
                    'satici': CihazSiniflandirici.satici_bul(bssid)
                })

        return aglar

class BluetoothTarayici:
    """Bluetooth cihaz tarayıcı"""

    def __init__(self):
        self.sonuclar: List[Dict] = []
        self.arac_mevcut = self._arac_kontrol()

    def _arac_kontrol(self) -> Dict[str, bool]:
        """Bluetooth araçlarını kontrol et"""
        araclar = {}

        for arac in ['hcitool', 'bluetoothctl', 'btmgmt']:
            try:
                subprocess.run(
                    ['which', arac],
                    capture_output=True,
                    timeout=5
                )
                araclar[arac] = True
            except Exception:
                araclar[arac] = False

        return araclar

    def tara(self, sure_saniye: int = 10) -> List[Dict]:
        """Bluetooth cihazlarını tara"""
        self.sonuclar = []

        # hcitool ile tara
        if self.arac_mevcut.get('hcitool'):
            try:
                # Klasik Bluetooth
                sonuc = subprocess.run(
                    ['sudo', 'hcitool', 'scan', '--flush'],
                    capture_output=True,
                    text=True,
                    timeout=sure_saniye + 5
                )

                if sonuc.returncode == 0:
                    for satir in sonuc.stdout.strip().split('\n')[1:]:
                        parcalar = satir.strip().split('\t')
                        if len(parcalar) >= 2:
                            mac = parcalar[0]
                            ad = parcalar[1] if len(parcalar) > 1 else 'Bilinmeyen'
                            self.sonuclar.append({
                                'mac': mac,
                                'ad': ad,
                                'tip': 'Klasik',
                                'kategori': CihazSiniflandirici.siniflandir(ad)
                            })
            except Exception:
                pass

            # BLE (Low Energy)
            try:
                sonuc = subprocess.run(
                    ['sudo', 'hcitool', 'lescan', '--duplicates'],
                    capture_output=True,
                    text=True,
                    timeout=sure_saniye
                )

                # hcitool lescan sürekli çıktı verir, timeout ile kesilir
            except subprocess.TimeoutExpired as e:
                if e.stdout:
                    cikti = e.stdout.decode() if isinstance(e.stdout, bytes) else e.stdout
                    gorulenler = set()
                    for satir in cikti.strip().split('\n'):
                        if satir.startswith('LE Scan'):
                            continue
                        parcalar = satir.strip().split()
                        if len(parcalar) >= 2:
                            mac = parcalar[0]
                            if mac not in gorulenler:
                                gorulenler.add(mac)
                                ad = ' '.join(parcalar[1:]) if len(parcalar) > 1 else 'Bilinmeyen'
                                self.sonuclar.append({
                                    'mac': mac,
                                    'ad': ad,
                                    'tip': 'BLE',
                                    'kategori': CihazSiniflandirici.siniflandir(ad)
                                })
            except Exception:
                pass

        # bluetoothctl ile alternatif
        if not self.sonuclar and self.arac_mevcut.get('bluetoothctl'):
            try:
                # Taramayı başlat
                baslat = subprocess.Popen(
                    ['bluetoothctl'],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )

                komutlar = "scan on\n"
                time.sleep(sure_saniye)
                komutlar += "devices\nscan off\nquit\n"

                cikti, _ = baslat.communicate(input=komutlar, timeout=sure_saniye + 5)

                for satir in cikti.split('\n'):
                    if 'Device' in satir:
                        parcalar = satir.split()
                        mac_idx = None
                        for i, p in enumerate(parcalar):
                            if ':' in p and len(p) == 17:
                                mac_idx = i
                                break

                        if mac_idx is not None:
                            mac = parcalar[mac_idx]
                            ad = ' '.join(parcalar[mac_idx + 1:]) if mac_idx + 1 < len(parcalar) else 'Bilinmeyen'

                            # Tekrarları önle
                            if not any(s['mac'] == mac for s in self.sonuclar):
                                self.sonuclar.append({
                                    'mac': mac,
                                    'ad': ad,
                                    'tip': 'Bilinmeyen',
                                    'kategori': CihazSiniflandirici.siniflandir(ad)
                                })
            except Exception:
                pass

        return self.sonuclar

# ==================== API İSTEMCİLERİ ====================
class WigleIstemci:
    """Wigle.net API istemcisi"""

    BASE_URL = "https://api.wigle.net/api/v2"

    def __init__(self, api_name: str, api_token: str):
        self.api_name = api_name
        self.api_token = api_token
        self._auth = base64.b64encode(f"{api_name}:{api_token}".encode()).decode()

    def _istek(self, endpoint: str, params: Dict = None) -> Dict:
        """API isteği gönder"""
        url = f"{self.BASE_URL}/{endpoint}"

        if params:
            url += "?" + urllib.parse.urlencode(params)

        istek = urllib.request.Request(url)
        istek.add_header("Authorization", f"Basic {self._auth}")
        istek.add_header("User-Agent", "DALGA/1.0")

        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(istek, timeout=30, context=ctx) as yanit:
                return json.loads(yanit.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def wifi_ara(self, enlem: float, boylam: float, yaricap: float = 0.01) -> List[Dict]:
        """Konuma göre WiFi ağları ara"""
        params = {
            "latrange1": enlem - yaricap,
            "latrange2": enlem + yaricap,
            "longrange1": boylam - yaricap,
            "longrange2": boylam + yaricap
        }

        yanit = self._istek("network/search", params)

        if "results" in yanit:
            return [{
                "bssid": r.get("netid"),
                "ssid": r.get("ssid"),
                "enlem": r.get("trilat"),
                "boylam": r.get("trilong"),
                "sinyal": r.get("level"),
                "son_gorulme": r.get("lastupdt"),
                "satici": CihazSiniflandirici.satici_bul(r.get("netid", ""))
            } for r in yanit["results"]]

        return []

    def bluetooth_ara(self, enlem: float, boylam: float, yaricap: float = 0.01) -> List[Dict]:
        """Konuma göre Bluetooth cihazları ara"""
        params = {
            "latrange1": enlem - yaricap,
            "latrange2": enlem + yaricap,
            "longrange1": boylam - yaricap,
            "longrange2": boylam + yaricap
        }

        yanit = self._istek("bluetooth/search", params)

        if "results" in yanit:
            return [{
                "mac": r.get("netid"),
                "ad": r.get("name"),
                "enlem": r.get("trilat"),
                "boylam": r.get("trilong"),
                "tip": r.get("type"),
                "sinyal": r.get("level"),
                "son_gorulme": r.get("lastupdt"),
                "kategori": CihazSiniflandirici.siniflandir(r.get("name"), r.get("type"))
            } for r in yanit["results"]]

        return []

    def bssid_ara(self, bssid: str) -> List[Dict]:
        """BSSID ile WiFi ağı ara"""
        yanit = self._istek("network/search", {"netid": bssid})

        if "results" in yanit:
            return yanit["results"]
        return []

    def ssid_ara(self, ssid: str) -> List[Dict]:
        """SSID ile WiFi ağı ara"""
        yanit = self._istek("network/search", {"ssid": ssid})

        if "results" in yanit:
            return yanit["results"]
        return []

class OpenCellIDIstemci:
    """OpenCellID API istemcisi"""

    BASE_URL = "https://opencellid.org"
    UNWIRED_URL = "https://us1.unwiredlabs.com/v2/process.php"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def baz_istasyonlari_ara(self, enlem: float, boylam: float, yaricap_km: float = 5) -> List[Dict]:
        """Konuma göre baz istasyonları ara"""
        # Derece cinsinden yarıçap (yaklaşık)
        yaricap_derece = yaricap_km / 111.0

        min_lat = enlem - yaricap_derece
        max_lat = enlem + yaricap_derece
        min_lon = boylam - yaricap_derece
        max_lon = boylam + yaricap_derece

        url = f"{self.BASE_URL}/cell/getInArea"
        params = {
            "key": self.api_key,
            "BBOX": f"{min_lat},{min_lon},{max_lat},{max_lon}",
            "format": "json"
        }

        url_full = url + "?" + urllib.parse.urlencode(params)

        try:
            istek = urllib.request.Request(url_full)
            istek.add_header("User-Agent", "DALGA/1.0")

            ctx = ssl.create_default_context()
            with urllib.request.urlopen(istek, timeout=30, context=ctx) as yanit:
                veri = json.loads(yanit.read().decode())

                if "cells" in veri:
                    return [{
                        "cell_id": c.get("cellid"),
                        "lac": c.get("lac"),
                        "mcc": c.get("mcc"),
                        "mnc": c.get("mnc"),
                        "radyo": c.get("radio"),
                        "enlem": c.get("lat"),
                        "boylam": c.get("lon"),
                        "sinyal": c.get("signal")
                    } for c in veri["cells"]]
        except Exception:
            pass

        return []

    def konum_sorgula(self, enlem: float, boylam: float) -> List[Dict]:
        """Unwired Labs API ile konum sorgula"""
        try:
            veri = {
                "token": self.api_key,
                "lat": enlem,
                "lon": boylam,
                "address": 0
            }

            veri_json = json.dumps(veri).encode()

            istek = urllib.request.Request(
                self.UNWIRED_URL,
                data=veri_json,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "DALGA/1.0"
                }
            )

            ctx = ssl.create_default_context()
            with urllib.request.urlopen(istek, timeout=30, context=ctx) as yanit:
                sonuc = json.loads(yanit.read().decode())

                if "cells" in sonuc:
                    return [{
                        "cell_id": c.get("cellid"),
                        "enlem": c.get("lat"),
                        "boylam": c.get("lon"),
                        "sinyal": c.get("signal"),
                        "dogruluk": c.get("accuracy")
                    } for c in sonuc["cells"]]
        except Exception:
            pass

        return []

class ShodanIstemci:
    """Shodan API istemcisi"""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: str):
        self.api_key = api_key

    def konum_ara(self, enlem: float, boylam: float, yaricap_km: int = 1, limit: int = 10) -> List[Dict]:
        """Konuma göre internete bağlı cihazları ara"""
        sorgu = f"geo:{enlem},{boylam},{yaricap_km}"

        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": sorgu,
            "limit": limit
        }

        url_full = url + "?" + urllib.parse.urlencode(params)

        try:
            istek = urllib.request.Request(url_full)
            istek.add_header("User-Agent", "DALGA/1.0")

            ctx = ssl.create_default_context()
            with urllib.request.urlopen(istek, timeout=30, context=ctx) as yanit:
                veri = json.loads(yanit.read().decode())

                if "matches" in veri:
                    return [{
                        "ip": m.get("ip_str"),
                        "enlem": m.get("location", {}).get("latitude"),
                        "boylam": m.get("location", {}).get("longitude"),
                        "organizasyon": m.get("org"),
                        "urun": m.get("product"),
                        "port": m.get("port"),
                        "veri": m.get("data", "")[:200]
                    } for m in veri["matches"]]
        except Exception:
            pass

        return []

    def genel_ara(self, sorgu: str, limit: int = 10) -> List[Dict]:
        """Genel sorgu ile ara"""
        url = f"{self.BASE_URL}/shodan/host/search"
        params = {
            "key": self.api_key,
            "query": sorgu,
            "limit": limit
        }

        url_full = url + "?" + urllib.parse.urlencode(params)

        try:
            istek = urllib.request.Request(url_full)
            istek.add_header("User-Agent", "DALGA/1.0")

            ctx = ssl.create_default_context()
            with urllib.request.urlopen(istek, timeout=30, context=ctx) as yanit:
                veri = json.loads(yanit.read().decode())

                if "matches" in veri:
                    return veri["matches"]
        except Exception:
            pass

        return []

# ==================== ANA MOTOR ====================
class DalgaMotor:
    """DALGA ana işlem motoru"""

    def __init__(self):
        self.veritabani = DalgaVeritabani()
        self.guvenlik = GuvenlikYoneticisi()
        self.wifi_tarayici = WiFiTarayici()
        self.bluetooth_tarayici = BluetoothTarayici()

        # API istemcileri (anahtarlar varsa)
        self.wigle: Optional[WigleIstemci] = None
        self.opencellid: Optional[OpenCellIDIstemci] = None
        self.shodan: Optional[ShodanIstemci] = None

        self._api_istemcileri_yukle()

        # Durum
        self.calistiriliyor = True
        self.mevcut_konum: Tuple[float, float] = (0.0, 0.0)

    def _api_istemcileri_yukle(self):
        """Kayıtlı API anahtarlarını yükle"""
        # Wigle
        wigle_name, wigle_token = self.veritabani.api_anahtari_getir("wigle", self.guvenlik)
        if wigle_name and wigle_token:
            self.wigle = WigleIstemci(wigle_name, wigle_token)

        # OpenCellID
        opencellid_key, _ = self.veritabani.api_anahtari_getir("opencellid", self.guvenlik)
        if opencellid_key:
            self.opencellid = OpenCellIDIstemci(opencellid_key)

        # Shodan
        shodan_key, _ = self.veritabani.api_anahtari_getir("shodan", self.guvenlik)
        if shodan_key:
            self.shodan = ShodanIstemci(shodan_key)

    def api_anahtari_ayarla(self, servis: str, anahtar: str, secret: str = None):
        """API anahtarı kaydet ve istemciyi güncelle"""
        self.veritabani.api_anahtari_kaydet(servis, anahtar, secret, self.guvenlik)
        self._api_istemcileri_yukle()

    def wifi_tara(self, yerel: bool = True, api: bool = False) -> List[Dict]:
        """WiFi ağlarını tara"""
        sonuclar = []

        if yerel:
            yerel_sonuclar = self.wifi_tarayici.tara()
            for ag in yerel_sonuclar:
                self.veritabani.wifi_kaydet(ag)
            sonuclar.extend(yerel_sonuclar)

        if api and self.wigle and self.mevcut_konum != (0.0, 0.0):
            api_sonuclar = self.wigle.wifi_ara(self.mevcut_konum[0], self.mevcut_konum[1])
            sonuclar.extend(api_sonuclar)

        return sonuclar

    def bluetooth_tara(self, yerel: bool = True, api: bool = False) -> List[Dict]:
        """Bluetooth cihazlarını tara"""
        sonuclar = []

        if yerel:
            yerel_sonuclar = self.bluetooth_tarayici.tara()
            for cihaz in yerel_sonuclar:
                self.veritabani.bluetooth_kaydet(cihaz)
            sonuclar.extend(yerel_sonuclar)

        if api and self.wigle and self.mevcut_konum != (0.0, 0.0):
            api_sonuclar = self.wigle.bluetooth_ara(self.mevcut_konum[0], self.mevcut_konum[1])
            sonuclar.extend(api_sonuclar)

        return sonuclar

    def baz_istasyonlari_tara(self) -> List[Dict]:
        """Baz istasyonlarını tara (sadece API)"""
        if not self.opencellid or self.mevcut_konum == (0.0, 0.0):
            return []

        return self.opencellid.baz_istasyonlari_ara(
            self.mevcut_konum[0],
            self.mevcut_konum[1]
        )

    def iot_cihazlari_tara(self) -> List[Dict]:
        """IoT cihazlarını tara (Shodan)"""
        if not self.shodan or self.mevcut_konum == (0.0, 0.0):
            return []

        return self.shodan.konum_ara(
            self.mevcut_konum[0],
            self.mevcut_konum[1]
        )

    def konum_ayarla(self, enlem: float, boylam: float):
        """Mevcut konumu ayarla"""
        self.mevcut_konum = (enlem, boylam)

    def durum_raporu(self) -> Dict:
        """Sistem durum raporu"""
        istatistikler = self.veritabani.istatistikler()

        return {
            "versiyon": DALGA_VERSION,
            "kod_adi": DALGA_CODENAME,
            "wifi_arayuz": self.wifi_tarayici.arayuz,
            "bluetooth_araclar": self.bluetooth_tarayici.arac_mevcut,
            "api_durumu": {
                "wigle": self.wigle is not None,
                "opencellid": self.opencellid is not None,
                "shodan": self.shodan is not None
            },
            "mevcut_konum": self.mevcut_konum,
            "istatistikler": istatistikler
        }

    def disa_aktar(self, format: str = "json", dosya_adi: str = None) -> str:
        """Verileri dışa aktar"""
        DALGA_EXPORTS.mkdir(parents=True, exist_ok=True)

        if not dosya_adi:
            tarih = datetime.now().strftime("%Y%m%d_%H%M%S")
            dosya_adi = f"dalga_export_{tarih}"

        wifi_verileri = self.veritabani.tum_wifi_getir(limit=1000)
        bt_verileri = self.veritabani.tum_bluetooth_getir(limit=1000)

        veri = {
            "meta": {
                "versiyon": DALGA_VERSION,
                "tarih": datetime.now().isoformat(),
                "toplam_wifi": len(wifi_verileri),
                "toplam_bluetooth": len(bt_verileri)
            },
            "wifi_aglar": wifi_verileri,
            "bluetooth_cihazlar": bt_verileri
        }

        if format == "json":
            dosya_yolu = DALGA_EXPORTS / f"{dosya_adi}.json"
            with open(dosya_yolu, "w", encoding="utf-8") as f:
                json.dump(veri, f, ensure_ascii=False, indent=2, default=str)

        elif format == "csv":
            # WiFi CSV
            wifi_dosya = DALGA_EXPORTS / f"{dosya_adi}_wifi.csv"
            with open(wifi_dosya, "w", encoding="utf-8") as f:
                if wifi_verileri:
                    basliklar = wifi_verileri[0].keys()
                    f.write(",".join(basliklar) + "\n")
                    for wifi in wifi_verileri:
                        f.write(",".join(str(wifi.get(k, "")) for k in basliklar) + "\n")

            # Bluetooth CSV
            bt_dosya = DALGA_EXPORTS / f"{dosya_adi}_bluetooth.csv"
            with open(bt_dosya, "w", encoding="utf-8") as f:
                if bt_verileri:
                    basliklar = bt_verileri[0].keys()
                    f.write(",".join(basliklar) + "\n")
                    for bt in bt_verileri:
                        f.write(",".join(str(bt.get(k, "")) for k in basliklar) + "\n")

            dosya_yolu = DALGA_EXPORTS

        return str(dosya_yolu)

# ==================== CLI ARAYÜZÜ ====================
class DalgaCLI:
    """DALGA komut satırı arayüzü"""

    def __init__(self):
        self.motor = DalgaMotor()
        self.komutlar = {
            'wifi': self._wifi_tara,
            'bluetooth': self._bluetooth_tara,
            'bt': self._bluetooth_tara,
            'baz': self._baz_tara,
            'iot': self._iot_tara,
            'konum': self._konum_ayarla,
            'durum': self._durum_goster,
            'api': self._api_ayarla,
            'gecmis': self._gecmis_goster,
            'aktar': self._disa_aktar,
            'menu': self._menu_goster,
            'yardim': self._yardim_goster,
            'temizle': self._ekran_temizle,
            'cik': self._cikis,
            'cikis': self._cikis,
            'q': self._cikis
        }

    def _banner_goster(self):
        """ASCII banner göster"""
        print(f"""
{Renk.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   {Renk.BEYAZ}██████╗  █████╗ ██╗      ██████╗  █████╗ {Renk.CYAN}                                   ║
║   {Renk.BEYAZ}██╔══██╗██╔══██╗██║     ██╔════╝ ██╔══██╗{Renk.CYAN}                                  ║
║   {Renk.BEYAZ}██║  ██║███████║██║     ██║  ███╗███████║{Renk.CYAN}                                  ║
║   {Renk.BEYAZ}██║  ██║██╔══██║██║     ██║   ██║██╔══██║{Renk.CYAN}                                  ║
║   {Renk.BEYAZ}██████╔╝██║  ██║███████╗╚██████╔╝██║  ██║{Renk.CYAN}                                  ║
║   {Renk.BEYAZ}╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝{Renk.CYAN}                                  ║
║                                                                              ║
║   {Renk.SARI}🌊 DALGA v{DALGA_VERSION} "{DALGA_CODENAME}" - Kablosuz Sinyal İstihbaratı{Renk.CYAN}               ║
║   {Renk.YESIL}📡 WiFi | 📶 Bluetooth | 📱 Hücresel | 🔌 IoT{Renk.CYAN}                              ║
║                                                                              ║
║   {Renk.KIRMIZI}⚠️  SADECE ETİK VE YASAL KULLANIM İÇİN{Renk.CYAN}                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Renk.SIFIRLA}
""")

    def _menu_goster(self, args=None) -> str:
        """Ana menüyü göster"""
        durum = self.motor.durum_raporu()
        api_durum = durum['api_durumu']

        wigle_str = f"{Renk.YESIL}✓{Renk.SIFIRLA}" if api_durum['wigle'] else f"{Renk.KIRMIZI}✗{Renk.SIFIRLA}"
        opencell_str = f"{Renk.YESIL}✓{Renk.SIFIRLA}" if api_durum['opencellid'] else f"{Renk.KIRMIZI}✗{Renk.SIFIRLA}"
        shodan_str = f"{Renk.YESIL}✓{Renk.SIFIRLA}" if api_durum['shodan'] else f"{Renk.KIRMIZI}✗{Renk.SIFIRLA}"

        return f"""
{Renk.CYAN}╔══════════════════════════════════════════════════════════════╗
║                    DALGA v{DALGA_VERSION} MENU                           ║
╠══════════════════════════════════════════════════════════════╣
║  API: Wigle {wigle_str}  OpenCellID {opencell_str}  Shodan {shodan_str}                ║
╠══════════════════════════════════════════════════════════════╣{Renk.SIFIRLA}
{Renk.SARI}  TARAMA:{Renk.SIFIRLA}
    {Renk.BEYAZ}wifi{Renk.SIFIRLA}                   WiFi ağlarını tara
    {Renk.BEYAZ}bluetooth{Renk.SIFIRLA} / {Renk.BEYAZ}bt{Renk.SIFIRLA}        Bluetooth cihazları tara
    {Renk.BEYAZ}baz{Renk.SIFIRLA}                    Baz istasyonlarını tara (API)
    {Renk.BEYAZ}iot{Renk.SIFIRLA}                    IoT cihazları ara (Shodan)

{Renk.SARI}  KONUM:{Renk.SIFIRLA}
    {Renk.BEYAZ}konum{Renk.SIFIRLA} <enlem> <boylam>  Konum ayarla (API aramaları için)

{Renk.SARI}  API:{Renk.SIFIRLA}
    {Renk.BEYAZ}api wigle{Renk.SIFIRLA} <name> <token>   Wigle API ayarla
    {Renk.BEYAZ}api opencellid{Renk.SIFIRLA} <key>       OpenCellID API ayarla
    {Renk.BEYAZ}api shodan{Renk.SIFIRLA} <key>           Shodan API ayarla

{Renk.SARI}  VERİ:{Renk.SIFIRLA}
    {Renk.BEYAZ}gecmis{Renk.SIFIRLA}                 Kayıtlı verileri göster
    {Renk.BEYAZ}aktar{Renk.SIFIRLA} [json|csv]      Verileri dışa aktar

{Renk.SARI}  GENEL:{Renk.SIFIRLA}
    {Renk.BEYAZ}durum{Renk.SIFIRLA}                  Sistem durumu
    {Renk.BEYAZ}menu{Renk.SIFIRLA}                   Bu menü
    {Renk.BEYAZ}yardim{Renk.SIFIRLA}                 Detaylı yardım
    {Renk.BEYAZ}temizle{Renk.SIFIRLA}                Ekranı temizle
    {Renk.BEYAZ}cik{Renk.SIFIRLA}                    Çıkış
{Renk.CYAN}╚══════════════════════════════════════════════════════════════╝{Renk.SIFIRLA}
"""

    def _wifi_tara(self, args=None) -> str:
        """WiFi taraması"""
        print(f"\n{Renk.CYAN}📡 WiFi ağları taranıyor...{Renk.SIFIRLA}")

        sonuclar = self.motor.wifi_tara(yerel=True)

        if not sonuclar:
            return f"{Renk.SARI}Hiç WiFi ağı bulunamadı. (sudo gerekebilir){Renk.SIFIRLA}"

        cikti = f"\n{Renk.YESIL}📡 {len(sonuclar)} WiFi ağı bulundu:{Renk.SIFIRLA}\n"
        cikti += f"{Renk.SOLUK}{'─' * 80}{Renk.SIFIRLA}\n"
        cikti += f"{'SSID':<25} {'BSSID':<18} {'CH':>3} {'SİNYAL':>7} {'ŞİFRE':<10} {'SATICI':<15}\n"
        cikti += f"{Renk.SOLUK}{'─' * 80}{Renk.SIFIRLA}\n"

        for ag in sonuclar[:20]:
            ssid = ag.get('ssid', '<Gizli>')[:24]
            bssid = ag.get('bssid', 'N/A')
            kanal = ag.get('kanal', 0)
            sinyal = ag.get('sinyal', 0)
            sifreleme = ag.get('sifreleme_tipi', 'Açık')[:9]
            satici = ag.get('satici', 'Bilinmeyen')[:14]

            # Sinyal gücüne göre renk
            if sinyal >= 70:
                sinyal_renk = Renk.YESIL
            elif sinyal >= 40:
                sinyal_renk = Renk.SARI
            else:
                sinyal_renk = Renk.KIRMIZI

            cikti += f"{ssid:<25} {bssid:<18} {kanal:>3} {sinyal_renk}{sinyal:>6}%{Renk.SIFIRLA} {sifreleme:<10} {satici:<15}\n"

        if len(sonuclar) > 20:
            cikti += f"\n{Renk.SOLUK}... ve {len(sonuclar) - 20} ağ daha{Renk.SIFIRLA}"

        return cikti

    def _bluetooth_tara(self, args=None) -> str:
        """Bluetooth taraması"""
        print(f"\n{Renk.CYAN}📶 Bluetooth cihazları taranıyor (10 saniye)...{Renk.SIFIRLA}")

        sonuclar = self.motor.bluetooth_tara(yerel=True)

        if not sonuclar:
            return f"{Renk.SARI}Hiç Bluetooth cihazı bulunamadı. (sudo ve bluetooth servis gerekebilir){Renk.SIFIRLA}"

        cikti = f"\n{Renk.YESIL}📶 {len(sonuclar)} Bluetooth cihazı bulundu:{Renk.SIFIRLA}\n"
        cikti += f"{Renk.SOLUK}{'─' * 70}{Renk.SIFIRLA}\n"
        cikti += f"{'MAC ADRESİ':<18} {'CİHAZ ADI':<25} {'TİP':<10} {'KATEGORİ':<15}\n"
        cikti += f"{Renk.SOLUK}{'─' * 70}{Renk.SIFIRLA}\n"

        for cihaz in sonuclar[:20]:
            mac = cihaz.get('mac', 'N/A')
            ad = cihaz.get('ad', 'Bilinmeyen')[:24]
            tip = cihaz.get('tip', 'N/A')[:9]
            kategori = cihaz.get('kategori', 'diger')[:14]

            # Kategoriye göre renk
            kategori_renkler = {
                'kulaklik': Renk.CYAN,
                'telefon': Renk.YESIL,
                'arac': Renk.MAGENTA,
                'iot': Renk.SARI,
                'bilgisayar': Renk.MAVI
            }
            kat_renk = kategori_renkler.get(kategori, Renk.BEYAZ)

            cikti += f"{mac:<18} {ad:<25} {tip:<10} {kat_renk}{kategori:<15}{Renk.SIFIRLA}\n"

        return cikti

    def _baz_tara(self, args=None) -> str:
        """Baz istasyonu taraması"""
        if not self.motor.opencellid:
            return f"{Renk.KIRMIZI}❌ OpenCellID API anahtarı ayarlanmamış.{Renk.SIFIRLA}\n   Kullanım: api opencellid <anahtar>"

        if self.motor.mevcut_konum == (0.0, 0.0):
            return f"{Renk.KIRMIZI}❌ Konum ayarlanmamış.{Renk.SIFIRLA}\n   Kullanım: konum <enlem> <boylam>"

        print(f"\n{Renk.CYAN}📱 Baz istasyonları taranıyor...{Renk.SIFIRLA}")

        sonuclar = self.motor.baz_istasyonlari_tara()

        if not sonuclar:
            return f"{Renk.SARI}Yakınlarda baz istasyonu bulunamadı.{Renk.SIFIRLA}"

        cikti = f"\n{Renk.YESIL}📱 {len(sonuclar)} baz istasyonu bulundu:{Renk.SIFIRLA}\n"
        cikti += f"{Renk.SOLUK}{'─' * 70}{Renk.SIFIRLA}\n"
        cikti += f"{'CELL ID':<12} {'LAC':<8} {'MCC':<6} {'MNC':<6} {'RADYO':<8} {'KONUM':<25}\n"
        cikti += f"{Renk.SOLUK}{'─' * 70}{Renk.SIFIRLA}\n"

        for baz in sonuclar[:15]:
            cell_id = str(baz.get('cell_id', 'N/A'))[:11]
            lac = str(baz.get('lac', 'N/A'))[:7]
            mcc = str(baz.get('mcc', 'N/A'))[:5]
            mnc = str(baz.get('mnc', 'N/A'))[:5]
            radyo = baz.get('radyo', 'N/A')[:7]
            enlem = baz.get('enlem', 0)
            boylam = baz.get('boylam', 0)
            konum = f"{enlem:.4f}, {boylam:.4f}"

            cikti += f"{cell_id:<12} {lac:<8} {mcc:<6} {mnc:<6} {radyo:<8} {konum:<25}\n"

        return cikti

    def _iot_tara(self, args=None) -> str:
        """IoT cihaz taraması (Shodan)"""
        if not self.motor.shodan:
            return f"{Renk.KIRMIZI}❌ Shodan API anahtarı ayarlanmamış.{Renk.SIFIRLA}\n   Kullanım: api shodan <anahtar>"

        if self.motor.mevcut_konum == (0.0, 0.0):
            return f"{Renk.KIRMIZI}❌ Konum ayarlanmamış.{Renk.SIFIRLA}\n   Kullanım: konum <enlem> <boylam>"

        print(f"\n{Renk.CYAN}🔌 IoT cihazları aranıyor (Shodan)...{Renk.SIFIRLA}")

        sonuclar = self.motor.iot_cihazlari_tara()

        if not sonuclar:
            return f"{Renk.SARI}Yakınlarda IoT cihazı bulunamadı.{Renk.SIFIRLA}"

        cikti = f"\n{Renk.YESIL}🔌 {len(sonuclar)} cihaz bulundu:{Renk.SIFIRLA}\n"
        cikti += f"{Renk.SOLUK}{'─' * 80}{Renk.SIFIRLA}\n"

        for cihaz in sonuclar[:10]:
            ip = cihaz.get('ip', 'N/A')
            port = cihaz.get('port', 'N/A')
            org = cihaz.get('organizasyon', 'N/A')[:30]
            urun = cihaz.get('urun', 'N/A')[:25]

            cikti += f"{Renk.BEYAZ}IP:{Renk.SIFIRLA} {ip}:{port}\n"
            cikti += f"   {Renk.SOLUK}Org:{Renk.SIFIRLA} {org}\n"
            cikti += f"   {Renk.SOLUK}Ürün:{Renk.SIFIRLA} {urun}\n"
            cikti += f"{Renk.SOLUK}{'─' * 40}{Renk.SIFIRLA}\n"

        return cikti

    def _konum_ayarla(self, args: str) -> str:
        """Konum ayarla"""
        if not args:
            if self.motor.mevcut_konum == (0.0, 0.0):
                return f"{Renk.SARI}Konum ayarlanmamış.{Renk.SIFIRLA}\nKullanım: konum <enlem> <boylam>\nÖrnek: konum 41.0082 28.9784"
            else:
                return f"{Renk.YESIL}Mevcut konum:{Renk.SIFIRLA} {self.motor.mevcut_konum[0]}, {self.motor.mevcut_konum[1]}"

        parcalar = args.split()
        if len(parcalar) < 2:
            return f"{Renk.KIRMIZI}Hata: Enlem ve boylam gerekli.{Renk.SIFIRLA}\nÖrnek: konum 41.0082 28.9784"

        try:
            enlem = float(parcalar[0])
            boylam = float(parcalar[1])

            if not (-90 <= enlem <= 90):
                return f"{Renk.KIRMIZI}Hata: Enlem -90 ile 90 arasında olmalı.{Renk.SIFIRLA}"
            if not (-180 <= boylam <= 180):
                return f"{Renk.KIRMIZI}Hata: Boylam -180 ile 180 arasında olmalı.{Renk.SIFIRLA}"

            self.motor.konum_ayarla(enlem, boylam)
            return f"{Renk.YESIL}✓ Konum ayarlandı:{Renk.SIFIRLA} {enlem}, {boylam}"

        except ValueError:
            return f"{Renk.KIRMIZI}Hata: Geçersiz koordinat formatı.{Renk.SIFIRLA}"

    def _api_ayarla(self, args: str) -> str:
        """API anahtarı ayarla"""
        if not args:
            return f"""
{Renk.SARI}API Anahtarı Ayarlama:{Renk.SIFIRLA}
  api wigle <api_name> <api_token>   - Wigle.net
  api opencellid <api_key>           - OpenCellID
  api shodan <api_key>               - Shodan

{Renk.SOLUK}API anahtarları şifreli olarak saklanır.{Renk.SIFIRLA}
"""

        parcalar = args.split()
        servis = parcalar[0].lower()

        if servis == 'wigle':
            if len(parcalar) < 3:
                return f"{Renk.KIRMIZI}Kullanım: api wigle <api_name> <api_token>{Renk.SIFIRLA}"
            self.motor.api_anahtari_ayarla('wigle', parcalar[1], parcalar[2])
            return f"{Renk.YESIL}✓ Wigle API anahtarı kaydedildi.{Renk.SIFIRLA}"

        elif servis == 'opencellid':
            if len(parcalar) < 2:
                return f"{Renk.KIRMIZI}Kullanım: api opencellid <api_key>{Renk.SIFIRLA}"
            self.motor.api_anahtari_ayarla('opencellid', parcalar[1])
            return f"{Renk.YESIL}✓ OpenCellID API anahtarı kaydedildi.{Renk.SIFIRLA}"

        elif servis == 'shodan':
            if len(parcalar) < 2:
                return f"{Renk.KIRMIZI}Kullanım: api shodan <api_key>{Renk.SIFIRLA}"
            self.motor.api_anahtari_ayarla('shodan', parcalar[1])
            return f"{Renk.YESIL}✓ Shodan API anahtarı kaydedildi.{Renk.SIFIRLA}"

        else:
            return f"{Renk.KIRMIZI}Bilinmeyen servis: {servis}{Renk.SIFIRLA}"

    def _durum_goster(self, args=None) -> str:
        """Sistem durumunu göster"""
        durum = self.motor.durum_raporu()

        api = durum['api_durumu']
        istat = durum['istatistikler']
        bt = durum['bluetooth_araclar']

        cikti = f"""
{Renk.KALIN}{Renk.CYAN}DALGA v{durum['versiyon']} "{durum['kod_adi']}" - DURUM{Renk.SIFIRLA}

{Renk.CYAN}Arayüzler:{Renk.SIFIRLA}
  WiFi: {durum['wifi_arayuz']}
  Bluetooth: hcitool={'✓' if bt.get('hcitool') else '✗'} bluetoothctl={'✓' if bt.get('bluetoothctl') else '✗'}

{Renk.CYAN}API Durumu:{Renk.SIFIRLA}
  Wigle: {'✓ Aktif' if api['wigle'] else '✗ Kapalı'}
  OpenCellID: {'✓ Aktif' if api['opencellid'] else '✗ Kapalı'}
  Shodan: {'✓ Aktif' if api['shodan'] else '✗ Kapalı'}

{Renk.CYAN}Konum:{Renk.SIFIRLA}
  {durum['mevcut_konum'][0]}, {durum['mevcut_konum'][1]} {'(ayarlanmamış)' if durum['mevcut_konum'] == (0.0, 0.0) else ''}

{Renk.CYAN}Veritabanı:{Renk.SIFIRLA}
  WiFi ağları: {istat['wifi_ag_sayisi']}
  Bluetooth cihazları: {istat['bluetooth_cihaz_sayisi']}
  Baz istasyonları: {istat['baz_istasyonu_sayisi']}
  Toplam tarama: {istat['toplam_tarama']}

{Renk.CYAN}Dizinler:{Renk.SIFIRLA}
  Veritabanı: {DALGA_DB}
  Dışa aktarım: {DALGA_EXPORTS}
"""
        return cikti

    def _gecmis_goster(self, args=None) -> str:
        """Kayıtlı verileri göster"""
        wifi_verileri = self.motor.veritabani.tum_wifi_getir(limit=10)
        bt_verileri = self.motor.veritabani.tum_bluetooth_getir(limit=10)

        cikti = f"\n{Renk.CYAN}📊 Kayıtlı Veriler:{Renk.SIFIRLA}\n"

        if wifi_verileri:
            cikti += f"\n{Renk.YESIL}Son 10 WiFi Ağı:{Renk.SIFIRLA}\n"
            for ag in wifi_verileri:
                cikti += f"  • {ag.get('ssid', '<Gizli>')} ({ag.get('bssid', 'N/A')}) - {ag.get('son_gorulme', 'N/A')}\n"

        if bt_verileri:
            cikti += f"\n{Renk.YESIL}Son 10 Bluetooth Cihazı:{Renk.SIFIRLA}\n"
            for cihaz in bt_verileri:
                cikti += f"  • {cihaz.get('cihaz_adi', 'Bilinmeyen')} ({cihaz.get('mac_adresi', 'N/A')}) - {cihaz.get('kategori', 'diger')}\n"

        if not wifi_verileri and not bt_verileri:
            cikti += f"\n{Renk.SARI}Henüz kayıtlı veri yok. Tarama yapın.{Renk.SIFIRLA}\n"

        return cikti

    def _disa_aktar(self, args: str = None) -> str:
        """Verileri dışa aktar"""
        format = args.strip().lower() if args else 'json'

        if format not in ['json', 'csv']:
            format = 'json'

        dosya_yolu = self.motor.disa_aktar(format=format)

        return f"{Renk.YESIL}✓ Veriler dışa aktarıldı:{Renk.SIFIRLA}\n   {dosya_yolu}"

    def _yardim_goster(self, args=None) -> str:
        """Detaylı yardım"""
        return f"""
{Renk.KALIN}{Renk.CYAN}DALGA v{DALGA_VERSION} - Detaylı Yardım{Renk.SIFIRLA}

{Renk.SARI}YEREL TARAMA (API gerektirmez):{Renk.SIFIRLA}
  {Renk.BEYAZ}wifi{Renk.SIFIRLA}
    Çevredeki WiFi ağlarını tarar. iwlist/iw/nmcli kullanır.
    Sudo yetkisi gerektirebilir.

  {Renk.BEYAZ}bluetooth{Renk.SIFIRLA} veya {Renk.BEYAZ}bt{Renk.SIFIRLA}
    Bluetooth cihazlarını tarar (Klasik + BLE).
    hcitool veya bluetoothctl gerektirir.

{Renk.SARI}API TARAMA (API anahtarı gerektirir):{Renk.SIFIRLA}
  {Renk.BEYAZ}baz{Renk.SIFIRLA}
    Yakındaki baz istasyonlarını arar (OpenCellID).
    Önce konum ayarlanmalı.

  {Renk.BEYAZ}iot{Renk.SIFIRLA}
    İnternete bağlı cihazları arar (Shodan).
    Premium Shodan hesabı önerilir.

{Renk.SARI}API ANAHTARLARI:{Renk.SIFIRLA}
  Wigle.net: https://wigle.net/account
  OpenCellID: https://opencellid.org/register
  Shodan: https://account.shodan.io/

{Renk.SARI}ÖRNEK KULLANIM:{Renk.SIFIRLA}
  1. konum 41.0082 28.9784    # İstanbul koordinatları
  2. api wigle <name> <token>  # API ayarla
  3. wifi                      # Yerel tarama
  4. baz                       # Baz istasyonları
  5. aktar json                # Verileri dışa aktar

{Renk.SARI}VERİ DEPOLAMA:{Renk.SIFIRLA}
  Tüm veriler şifreli SQLite veritabanında saklanır.
  Konum: {DALGA_DB}

{Renk.KIRMIZI}⚠️  YASAL UYARI:{Renk.SIFIRLA}
  Bu araç sadece eğitim ve yasal güvenlik testleri içindir.
  İzinsiz kullanım yasaktır ve yasal sonuçları olabilir.
"""

    def _ekran_temizle(self, args=None) -> str:
        """Ekranı temizle"""
        os.system('clear' if os.name == 'posix' else 'cls')
        return ""

    def _cikis(self, args=None) -> str:
        """Çıkış"""
        self.motor.calistiriliyor = False
        return f"{Renk.SARI}Güvenle kal...{Renk.SIFIRLA}"

    def komut_isle(self, giris: str) -> str:
        """Komutu işle"""
        giris = giris.strip()
        if not giris:
            return ""

        parcalar = giris.split(maxsplit=1)
        komut = parcalar[0].lower()
        args = parcalar[1] if len(parcalar) > 1 else ""

        if komut in self.komutlar:
            return self.komutlar[komut](args)
        else:
            return f"{Renk.KIRMIZI}Bilinmeyen komut: {komut}{Renk.SIFIRLA}\n'menu' veya 'yardim' yazın."

    def calistir(self):
        """Ana döngü"""
        self._ekran_temizle()
        self._banner_goster()
        print(self._menu_goster())

        while self.motor.calistiriliyor:
            try:
                prompt = f"{Renk.RL_CYAN}DALGA >{Renk.RL_SIFIRLA} "
                giris = input(prompt).strip()

                if not giris:
                    continue

                sonuc = self.komut_isle(giris)
                if sonuc:
                    print(sonuc)

            except KeyboardInterrupt:
                print(f"\n{Renk.SARI}Çıkılıyor...{Renk.SIFIRLA}")
                break
            except EOFError:
                break

# ==================== ANA GİRİŞ ====================
def main():
    """Ana giriş noktası"""
    import argparse

    parser = argparse.ArgumentParser(
        description="DALGA - Kablosuz Sinyal İstihbarat Platformu"
    )
    parser.add_argument('--version', '-v', action='version', version=f'DALGA v{DALGA_VERSION}')
    parser.add_argument('--wifi', action='store_true', help='WiFi taraması yap ve çık')
    parser.add_argument('--bluetooth', '-bt', action='store_true', help='Bluetooth taraması yap ve çık')
    parser.add_argument('--json', action='store_true', help='Çıktıyı JSON formatında ver')

    args = parser.parse_args()

    # Tek seferlik tarama modları
    if args.wifi or args.bluetooth:
        motor = DalgaMotor()

        if args.wifi:
            sonuclar = motor.wifi_tara()
            if args.json:
                print(json.dumps(sonuclar, ensure_ascii=False, indent=2, default=str))
            else:
                for ag in sonuclar:
                    print(f"{ag.get('ssid', '<Gizli>')}\t{ag.get('bssid', 'N/A')}\t{ag.get('sinyal', 0)}%")

        if args.bluetooth:
            sonuclar = motor.bluetooth_tara()
            if args.json:
                print(json.dumps(sonuclar, ensure_ascii=False, indent=2, default=str))
            else:
                for cihaz in sonuclar:
                    print(f"{cihaz.get('mac', 'N/A')}\t{cihaz.get('ad', 'Bilinmeyen')}\t{cihaz.get('kategori', 'diger')}")

        return

    # İnteraktif mod
    cli = DalgaCLI()
    cli.calistir()

if __name__ == "__main__":
    main()
