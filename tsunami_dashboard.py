#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI GUVENLIK DASHBOARD v1.0
    Dunya Sinifi Elite Hacker Guvenlik Merkezi
================================================================================

    SOC Analisti Is Istasyonu - Profesyonel Siber Guvenlik Kontrol Merkezi

    Ozellikler:
    - Gercek zamanli tehdit goruntulemesi
    - MITRE ATT&CK entegrasyonu
    - BEYIN, Defender, Network Guardian entegrasyonu
    - Hizli mudahale yetenekleri
    - Otomatik ve manuel yanit secenekleri
    - Profesyonel karanlik tema
    - Turkce arayuz

    Gereksinimler:
    sudo apt install python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-notify-0.7
    pip3 install websocket-client requests psutil

================================================================================
"""

import gi
gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')
gi.require_version('Notify', '0.7')

from gi.repository import Gtk, Adw, Gdk, GLib, Gio, Notify, Pango
import os
import sys
import json
import time
import sqlite3
import threading
import subprocess
import socket
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import deque
import hashlib

# Psutil - sistem izleme
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# WebSocket - gercek zamanli iletisim
try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False

# Requests - API istekleri
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ============================================================================
# YAPILANDIRMA
# ============================================================================

TSUNAMI_HOME = Path("/home/lydian/Desktop/TSUNAMI")
TSUNAMI_DB = TSUNAMI_HOME / "tsunami.db"
TSUNAMI_CONFIG = TSUNAMI_HOME / "tsunami_config.json"
DASHBOARD_DB = TSUNAMI_HOME / "dashboard_cache.db"
TSUNAMI_LOGS = TSUNAMI_HOME / "logs"

# Loglama
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("TsunamiDashboard")

# Bildirim baslat
Notify.init("TSUNAMI Guvenlik Dashboard")


# ============================================================================
# ENUM VE DATACLASS TANIMLARI
# ============================================================================

class TehditSeviyesi(Enum):
    """Tehdit seviyeleri"""
    KRITIK = "kritik"
    YUKSEK = "yuksek"
    ORTA = "orta"
    DUSUK = "dusuk"
    BILGI = "bilgi"


class DefconSeviyesi(Enum):
    """DEFCON seviyeleri"""
    DEFCON_1 = 1  # Aktif saldiri
    DEFCON_2 = 2  # Ciddi tehdit
    DEFCON_3 = 3  # Anormallik
    DEFCON_4 = 4  # Normal izleme
    DEFCON_5 = 5  # Tam guvenli


class ModulDurum(Enum):
    """Modul durumlari"""
    AKTIF = "aktif"
    PASIF = "pasif"
    HATA = "hata"
    BASLATIYOR = "baslatiyor"


@dataclass
class TehditOlayi:
    """Tehdit olayi veri yapisi"""
    id: str
    zaman: datetime
    kaynak: str
    tip: str
    seviye: TehditSeviyesi
    aciklama: str
    ip_adresi: Optional[str] = None
    port: Optional[int] = None
    mitre_teknik: Optional[str] = None
    aksiyon_yapildi: bool = False
    aksiyon_tipi: Optional[str] = None


@dataclass
class AgCihazi:
    """Ag cihazi veri yapisi"""
    ip: str
    mac: str
    hostname: Optional[str]
    vendor: Optional[str]
    ilk_gorulen: datetime
    son_gorulen: datetime
    guvenilir: bool = False
    notlar: str = ""


# ============================================================================
# CSS TEMA - ELITE HACKER GORUNUMU
# ============================================================================

DASHBOARD_CSS = """
/* ================================================================
   TSUNAMI COCKPIT v3.0 - BLACK & WHITE ELITE
   Monochrome Aircraft HUD Style - Siyah Üstü Beyaz
   ================================================================ */

/* === ANIMATIONS === */
@keyframes pulse {
    0% { opacity: 1; }
    50% { opacity: 0.7; }
    100% { opacity: 1; }
}

@keyframes scan-line {
    0% { opacity: 0.5; }
    50% { opacity: 1; }
    100% { opacity: 0.5; }
}

/* === MAIN WINDOW === */
window {
    background-color: #000000;
}

/* === HEADER - TOP COCKPIT PANEL === */
.dashboard-header {
    background-color: #0a0a0a;
    border-bottom: 1px solid #ffffff;
    padding: 16px 24px;
}

.main-title {
    font-size: 24px;
    font-weight: 900;
    color: #ffffff;
    letter-spacing: 4px;
}

.subtitle {
    font-size: 11px;
    color: #aaaaaa;
    letter-spacing: 2px;
}

/* === CARDS - HUD PANELS === */
.card {
    background-color: #0a0a0a;
    border: 1px solid #444444;
    border-radius: 2px;
    padding: 16px;
    margin: 8px;
}

.card:hover {
    border-color: #ffffff;
}

.card-title {
    font-size: 12px;
    font-weight: bold;
    color: #ffffff;
    letter-spacing: 2px;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid #333333;
}

/* === THREAT LEVELS === */
.threat-critical {
    background-color: #1a0000;
    border: 1px solid #ff0000;
    border-left: 4px solid #ff0000;
}

.threat-high {
    background-color: #1a0a00;
    border: 1px solid #ff6600;
    border-left: 4px solid #ff6600;
}

.threat-medium {
    background-color: #1a1a00;
    border: 1px solid #ffcc00;
    border-left: 4px solid #ffcc00;
}

.threat-low {
    background-color: #0a0a0a;
    border: 1px solid #666666;
    border-left: 4px solid #888888;
}

.threat-info {
    background-color: #0a0a0a;
    border: 1px solid #444444;
    border-left: 4px solid #666666;
}

/* === DEFCON INDICATORS === */
.defcon-1 {
    background-color: #ff0000;
    color: #ffffff;
    font-weight: 900;
    padding: 10px 20px;
    border-radius: 2px;
    border: 2px solid #ffffff;
    animation: pulse 0.5s infinite;
}

.defcon-2 {
    background-color: #ff6600;
    color: #000000;
    font-weight: 900;
    padding: 10px 20px;
    border-radius: 2px;
    border: 2px solid #ffffff;
}

.defcon-3 {
    background-color: #ffcc00;
    color: #000000;
    font-weight: 900;
    padding: 10px 20px;
    border-radius: 2px;
    border: 2px solid #ffffff;
}

.defcon-4 {
    background-color: #333333;
    color: #ffffff;
    font-weight: 900;
    padding: 10px 20px;
    border-radius: 2px;
    border: 2px solid #888888;
}

.defcon-5 {
    background-color: #1a1a1a;
    color: #00ff00;
    font-weight: 900;
    padding: 10px 20px;
    border-radius: 2px;
    border: 2px solid #00ff00;
}

/* === STATUS INDICATORS === */
.status-active {
    color: #00ff00;
    font-weight: bold;
}

.status-inactive {
    color: #ff0000;
}

.status-warning {
    color: #ffcc00;
    animation: pulse 1s infinite;
}

/* === ACTION BUTTONS === */
.action-button {
    background-color: #1a1a1a;
    border: 1px solid #ffffff;
    color: #ffffff;
    padding: 10px 20px;
    border-radius: 2px;
    font-weight: 600;
    letter-spacing: 1px;
}

.action-button:hover {
    background-color: #333333;
    border-color: #ffffff;
}

.action-button-danger {
    background-color: #1a0000;
    border: 1px solid #ff0000;
    color: #ff0000;
}

.action-button-danger:hover {
    background-color: #330000;
}

.action-button-success {
    background-color: #001a00;
    border: 1px solid #00ff00;
    color: #00ff00;
}

.action-button-success:hover {
    background-color: #003300;
}

/* === METRICS - HUD DISPLAYS === */
.metric-value {
    font-size: 36px;
    font-weight: 900;
    color: #ffffff;
}

.metric-label {
    font-size: 11px;
    color: #888888;
    letter-spacing: 1px;
}

.metric-change-positive {
    color: #00ff00;
    font-size: 12px;
}

.metric-change-negative {
    color: #ff0000;
    font-size: 12px;
}

/* === TABLES === */
.data-table {
    background-color: #000000;
    border: 1px solid #333333;
}

.table-header {
    background-color: #1a1a1a;
    color: #ffffff;
    font-weight: bold;
    letter-spacing: 1px;
    padding: 10px 14px;
    border-bottom: 1px solid #ffffff;
}

.table-row {
    padding: 10px 14px;
    border-bottom: 1px solid #222222;
    color: #cccccc;
}

.table-row:hover {
    background-color: #1a1a1a;
}

/* === TERMINAL === */
.terminal {
    background-color: #000000;
    font-family: monospace;
    font-size: 13px;
    color: #00ff00;
    padding: 14px;
    border: 1px solid #333333;
    border-radius: 2px;
}

.log-error {
    color: #ff0000;
}

.log-warning {
    color: #ffcc00;
}

.log-info {
    color: #ffffff;
}

.log-success {
    color: #00ff00;
}

/* === COMMAND INPUT === */
.command-input {
    background-color: #000000;
    border: 1px solid #ffffff;
    border-radius: 2px;
    color: #ffffff;
    font-family: monospace;
    font-size: 14px;
    padding: 14px 18px;
}

.command-input:focus {
    border-color: #ffffff;
    box-shadow: 0 0 5px rgba(255, 255, 255, 0.3);
}

/* === TABS === */
notebook > header {
    background-color: #0a0a0a;
    border-bottom: 1px solid #444444;
}

notebook > header > tabs > tab {
    background-color: transparent;
    color: #888888;
    padding: 12px 24px;
    letter-spacing: 1px;
    border-bottom: 2px solid transparent;
}

notebook > header > tabs > tab:hover {
    color: #ffffff;
    background-color: #1a1a1a;
}

notebook > header > tabs > tab:checked {
    color: #ffffff;
    border-bottom: 2px solid #ffffff;
    background-color: #1a1a1a;
}

/* === SCROLLBARS === */
scrollbar {
    background-color: #000000;
}

scrollbar slider {
    background-color: #444444;
    border-radius: 2px;
    min-width: 8px;
}

scrollbar slider:hover {
    background-color: #666666;
}

/* === BOTTOM STATUS BAR === */
.status-bar {
    background-color: #0a0a0a;
    border-top: 1px solid #333333;
    padding: 8px 16px;
    font-size: 11px;
    color: #888888;
}

/* === WINDOW HEADER BAR === */
headerbar {
    background-color: #0a0a0a;
    border-bottom: 1px solid #444444;
}

headerbar title {
    color: #ffffff;
    font-weight: 700;
    letter-spacing: 2px;
}

/* === TOR & GHOST INDICATORS === */
.tor-active {
    background-color: #1a001a;
    color: #ff00ff;
    padding: 6px 14px;
    border-radius: 2px;
    font-weight: bold;
    border: 1px solid #ff00ff;
}

.ghost-active {
    background-color: #001a1a;
    color: #00ffff;
    padding: 6px 14px;
    border-radius: 2px;
    font-weight: bold;
    border: 1px solid #00ffff;
}

/* === MODULE PANEL === */
.module-panel {
    background-color: #0a0a0a;
    border: 1px solid #333333;
    border-radius: 2px;
    padding: 12px;
}

.module-item {
    padding: 10px 14px;
    border-bottom: 1px solid #222222;
}

.module-name {
    color: #cccccc;
    font-weight: 500;
}

.module-status-active {
    color: #00ff00;
    font-weight: bold;
}

.module-status-inactive {
    color: #666666;
}

/* === BADGES === */
.module-status-badge {
    padding: 4px 12px;
    border-radius: 2px;
    font-size: 11px;
    font-weight: bold;
    letter-spacing: 1px;
}

.badge-active {
    background-color: #003300;
    color: #00ff00;
    border: 1px solid #00ff00;
}

.badge-error {
    background-color: #330000;
    color: #ff0000;
    border: 1px solid #ff0000;
}

.badge-inactive {
    background-color: #1a1a1a;
    color: #666666;
    border: 1px solid #444444;
}

/* === SELECTION === */
selection {
    background-color: #333333;
    color: #ffffff;
}

/* === TOOLTIPS === */
tooltip {
    background-color: #1a1a1a;
    border: 1px solid #ffffff;
    color: #ffffff;
    padding: 8px 12px;
    border-radius: 2px;
}

/* === PROGRESS BARS === */
progressbar trough {
    background-color: #1a1a1a;
    border-radius: 2px;
}

progressbar progress {
    background-color: #ffffff;
    border-radius: 2px;
}

/* === BUTTONS === */
button {
    background-color: #1a1a1a;
    border: 1px solid #444444;
    color: #ffffff;
    border-radius: 2px;
    padding: 8px 16px;
}

button:hover {
    background-color: #333333;
    border-color: #ffffff;
}

button:active {
    background-color: #0a0a0a;
}

/* === ENTRIES === */
entry {
    background-color: #000000;
    border: 1px solid #444444;
    color: #ffffff;
    border-radius: 2px;
    padding: 8px 12px;
}

entry:focus {
    border-color: #ffffff;
}

/* === LABELS === */
label {
    color: #cccccc;
}

/* === CHECKBOXES AND SWITCHES === */
checkbutton check {
    background-color: #1a1a1a;
    border: 1px solid #666666;
}

checkbutton:checked check {
    background-color: #00ff00;
    border-color: #00ff00;
}

switch {
    background-color: #1a1a1a;
    border: 1px solid #444444;
}

switch:checked {
    background-color: #00ff00;
}

switch slider {
    background-color: #ffffff;
}

/* === COMBOBOX === */
combobox button {
    background-color: #1a1a1a;
    border: 1px solid #444444;
    color: #ffffff;
}

/* === LIST/TREE VIEWS === */
treeview {
    background-color: #000000;
    color: #cccccc;
}

treeview:selected {
    background-color: #333333;
    color: #ffffff;
}

treeview header button {
    background-color: #1a1a1a;
    color: #ffffff;
    border: none;
    border-bottom: 1px solid #444444;
}

/* === SEPARATOR === */
separator {
    background-color: #333333;
}

/* === SPECIAL GLOW EFFECTS === */
.glow-white {
    box-shadow: 0 0 10px rgba(255, 255, 255, 0.5);
}

.glow-green {
    box-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
}

.glow-red {
    box-shadow: 0 0 10px rgba(255, 0, 0, 0.5);
}

/* === FRAME === */
frame {
    border: 1px solid #333333;
    border-radius: 2px;
}

frame > label {
    color: #ffffff;
    font-weight: bold;
}

/* === EXPANDER === */
expander {
    border: 1px solid #333333;
}

expander title {
    color: #ffffff;
}

"""


# ============================================================================
# VERITABANI YONETIMI
# ============================================================================

class DashboardDB:
    """Dashboard yerel onbellek veritabani"""

    def __init__(self, db_path: Path = DASHBOARD_DB):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Veritabani tablolarini olustur"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Tehdit olaylari tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tehdit_olaylari (
                id TEXT PRIMARY KEY,
                zaman TIMESTAMP,
                kaynak TEXT,
                tip TEXT,
                seviye TEXT,
                aciklama TEXT,
                ip_adresi TEXT,
                port INTEGER,
                mitre_teknik TEXT,
                aksiyon_yapildi INTEGER DEFAULT 0,
                aksiyon_tipi TEXT
            )
        """)

        # Ag cihazlari tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ag_cihazlari (
                ip TEXT PRIMARY KEY,
                mac TEXT,
                hostname TEXT,
                vendor TEXT,
                ilk_gorulen TIMESTAMP,
                son_gorulen TIMESTAMP,
                guvenilir INTEGER DEFAULT 0,
                notlar TEXT
            )
        """)

        # Komut gecmisi tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS komut_gecmisi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                zaman TIMESTAMP,
                komut TEXT,
                sonuc TEXT
            )
        """)

        # Ayarlar tablosu
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ayarlar (
                anahtar TEXT PRIMARY KEY,
                deger TEXT
            )
        """)

        conn.commit()
        conn.close()

    def tehdit_ekle(self, tehdit: TehditOlayi) -> None:
        """Yeni tehdit olayi ekle"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO tehdit_olaylari
            (id, zaman, kaynak, tip, seviye, aciklama, ip_adresi, port, mitre_teknik, aksiyon_yapildi, aksiyon_tipi)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            tehdit.id, tehdit.zaman, tehdit.kaynak, tehdit.tip,
            tehdit.seviye.value, tehdit.aciklama, tehdit.ip_adresi,
            tehdit.port, tehdit.mitre_teknik, int(tehdit.aksiyon_yapildi),
            tehdit.aksiyon_tipi
        ))
        conn.commit()
        conn.close()

    def son_tehditler(self, limit: int = 50) -> List[TehditOlayi]:
        """Son tehdit olaylarini getir"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM tehdit_olaylari
            ORDER BY zaman DESC LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()

        tehditler = []
        for row in rows:
            try:
                tehditler.append(TehditOlayi(
                    id=row[0],
                    zaman=datetime.fromisoformat(row[1]) if isinstance(row[1], str) else row[1],
                    kaynak=row[2],
                    tip=row[3],
                    seviye=TehditSeviyesi(row[4]),
                    aciklama=row[5],
                    ip_adresi=row[6],
                    port=row[7],
                    mitre_teknik=row[8],
                    aksiyon_yapildi=bool(row[9]),
                    aksiyon_tipi=row[10]
                ))
            except Exception as e:
                logger.error(f"Tehdit parse hatasi: {e}")
        return tehditler

    def ayar_kaydet(self, anahtar: str, deger: Any) -> None:
        """Ayar kaydet"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO ayarlar (anahtar, deger)
            VALUES (?, ?)
        """, (anahtar, json.dumps(deger)))
        conn.commit()
        conn.close()

    def ayar_al(self, anahtar: str, varsayilan: Any = None) -> Any:
        """Ayar getir"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT deger FROM ayarlar WHERE anahtar = ?", (anahtar,))
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return varsayilan


# ============================================================================
# SISTEM IZLEME
# ============================================================================

class SistemIzleyici:
    """Sistem kaynaklarini izle"""

    def __init__(self):
        self.cpu_gecmisi = deque(maxlen=60)  # Son 60 saniye
        self.ram_gecmisi = deque(maxlen=60)
        self.ag_gecmisi = deque(maxlen=60)

    def cpu_kullanimi(self) -> float:
        """CPU kullanim yuzdesi"""
        if PSUTIL_AVAILABLE:
            return psutil.cpu_percent(interval=0.1)
        return 0.0

    def ram_kullanimi(self) -> Tuple[float, int, int]:
        """RAM kullanimi (yuzde, kullanilan_mb, toplam_mb)"""
        if PSUTIL_AVAILABLE:
            mem = psutil.virtual_memory()
            return mem.percent, mem.used // (1024 * 1024), mem.total // (1024 * 1024)
        return 0.0, 0, 0

    def disk_kullanimi(self) -> Tuple[float, int, int]:
        """Disk kullanimi (yuzde, kullanilan_gb, toplam_gb)"""
        if PSUTIL_AVAILABLE:
            disk = psutil.disk_usage('/')
            return disk.percent, disk.used // (1024 ** 3), disk.total // (1024 ** 3)
        return 0.0, 0, 0

    def ag_trafigi(self) -> Tuple[int, int]:
        """Ag trafigi (bytes_gonderilen, bytes_alinan)"""
        if PSUTIL_AVAILABLE:
            net = psutil.net_io_counters()
            return net.bytes_sent, net.bytes_recv
        return 0, 0

    def aktif_baglantilar(self) -> List[Dict]:
        """Aktif ag baglantilari"""
        if not PSUTIL_AVAILABLE:
            return []

        baglantilar = []
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status == 'ESTABLISHED':
                    baglantilar.append({
                        'yerel_ip': conn.laddr.ip if conn.laddr else '',
                        'yerel_port': conn.laddr.port if conn.laddr else 0,
                        'uzak_ip': conn.raddr.ip if conn.raddr else '',
                        'uzak_port': conn.raddr.port if conn.raddr else 0,
                        'durum': conn.status,
                        'pid': conn.pid
                    })
            except (AttributeError, PermissionError):
                pass
        return baglantilar

    def calisanlar_prosesler(self) -> List[Dict]:
        """Calisan prosesler"""
        if not PSUTIL_AVAILABLE:
            return []

        prosesler = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                if info['cpu_percent'] > 0 or info['memory_percent'] > 1:
                    prosesler.append(info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return sorted(prosesler, key=lambda x: x.get('cpu_percent', 0), reverse=True)[:20]

    def guncelle(self):
        """Gecmis verilerini guncelle"""
        self.cpu_gecmisi.append(self.cpu_kullanimi())
        ram_pct, _, _ = self.ram_kullanimi()
        self.ram_gecmisi.append(ram_pct)


# ============================================================================
# TSUNAMI ENTEGRASYONU
# ============================================================================

class TsunamiEntegrasyon:
    """TSUNAMI modulleri ile entegrasyon"""

    def __init__(self):
        self.beyin_aktif = False
        self.guardian_aktif = False
        self.ghost_mod = False
        self.tor_aktif = False
        self.defcon = DefconSeviyesi.DEFCON_5

    def modul_durumu_kontrol(self) -> Dict[str, ModulDurum]:
        """Tum modullerin durumunu kontrol et"""
        durumlar = {}

        # BEYIN kontrolu (Web server ile birlikte calisiyor)
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'dalga_web.py'],
                capture_output=True, text=True, timeout=5
            )
            durumlar['BEYIN'] = ModulDurum.AKTIF if result.returncode == 0 else ModulDurum.PASIF
        except Exception:
            durumlar['BEYIN'] = ModulDurum.PASIF

        # Network Guardian kontrolu (systemd user service)
        try:
            result = subprocess.run(
                ['systemctl', '--user', 'is-active', 'tsunami-guardian.service'],
                capture_output=True, text=True, timeout=5
            )
            if result.stdout.strip() == 'active':
                durumlar['Network Guardian'] = ModulDurum.AKTIF
            else:
                # Fallback: process kontrolu
                result2 = subprocess.run(
                    ['pgrep', '-f', 'network_guardian.py'],
                    capture_output=True, text=True, timeout=5
                )
                durumlar['Network Guardian'] = ModulDurum.AKTIF if result2.returncode == 0 else ModulDurum.PASIF
        except Exception:
            durumlar['Network Guardian'] = ModulDurum.PASIF

        # TOR kontrolu (system service)
        try:
            result = subprocess.run(
                ['systemctl', 'is-active', 'tor'],
                capture_output=True, text=True, timeout=5
            )
            self.tor_aktif = result.stdout.strip() == 'active'
            durumlar['TOR'] = ModulDurum.AKTIF if self.tor_aktif else ModulDurum.PASIF
        except Exception:
            durumlar['TOR'] = ModulDurum.PASIF

        # Web Server kontrolu
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'dalga_web.py'],
                capture_output=True, text=True, timeout=5
            )
            durumlar['Web Server'] = ModulDurum.AKTIF if result.returncode == 0 else ModulDurum.PASIF
        except Exception:
            durumlar['Web Server'] = ModulDurum.PASIF

        # Ghost Mode kontrolu (config + API)
        try:
            if TSUNAMI_CONFIG.exists():
                with open(TSUNAMI_CONFIG) as f:
                    config = json.load(f)
                    self.ghost_mod = config.get('stealth', {}).get('ghost_mode', False)
                    durumlar['Ghost Mode'] = ModulDurum.AKTIF if self.ghost_mod else ModulDurum.PASIF
            else:
                durumlar['Ghost Mode'] = ModulDurum.PASIF
        except Exception:
            durumlar['Ghost Mode'] = ModulDurum.PASIF

        # Defender kontrolu
        try:
            result = subprocess.run(
                ['pgrep', '-f', 'tsunami_defender.py'],
                capture_output=True, text=True, timeout=5
            )
            durumlar['Defender'] = ModulDurum.AKTIF if result.returncode == 0 else ModulDurum.PASIF
        except Exception:
            durumlar['Defender'] = ModulDurum.PASIF

        return durumlar

    def ip_engelle(self, ip: str) -> Tuple[bool, str]:
        """IP adresini UFW ile engelle"""
        try:
            result = subprocess.run(
                ['sudo', 'ufw', 'deny', 'from', ip],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return True, f"IP engellendi: {ip}"
            return False, f"Hata: {result.stderr}"
        except Exception as e:
            return False, f"Istisna: {str(e)}"

    def proses_sonlandir(self, pid: int) -> Tuple[bool, str]:
        """Prosesi sonlandir"""
        try:
            result = subprocess.run(
                ['kill', '-9', str(pid)],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return True, f"Proses sonlandirildi: {pid}"
            return False, f"Hata: {result.stderr}"
        except Exception as e:
            return False, f"Istisna: {str(e)}"

    def tor_kimlik_yenile(self) -> Tuple[bool, str]:
        """TOR kimligini yenile"""
        try:
            result = subprocess.run(
                ['sudo', 'killall', '-HUP', 'tor'],
                capture_output=True, text=True, timeout=10
            )
            return True, "TOR kimligi yenilendi"
        except Exception as e:
            return False, f"Hata: {str(e)}"

    def acil_tarama_baslat(self) -> Tuple[bool, str]:
        """Acil guvenlik taramasi baslat"""
        try:
            # Network Guardian tek seferlik tarama
            script_path = TSUNAMI_HOME / "scripts" / "network_guardian.py"
            if script_path.exists():
                subprocess.Popen(
                    ['python3', str(script_path), 'scan'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                return True, "Acil tarama baslatildi"
            return False, "network_guardian.py bulunamadi"
        except Exception as e:
            return False, f"Hata: {str(e)}"

    def ghost_mod_toggle(self, aktif: bool) -> Tuple[bool, str]:
        """Ghost modunu ac/kapat"""
        try:
            if TSUNAMI_CONFIG.exists():
                with open(TSUNAMI_CONFIG) as f:
                    config = json.load(f)
            else:
                config = {}

            config['ghost_mode'] = aktif
            self.ghost_mod = aktif

            with open(TSUNAMI_CONFIG, 'w') as f:
                json.dump(config, f, indent=2)

            durum = "aktif" if aktif else "pasif"
            return True, f"Ghost modu {durum}"
        except Exception as e:
            return False, f"Hata: {str(e)}"

    def defcon_seviyesi_al(self) -> DefconSeviyesi:
        """Mevcut DEFCON seviyesini al"""
        try:
            if TSUNAMI_DB.exists():
                conn = sqlite3.connect(TSUNAMI_DB)
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT value FROM system_state WHERE key = 'defcon_level'
                """)
                row = cursor.fetchone()
                conn.close()
                if row:
                    return DefconSeviyesi(int(row[0]))
        except Exception:
            pass
        return DefconSeviyesi.DEFCON_5


# ============================================================================
# HIZLI AKSIYON WIDGETLARI
# ============================================================================

class HizliAksiyonButonu(Gtk.Button):
    """Hizli aksiyon butonu"""

    def __init__(self, etiket: str, ikon: str, tehlikeli: bool = False, basarili: bool = False):
        super().__init__()

        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        # Ikon
        ikon_widget = Gtk.Label(label=ikon)
        box.append(ikon_widget)

        # Etiket
        etiket_widget = Gtk.Label(label=etiket)
        box.append(etiket_widget)

        self.set_child(box)

        # CSS sinifi
        if tehlikeli:
            self.add_css_class('action-button-danger')
        elif basarili:
            self.add_css_class('action-button-success')
        else:
            self.add_css_class('action-button')


# ============================================================================
# TEHDIT KARTI WIDGET
# ============================================================================

class TehditKarti(Gtk.Box):
    """Tehdit olayi karti"""

    def __init__(self, tehdit: TehditOlayi, on_action=None):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.tehdit = tehdit
        self.on_action = on_action

        # CSS sinifi
        self.add_css_class('card')
        seviye_css = f'threat-{tehdit.seviye.value}'
        self.add_css_class(seviye_css)

        # Ust kisim: Zaman ve Seviye
        ust_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ust_box.set_hexpand(True)

        # Zaman
        zaman_str = tehdit.zaman.strftime("%H:%M:%S") if isinstance(tehdit.zaman, datetime) else str(tehdit.zaman)
        zaman_label = Gtk.Label(label=zaman_str)
        zaman_label.add_css_class('subtitle')
        zaman_label.set_halign(Gtk.Align.START)
        ust_box.append(zaman_label)

        # Bosluk
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        ust_box.append(spacer)

        # Seviye badge
        seviye_badge = Gtk.Label(label=tehdit.seviye.value.upper())
        seviye_badge.add_css_class('module-status-badge')
        if tehdit.seviye == TehditSeviyesi.KRITIK:
            seviye_badge.add_css_class('badge-error')
        elif tehdit.seviye == TehditSeviyesi.YUKSEK:
            seviye_badge.add_css_class('badge-error')
        else:
            seviye_badge.add_css_class('badge-active')
        ust_box.append(seviye_badge)

        self.append(ust_box)

        # Tip ve Kaynak
        tip_label = Gtk.Label(label=f"{tehdit.tip} - {tehdit.kaynak}")
        tip_label.add_css_class('card-title')
        tip_label.set_halign(Gtk.Align.START)
        self.append(tip_label)

        # Aciklama
        aciklama_label = Gtk.Label(label=tehdit.aciklama)
        aciklama_label.set_wrap(True)
        aciklama_label.set_halign(Gtk.Align.START)
        aciklama_label.set_max_width_chars(60)
        self.append(aciklama_label)

        # IP ve Port (varsa)
        if tehdit.ip_adresi:
            ip_text = f"IP: {tehdit.ip_adresi}"
            if tehdit.port:
                ip_text += f":{tehdit.port}"
            ip_label = Gtk.Label(label=ip_text)
            ip_label.add_css_class('terminal')
            ip_label.set_halign(Gtk.Align.START)
            self.append(ip_label)

        # MITRE ATT&CK (varsa)
        if tehdit.mitre_teknik:
            mitre_label = Gtk.Label(label=f"MITRE: {tehdit.mitre_teknik}")
            mitre_label.add_css_class('log-info')
            mitre_label.set_halign(Gtk.Align.START)
            self.append(mitre_label)

        # Aksiyon butonlari
        if not tehdit.aksiyon_yapildi and tehdit.ip_adresi:
            aksiyon_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            aksiyon_box.set_margin_top(8)

            engelle_btn = HizliAksiyonButonu("IP Engelle", "🚫", tehlikeli=True)
            engelle_btn.connect('clicked', self._on_ip_engelle)
            aksiyon_box.append(engelle_btn)

            ayrinti_btn = HizliAksiyonButonu("Detay", "🔍")
            aksiyon_box.append(ayrinti_btn)

            self.append(aksiyon_box)

    def _on_ip_engelle(self, button):
        """IP engelleme aksiyonu"""
        if self.on_action:
            self.on_action('ip_engelle', self.tehdit)


# ============================================================================
# MODUL DURUM KARTI
# ============================================================================

class ModulDurumKarti(Gtk.Box):
    """Modul durum karti"""

    def __init__(self, isim: str, durum: ModulDurum, aciklama: str = ""):
        super().__init__(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.add_css_class('module-card')
        self.set_hexpand(True)

        # Sol: Ikon ve isim
        sol_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)

        isim_label = Gtk.Label(label=isim)
        isim_label.add_css_class('module-name')
        isim_label.set_halign(Gtk.Align.START)
        sol_box.append(isim_label)

        if aciklama:
            aciklama_label = Gtk.Label(label=aciklama)
            aciklama_label.add_css_class('subtitle')
            aciklama_label.set_halign(Gtk.Align.START)
            sol_box.append(aciklama_label)

        self.append(sol_box)

        # Bosluk
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        self.append(spacer)

        # Sag: Durum badge
        durum_text = {
            ModulDurum.AKTIF: "AKTIF",
            ModulDurum.PASIF: "PASIF",
            ModulDurum.HATA: "HATA",
            ModulDurum.BASLATIYOR: "BASLATIYOR"
        }.get(durum, "BILINMIYOR")

        badge = Gtk.Label(label=durum_text)
        badge.add_css_class('module-status-badge')

        if durum == ModulDurum.AKTIF:
            badge.add_css_class('badge-active')
        elif durum == ModulDurum.HATA:
            badge.add_css_class('badge-error')
        else:
            badge.add_css_class('badge-inactive')

        self.append(badge)


# ============================================================================
# METRIK KARTI
# ============================================================================

class MetrikKarti(Gtk.Box):
    """Metrik gosterge karti"""

    def __init__(self, baslik: str, deger: str, birim: str = "", degisim: str = ""):
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.add_css_class('card')
        self.set_size_request(150, 100)

        # Baslik
        baslik_label = Gtk.Label(label=baslik)
        baslik_label.add_css_class('metric-label')
        baslik_label.set_halign(Gtk.Align.START)
        self.append(baslik_label)

        # Deger
        deger_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=4)
        deger_label = Gtk.Label(label=deger)
        deger_label.add_css_class('metric-value')
        deger_box.append(deger_label)

        if birim:
            birim_label = Gtk.Label(label=birim)
            birim_label.add_css_class('metric-label')
            birim_label.set_valign(Gtk.Align.END)
            birim_label.set_margin_bottom(8)
            deger_box.append(birim_label)

        self.append(deger_box)

        # Degisim
        if degisim:
            degisim_label = Gtk.Label(label=degisim)
            if degisim.startswith('+'):
                degisim_label.add_css_class('metric-change-positive')
            elif degisim.startswith('-'):
                degisim_label.add_css_class('metric-change-negative')
            degisim_label.set_halign(Gtk.Align.START)
            self.append(degisim_label)

        self.deger_label = deger_label

    def deger_guncelle(self, yeni_deger: str):
        """Deger guncelle"""
        self.deger_label.set_text(yeni_deger)


# ============================================================================
# ANA DASHBOARD PENCERESI
# ============================================================================

class TsunamiDashboard(Gtk.ApplicationWindow):
    """Ana dashboard penceresi - Hacker Cockpit Style"""

    def __init__(self, app):
        super().__init__(application=app, title="TSUNAMI Siber Komuta Merkezi")

        # Pencere ayarlari - kucultup buyutme aktif
        self.set_default_size(1200, 750)
        self.set_resizable(True)

        # HeaderBar ile pencere kontrolleri (kucult, buyut, kapat)
        header = Gtk.HeaderBar()
        header.set_show_title_buttons(True)  # Minimize, Maximize, Close butonlari
        header.set_title_widget(Gtk.Label(label="TSUNAMI Siber Komuta Merkezi"))
        self.set_titlebar(header)

        # Bildirim sistemi
        self.bildirim_aktif = True

        # Bilesenler
        self.db = DashboardDB()
        self.sistem = SistemIzleyici()
        self.tsunami = TsunamiEntegrasyon()

        # Durum
        self.tehditler: List[TehditOlayi] = []
        self.log_mesajlari: deque = deque(maxlen=100)

        # UI olustur
        self._css_yukle()
        self._ui_olustur()

        # Zamanlayicilar
        self._zamanlayicilar_baslat()

        # Baslangic verileri
        self._verileri_guncelle()

    def _css_yukle(self):
        """CSS temasini yukle"""
        css_provider = Gtk.CssProvider()
        css_provider.load_from_data(DASHBOARD_CSS.encode())
        Gtk.StyleContext.add_provider_for_display(
            Gdk.Display.get_default(),
            css_provider,
            Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

    def _ui_olustur(self):
        """Ana UI yapisini olustur"""
        # Ana kutu
        ana_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        # Baslik cubugu
        header = self._baslik_olustur()
        ana_kutu.append(header)

        # Tab notebook
        self.notebook = Gtk.Notebook()
        self.notebook.set_vexpand(True)

        # Sekmeleri olustur
        self._genel_bakis_sekmesi_olustur()
        self._tehditler_sekmesi_olustur()
        self._ag_izleme_sekmesi_olustur()
        self._olaylar_sekmesi_olustur()
        self._hizli_komut_sekmesi_olustur()
        self._ayarlar_sekmesi_olustur()

        ana_kutu.append(self.notebook)

        # Alt bilgi cubugu
        alt_bilgi = self._alt_bilgi_olustur()
        ana_kutu.append(alt_bilgi)

        self.set_child(ana_kutu)

    def _baslik_olustur(self) -> Gtk.Box:
        """Baslik cubugu olustur"""
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        header.add_css_class('dashboard-header')

        # Logo ve baslik
        baslik_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)

        baslik = Gtk.Label(label="🌊 TSUNAMI GUVENLIK MERKEZI")
        baslik.add_css_class('main-title')
        baslik.set_halign(Gtk.Align.START)
        baslik_box.append(baslik)

        alt_baslik = Gtk.Label(label="SOC Analisti Kontrol Paneli | v1.0")
        alt_baslik.add_css_class('subtitle')
        alt_baslik.set_halign(Gtk.Align.START)
        baslik_box.append(alt_baslik)

        header.append(baslik_box)

        # Bosluk
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        header.append(spacer)

        # Stealth gostergeleri
        stealth_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        # TOR durumu
        self.tor_badge = Gtk.Label(label="TOR")
        self.tor_badge.add_css_class('stealth-indicator')
        self.tor_badge.add_css_class('stealth-inactive')
        stealth_box.append(self.tor_badge)

        # Ghost durumu
        self.ghost_badge = Gtk.Label(label="GHOST")
        self.ghost_badge.add_css_class('stealth-indicator')
        self.ghost_badge.add_css_class('stealth-inactive')
        stealth_box.append(self.ghost_badge)

        header.append(stealth_box)

        # DEFCON gostergesi
        self.defcon_label = Gtk.Label(label="DEFCON 5")
        self.defcon_label.add_css_class('defcon-5')
        header.append(self.defcon_label)

        return header

    def _alt_bilgi_olustur(self) -> Gtk.Box:
        """Alt bilgi cubugu"""
        alt = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        alt.add_css_class('card')
        alt.set_margin_start(8)
        alt.set_margin_end(8)
        alt.set_margin_bottom(8)

        # Son guncelleme
        self.son_guncelleme_label = Gtk.Label(label="Son Guncelleme: --:--:--")
        self.son_guncelleme_label.add_css_class('subtitle')
        alt.append(self.son_guncelleme_label)

        # Bosluk
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        alt.append(spacer)

        # Sistem bilgisi
        self.sistem_bilgi_label = Gtk.Label(label="CPU: --% | RAM: --% | Disk: --%")
        self.sistem_bilgi_label.add_css_class('subtitle')
        alt.append(self.sistem_bilgi_label)

        return alt

    # ========================================================================
    # GENEL BAKIS SEKMESI
    # ========================================================================

    def _genel_bakis_sekmesi_olustur(self):
        """Genel bakis sekmesi"""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        ana_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        ana_kutu.set_margin_start(16)
        ana_kutu.set_margin_end(16)
        ana_kutu.set_margin_top(16)
        ana_kutu.set_margin_bottom(16)

        # Ust metrikler
        metrik_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        metrik_box.set_homogeneous(True)

        self.tehdit_sayisi_kart = MetrikKarti("Aktif Tehditler", "0", "", "")
        metrik_box.append(self.tehdit_sayisi_kart)

        self.engellenen_ip_kart = MetrikKarti("Engellenen IP", "0", "", "")
        metrik_box.append(self.engellenen_ip_kart)

        self.aktif_baglanti_kart = MetrikKarti("Aktif Baglantilar", "0", "", "")
        metrik_box.append(self.aktif_baglanti_kart)

        self.tehdit_skoru_kart = MetrikKarti("Tehdit Skoru", "0", "/100", "")
        metrik_box.append(self.tehdit_skoru_kart)

        ana_kutu.append(metrik_box)

        # Ortada: Modul durumu ve Son tehditler
        orta_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)

        # Sol: Modul durumu
        modul_frame = Gtk.Frame(label="Modul Durumu")
        modul_frame.add_css_class('card')
        modul_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        modul_kutu.set_margin_start(12)
        modul_kutu.set_margin_end(12)
        modul_kutu.set_margin_top(12)
        modul_kutu.set_margin_bottom(12)

        self.modul_durumu_kutu = modul_kutu
        modul_frame.set_child(modul_kutu)
        modul_frame.set_size_request(350, -1)
        orta_box.append(modul_frame)

        # Sag: Son tehditler
        tehdit_frame = Gtk.Frame(label="Son Tehditler")
        tehdit_frame.add_css_class('card')
        tehdit_frame.set_hexpand(True)

        tehdit_scroll = Gtk.ScrolledWindow()
        tehdit_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        tehdit_scroll.set_min_content_height(300)

        self.son_tehditler_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.son_tehditler_kutu.set_margin_start(12)
        self.son_tehditler_kutu.set_margin_end(12)
        self.son_tehditler_kutu.set_margin_top(12)
        self.son_tehditler_kutu.set_margin_bottom(12)

        tehdit_scroll.set_child(self.son_tehditler_kutu)
        tehdit_frame.set_child(tehdit_scroll)
        orta_box.append(tehdit_frame)

        ana_kutu.append(orta_box)

        # Hizli aksiyonlar
        aksiyon_frame = Gtk.Frame(label="Hizli Aksiyonlar")
        aksiyon_frame.add_css_class('card')

        aksiyon_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        aksiyon_box.set_margin_start(12)
        aksiyon_box.set_margin_end(12)
        aksiyon_box.set_margin_top(12)
        aksiyon_box.set_margin_bottom(12)
        aksiyon_box.set_halign(Gtk.Align.CENTER)

        btn_acil_tarama = HizliAksiyonButonu("Acil Tarama", "🔍", tehlikeli=True)
        btn_acil_tarama.connect('clicked', self._on_acil_tarama)
        aksiyon_box.append(btn_acil_tarama)

        btn_tor_yenile = HizliAksiyonButonu("TOR Yenile", "🔄")
        btn_tor_yenile.connect('clicked', self._on_tor_yenile)
        aksiyon_box.append(btn_tor_yenile)

        btn_ghost_toggle = HizliAksiyonButonu("Ghost Mod", "👻")
        btn_ghost_toggle.connect('clicked', self._on_ghost_toggle)
        aksiyon_box.append(btn_ghost_toggle)

        btn_loglari_gor = HizliAksiyonButonu("Loglari Gor", "📋", basarili=True)
        btn_loglari_gor.connect('clicked', self._on_loglari_gor)
        aksiyon_box.append(btn_loglari_gor)

        btn_yedek_al = HizliAksiyonButonu("Yedek Al", "💾", basarili=True)
        btn_yedek_al.connect('clicked', self._on_yedek_al)
        aksiyon_box.append(btn_yedek_al)

        aksiyon_frame.set_child(aksiyon_box)
        ana_kutu.append(aksiyon_frame)

        scroll.set_child(ana_kutu)
        self.notebook.append_page(scroll, Gtk.Label(label="GENEL BAKIS"))

    # ========================================================================
    # TEHDITLER SEKMESI
    # ========================================================================

    def _tehditler_sekmesi_olustur(self):
        """Tehditler sekmesi"""
        ana_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        ana_kutu.set_margin_start(16)
        ana_kutu.set_margin_end(16)
        ana_kutu.set_margin_top(16)
        ana_kutu.set_margin_bottom(16)

        # Filtre cubugu
        filtre_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        # Seviye filtresi
        seviye_label = Gtk.Label(label="Seviye:")
        filtre_box.append(seviye_label)

        self.seviye_combo = Gtk.ComboBoxText()
        self.seviye_combo.append_text("Tumu")
        self.seviye_combo.append_text("Kritik")
        self.seviye_combo.append_text("Yuksek")
        self.seviye_combo.append_text("Orta")
        self.seviye_combo.append_text("Dusuk")
        self.seviye_combo.set_active(0)
        self.seviye_combo.connect('changed', self._on_filtre_degisti)
        filtre_box.append(self.seviye_combo)

        # Arama
        self.arama_entry = Gtk.Entry()
        self.arama_entry.set_placeholder_text("Ara...")
        self.arama_entry.set_hexpand(True)
        self.arama_entry.connect('changed', self._on_filtre_degisti)
        filtre_box.append(self.arama_entry)

        # Yenile butonu
        yenile_btn = HizliAksiyonButonu("Yenile", "🔄")
        yenile_btn.connect('clicked', lambda w: self._tehditler_guncelle())
        filtre_box.append(yenile_btn)

        ana_kutu.append(filtre_box)

        # Tehdit listesi
        tehdit_scroll = Gtk.ScrolledWindow()
        tehdit_scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        tehdit_scroll.set_vexpand(True)

        self.tehdit_listesi_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        tehdit_scroll.set_child(self.tehdit_listesi_kutu)

        ana_kutu.append(tehdit_scroll)

        self.notebook.append_page(ana_kutu, Gtk.Label(label="TEHDITLER"))

    # ========================================================================
    # AG IZLEME SEKMESI
    # ========================================================================

    def _ag_izleme_sekmesi_olustur(self):
        """Ag izleme sekmesi"""
        ana_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        ana_kutu.set_margin_start(16)
        ana_kutu.set_margin_end(16)
        ana_kutu.set_margin_top(16)
        ana_kutu.set_margin_bottom(16)

        # Ag istatistikleri
        istatistik_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
        istatistik_box.set_homogeneous(True)

        self.ag_gonderilen_kart = MetrikKarti("Gonderilen", "0", "MB", "")
        istatistik_box.append(self.ag_gonderilen_kart)

        self.ag_alinan_kart = MetrikKarti("Alinan", "0", "MB", "")
        istatistik_box.append(self.ag_alinan_kart)

        self.ag_cihaz_kart = MetrikKarti("Cihazlar", "0", "", "")
        istatistik_box.append(self.ag_cihaz_kart)

        ana_kutu.append(istatistik_box)

        # Aktif baglantilar
        baglanti_frame = Gtk.Frame(label="Aktif Baglantilar")
        baglanti_frame.add_css_class('card')
        baglanti_frame.set_vexpand(True)

        baglanti_scroll = Gtk.ScrolledWindow()
        baglanti_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        # Liste store ve tree view
        self.baglanti_store = Gtk.ListStore(str, str, str, str, str, int)
        self.baglanti_view = Gtk.TreeView(model=self.baglanti_store)

        kolonlar = [
            ("Yerel IP", 0),
            ("Yerel Port", 1),
            ("Uzak IP", 2),
            ("Uzak Port", 3),
            ("Durum", 4),
            ("PID", 5)
        ]

        for baslik, idx in kolonlar:
            renderer = Gtk.CellRendererText()
            column = Gtk.TreeViewColumn(baslik, renderer, text=idx)
            column.set_resizable(True)
            self.baglanti_view.append_column(column)

        baglanti_scroll.set_child(self.baglanti_view)
        baglanti_frame.set_child(baglanti_scroll)
        ana_kutu.append(baglanti_frame)

        self.notebook.append_page(ana_kutu, Gtk.Label(label="AG IZLEME"))

    # ========================================================================
    # OLAYLAR SEKMESI
    # ========================================================================

    def _olaylar_sekmesi_olustur(self):
        """Olaylar sekmesi - log goruntuleyici"""
        ana_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        ana_kutu.set_margin_start(16)
        ana_kutu.set_margin_end(16)
        ana_kutu.set_margin_top(16)
        ana_kutu.set_margin_bottom(16)

        # Kontroller
        kontrol_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        # Log seviyesi
        seviye_label = Gtk.Label(label="Seviye:")
        kontrol_box.append(seviye_label)

        self.log_seviye_combo = Gtk.ComboBoxText()
        self.log_seviye_combo.append_text("Tumu")
        self.log_seviye_combo.append_text("ERROR")
        self.log_seviye_combo.append_text("WARNING")
        self.log_seviye_combo.append_text("INFO")
        self.log_seviye_combo.set_active(0)
        kontrol_box.append(self.log_seviye_combo)

        # Bosluk
        spacer = Gtk.Box()
        spacer.set_hexpand(True)
        kontrol_box.append(spacer)

        # Temizle butonu
        temizle_btn = HizliAksiyonButonu("Temizle", "🗑️", tehlikeli=True)
        temizle_btn.connect('clicked', self._on_log_temizle)
        kontrol_box.append(temizle_btn)

        ana_kutu.append(kontrol_box)

        # Log alani
        log_scroll = Gtk.ScrolledWindow()
        log_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        log_scroll.set_vexpand(True)

        self.log_text = Gtk.TextView()
        self.log_text.set_editable(False)
        self.log_text.set_monospace(True)
        self.log_text.add_css_class('terminal')

        # Tag'ler olustur
        buffer = self.log_text.get_buffer()
        buffer.create_tag("error", foreground="#f85149")
        buffer.create_tag("warning", foreground="#ffa657")
        buffer.create_tag("info", foreground="#58a6ff")
        buffer.create_tag("success", foreground="#3fb950")

        log_scroll.set_child(self.log_text)
        ana_kutu.append(log_scroll)

        self.notebook.append_page(ana_kutu, Gtk.Label(label="OLAYLAR"))

    # ========================================================================
    # HIZLI KOMUT SEKMESI
    # ========================================================================

    def _hizli_komut_sekmesi_olustur(self):
        """Hizli komut sekmesi - NLP arayuzu"""
        ana_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        ana_kutu.set_margin_start(16)
        ana_kutu.set_margin_end(16)
        ana_kutu.set_margin_top(16)
        ana_kutu.set_margin_bottom(16)

        # Aciklama
        aciklama = Gtk.Label(label="Turkce dogal dil komutlari girin. Ornek: 'supheli IP adresi 192.168.1.100 engelle' veya 'son 24 saatteki tehditler'")
        aciklama.set_wrap(True)
        aciklama.add_css_class('subtitle')
        ana_kutu.append(aciklama)

        # Komut giris
        giris_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        self.komut_entry = Gtk.Entry()
        self.komut_entry.set_placeholder_text("Komut girin...")
        self.komut_entry.add_css_class('command-input')
        self.komut_entry.set_hexpand(True)
        self.komut_entry.connect('activate', self._on_komut_calistir)
        giris_box.append(self.komut_entry)

        calistir_btn = HizliAksiyonButonu("Calistir", "▶️", basarili=True)
        calistir_btn.connect('clicked', self._on_komut_calistir)
        giris_box.append(calistir_btn)

        ana_kutu.append(giris_box)

        # Ornek komutlar
        ornek_frame = Gtk.Frame(label="Ornek Komutlar")
        ornek_frame.add_css_class('card')

        ornek_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        ornek_box.set_margin_start(12)
        ornek_box.set_margin_end(12)
        ornek_box.set_margin_top(12)
        ornek_box.set_margin_bottom(12)

        ornekler = [
            "• 'IP engelle 192.168.1.100' - Belirtilen IP'yi engeller",
            "• 'son tehditler goster' - Son tehdit olaylarini listeler",
            "• 'sistem durumu' - Tum modullerin durumunu gosterir",
            "• 'acil tarama baslat' - Acil guvenlik taramasi baslatir",
            "• 'TOR yenile' - TOR kimligini yeniler",
            "• 'ghost modu ac/kapat' - Gizli modu ac/kapat",
            "• 'kim bagli' - Aga bagli cihazlari listeler",
        ]

        for ornek in ornekler:
            label = Gtk.Label(label=ornek)
            label.set_halign(Gtk.Align.START)
            label.add_css_class('terminal')
            ornek_box.append(label)

        ornek_frame.set_child(ornek_box)
        ana_kutu.append(ornek_frame)

        # Sonuc alani
        sonuc_frame = Gtk.Frame(label="Sonuc")
        sonuc_frame.add_css_class('card')
        sonuc_frame.set_vexpand(True)

        sonuc_scroll = Gtk.ScrolledWindow()
        sonuc_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        self.komut_sonuc = Gtk.TextView()
        self.komut_sonuc.set_editable(False)
        self.komut_sonuc.set_monospace(True)
        self.komut_sonuc.add_css_class('terminal')

        sonuc_scroll.set_child(self.komut_sonuc)
        sonuc_frame.set_child(sonuc_scroll)
        ana_kutu.append(sonuc_frame)

        self.notebook.append_page(ana_kutu, Gtk.Label(label="HIZLI KOMUT"))

    # ========================================================================
    # AYARLAR SEKMESI
    # ========================================================================

    def _ayarlar_sekmesi_olustur(self):
        """Ayarlar sekmesi"""
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)

        ana_kutu = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=16)
        ana_kutu.set_margin_start(16)
        ana_kutu.set_margin_end(16)
        ana_kutu.set_margin_top(16)
        ana_kutu.set_margin_bottom(16)

        # Bildirim ayarlari
        bildirim_frame = Gtk.Frame(label="Bildirim Ayarlari")
        bildirim_frame.add_css_class('card')

        bildirim_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        bildirim_box.set_margin_start(12)
        bildirim_box.set_margin_end(12)
        bildirim_box.set_margin_top(12)
        bildirim_box.set_margin_bottom(12)

        # Bildirimler aktif
        bildirim_switch_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        bildirim_label = Gtk.Label(label="Masaustu Bildirimleri")
        bildirim_label.set_hexpand(True)
        bildirim_label.set_halign(Gtk.Align.START)
        bildirim_switch_box.append(bildirim_label)

        self.bildirim_switch = Gtk.Switch()
        self.bildirim_switch.set_active(self.db.ayar_al('bildirimler_aktif', True))
        self.bildirim_switch.connect('state-set', self._on_bildirim_ayar)
        bildirim_switch_box.append(self.bildirim_switch)
        bildirim_box.append(bildirim_switch_box)

        # Ses aktif
        ses_switch_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ses_label = Gtk.Label(label="Sesli Uyarilar")
        ses_label.set_hexpand(True)
        ses_label.set_halign(Gtk.Align.START)
        ses_switch_box.append(ses_label)

        self.ses_switch = Gtk.Switch()
        self.ses_switch.set_active(self.db.ayar_al('sesler_aktif', True))
        self.ses_switch.connect('state-set', self._on_ses_ayar)
        ses_switch_box.append(self.ses_switch)
        bildirim_box.append(ses_switch_box)

        bildirim_frame.set_child(bildirim_box)
        ana_kutu.append(bildirim_frame)

        # Guvenlik ayarlari
        guvenlik_frame = Gtk.Frame(label="Guvenlik Ayarlari")
        guvenlik_frame.add_css_class('card')

        guvenlik_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        guvenlik_box.set_margin_start(12)
        guvenlik_box.set_margin_end(12)
        guvenlik_box.set_margin_top(12)
        guvenlik_box.set_margin_bottom(12)

        # Otomatik engelleme
        oto_engelle_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        oto_engelle_label = Gtk.Label(label="Otomatik IP Engelleme")
        oto_engelle_label.set_hexpand(True)
        oto_engelle_label.set_halign(Gtk.Align.START)
        oto_engelle_box.append(oto_engelle_label)

        self.oto_engelle_switch = Gtk.Switch()
        self.oto_engelle_switch.set_active(self.db.ayar_al('otomatik_engelleme', False))
        self.oto_engelle_switch.connect('state-set', self._on_oto_engelle_ayar)
        oto_engelle_box.append(self.oto_engelle_switch)
        guvenlik_box.append(oto_engelle_box)

        # Ghost mod varsayilan
        ghost_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        ghost_label = Gtk.Label(label="Baslangicta Ghost Modu")
        ghost_label.set_hexpand(True)
        ghost_label.set_halign(Gtk.Align.START)
        ghost_box.append(ghost_label)

        self.ghost_baslangic_switch = Gtk.Switch()
        self.ghost_baslangic_switch.set_active(self.db.ayar_al('ghost_baslangic', False))
        self.ghost_baslangic_switch.connect('state-set', self._on_ghost_baslangic_ayar)
        ghost_box.append(self.ghost_baslangic_switch)
        guvenlik_box.append(ghost_box)

        guvenlik_frame.set_child(guvenlik_box)
        ana_kutu.append(guvenlik_frame)

        # Guncelleme ayarlari
        guncelleme_frame = Gtk.Frame(label="Guncelleme Araliklari")
        guncelleme_frame.add_css_class('card')

        guncelleme_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        guncelleme_box.set_margin_start(12)
        guncelleme_box.set_margin_end(12)
        guncelleme_box.set_margin_top(12)
        guncelleme_box.set_margin_bottom(12)

        # Guncelleme araligi
        aralik_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        aralik_label = Gtk.Label(label="Guncelleme Araligi (saniye):")
        aralik_label.set_halign(Gtk.Align.START)
        aralik_box.append(aralik_label)

        self.aralik_spin = Gtk.SpinButton()
        self.aralik_spin.set_range(1, 60)
        self.aralik_spin.set_value(self.db.ayar_al('guncelleme_araligi', 5))
        self.aralik_spin.set_increments(1, 5)
        self.aralik_spin.connect('value-changed', self._on_aralik_degisti)
        aralik_box.append(self.aralik_spin)

        guncelleme_box.append(aralik_box)
        guncelleme_frame.set_child(guncelleme_box)
        ana_kutu.append(guncelleme_frame)

        # Hakkinda
        hakkinda_frame = Gtk.Frame(label="Hakkinda")
        hakkinda_frame.add_css_class('card')

        hakkinda_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        hakkinda_box.set_margin_start(12)
        hakkinda_box.set_margin_end(12)
        hakkinda_box.set_margin_top(12)
        hakkinda_box.set_margin_bottom(12)

        hakkinda_text = """TSUNAMI Guvenlik Dashboard v1.0
Dunya Sinifi Elite Hacker Guvenlik Merkezi

SOC Analisti Is Istasyonu
AILYDIAN Projesi

Ozellikler:
- Gercek zamanli tehdit goruntulemesi
- MITRE ATT&CK entegrasyonu
- BEYIN, Defender, Network Guardian entegrasyonu
- Hizli mudahale yetenekleri
- Profesyonel karanlik tema"""

        hakkinda_label = Gtk.Label(label=hakkinda_text)
        hakkinda_label.set_halign(Gtk.Align.START)
        hakkinda_box.append(hakkinda_label)

        hakkinda_frame.set_child(hakkinda_box)
        ana_kutu.append(hakkinda_frame)

        scroll.set_child(ana_kutu)
        self.notebook.append_page(scroll, Gtk.Label(label="AYARLAR"))

    # ========================================================================
    # OLAY ISLEYICILER
    # ========================================================================

    def _on_acil_tarama(self, button):
        """Acil tarama baslat"""
        basarili, mesaj = self.tsunami.acil_tarama_baslat()
        self._bildirim_goster("Acil Tarama", mesaj, "kritik" if not basarili else "bilgi")
        self._log_ekle(mesaj, "info" if basarili else "error")

    def _on_tor_yenile(self, button):
        """TOR kimligini yenile"""
        basarili, mesaj = self.tsunami.tor_kimlik_yenile()
        self._bildirim_goster("TOR", mesaj, "bilgi")
        self._log_ekle(mesaj, "info" if basarili else "error")

    def _on_ghost_toggle(self, button):
        """Ghost modu toggle"""
        yeni_durum = not self.tsunami.ghost_mod
        basarili, mesaj = self.tsunami.ghost_mod_toggle(yeni_durum)
        self._bildirim_goster("Ghost Modu", mesaj, "bilgi")
        self._log_ekle(mesaj, "info" if basarili else "error")
        self._stealth_guncelle()

    def _on_loglari_gor(self, button):
        """Olaylar sekmesine git"""
        self.notebook.set_current_page(3)  # OLAYLAR sekmesi

    def _on_yedek_al(self, button):
        """Yedek al"""
        try:
            yedek_dir = TSUNAMI_HOME / "backups"
            yedek_dir.mkdir(exist_ok=True)
            zaman = datetime.now().strftime("%Y%m%d_%H%M%S")
            yedek_dosya = yedek_dir / f"tsunami_backup_{zaman}.json"

            # Basit yedekleme
            yedek_veri = {
                'zaman': zaman,
                'tehditler': [asdict(t) for t in self.db.son_tehditler(100)],
                'ayarlar': {
                    'bildirimler': self.db.ayar_al('bildirimler_aktif'),
                    'sesler': self.db.ayar_al('sesler_aktif'),
                    'otomatik_engelleme': self.db.ayar_al('otomatik_engelleme')
                }
            }

            with open(yedek_dosya, 'w') as f:
                json.dump(yedek_veri, f, indent=2, default=str)

            self._bildirim_goster("Yedekleme", f"Yedek alindi: {yedek_dosya.name}", "bilgi")
            self._log_ekle(f"Yedek alindi: {yedek_dosya}", "success")
        except Exception as e:
            self._bildirim_goster("Yedekleme Hatasi", str(e), "kritik")
            self._log_ekle(f"Yedekleme hatasi: {e}", "error")

    def _on_filtre_degisti(self, widget):
        """Tehdit filtresi degisti"""
        self._tehditler_guncelle()

    def _on_log_temizle(self, button):
        """Log temizle"""
        buffer = self.log_text.get_buffer()
        buffer.set_text("")
        self.log_mesajlari.clear()

    def _on_komut_calistir(self, widget):
        """NLP komut calistir"""
        komut = self.komut_entry.get_text().strip().lower()
        if not komut:
            return

        sonuc = self._nlp_komut_isle(komut)
        buffer = self.komut_sonuc.get_buffer()
        buffer.set_text(sonuc)

        self.komut_entry.set_text("")

    def _on_bildirim_ayar(self, switch, state):
        """Bildirim ayari degisti"""
        self.db.ayar_kaydet('bildirimler_aktif', state)

    def _on_ses_ayar(self, switch, state):
        """Ses ayari degisti"""
        self.db.ayar_kaydet('sesler_aktif', state)

    def _on_oto_engelle_ayar(self, switch, state):
        """Otomatik engelleme ayari degisti"""
        self.db.ayar_kaydet('otomatik_engelleme', state)

    def _on_ghost_baslangic_ayar(self, switch, state):
        """Ghost baslangic ayari degisti"""
        self.db.ayar_kaydet('ghost_baslangic', state)

    def _on_aralik_degisti(self, spinbutton):
        """Guncelleme araligi degisti"""
        self.db.ayar_kaydet('guncelleme_araligi', int(spinbutton.get_value()))

    def _on_tehdit_aksiyon(self, aksiyon: str, tehdit: TehditOlayi):
        """Tehdit aksiyonu"""
        if aksiyon == 'ip_engelle' and tehdit.ip_adresi:
            basarili, mesaj = self.tsunami.ip_engelle(tehdit.ip_adresi)
            self._bildirim_goster("IP Engelleme", mesaj, "kritik" if not basarili else "bilgi")
            self._log_ekle(mesaj, "success" if basarili else "error")

    # ========================================================================
    # NLP KOMUT ISLEME
    # ========================================================================

    def _nlp_komut_isle(self, komut: str) -> str:
        """Turkce NLP komutlarini isle"""
        komut = komut.lower().strip()

        # IP engelle
        if 'engelle' in komut and ('ip' in komut or any(c.isdigit() for c in komut)):
            # IP adresini bul
            import re
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', komut)
            if ip_match:
                ip = ip_match.group()
                basarili, mesaj = self.tsunami.ip_engelle(ip)
                return f"Sonuc: {mesaj}"
            return "Hata: IP adresi bulunamadi. Ornek: 'IP engelle 192.168.1.100'"

        # Son tehditler
        if 'tehdit' in komut and ('son' in komut or 'goster' in komut or 'listele' in komut):
            tehditler = self.db.son_tehditler(10)
            if not tehditler:
                return "Son tehdit olayi bulunamadi."
            sonuc = "Son 10 Tehdit Olayi:\n" + "-" * 50 + "\n"
            for t in tehditler:
                sonuc += f"[{t.seviye.value.upper()}] {t.tip} - {t.aciklama[:50]}...\n"
            return sonuc

        # Sistem durumu
        if 'sistem' in komut and 'durum' in komut:
            durumlar = self.tsunami.modul_durumu_kontrol()
            sonuc = "Modul Durumlari:\n" + "-" * 30 + "\n"
            for isim, durum in durumlar.items():
                sonuc += f"{isim}: {durum.value}\n"

            cpu = self.sistem.cpu_kullanimi()
            ram_pct, ram_used, ram_total = self.sistem.ram_kullanimi()
            sonuc += f"\nSistem: CPU {cpu:.1f}% | RAM {ram_pct:.1f}% ({ram_used}MB/{ram_total}MB)"
            return sonuc

        # Acil tarama
        if 'acil' in komut and 'tarama' in komut:
            basarili, mesaj = self.tsunami.acil_tarama_baslat()
            return f"Sonuc: {mesaj}"

        # TOR yenile
        if 'tor' in komut and 'yenile' in komut:
            basarili, mesaj = self.tsunami.tor_kimlik_yenile()
            return f"Sonuc: {mesaj}"

        # Ghost modu
        if 'ghost' in komut:
            if 'ac' in komut or 'aktif' in komut:
                basarili, mesaj = self.tsunami.ghost_mod_toggle(True)
                return f"Sonuc: {mesaj}"
            elif 'kapat' in komut or 'pasif' in komut:
                basarili, mesaj = self.tsunami.ghost_mod_toggle(False)
                return f"Sonuc: {mesaj}"
            return "Ghost modu: 'ghost modu ac' veya 'ghost modu kapat'"

        # Bagli cihazlar
        if 'kim' in komut and 'bagli' in komut:
            baglantilar = self.sistem.aktif_baglantilar()
            if not baglantilar:
                return "Aktif baglanti bulunamadi."
            sonuc = f"Aktif Baglantilar ({len(baglantilar)}):\n" + "-" * 50 + "\n"
            for b in baglantilar[:20]:
                sonuc += f"{b['yerel_ip']}:{b['yerel_port']} -> {b['uzak_ip']}:{b['uzak_port']}\n"
            return sonuc

        # DEFCON durumu
        if 'defcon' in komut:
            defcon = self.tsunami.defcon_seviyesi_al()
            return f"Mevcut DEFCON Seviyesi: {defcon.value}"

        return "Komut anlasilamadi. 'yardim' yazarak ornek komutlari gorebilirsiniz."

    # ========================================================================
    # VERI GUNCELLEME
    # ========================================================================

    def _zamanlayicilar_baslat(self):
        """Periyodik guncelleme zamanlayicilari"""
        # Her 5 saniyede bir guncelle
        aralik = self.db.ayar_al('guncelleme_araligi', 5) * 1000
        GLib.timeout_add(aralik, self._periyodik_guncelleme)

    def _periyodik_guncelleme(self) -> bool:
        """Periyodik veri guncellemesi"""
        self._verileri_guncelle()
        return True  # Devam et

    def _verileri_guncelle(self):
        """Tum verileri guncelle"""
        try:
            # Sistem verileri
            self.sistem.guncelle()
            cpu = self.sistem.cpu_kullanimi()
            ram_pct, ram_used, ram_total = self.sistem.ram_kullanimi()
            disk_pct, disk_used, disk_total = self.sistem.disk_kullanimi()

            # Alt bilgi guncelle
            self.sistem_bilgi_label.set_text(
                f"CPU: {cpu:.1f}% | RAM: {ram_pct:.1f}% | Disk: {disk_pct:.1f}%"
            )
            self.son_guncelleme_label.set_text(
                f"Son Guncelleme: {datetime.now().strftime('%H:%M:%S')}"
            )

            # Modul durumlari
            self._modul_durumu_guncelle()

            # Tehditler
            self._tehditler_guncelle()

            # Stealth durumu
            self._stealth_guncelle()

            # DEFCON
            self._defcon_guncelle()

            # Ag istatistikleri
            self._ag_guncelle()

        except Exception as e:
            logger.error(f"Veri guncelleme hatasi: {e}")

    def _modul_durumu_guncelle(self):
        """Modul durumlarini guncelle"""
        # Onceki cocuklari temizle
        while child := self.modul_durumu_kutu.get_first_child():
            self.modul_durumu_kutu.remove(child)

        durumlar = self.tsunami.modul_durumu_kontrol()
        for isim, durum in durumlar.items():
            kart = ModulDurumKarti(isim, durum)
            self.modul_durumu_kutu.append(kart)

    def _tehditler_guncelle(self):
        """Tehdit listesini guncelle"""
        # Son tehditler kutusunu temizle
        while child := self.son_tehditler_kutu.get_first_child():
            self.son_tehditler_kutu.remove(child)

        # Veritabanindan al
        tehditler = self.db.son_tehditler(5)

        if not tehditler:
            # Gercek tehdit yok - bos durum goster
            bos_etiket = Gtk.Label(label="Aktif tehdit tespit edilmedi")
            bos_etiket.add_css_class('dim-label')
            self.son_tehditler_kutu.append(bos_etiket)

        for tehdit in tehditler[:5]:
            kart = TehditKarti(tehdit, on_action=self._on_tehdit_aksiyon)
            self.son_tehditler_kutu.append(kart)

        # Metrikleri guncelle
        self.tehdit_sayisi_kart.deger_guncelle(str(len(tehditler)))

        # Tam tehdit listesi de guncelle
        while child := self.tehdit_listesi_kutu.get_first_child():
            self.tehdit_listesi_kutu.remove(child)

        for tehdit in self.db.son_tehditler(50):
            kart = TehditKarti(tehdit, on_action=self._on_tehdit_aksiyon)
            self.tehdit_listesi_kutu.append(kart)

    def _stealth_guncelle(self):
        """Stealth gostergelerini guncelle"""
        # TOR
        if self.tsunami.tor_aktif:
            self.tor_badge.remove_css_class('stealth-inactive')
            self.tor_badge.add_css_class('stealth-active')
        else:
            self.tor_badge.remove_css_class('stealth-active')
            self.tor_badge.add_css_class('stealth-inactive')

        # Ghost
        if self.tsunami.ghost_mod:
            self.ghost_badge.remove_css_class('stealth-inactive')
            self.ghost_badge.add_css_class('stealth-active')
        else:
            self.ghost_badge.remove_css_class('stealth-active')
            self.ghost_badge.add_css_class('stealth-inactive')

    def _defcon_guncelle(self):
        """DEFCON gostergesini guncelle"""
        defcon = self.tsunami.defcon_seviyesi_al()

        # Onceki CSS siniflarini temizle
        for i in range(1, 6):
            self.defcon_label.remove_css_class(f'defcon-{i}')

        # Yeni sinif ekle
        self.defcon_label.add_css_class(f'defcon-{defcon.value}')
        self.defcon_label.set_text(f"DEFCON {defcon.value}")

    def _ag_guncelle(self):
        """Ag istatistiklerini guncelle"""
        gonderilen, alinan = self.sistem.ag_trafigi()

        self.ag_gonderilen_kart.deger_guncelle(f"{gonderilen // (1024*1024)}")
        self.ag_alinan_kart.deger_guncelle(f"{alinan // (1024*1024)}")

        baglantilar = self.sistem.aktif_baglantilar()
        self.aktif_baglanti_kart.deger_guncelle(str(len(baglantilar)))

        # Baglanti tablosunu guncelle
        self.baglanti_store.clear()
        for b in baglantilar[:100]:
            self.baglanti_store.append([
                b['yerel_ip'],
                str(b['yerel_port']),
                b['uzak_ip'],
                str(b['uzak_port']),
                b['durum'],
                b['pid'] or 0
            ])

    # ========================================================================
    # YARDIMCI METODLAR
    # ========================================================================

    def _bildirim_goster(self, baslik: str, mesaj: str, seviye: str = "bilgi"):
        """Desktop bildirimi goster"""
        if not self.db.ayar_al('bildirimler_aktif', True):
            return

        try:
            notification = Notify.Notification.new(baslik, mesaj, "dialog-information")
            notification.show()
        except Exception as e:
            logger.error(f"Bildirim hatasi: {e}")

    def _log_ekle(self, mesaj: str, seviye: str = "info"):
        """Log mesaji ekle"""
        zaman = datetime.now().strftime("%H:%M:%S")
        tam_mesaj = f"[{zaman}] [{seviye.upper()}] {mesaj}"
        self.log_mesajlari.append((tam_mesaj, seviye))

        buffer = self.log_text.get_buffer()
        end_iter = buffer.get_end_iter()
        buffer.insert_with_tags_by_name(end_iter, tam_mesaj + "\n", seviye)

        # Auto-scroll
        mark = buffer.create_mark(None, buffer.get_end_iter(), False)
        self.log_text.scroll_to_mark(mark, 0, True, 0, 1)


# ============================================================================
# UYGULAMA SINIFI
# ============================================================================

class TsunamiDashboardApp(Adw.Application):
    """Ana uygulama sinifi"""

    def __init__(self):
        super().__init__(
            application_id="com.ailydian.tsunami.dashboard",
            flags=Gio.ApplicationFlags.FLAGS_NONE
        )

    def do_activate(self):
        """Uygulama aktive edildiginde"""
        win = TsunamiDashboard(self)
        win.present()


# ============================================================================
# ANA GIRIS
# ============================================================================

def main():
    """Ana giris noktasi"""
    app = TsunamiDashboardApp()
    return app.run(sys.argv)


if __name__ == "__main__":
    sys.exit(main())
