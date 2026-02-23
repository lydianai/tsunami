#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI DEFENDER v1.0
    Gercek Zamanli Sistem Koruma Daemon'u
================================================================================

    AMAC: Ubuntu sistemini gercek zamanli tehditlerden korumak
    YONTEM: Surekli izleme, tespit ve otomatik mudahale

    OZELLIKLER:
    - Gercek zamanli tehdit izleme
    - TSUNAMI BEYIN ile entegrasyon
    - Ag baglantilari izleme
    - Port tarama tespiti
    - Supheli proses algilama
    - Guvenlik olaylari loglama
    - Otomatik IP engelleme
    - Dosya butunlugu izleme

    KULLANIM:
        python3 tsunami_defender.py start    # Daemon baslat
        python3 tsunami_defender.py stop     # Daemon durdur
        python3 tsunami_defender.py status   # Durum goster
        python3 tsunami_defender.py scan     # Tek seferlik tarama

    DIKKAT: Bu modul SAVUNMA amaclidir. Sisteminizi korur.

================================================================================
"""

import os
import sys
import json
import time
import signal
import socket
import hashlib
import logging
import asyncio
import threading
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
import ipaddress
import re

# Psutil - sistem izleme
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

# Watchdog - dosya izleme
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileSystemEvent
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# Inotify - alternatif dosya izleme
try:
    import inotify.adapters
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False


# ==============================================================================
# YAPILANDIRMA
# ==============================================================================

def _get_default_log_dir():
    """Root degilse kullanici dizinini kullan"""
    if os.geteuid() != 0:
        user_dir = os.path.expanduser("~/.tsunami/logs")
        os.makedirs(user_dir, exist_ok=True)
        return user_dir
    return "/var/log/tsunami"

def _get_default_pid_file():
    """Root degilse kullanici dizinini kullan"""
    if os.geteuid() != 0:
        return os.path.expanduser("~/.tsunami/defender.pid")
    return "/var/run/tsunami_defender.pid"

@dataclass
class DefenderConfig:
    """Defender yapilandirmasi"""
    # Genel
    log_dir: str = field(default_factory=_get_default_log_dir)
    pid_file: str = field(default_factory=_get_default_pid_file)
    config_file: str = "/home/lydian/Desktop/TSUNAMI/tsunami_config.json"

    # Izleme ayarlari
    scan_interval: int = 30  # saniye
    connection_check_interval: int = 5  # saniye
    process_check_interval: int = 10  # saniye
    file_integrity_interval: int = 300  # saniye

    # Esik degerleri
    max_connections_per_ip: int = 50
    port_scan_threshold: int = 10  # X port taramasi = saldiri
    port_scan_window: int = 60  # saniye icinde
    suspicious_process_cpu: float = 90.0  # %
    suspicious_process_memory: float = 80.0  # %

    # Otomatik engelleme
    auto_block: bool = True
    block_duration: int = 3600  # saniye
    whitelist_ips: List[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])

    # Izlenecek dizinler - sadece okunabilir dosyalar
    critical_directories: List[str] = field(default_factory=lambda: [
        "/etc/passwd",
        "/etc/ssh/sshd_config",
        "/var/log/auth.log"
    ])

    # Supheli prosesler - exact match yapilir (substring degil)
    suspicious_processes: List[str] = field(default_factory=lambda: [
        "nc", "netcat", "ncat",
        "nmap", "masscan",
        "hydra", "medusa",
        "john", "hashcat",
        "mimikatz", "lazagne",
        "metasploit", "msfconsole",
        "beef", "bettercap",
        "aircrack-ng", "reaver"
    ])

    # Guvenli prosesler (whitelist) - bunlar asla supheli olarak isaretlenmez
    process_whitelist: List[str] = field(default_factory=lambda: [
        "chrome", "chromium", "firefox", "brave", "opera", "edge",
        "at-spi-bus-launcher", "chrome-headless-shell", "electron",
        "code", "vscode", "cursor", "sublime", "atom",
        "gnome-", "kde-", "xfce-", "systemd", "dbus",
        "nautilus", "dolphin", "thunar", "nemo",
        "python3", "python", "node", "npm", "bun",
        "postgres", "postgresql", "containerd", "dockerd", "runc",
        "kworker", "ksoftirqd", "kdevtmpfs", "migration",
        "snapd", "packagekitd", "polkitd", "accounts-daemon",
        "NetworkManager", "avahi-daemon", "cupsd", "bluetoothd",
        "pipewire", "wireplumber", "pulseaudio", "gdm", "lightdm",
        "Xorg", "Xwayland", "gnome-shell", "plasmashell",
        "udisksd", "upowerd", "colord", "fwupd",
        "thermald", "irqbalance", "cron", "rsyslogd"
    ])


# ==============================================================================
# LOG YAPILANDIRMASI
# ==============================================================================

def setup_logging(log_dir: str) -> logging.Logger:
    """Loglama yapilandirmasi"""
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("TsunamiDefender")
    logger.setLevel(logging.DEBUG)

    # Dosya handler
    log_file = os.path.join(log_dir, f"defender_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '\033[36m[TSUNAMI]\033[0m %(levelname)s: %(message)s'
    )
    console_handler.setFormatter(console_format)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# ==============================================================================
# VERI YAPILARI
# ==============================================================================

@dataclass
class SecurityEvent:
    """Guvenlik olayi"""
    timestamp: str
    event_type: str
    severity: str  # critical, high, medium, low, info
    source_ip: Optional[str]
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    action_taken: Optional[str] = None

    def to_dict(self) -> Dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


@dataclass
class ConnectionInfo:
    """Ag baglantisi bilgisi"""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    status: str
    pid: Optional[int]
    process_name: Optional[str]


@dataclass
class ProcessInfo:
    """Proses bilgisi"""
    pid: int
    name: str
    username: str
    cpu_percent: float
    memory_percent: float
    cmdline: str
    create_time: float
    connections: int


@dataclass
class FileIntegrityRecord:
    """Dosya butunluk kaydi"""
    path: str
    hash_md5: str
    hash_sha256: str
    size: int
    mtime: float
    permissions: str


# ==============================================================================
# TEHDIT TESPIT MOTORU
# ==============================================================================

class ThreatDetectionEngine:
    """Tehdit tespit motoru"""

    def __init__(self, config: DefenderConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger

        # Port tarama izleme
        self._port_scan_tracker: Dict[str, List[Tuple[int, float]]] = defaultdict(list)
        self._blocked_ips: Dict[str, float] = {}

        # Dosya butunlugu veritabani
        self._file_hashes: Dict[str, FileIntegrityRecord] = {}

        # Istatistikler
        self.stats = {
            "events_detected": 0,
            "ips_blocked": 0,
            "port_scans_detected": 0,
            "suspicious_processes": 0,
            "file_modifications": 0
        }

    # === AG IZLEME ===

    def get_active_connections(self) -> List[ConnectionInfo]:
        """Aktif ag baglantilerini al"""
        if not PSUTIL_AVAILABLE:
            return []

        connections = []
        try:
            for conn in psutil.net_connections(kind='all'):
                if conn.status == 'ESTABLISHED' or conn.status == 'LISTEN':
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        connections.append(ConnectionInfo(
                            local_addr=conn.laddr.ip if conn.laddr else "",
                            local_port=conn.laddr.port if conn.laddr else 0,
                            remote_addr=conn.raddr.ip if conn.raddr else "",
                            remote_port=conn.raddr.port if conn.raddr else 0,
                            status=conn.status,
                            pid=conn.pid,
                            process_name=proc.name() if proc else None
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except Exception as e:
            self.logger.error(f"Baglanti taramasi hatasi: {e}")

        return connections

    def detect_port_scan(self, connections: List[ConnectionInfo]) -> List[SecurityEvent]:
        """Port taramasi tespit et - sadece gelen (incoming) baglantilar icin"""
        events = []
        current_time = time.time()

        # Sadece gelen baglantilar icin port taramasi tespit et
        # Gelen = remote taraf bizim farkli portlarimiza baglanir
        # Giden = biz remote portlara baglaniriz (browser, CDN vs. - bu normal)
        # Filtre: local_port < 1024 veya bilinen servis portlari = hedef olabilir
        # Ayrica: ayni remote IP birden fazla FARKLI local porta baglaniyorsa = potansiyel tarama
        ip_ports: Dict[str, Set[int]] = defaultdict(set)
        for conn in connections:
            if not conn.remote_addr or conn.remote_addr in self.config.whitelist_ips:
                continue
            # Sadece LISTEN olmayan, ESTABLISHED olan gelen baglantilar
            # Gelen baglanti: remote_port genelde yuksek (ephemeral), local_port dusuk (servis)
            # Ama tarama durumunda remote birden fazla local porta baglanir
            # Giden baglanti: local_port ephemeral (>32768), remote_port bilinen servis
            # Giden baglantilarida filtrele - bunlar normal internet kullanimi
            if conn.local_port > 32768:
                continue  # Ephemeral local port = giden baglanti, tarama degil
            ip_ports[conn.remote_addr].add(conn.local_port)

        for ip, ports in ip_ports.items():
            # Eski kayitlari temizle
            self._port_scan_tracker[ip] = [
                (port, timestamp) for port, timestamp in self._port_scan_tracker[ip]
                if current_time - timestamp < self.config.port_scan_window
            ]

            # Yeni portlari ekle
            for port in ports:
                self._port_scan_tracker[ip].append((port, current_time))

            # Esik kontrolu
            unique_ports = len(set(p for p, _ in self._port_scan_tracker[ip]))
            if unique_ports >= self.config.port_scan_threshold:
                # Ayni IP icin tekrar eden alarmlari onle (60 saniye debounce)
                last_alert_key = f"_last_portscan_alert_{ip}"
                last_alert_time = getattr(self, last_alert_key, 0)
                if current_time - last_alert_time < 60:
                    continue
                setattr(self, last_alert_key, current_time)

                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="PORT_SCAN_DETECTED",
                    severity="high",
                    source_ip=ip,
                    description=f"Port taramasi tespit edildi: {unique_ports} port tarandi",
                    details={
                        "ports_scanned": list(set(p for p, _ in self._port_scan_tracker[ip])),
                        "window_seconds": self.config.port_scan_window
                    }
                )
                events.append(event)
                self.stats["port_scans_detected"] += 1

                # Otomatik engelleme
                if self.config.auto_block:
                    self.block_ip(ip, "Port taramasi")

        return events

    def detect_connection_flood(self, connections: List[ConnectionInfo]) -> List[SecurityEvent]:
        """Baglanti tasmasi (flood) tespit et"""
        events = []

        # IP bazinda baglanti sayisi
        ip_counts: Dict[str, int] = defaultdict(int)
        for conn in connections:
            if conn.remote_addr and conn.remote_addr not in self.config.whitelist_ips:
                ip_counts[conn.remote_addr] += 1

        for ip, count in ip_counts.items():
            if count >= self.config.max_connections_per_ip:
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="CONNECTION_FLOOD",
                    severity="high",
                    source_ip=ip,
                    description=f"Baglanti tasmasi: {count} baglanti",
                    details={"connection_count": count}
                )
                events.append(event)

                if self.config.auto_block:
                    self.block_ip(ip, "Baglanti tasmasi")

        return events

    # === PROSES IZLEME ===

    def get_running_processes(self) -> List[ProcessInfo]:
        """Calisan prosesleri al"""
        if not PSUTIL_AVAILABLE:
            return []

        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent',
                                             'memory_percent', 'cmdline', 'create_time']):
                try:
                    pinfo = proc.info
                    try:
                        connections = len(proc.net_connections()) if hasattr(proc, 'net_connections') else len(proc.connections())
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        connections = 0
                    processes.append(ProcessInfo(
                        pid=pinfo['pid'],
                        name=pinfo['name'] or '',
                        username=pinfo['username'] or '',
                        cpu_percent=pinfo['cpu_percent'] or 0,
                        memory_percent=pinfo['memory_percent'] or 0,
                        cmdline=' '.join(pinfo['cmdline'] or []),
                        create_time=pinfo['create_time'] or 0,
                        connections=connections
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            self.logger.error(f"Proses taramasi hatasi: {e}")

        return processes

    def detect_suspicious_processes(self, processes: List[ProcessInfo]) -> List[SecurityEvent]:
        """Supheli prosesleri tespit et"""
        events = []

        # Whitelist - guvenli prosesler (tarayicilar vs.)
        whitelist = self.config.process_whitelist

        for proc in processes:
            # Whitelist kontrolu - guvenli prosesleri atla
            proc_name_lower = proc.name.lower()
            if any(safe in proc_name_lower for safe in whitelist):
                continue

            # Bilinen supheli araclar - exact match veya cmdline word match
            for suspicious in self.config.suspicious_processes:
                # Proses adi exact match (substring degil - false positive onlemi)
                name_match = (proc_name_lower == suspicious)
                # Cmdline'da word boundary match (bagimsiz kelime olarak)
                cmdline_lower = proc.cmdline.lower()
                cmdline_parts = re.split(r'[\s/\\]+', cmdline_lower)
                cmdline_match = suspicious in cmdline_parts
                if name_match or cmdline_match:
                    event = SecurityEvent(
                        timestamp=datetime.now().isoformat(),
                        event_type="SUSPICIOUS_PROCESS",
                        severity="critical",
                        source_ip=None,
                        description=f"Supheli proses tespit edildi: {proc.name}",
                        details={
                            "pid": proc.pid,
                            "name": proc.name,
                            "user": proc.username,
                            "cmdline": proc.cmdline[:200],
                            "matched_pattern": suspicious
                        }
                    )
                    events.append(event)
                    self.stats["suspicious_processes"] += 1
                    break

            # Asiri kaynak kullanan prosesler
            if proc.cpu_percent > self.config.suspicious_process_cpu:
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="HIGH_CPU_PROCESS",
                    severity="medium",
                    source_ip=None,
                    description=f"Yuksek CPU kullanan proses: {proc.name} ({proc.cpu_percent}%)",
                    details={
                        "pid": proc.pid,
                        "name": proc.name,
                        "cpu_percent": proc.cpu_percent
                    }
                )
                events.append(event)

            if proc.memory_percent > self.config.suspicious_process_memory:
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="HIGH_MEMORY_PROCESS",
                    severity="medium",
                    source_ip=None,
                    description=f"Yuksek bellek kullanan proses: {proc.name} ({proc.memory_percent}%)",
                    details={
                        "pid": proc.pid,
                        "name": proc.name,
                        "memory_percent": proc.memory_percent
                    }
                )
                events.append(event)

        return events

    # === DOSYA BUTUNLUGU ===

    def calculate_file_hash(self, filepath: str) -> Optional[FileIntegrityRecord]:
        """Dosya hash'ini hesapla"""
        try:
            path = Path(filepath)
            if not path.exists():
                return None

            stat = path.stat()

            with open(filepath, 'rb') as f:
                content = f.read()
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

            return FileIntegrityRecord(
                path=filepath,
                hash_md5=md5_hash,
                hash_sha256=sha256_hash,
                size=stat.st_size,
                mtime=stat.st_mtime,
                permissions=oct(stat.st_mode)[-3:]
            )
        except Exception as e:
            self.logger.error(f"Dosya hash hatasi ({filepath}): {e}")
            return None

    def initialize_file_integrity(self):
        """Dosya butunlugu veritabanini baslat"""
        self.logger.info("Dosya butunlugu veritabani olusturuluyor...")

        for filepath in self.config.critical_directories:
            record = self.calculate_file_hash(filepath)
            if record:
                self._file_hashes[filepath] = record
                self.logger.debug(f"Hash kaydedildi: {filepath}")

        self.logger.info(f"{len(self._file_hashes)} dosya icin hash kaydedildi")

    def check_file_integrity(self) -> List[SecurityEvent]:
        """Dosya butunlugunu kontrol et"""
        events = []

        for filepath, original in self._file_hashes.items():
            current = self.calculate_file_hash(filepath)

            if current is None:
                # Dosya silindi
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="FILE_DELETED",
                    severity="critical",
                    source_ip=None,
                    description=f"Kritik dosya silindi: {filepath}",
                    details={"original_hash": original.hash_sha256}
                )
                events.append(event)
                self.stats["file_modifications"] += 1

            elif current.hash_sha256 != original.hash_sha256:
                # Dosya degistirildi
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="FILE_MODIFIED",
                    severity="critical",
                    source_ip=None,
                    description=f"Kritik dosya degistirildi: {filepath}",
                    details={
                        "original_hash": original.hash_sha256,
                        "current_hash": current.hash_sha256,
                        "size_change": current.size - original.size
                    }
                )
                events.append(event)
                self.stats["file_modifications"] += 1

                # Hash'i guncelle
                self._file_hashes[filepath] = current

            elif current.permissions != original.permissions:
                # Izinler degisti
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type="FILE_PERMISSIONS_CHANGED",
                    severity="high",
                    source_ip=None,
                    description=f"Dosya izinleri degisti: {filepath}",
                    details={
                        "original_permissions": original.permissions,
                        "current_permissions": current.permissions
                    }
                )
                events.append(event)

        return events

    # === IP ENGELLEME ===

    def block_ip(self, ip: str, reason: str):
        """IP adresini engelle"""
        if ip in self.config.whitelist_ips:
            return

        # Tekrarli engelleme girisimini onle
        if ip in self._blocked_ips:
            return

        try:
            action_taken = "logged_only"

            # Root kontrolu - sadece root ise UFW kullan
            if os.geteuid() == 0:
                cmd = f"ufw insert 1 deny from {ip} to any"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                if result.returncode == 0:
                    action_taken = "ufw deny"
                    self.logger.warning(f"IP engellendi: {ip} - Sebep: {reason}")
                else:
                    self.logger.warning(f"UFW engelleme basarisiz ({ip}): {result.stderr.strip()}")

            # Her durumda kaydet (engellenmis olarak isaretle)
            self._blocked_ips[ip] = time.time()
            self.stats["ips_blocked"] += 1

            event = SecurityEvent(
                timestamp=datetime.now().isoformat(),
                event_type="IP_BLOCKED",
                severity="high",
                source_ip=ip,
                description=f"IP adresi engellendi: {reason}",
                action_taken=action_taken
            )
            self.log_event(event)

        except Exception as e:
            self.logger.error(f"IP engelleme hatasi ({ip}): {e}")

    def unblock_expired_ips(self):
        """Suresi dolan IP engellerini kaldir"""
        current_time = time.time()
        expired = []

        for ip, block_time in self._blocked_ips.items():
            if current_time - block_time > self.config.block_duration:
                expired.append(ip)

        for ip in expired:
            try:
                cmd = f"ufw delete deny from {ip} to any"
                subprocess.run(cmd.split(), capture_output=True)
                del self._blocked_ips[ip]
                self.logger.info(f"IP engeli kaldirildi: {ip}")
            except Exception as e:
                self.logger.error(f"IP engel kaldirma hatasi ({ip}): {e}")

    # === LOGLAMA ===

    def log_event(self, event: SecurityEvent):
        """Guvenlik olayini logla"""
        self.stats["events_detected"] += 1

        # Dosyaya yaz
        log_file = os.path.join(self.config.log_dir, "security_events.json")
        try:
            with open(log_file, 'a') as f:
                f.write(event.to_json() + '\n')
        except Exception as e:
            self.logger.error(f"Olay loglama hatasi: {e}")

        # Konsola yaz
        severity_colors = {
            "critical": "\033[31m",  # Kirmizi
            "high": "\033[91m",      # Acik kirmizi
            "medium": "\033[93m",    # Sari
            "low": "\033[94m",       # Mavi
            "info": "\033[37m"       # Beyaz
        }
        color = severity_colors.get(event.severity, "\033[0m")
        self.logger.warning(f"{color}[{event.severity.upper()}]\033[0m {event.description}")


# ==============================================================================
# DOSYA IZLEME HANDLER
# ==============================================================================

if WATCHDOG_AVAILABLE:
    class FileChangeHandler(FileSystemEventHandler):
        """Dosya degisiklik handler'i"""

        def __init__(self, engine: ThreatDetectionEngine, logger: logging.Logger):
            self.engine = engine
            self.logger = logger

        def on_modified(self, event: FileSystemEvent):
            if not event.is_directory:
                self._handle_change(event.src_path, "modified")

        def on_created(self, event: FileSystemEvent):
            if not event.is_directory:
                self._handle_change(event.src_path, "created")

        def on_deleted(self, event: FileSystemEvent):
            if not event.is_directory:
                self._handle_change(event.src_path, "deleted")

        def _handle_change(self, filepath: str, change_type: str):
            # Kritik dosya kontrolu
            if filepath in self.engine.config.critical_directories:
                event = SecurityEvent(
                    timestamp=datetime.now().isoformat(),
                    event_type=f"FILE_{change_type.upper()}",
                    severity="critical",
                    source_ip=None,
                    description=f"Kritik dosya {change_type}: {filepath}"
                )
                self.engine.log_event(event)


# ==============================================================================
# BEYIN ENTEGRASYONU
# ==============================================================================

class BeyinIntegration:
    """TSUNAMI BEYIN ile entegrasyon"""

    def __init__(self, config: DefenderConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self._beyin_socket = None

    async def connect(self):
        """BEYIN'e baglan"""
        # BEYIN soket/API baglantisi
        # Bu ornekte basit bir dosya bazli iletisim
        self.logger.info("BEYIN entegrasyonu aktif")

    async def send_alert(self, event: SecurityEvent):
        """BEYIN'e alarm gonder"""
        alert_file = os.path.join(self.config.log_dir, "beyin_alerts.json")
        try:
            alert = {
                "source": "TSUNAMI_DEFENDER",
                "timestamp": event.timestamp,
                "severity": event.severity,
                "type": event.event_type,
                "description": event.description,
                "details": event.details
            }

            with open(alert_file, 'a') as f:
                f.write(json.dumps(alert, ensure_ascii=False) + '\n')

        except Exception as e:
            self.logger.error(f"BEYIN alarm hatasi: {e}")

    async def get_threat_intel(self, ip: str) -> Dict:
        """BEYIN'den tehdit istihbaratı al - gerçek API sorgusu"""
        import aiohttp

        result = {"ip": ip, "reputation": "unknown", "threats": [], "sources": []}

        # AbuseIPDB sorgusu
        abuseipdb_key = os.environ.get('ABUSEIPDB_API_KEY')
        if abuseipdb_key:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": abuseipdb_key, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": 90},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = (await resp.json()).get("data", {})
                            score = data.get("abuseConfidenceScore", 0)
                            if score >= 75:
                                result["reputation"] = "malicious"
                            elif score >= 25:
                                result["reputation"] = "suspicious"
                            else:
                                result["reputation"] = "clean"
                            result["abuse_score"] = score
                            result["country"] = data.get("countryCode", "")
                            result["isp"] = data.get("isp", "")
                            result["total_reports"] = data.get("totalReports", 0)
                            result["sources"].append("abuseipdb")
            except Exception as e:
                self.logger.debug(f"AbuseIPDB sorgu hatası: {e}")

        # GreyNoise sorgusu (API key opsiyonel - community endpoint)
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://api.greynoise.io/v3/community/{ip}",
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        classification = data.get("classification", "")
                        if classification == "malicious":
                            result["reputation"] = "malicious"
                            result["threats"].append(f"GreyNoise: {data.get('name', 'unknown threat')}")
                        elif classification == "benign":
                            if result["reputation"] == "unknown":
                                result["reputation"] = "clean"
                        result["noise"] = data.get("noise", False)
                        result["riot"] = data.get("riot", False)
                        result["sources"].append("greynoise")
        except Exception as e:
            self.logger.debug(f"GreyNoise sorgu hatası: {e}")

        return result


# ==============================================================================
# ANA DEFENDER DAEMON
# ==============================================================================

class TsunamiDefender:
    """Ana Defender daemon sinifi"""

    def __init__(self, config: DefenderConfig = None):
        self.config = config or DefenderConfig()
        self.logger = setup_logging(self.config.log_dir)

        # Bilesenleri baslat
        self.engine = ThreatDetectionEngine(self.config, self.logger)
        self.beyin = BeyinIntegration(self.config, self.logger)

        # Durum
        self._running = False
        self._tasks: List[asyncio.Task] = []

        # Signal handler
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Sinyal handler'i"""
        self.logger.info(f"Sinyal alindi: {signum}")
        self.stop()

    def _write_pid(self):
        """PID dosyasi yaz"""
        with open(self.config.pid_file, 'w') as f:
            f.write(str(os.getpid()))

    def _remove_pid(self):
        """PID dosyasini sil"""
        if os.path.exists(self.config.pid_file):
            os.remove(self.config.pid_file)

    def _is_running(self) -> bool:
        """Daemon zaten calisiyor mu?"""
        if os.path.exists(self.config.pid_file):
            try:
                with open(self.config.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, 0)
                return True
            except (ProcessLookupError, ValueError):
                self._remove_pid()
        return False

    async def _connection_monitor(self):
        """Ag baglantisi izleme gorevi"""
        while self._running:
            try:
                connections = self.engine.get_active_connections()

                # Port tarama tespiti
                events = self.engine.detect_port_scan(connections)
                for event in events:
                    self.engine.log_event(event)
                    await self.beyin.send_alert(event)

                # Baglanti tasmasi tespiti
                events = self.engine.detect_connection_flood(connections)
                for event in events:
                    self.engine.log_event(event)
                    await self.beyin.send_alert(event)

            except Exception as e:
                self.logger.error(f"Baglanti izleme hatasi: {e}")

            await asyncio.sleep(self.config.connection_check_interval)

    async def _process_monitor(self):
        """Proses izleme gorevi"""
        while self._running:
            try:
                processes = self.engine.get_running_processes()
                events = self.engine.detect_suspicious_processes(processes)

                for event in events:
                    self.engine.log_event(event)
                    await self.beyin.send_alert(event)

            except Exception as e:
                self.logger.error(f"Proses izleme hatasi: {e}")

            await asyncio.sleep(self.config.process_check_interval)

    async def _file_integrity_monitor(self):
        """Dosya butunlugu izleme gorevi"""
        while self._running:
            try:
                events = self.engine.check_file_integrity()

                for event in events:
                    self.engine.log_event(event)
                    await self.beyin.send_alert(event)

            except Exception as e:
                self.logger.error(f"Dosya butunluk izleme hatasi: {e}")

            await asyncio.sleep(self.config.file_integrity_interval)

    async def _ip_unblock_monitor(self):
        """Suresi dolan IP engellerini kaldir"""
        while self._running:
            try:
                self.engine.unblock_expired_ips()
            except Exception as e:
                self.logger.error(f"IP engel kaldirma hatasi: {e}")

            await asyncio.sleep(60)  # Dakikada bir kontrol

    async def _main_loop(self):
        """Ana izleme dongusu"""
        self.logger.info("TSUNAMI Defender baslatiliyor...")

        # BEYIN baglantisi
        await self.beyin.connect()

        # Dosya butunlugu veritabanini baslat
        self.engine.initialize_file_integrity()

        # Izleme gorevlerini baslat
        self._tasks = [
            asyncio.create_task(self._connection_monitor()),
            asyncio.create_task(self._process_monitor()),
            asyncio.create_task(self._file_integrity_monitor()),
            asyncio.create_task(self._ip_unblock_monitor()),
        ]

        self.logger.info("Tum izleme gorevleri baslatildi")

        # Ana dongu
        while self._running:
            try:
                # Durum raporu
                self.logger.info(
                    f"Durum: Olaylar={self.engine.stats['events_detected']}, "
                    f"Engellenen IP={self.engine.stats['ips_blocked']}, "
                    f"Port Tarama={self.engine.stats['port_scans_detected']}"
                )

                await asyncio.sleep(self.config.scan_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Ana dongu hatasi: {e}")

        # Gorevleri iptal et
        for task in self._tasks:
            task.cancel()

        self.logger.info("TSUNAMI Defender durduruldu")

    def start(self):
        """Daemon'u baslat"""
        if self._is_running():
            print("TSUNAMI Defender zaten calisiyor!")
            return

        # Banner
        print("""
        ================================================================================
            TSUNAMI DEFENDER v1.0 - Gercek Zamanli Koruma
        ================================================================================
        """)

        self._running = True
        self._write_pid()

        try:
            asyncio.run(self._main_loop())
        finally:
            self._remove_pid()

    def stop(self):
        """Daemon'u durdur"""
        self._running = False

    def status(self) -> Dict:
        """Daemon durumu"""
        running = self._is_running()

        status = {
            "running": running,
            "pid": None,
            "stats": {}
        }

        if running:
            try:
                with open(self.config.pid_file, 'r') as f:
                    status["pid"] = int(f.read().strip())
            except:
                pass

        # Son olaylari oku
        events_file = os.path.join(self.config.log_dir, "security_events.json")
        recent_events = []
        if os.path.exists(events_file):
            try:
                with open(events_file, 'r') as f:
                    lines = f.readlines()[-10:]  # Son 10 olay
                    for line in lines:
                        try:
                            recent_events.append(json.loads(line))
                        except:
                            pass
            except:
                pass

        status["recent_events"] = recent_events

        return status

    def scan(self):
        """Tek seferlik tarama yap"""
        print("Tek seferlik guvenlik taramasi baslatiliyor...")

        # Baglanti taramasi
        print("\n[1/3] Ag baglantilari taranıyor...")
        connections = self.engine.get_active_connections()
        events = self.engine.detect_port_scan(connections)
        events.extend(self.engine.detect_connection_flood(connections))

        for event in events:
            print(f"  - [{event.severity.upper()}] {event.description}")

        # Proses taramasi
        print("\n[2/3] Prosesler taranıyor...")
        processes = self.engine.get_running_processes()
        events = self.engine.detect_suspicious_processes(processes)

        for event in events:
            print(f"  - [{event.severity.upper()}] {event.description}")

        # Dosya butunlugu
        print("\n[3/3] Dosya butunlugu kontrol ediliyor...")
        self.engine.initialize_file_integrity()
        events = self.engine.check_file_integrity()

        for event in events:
            print(f"  - [{event.severity.upper()}] {event.description}")

        # Ozet
        print("\n" + "="*60)
        print(f"Tarama tamamlandi: {self.engine.stats['events_detected']} olay tespit edildi")
        print("="*60)


# ==============================================================================
# CLI
# ==============================================================================

def print_banner():
    """Banner yazdir"""
    banner = """
    \033[36m
    ████████╗███████╗██╗   ██╗███╗   ██╗ █████╗ ███╗   ███╗██╗
    ╚══██╔══╝██╔════╝██║   ██║████╗  ██║██╔══██╗████╗ ████║██║
       ██║   ███████╗██║   ██║██╔██╗ ██║███████║██╔████╔██║██║
       ██║   ╚════██║██║   ██║██║╚██╗██║██╔══██║██║╚██╔╝██║██║
       ██║   ███████║╚██████╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║██║
       ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝

             DEFENDER - Gercek Zamanli Sistem Korumasi
    \033[0m
    """
    print(banner)


def main():
    """Ana fonksiyon"""
    print_banner()

    if len(sys.argv) < 2:
        print("Kullanim: tsunami_defender.py <komut>")
        print("")
        print("Komutlar:")
        print("  start   - Defender daemon'unu baslat")
        print("  stop    - Defender daemon'unu durdur")
        print("  status  - Daemon durumunu goster")
        print("  scan    - Tek seferlik guvenlik taramasi")
        print("")
        sys.exit(1)

    command = sys.argv[1].lower()

    # Root kontrolu - root olmadan sinirli mod
    if os.geteuid() != 0 and command in ['start', 'stop']:
        print("\033[33m[UYARI]\033[0m Root yetkisi olmadan sinirli modda calisacak")
        print("         IP engelleme ve bazi sistem dosyalari izlenemeyecek")
        print("         Tam koruma icin: sudo python3 tsunami_defender.py " + command)

    # Config yukle
    config = DefenderConfig()
    if os.path.exists(config.config_file):
        try:
            with open(config.config_file, 'r') as f:
                tsunami_config = json.load(f)
                # Config'den ayarlari al
                if "defender" in tsunami_config:
                    defender_cfg = tsunami_config["defender"]
                    for key, value in defender_cfg.items():
                        if hasattr(config, key):
                            setattr(config, key, value)
        except Exception as e:
            print(f"Config yukleme hatasi: {e}")

    defender = TsunamiDefender(config)

    if command == "start":
        defender.start()

    elif command == "stop":
        if defender._is_running():
            try:
                with open(config.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, signal.SIGTERM)
                print("TSUNAMI Defender durduruldu")
            except Exception as e:
                print(f"Durdurma hatasi: {e}")
        else:
            print("TSUNAMI Defender calismıyor")

    elif command == "status":
        status = defender.status()
        print(f"Durum: {'Calisiyor' if status['running'] else 'Durdu'}")
        if status['pid']:
            print(f"PID: {status['pid']}")
        if status['recent_events']:
            print("\nSon Olaylar:")
            for event in status['recent_events']:
                print(f"  [{event.get('severity', 'N/A').upper()}] {event.get('description', 'N/A')}")

    elif command == "scan":
        defender.scan()

    else:
        print(f"Bilinmeyen komut: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
