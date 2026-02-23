#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI NETWORK GUARDIAN v1.0
    Ag ve WiFi Izleme Daemon'u - White Hat Guvenlik Araci
================================================================================

    AMAC: Ag trafiginizi ve WiFi baglantilarinizi gercek zamanli izlemek
    YONTEM: Surekli izleme, anomali tespiti ve otomatik savunma

    OZELLIKLER:
    - Tum ag arayuzlerini izleme
    - Yeni cihaz tespiti (kimse habersiz agina baglanamasin)
    - Sahte erisim noktasi (rogue AP) taramasi
    - ARP tablosu spoofing tespiti (MITM saldirilari)
    - WiFi ag takibi
    - Supheli ag aktivitesi tespiti
    - TSUNAMI BEYIN entegrasyonu
    - Otomatik IP engelleme
    - Kapsamli loglama

    KULLANIM:
        python3 network_guardian.py start    # Daemon baslat
        python3 network_guardian.py stop     # Daemon durdur
        python3 network_guardian.py status   # Durum goster
        python3 network_guardian.py scan     # Tek seferlik tarama
        python3 network_guardian.py devices  # Bagli cihazlari listele
        python3 network_guardian.py wifi     # WiFi taramasi yap

    DIKKAT: Bu modul SAVUNMA amaclidir. Kendi sisteminizi ve aginizi korur.
            Sadece yetkili oldugunuz aglarda kullanin.

================================================================================
"""

import os
import sys
import json
import time
import signal
import socket
import struct
import hashlib
import logging
import asyncio
import threading
import subprocess
import ipaddress
import re
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from collections import defaultdict
from pathlib import Path
from enum import Enum
import uuid

# ==============================================================================
# OPSIYONEL KUTUPHANELER
# ==============================================================================

# Psutil - sistem ve ag izleme
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("[UYARI] psutil yuklu degil: pip install psutil")

# Scapy - paket analizi (root gerektirir)
try:
    # Scapy uyarilarini sustur
    import logging as scapy_logging
    scapy_logging.getLogger("scapy.runtime").setLevel(scapy_logging.ERROR)

    from scapy.all import ARP, Ether, srp, sniff, conf, get_if_list
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeResp
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[UYARI] scapy yuklu degil: pip install scapy")

# Netifaces - ag arayuzu bilgileri
try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False


# ==============================================================================
# ENUM VE SABITLER
# ==============================================================================

class AlertSeverity(Enum):
    """Alarm oncelik seviyeleri"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Alarm tipleri"""
    NEW_DEVICE = "new_device"
    ROGUE_AP = "rogue_ap"
    ARP_SPOOF = "arp_spoof"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_TRAFFIC = "suspicious_traffic"
    INTERFACE_CHANGE = "interface_change"
    WIFI_CHANGE = "wifi_change"
    GATEWAY_CHANGE = "gateway_change"
    DNS_CHANGE = "dns_change"
    MAC_CHANGE = "mac_change"
    BANDWIDTH_ANOMALY = "bandwidth_anomaly"
    UNKNOWN_PROTOCOL = "unknown_protocol"


# Bilinen tehditli MAC vendor'lari (ornek - gercek veritabaninda daha fazla olur)
# Bu liste sadece ornektir, gercek kullanim icin guncel bir OUI veritabani kullanin
SUSPICIOUS_VENDORS = {
    "00:00:00": "Testler icin null MAC",
}


# ==============================================================================
# VERI YAPILARI
# ==============================================================================

@dataclass
class NetworkInterface:
    """Ag arayuzu bilgisi"""
    name: str
    mac: str
    ipv4: List[str] = field(default_factory=list)
    ipv6: List[str] = field(default_factory=list)
    is_up: bool = True
    is_wireless: bool = False
    speed: int = 0  # Mbps
    mtu: int = 1500
    stats: Dict[str, int] = field(default_factory=dict)


@dataclass
class NetworkDevice:
    """Agdaki cihaz bilgisi"""
    ip: str
    mac: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_gateway: bool = False
    is_trusted: bool = False
    open_ports: List[int] = field(default_factory=list)
    os_guess: Optional[str] = None


@dataclass
class WifiNetwork:
    """WiFi ag bilgisi"""
    ssid: str
    bssid: str  # MAC adresi
    channel: int
    frequency: int  # MHz
    signal: int  # dBm
    encryption: str
    is_hidden: bool = False
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    is_trusted: bool = False


@dataclass
class NetworkAlert:
    """Ag alarmi"""
    id: str
    timestamp: str
    alert_type: AlertType
    severity: AlertSeverity
    source_ip: Optional[str]
    source_mac: Optional[str]
    target_ip: Optional[str]
    description: str
    details: Dict[str, Any] = field(default_factory=dict)
    handled: bool = False


@dataclass
class GuardianConfig:
    """Network Guardian yapilandirmasi"""
    # Genel ayarlar
    log_dir: str = field(default_factory=lambda: os.path.expanduser("~/.tsunami/logs"))
    pid_file: str = field(default_factory=lambda: os.path.expanduser("~/.tsunami/network_guardian.pid"))
    config_file: str = "/home/lydian/Desktop/TSUNAMI/tsunami_config.json"
    data_dir: str = field(default_factory=lambda: os.path.expanduser("~/.tsunami/network_data"))

    # Izleme intervalleri (saniye)
    interface_scan_interval: int = 30
    device_scan_interval: int = 60
    arp_monitor_interval: int = 10
    wifi_scan_interval: int = 120
    traffic_analysis_interval: int = 5

    # Esik degerleri
    new_device_alert: bool = True
    arp_spoof_detection: bool = True
    rogue_ap_detection: bool = True
    bandwidth_threshold_mbps: float = 100.0
    packet_threshold_per_second: int = 10000

    # Guvenli listeler
    trusted_macs: List[str] = field(default_factory=list)
    trusted_ips: List[str] = field(default_factory=lambda: ["127.0.0.1", "::1"])
    trusted_ssids: List[str] = field(default_factory=list)
    trusted_networks: List[str] = field(default_factory=list)  # CIDR notation

    # Engellenecek MAC adresleri
    blocked_macs: List[str] = field(default_factory=list)

    # BEYIN entegrasyonu
    beyin_integration: bool = True
    beyin_alert_file: str = field(default_factory=lambda: os.path.expanduser("~/.tsunami/logs/beyin_alerts.json"))

    # Loglama
    log_level: str = "INFO"
    log_all_traffic: bool = False
    log_retention_days: int = 30


# ==============================================================================
# LOGLAMA KURULUMU
# ==============================================================================

def setup_logging(log_dir: str, level: str = "INFO") -> logging.Logger:
    """Loglama sistemini kur"""
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("NetworkGuardian")
    logger.setLevel(getattr(logging, level.upper()))

    # Dosya handler
    log_file = os.path.join(log_dir, f"network_guardian_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, level.upper()))

    # Format
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger


# ==============================================================================
# MAC VENDOR LOOKUP
# ==============================================================================

class MacVendorLookup:
    """MAC adresi vendor sorgusu (lokal OUI veritabani)"""

    # Yaygin vendor'lar (ornek - tam liste icin oui.txt kullanin)
    VENDORS = {
        "00:00:5E": "IANA",
        "00:0C:29": "VMware",
        "00:50:56": "VMware",
        "00:1C:42": "Parallels",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:15:5D": "Hyper-V",
        "DC:A6:32": "Raspberry Pi",
        "B8:27:EB": "Raspberry Pi",
        "E4:5F:01": "Raspberry Pi",
        "00:1A:79": "Ubiquiti",
        "04:18:D6": "Ubiquiti",
        "24:A4:3C": "Ubiquiti",
        "F0:9F:C2": "Ubiquiti",
        "44:D9:E7": "Ubiquiti",
        "74:83:C2": "Ubiquiti",
        "78:8A:20": "Ubiquiti",
        "80:2A:A8": "Ubiquiti",
        "AC:8B:A9": "Ubiquiti",
        "00:17:88": "Philips Hue",
        "EC:B5:FA": "Philips Hue",
        "00:50:F2": "Microsoft",
        "00:03:FF": "Microsoft",
        "28:18:78": "Microsoft",
        "3C:5A:B4": "Google",
        "54:60:09": "Google",
        "F4:F5:D8": "Google",
        "00:1E:C2": "Apple",
        "00:25:00": "Apple",
        "04:0C:CE": "Apple",
        "18:AF:61": "Apple",
        "28:CF:E9": "Apple",
        "3C:06:30": "Apple",
        "40:A6:D9": "Apple",
        "5C:F9:38": "Apple",
        "70:56:81": "Apple",
        "7C:6D:62": "Apple",
        "88:66:A5": "Apple",
        "98:01:A7": "Apple",
        "A4:83:E7": "Apple",
        "AC:BC:32": "Apple",
        "B8:E8:56": "Apple",
        "C8:69:CD": "Apple",
        "D0:03:4B": "Apple",
        "DC:A9:04": "Apple",
        "E0:5F:45": "Apple",
        "F0:D1:A9": "Apple",
        "FC:FC:48": "Apple",
        "00:1B:63": "Apple",
        "00:21:E9": "Apple",
        "00:23:12": "Apple",
        "00:24:36": "Apple",
        "00:25:BC": "Apple",
        "00:26:08": "Apple",
        "00:26:4A": "Apple",
        "00:26:B0": "Apple",
        "00:26:BB": "Apple",
        "14:10:9F": "Samsung",
        "1C:66:AA": "Samsung",
        "24:4B:81": "Samsung",
        "2C:AE:2B": "Samsung",
        "34:23:BA": "Samsung",
        "4C:BC:98": "Samsung",
        "50:01:BB": "Samsung",
        "5C:3C:27": "Samsung",
        "64:B5:C6": "Samsung",
        "70:F9:27": "Samsung",
        "78:BD:BC": "Samsung",
        "84:25:DB": "Samsung",
        "8C:C8:4B": "Samsung",
        "94:51:03": "Samsung",
        "98:52:B1": "Samsung",
        "A0:82:1F": "Samsung",
        "AC:36:13": "Samsung",
        "B8:BC:1B": "Samsung",
        "C4:50:06": "Samsung",
        "CC:07:AB": "Samsung",
        "D0:22:BE": "Samsung",
        "D8:90:E8": "Samsung",
        "EC:1F:72": "Samsung",
        "F4:42:8F": "Samsung",
        "FC:A1:3E": "Samsung",
    }

    @classmethod
    def lookup(cls, mac: str) -> Optional[str]:
        """MAC adresinden vendor bul"""
        if not mac:
            return None

        # MAC formatini normalize et
        mac = mac.upper().replace("-", ":")
        prefix = mac[:8]

        return cls.VENDORS.get(prefix)


# ==============================================================================
# AG TARAMA MOTORU
# ==============================================================================

class NetworkScanner:
    """Ag tarama ve izleme motoru"""

    def __init__(self, config: GuardianConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger

        # Veri depolama
        self.interfaces: Dict[str, NetworkInterface] = {}
        self.devices: Dict[str, NetworkDevice] = {}  # MAC -> Device
        self.wifi_networks: Dict[str, WifiNetwork] = {}  # BSSID -> Network
        self.arp_table: Dict[str, str] = {}  # IP -> MAC
        self.alerts: List[NetworkAlert] = []

        # Istatistikler
        self.stats = {
            "scans_completed": 0,
            "devices_discovered": 0,
            "alerts_generated": 0,
            "packets_analyzed": 0,
            "arp_spoofs_detected": 0,
            "rogue_aps_detected": 0,
        }

        # Veri dizinini olustur
        os.makedirs(config.data_dir, exist_ok=True)

        # Onceki verileri yukle
        self._load_persistent_data()

    def _load_persistent_data(self):
        """Kalici verileri yukle"""
        try:
            devices_file = os.path.join(self.config.data_dir, "known_devices.json")
            if os.path.exists(devices_file):
                with open(devices_file, 'r') as f:
                    data = json.load(f)
                    for mac, dev_data in data.items():
                        # Tarihleri parse et
                        dev_data['first_seen'] = datetime.fromisoformat(dev_data['first_seen'])
                        dev_data['last_seen'] = datetime.fromisoformat(dev_data['last_seen'])
                        self.devices[mac] = NetworkDevice(**dev_data)
                self.logger.info(f"{len(self.devices)} bilinen cihaz yuklendi")
        except Exception as e:
            self.logger.error(f"Cihaz verisi yukleme hatasi: {e}")

    def _save_persistent_data(self):
        """Kalici verileri kaydet"""
        try:
            devices_file = os.path.join(self.config.data_dir, "known_devices.json")
            data = {}
            for mac, device in self.devices.items():
                dev_dict = asdict(device)
                dev_dict['first_seen'] = device.first_seen.isoformat()
                dev_dict['last_seen'] = device.last_seen.isoformat()
                data[mac] = dev_dict

            with open(devices_file, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.logger.error(f"Cihaz verisi kaydetme hatasi: {e}")

    def get_interfaces(self) -> Dict[str, NetworkInterface]:
        """Tum ag arayuzlerini al"""
        interfaces = {}

        if not PSUTIL_AVAILABLE:
            self.logger.error("psutil gerekli")
            return interfaces

        try:
            # Arayuz adresleri
            addrs = psutil.net_if_addrs()
            # Arayuz istatistikleri
            stats = psutil.net_if_stats()
            # IO sayaclari
            io_counters = psutil.net_io_counters(pernic=True)

            for name, addr_list in addrs.items():
                iface = NetworkInterface(
                    name=name,
                    mac="",
                    ipv4=[],
                    ipv6=[],
                )

                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        iface.ipv4.append(addr.address)
                    elif addr.family == socket.AF_INET6:
                        iface.ipv6.append(addr.address)
                    elif addr.family == psutil.AF_LINK:
                        iface.mac = addr.address

                # Istatistikler
                if name in stats:
                    stat = stats[name]
                    iface.is_up = stat.isup
                    iface.speed = stat.speed
                    iface.mtu = stat.mtu

                # Wireless kontrolu
                iface.is_wireless = self._is_wireless_interface(name)

                # IO istatistikleri
                if name in io_counters:
                    io = io_counters[name]
                    iface.stats = {
                        "bytes_sent": io.bytes_sent,
                        "bytes_recv": io.bytes_recv,
                        "packets_sent": io.packets_sent,
                        "packets_recv": io.packets_recv,
                        "errin": io.errin,
                        "errout": io.errout,
                        "dropin": io.dropin,
                        "dropout": io.dropout,
                    }

                interfaces[name] = iface

            self.interfaces = interfaces

        except Exception as e:
            self.logger.error(f"Arayuz tarama hatasi: {e}")

        return interfaces

    def _is_wireless_interface(self, name: str) -> bool:
        """Arayuzun wireless olup olmadigini kontrol et"""
        # Linux'ta wireless arayuzleri
        wireless_path = f"/sys/class/net/{name}/wireless"
        if os.path.exists(wireless_path):
            return True

        # Isim bazli tahmin
        wireless_prefixes = ["wlan", "wlp", "wifi", "ath", "ra"]
        return any(name.startswith(prefix) for prefix in wireless_prefixes)

    def scan_local_network(self, interface: str = None) -> List[NetworkDevice]:
        """Lokal agi ARP ile tara"""
        discovered = []

        if not SCAPY_AVAILABLE:
            # Scapy yoksa arp komutunu kullan
            return self._scan_with_arp_command()

        try:
            # Hangi arayuzleri tarayacagimizi belirle
            if interface:
                ifaces = [interface]
            else:
                ifaces = [name for name, iface in self.interfaces.items()
                         if iface.is_up and iface.ipv4 and name != "lo"]

            for iface_name in ifaces:
                iface = self.interfaces.get(iface_name)
                if not iface or not iface.ipv4:
                    continue

                for ip in iface.ipv4:
                    try:
                        # IP'den ag adresini hesapla (varsayilan /24)
                        network = ipaddress.IPv4Network(f"{ip}/24", strict=False)

                        self.logger.debug(f"Ag taraniyor: {network} ({iface_name})")

                        # ARP taramasi
                        arp_request = ARP(pdst=str(network))
                        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
                        packet = broadcast / arp_request

                        # Tarama (root gerektirir)
                        if os.geteuid() == 0:
                            result = srp(packet, timeout=3, iface=iface_name, verbose=False)[0]

                            for sent, received in result:
                                device = self._process_discovered_device(
                                    ip=received.psrc,
                                    mac=received.hwsrc
                                )
                                if device:
                                    discovered.append(device)
                        else:
                            self.logger.warning("Root yetkisi olmadan ARP taramasi sinirli")
                            # Root degilse arp tablosunu kullan
                            discovered.extend(self._scan_with_arp_command())

                    except Exception as e:
                        self.logger.debug(f"Ag tarama hatasi ({ip}): {e}")

            self.stats["scans_completed"] += 1

        except Exception as e:
            self.logger.error(f"Ag tarama hatasi: {e}")

        return discovered

    def _scan_with_arp_command(self) -> List[NetworkDevice]:
        """arp komutuyla tarama (root gerektirmez)"""
        discovered = []

        try:
            # ARP tablosunu oku
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode != 0:
                # ip neigh komutunu dene
                result = subprocess.run(
                    ["ip", "neigh", "show"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

            # Parse et
            for line in result.stdout.split('\n'):
                # arp -a formati: hostname (IP) at MAC [ether] on interface
                match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
                if match:
                    ip, mac = match.groups()
                    device = self._process_discovered_device(ip, mac)
                    if device:
                        discovered.append(device)
                    continue

                # ip neigh formati: IP dev interface lladdr MAC STATE
                match = re.search(r'^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]+)', line)
                if match:
                    ip, mac = match.groups()
                    device = self._process_discovered_device(ip, mac)
                    if device:
                        discovered.append(device)

        except Exception as e:
            self.logger.error(f"ARP komut taramasi hatasi: {e}")

        return discovered

    def _process_discovered_device(self, ip: str, mac: str) -> Optional[NetworkDevice]:
        """Kesfedilen cihazi isle"""
        if not ip or not mac:
            return None

        # MAC'i normalize et
        mac = mac.upper()

        # Gecersiz MAC'leri atla
        if mac in ["00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"]:
            return None

        now = datetime.now()

        # Cihaz zaten biliniyor mu?
        if mac in self.devices:
            device = self.devices[mac]
            device.last_seen = now

            # IP degisti mi?
            if device.ip != ip:
                self.logger.info(f"Cihaz IP degisti: {mac} ({device.ip} -> {ip})")
                device.ip = ip

            return device

        # Yeni cihaz
        device = NetworkDevice(
            ip=ip,
            mac=mac,
            hostname=self._resolve_hostname(ip),
            vendor=MacVendorLookup.lookup(mac),
            first_seen=now,
            last_seen=now,
            is_gateway=self._is_gateway(ip),
            is_trusted=mac in self.config.trusted_macs or ip in self.config.trusted_ips,
        )

        self.devices[mac] = device
        self.stats["devices_discovered"] += 1

        # Yeni cihaz alarmi
        if self.config.new_device_alert and not device.is_trusted:
            self._create_alert(
                alert_type=AlertType.NEW_DEVICE,
                severity=AlertSeverity.MEDIUM,
                source_ip=ip,
                source_mac=mac,
                description=f"Yeni cihaz tespit edildi: {ip} ({mac})",
                details={
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "is_gateway": device.is_gateway,
                }
            )

        self.logger.info(f"Yeni cihaz: {ip} ({mac}) - {device.vendor or 'Bilinmeyen vendor'}")

        # Verileri kaydet
        self._save_persistent_data()

        return device

    def _resolve_hostname(self, ip: str) -> Optional[str]:
        """IP'den hostname coz"""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None

    def _is_gateway(self, ip: str) -> bool:
        """IP'nin gateway olup olmadigini kontrol et"""
        try:
            # Default gateway'i al
            result = subprocess.run(
                ["ip", "route", "show", "default"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return ip in result.stdout
        except:
            return False

    def detect_arp_spoofing(self) -> List[NetworkAlert]:
        """ARP spoofing tespiti"""
        alerts = []

        if not self.config.arp_spoof_detection:
            return alerts

        try:
            # Mevcut ARP tablosunu al
            current_arp = {}

            result = subprocess.run(
                ["ip", "neigh", "show"],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.split('\n'):
                match = re.search(r'^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-fA-F:]+)', line)
                if match:
                    ip, mac = match.groups()
                    mac = mac.upper()
                    current_arp[ip] = mac

            # Onceki tabloyla karsilastir
            for ip, mac in current_arp.items():
                if ip in self.arp_table:
                    old_mac = self.arp_table[ip]
                    if old_mac != mac:
                        # MAC degisikligi - potansiyel ARP spoofing!
                        self.stats["arp_spoofs_detected"] += 1

                        alert = self._create_alert(
                            alert_type=AlertType.ARP_SPOOF,
                            severity=AlertSeverity.CRITICAL,
                            source_ip=ip,
                            source_mac=mac,
                            description=f"ARP SPOOFING TESPITI! {ip} icin MAC degisti: {old_mac} -> {mac}",
                            details={
                                "old_mac": old_mac,
                                "new_mac": mac,
                                "old_vendor": MacVendorLookup.lookup(old_mac),
                                "new_vendor": MacVendorLookup.lookup(mac),
                            }
                        )
                        alerts.append(alert)

                        self.logger.critical(f"ARP SPOOFING: {ip} MAC degisti: {old_mac} -> {mac}")

            # Tabloyu guncelle
            self.arp_table = current_arp

        except Exception as e:
            self.logger.error(f"ARP spoofing tespiti hatasi: {e}")

        return alerts

    def scan_wifi_networks(self) -> List[WifiNetwork]:
        """WiFi aglarini tara"""
        networks = []

        try:
            # iwlist ile tarama (root gerektirebilir)
            # Wireless arayuzleri bul
            wireless_ifaces = [name for name, iface in self.interfaces.items()
                             if iface.is_wireless and iface.is_up]

            if not wireless_ifaces:
                self.logger.debug("Aktif wireless arayuz bulunamadi")
                return networks

            for iface in wireless_ifaces:
                try:
                    result = subprocess.run(
                        ["sudo", "iwlist", iface, "scan"],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if result.returncode != 0:
                        # nmcli'yi dene
                        result = subprocess.run(
                            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "dev", "wifi", "list"],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )

                        if result.returncode == 0:
                            networks.extend(self._parse_nmcli_wifi(result.stdout))
                    else:
                        networks.extend(self._parse_iwlist_wifi(result.stdout))

                except subprocess.TimeoutExpired:
                    self.logger.warning(f"WiFi taramasi zaman asimi: {iface}")
                except Exception as e:
                    self.logger.debug(f"WiFi taramasi hatasi ({iface}): {e}")

            # Aglardan rogue AP'leri kontrol et
            self._check_rogue_aps(networks)

        except Exception as e:
            self.logger.error(f"WiFi tarama hatasi: {e}")

        return networks

    def _parse_nmcli_wifi(self, output: str) -> List[WifiNetwork]:
        """nmcli ciktisini parse et"""
        networks = []

        for line in output.strip().split('\n'):
            if not line:
                continue

            parts = line.split(':')
            if len(parts) >= 6:
                ssid = parts[0] or "<Gizli>"
                bssid = parts[1].upper()

                try:
                    channel = int(parts[2]) if parts[2] else 0
                    freq = int(parts[3].replace(" MHz", "")) if parts[3] else 0
                    signal = int(parts[4]) if parts[4] else -100
                except ValueError:
                    channel, freq, signal = 0, 0, -100

                encryption = parts[5] if parts[5] else "Open"

                network = WifiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    channel=channel,
                    frequency=freq,
                    signal=signal,
                    encryption=encryption,
                    is_hidden=(ssid == "<Gizli>"),
                    is_trusted=(ssid in self.config.trusted_ssids),
                )

                # Mevcut kaydi guncelle veya ekle
                if bssid in self.wifi_networks:
                    old = self.wifi_networks[bssid]
                    network.first_seen = old.first_seen

                self.wifi_networks[bssid] = network
                networks.append(network)

        return networks

    def _parse_iwlist_wifi(self, output: str) -> List[WifiNetwork]:
        """iwlist ciktisini parse et"""
        networks = []
        current = {}

        for line in output.split('\n'):
            line = line.strip()

            if "Cell" in line and "Address:" in line:
                if current:
                    networks.append(self._create_wifi_from_dict(current))
                current = {}
                match = re.search(r'Address:\s*([0-9A-Fa-f:]+)', line)
                if match:
                    current['bssid'] = match.group(1).upper()

            elif "ESSID:" in line:
                match = re.search(r'ESSID:"([^"]*)"', line)
                if match:
                    current['ssid'] = match.group(1) or "<Gizli>"

            elif "Channel:" in line:
                match = re.search(r'Channel:(\d+)', line)
                if match:
                    current['channel'] = int(match.group(1))

            elif "Frequency:" in line:
                match = re.search(r'Frequency:([0-9.]+)\s*GHz', line)
                if match:
                    current['frequency'] = int(float(match.group(1)) * 1000)

            elif "Signal level=" in line:
                match = re.search(r'Signal level[=:](-?\d+)', line)
                if match:
                    current['signal'] = int(match.group(1))

            elif "Encryption key:" in line:
                if "on" in line.lower():
                    current['encryption'] = "WPA/WPA2"
                else:
                    current['encryption'] = "Open"

        if current:
            networks.append(self._create_wifi_from_dict(current))

        return networks

    def _create_wifi_from_dict(self, data: Dict) -> WifiNetwork:
        """Dict'ten WifiNetwork olustur"""
        ssid = data.get('ssid', '<Gizli>')
        bssid = data.get('bssid', '')

        network = WifiNetwork(
            ssid=ssid,
            bssid=bssid,
            channel=data.get('channel', 0),
            frequency=data.get('frequency', 0),
            signal=data.get('signal', -100),
            encryption=data.get('encryption', 'Unknown'),
            is_hidden=(ssid == '<Gizli>'),
            is_trusted=(ssid in self.config.trusted_ssids),
        )

        if bssid in self.wifi_networks:
            old = self.wifi_networks[bssid]
            network.first_seen = old.first_seen

        self.wifi_networks[bssid] = network
        return network

    def _check_rogue_aps(self, networks: List[WifiNetwork]):
        """Rogue (sahte) erisim noktalarini kontrol et"""
        if not self.config.rogue_ap_detection:
            return

        # Trusted SSID'lerin BSSID'lerini topla
        trusted_bssids: Dict[str, Set[str]] = defaultdict(set)
        for ssid in self.config.trusted_ssids:
            for bssid, net in self.wifi_networks.items():
                if net.ssid == ssid and net.is_trusted:
                    trusted_bssids[ssid].add(bssid)

        # Ayni SSID ile farkli BSSID'leri kontrol et (potansiyel evil twin)
        for network in networks:
            if network.ssid in self.config.trusted_ssids:
                if network.bssid not in trusted_bssids.get(network.ssid, set()):
                    # Yeni BSSID ile trusted SSID - potansiyel evil twin!
                    if trusted_bssids.get(network.ssid):  # Daha once bilinen BSSID var
                        self.stats["rogue_aps_detected"] += 1

                        self._create_alert(
                            alert_type=AlertType.ROGUE_AP,
                            severity=AlertSeverity.HIGH,
                            source_mac=network.bssid,
                            description=f"Potansiyel Evil Twin AP: {network.ssid} ({network.bssid})",
                            details={
                                "ssid": network.ssid,
                                "bssid": network.bssid,
                                "channel": network.channel,
                                "signal": network.signal,
                                "encryption": network.encryption,
                                "known_bssids": list(trusted_bssids.get(network.ssid, [])),
                            }
                        )

                        self.logger.warning(f"ROGUE AP UYARISI: {network.ssid} - yeni BSSID: {network.bssid}")

    def get_current_connection(self) -> Optional[Dict[str, Any]]:
        """Mevcut WiFi baglantisi bilgisini al"""
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi"],
                capture_output=True,
                text=True,
                timeout=10
            )

            for line in result.stdout.split('\n'):
                if line.startswith("yes:"):
                    parts = line.split(':')
                    if len(parts) >= 6:
                        return {
                            "connected": True,
                            "ssid": parts[1],
                            "bssid": parts[2],
                            "channel": int(parts[3]) if parts[3] else 0,
                            "signal": int(parts[4]) if parts[4] else 0,
                            "security": parts[5],
                        }

            return {"connected": False}

        except Exception as e:
            self.logger.debug(f"Baglanti bilgisi alinamadi: {e}")
            return None

    def _create_alert(self, alert_type: AlertType, severity: AlertSeverity,
                     description: str, source_ip: str = None, source_mac: str = None,
                     target_ip: str = None, details: Dict = None) -> NetworkAlert:
        """Alarm olustur"""
        alert = NetworkAlert(
            id=str(uuid.uuid4())[:8],
            timestamp=datetime.now().isoformat(),
            alert_type=alert_type,
            severity=severity,
            source_ip=source_ip,
            source_mac=source_mac,
            target_ip=target_ip,
            description=description,
            details=details or {},
        )

        self.alerts.append(alert)
        self.stats["alerts_generated"] += 1

        # Log'a yaz - severity.value'yu Python log seviyesine esle
        severity_to_log = {
            "info": "info",
            "low": "info",
            "medium": "warning",
            "high": "error",
            "critical": "critical"
        }
        log_level = severity_to_log.get(severity.value, "info")
        log_method = getattr(self.logger, log_level)
        log_method(f"[{alert_type.value.upper()}] {description}")

        return alert


# ==============================================================================
# BEYIN ENTEGRASYONU
# ==============================================================================

class BeyinIntegration:
    """TSUNAMI BEYIN ile entegrasyon"""

    def __init__(self, config: GuardianConfig, logger: logging.Logger):
        self.config = config
        self.logger = logger
        self._connected = False

    async def connect(self):
        """BEYIN'e baglan"""
        if not self.config.beyin_integration:
            return

        self._connected = True
        self.logger.info("BEYIN entegrasyonu aktif")

    async def send_alert(self, alert: NetworkAlert):
        """BEYIN'e alarm gonder"""
        if not self.config.beyin_integration:
            return

        try:
            alert_data = {
                "source": "NETWORK_GUARDIAN",
                "timestamp": alert.timestamp,
                "severity": alert.severity.value,
                "type": alert.alert_type.value,
                "description": alert.description,
                "source_ip": alert.source_ip,
                "source_mac": alert.source_mac,
                "target_ip": alert.target_ip,
                "details": alert.details,
            }

            # Alert dosyasina yaz
            os.makedirs(os.path.dirname(self.config.beyin_alert_file), exist_ok=True)
            with open(self.config.beyin_alert_file, 'a') as f:
                f.write(json.dumps(alert_data, ensure_ascii=False) + '\n')

        except Exception as e:
            self.logger.error(f"BEYIN alarm gonderme hatasi: {e}")


# ==============================================================================
# ANA GUARDIAN DAEMON
# ==============================================================================

class NetworkGuardian:
    """Ana Network Guardian daemon sinifi"""

    def __init__(self, config: GuardianConfig = None):
        self.config = config or GuardianConfig()

        # Log dizinini olustur
        os.makedirs(self.config.log_dir, exist_ok=True)
        os.makedirs(os.path.dirname(self.config.pid_file), exist_ok=True)

        self.logger = setup_logging(self.config.log_dir, self.config.log_level)

        # Bilesenleri baslat
        self.scanner = NetworkScanner(self.config, self.logger)
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

    def _is_running(self) -> Tuple[bool, Optional[int]]:
        """Daemon zaten calisiyor mu?"""
        if os.path.exists(self.config.pid_file):
            try:
                with open(self.config.pid_file, 'r') as f:
                    pid = int(f.read().strip())
                os.kill(pid, 0)
                return True, pid
            except (ProcessLookupError, ValueError):
                self._remove_pid()
        return False, None

    async def _interface_monitor(self):
        """Ag arayuzlerini izle"""
        previous_ifaces = set()

        while self._running:
            try:
                ifaces = self.scanner.get_interfaces()
                current_ifaces = set(ifaces.keys())

                # Yeni arayuzler
                new_ifaces = current_ifaces - previous_ifaces
                for name in new_ifaces:
                    if name != "lo":
                        self.logger.info(f"Yeni arayuz tespit edildi: {name}")

                        alert = self.scanner._create_alert(
                            alert_type=AlertType.INTERFACE_CHANGE,
                            severity=AlertSeverity.LOW,
                            description=f"Yeni ag arayuzu: {name}",
                            details=asdict(ifaces[name])
                        )
                        await self.beyin.send_alert(alert)

                # Kaybolan arayuzler
                lost_ifaces = previous_ifaces - current_ifaces
                for name in lost_ifaces:
                    if name != "lo":
                        self.logger.warning(f"Arayuz kayboldu: {name}")

                        alert = self.scanner._create_alert(
                            alert_type=AlertType.INTERFACE_CHANGE,
                            severity=AlertSeverity.MEDIUM,
                            description=f"Ag arayuzu kayboldu: {name}",
                        )
                        await self.beyin.send_alert(alert)

                previous_ifaces = current_ifaces

            except Exception as e:
                self.logger.error(f"Arayuz izleme hatasi: {e}")

            await asyncio.sleep(self.config.interface_scan_interval)

    async def _device_scanner(self):
        """Cihaz taramasi gorevi"""
        while self._running:
            try:
                devices = self.scanner.scan_local_network()

                # Yeni cihaz alarmlarini BEYIN'e gonder
                for alert in list(self.scanner.alerts):
                    if alert.alert_type == AlertType.NEW_DEVICE and not alert.handled:
                        await self.beyin.send_alert(alert)
                        alert.handled = True

            except Exception as e:
                self.logger.error(f"Cihaz tarama hatasi: {e}")

            await asyncio.sleep(self.config.device_scan_interval)

    async def _arp_monitor(self):
        """ARP tablosu izleme gorevi"""
        while self._running:
            try:
                alerts = self.scanner.detect_arp_spoofing()

                for alert in alerts:
                    await self.beyin.send_alert(alert)

            except Exception as e:
                self.logger.error(f"ARP izleme hatasi: {e}")

            await asyncio.sleep(self.config.arp_monitor_interval)

    async def _wifi_scanner(self):
        """WiFi tarama gorevi"""
        while self._running:
            try:
                networks = self.scanner.scan_wifi_networks()

                # Rogue AP alarmlarini BEYIN'e gonder
                for alert in list(self.scanner.alerts):
                    if alert.alert_type == AlertType.ROGUE_AP and not alert.handled:
                        await self.beyin.send_alert(alert)
                        alert.handled = True

            except Exception as e:
                self.logger.error(f"WiFi tarama hatasi: {e}")

            await asyncio.sleep(self.config.wifi_scan_interval)

    async def _main_loop(self):
        """Ana izleme dongusu"""
        self.logger.info("=" * 60)
        self.logger.info("TSUNAMI Network Guardian baslatiliyor...")
        self.logger.info("=" * 60)

        # BEYIN baglantisi
        await self.beyin.connect()

        # Ilk tarama
        self.scanner.get_interfaces()

        # Izleme gorevlerini baslat
        self._tasks = [
            asyncio.create_task(self._interface_monitor()),
            asyncio.create_task(self._device_scanner()),
            asyncio.create_task(self._arp_monitor()),
            asyncio.create_task(self._wifi_scanner()),
        ]

        self.logger.info("Tum izleme gorevleri baslatildi")
        self.logger.info(f"  - Arayuz izleme: {self.config.interface_scan_interval}s")
        self.logger.info(f"  - Cihaz tarama: {self.config.device_scan_interval}s")
        self.logger.info(f"  - ARP izleme: {self.config.arp_monitor_interval}s")
        self.logger.info(f"  - WiFi tarama: {self.config.wifi_scan_interval}s")

        # Ana dongu
        while self._running:
            try:
                # Durum raporu
                self.logger.info(
                    f"Durum: Cihazlar={len(self.scanner.devices)}, "
                    f"WiFi={len(self.scanner.wifi_networks)}, "
                    f"Alarmlar={self.scanner.stats['alerts_generated']}, "
                    f"ARP Spoof={self.scanner.stats['arp_spoofs_detected']}"
                )

                await asyncio.sleep(60)  # Dakikada bir durum raporu

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Ana dongu hatasi: {e}")

        # Gorevleri iptal et
        for task in self._tasks:
            task.cancel()

        self.logger.info("TSUNAMI Network Guardian durduruldu")

    def start(self):
        """Daemon'u baslat"""
        running, pid = self._is_running()
        if running:
            print(f"Network Guardian zaten calisiyor! (PID: {pid})")
            return

        # Banner
        print("""
================================================================================
    TSUNAMI NETWORK GUARDIAN v1.0 - Ag ve WiFi Korumasi
================================================================================
    Tum ag aktiviteleriniz izleniyor...
    - Yeni cihaz tespiti
    - ARP spoofing koruması
    - Rogue AP tespiti
    - WiFi guvenlik izleme
================================================================================
        """)

        # Root kontrolu
        if os.geteuid() != 0:
            print("[UYARI] Root yetkisi olmadan calisiyor - bazi ozellikler sinirli")
            print("        Tam koruma icin: sudo python3 network_guardian.py start")
            print()

        self._running = True
        self._write_pid()

        try:
            asyncio.run(self._main_loop())
        except KeyboardInterrupt:
            self.logger.info("Klavye kesintisi alindi")
        finally:
            self._remove_pid()

    def stop(self):
        """Daemon'u durdur"""
        self._running = False

    def status(self):
        """Daemon durumunu goster"""
        running, pid = self._is_running()

        print("\n" + "=" * 60)
        print("TSUNAMI NETWORK GUARDIAN - DURUM")
        print("=" * 60)

        if running:
            print(f"Durum: CALISIYOR (PID: {pid})")
        else:
            print("Durum: DURDURULDU")

        # Cihaz sayisi
        devices_file = os.path.join(self.config.data_dir, "known_devices.json")
        if os.path.exists(devices_file):
            try:
                with open(devices_file, 'r') as f:
                    devices = json.load(f)
                print(f"Bilinen cihazlar: {len(devices)}")
            except:
                pass

        # Son alarmlar
        if os.path.exists(self.config.beyin_alert_file):
            try:
                with open(self.config.beyin_alert_file, 'r') as f:
                    lines = f.readlines()
                print(f"Toplam alarm: {len(lines)}")
                if lines:
                    last = json.loads(lines[-1])
                    print(f"Son alarm: {last.get('description', 'N/A')}")
            except:
                pass

        print("=" * 60 + "\n")

    def scan(self):
        """Tek seferlik tarama yap"""
        print("\n" + "=" * 60)
        print("TSUNAMI NETWORK GUARDIAN - TEK TARAMA")
        print("=" * 60)

        # Arayuzler
        print("\n[ARAYUZLER]")
        ifaces = self.scanner.get_interfaces()
        for name, iface in ifaces.items():
            status = "UP" if iface.is_up else "DOWN"
            wifi = " (WiFi)" if iface.is_wireless else ""
            ips = ", ".join(iface.ipv4) if iface.ipv4 else "IP yok"
            print(f"  {name}: {status}{wifi} - {ips} ({iface.mac})")

        # Cihazlar
        print("\n[AGDAKI CIHAZLAR]")
        devices = self.scanner.scan_local_network()
        if devices:
            for device in devices:
                vendor = device.vendor or "Bilinmeyen"
                gw = " [GATEWAY]" if device.is_gateway else ""
                print(f"  {device.ip} - {device.mac} ({vendor}){gw}")
        else:
            print("  Cihaz bulunamadi")

        # ARP kontrolu
        print("\n[ARP KONTROLU]")
        alerts = self.scanner.detect_arp_spoofing()
        if alerts:
            for alert in alerts:
                print(f"  [UYARI] {alert.description}")
        else:
            print("  ARP tablosu temiz")

        # WiFi
        print("\n[WIFI AGLARI]")
        networks = self.scanner.scan_wifi_networks()
        if networks:
            for net in sorted(networks, key=lambda x: x.signal, reverse=True):
                enc = net.encryption or "?"
                print(f"  {net.ssid}: {net.signal} dBm, CH{net.channel}, {enc}")
        else:
            print("  WiFi agi bulunamadi veya tarama yapilamadi")

        print("\n" + "=" * 60 + "\n")

    def list_devices(self):
        """Bilinen cihazlari listele"""
        print("\n" + "=" * 60)
        print("TSUNAMI NETWORK GUARDIAN - BILINEN CIHAZLAR")
        print("=" * 60)

        # Verileri yukle
        self.scanner._load_persistent_data()

        if not self.scanner.devices:
            print("\nHenuz cihaz kaydedilmedi. 'scan' komutunu calistirin.\n")
            return

        for mac, device in sorted(self.scanner.devices.items(), key=lambda x: x[1].last_seen, reverse=True):
            vendor = device.vendor or "Bilinmeyen"
            hostname = device.hostname or "N/A"
            gw = " [GATEWAY]" if device.is_gateway else ""
            trusted = " [GUVENLI]" if device.is_trusted else ""

            print(f"\n  MAC: {mac}")
            print(f"  IP: {device.ip}")
            print(f"  Hostname: {hostname}")
            print(f"  Vendor: {vendor}")
            print(f"  Ilk gorulme: {device.first_seen.strftime('%Y-%m-%d %H:%M')}")
            print(f"  Son gorulme: {device.last_seen.strftime('%Y-%m-%d %H:%M')}")
            print(f"  Ozellikler:{gw}{trusted}")

        print("\n" + "=" * 60 + "\n")

    def wifi_scan(self):
        """WiFi taramasi yap"""
        print("\n" + "=" * 60)
        print("TSUNAMI NETWORK GUARDIAN - WIFI TARAMASI")
        print("=" * 60)

        # Ilk olarak arayuzleri al
        self.scanner.get_interfaces()

        # WiFi tara
        networks = self.scanner.scan_wifi_networks()

        if not networks:
            print("\nWiFi agi bulunamadi veya tarama yapilamadi.")
            print("Root yetkisi gerekebilir: sudo python3 network_guardian.py wifi\n")
            return

        # Mevcut baglanti
        current = self.scanner.get_current_connection()
        if current and current.get("connected"):
            print(f"\n[BAGLI AG] {current['ssid']} ({current['bssid']})")

        print("\n[BULUNAN AGLAR]")
        for net in sorted(networks, key=lambda x: x.signal, reverse=True):
            enc = net.encryption or "Bilinmiyor"
            hidden = " [GIZLI]" if net.is_hidden else ""
            trusted = " [GUVENLI]" if net.is_trusted else ""

            print(f"\n  SSID: {net.ssid}{hidden}{trusted}")
            print(f"  BSSID: {net.bssid}")
            print(f"  Sinyal: {net.signal} dBm")
            print(f"  Kanal: {net.channel}")
            print(f"  Sifreleme: {enc}")

        print("\n" + "=" * 60 + "\n")


# ==============================================================================
# YAPILANDIRMA YUKLEME
# ==============================================================================

def load_config_from_json(config_path: str) -> GuardianConfig:
    """JSON dosyasindan yapilandirma yukle"""
    config = GuardianConfig()

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)

            # network_guardian bolumunu al
            ng_config = data.get("network_guardian", {})

            # Degerleri ata
            for key, value in ng_config.items():
                if hasattr(config, key):
                    setattr(config, key, value)

            # Defender bolumunden de bazi ayarlari al
            defender_config = data.get("defender", {})
            if "log_dir" in defender_config:
                config.log_dir = defender_config["log_dir"]
            if "whitelist_ips" in defender_config:
                config.trusted_ips = defender_config["whitelist_ips"]

        except Exception as e:
            print(f"[UYARI] Yapilandirma yukleme hatasi: {e}")

    return config


# ==============================================================================
# CLI
# ==============================================================================

def print_help():
    """Yardim mesaji goster"""
    print("""
================================================================================
    TSUNAMI NETWORK GUARDIAN v1.0 - Ag ve WiFi Korumasi
================================================================================

KULLANIM:
    python3 network_guardian.py <komut>

KOMUTLAR:
    start    - Guardian daemon'unu baslat (7/24 izleme)
    stop     - Guardian daemon'unu durdur
    status   - Daemon durumunu goster
    scan     - Tek seferlik tam tarama yap
    devices  - Bilinen cihazlari listele
    wifi     - WiFi aglarini tara

OZELLIKLER:
    - Ag arayuzu izleme
    - Yeni cihaz tespiti
    - ARP spoofing tespiti (MITM koruması)
    - Rogue AP / Evil Twin tespiti
    - WiFi guvenlik izleme
    - TSUNAMI BEYIN entegrasyonu
    - Kapsamli loglama

NOTLAR:
    - Tam koruma icin root yetkisi gerekir
    - Root olmadan temel izleme yapilir
    - Loglar: ~/.tsunami/logs/

================================================================================
    """)


def main():
    """Ana giris noktasi"""
    if len(sys.argv) < 2:
        print_help()
        sys.exit(0)

    command = sys.argv[1].lower()

    # Yapilandirmayi yukle
    config_path = "/home/lydian/Desktop/TSUNAMI/tsunami_config.json"
    config = load_config_from_json(config_path)

    guardian = NetworkGuardian(config)

    if command == "start":
        guardian.start()
    elif command == "stop":
        running, pid = guardian._is_running()
        if running:
            os.kill(pid, signal.SIGTERM)
            print(f"Network Guardian durduruldu (PID: {pid})")
        else:
            print("Network Guardian calismıyor")
    elif command == "status":
        guardian.status()
    elif command == "scan":
        guardian.scan()
    elif command == "devices":
        guardian.list_devices()
    elif command == "wifi":
        guardian.wifi_scan()
    elif command in ["help", "-h", "--help"]:
        print_help()
    else:
        print(f"Bilinmeyen komut: {command}")
        print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
