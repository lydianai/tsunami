#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Kablosuz Guvenlik Izleme Modulu (Wireless Security Monitoring)
    Yalnizca SAVUNMA Amacli - Pasif Izleme ve Tespit
================================================================================

    Bu modul yalnizca SAVUNMA amaciyla tasarlanmistir:
    - Pasif kablosuz ag izleme
    - Sahte erisim noktasi tespiti
    - Deauth saldiri algilama
    - Zayif sifreleme raporlama
    - Bluetooth guvenlik izleme
    - Kablosuz IDS/IPS entegrasyonu

    AKTIF SALDIRI YETENEGI YOKTUR - Yalnizca izleme ve tespit.

    Bilesenler:
    - wifi_monitor.py: Pasif WiFi guvenlik izleme
    - bluetooth_monitor.py: Pasif Bluetooth guvenlik izleme
    - wireless_ids.py: Kablosuz Saldiri Tespit Sistemi
    - alert_manager.py: Alarm yonetimi ve bildirim

================================================================================
"""

from .wifi_monitor import (
    WiFiSecurityMonitor,
    RogueAPDetection,
    EvilTwinDetection,
    DeauthAttackEvent,
    EncryptionAnalysis,
    HiddenNetworkInfo
)

from .bluetooth_monitor import (
    BluetoothSecurityMonitor,
    SuspiciousDevice,
    PairingAttempt,
    SpoofedNameDetection
)

from .wireless_ids import (
    WirelessIDS,
    WirelessThreatSignature,
    AnomalyDetection,
    WirelessSecurityEvent,
    ThreatCategory
)

from .alert_manager import (
    WirelessAlertManager,
    WirelessAlert,
    AlertSeverity,
    AlertChannel,
    AlertAggregator
)

__version__ = "1.0.0"
__author__ = "TSUNAMI Security Team"

__all__ = [
    # WiFi Security Monitor
    'WiFiSecurityMonitor',
    'RogueAPDetection',
    'EvilTwinDetection',
    'DeauthAttackEvent',
    'EncryptionAnalysis',
    'HiddenNetworkInfo',

    # Bluetooth Security Monitor
    'BluetoothSecurityMonitor',
    'SuspiciousDevice',
    'PairingAttempt',
    'SpoofedNameDetection',

    # Wireless IDS
    'WirelessIDS',
    'WirelessThreatSignature',
    'AnomalyDetection',
    'WirelessSecurityEvent',
    'ThreatCategory',

    # Alert Manager
    'WirelessAlertManager',
    'WirelessAlert',
    'AlertSeverity',
    'AlertChannel',
    'AlertAggregator'
]
