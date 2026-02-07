#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI Kablosuz Alarm Yoneticisi (Wireless Alert Manager)
    Alarm Yonetimi, Bildirim ve Entegrasyon
================================================================================

    Ozellikler:
    - Alarm ciddiyet siniflandirmasi
    - Coklu bildirim kanali (email, webhook, message bus)
    - Alarm toplanma (aggregation) ve tekrar onleme (deduplication)
    - dalga_beyin.py entegrasyonu

    Bu modul tespit edilen olaylari isler ve bildirim gonderir.
    Aktif mudahale yapmaz, yalnizca alarm ve bildirim uretir.

================================================================================
"""

import logging
import hashlib
import json
import asyncio
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Any, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import queue
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# HTTP istekleri icin
try:
    import requests
except ImportError:
    requests = None

# TSUNAMI entegrasyonlari
try:
    from dalga_beyin import MesajTipi, Mesaj, DefconSeviyesi
    DALGA_BEYIN_AVAILABLE = True
except ImportError:
    DALGA_BEYIN_AVAILABLE = False

logger = logging.getLogger('tsunami.wireless_defense.alerts')


# ============================================================================
# ENUM TANIMLARI
# ============================================================================

class AlertSeverity(Enum):
    """Alarm ciddiyet seviyeleri"""
    INFO = 1        # Bilgilendirme
    LOW = 2         # Dusuk oncelik
    MEDIUM = 3      # Orta oncelik
    HIGH = 4        # Yuksek oncelik
    CRITICAL = 5    # Kritik - hemen mudahale


class AlertChannel(Enum):
    """Bildirim kanallari"""
    EMAIL = "email"
    WEBHOOK = "webhook"
    MESSAGE_BUS = "message_bus"     # dalga_beyin entegrasyonu
    SLACK = "slack"
    TEAMS = "teams"
    TELEGRAM = "telegram"
    SMS = "sms"
    SYSLOG = "syslog"
    CONSOLE = "console"


class AlertStatus(Enum):
    """Alarm durumu"""
    NEW = "yeni"
    ACKNOWLEDGED = "onaylandi"
    INVESTIGATING = "inceleniyor"
    RESOLVED = "cozuldu"
    FALSE_POSITIVE = "yanlis_pozitif"
    SUPPRESSED = "bastirildi"


# ============================================================================
# VERI YAPILARI
# ============================================================================

@dataclass
class WirelessAlert:
    """
    Kablosuz Guvenlik Alarmi
    Tam alarm kaydi
    """
    alert_id: str                           # Benzersiz alarm ID
    timestamp: datetime                     # Olusturulma zamani
    severity: AlertSeverity                 # Ciddiyet
    category: str                           # Kategori
    title: str                              # Alarm basligi
    description: str                        # Detayli aciklama
    source: str                             # Kaynak modul
    source_identifier: Optional[str]        # Kaynak cihaz/MAC
    target_identifier: Optional[str]        # Hedef cihaz
    event_count: int                        # Toplanmis olay sayisi
    first_seen: datetime                    # Ilk gorunme
    last_seen: datetime                     # Son gorunme
    raw_events: List[Dict]                  # Ham olay verileri
    recommended_actions: List[str]          # Onerilen aksiyonlar
    status: AlertStatus = AlertStatus.NEW   # Durum
    assigned_to: Optional[str] = None       # Atanan kisi
    notes: List[str] = field(default_factory=list)  # Notlar
    tags: Set[str] = field(default_factory=set)     # Etiketler
    notifications_sent: List[Dict] = field(default_factory=list)  # Gonderilen bildirimler
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """JSON serializasyonu icin dict'e donustur"""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'severity_name': self.severity.name,
            'category': self.category,
            'title': self.title,
            'description': self.description,
            'source': self.source,
            'source_identifier': self.source_identifier,
            'target_identifier': self.target_identifier,
            'event_count': self.event_count,
            'first_seen': self.first_seen.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'raw_events': self.raw_events[-10:],  # Son 10 olay
            'recommended_actions': self.recommended_actions,
            'status': self.status.value,
            'assigned_to': self.assigned_to,
            'notes': self.notes,
            'tags': list(self.tags),
            'notifications_sent': self.notifications_sent,
            'metadata': self.metadata
        }

    def to_turkish_summary(self) -> str:
        """Turkce okunabilir ozet"""
        severity_tr = {
            AlertSeverity.INFO: 'Bilgi',
            AlertSeverity.LOW: 'Dusuk',
            AlertSeverity.MEDIUM: 'Orta',
            AlertSeverity.HIGH: 'Yuksek',
            AlertSeverity.CRITICAL: 'KRITIK'
        }
        return (
            f"[{severity_tr[self.severity]}] {self.title}\n"
            f"Kategori: {self.category}\n"
            f"Kaynak: {self.source_identifier or 'Bilinmiyor'}\n"
            f"Zaman: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Olay Sayisi: {self.event_count}\n"
            f"Aciklama: {self.description}"
        )


@dataclass
class AlertAggregator:
    """
    Alarm Toplayici
    Benzer alarmlari gruplar
    """
    aggregation_key: str                    # Gruplama anahtari
    alerts: List[str]                       # Alarm ID'leri
    event_count: int                        # Toplam olay sayisi
    first_seen: datetime                    # Ilk olay zamani
    last_seen: datetime                     # Son olay zamani
    severity: AlertSeverity                 # En yuksek ciddiyet
    is_suppressed: bool = False             # Bastirildi mi
    suppression_until: Optional[datetime] = None  # Bastirma bitis zamani


# ============================================================================
# ANA ALERT MANAGER SINIFI
# ============================================================================

class WirelessAlertManager:
    """
    Kablosuz Alarm Yoneticisi

    Kablosuz guvenlik olaylari icin merkezi alarm yonetimi.
    Bildirim gonderme, toplanma ve dalga_beyin entegrasyonu.

    Kullanim:
        manager = WirelessAlertManager()

        # Kanal yapilandirmasi
        manager.configure_channel(AlertChannel.WEBHOOK, {
            'url': 'https://example.com/webhook',
            'secret': 'xxx'
        })

        # Alarm olustur
        alert = manager.create_alert(...)

        # Bildirim gonder
        manager.dispatch_notification(alert)
    """

    # Ciddiyet -> DEFCON eslestirmesi
    SEVERITY_TO_DEFCON = {
        AlertSeverity.INFO: 5,      # GUVENLI
        AlertSeverity.LOW: 4,       # DUSUK
        AlertSeverity.MEDIUM: 3,    # ORTA
        AlertSeverity.HIGH: 2,      # YUKSEK
        AlertSeverity.CRITICAL: 1   # KRITIK
    }

    # Varsayilan toplanma penceresi (saniye)
    DEFAULT_AGGREGATION_WINDOW = 300  # 5 dakika

    # Varsayilan tekrar onleme penceresi (saniye)
    DEFAULT_DEDUP_WINDOW = 60  # 1 dakika

    def __init__(
        self,
        dalga_beyin_callback: Optional[Callable] = None,
        aggregation_window: int = 300,
        dedup_window: int = 60,
        auto_dispatch: bool = True
    ):
        """
        Alarm Yoneticisi baslatici

        Args:
            dalga_beyin_callback: dalga_beyin mesaj gonderme callback'i
            aggregation_window: Alarm toplanma penceresi (saniye)
            dedup_window: Tekrar onleme penceresi (saniye)
            auto_dispatch: Otomatik bildirim gonderme
        """
        self.dalga_beyin_callback = dalga_beyin_callback
        self.aggregation_window = aggregation_window
        self.dedup_window = dedup_window
        self.auto_dispatch = auto_dispatch

        # Kanal yapilandirmalari
        self._channel_configs: Dict[AlertChannel, Dict] = {}

        # Alarm depolama
        self._alerts: Dict[str, WirelessAlert] = {}
        self._alert_history: List[str] = []  # Kronolojik ID listesi

        # Toplanma ve tekrar onleme
        self._aggregators: Dict[str, AlertAggregator] = {}
        self._recent_hashes: Dict[str, datetime] = {}  # Tekrar onleme

        # Bildirim kuyrugu
        self._notification_queue: queue.Queue = queue.Queue()
        self._dispatch_thread: Optional[threading.Thread] = None
        self._running = False

        # Istatistikler
        self._stats = {
            'total_alerts': 0,
            'alerts_by_severity': defaultdict(int),
            'alerts_by_category': defaultdict(int),
            'notifications_sent': defaultdict(int),
            'deduplicated': 0,
            'aggregated': 0
        }

        logger.info("[Alert Manager] Kablosuz alarm yoneticisi baslatildi")

    def start(self):
        """Bildirim dispatcher'i baslat"""
        if self._running:
            return

        self._running = True
        self._dispatch_thread = threading.Thread(
            target=self._dispatch_worker,
            daemon=True
        )
        self._dispatch_thread.start()
        logger.info("[Alert Manager] Bildirim dispatcher baslatildi")

    def stop(self):
        """Bildirim dispatcher'i durdur"""
        self._running = False
        if self._dispatch_thread:
            self._dispatch_thread.join(timeout=5)
            logger.info("[Alert Manager] Bildirim dispatcher durduruldu")

    def configure_channel(
        self,
        channel: AlertChannel,
        config: Dict[str, Any]
    ):
        """
        Bildirim Kanali Yapilandirmasi

        Args:
            channel: Kanal tipi
            config: Kanal yapilandirmasi

        Yapilandirma ornekleri:

        EMAIL:
            {
                'smtp_host': 'smtp.example.com',
                'smtp_port': 587,
                'smtp_user': 'alerts@example.com',
                'smtp_pass': 'xxx',
                'from_addr': 'alerts@example.com',
                'to_addrs': ['admin@example.com'],
                'use_tls': True
            }

        WEBHOOK:
            {
                'url': 'https://example.com/webhook',
                'method': 'POST',
                'headers': {'Authorization': 'Bearer xxx'},
                'secret': 'hmac_secret'  # Opsiyonel HMAC dogrulama
            }

        SLACK:
            {
                'webhook_url': 'https://hooks.slack.com/services/xxx',
                'channel': '#security-alerts',
                'username': 'TSUNAMI IDS'
            }

        MESSAGE_BUS:
            {
                'enabled': True
            }
        """
        self._channel_configs[channel] = config
        logger.info(f"[Alert Manager] Kanal yapilandirmasi: {channel.value}")

    def create_alert(
        self,
        severity: AlertSeverity,
        category: str,
        title: str,
        description: str,
        source: str,
        source_identifier: Optional[str] = None,
        target_identifier: Optional[str] = None,
        raw_event: Optional[Dict] = None,
        recommended_actions: Optional[List[str]] = None,
        tags: Optional[Set[str]] = None,
        metadata: Optional[Dict] = None
    ) -> Optional[WirelessAlert]:
        """
        Yeni Alarm Olustur

        Tekrar onleme ve toplanma uygular.

        Args:
            severity: Ciddiyet seviyesi
            category: Alarm kategorisi
            title: Baslik
            description: Aciklama
            source: Kaynak modul
            source_identifier: Kaynak MAC/BSSID
            target_identifier: Hedef
            raw_event: Ham olay verisi
            recommended_actions: Onerilen aksiyonlar
            tags: Etiketler
            metadata: Ek metadata

        Returns:
            WirelessAlert: Olusturulan alarm (tekrar ise None)
        """
        now = datetime.now()

        # Tekrar onleme hash'i
        dedup_key = self._create_dedup_key(
            severity, category, title, source_identifier
        )

        # Tekrar kontrolu
        if dedup_key in self._recent_hashes:
            if now - self._recent_hashes[dedup_key] < timedelta(seconds=self.dedup_window):
                # Bu bir tekrar - sadece aggregator'i guncelle
                self._stats['deduplicated'] += 1
                agg_key = self._get_aggregation_key(category, source_identifier)
                if agg_key in self._aggregators:
                    agg = self._aggregators[agg_key]
                    agg.event_count += 1
                    agg.last_seen = now
                    if severity.value > agg.severity.value:
                        agg.severity = severity
                return None

        self._recent_hashes[dedup_key] = now

        # Alarm ID olustur
        alert_id = self._generate_alert_id()

        # Alarm olustur
        alert = WirelessAlert(
            alert_id=alert_id,
            timestamp=now,
            severity=severity,
            category=category,
            title=title,
            description=description,
            source=source,
            source_identifier=source_identifier,
            target_identifier=target_identifier,
            event_count=1,
            first_seen=now,
            last_seen=now,
            raw_events=[raw_event] if raw_event else [],
            recommended_actions=recommended_actions or [],
            tags=tags or set(),
            metadata=metadata or {}
        )

        # Toplanma guncelle
        agg_key = self._get_aggregation_key(category, source_identifier)
        if agg_key in self._aggregators:
            agg = self._aggregators[agg_key]
            agg.alerts.append(alert_id)
            agg.event_count += 1
            agg.last_seen = now
            if severity.value > agg.severity.value:
                agg.severity = severity
            self._stats['aggregated'] += 1
        else:
            self._aggregators[agg_key] = AlertAggregator(
                aggregation_key=agg_key,
                alerts=[alert_id],
                event_count=1,
                first_seen=now,
                last_seen=now,
                severity=severity
            )

        # Sakla
        self._alerts[alert_id] = alert
        self._alert_history.append(alert_id)

        # Istatistikler
        self._stats['total_alerts'] += 1
        self._stats['alerts_by_severity'][severity.name] += 1
        self._stats['alerts_by_category'][category] += 1

        logger.info(
            f"[Alert Manager] Yeni alarm: {alert_id} - "
            f"[{severity.name}] {title}"
        )

        # Otomatik bildirim
        if self.auto_dispatch:
            self.dispatch_notification(alert)

        return alert

    def dispatch_notification(
        self,
        alert: WirelessAlert,
        channels: Optional[List[AlertChannel]] = None
    ):
        """
        Bildirim Gonder

        Belirtilen kanallara veya ciddiyet-tabanli varsayilan kanallara
        bildirim gonderir.

        Args:
            alert: Gonderilecek alarm
            channels: Hedef kanallar (None ise ciddiyet-tabanli)
        """
        # Bastirilmis mi kontrol et
        agg_key = self._get_aggregation_key(alert.category, alert.source_identifier)
        if agg_key in self._aggregators:
            agg = self._aggregators[agg_key]
            if agg.is_suppressed:
                if agg.suppression_until and datetime.now() < agg.suppression_until:
                    logger.debug(f"[Alert Manager] Bastirilmis alarm: {alert.alert_id}")
                    return
                else:
                    agg.is_suppressed = False

        # Kanallar belirlenmemisse ciddiyet tabanli sec
        if channels is None:
            channels = self._get_channels_for_severity(alert.severity)

        for channel in channels:
            if channel not in self._channel_configs:
                continue

            # Kuyruga ekle
            self._notification_queue.put({
                'alert': alert,
                'channel': channel,
                'config': self._channel_configs[channel]
            })

    def _dispatch_worker(self):
        """Bildirim dispatcher is parcacigi"""
        while self._running:
            try:
                item = self._notification_queue.get(timeout=1)
                if item:
                    self._send_notification(
                        item['alert'],
                        item['channel'],
                        item['config']
                    )
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"[Alert Manager] Dispatcher hatasi: {e}")

    def _send_notification(
        self,
        alert: WirelessAlert,
        channel: AlertChannel,
        config: Dict
    ):
        """Tek bir bildirim gonder"""
        success = False
        error_msg = None

        try:
            if channel == AlertChannel.EMAIL:
                success = self._send_email(alert, config)

            elif channel == AlertChannel.WEBHOOK:
                success = self._send_webhook(alert, config)

            elif channel == AlertChannel.SLACK:
                success = self._send_slack(alert, config)

            elif channel == AlertChannel.TEAMS:
                success = self._send_teams(alert, config)

            elif channel == AlertChannel.TELEGRAM:
                success = self._send_telegram(alert, config)

            elif channel == AlertChannel.MESSAGE_BUS:
                success = self._send_to_dalga_beyin(alert, config)

            elif channel == AlertChannel.CONSOLE:
                success = self._send_console(alert, config)

            elif channel == AlertChannel.SYSLOG:
                success = self._send_syslog(alert, config)

        except Exception as e:
            error_msg = str(e)
            logger.error(f"[Alert Manager] {channel.value} hatasi: {e}")

        # Kayit
        alert.notifications_sent.append({
            'channel': channel.value,
            'timestamp': datetime.now().isoformat(),
            'success': success,
            'error': error_msg
        })

        if success:
            self._stats['notifications_sent'][channel.value] += 1

    def _send_email(self, alert: WirelessAlert, config: Dict) -> bool:
        """Email bildirimi gonder"""
        try:
            msg = MIMEMultipart()
            msg['From'] = config['from_addr']
            msg['To'] = ', '.join(config['to_addrs'])
            msg['Subject'] = f"[{alert.severity.name}] TSUNAMI Alert: {alert.title}"

            body = alert.to_turkish_summary()
            body += f"\n\nOnerilen Aksiyonlar:\n"
            for action in alert.recommended_actions:
                body += f"  - {action}\n"

            msg.attach(MIMEText(body, 'plain', 'utf-8'))

            smtp = smtplib.SMTP(config['smtp_host'], config.get('smtp_port', 587))
            if config.get('use_tls', True):
                smtp.starttls()
            smtp.login(config['smtp_user'], config['smtp_pass'])
            smtp.sendmail(config['from_addr'], config['to_addrs'], msg.as_string())
            smtp.quit()

            logger.info(f"[Alert Manager] Email gonderildi: {alert.alert_id}")
            return True

        except Exception as e:
            logger.error(f"[Alert Manager] Email hatasi: {e}")
            return False

    def _send_webhook(self, alert: WirelessAlert, config: Dict) -> bool:
        """Webhook bildirimi gonder"""
        if not requests:
            logger.error("[Alert Manager] requests modulu yuklu degil")
            return False

        try:
            url = config['url']
            method = config.get('method', 'POST')
            headers = config.get('headers', {})
            headers['Content-Type'] = 'application/json'

            payload = {
                'source': 'tsunami_wireless_ids',
                'alert': alert.to_dict()
            }

            # HMAC imza (opsiyonel)
            if 'secret' in config:
                import hmac
                signature = hmac.new(
                    config['secret'].encode(),
                    json.dumps(payload).encode(),
                    hashlib.sha256
                ).hexdigest()
                headers['X-TSUNAMI-Signature'] = signature

            if method.upper() == 'POST':
                response = requests.post(url, json=payload, headers=headers, timeout=10)
            else:
                response = requests.request(method, url, json=payload, headers=headers, timeout=10)

            success = response.status_code in (200, 201, 202, 204)

            if success:
                logger.info(f"[Alert Manager] Webhook gonderildi: {alert.alert_id}")
            else:
                logger.warning(f"[Alert Manager] Webhook yaniti: {response.status_code}")

            return success

        except Exception as e:
            logger.error(f"[Alert Manager] Webhook hatasi: {e}")
            return False

    def _send_slack(self, alert: WirelessAlert, config: Dict) -> bool:
        """Slack bildirimi gonder"""
        if not requests:
            return False

        try:
            severity_colors = {
                AlertSeverity.INFO: '#36a64f',
                AlertSeverity.LOW: '#2eb886',
                AlertSeverity.MEDIUM: '#daa038',
                AlertSeverity.HIGH: '#e01e5a',
                AlertSeverity.CRITICAL: '#ff0000'
            }

            payload = {
                'channel': config.get('channel', '#security-alerts'),
                'username': config.get('username', 'TSUNAMI IDS'),
                'icon_emoji': ':shield:',
                'attachments': [{
                    'color': severity_colors[alert.severity],
                    'title': f"[{alert.severity.name}] {alert.title}",
                    'text': alert.description,
                    'fields': [
                        {
                            'title': 'Kategori',
                            'value': alert.category,
                            'short': True
                        },
                        {
                            'title': 'Kaynak',
                            'value': alert.source_identifier or 'Bilinmiyor',
                            'short': True
                        },
                        {
                            'title': 'Zaman',
                            'value': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                            'short': True
                        },
                        {
                            'title': 'Olay Sayisi',
                            'value': str(alert.event_count),
                            'short': True
                        }
                    ],
                    'footer': 'TSUNAMI Wireless Defense',
                    'ts': int(alert.timestamp.timestamp())
                }]
            }

            response = requests.post(
                config['webhook_url'],
                json=payload,
                timeout=10
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"[Alert Manager] Slack hatasi: {e}")
            return False

    def _send_teams(self, alert: WirelessAlert, config: Dict) -> bool:
        """Microsoft Teams bildirimi gonder"""
        if not requests:
            return False

        try:
            severity_colors = {
                AlertSeverity.INFO: '00ff00',
                AlertSeverity.LOW: '00ff00',
                AlertSeverity.MEDIUM: 'ffff00',
                AlertSeverity.HIGH: 'ff8c00',
                AlertSeverity.CRITICAL: 'ff0000'
            }

            payload = {
                '@type': 'MessageCard',
                '@context': 'http://schema.org/extensions',
                'themeColor': severity_colors[alert.severity],
                'summary': f"TSUNAMI Alert: {alert.title}",
                'sections': [{
                    'activityTitle': f"[{alert.severity.name}] {alert.title}",
                    'activitySubtitle': alert.category,
                    'facts': [
                        {'name': 'Kaynak', 'value': alert.source_identifier or 'Bilinmiyor'},
                        {'name': 'Zaman', 'value': alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')},
                        {'name': 'Olay Sayisi', 'value': str(alert.event_count)}
                    ],
                    'text': alert.description
                }]
            }

            response = requests.post(
                config['webhook_url'],
                json=payload,
                timeout=10
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"[Alert Manager] Teams hatasi: {e}")
            return False

    def _send_telegram(self, alert: WirelessAlert, config: Dict) -> bool:
        """Telegram bildirimi gonder"""
        if not requests:
            return False

        try:
            bot_token = config['bot_token']
            chat_id = config['chat_id']

            severity_emoji = {
                AlertSeverity.INFO: 'ℹ️',
                AlertSeverity.LOW: '🟢',
                AlertSeverity.MEDIUM: '🟡',
                AlertSeverity.HIGH: '🟠',
                AlertSeverity.CRITICAL: '🔴'
            }

            message = (
                f"{severity_emoji[alert.severity]} *TSUNAMI Alert*\n\n"
                f"*[{alert.severity.name}]* {alert.title}\n\n"
                f"📁 *Kategori:* {alert.category}\n"
                f"🎯 *Kaynak:* {alert.source_identifier or 'Bilinmiyor'}\n"
                f"⏰ *Zaman:* {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"📊 *Olay Sayisi:* {alert.event_count}\n\n"
                f"📝 *Aciklama:*\n{alert.description}"
            )

            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }

            response = requests.post(url, json=payload, timeout=10)
            return response.status_code == 200

        except Exception as e:
            logger.error(f"[Alert Manager] Telegram hatasi: {e}")
            return False

    def _send_to_dalga_beyin(self, alert: WirelessAlert, config: Dict) -> bool:
        """dalga_beyin mesaj veri yoluna gonder"""
        if not config.get('enabled', True):
            return False

        try:
            if self.dalga_beyin_callback:
                # Callback varsa kullan
                defcon = self.SEVERITY_TO_DEFCON.get(alert.severity, 5)

                message_data = {
                    'tip': 'alarm',
                    'kaynak': 'wireless_ids',
                    'defcon': defcon,
                    'alarm_id': alert.alert_id,
                    'baslik': alert.title,
                    'aciklama': alert.description,
                    'kategori': alert.category,
                    'ciddiyet': alert.severity.name,
                    'kaynak_cihaz': alert.source_identifier,
                    'zaman': alert.timestamp.isoformat(),
                    'olay_sayisi': alert.event_count,
                    'onerilen_aksiyonlar': alert.recommended_actions
                }

                self.dalga_beyin_callback(message_data)
                logger.info(f"[Alert Manager] dalga_beyin'e gonderildi: {alert.alert_id}")
                return True

            elif DALGA_BEYIN_AVAILABLE:
                # dalga_beyin modulu varsa dogrudan kullan
                # Bu kısım entegrasyon sırasında özelleştirilmeli
                logger.info(f"[Alert Manager] dalga_beyin mesaji hazir: {alert.alert_id}")
                return True

            else:
                logger.warning("[Alert Manager] dalga_beyin entegrasyonu yapilmamis")
                return False

        except Exception as e:
            logger.error(f"[Alert Manager] dalga_beyin hatasi: {e}")
            return False

    def _send_console(self, alert: WirelessAlert, config: Dict) -> bool:
        """Konsola yazdir"""
        try:
            severity_colors = {
                AlertSeverity.INFO: '\033[92m',     # Yesil
                AlertSeverity.LOW: '\033[96m',      # Cyan
                AlertSeverity.MEDIUM: '\033[93m',   # Sari
                AlertSeverity.HIGH: '\033[91m',     # Kirmizi
                AlertSeverity.CRITICAL: '\033[1;91m'  # Bold kirmizi
            }
            reset = '\033[0m'

            color = severity_colors.get(alert.severity, '')
            print(f"\n{color}{'='*60}")
            print(f"TSUNAMI WIRELESS ALERT")
            print(f"{'='*60}{reset}")
            print(alert.to_turkish_summary())
            print(f"{color}{'='*60}{reset}\n")

            return True

        except Exception as e:
            logger.error(f"[Alert Manager] Console hatasi: {e}")
            return False

    def _send_syslog(self, alert: WirelessAlert, config: Dict) -> bool:
        """Syslog'a gonder"""
        try:
            import syslog

            severity_map = {
                AlertSeverity.INFO: syslog.LOG_INFO,
                AlertSeverity.LOW: syslog.LOG_NOTICE,
                AlertSeverity.MEDIUM: syslog.LOG_WARNING,
                AlertSeverity.HIGH: syslog.LOG_ERR,
                AlertSeverity.CRITICAL: syslog.LOG_CRIT
            }

            syslog.openlog('tsunami-wireless-ids', syslog.LOG_PID, syslog.LOG_LOCAL0)
            syslog.syslog(
                severity_map.get(alert.severity, syslog.LOG_INFO),
                f"[{alert.severity.name}] {alert.title}: {alert.description}"
            )
            syslog.closelog()

            return True

        except Exception as e:
            logger.error(f"[Alert Manager] Syslog hatasi: {e}")
            return False

    # ========================================================================
    # YARDIMCI METODLAR
    # ========================================================================

    def _generate_alert_id(self) -> str:
        """Benzersiz alarm ID olustur"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        random_part = hashlib.md5(
            f"{timestamp}{len(self._alerts)}".encode()
        ).hexdigest()[:6]
        return f"WLA-{timestamp}-{random_part.upper()}"

    def _create_dedup_key(
        self,
        severity: AlertSeverity,
        category: str,
        title: str,
        source: Optional[str]
    ) -> str:
        """Tekrar onleme anahtari olustur"""
        key_str = f"{severity.value}:{category}:{title}:{source or ''}"
        return hashlib.md5(key_str.encode()).hexdigest()

    def _get_aggregation_key(
        self,
        category: str,
        source: Optional[str]
    ) -> str:
        """Toplanma anahtari olustur"""
        return f"{category}:{source or 'unknown'}"

    def _get_channels_for_severity(
        self,
        severity: AlertSeverity
    ) -> List[AlertChannel]:
        """Ciddiyet seviyesine gore varsayilan kanallar"""
        channels = []

        # Her zaman console
        if AlertChannel.CONSOLE in self._channel_configs:
            channels.append(AlertChannel.CONSOLE)

        # Her zaman message bus (dalga_beyin)
        if AlertChannel.MESSAGE_BUS in self._channel_configs:
            channels.append(AlertChannel.MESSAGE_BUS)

        # Ciddiyet bazli
        if severity.value >= AlertSeverity.MEDIUM.value:
            if AlertChannel.WEBHOOK in self._channel_configs:
                channels.append(AlertChannel.WEBHOOK)
            if AlertChannel.SLACK in self._channel_configs:
                channels.append(AlertChannel.SLACK)
            if AlertChannel.TEAMS in self._channel_configs:
                channels.append(AlertChannel.TEAMS)

        if severity.value >= AlertSeverity.HIGH.value:
            if AlertChannel.EMAIL in self._channel_configs:
                channels.append(AlertChannel.EMAIL)
            if AlertChannel.TELEGRAM in self._channel_configs:
                channels.append(AlertChannel.TELEGRAM)

        if severity == AlertSeverity.CRITICAL:
            # Kritik icin tum yapilanmis kanallar
            for ch in self._channel_configs:
                if ch not in channels:
                    channels.append(ch)

        return channels

    def suppress_alerts(
        self,
        category: Optional[str] = None,
        source: Optional[str] = None,
        duration_minutes: int = 30
    ):
        """
        Alarm Bastirma

        Belirli kategori/kaynak icin gecici alarm bastirma.

        Args:
            category: Bastirilacak kategori
            source: Bastirilacak kaynak
            duration_minutes: Bastirma suresi (dakika)
        """
        agg_key = self._get_aggregation_key(category or '*', source)
        suppression_until = datetime.now() + timedelta(minutes=duration_minutes)

        if agg_key in self._aggregators:
            self._aggregators[agg_key].is_suppressed = True
            self._aggregators[agg_key].suppression_until = suppression_until
        else:
            self._aggregators[agg_key] = AlertAggregator(
                aggregation_key=agg_key,
                alerts=[],
                event_count=0,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                severity=AlertSeverity.INFO,
                is_suppressed=True,
                suppression_until=suppression_until
            )

        logger.info(
            f"[Alert Manager] Alarm bastirildi: {agg_key}, "
            f"Sure: {duration_minutes} dakika"
        )

    def get_alert(self, alert_id: str) -> Optional[WirelessAlert]:
        """Alarm ID ile alarm getir"""
        return self._alerts.get(alert_id)

    def get_alerts(
        self,
        severity: Optional[AlertSeverity] = None,
        category: Optional[str] = None,
        status: Optional[AlertStatus] = None,
        limit: int = 100
    ) -> List[WirelessAlert]:
        """Alarmlari filtrele ve getir"""
        alerts = list(self._alerts.values())

        if severity:
            alerts = [a for a in alerts if a.severity.value >= severity.value]

        if category:
            alerts = [a for a in alerts if a.category == category]

        if status:
            alerts = [a for a in alerts if a.status == status]

        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

    def update_alert_status(
        self,
        alert_id: str,
        status: AlertStatus,
        assigned_to: Optional[str] = None,
        note: Optional[str] = None,
        resolution: Optional[str] = None
    ) -> bool:
        """Alarm durumunu guncelle"""
        if alert_id not in self._alerts:
            return False

        alert = self._alerts[alert_id]
        alert.status = status

        if assigned_to:
            alert.assigned_to = assigned_to

        if note:
            alert.notes.append(f"[{datetime.now().isoformat()}] {note}")

        if resolution:
            alert.resolution = resolution

        logger.info(f"[Alert Manager] Alarm durumu guncellendi: {alert_id} -> {status.value}")
        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Istatistikleri getir"""
        return {
            'total_alerts': self._stats['total_alerts'],
            'alerts_by_severity': dict(self._stats['alerts_by_severity']),
            'alerts_by_category': dict(self._stats['alerts_by_category']),
            'notifications_sent': dict(self._stats['notifications_sent']),
            'deduplicated': self._stats['deduplicated'],
            'aggregated': self._stats['aggregated'],
            'active_aggregators': len(self._aggregators),
            'configured_channels': [ch.value for ch in self._channel_configs]
        }
