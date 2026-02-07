#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI BILDIRIM DAEMON v1.0
    Gercek Zamanli Tehdit Bildirimi Servisi
================================================================================

    Ozellikler:
    - TSUNAMI loglarini ve BEYIN alarmlarini izler
    - Masaustu bildirimleri gonderir
    - Kritik alarmlar icin sesli uyari
    - Tiklama aksiyonlari destekler
    - Tehdit seviyesi ikonlari

    Kullanim:
        python3 tsunami_notify.py start   # Daemon baslat
        python3 tsunami_notify.py stop    # Daemon durdur
        python3 tsunami_notify.py status  # Durum goster
        python3 tsunami_notify.py test    # Test bildirimi

================================================================================
"""

import gi
gi.require_version('Notify', '0.7')
gi.require_version('Gtk', '4.0')

from gi.repository import Notify, GLib, Gio
import os
import sys
import json
import time
import signal
import sqlite3
import logging
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import hashlib

# Daemon icin
try:
    import daemon
    from daemon import pidfile
    DAEMON_AVAILABLE = True
except ImportError:
    DAEMON_AVAILABLE = False

# ============================================================================
# YAPILANDIRMA
# ============================================================================

TSUNAMI_HOME = Path("/home/lydian/Desktop/TSUNAMI")
TSUNAMI_DB = TSUNAMI_HOME / "tsunami.db"
TSUNAMI_CONFIG = TSUNAMI_HOME / "tsunami_config.json"
NOTIFY_CONFIG = TSUNAMI_HOME / "notify_config.json"
PID_FILE = Path("/tmp/tsunami_notify.pid")
LOG_FILE = TSUNAMI_HOME / "logs" / "notify_daemon.log"

# Loglama ayarla
TSUNAMI_HOME.joinpath("logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("TsunamiNotify")


# ============================================================================
# ENUM VE DATACLASS
# ============================================================================

class TehditSeviyesi(Enum):
    """Tehdit seviyeleri"""
    KRITIK = "kritik"
    YUKSEK = "yuksek"
    ORTA = "orta"
    DUSUK = "dusuk"
    BILGI = "bilgi"


class BildirimOnceligi(Enum):
    """Bildirim oncelik seviyeleri"""
    ACIL = "acil"       # Ekrani kaplasin, sesli uyari
    YUKSEK = "yuksek"   # Normal bildirim + ses
    NORMAL = "normal"   # Normal bildirim
    DUSUK = "dusuk"     # Sessiz bildirim


@dataclass
class BildirimOlayi:
    """Bildirim olayi veri yapisi"""
    id: str
    baslik: str
    mesaj: str
    seviye: TehditSeviyesi
    oncelik: BildirimOnceligi
    zaman: datetime = field(default_factory=datetime.now)
    kaynak: str = "TSUNAMI"
    ip_adresi: Optional[str] = None
    aksiyon_url: Optional[str] = None
    gosterildi: bool = False


@dataclass
class BildirimAyarlari:
    """Bildirim ayarlari"""
    aktif: bool = True
    ses_aktif: bool = True
    kritik_ses_dosyasi: str = "/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"
    uyari_ses_dosyasi: str = "/usr/share/sounds/freedesktop/stereo/bell.oga"
    bildirim_suresi: int = 10000  # milisaniye
    min_seviye: TehditSeviyesi = TehditSeviyesi.DUSUK
    izleme_araligi: int = 5  # saniye


# ============================================================================
# SES YONETIMI
# ============================================================================

class SesYoneticisi:
    """Sesli uyari yoneticisi"""

    def __init__(self, ayarlar: BildirimAyarlari):
        self.ayarlar = ayarlar
        self._muted = False

    def ses_cal(self, seviye: TehditSeviyesi):
        """Tehdit seviyesine gore ses cal"""
        if not self.ayarlar.ses_aktif or self._muted:
            return

        try:
            if seviye in [TehditSeviyesi.KRITIK, TehditSeviyesi.YUKSEK]:
                ses_dosyasi = self.ayarlar.kritik_ses_dosyasi
            else:
                ses_dosyasi = self.ayarlar.uyari_ses_dosyasi

            if Path(ses_dosyasi).exists():
                # paplay kullan (PulseAudio)
                subprocess.Popen(
                    ['paplay', ses_dosyasi],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
        except Exception as e:
            logger.error(f"Ses calma hatasi: {e}")

    def sessize_al(self, sure_saniye: int = 300):
        """Belirli sure sessiz mod"""
        self._muted = True

        def unmute():
            self._muted = False

        threading.Timer(sure_saniye, unmute).start()


# ============================================================================
# BILDIRIM YONETICISI
# ============================================================================

class BildirimYoneticisi:
    """Desktop bildirim yoneticisi"""

    def __init__(self, ayarlar: BildirimAyarlari):
        self.ayarlar = ayarlar
        self.ses = SesYoneticisi(ayarlar)
        self._son_bildirimler: deque = deque(maxlen=100)

        # Libnotify baslat
        if not Notify.is_initted():
            Notify.init("TSUNAMI Guvenlik")

    def bildirim_gonder(self, olay: BildirimOlayi) -> bool:
        """Bildirim gonder"""
        if not self.ayarlar.aktif:
            return False

        # Minimum seviye kontrolu
        seviye_sirasi = [
            TehditSeviyesi.BILGI,
            TehditSeviyesi.DUSUK,
            TehditSeviyesi.ORTA,
            TehditSeviyesi.YUKSEK,
            TehditSeviyesi.KRITIK
        ]

        if seviye_sirasi.index(olay.seviye) < seviye_sirasi.index(self.ayarlar.min_seviye):
            return False

        # Tekrar kontrolu
        for son in self._son_bildirimler:
            if son.baslik == olay.baslik and son.mesaj == olay.mesaj:
                if (datetime.now() - son.zaman).total_seconds() < 60:
                    return False

        try:
            # Ikon sec
            ikon = self._seviye_ikon(olay.seviye)

            # Bildirim olustur
            notification = Notify.Notification.new(
                olay.baslik,
                olay.mesaj,
                ikon
            )

            # Oncelik ayarla
            if olay.oncelik == BildirimOnceligi.ACIL:
                notification.set_urgency(Notify.Urgency.CRITICAL)
            elif olay.oncelik == BildirimOnceligi.YUKSEK:
                notification.set_urgency(Notify.Urgency.NORMAL)
            else:
                notification.set_urgency(Notify.Urgency.LOW)

            # Timeout
            notification.set_timeout(self.ayarlar.bildirim_suresi)

            # Aksiyon ekle
            if olay.ip_adresi:
                notification.add_action(
                    "ip_engelle",
                    f"IP Engelle ({olay.ip_adresi})",
                    self._aksiyon_callback,
                    olay.ip_adresi
                )

            notification.add_action(
                "dashboard_ac",
                "Dashboard Ac",
                self._aksiyon_callback,
                "dashboard"
            )

            # Goster
            notification.show()

            # Ses cal
            self.ses.ses_cal(olay.seviye)

            # Kaydet
            olay.gosterildi = True
            self._son_bildirimler.append(olay)

            logger.info(f"Bildirim gonderildi: {olay.baslik}")
            return True

        except Exception as e:
            logger.error(f"Bildirim gonderme hatasi: {e}")
            return False

    def _seviye_ikon(self, seviye: TehditSeviyesi) -> str:
        """Seviyeye gore ikon sec"""
        ikonlar = {
            TehditSeviyesi.KRITIK: "dialog-error",
            TehditSeviyesi.YUKSEK: "dialog-warning",
            TehditSeviyesi.ORTA: "dialog-information",
            TehditSeviyesi.DUSUK: "dialog-information",
            TehditSeviyesi.BILGI: "dialog-information"
        }
        return ikonlar.get(seviye, "dialog-information")

    def _aksiyon_callback(self, notification, action, data):
        """Bildirim aksiyonu callback"""
        logger.info(f"Aksiyon: {action}, Data: {data}")

        if action == "ip_engelle" and data:
            try:
                subprocess.run(
                    ['sudo', 'ufw', 'deny', 'from', data],
                    capture_output=True, timeout=30
                )
                self.bildirim_gonder(BildirimOlayi(
                    id=hashlib.md5(f"engel_{data}".encode()).hexdigest()[:8],
                    baslik="IP Engellendi",
                    mesaj=f"{data} adresi engellendi",
                    seviye=TehditSeviyesi.BILGI,
                    oncelik=BildirimOnceligi.NORMAL
                ))
            except Exception as e:
                logger.error(f"IP engelleme hatasi: {e}")

        elif action == "dashboard_ac":
            try:
                subprocess.Popen(
                    ['python3', str(TSUNAMI_HOME / 'tsunami_dashboard.py')],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as e:
                logger.error(f"Dashboard acma hatasi: {e}")

    def kapat(self):
        """Temizlik"""
        if Notify.is_initted():
            Notify.uninit()


# ============================================================================
# LOG IZLEYICI
# ============================================================================

class LogIzleyici:
    """TSUNAMI log dosyalarini izler"""

    def __init__(self, bildirim: BildirimYoneticisi):
        self.bildirim = bildirim
        self._izlenen_dosyalar: Dict[Path, int] = {}
        self._calisma = False

    def dosya_ekle(self, dosya: Path):
        """Izlenecek dosya ekle"""
        if dosya.exists():
            self._izlenen_dosyalar[dosya] = dosya.stat().st_size

    def izle(self):
        """Log dosyalarini izle"""
        for dosya, son_boyut in list(self._izlenen_dosyalar.items()):
            if not dosya.exists():
                continue

            mevcut_boyut = dosya.stat().st_size
            if mevcut_boyut > son_boyut:
                # Yeni satir eklenmis
                try:
                    with open(dosya, 'r') as f:
                        f.seek(son_boyut)
                        yeni_satirlar = f.readlines()

                    for satir in yeni_satirlar:
                        self._satir_isle(satir.strip(), dosya.name)

                    self._izlenen_dosyalar[dosya] = mevcut_boyut
                except Exception as e:
                    logger.error(f"Log okuma hatasi ({dosya}): {e}")

    def _satir_isle(self, satir: str, kaynak: str):
        """Log satirini isle ve gerekirse bildirim gonder"""
        if not satir:
            return

        satir_lower = satir.lower()

        # Tehdit tespiti
        tehdit_kaliplari = {
            TehditSeviyesi.KRITIK: [
                'critical', 'kritik', 'saldiri', 'attack', 'breach', 'intrusion',
                'defcon 1', 'defcon_1', 'compromise', 'rootkit', 'backdoor'
            ],
            TehditSeviyesi.YUKSEK: [
                'high', 'yuksek', 'alert', 'alarm', 'warning', 'uyari',
                'defcon 2', 'defcon_2', 'suspicious', 'supheli', 'malware'
            ],
            TehditSeviyesi.ORTA: [
                'medium', 'orta', 'notice', 'bildirim', 'defcon 3', 'defcon_3',
                'anomaly', 'anormal', 'unusual'
            ],
            TehditSeviyesi.DUSUK: [
                'low', 'dusuk', 'info', 'bilgi', 'defcon 4', 'defcon_4'
            ]
        }

        tespit_edilen_seviye = None
        for seviye, kaliplar in tehdit_kaliplari.items():
            for kalip in kaliplar:
                if kalip in satir_lower:
                    tespit_edilen_seviye = seviye
                    break
            if tespit_edilen_seviye:
                break

        if tespit_edilen_seviye:
            # IP adresi cikar
            import re
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', satir)
            ip_adresi = ip_match.group() if ip_match else None

            # Oncelik belirle
            oncelik = BildirimOnceligi.NORMAL
            if tespit_edilen_seviye == TehditSeviyesi.KRITIK:
                oncelik = BildirimOnceligi.ACIL
            elif tespit_edilen_seviye == TehditSeviyesi.YUKSEK:
                oncelik = BildirimOnceligi.YUKSEK

            olay = BildirimOlayi(
                id=hashlib.md5(satir.encode()).hexdigest()[:8],
                baslik=f"TSUNAMI {tespit_edilen_seviye.value.upper()}",
                mesaj=satir[:200],
                seviye=tespit_edilen_seviye,
                oncelik=oncelik,
                kaynak=kaynak,
                ip_adresi=ip_adresi
            )

            self.bildirim.bildirim_gonder(olay)


# ============================================================================
# VERITABANI IZLEYICI
# ============================================================================

class VeritabaniIzleyici:
    """TSUNAMI veritabanini izler"""

    def __init__(self, bildirim: BildirimYoneticisi):
        self.bildirim = bildirim
        self._son_kontrol = datetime.now()
        self._islenen_idler: set = set()

    def izle(self):
        """Veritabanindaki yeni tehditler icin kontrol"""
        if not TSUNAMI_DB.exists():
            return

        try:
            conn = sqlite3.connect(TSUNAMI_DB)
            cursor = conn.cursor()

            # Son kontrol zamanindan sonraki tehditler
            cursor.execute("""
                SELECT id, timestamp, source, type, severity, description, ip_address
                FROM threats
                WHERE timestamp > ?
                ORDER BY timestamp DESC
                LIMIT 10
            """, (self._son_kontrol.isoformat(),))

            rows = cursor.fetchall()
            conn.close()

            for row in rows:
                tehdit_id = row[0]
                if tehdit_id in self._islenen_idler:
                    continue

                seviye = self._seviye_cevir(row[4])
                oncelik = BildirimOnceligi.NORMAL
                if seviye == TehditSeviyesi.KRITIK:
                    oncelik = BildirimOnceligi.ACIL
                elif seviye == TehditSeviyesi.YUKSEK:
                    oncelik = BildirimOnceligi.YUKSEK

                olay = BildirimOlayi(
                    id=tehdit_id,
                    baslik=f"{row[3]} - {row[2]}",
                    mesaj=row[5][:200] if row[5] else "Tehdit tespit edildi",
                    seviye=seviye,
                    oncelik=oncelik,
                    kaynak=row[2],
                    ip_adresi=row[6]
                )

                if self.bildirim.bildirim_gonder(olay):
                    self._islenen_idler.add(tehdit_id)

            self._son_kontrol = datetime.now()

            # Islenen ID'leri temizle (son 1000)
            if len(self._islenen_idler) > 1000:
                self._islenen_idler = set(list(self._islenen_idler)[-500:])

        except sqlite3.OperationalError as e:
            # Tablo yoksa normal, sessizce gec
            if "no such table" not in str(e):
                logger.error(f"Veritabani hatasi: {e}")
        except Exception as e:
            logger.error(f"Veritabani izleme hatasi: {e}")

    def _seviye_cevir(self, seviye_str: str) -> TehditSeviyesi:
        """String seviyeyi enum'a cevir"""
        seviye_map = {
            'critical': TehditSeviyesi.KRITIK,
            'kritik': TehditSeviyesi.KRITIK,
            'high': TehditSeviyesi.YUKSEK,
            'yuksek': TehditSeviyesi.YUKSEK,
            'medium': TehditSeviyesi.ORTA,
            'orta': TehditSeviyesi.ORTA,
            'low': TehditSeviyesi.DUSUK,
            'dusuk': TehditSeviyesi.DUSUK,
            'info': TehditSeviyesi.BILGI,
            'bilgi': TehditSeviyesi.BILGI
        }
        return seviye_map.get(str(seviye_str).lower(), TehditSeviyesi.BILGI)


# ============================================================================
# BEYIN IZLEYICI
# ============================================================================

class BeyinIzleyici:
    """BEYIN modulu mesajlarini izler"""

    def __init__(self, bildirim: BildirimYoneticisi):
        self.bildirim = bildirim
        self._son_defcon = 5

    def izle(self):
        """BEYIN durumunu kontrol et"""
        if not TSUNAMI_DB.exists():
            return

        try:
            conn = sqlite3.connect(TSUNAMI_DB)
            cursor = conn.cursor()

            # DEFCON seviyesi
            cursor.execute("""
                SELECT value FROM system_state WHERE key = 'defcon_level'
            """)
            row = cursor.fetchone()

            if row:
                yeni_defcon = int(row[0])
                if yeni_defcon < self._son_defcon:
                    # DEFCON yükseldi (sayi duserse tehdit artar)
                    seviye = TehditSeviyesi.KRITIK if yeni_defcon <= 2 else TehditSeviyesi.YUKSEK
                    oncelik = BildirimOnceligi.ACIL if yeni_defcon == 1 else BildirimOnceligi.YUKSEK

                    olay = BildirimOlayi(
                        id=f"defcon_{yeni_defcon}_{int(time.time())}",
                        baslik=f"DEFCON {yeni_defcon} ALARMI",
                        mesaj=f"Tehdit seviyesi DEFCON {yeni_defcon}'e yukseldi! Acil mudahale gerekebilir.",
                        seviye=seviye,
                        oncelik=oncelik,
                        kaynak="BEYIN"
                    )
                    self.bildirim.bildirim_gonder(olay)

                self._son_defcon = yeni_defcon

            conn.close()

        except sqlite3.OperationalError:
            pass
        except Exception as e:
            logger.error(f"BEYIN izleme hatasi: {e}")


# ============================================================================
# ANA DAEMON
# ============================================================================

class TsunamiBildirimDaemon:
    """Ana bildirim daemon'u"""

    def __init__(self):
        self._calisma = False
        self._ayarlar = self._ayarlari_yukle()
        self._bildirim = BildirimYoneticisi(self._ayarlar)
        self._log_izleyici = LogIzleyici(self._bildirim)
        self._db_izleyici = VeritabaniIzleyici(self._bildirim)
        self._beyin_izleyici = BeyinIzleyici(self._bildirim)

        # Log dosyalarini ekle
        log_dizini = TSUNAMI_HOME / "logs"
        if log_dizini.exists():
            for log_dosya in log_dizini.glob("*.log"):
                self._log_izleyici.dosya_ekle(log_dosya)

        # Denetim logu
        denetim_log = TSUNAMI_HOME / "dalga_denetim.log"
        if denetim_log.exists():
            self._log_izleyici.dosya_ekle(denetim_log)

    def _ayarlari_yukle(self) -> BildirimAyarlari:
        """Ayarlari dosyadan yukle"""
        ayarlar = BildirimAyarlari()

        try:
            if NOTIFY_CONFIG.exists():
                with open(NOTIFY_CONFIG) as f:
                    data = json.load(f)
                    ayarlar.aktif = data.get('aktif', True)
                    ayarlar.ses_aktif = data.get('ses_aktif', True)
                    ayarlar.izleme_araligi = data.get('izleme_araligi', 5)
        except Exception as e:
            logger.warning(f"Ayar yukleme hatasi, varsayilan kullaniliyor: {e}")

        return ayarlar

    def baslat(self):
        """Daemon'u baslat"""
        self._calisma = True
        logger.info("TSUNAMI Bildirim Daemon baslatildi")

        # Baslangic bildirimi
        self._bildirim.bildirim_gonder(BildirimOlayi(
            id="startup",
            baslik="TSUNAMI Guvenlik",
            mesaj="Bildirim servisi baslatildi. Sistem izleniyor...",
            seviye=TehditSeviyesi.BILGI,
            oncelik=BildirimOnceligi.DUSUK
        ))

        # Ana dongu
        while self._calisma:
            try:
                # Log dosyalarini izle
                self._log_izleyici.izle()

                # Veritabanini izle
                self._db_izleyici.izle()

                # BEYIN'i izle
                self._beyin_izleyici.izle()

                # Bekle
                time.sleep(self._ayarlar.izleme_araligi)

            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Izleme hatasi: {e}")
                time.sleep(10)

        self.durdur()

    def durdur(self):
        """Daemon'u durdur"""
        self._calisma = False
        self._bildirim.kapat()
        logger.info("TSUNAMI Bildirim Daemon durduruldu")

    def durum(self) -> Dict[str, Any]:
        """Daemon durumu"""
        return {
            'calisma': self._calisma,
            'ayarlar': {
                'aktif': self._ayarlar.aktif,
                'ses_aktif': self._ayarlar.ses_aktif,
                'izleme_araligi': self._ayarlar.izleme_araligi
            },
            'izlenen_loglar': len(self._log_izleyici._izlenen_dosyalar)
        }


# ============================================================================
# SINYAL ISLEYICILERI
# ============================================================================

daemon_instance: Optional[TsunamiBildirimDaemon] = None


def sinyal_isle(signum, frame):
    """Sinyal isleyici"""
    global daemon_instance
    logger.info(f"Sinyal alindi: {signum}")
    if daemon_instance:
        daemon_instance.durdur()
    sys.exit(0)


# ============================================================================
# CLI KOMUTLARI
# ============================================================================

def daemon_baslat():
    """Daemon'u baslat"""
    global daemon_instance

    # PID kontrolu
    if PID_FILE.exists():
        try:
            with open(PID_FILE) as f:
                pid = int(f.read().strip())
            # Proses calisiyorsa
            os.kill(pid, 0)
            print(f"Daemon zaten calisiyor (PID: {pid})")
            return
        except (ProcessLookupError, ValueError):
            # Proses olmus veya gecersiz PID
            PID_FILE.unlink()

    # PID kaydet
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))

    # Sinyal isleyicileri
    signal.signal(signal.SIGTERM, sinyal_isle)
    signal.signal(signal.SIGINT, sinyal_isle)

    try:
        daemon_instance = TsunamiBildirimDaemon()
        daemon_instance.baslat()
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink()


def daemon_durdur():
    """Daemon'u durdur"""
    if not PID_FILE.exists():
        print("Daemon calismiyior")
        return

    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"Daemon durduruldu (PID: {pid})")
    except (ProcessLookupError, ValueError):
        print("Daemon bulunamadi")
    finally:
        if PID_FILE.exists():
            PID_FILE.unlink()


def daemon_durum():
    """Daemon durumunu goster"""
    if not PID_FILE.exists():
        print("Durum: DURMUS")
        return

    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        print(f"Durum: CALISIYOR (PID: {pid})")
    except (ProcessLookupError, ValueError):
        print("Durum: DURMUS (eski PID dosyasi var)")
        PID_FILE.unlink()


def test_bildirimi():
    """Test bildirimi gonder"""
    if not Notify.is_initted():
        Notify.init("TSUNAMI Guvenlik")

    ayarlar = BildirimAyarlari()
    bildirim = BildirimYoneticisi(ayarlar)

    # Farkli seviyede test bildirimleri
    test_olaylari = [
        BildirimOlayi(
            id="test_kritik",
            baslik="TEST: KRITIK ALARM",
            mesaj="Bu bir test bildirimidir. Kritik seviye tehdit simulasyonu.",
            seviye=TehditSeviyesi.KRITIK,
            oncelik=BildirimOnceligi.ACIL,
            ip_adresi="192.168.1.100"
        ),
        BildirimOlayi(
            id="test_yuksek",
            baslik="TEST: Yuksek Uyari",
            mesaj="Bu bir test bildirimidir. Yuksek seviye tehdit simulasyonu.",
            seviye=TehditSeviyesi.YUKSEK,
            oncelik=BildirimOnceligi.YUKSEK
        ),
        BildirimOlayi(
            id="test_bilgi",
            baslik="TEST: Bilgi",
            mesaj="Bu bir test bildirimidir. Sistem normal calisiyior.",
            seviye=TehditSeviyesi.BILGI,
            oncelik=BildirimOnceligi.DUSUK
        )
    ]

    for olay in test_olaylari:
        bildirim.bildirim_gonder(olay)
        time.sleep(2)

    print("Test bildirimleri gonderildi")
    bildirim.kapat()


# ============================================================================
# ANA GIRIS
# ============================================================================

def main():
    """Ana giris noktasi"""
    if len(sys.argv) < 2:
        print("""
TSUNAMI Bildirim Daemon v1.0

Kullanim:
    python3 tsunami_notify.py <komut>

Komutlar:
    start   - Daemon'u baslat
    stop    - Daemon'u durdur
    status  - Durum goster
    test    - Test bildirimi gonder
    help    - Bu yardimi goster
""")
        return

    komut = sys.argv[1].lower()

    if komut == 'start':
        daemon_baslat()
    elif komut == 'stop':
        daemon_durdur()
    elif komut == 'status':
        daemon_durum()
    elif komut == 'test':
        test_bildirimi()
    elif komut == 'help':
        main()  # Yardimi goster
    else:
        print(f"Bilinmeyen komut: {komut}")
        print("'help' ile kullanim bilgisi alin")


if __name__ == "__main__":
    main()
