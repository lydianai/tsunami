"""
TSUNAMI BLE Threat Detector
===========================

Stalker/tracker cihaz tespiti ve uyari sistemi.
Beyaz sapkali guvenlik prensipleri ile tasarlanmistir.

Amac: SAVUNMA
- Kullaniciyi izleyen cihazlari tespit et
- Potansiyel tehditleri uyar
- Gizlilik korumasi sagla
"""

import logging
from enum import Enum
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, field
from collections import defaultdict

from .ble_scanner import BLEDevice
from .device_fingerprint import DeviceFingerprint, CihazTipi, fingerprinter_al

logger = logging.getLogger(__name__)


class TehditSeviyesi(Enum):
    """Tehdit seviyeleri"""
    YOK = 0
    DUSUK = 1
    ORTA = 2
    YUKSEK = 3
    KRITIK = 4


@dataclass
class TehditUyari:
    """Tehdit uyari yapisi"""
    cihaz_adres: str
    cihaz_isim: Optional[str]
    cihaz_tipi: CihazTipi
    seviye: TehditSeviyesi
    aciklama: str
    olusturma_zamani: datetime = field(default_factory=datetime.now)
    aktif: bool = True

    # Analiz detaylari
    takip_suresi: Optional[float] = None  # dakika
    gorulme_sayisi: int = 0
    mesafe_ortalama: Optional[float] = None

    def to_dict(self) -> Dict:
        return {
            'adres': self.cihaz_adres,
            'isim': self.cihaz_isim or 'Isimsiz',
            'tip': self.cihaz_tipi.value,
            'seviye': self.seviye.name,
            'seviye_deger': self.seviye.value,
            'aciklama': self.aciklama,
            'zaman': self.olusturma_zamani.isoformat(),
            'aktif': self.aktif,
            'takip_suresi_dk': self.takip_suresi,
            'gorulme': self.gorulme_sayisi,
            'mesafe_m': self.mesafe_ortalama
        }


class ThreatDetector:
    """
    BLE Tehdit Dedektoru

    Potansiyel takip cihazlarini tespit eder.
    Uzun sure yakininda kalan cihazlari uyarir.
    """

    # Esik degerleri
    TAKIP_ESIK_DAKIKA = 10  # 10 dakikadan fazla gorulen cihaz
    YAKIN_MESAFE_METRE = 5  # 5 metreden yakin cihaz
    GORULME_ESIK = 5  # En az 5 kez gorulen cihaz

    # Potansiyel tehdit tipler
    TEHDIT_TIPLER = {
        CihazTipi.APPLE_AIRTAG,
        CihazTipi.APPLE_FINDMY,
        CihazTipi.SAMSUNG_SMARTTAG,
        CihazTipi.TILE_TRACKER,
        CihazTipi.GENEL_TRACKER,
    }

    def __init__(self):
        self.uyarilar: Dict[str, TehditUyari] = {}  # adres -> uyari
        self.cihaz_gecmisi: Dict[str, List[datetime]] = defaultdict(list)
        self.fingerprinter = fingerprinter_al()

        # Callback (yeni tehdit bildirim)
        self.tehdit_callback: Optional[Callable[[TehditUyari], None]] = None

    def analiz_et(self, cihaz: BLEDevice) -> Optional[TehditUyari]:
        """
        Cihazi tehdit acisindan analiz et

        Args:
            cihaz: BLEDevice nesnesi

        Returns:
            TehditUyari (tehdit varsa) veya None
        """
        # Parmak izi al
        parmak_izi = self.fingerprinter.tanimla(
            adres=cihaz.adres,
            isim=cihaz.isim,
            manufacturer_data=cihaz.manufacturer_data,
            service_uuids=cihaz.service_uuids
        )

        # Gecmise kaydet
        self.cihaz_gecmisi[cihaz.adres].append(datetime.now())

        # Tehdit skoru hesapla
        skor, aciklama = self._tehdit_skoru_hesapla(cihaz, parmak_izi)
        cihaz.tehdit_skoru = skor
        cihaz.cihaz_tipi = parmak_izi.tip.value

        # Esik kontrolu
        if skor >= 50:  # %50+ tehdit skoru
            seviye = self._skor_seviye(skor)
            uyari = self._uyari_olustur(cihaz, parmak_izi, seviye, aciklama)

            # Callback cagir
            if self.tehdit_callback and cihaz.adres not in self.uyarilar:
                self.tehdit_callback(uyari)

            self.uyarilar[cihaz.adres] = uyari
            return uyari

        return None

    def _tehdit_skoru_hesapla(self, cihaz: BLEDevice,
                              parmak_izi: 'ParmakIzi') -> tuple[int, str]:
        """
        Tehdit skoru hesapla (0-100)

        Faktorler:
        - Cihaz tipi (tracker = +40)
        - Takip suresi (+20 max)
        - Yakinlik (+20 max)
        - Gorulme sikligi (+20 max)
        """
        skor = 0
        aciklamalar = []

        # 1. Cihaz tipi kontrolu
        if parmak_izi.tip in self.TEHDIT_TIPLER:
            skor += 40
            aciklamalar.append(f"Bilinen takip cihazi: {parmak_izi.tip.value}")

        elif parmak_izi.potansiyel_tehdit:
            skor += 25
            aciklamalar.append("Potansiyel takip cihazi")

        # 2. Takip suresi
        gecmis = self.cihaz_gecmisi.get(cihaz.adres, [])
        if len(gecmis) >= 2:
            ilk_gorulme = gecmis[0]
            son_gorulme = gecmis[-1]
            sure_dakika = (son_gorulme - ilk_gorulme).total_seconds() / 60

            if sure_dakika >= self.TAKIP_ESIK_DAKIKA:
                puan = min(20, int(sure_dakika / self.TAKIP_ESIK_DAKIKA * 20))
                skor += puan
                aciklamalar.append(f"{sure_dakika:.0f} dakikadir takip ediyor")

        # 3. Yakinlik
        if cihaz.tahmini_mesafe:
            if cihaz.tahmini_mesafe <= self.YAKIN_MESAFE_METRE:
                puan = min(20, int((self.YAKIN_MESAFE_METRE - cihaz.tahmini_mesafe) * 4))
                skor += puan
                aciklamalar.append(f"Cok yakin: {cihaz.tahmini_mesafe:.1f}m")

        # 4. Gorulme sikligi
        if cihaz.gorulme_sayisi >= self.GORULME_ESIK:
            puan = min(20, cihaz.gorulme_sayisi - self.GORULME_ESIK + 5)
            skor += puan
            aciklamalar.append(f"{cihaz.gorulme_sayisi} kez goruldu")

        # 5. Bilinmeyen cihaz bonusu
        if not cihaz.isim or cihaz.isim.lower() in ['unknown', 'bilinmeyen', '']:
            skor += 5
            aciklamalar.append("Isimsiz cihaz")

        return min(100, skor), " | ".join(aciklamalar) if aciklamalar else "Tehdit yok"

    def _skor_seviye(self, skor: int) -> TehditSeviyesi:
        """Skoru seviyeye cevir"""
        if skor >= 80:
            return TehditSeviyesi.KRITIK
        elif skor >= 60:
            return TehditSeviyesi.YUKSEK
        elif skor >= 40:
            return TehditSeviyesi.ORTA
        elif skor >= 20:
            return TehditSeviyesi.DUSUK
        return TehditSeviyesi.YOK

    def _uyari_olustur(self, cihaz: BLEDevice, parmak_izi: 'ParmakIzi',
                       seviye: TehditSeviyesi, aciklama: str) -> TehditUyari:
        """Tehdit uyarisi olustur"""
        gecmis = self.cihaz_gecmisi.get(cihaz.adres, [])
        takip_suresi = None
        if len(gecmis) >= 2:
            takip_suresi = (gecmis[-1] - gecmis[0]).total_seconds() / 60

        return TehditUyari(
            cihaz_adres=cihaz.adres,
            cihaz_isim=cihaz.isim,
            cihaz_tipi=parmak_izi.tip,
            seviye=seviye,
            aciklama=aciklama,
            takip_suresi=takip_suresi,
            gorulme_sayisi=cihaz.gorulme_sayisi,
            mesafe_ortalama=cihaz.tahmini_mesafe
        )

    def aktif_tehditler(self) -> List[Dict]:
        """Aktif tehditleri dondur"""
        return [
            uyari.to_dict()
            for uyari in self.uyarilar.values()
            if uyari.aktif
        ]

    def tehdit_sayisi(self) -> Dict[str, int]:
        """Seviyeye gore tehdit sayilari"""
        sayilar = {seviye.name: 0 for seviye in TehditSeviyesi}
        for uyari in self.uyarilar.values():
            if uyari.aktif:
                sayilar[uyari.seviye.name] += 1
        return sayilar

    def uyari_kapat(self, adres: str):
        """Uyariyi kapat"""
        if adres in self.uyarilar:
            self.uyarilar[adres].aktif = False
            logger.info(f"Uyari kapatildi: {adres}")

    def tum_uyarilari_temizle(self):
        """Tum uyarilari temizle"""
        self.uyarilar.clear()
        self.cihaz_gecmisi.clear()
        logger.info("Tum tehdit uyarilari temizlendi")

    def istatistik_al(self) -> Dict:
        """Tehdit istatistikleri"""
        return {
            'toplam_uyari': len(self.uyarilar),
            'aktif_uyari': sum(1 for u in self.uyarilar.values() if u.aktif),
            'seviye_dagilimi': self.tehdit_sayisi(),
            'izlenen_cihaz': len(self.cihaz_gecmisi),
        }


# Global instance
_detector: Optional[ThreatDetector] = None


def detector_al() -> ThreatDetector:
    """Global detector instance"""
    global _detector
    if _detector is None:
        _detector = ThreatDetector()
    return _detector
