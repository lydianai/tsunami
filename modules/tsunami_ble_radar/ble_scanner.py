"""
TSUNAMI BLE Scanner
===================

Bleak kutuphanesi ile cross-platform BLE tarama.
MetaRadar'dan ilham alinmistir.

Beyaz Sapkali Prensipler:
- Sadece pasif tarama (broadcast dinleme)
- Cihazlara baglanma yok (izinsiz erisim yok)
- Tum veri yerel kalir
"""

import asyncio
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)

# Bleak import - opsiyonel
try:
    from bleak import BleakScanner
    from bleak.backends.device import BLEDevice as BleakDevice
    BLEAK_MEVCUT = True
except ImportError:
    BLEAK_MEVCUT = False
    logger.warning("Bleak yuklu degil. 'pip install bleak' ile yukleyin.")


@dataclass
class BLEDevice:
    """BLE cihaz veri yapisi"""
    adres: str  # MAC adresi
    isim: Optional[str] = None
    rssi: int = -100  # Sinyal gucu (dBm)
    ilk_gorulme: datetime = field(default_factory=datetime.now)
    son_gorulme: datetime = field(default_factory=datetime.now)
    gorulme_sayisi: int = 1

    # Ek bilgiler
    manufacturer_data: Dict[int, bytes] = field(default_factory=dict)
    service_uuids: List[str] = field(default_factory=list)
    tx_power: Optional[int] = None

    # Hesaplanan degerler
    tahmini_mesafe: Optional[float] = None  # Metre
    cihaz_tipi: str = "Bilinmeyen"
    tehdit_skoru: int = 0  # 0-100

    def guncelle(self, rssi: int, manufacturer_data: Dict = None,
                 service_uuids: List = None, tx_power: int = None):
        """Cihaz bilgilerini guncelle"""
        self.rssi = rssi
        self.son_gorulme = datetime.now()
        self.gorulme_sayisi += 1

        if manufacturer_data:
            self.manufacturer_data.update(manufacturer_data)
        if service_uuids:
            self.service_uuids = list(set(self.service_uuids + service_uuids))
        if tx_power is not None:
            self.tx_power = tx_power

        # Mesafe hesapla
        self.tahmini_mesafe = self._mesafe_hesapla()

    def _mesafe_hesapla(self) -> Optional[float]:
        """RSSI'dan tahmini mesafe hesapla"""
        if self.rssi >= 0:
            return None

        # Basit path-loss modeli
        # d = 10 ^ ((TxPower - RSSI) / (10 * n))
        # n: path-loss exponent (tipik olarak 2-4)
        tx_power = self.tx_power if self.tx_power else -59  # Varsayilan 1m'deki RSSI
        n = 2.5  # Ic mekan icin tipik deger

        mesafe = 10 ** ((tx_power - self.rssi) / (10 * n))
        return round(mesafe, 2)

    def to_dict(self) -> Dict[str, Any]:
        """Dictionary'e donustur"""
        return {
            'adres': self.adres,
            'isim': self.isim or 'Isimsiz',
            'rssi': self.rssi,
            'ilk_gorulme': self.ilk_gorulme.isoformat(),
            'son_gorulme': self.son_gorulme.isoformat(),
            'gorulme_sayisi': self.gorulme_sayisi,
            'tahmini_mesafe': self.tahmini_mesafe,
            'cihaz_tipi': self.cihaz_tipi,
            'tehdit_skoru': self.tehdit_skoru,
            'service_uuids': self.service_uuids,
            'sinyal_yuzde': self._rssi_yuzde()
        }

    def _rssi_yuzde(self) -> int:
        """RSSI'yi yuzdeye cevir"""
        # -30 dBm = %100, -100 dBm = %0
        if self.rssi >= -30:
            return 100
        elif self.rssi <= -100:
            return 0
        return int(((self.rssi + 100) / 70) * 100)


class BLEScanner:
    """
    BLE Tarayici

    Asenkron BLE cihaz taramasi yapar.
    Bulunan cihazlari izler ve analiz eder.
    """

    def __init__(self):
        self.aktif = False
        self.cihazlar: Dict[str, BLEDevice] = {}  # MAC -> BLEDevice
        self.tarama_suresi = 10.0  # saniye
        self.callback: Optional[Callable] = None

        # Istatistikler
        self.toplam_tarama = 0
        self.son_tarama: Optional[datetime] = None

    async def tara(self, sure: float = None) -> List[BLEDevice]:
        """
        BLE taramasi yap

        Args:
            sure: Tarama suresi (saniye)

        Returns:
            Bulunan cihaz listesi
        """
        if not BLEAK_MEVCUT:
            logger.error("Bleak yuklu degil!")
            return []

        sure = sure or self.tarama_suresi
        self.aktif = True
        self.toplam_tarama += 1
        self.son_tarama = datetime.now()

        try:
            logger.info(f"BLE taramasi baslatildi ({sure}s)")

            # Tarama
            devices = await BleakScanner.discover(
                timeout=sure,
                return_adv=True
            )

            # Cihazlari isle
            for device, adv_data in devices.values():
                self._cihaz_isle(device, adv_data)

            logger.info(f"BLE taramasi tamamlandi: {len(devices)} cihaz bulundu")

            return list(self.cihazlar.values())

        except Exception as e:
            logger.error(f"BLE tarama hatasi: {e}")
            return []
        finally:
            self.aktif = False

    def _cihaz_isle(self, device: 'BleakDevice', adv_data: Any):
        """Bulunan cihazi isle"""
        adres = device.address

        # Mevcut cihazi guncelle veya yeni ekle
        if adres in self.cihazlar:
            self.cihazlar[adres].guncelle(
                rssi=adv_data.rssi if adv_data else -100,
                manufacturer_data=dict(adv_data.manufacturer_data) if adv_data else {},
                service_uuids=list(adv_data.service_uuids) if adv_data else [],
                tx_power=adv_data.tx_power if adv_data else None
            )
        else:
            self.cihazlar[adres] = BLEDevice(
                adres=adres,
                isim=device.name,
                rssi=adv_data.rssi if adv_data else -100,
                manufacturer_data=dict(adv_data.manufacturer_data) if adv_data and adv_data.manufacturer_data else {},
                service_uuids=list(adv_data.service_uuids) if adv_data and adv_data.service_uuids else [],
                tx_power=adv_data.tx_power if adv_data else None
            )

        # Callback cagir
        if self.callback:
            self.callback(self.cihazlar[adres])

    async def surekli_tara(self, aralik: float = 5.0):
        """
        Surekli tarama yap

        Args:
            aralik: Taramalar arasi bekleme (saniye)
        """
        while self.aktif:
            await self.tara()
            await asyncio.sleep(aralik)

    def durdur(self):
        """Taramayi durdur"""
        self.aktif = False
        logger.info("BLE taramasi durduruldu")

    def cihaz_listesi(self, filtre: str = None) -> List[Dict]:
        """
        Cihaz listesini dondur

        Args:
            filtre: Isim/adres filtresi

        Returns:
            Cihaz listesi (dict)
        """
        cihazlar = list(self.cihazlar.values())

        # Filtre uygula
        if filtre:
            filtre_lower = filtre.lower()
            cihazlar = [
                c for c in cihazlar
                if (c.isim and filtre_lower in c.isim.lower()) or
                   filtre_lower in c.adres.lower()
            ]

        # RSSI'ya gore sirala (guclu sinyal once)
        cihazlar.sort(key=lambda x: x.rssi, reverse=True)

        return [c.to_dict() for c in cihazlar]

    def cihaz_al(self, adres: str) -> Optional[Dict]:
        """Belirli bir cihazin bilgilerini al"""
        cihaz = self.cihazlar.get(adres)
        return cihaz.to_dict() if cihaz else None

    def istatistik_al(self) -> Dict[str, Any]:
        """Tarama istatistiklerini dondur"""
        return {
            'toplam_cihaz': len(self.cihazlar),
            'toplam_tarama': self.toplam_tarama,
            'son_tarama': self.son_tarama.isoformat() if self.son_tarama else None,
            'aktif': self.aktif,
            'rssi_ortalama': self._rssi_ortalama(),
            'cihaz_tipleri': self._tip_dagilimi()
        }

    def _rssi_ortalama(self) -> float:
        """Ortalama RSSI hesapla"""
        if not self.cihazlar:
            return -100
        return sum(c.rssi for c in self.cihazlar.values()) / len(self.cihazlar)

    def _tip_dagilimi(self) -> Dict[str, int]:
        """Cihaz tipi dagilimi"""
        dagilim = defaultdict(int)
        for cihaz in self.cihazlar.values():
            dagilim[cihaz.cihaz_tipi] += 1
        return dict(dagilim)

    def temizle(self, eski_saniye: int = 300):
        """Eski cihazlari temizle"""
        simdi = datetime.now()
        eski_cihazlar = [
            adres for adres, cihaz in self.cihazlar.items()
            if (simdi - cihaz.son_gorulme).total_seconds() > eski_saniye
        ]

        for adres in eski_cihazlar:
            del self.cihazlar[adres]

        logger.info(f"{len(eski_cihazlar)} eski cihaz temizlendi")


# Senkron wrapper (Flask icin)
def ble_tara_senkron(sure: float = 10.0) -> List[Dict]:
    """Senkron BLE tarama (Flask route'lar icin)"""
    scanner = BLEScanner()

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cihazlar = loop.run_until_complete(scanner.tara(sure))
        return [c.to_dict() for c in cihazlar]
    except Exception as e:
        logger.error(f"Senkron BLE tarama hatasi: {e}")
        return []
    finally:
        loop.close()


# Global scanner instance
_scanner: Optional[BLEScanner] = None


def scanner_al() -> BLEScanner:
    """Global scanner instance dondur"""
    global _scanner
    if _scanner is None:
        _scanner = BLEScanner()
    return _scanner
