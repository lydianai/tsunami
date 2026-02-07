"""
TSUNAMI BLE Device Fingerprinting
=================================

BLE cihaz tipi tespiti ve parmak izi eslestirme.
MetaRadar'dan ilham alinarak gelistirilmistir.

Desteklenen Cihaz Tipleri:
- Apple AirTag, FindMy
- Samsung SmartTag
- Tile tracker
- Beacon'lar (iBeacon, Eddystone)
- Fitness cihazlari
- Kulakliklar/Hoparlor
- Akilli saatler
- IoT cihazlar
"""

import re
import logging
from enum import Enum
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class CihazTipi(Enum):
    """BLE cihaz tipleri"""
    BILINMEYEN = "Bilinmeyen"

    # Takip cihazlari (potansiyel tehdit)
    APPLE_AIRTAG = "Apple AirTag"
    APPLE_FINDMY = "Apple FindMy"
    SAMSUNG_SMARTTAG = "Samsung SmartTag"
    TILE_TRACKER = "Tile Tracker"
    GENEL_TRACKER = "Takip Cihazi"

    # Beacon'lar
    IBEACON = "iBeacon"
    EDDYSTONE = "Eddystone Beacon"
    ALTBEACON = "AltBeacon"

    # Tuketici elektronigi
    KULAKLIK = "Kulaklik/Hoparlor"
    AKILLI_SAAT = "Akilli Saat"
    FITNESS = "Fitness Cihazi"
    TELEFON = "Telefon"
    TABLET = "Tablet"

    # IoT
    AKILLI_EV = "Akilli Ev Cihazi"
    SENSOR = "Sensor"
    MEDIKAL = "Medikal Cihaz"

    # Uretici bazli
    APPLE = "Apple Cihaz"
    SAMSUNG = "Samsung Cihaz"
    GOOGLE = "Google Cihaz"
    XIAOMI = "Xiaomi Cihaz"
    HUAWEI = "Huawei Cihaz"


# Manufacturer Company ID'leri (Bluetooth SIG)
MANUFACTURER_IDS = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x000F: "Broadcom",
    0x00E0: "Google",
    0x0075: "Samsung",
    0x0157: "Xiaomi",
    0x027D: "Huawei",
    0x0087: "Garmin",
    0x0078: "Nike",
    0x0310: "Tile",
    0x02E1: "Polar",
    0x00D2: "Seiko",
    0x038F: "Oura",
    0x02A5: "Fitbit",
}

# Apple iBeacon UUID prefix
IBEACON_PREFIX = bytes([0x02, 0x15])

# Bilinen servis UUID'leri
KNOWN_SERVICE_UUIDS = {
    # Apple
    "0000fd6f-0000-1000-8000-00805f9b34fb": CihazTipi.APPLE_FINDMY,

    # Tile
    "0000feed-0000-1000-8000-00805f9b34fb": CihazTipi.TILE_TRACKER,

    # Fitness
    "0000180d-0000-1000-8000-00805f9b34fb": CihazTipi.FITNESS,  # Heart Rate
    "0000180f-0000-1000-8000-00805f9b34fb": CihazTipi.FITNESS,  # Battery

    # Audio
    "0000110b-0000-1000-8000-00805f9b34fb": CihazTipi.KULAKLIK,  # A2DP Sink
    "0000111e-0000-1000-8000-00805f9b34fb": CihazTipi.KULAKLIK,  # Handsfree

    # IoT
    "0000fe95-0000-1000-8000-00805f9b34fb": CihazTipi.XIAOMI,  # Xiaomi
    "0000fe9f-0000-1000-8000-00805f9b34fb": CihazTipi.GOOGLE,  # Google Fast Pair
}

# Isim kaliplari
NAME_PATTERNS = {
    CihazTipi.APPLE_AIRTAG: [r"airtag", r"found", r"findmy"],
    CihazTipi.SAMSUNG_SMARTTAG: [r"smarttag", r"galaxy\s*tag"],
    CihazTipi.TILE_TRACKER: [r"tile", r"^t\d{2}$"],
    CihazTipi.KULAKLIK: [r"airpods", r"buds", r"earbuds", r"headphone", r"jbl", r"bose", r"sony wf", r"galaxy buds"],
    CihazTipi.AKILLI_SAAT: [r"watch", r"band", r"fit", r"garmin", r"polar", r"mi band", r"galaxy watch"],
    CihazTipi.FITNESS: [r"fitness", r"sport", r"run", r"bike", r"gym"],
    CihazTipi.TELEFON: [r"iphone", r"galaxy", r"pixel", r"oneplus", r"xiaomi", r"huawei", r"redmi"],
    CihazTipi.AKILLI_EV: [r"smart", r"home", r"plug", r"bulb", r"light", r"switch", r"door", r"lock"],
}


@dataclass
class ParmakIzi:
    """Cihaz parmak izi"""
    tip: CihazTipi
    guven: float  # 0.0 - 1.0
    uretici: Optional[str] = None
    detay: Optional[str] = None
    potansiyel_tehdit: bool = False


class DeviceFingerprint:
    """
    BLE Cihaz Parmak Izi Eslestirici

    Manufacturer data, service UUID ve isim bilgilerini
    kullanarak cihaz tipini tespit eder.
    """

    # Tracker tipler (potansiyel tehdit)
    TRACKER_TIPLER = {
        CihazTipi.APPLE_AIRTAG,
        CihazTipi.APPLE_FINDMY,
        CihazTipi.SAMSUNG_SMARTTAG,
        CihazTipi.TILE_TRACKER,
        CihazTipi.GENEL_TRACKER,
    }

    def __init__(self):
        self.cache: Dict[str, ParmakIzi] = {}

    def tanimla(self, adres: str, isim: Optional[str],
                manufacturer_data: Dict[int, bytes],
                service_uuids: List[str]) -> ParmakIzi:
        """
        Cihaz tipini tanimla

        Args:
            adres: MAC adresi
            isim: Cihaz ismi
            manufacturer_data: Manufacturer specific data
            service_uuids: Reklam edilen servis UUID'leri

        Returns:
            ParmakIzi nesnesi
        """
        # Cache kontrol
        if adres in self.cache:
            return self.cache[adres]

        # Analiz baslat
        tip = CihazTipi.BILINMEYEN
        guven = 0.0
        uretici = None
        detay = None

        # 1. Manufacturer data analizi
        for company_id, data in manufacturer_data.items():
            if company_id in MANUFACTURER_IDS:
                uretici = MANUFACTURER_IDS[company_id]

                # Apple ozel analiz
                if company_id == 0x004C:  # Apple
                    tip, guven, detay = self._apple_analiz(data)
                    break

                # Samsung ozel analiz
                elif company_id == 0x0075:  # Samsung
                    tip, guven, detay = self._samsung_analiz(data, isim)
                    break

                # Tile
                elif company_id == 0x0310:  # Tile
                    tip = CihazTipi.TILE_TRACKER
                    guven = 0.95
                    detay = "Tile tracker tespit edildi"
                    break

                # Xiaomi
                elif company_id == 0x0157:
                    tip = CihazTipi.XIAOMI
                    guven = 0.8
                    break

        # 2. Service UUID analizi
        if tip == CihazTipi.BILINMEYEN and service_uuids:
            for uuid in service_uuids:
                uuid_lower = uuid.lower()
                if uuid_lower in KNOWN_SERVICE_UUIDS:
                    tip = KNOWN_SERVICE_UUIDS[uuid_lower]
                    guven = 0.7
                    break

        # 3. Isim analizi
        if tip == CihazTipi.BILINMEYEN and isim:
            tip, guven = self._isim_analiz(isim)

        # 4. MAC OUI analizi (son care)
        if tip == CihazTipi.BILINMEYEN:
            tip, guven = self._mac_analiz(adres)

        # Parmak izi olustur
        parmak_izi = ParmakIzi(
            tip=tip,
            guven=guven,
            uretici=uretici,
            detay=detay,
            potansiyel_tehdit=tip in self.TRACKER_TIPLER
        )

        # Cache'e kaydet
        self.cache[adres] = parmak_izi

        return parmak_izi

    def _apple_analiz(self, data: bytes) -> Tuple[CihazTipi, float, str]:
        """Apple cihaz analizi"""
        if len(data) < 2:
            return CihazTipi.APPLE, 0.5, None

        # AirTag/FindMy tespiti
        # Type byte 0x07 = FindMy/AirTag nearby
        # Type byte 0x12 = FindMy
        if data[0] == 0x07 or data[0] == 0x12:
            return CihazTipi.APPLE_FINDMY, 0.95, "Apple FindMy cihazi (potansiyel AirTag)"

        # Nearby detection
        if data[0] == 0x10:
            return CihazTipi.APPLE, 0.7, "Apple Nearby cihaz"

        # iBeacon
        if len(data) >= 23 and data[:2] == IBEACON_PREFIX:
            return CihazTipi.IBEACON, 0.9, "Apple iBeacon"

        return CihazTipi.APPLE, 0.6, None

    def _samsung_analiz(self, data: bytes, isim: Optional[str]) -> Tuple[CihazTipi, float, str]:
        """Samsung cihaz analizi"""
        # SmartTag pattern
        if isim and re.search(r"smarttag|galaxy\s*tag", isim, re.I):
            return CihazTipi.SAMSUNG_SMARTTAG, 0.95, "Samsung SmartTag tespit edildi"

        # Galaxy Buds
        if isim and re.search(r"buds|galaxy\s*buds", isim, re.I):
            return CihazTipi.KULAKLIK, 0.9, "Samsung Galaxy Buds"

        # Galaxy Watch
        if isim and re.search(r"watch|galaxy\s*watch", isim, re.I):
            return CihazTipi.AKILLI_SAAT, 0.9, "Samsung Galaxy Watch"

        return CihazTipi.SAMSUNG, 0.6, None

    def _isim_analiz(self, isim: str) -> Tuple[CihazTipi, float]:
        """Isim bazli analiz"""
        isim_lower = isim.lower()

        for tip, kaliplar in NAME_PATTERNS.items():
            for kalip in kaliplar:
                if re.search(kalip, isim_lower):
                    return tip, 0.7

        return CihazTipi.BILINMEYEN, 0.0

    def _mac_analiz(self, adres: str) -> Tuple[CihazTipi, float]:
        """MAC OUI analizi"""
        # Basit OUI prefix kontrolu
        # Gercek uygulamada IEEE OUI veritabani kullanilmali
        oui = adres.upper().replace(":", "")[:6]

        apple_oui = ["A4C361", "D0817A", "AC3C0B", "70CD60", "4C57CA"]
        samsung_oui = ["002567", "D0176A", "78D6F0", "94B97E", "B4EF39"]

        if oui in apple_oui:
            return CihazTipi.APPLE, 0.5
        elif oui in samsung_oui:
            return CihazTipi.SAMSUNG, 0.5

        return CihazTipi.BILINMEYEN, 0.0

    def temizle(self):
        """Cache temizle"""
        self.cache.clear()


# Global instance
_fingerprinter: Optional[DeviceFingerprint] = None


def fingerprinter_al() -> DeviceFingerprint:
    """Global fingerprinter instance"""
    global _fingerprinter
    if _fingerprinter is None:
        _fingerprinter = DeviceFingerprint()
    return _fingerprinter
