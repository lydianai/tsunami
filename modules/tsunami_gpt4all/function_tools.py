"""
TSUNAMI AI Asistan - Fonksiyon Araclari
=======================================

Harita ve SIGINT kontrolu icin AI'nin kullanabilecegi fonksiyonlar.
Beyaz sapkali guvenlik prensipleri ile tasarlanmistir.
"""

import re
import json
import logging
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class KomutTipi(Enum):
    """Komut kategorileri"""
    HARITA = "harita"
    WIFI = "wifi"
    BLUETOOTH = "bluetooth"
    BAZ = "baz"
    IOT = "iot"
    TOR = "tor"
    GHOST = "ghost"
    SISTEM = "sistem"
    ALARM = "alarm"
    RAPOR = "rapor"


class GuvenlikSeviyesi(Enum):
    """Komut guvenlik seviyeleri"""
    GUVENLI = "guvenli"  # Dogrudan calistirilabilir
    ONAY_GEREKLI = "onay_gerekli"  # Kullanici onayi gerekir
    YASAKLI = "yasakli"  # Kesinlikle calistirilmaz


@dataclass
class KomutSonucu:
    """Komut calistirma sonucu"""
    basarili: bool
    mesaj: str
    veri: Optional[Dict] = None
    aksiyon: Optional[str] = None  # Frontend'de calistirilacak JS
    onay_gerekli: bool = False


@dataclass
class Komut:
    """Tanimli komut yapisi"""
    ad: str
    aciklama: str
    tip: KomutTipi
    guvenlik: GuvenlikSeviyesi
    parametreler: List[str] = field(default_factory=list)
    ornek: str = ""


class HaritaKomutlari:
    """Harita kontrol komutlari"""

    # Turkiye sehir koordinatlari (genisletilmis)
    SEHIRLER = {
        # Buyuk sehirler
        'istanbul': (41.0082, 28.9784),
        'ankara': (39.9334, 32.8597),
        'izmir': (38.4237, 27.1428),
        'antalya': (36.8969, 30.7133),
        'bursa': (40.1885, 29.0610),
        'adana': (37.0000, 35.3213),
        'konya': (37.8746, 32.4932),
        'gaziantep': (37.0662, 37.3833),
        'mersin': (36.8121, 34.6415),
        'diyarbakir': (37.9144, 40.2306),
        'kayseri': (38.7312, 35.4787),
        'eskisehir': (39.7767, 30.5206),
        'trabzon': (41.0027, 39.7168),
        'samsun': (41.2867, 36.3300),
        'denizli': (37.7765, 29.0864),
        'malatya': (38.3552, 38.3095),
        'erzurum': (39.9055, 41.2658),
        'van': (38.4891, 43.4089),
        'batman': (37.8812, 41.1351),
        'mardin': (37.3212, 40.7245),
        # Turistik ve ek sehirler
        'edirne': (41.6818, 26.5623),
        'canakkale': (40.1553, 26.4142),
        'balikesir': (39.6484, 27.8826),
        'mugla': (37.2153, 28.3636),
        'aydin': (37.8560, 27.8416),
        'manisa': (38.6191, 27.4289),
        'kutahya': (39.4242, 29.9833),
        'afyon': (38.7507, 30.5567),
        'isparta': (37.7648, 30.5566),
        'burdur': (37.7203, 30.2906),
        'usak': (38.6823, 29.4082),
        'hatay': (36.2025, 36.1601),
        'urfa': (37.1591, 38.7969),
        'sanliurfa': (37.1591, 38.7969),
        'kahramanmaras': (37.5753, 36.9228),
        'osmaniye': (37.0742, 36.2478),
        'kilis': (36.7184, 37.1212),
        'adiyaman': (37.7648, 38.2786),
        'elazig': (38.6810, 39.2264),
        'tunceli': (39.1079, 39.5401),
        'bingol': (38.8855, 40.4966),
        'mus': (38.9462, 41.7539),
        'bitlis': (38.4006, 42.1095),
        'siirt': (37.9273, 41.9420),
        'sirnak': (37.5164, 42.4611),
        'hakkari': (37.5744, 43.7408),
        'agri': (39.7191, 43.0503),
        'igdir': (39.9237, 44.0450),
        'kars': (40.6013, 43.0975),
        'ardahan': (41.1105, 42.7022),
        'artvin': (41.1828, 41.8183),
        'rize': (41.0201, 40.5234),
        'giresun': (40.9128, 38.3895),
        'ordu': (40.9839, 37.8764),
        'amasya': (40.6499, 35.8353),
        'tokat': (40.3167, 36.5544),
        'sivas': (39.7477, 37.0179),
        'yozgat': (39.8181, 34.8147),
        'nevsehir': (38.6939, 34.6857),
        'nigde': (37.9667, 34.6939),
        'aksaray': (38.3687, 34.0370),
        'kirikkale': (39.8468, 33.5153),
        'kirsehir': (39.1425, 34.1709),
        'cankiri': (40.6013, 33.6134),
        'kastamonu': (41.3887, 33.7827),
        'sinop': (42.0231, 35.1531),
        'bartin': (41.6344, 32.3375),
        'karabuk': (41.2061, 32.6204),
        'zonguldak': (41.4564, 31.7987),
        'duzce': (40.8438, 31.1565),
        'bolu': (40.7391, 31.6089),
        'sakarya': (40.6940, 30.4358),
        'kocaeli': (40.8533, 29.8815),
        'yalova': (40.6500, 29.2667),
        'bilecik': (40.0567, 30.0665),
        'tekirdag': (40.9833, 27.5167),
        'kirklareli': (41.7333, 27.2167),
        # Turistik bolgeler
        'bodrum': (37.0343, 27.4305),
        'marmaris': (36.8550, 28.2741),
        'fethiye': (36.6220, 29.1156),
        'kas': (36.2022, 29.6419),
        'kalkan': (36.2644, 29.4156),
        'alanya': (36.5437, 31.9993),
        'side': (36.7675, 31.3903),
        'kemer': (36.5978, 30.5594),
        'cesme': (38.3236, 26.3028),
        'kusadasi': (37.8579, 27.2610),
        'didim': (37.3833, 27.2667),
        'datca': (36.7333, 27.6833),
        'gokova': (36.9167, 28.3167),
        'oludeniz': (36.5500, 29.1167),
        'kapadokya': (38.6431, 34.8289),
        'goreme': (38.6431, 34.8289),
        'pamukkale': (37.9203, 29.1186),
        'efes': (37.9394, 27.3417),
        # Ulke geneli
        'turkiye': (39.0, 35.0),
        'turkey': (39.0, 35.0),
    }

    # Onemli konumlar
    ONEMLI_KONUMLAR = {
        'taksim': (41.0370, 28.9850),
        'kadikoy': (40.9927, 29.0230),
        'besiktas': (41.0422, 29.0067),
        'kizilay': (39.9208, 32.8541),
        'ulus': (39.9425, 32.8644),
        'konak': (38.4189, 27.1287),
        'alsancak': (38.4346, 27.1426),
    }

    @staticmethod
    def konum_bul(metin: str) -> Optional[tuple]:
        """Metinden konum koordinatlarini cikar"""
        metin = metin.lower().strip()

        # Sehir kontrolu
        for sehir, koordinat in HaritaKomutlari.SEHIRLER.items():
            if sehir in metin:
                return koordinat

        # Onemli konum kontrolu
        for konum, koordinat in HaritaKomutlari.ONEMLI_KONUMLAR.items():
            if konum in metin:
                return koordinat

        # Koordinat pattern: 41.0082, 28.9784
        koordinat_pattern = r'(-?\d+\.?\d*)\s*[,\s]\s*(-?\d+\.?\d*)'
        match = re.search(koordinat_pattern, metin)
        if match:
            lat, lon = float(match.group(1)), float(match.group(2))
            if -90 <= lat <= 90 and -180 <= lon <= 180:
                return (lat, lon)

        return None

    @staticmethod
    def zoom_seviyesi_bul(metin: str) -> int:
        """Metinden zoom seviyesi cikar"""
        metin = metin.lower()

        if any(k in metin for k in ['cok yakin', 'maksimum', 'en yakin', 'detayli']):
            return 18
        elif any(k in metin for k in ['yakin', 'yakinlas', 'buyut']):
            return 14
        elif any(k in metin for k in ['orta', 'normal']):
            return 10
        elif any(k in metin for k in ['uzak', 'uzaklas', 'kucult', 'genel']):
            return 6
        elif any(k in metin for k in ['tum turkiye', 'ulke', 'harita']):
            return 6

        return 12  # Varsayilan

    @staticmethod
    def katman_bul(metin: str) -> Optional[str]:
        """Metinden katman adini cikar"""
        metin = metin.lower()

        katmanlar = {
            'wifi': ['wifi', 'kablosuz', 'wireless', 'ag'],
            'bluetooth': ['bluetooth', 'bt', 'mavi dis'],
            'baz': ['baz', 'baz istasyonu', 'cell', 'hucre', 'gsm'],
            'iot': ['iot', 'nesnelerin interneti', 'cihaz'],
            'tehdit': ['tehdit', 'saldiri', 'alarm', 'uyari'],
            'ucak': ['ucak', 'havacilik', 'flight', 'aircraft'],
            'deprem': ['deprem', 'sismik', 'fay'],
            'uydu': ['uydu', 'satellite', 'starlink', 'turksat'],
        }

        for katman, anahtar_kelimeler in katmanlar.items():
            if any(k in metin for k in anahtar_kelimeler):
                return katman

        return None

    @staticmethod
    def harita_git(konum: tuple, zoom: int = 12) -> KomutSonucu:
        """Haritayi belirtilen konuma gotur"""
        lat, lon = konum
        return KomutSonucu(
            basarili=True,
            mesaj=f"Harita {lat:.4f}, {lon:.4f} konumuna tasindi (zoom: {zoom})",
            veri={'lat': lat, 'lon': lon, 'zoom': zoom},
            aksiyon=f"map.setView([{lat}, {lon}], {zoom});"
        )

    @staticmethod
    def katman_degistir(katman: str, durum: bool) -> KomutSonucu:
        """Harita katmanini ac/kapat"""
        aksiyon_ad = 'ac' if durum else 'kapat'

        # Katman kontrol fonksiyonu
        js_fonksiyonlar = {
            'wifi': f"toggleLayer('wifi', {str(durum).lower()});",
            'bluetooth': f"toggleLayer('bluetooth', {str(durum).lower()});",
            'baz': f"toggleLayer('baz', {str(durum).lower()});",
            'iot': f"toggleLayer('iot', {str(durum).lower()});",
            'tehdit': f"toggleLayer('threats', {str(durum).lower()});",
            'ucak': f"toggleAircraftLayer({str(durum).lower()});",
            'deprem': f"toggleEarthquakeLayer({str(durum).lower()});",
            'uydu': f"toggleSatelliteLayer({str(durum).lower()});",
        }

        js = js_fonksiyonlar.get(katman, f"console.log('Bilinmeyen katman: {katman}');")

        return KomutSonucu(
            basarili=True,
            mesaj=f"{katman.upper()} katmani {'acildi' if durum else 'kapatildi'}",
            veri={'katman': katman, 'durum': durum},
            aksiyon=js
        )

    @staticmethod
    def marker_ekle(lat: float, lon: float, baslik: str, tur: str = "ozel") -> KomutSonucu:
        """Haritaya marker ekle"""
        return KomutSonucu(
            basarili=True,
            mesaj=f"Marker eklendi: {baslik} ({lat:.4f}, {lon:.4f})",
            veri={'lat': lat, 'lon': lon, 'baslik': baslik, 'tur': tur},
            aksiyon=f"""
                L.marker([{lat}, {lon}])
                    .addTo(map)
                    .bindPopup('<b>{baslik}</b><br>Koordinat: {lat:.4f}, {lon:.4f}')
                    .openPopup();
            """
        )


class SIGINTKomutlari:
    """SIGINT islem komutlari"""

    @staticmethod
    def wifi_tara() -> KomutSonucu:
        """WiFi taramasi baslat"""
        return KomutSonucu(
            basarili=True,
            mesaj="WiFi taramasi baslatildi. Sonuclar haritada goruntulenecek.",
            veri={'islem': 'wifi_tara'},
            aksiyon="startWiFiScan();"
        )

    @staticmethod
    def bluetooth_tara() -> KomutSonucu:
        """Bluetooth taramasi baslat"""
        return KomutSonucu(
            basarili=True,
            mesaj="Bluetooth taramasi baslatildi. BLE cihazlar tespit edilecek.",
            veri={'islem': 'bluetooth_tara'},
            aksiyon="startBluetoothScan();"
        )

    @staticmethod
    def tehdit_analizi() -> KomutSonucu:
        """Tehdit analizi yap"""
        return KomutSonucu(
            basarili=True,
            mesaj="Tehdit analizi baslatildi. Sonuclar terminal'de goruntulenecek.",
            veri={'islem': 'tehdit_analizi'},
            aksiyon="runThreatAnalysis();"
        )

    @staticmethod
    def tor_yenile() -> KomutSonucu:
        """TOR kimligini yenile"""
        return KomutSonucu(
            basarili=True,
            mesaj="TOR kimligi yenileniyor...",
            veri={'islem': 'tor_yenile'},
            aksiyon="refreshTorIdentity();"
        )

    @staticmethod
    def ghost_mod(durum: bool) -> KomutSonucu:
        """Ghost modu ac/kapat"""
        return KomutSonucu(
            basarili=True,
            mesaj=f"Ghost modu {'aktif' if durum else 'pasif'} edildi",
            veri={'islem': 'ghost_mod', 'durum': durum},
            aksiyon=f"toggleGhostMode({str(durum).lower()});"
        )

    @staticmethod
    def sistem_durumu() -> KomutSonucu:
        """Sistem durumunu getir"""
        return KomutSonucu(
            basarili=True,
            mesaj="Sistem durumu sorgulanıyor...",
            veri={'islem': 'sistem_durumu'},
            aksiyon="fetchSystemStatus();"
        )


class KomutYorumcu:
    """Dogal dil komutlarini yorumla ve calistir"""

    def __init__(self):
        self.harita = HaritaKomutlari()
        self.sigint = SIGINTKomutlari()

        # Komut kaliplari
        self.kalipler = {
            # Harita navigasyon
            r'(git|tasi|gotur|yakinlas|zoom).*?(\w+)': self._harita_git,
            r'(\w+).*(goster|goruntuler|bak)': self._harita_git,

            # Katman kontrol
            r'(ac|aktif|goster).*?(wifi|bluetooth|baz|iot|tehdit|ucak|deprem|uydu)': self._katman_ac,
            r'(kapat|pasif|gizle).*?(wifi|bluetooth|baz|iot|tehdit|ucak|deprem|uydu)': self._katman_kapat,
            r'(wifi|bluetooth|baz|iot|tehdit|ucak|deprem|uydu).*?(ac|aktif|goster)': self._katman_ac,
            r'(wifi|bluetooth|baz|iot|tehdit|ucak|deprem|uydu).*?(kapat|pasif|gizle)': self._katman_kapat,

            # SIGINT
            r'(wifi|kablosuz).*?(tara|tarama|scan)': lambda m, t: self.sigint.wifi_tara(),
            r'(tara|tarama|scan).*?(wifi|kablosuz)': lambda m, t: self.sigint.wifi_tara(),
            r'(bluetooth|bt).*?(tara|tarama|scan)': lambda m, t: self.sigint.bluetooth_tara(),
            r'(tara|tarama|scan).*?(bluetooth|bt)': lambda m, t: self.sigint.bluetooth_tara(),
            r'(tehdit|threat).*?(analiz|analizi|tara)': lambda m, t: self.sigint.tehdit_analizi(),

            # TOR/Ghost
            r'(tor|onion).*?(yenile|degistir|refresh)': lambda m, t: self.sigint.tor_yenile(),
            r'(ghost|hayalet).*?(ac|aktif)': lambda m, t: self.sigint.ghost_mod(True),
            r'(ghost|hayalet).*?(kapat|pasif)': lambda m, t: self.sigint.ghost_mod(False),

            # Sistem
            r'(sistem|system).*?(durum|status|bilgi)': lambda m, t: self.sigint.sistem_durumu(),
        }

    def _harita_git(self, match, metin: str) -> KomutSonucu:
        """Harita navigasyon komutu"""
        konum = self.harita.konum_bul(metin)
        if konum:
            zoom = self.harita.zoom_seviyesi_bul(metin)
            return self.harita.harita_git(konum, zoom)
        return KomutSonucu(
            basarili=False,
            mesaj="Konum bulunamadi. Lutfen sehir adi veya koordinat belirtin."
        )

    def _katman_ac(self, match, metin: str) -> KomutSonucu:
        """Katman acma komutu"""
        katman = self.harita.katman_bul(metin)
        if katman:
            return self.harita.katman_degistir(katman, True)
        return KomutSonucu(
            basarili=False,
            mesaj="Katman bulunamadi. Mevcut katmanlar: wifi, bluetooth, baz, iot, tehdit, ucak, deprem, uydu"
        )

    def _katman_kapat(self, match, metin: str) -> KomutSonucu:
        """Katman kapatma komutu"""
        katman = self.harita.katman_bul(metin)
        if katman:
            return self.harita.katman_degistir(katman, False)
        return KomutSonucu(
            basarili=False,
            mesaj="Katman bulunamadi. Mevcut katmanlar: wifi, bluetooth, baz, iot, tehdit, ucak, deprem, uydu"
        )

    def yorumla(self, metin: str) -> KomutSonucu:
        """Metni yorumla ve uygun komutu calistir"""
        metin_lower = metin.lower().strip()

        # Kaliplari kontrol et
        for kalip, fonksiyon in self.kalipler.items():
            match = re.search(kalip, metin_lower)
            if match:
                try:
                    return fonksiyon(match, metin_lower)
                except Exception as e:
                    logger.error(f"Komut hatasi: {e}")
                    return KomutSonucu(
                        basarili=False,
                        mesaj=f"Komut calistirilirken hata olustu: {str(e)}"
                    )

        # Dogrudan konum kontrolu
        konum = self.harita.konum_bul(metin_lower)
        if konum:
            zoom = self.harita.zoom_seviyesi_bul(metin_lower)
            return self.harita.harita_git(konum, zoom)

        # Komut bulunamadi
        return KomutSonucu(
            basarili=False,
            mesaj="Bu komutu anlamadim. Ornekler: 'Istanbul'a git', 'WiFi katmanini ac', 'TOR yenile'"
        )
