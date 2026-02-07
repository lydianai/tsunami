#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI OSINT MODULE - Professional Open Source Intelligence
============================================================

Gercek OSINT yetenekleri:
- Telefon numarasi istihbarati ve konum
- E-posta arastirmasi ve platform tespiti
- Sosyal medya kullanici arastirmasi
- Adli bilisim (metadata analizi)
- IP/Domain istihbarati
- Harita uzerinde gorsellestirme

Entegre Araclar:
- phonenumbers (offline telefon analizi)
- Holehe (120+ platform email kontrolu)
- Sherlock/Maigret (3000+ site username arama)
- ExifTool (metadata cikarma)
- HIBP (veri ihlali kontrolu)
"""

import os
import re
import json
import hashlib
import subprocess
import asyncio
import aiohttp
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import threading

# Telefon numarasi analizi
try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone, number_type
    from phonenumbers.phonenumberutil import NumberParseException
    PHONENUMBERS_AKTIF = True
except ImportError:
    PHONENUMBERS_AKTIF = False
    print("[OSINT] phonenumbers bulunamadi - pip install phonenumbers")

# DNS ve WHOIS
try:
    import dns.resolver
    DNS_AKTIF = True
except ImportError:
    DNS_AKTIF = False

try:
    import whois
    WHOIS_AKTIF = True
except ImportError:
    WHOIS_AKTIF = False

# IP WHOIS
try:
    from ipwhois import IPWhois
    IPWHOIS_AKTIF = True
except ImportError:
    IPWHOIS_AKTIF = False

# GeoIP
try:
    import geoip2.database
    GEOIP_AKTIF = True
except ImportError:
    GEOIP_AKTIF = False

# PIL for EXIF
try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AKTIF = True
except ImportError:
    PIL_AKTIF = False


# ==================== ENUM VE DATACLASS ====================

class OSINTTipi(Enum):
    """OSINT veri tipleri"""
    TELEFON = "telefon"
    EMAIL = "email"
    KULLANICI = "kullanici"
    IP = "ip"
    DOMAIN = "domain"
    DOSYA = "dosya"
    KONUM = "konum"


class PlatformDurumu(Enum):
    """Platform kontrol durumu"""
    MEVCUT = "mevcut"      # Hesap var
    YOK = "yok"            # Hesap yok
    BELIRSIZ = "belirsiz"  # Kontrol edilemedi
    HATA = "hata"          # API hatasi


@dataclass
class OSINTSonuc:
    """OSINT sonuc verisi"""
    tip: OSINTTipi
    hedef: str
    basarili: bool
    veri: Dict[str, Any]
    konum: Optional[Dict[str, float]] = None  # lat, lng
    guven_skoru: float = 0.0
    kaynaklar: List[str] = field(default_factory=list)
    zaman: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> Dict:
        return {
            'tip': self.tip.value,
            'hedef': self.hedef,
            'basarili': self.basarili,
            'veri': self.veri,
            'konum': self.konum,
            'guven_skoru': self.guven_skoru,
            'kaynaklar': self.kaynaklar,
            'zaman': self.zaman.isoformat()
        }


# ==================== TELEFON OSINT ====================

class TelefonOSINT:
    """
    Telefon numarasi istihbarati

    Yetenekler:
    - Ulke ve bolge tespiti
    - Operator tespiti
    - Numara tipi (mobil, sabit, VoIP)
    - Zaman dilimi
    - Tahmini konum (ulke/bolge seviyesinde)
    """

    # Turkiye operator kodlari ve bilgileri
    TURKIYE_OPERATORLER = {
        '530': {'ad': 'Vodafone', 'tip': 'GSM', 'renk': '#E60000'},
        '531': {'ad': 'Vodafone', 'tip': 'GSM', 'renk': '#E60000'},
        '532': {'ad': 'Vodafone', 'tip': 'GSM', 'renk': '#E60000'},
        '533': {'ad': 'Vodafone', 'tip': 'GSM', 'renk': '#E60000'},
        '534': {'ad': 'Vodafone', 'tip': 'GSM', 'renk': '#E60000'},
        '535': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '536': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '537': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '538': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '539': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '540': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '541': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '542': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '543': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '544': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '545': {'ad': 'Turkcell', 'tip': 'GSM', 'renk': '#FFD100'},
        '546': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '547': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '548': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '549': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '550': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '551': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '552': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '553': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '554': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '555': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
        '559': {'ad': 'Turk Telekom', 'tip': 'GSM', 'renk': '#00A0E1'},
    }

    # Ulke merkez koordinatlari (ulke kodu -> lat, lng)
    ULKE_KOORDINATLARI = {
        'TR': {'lat': 39.9334, 'lng': 32.8597, 'ad': 'Türkiye'},
        'US': {'lat': 38.8951, 'lng': -77.0364, 'ad': 'ABD'},
        'GB': {'lat': 51.5074, 'lng': -0.1278, 'ad': 'İngiltere'},
        'DE': {'lat': 52.5200, 'lng': 13.4050, 'ad': 'Almanya'},
        'FR': {'lat': 48.8566, 'lng': 2.3522, 'ad': 'Fransa'},
        'RU': {'lat': 55.7558, 'lng': 37.6173, 'ad': 'Rusya'},
        'CN': {'lat': 39.9042, 'lng': 116.4074, 'ad': 'Çin'},
        'JP': {'lat': 35.6762, 'lng': 139.6503, 'ad': 'Japonya'},
        'IN': {'lat': 28.6139, 'lng': 77.2090, 'ad': 'Hindistan'},
        'BR': {'lat': -15.7975, 'lng': -47.8919, 'ad': 'Brezilya'},
        'AU': {'lat': -35.2809, 'lng': 149.1300, 'ad': 'Avustralya'},
        'IT': {'lat': 41.9028, 'lng': 12.4964, 'ad': 'İtalya'},
        'ES': {'lat': 40.4168, 'lng': -3.7038, 'ad': 'İspanya'},
        'NL': {'lat': 52.3676, 'lng': 4.9041, 'ad': 'Hollanda'},
        'SE': {'lat': 59.3293, 'lng': 18.0686, 'ad': 'İsveç'},
        'CH': {'lat': 46.9480, 'lng': 7.4474, 'ad': 'İsviçre'},
        'AE': {'lat': 25.2048, 'lng': 55.2708, 'ad': 'BAE'},
        'SA': {'lat': 24.7136, 'lng': 46.6753, 'ad': 'Suudi Arabistan'},
        'EG': {'lat': 30.0444, 'lng': 31.2357, 'ad': 'Mısır'},
        'ZA': {'lat': -25.7461, 'lng': 28.1881, 'ad': 'Güney Afrika'},
        'KR': {'lat': 37.5665, 'lng': 126.9780, 'ad': 'Güney Kore'},
        'MX': {'lat': 19.4326, 'lng': -99.1332, 'ad': 'Meksika'},
        'AR': {'lat': -34.6037, 'lng': -58.3816, 'ad': 'Arjantin'},
        'PL': {'lat': 52.2297, 'lng': 21.0122, 'ad': 'Polonya'},
        'UA': {'lat': 50.4501, 'lng': 30.5234, 'ad': 'Ukrayna'},
        'IR': {'lat': 35.6892, 'lng': 51.3890, 'ad': 'İran'},
        'IL': {'lat': 31.7683, 'lng': 35.2137, 'ad': 'İsrail'},
        'GR': {'lat': 37.9838, 'lng': 23.7275, 'ad': 'Yunanistan'},
        'BG': {'lat': 42.6977, 'lng': 23.3219, 'ad': 'Bulgaristan'},
        'RO': {'lat': 44.4268, 'lng': 26.1025, 'ad': 'Romanya'},
    }

    # Turkiye il alan kodlari
    TURKIYE_ALAN_KODLARI = {
        '212': {'il': 'İstanbul (Avrupa)', 'lat': 41.0082, 'lng': 28.9784},
        '216': {'il': 'İstanbul (Anadolu)', 'lat': 40.9828, 'lng': 29.0276},
        '312': {'il': 'Ankara', 'lat': 39.9334, 'lng': 32.8597},
        '232': {'il': 'İzmir', 'lat': 38.4192, 'lng': 27.1287},
        '224': {'il': 'Bursa', 'lat': 40.1826, 'lng': 29.0665},
        '242': {'il': 'Antalya', 'lat': 36.8969, 'lng': 30.7133},
        '322': {'il': 'Adana', 'lat': 36.9914, 'lng': 35.3308},
        '262': {'il': 'Kocaeli', 'lat': 40.8533, 'lng': 29.8815},
        '342': {'il': 'Gaziantep', 'lat': 37.0662, 'lng': 37.3833},
        '352': {'il': 'Kayseri', 'lat': 38.7312, 'lng': 35.4787},
        '362': {'il': 'Samsun', 'lat': 41.2867, 'lng': 36.3300},
        '422': {'il': 'Malatya', 'lat': 38.3552, 'lng': 38.3095},
        '442': {'il': 'Erzurum', 'lat': 39.9055, 'lng': 41.2658},
        '462': {'il': 'Trabzon', 'lat': 41.0027, 'lng': 39.7168},
        '412': {'il': 'Diyarbakır', 'lat': 37.9144, 'lng': 40.2306},
        '332': {'il': 'Konya', 'lat': 37.8746, 'lng': 32.4932},
        '274': {'il': 'Eskişehir', 'lat': 39.7767, 'lng': 30.5206},
        '252': {'il': 'Muğla', 'lat': 37.2153, 'lng': 28.3636},
        '384': {'il': 'Nevşehir', 'lat': 38.6244, 'lng': 34.7144},
    }

    def __init__(self):
        self._api_keys = {
            'numverify': os.getenv('NUMVERIFY_API_KEY', ''),
            'twilio_sid': os.getenv('TWILIO_ACCOUNT_SID', ''),
            'twilio_token': os.getenv('TWILIO_AUTH_TOKEN', ''),
            'ipqs': os.getenv('IPQS_API_KEY', ''),  # HLR Lookup
        }

    def analiz_et(self, telefon: str) -> OSINTSonuc:
        """
        Telefon numarasini analiz et

        Args:
            telefon: Telefon numarasi (+905551234567 veya 05551234567)

        Returns:
            OSINTSonuc: Analiz sonuclari ve konum
        """
        # Numarayi temizle
        telefon_temiz = re.sub(r'[\s\-\(\)]', '', telefon)
        if not telefon_temiz.startswith('+'):
            if telefon_temiz.startswith('0'):
                telefon_temiz = '+90' + telefon_temiz[1:]
            else:
                telefon_temiz = '+' + telefon_temiz

        veri = {
            'orijinal': telefon,
            'temiz': telefon_temiz,
            'gecerli': False,
            'ulke': None,
            'ulke_kodu': None,
            'bolge': None,
            'operator': None,
            'numara_tipi': None,
            'zaman_dilimi': None,
            'format_uluslararasi': None,
            'format_ulusal': None,
        }
        konum = None
        kaynaklar = []

        if not PHONENUMBERS_AKTIF:
            return OSINTSonuc(
                tip=OSINTTipi.TELEFON,
                hedef=telefon,
                basarili=False,
                veri={'hata': 'phonenumbers modulu yuklu degil'},
                guven_skoru=0.0
            )

        try:
            # phonenumbers ile parse et
            parsed = phonenumbers.parse(telefon_temiz)

            veri['gecerli'] = phonenumbers.is_valid_number(parsed)
            veri['ulke'] = geocoder.description_for_number(parsed, 'tr')
            veri['ulke_kodu'] = phonenumbers.region_code_for_number(parsed)
            veri['operator'] = carrier.name_for_number(parsed, 'tr')
            veri['zaman_dilimi'] = list(timezone.time_zones_for_number(parsed))
            veri['format_uluslararasi'] = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL
            )
            veri['format_ulusal'] = phonenumbers.format_number(
                parsed, phonenumbers.PhoneNumberFormat.NATIONAL
            )

            # Numara tipi
            nt = number_type(parsed)
            tip_map = {
                0: 'Sabit Hat',
                1: 'Mobil',
                2: 'Sabit/Mobil',
                3: 'Ucretsiz Hat',
                4: 'Premium',
                5: 'Shared Cost',
                6: 'VoIP',
                7: 'Kisisel',
                8: 'Cagri',
                9: 'UAN',
                10: 'Bilinmiyor'
            }
            veri['numara_tipi'] = tip_map.get(nt, 'Bilinmiyor')

            kaynaklar.append('phonenumbers')

            # Turkiye numarasi mi?
            if veri['ulke_kodu'] == 'TR':
                # Operator detayi
                ulusal = veri['format_ulusal'].replace(' ', '')
                if ulusal.startswith('0'):
                    prefix = ulusal[1:4]

                    # Mobil mi?
                    if prefix in self.TURKIYE_OPERATORLER:
                        op_bilgi = self.TURKIYE_OPERATORLER[prefix]
                        veri['operator_detay'] = op_bilgi
                        veri['operator'] = op_bilgi['ad']

                    # Sabit hat mi? (alan kodu)
                    elif prefix in self.TURKIYE_ALAN_KODLARI:
                        alan_bilgi = self.TURKIYE_ALAN_KODLARI[prefix]
                        veri['bolge'] = alan_bilgi['il']
                        konum = {
                            'lat': alan_bilgi['lat'],
                            'lng': alan_bilgi['lng'],
                            'dogruluk': 'il',
                            'kaynak': 'alan_kodu'
                        }

            # Ulke bazli konum
            if not konum and veri['ulke_kodu']:
                ulke_konum = self.ULKE_KOORDINATLARI.get(veri['ulke_kodu'])
                if ulke_konum:
                    konum = {
                        'lat': ulke_konum['lat'],
                        'lng': ulke_konum['lng'],
                        'dogruluk': 'ulke',
                        'kaynak': 'ulke_kodu',
                        'ulke_adi': ulke_konum['ad']
                    }

            # NumVerify API (opsiyonel - daha detayli bilgi)
            if self._api_keys['numverify']:
                numverify_data = self._numverify_lookup(telefon_temiz)
                if numverify_data:
                    veri['numverify'] = numverify_data
                    kaynaklar.append('numverify')

            # HLR Lookup (gercek operatör durumu)
            if self._api_keys.get('ipqs'):
                hlr_data = self._hlr_lookup(telefon_temiz)
                if hlr_data:
                    veri['hlr'] = hlr_data
                    kaynaklar.append('hlr_lookup')

                    # HLR'dan gelen konum bilgisi
                    if hlr_data.get('sehir') and not konum:
                        # HLR konum bilgisini kullan
                        veri['hlr_konum'] = {
                            'sehir': hlr_data.get('sehir'),
                            'bolge': hlr_data.get('bolge'),
                            'ulke': hlr_data.get('ulke'),
                        }

            guven = 0.8 if veri['gecerli'] else 0.3
            if konum:
                if konum['dogruluk'] == 'il':
                    guven = 0.9
                elif konum['dogruluk'] == 'ulke':
                    guven = 0.7

            return OSINTSonuc(
                tip=OSINTTipi.TELEFON,
                hedef=telefon,
                basarili=True,
                veri=veri,
                konum=konum,
                guven_skoru=guven,
                kaynaklar=kaynaklar
            )

        except NumberParseException as e:
            return OSINTSonuc(
                tip=OSINTTipi.TELEFON,
                hedef=telefon,
                basarili=False,
                veri={'hata': str(e), 'orijinal': telefon},
                guven_skoru=0.0
            )

    def _numverify_lookup(self, telefon: str) -> Optional[Dict]:
        """NumVerify API ile detayli bilgi al"""
        try:
            url = "http://apilayer.net/api/validate"
            params = {
                'access_key': self._api_keys['numverify'],
                'number': telefon.replace('+', ''),
                'country_code': '',
                'format': 1
            }
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"[OSINT] NumVerify hatasi: {e}")
        return None

    def _hlr_lookup(self, telefon: str) -> Optional[Dict]:
        """
        HLR Lookup - Gercek operator durumu
        IPQualityScore API kullanir
        """
        api_key = self._api_keys.get('ipqs')
        if not api_key:
            return None

        try:
            url = f"https://ipqualityscore.com/api/json/phone/{api_key}/{telefon}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                if data.get('success'):
                    return {
                        'aktif': data.get('active'),
                        'gecerli': data.get('valid'),
                        'operator': data.get('carrier'),
                        'hat_tipi': data.get('line_type'),
                        'ulke': data.get('country'),
                        'bolge': data.get('region'),
                        'sehir': data.get('city'),
                        'zip_kodu': data.get('zip_code'),
                        'dolandiricilik_skoru': data.get('fraud_score'),
                        'sahte_numara': data.get('spammer'),
                        'voip': data.get('VOIP'),
                        'prepaid': data.get('prepaid'),
                        'roaming': data.get('roaming'),
                        'mcc': data.get('mcc'),
                        'mnc': data.get('mnc'),
                    }
        except Exception as e:
            print(f"[OSINT] HLR Lookup hatasi: {e}")

        return None

    def toplu_analiz(self, telefonlar: List[str]) -> List[OSINTSonuc]:
        """Birden fazla telefon numarasini analiz et"""
        sonuclar = []
        for tel in telefonlar:
            sonuclar.append(self.analiz_et(tel))
        return sonuclar


# ==================== EMAIL OSINT ====================

class EmailOSINT:
    """
    E-posta istihbarati

    Yetenekler:
    - Platform tespiti (hangi sitelerde kayitli)
    - Veri ihlali kontrolu (HIBP)
    - Email dogrulama
    - Domain analizi
    """

    # Kontrol edilecek platformlar
    PLATFORMLAR = [
        {'ad': 'Twitter/X', 'url': 'twitter.com', 'ikon': '🐦'},
        {'ad': 'Instagram', 'url': 'instagram.com', 'ikon': '📷'},
        {'ad': 'Facebook', 'url': 'facebook.com', 'ikon': '👤'},
        {'ad': 'LinkedIn', 'url': 'linkedin.com', 'ikon': '💼'},
        {'ad': 'GitHub', 'url': 'github.com', 'ikon': '🐙'},
        {'ad': 'Spotify', 'url': 'spotify.com', 'ikon': '🎵'},
        {'ad': 'Discord', 'url': 'discord.com', 'ikon': '🎮'},
        {'ad': 'Pinterest', 'url': 'pinterest.com', 'ikon': '📌'},
        {'ad': 'TikTok', 'url': 'tiktok.com', 'ikon': '🎬'},
        {'ad': 'Reddit', 'url': 'reddit.com', 'ikon': '🤖'},
        {'ad': 'Twitch', 'url': 'twitch.tv', 'ikon': '🎮'},
        {'ad': 'Medium', 'url': 'medium.com', 'ikon': '📝'},
        {'ad': 'Tumblr', 'url': 'tumblr.com', 'ikon': '📓'},
        {'ad': 'WordPress', 'url': 'wordpress.com', 'ikon': '📰'},
        {'ad': 'Gravatar', 'url': 'gravatar.com', 'ikon': '👤'},
        {'ad': 'Adobe', 'url': 'adobe.com', 'ikon': '🎨'},
        {'ad': 'Amazon', 'url': 'amazon.com', 'ikon': '📦'},
        {'ad': 'Apple', 'url': 'apple.com', 'ikon': '🍎'},
        {'ad': 'Google', 'url': 'google.com', 'ikon': '🔍'},
        {'ad': 'Microsoft', 'url': 'microsoft.com', 'ikon': '🪟'},
    ]

    def __init__(self):
        self._api_keys = {
            'hibp': os.getenv('HIBP_API_KEY', ''),
            'hunter': os.getenv('HUNTER_API_KEY', ''),
        }
        self._holehe_mevcut = self._check_holehe()

    def _check_holehe(self) -> bool:
        """Holehe kurulu mu kontrol et"""
        try:
            result = subprocess.run(
                ['holehe', '--help'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def analiz_et(self, email: str) -> OSINTSonuc:
        """
        E-posta adresini analiz et

        Args:
            email: E-posta adresi

        Returns:
            OSINTSonuc: Bulunan platformlar ve ihlaller
        """
        # Email formatini dogrula
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, email):
            return OSINTSonuc(
                tip=OSINTTipi.EMAIL,
                hedef=email,
                basarili=False,
                veri={'hata': 'Gecersiz email formati'},
                guven_skoru=0.0
            )

        veri = {
            'email': email,
            'domain': email.split('@')[1],
            'kullanici': email.split('@')[0],
            'platformlar': [],
            'ihlaller': [],
            'domain_bilgi': {},
        }
        kaynaklar = []

        # Holehe ile platform kontrolu
        if self._holehe_mevcut:
            platformlar = self._holehe_check(email)
            veri['platformlar'] = platformlar
            kaynaklar.append('holehe')
        else:
            # Manuel kontrol (basit)
            veri['platformlar'] = self._manuel_platform_check(email)
            kaynaklar.append('manuel_kontrol')

        # HIBP ile ihlal kontrolu
        if self._api_keys['hibp']:
            ihlaller = self._hibp_check(email)
            veri['ihlaller'] = ihlaller
            kaynaklar.append('haveibeenpwned')

        # Domain analizi
        domain_bilgi = self._domain_analiz(veri['domain'])
        veri['domain_bilgi'] = domain_bilgi
        kaynaklar.append('dns')

        # Guven skoru
        platform_sayisi = len([p for p in veri['platformlar'] if p.get('mevcut')])
        guven = min(0.9, 0.5 + (platform_sayisi * 0.05))

        return OSINTSonuc(
            tip=OSINTTipi.EMAIL,
            hedef=email,
            basarili=True,
            veri=veri,
            guven_skoru=guven,
            kaynaklar=kaynaklar
        )

    def _holehe_check(self, email: str) -> List[Dict]:
        """Holehe ile platform kontrolu"""
        platformlar = []
        try:
            result = subprocess.run(
                ['holehe', email, '--only-used', '-NP', '-C'],
                capture_output=True,
                text=True,
                timeout=120
            )

            # Ciktiyi parse et
            for line in result.stdout.split('\n'):
                if '[+]' in line:  # Bulunan platform
                    platform_ad = line.split('[+]')[1].strip().split()[0]
                    platformlar.append({
                        'ad': platform_ad,
                        'mevcut': True,
                        'kaynak': 'holehe'
                    })

        except subprocess.TimeoutExpired:
            print("[OSINT] Holehe zaman asimi")
        except Exception as e:
            print(f"[OSINT] Holehe hatasi: {e}")

        return platformlar

    def _manuel_platform_check(self, email: str) -> List[Dict]:
        """Basit platform kontrolu (API olmadan)"""
        # Gravatar kontrolu (public)
        platformlar = []

        # Gravatar hash
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

        try:
            resp = requests.head(gravatar_url, timeout=5)
            platformlar.append({
                'ad': 'Gravatar',
                'mevcut': resp.status_code == 200,
                'url': f"https://gravatar.com/{email_hash}",
                'kaynak': 'api'
            })
        except:
            pass

        return platformlar

    def _hibp_check(self, email: str) -> List[Dict]:
        """Have I Been Pwned ile ihlal kontrolu"""
        ihlaller = []
        try:
            headers = {
                'hibp-api-key': self._api_keys['hibp'],
                'User-Agent': 'TSUNAMI-OSINT'
            }
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code == 200:
                for breach in response.json():
                    ihlaller.append({
                        'ad': breach.get('Name'),
                        'tarih': breach.get('BreachDate'),
                        'etkilenen': breach.get('PwnCount'),
                        'veri_tipleri': breach.get('DataClasses', [])
                    })
        except Exception as e:
            print(f"[OSINT] HIBP hatasi: {e}")

        return ihlaller

    def _domain_analiz(self, domain: str) -> Dict:
        """Email domain analizi"""
        bilgi = {
            'domain': domain,
            'mx_kayitlari': [],
            'kurumsal': False,
        }

        # Bilinen email providerlari
        public_providers = [
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'icloud.com', 'protonmail.com', 'mail.com', 'yandex.com'
        ]

        bilgi['kurumsal'] = domain.lower() not in public_providers

        # MX kayitlari
        if DNS_AKTIF:
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                bilgi['mx_kayitlari'] = [str(r.exchange) for r in mx_records]
            except:
                pass

        return bilgi

    def sifre_ihlal_kontrol(self, sifre: str) -> Dict:
        """
        Sifrenin ihlal edilip edilmedigini kontrol et (k-Anonymity)
        HIBP API key gerektirmez
        """
        sha1_hash = hashlib.sha1(sifre.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]

        try:
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)

            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return {
                        'ihlal_edilmis': True,
                        'gorulme_sayisi': int(count),
                        'uyari': f'Bu sifre {count} kez ihlallerde gorulmus!'
                    }

            return {'ihlal_edilmis': False, 'gorulme_sayisi': 0}
        except Exception as e:
            return {'hata': str(e)}


# ==================== SOSYAL MEDYA OSINT ====================

class SosyalMedyaOSINT:
    """
    Sosyal medya kullanici arastirmasi

    Yetenekler:
    - Username arama (3000+ site)
    - Profil bilgisi toplama
    - Cross-platform korelasyon
    """

    # Platform bilgileri ve URL sablonlari
    PLATFORMLAR = {
        'twitter': {'url': 'https://twitter.com/{username}', 'ikon': '🐦'},
        'instagram': {'url': 'https://instagram.com/{username}', 'ikon': '📷'},
        'facebook': {'url': 'https://facebook.com/{username}', 'ikon': '👤'},
        'github': {'url': 'https://github.com/{username}', 'ikon': '🐙'},
        'linkedin': {'url': 'https://linkedin.com/in/{username}', 'ikon': '💼'},
        'tiktok': {'url': 'https://tiktok.com/@{username}', 'ikon': '🎬'},
        'youtube': {'url': 'https://youtube.com/@{username}', 'ikon': '📺'},
        'reddit': {'url': 'https://reddit.com/user/{username}', 'ikon': '🤖'},
        'pinterest': {'url': 'https://pinterest.com/{username}', 'ikon': '📌'},
        'tumblr': {'url': 'https://{username}.tumblr.com', 'ikon': '📓'},
        'twitch': {'url': 'https://twitch.tv/{username}', 'ikon': '🎮'},
        'medium': {'url': 'https://medium.com/@{username}', 'ikon': '📝'},
        'spotify': {'url': 'https://open.spotify.com/user/{username}', 'ikon': '🎵'},
        'soundcloud': {'url': 'https://soundcloud.com/{username}', 'ikon': '🎶'},
        'vimeo': {'url': 'https://vimeo.com/{username}', 'ikon': '🎥'},
        'flickr': {'url': 'https://flickr.com/people/{username}', 'ikon': '📸'},
        'behance': {'url': 'https://behance.net/{username}', 'ikon': '🎨'},
        'dribbble': {'url': 'https://dribbble.com/{username}', 'ikon': '🏀'},
        'deviantart': {'url': 'https://deviantart.com/{username}', 'ikon': '🖼️'},
        'telegram': {'url': 'https://t.me/{username}', 'ikon': '📱'},
    }

    def __init__(self):
        self._sherlock_mevcut = self._check_sherlock()
        self._maigret_mevcut = self._check_maigret()

    def _check_sherlock(self) -> bool:
        """Sherlock kurulu mu?"""
        try:
            result = subprocess.run(
                ['sherlock', '--help'],
                capture_output=True,
                timeout=5
            )
            return True
        except:
            return False

    def _check_maigret(self) -> bool:
        """Maigret kurulu mu?"""
        try:
            result = subprocess.run(
                ['maigret', '--help'],
                capture_output=True,
                timeout=5
            )
            return True
        except:
            return False

    def ara(self, kullanici_adi: str, hizli: bool = True) -> OSINTSonuc:
        """
        Kullanici adini tum platformlarda ara

        Args:
            kullanici_adi: Aranacak username
            hizli: True=sadece populer siteler, False=tum siteler

        Returns:
            OSINTSonuc: Bulunan profiller
        """
        veri = {
            'kullanici_adi': kullanici_adi,
            'profiller': [],
            'toplam_bulunan': 0,
            'arac': None
        }
        kaynaklar = []

        # Maigret tercih edilir (daha kapsamli)
        if self._maigret_mevcut and not hizli:
            profiller = self._maigret_search(kullanici_adi)
            veri['profiller'] = profiller
            veri['arac'] = 'maigret'
            kaynaklar.append('maigret')
        elif self._sherlock_mevcut:
            profiller = self._sherlock_search(kullanici_adi)
            veri['profiller'] = profiller
            veri['arac'] = 'sherlock'
            kaynaklar.append('sherlock')
        else:
            # Manuel kontrol
            profiller = self._manuel_search(kullanici_adi)
            veri['profiller'] = profiller
            veri['arac'] = 'manuel'
            kaynaklar.append('http_check')

        veri['toplam_bulunan'] = len([p for p in veri['profiller'] if p.get('mevcut')])

        return OSINTSonuc(
            tip=OSINTTipi.KULLANICI,
            hedef=kullanici_adi,
            basarili=True,
            veri=veri,
            guven_skoru=0.8 if veri['toplam_bulunan'] > 0 else 0.5,
            kaynaklar=kaynaklar
        )

    def _sherlock_search(self, username: str) -> List[Dict]:
        """Sherlock ile arama"""
        profiller = []
        try:
            result = subprocess.run(
                ['sherlock', username, '--print-found', '--timeout', '10'],
                capture_output=True,
                text=True,
                timeout=300
            )

            for line in result.stdout.split('\n'):
                if 'http' in line.lower():
                    # URL'i cikar
                    match = re.search(r'https?://[^\s]+', line)
                    if match:
                        url = match.group()
                        # Platform adini tahmin et
                        platform = url.split('/')[2].replace('www.', '').split('.')[0]
                        profiller.append({
                            'platform': platform.capitalize(),
                            'url': url,
                            'mevcut': True,
                            'kaynak': 'sherlock'
                        })

        except subprocess.TimeoutExpired:
            print("[OSINT] Sherlock zaman asimi")
        except Exception as e:
            print(f"[OSINT] Sherlock hatasi: {e}")

        return profiller

    def _maigret_search(self, username: str) -> List[Dict]:
        """Maigret ile kapsamli arama"""
        profiller = []
        try:
            output_file = f'/tmp/maigret_{username}.json'

            result = subprocess.run(
                ['maigret', username, '--json', 'simple', '-o', f'/tmp/maigret_{username}'],
                capture_output=True,
                text=True,
                timeout=600
            )

            # JSON dosyasini oku
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    data = json.load(f)

                for site, info in data.items():
                    if info.get('status') == 'Claimed':
                        profiller.append({
                            'platform': site,
                            'url': info.get('url_user'),
                            'mevcut': True,
                            'kaynak': 'maigret'
                        })

                # Temizle
                os.remove(output_file)

        except Exception as e:
            print(f"[OSINT] Maigret hatasi: {e}")

        return profiller

    def _manuel_search(self, username: str) -> List[Dict]:
        """Manuel HTTP kontrolu"""
        profiller = []

        for platform, bilgi in self.PLATFORMLAR.items():
            url = bilgi['url'].format(username=username)
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                mevcut = resp.status_code == 200
                profiller.append({
                    'platform': platform.capitalize(),
                    'url': url,
                    'mevcut': mevcut,
                    'ikon': bilgi['ikon'],
                    'kaynak': 'http_check'
                })
            except:
                profiller.append({
                    'platform': platform.capitalize(),
                    'url': url,
                    'mevcut': False,
                    'hata': 'baglanti_hatasi'
                })

        return profiller


# ==================== ADLI BILISIM ====================

class AdliBilisim:
    """
    Dijital adli bilisim

    Yetenekler:
    - Dosya metadata cikarma (EXIF, vb.)
    - GPS koordinat cikarma
    - Hash hesaplama
    - VirusTotal entegrasyonu
    """

    def __init__(self):
        self._api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
        }
        self._exiftool_mevcut = self._check_exiftool()

    def _check_exiftool(self) -> bool:
        """ExifTool kurulu mu?"""
        try:
            result = subprocess.run(
                ['exiftool', '-ver'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def metadata_cikar(self, dosya_yolu: str) -> OSINTSonuc:
        """
        Dosyadan metadata cikar

        Args:
            dosya_yolu: Analiz edilecek dosya

        Returns:
            OSINTSonuc: Metadata ve konum (varsa)
        """
        if not os.path.exists(dosya_yolu):
            return OSINTSonuc(
                tip=OSINTTipi.DOSYA,
                hedef=dosya_yolu,
                basarili=False,
                veri={'hata': 'Dosya bulunamadi'},
                guven_skoru=0.0
            )

        veri = {
            'dosya': os.path.basename(dosya_yolu),
            'boyut': os.path.getsize(dosya_yolu),
            'metadata': {},
            'hashler': {},
            'gps': None,
        }
        konum = None
        kaynaklar = []

        # Hash hesapla
        veri['hashler'] = self._hash_hesapla(dosya_yolu)
        kaynaklar.append('hash')

        # ExifTool ile metadata
        if self._exiftool_mevcut:
            metadata = self._exiftool_cikar(dosya_yolu)
            veri['metadata'] = metadata
            kaynaklar.append('exiftool')

            # GPS koordinatlari
            if 'GPSLatitude' in metadata and 'GPSLongitude' in metadata:
                lat = self._gps_to_decimal(metadata.get('GPSLatitude'), metadata.get('GPSLatitudeRef', 'N'))
                lng = self._gps_to_decimal(metadata.get('GPSLongitude'), metadata.get('GPSLongitudeRef', 'E'))

                if lat and lng:
                    veri['gps'] = {'lat': lat, 'lng': lng}
                    konum = {
                        'lat': lat,
                        'lng': lng,
                        'dogruluk': 'gps',
                        'kaynak': 'exif'
                    }

        elif PIL_AKTIF:
            # PIL ile basit EXIF
            metadata, gps = self._pil_exif_cikar(dosya_yolu)
            veri['metadata'] = metadata
            kaynaklar.append('pil')

            if gps:
                veri['gps'] = gps
                konum = {
                    'lat': gps['lat'],
                    'lng': gps['lng'],
                    'dogruluk': 'gps',
                    'kaynak': 'exif'
                }

        guven = 0.9 if konum else 0.7

        return OSINTSonuc(
            tip=OSINTTipi.DOSYA,
            hedef=dosya_yolu,
            basarili=True,
            veri=veri,
            konum=konum,
            guven_skoru=guven,
            kaynaklar=kaynaklar
        )

    def _hash_hesapla(self, dosya_yolu: str) -> Dict[str, str]:
        """Dosya hashlerini hesapla"""
        hashler = {}

        with open(dosya_yolu, 'rb') as f:
            icerik = f.read()
            hashler['md5'] = hashlib.md5(icerik).hexdigest()
            hashler['sha1'] = hashlib.sha1(icerik).hexdigest()
            hashler['sha256'] = hashlib.sha256(icerik).hexdigest()

        return hashler

    def _exiftool_cikar(self, dosya_yolu: str) -> Dict:
        """ExifTool ile metadata cikar"""
        try:
            result = subprocess.run(
                ['exiftool', '-json', dosya_yolu],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                if data:
                    return data[0]
        except Exception as e:
            print(f"[OSINT] ExifTool hatasi: {e}")

        return {}

    def _pil_exif_cikar(self, dosya_yolu: str) -> Tuple[Dict, Optional[Dict]]:
        """PIL ile EXIF cikar"""
        metadata = {}
        gps = None

        try:
            image = Image.open(dosya_yolu)
            exif = image._getexif()

            if exif:
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)

                    if tag == 'GPSInfo':
                        gps_data = {}
                        for t in value:
                            gps_tag = GPSTAGS.get(t, t)
                            gps_data[gps_tag] = value[t]

                        # GPS koordinatlarini hesapla
                        if 'GPSLatitude' in gps_data and 'GPSLongitude' in gps_data:
                            lat = self._gps_tuple_to_decimal(
                                gps_data['GPSLatitude'],
                                gps_data.get('GPSLatitudeRef', 'N')
                            )
                            lng = self._gps_tuple_to_decimal(
                                gps_data['GPSLongitude'],
                                gps_data.get('GPSLongitudeRef', 'E')
                            )
                            gps = {'lat': lat, 'lng': lng}
                    else:
                        metadata[tag] = str(value)

        except Exception as e:
            print(f"[OSINT] PIL EXIF hatasi: {e}")

        return metadata, gps

    def _gps_to_decimal(self, gps_str: str, ref: str) -> Optional[float]:
        """GPS string'ini decimal'e cevir"""
        try:
            # ExifTool formati: "41 deg 0' 54.00\" N"
            match = re.match(r"(\d+)\s*deg\s*(\d+)'\s*([\d.]+)\"", gps_str)
            if match:
                d, m, s = map(float, match.groups())
                decimal = d + m/60 + s/3600
                if ref in ['S', 'W']:
                    decimal = -decimal
                return decimal
        except:
            pass
        return None

    def _gps_tuple_to_decimal(self, gps_tuple, ref: str) -> float:
        """GPS tuple'i decimal'e cevir"""
        d = float(gps_tuple[0])
        m = float(gps_tuple[1])
        s = float(gps_tuple[2])

        decimal = d + m/60 + s/3600
        if ref in ['S', 'W']:
            decimal = -decimal

        return decimal

    def virustotal_tara(self, dosya_yolu: str) -> Dict:
        """VirusTotal ile dosya tara"""
        if not self._api_keys['virustotal']:
            return {'hata': 'VirusTotal API key gerekli'}

        # Once hash ile kontrol et
        hashler = self._hash_hesapla(dosya_yolu)
        sha256 = hashler['sha256']

        try:
            headers = {'x-apikey': self._api_keys['virustotal']}

            # Hash ile sorgula
            url = f"https://www.virustotal.com/api/v3/files/{sha256}"
            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()['data']['attributes']
                stats = data.get('last_analysis_stats', {})

                return {
                    'bulundu': True,
                    'zararli': stats.get('malicious', 0),
                    'supheli': stats.get('suspicious', 0),
                    'temiz': stats.get('harmless', 0),
                    'tespit_edilemedi': stats.get('undetected', 0),
                    'tip': data.get('type_description'),
                    'isimler': data.get('names', [])[:5],
                }
            elif response.status_code == 404:
                return {
                    'bulundu': False,
                    'mesaj': 'Dosya VirusTotal veritabaninda yok',
                    'sha256': sha256
                }

        except Exception as e:
            return {'hata': str(e)}

        return {}


# ==================== IP/DOMAIN OSINT ====================

class NetworkOSINT:
    """
    IP ve Domain istihbarati

    Yetenekler:
    - IP geolocation
    - WHOIS sorgulari
    - DNS enumeration
    - ASN bilgisi
    """

    # Ucretsiz IP geolocation API'leri
    GEOIP_APIS = [
        'http://ip-api.com/json/{ip}',
        'https://ipapi.co/{ip}/json/',
        'https://ipinfo.io/{ip}/json',
    ]

    def __init__(self):
        self._geoip_db = None
        if GEOIP_AKTIF:
            # MaxMind GeoLite2 veritabani varsa yukle
            db_paths = [
                '/usr/share/GeoIP/GeoLite2-City.mmdb',
                '/var/lib/GeoIP/GeoLite2-City.mmdb',
                os.path.expanduser('~/.geoip/GeoLite2-City.mmdb'),
            ]
            for path in db_paths:
                if os.path.exists(path):
                    try:
                        self._geoip_db = geoip2.database.Reader(path)
                        break
                    except:
                        pass

    def ip_analiz(self, ip: str) -> OSINTSonuc:
        """
        IP adresini analiz et

        Args:
            ip: IP adresi

        Returns:
            OSINTSonuc: Konum ve ASN bilgisi
        """
        # IP formatini dogrula
        ip_regex = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_regex, ip):
            return OSINTSonuc(
                tip=OSINTTipi.IP,
                hedef=ip,
                basarili=False,
                veri={'hata': 'Gecersiz IP formati'},
                guven_skoru=0.0
            )

        veri = {
            'ip': ip,
            'konum': {},
            'asn': {},
            'whois': {},
        }
        konum = None
        kaynaklar = []

        # GeoIP
        geo_bilgi = self._geoip_lookup(ip)
        if geo_bilgi:
            veri['konum'] = geo_bilgi
            kaynaklar.append(geo_bilgi.get('kaynak', 'geoip'))

            if geo_bilgi.get('lat') and geo_bilgi.get('lng'):
                konum = {
                    'lat': geo_bilgi['lat'],
                    'lng': geo_bilgi['lng'],
                    'dogruluk': 'ip',
                    'kaynak': 'geoip'
                }

        # IP WHOIS
        if IPWHOIS_AKTIF:
            whois_bilgi = self._ip_whois(ip)
            veri['whois'] = whois_bilgi
            veri['asn'] = {
                'numara': whois_bilgi.get('asn'),
                'aciklama': whois_bilgi.get('asn_description'),
                'ulke': whois_bilgi.get('asn_country_code'),
            }
            kaynaklar.append('ipwhois')

        return OSINTSonuc(
            tip=OSINTTipi.IP,
            hedef=ip,
            basarili=True,
            veri=veri,
            konum=konum,
            guven_skoru=0.8 if konum else 0.5,
            kaynaklar=kaynaklar
        )

    def _geoip_lookup(self, ip: str) -> Dict:
        """IP geolocation"""
        # MaxMind veritabani varsa kullan
        if self._geoip_db:
            try:
                response = self._geoip_db.city(ip)
                return {
                    'ulke': response.country.name,
                    'ulke_kodu': response.country.iso_code,
                    'sehir': response.city.name,
                    'bolge': response.subdivisions.most_specific.name if response.subdivisions else None,
                    'lat': response.location.latitude,
                    'lng': response.location.longitude,
                    'zaman_dilimi': response.location.time_zone,
                    'kaynak': 'maxmind'
                }
            except:
                pass

        # API fallback
        for api_url in self.GEOIP_APIS:
            try:
                url = api_url.format(ip=ip)
                response = requests.get(url, timeout=10)

                if response.status_code == 200:
                    data = response.json()

                    # ip-api.com formati
                    if 'status' in data and data['status'] == 'success':
                        return {
                            'ulke': data.get('country'),
                            'ulke_kodu': data.get('countryCode'),
                            'sehir': data.get('city'),
                            'bolge': data.get('regionName'),
                            'lat': data.get('lat'),
                            'lng': data.get('lon'),
                            'isp': data.get('isp'),
                            'org': data.get('org'),
                            'zaman_dilimi': data.get('timezone'),
                            'kaynak': 'ip-api'
                        }

                    # ipinfo.io formati
                    elif 'loc' in data:
                        lat, lng = data['loc'].split(',')
                        return {
                            'ulke': data.get('country'),
                            'sehir': data.get('city'),
                            'bolge': data.get('region'),
                            'lat': float(lat),
                            'lng': float(lng),
                            'org': data.get('org'),
                            'zaman_dilimi': data.get('timezone'),
                            'kaynak': 'ipinfo'
                        }

            except Exception as e:
                continue

        return {}

    def _ip_whois(self, ip: str) -> Dict:
        """IP WHOIS sorgula"""
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap()

            return {
                'asn': result.get('asn'),
                'asn_description': result.get('asn_description'),
                'asn_country_code': result.get('asn_country_code'),
                'network_name': result.get('network', {}).get('name'),
                'network_cidr': result.get('network', {}).get('cidr'),
            }
        except Exception as e:
            return {'hata': str(e)}

    def domain_analiz(self, domain: str) -> OSINTSonuc:
        """Domain analizi"""
        veri = {
            'domain': domain,
            'dns': {},
            'whois': {},
            'ip_adresleri': [],
        }
        kaynaklar = []

        # DNS kayitlari
        if DNS_AKTIF:
            dns_kayitlari = {}
            kayit_tipleri = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

            for rtype in kayit_tipleri:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    dns_kayitlari[rtype] = [str(r) for r in answers]

                    if rtype == 'A':
                        veri['ip_adresleri'] = dns_kayitlari[rtype]
                except:
                    dns_kayitlari[rtype] = []

            veri['dns'] = dns_kayitlari
            kaynaklar.append('dns')

        # WHOIS
        if WHOIS_AKTIF:
            try:
                w = whois.whois(domain)
                veri['whois'] = {
                    'registrar': w.registrar,
                    'creation_date': str(w.creation_date) if w.creation_date else None,
                    'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                    'name_servers': w.name_servers,
                    'org': w.org,
                    'emails': w.emails,
                }
                kaynaklar.append('whois')
            except:
                pass

        # IP'lerden konum al
        konum = None
        if veri['ip_adresleri']:
            ip_sonuc = self.ip_analiz(veri['ip_adresleri'][0])
            if ip_sonuc.konum:
                konum = ip_sonuc.konum
                veri['sunucu_konum'] = ip_sonuc.veri.get('konum', {})

        return OSINTSonuc(
            tip=OSINTTipi.DOMAIN,
            hedef=domain,
            basarili=True,
            veri=veri,
            konum=konum,
            guven_skoru=0.8,
            kaynaklar=kaynaklar
        )


# ==================== MERKEZI OSINT YONETICISI ====================

class OSINTYoneticisi:
    """
    Tum OSINT modullerini koordine eden merkezi sinif
    """

    def __init__(self):
        self.telefon = TelefonOSINT()
        self.email = EmailOSINT()
        self.sosyal = SosyalMedyaOSINT()
        self.adli = AdliBilisim()
        self.network = NetworkOSINT()

        self._sonuc_cache: Dict[str, OSINTSonuc] = {}
        self._executor = ThreadPoolExecutor(max_workers=10)

    def otomatik_tip_tespit(self, hedef: str) -> OSINTTipi:
        """Hedefin tipini otomatik tespit et"""
        hedef = hedef.strip()

        # Email
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', hedef):
            return OSINTTipi.EMAIL

        # IP
        if re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', hedef):
            return OSINTTipi.IP

        # Telefon (+ ile baslayan veya 0 ile baslayan 10+ haneli)
        if hedef.startswith('+') or (hedef.startswith('0') and len(re.sub(r'\D', '', hedef)) >= 10):
            return OSINTTipi.TELEFON

        # Domain (nokta iceren ve bos olmayan)
        if '.' in hedef and not hedef.startswith('@'):
            return OSINTTipi.DOMAIN

        # Varsayilan: kullanici adi
        return OSINTTipi.KULLANICI

    def arastir(self, hedef: str, tip: Optional[OSINTTipi] = None) -> OSINTSonuc:
        """
        Hedefi arastir

        Args:
            hedef: Arastirilacak hedef (telefon, email, IP, domain, username)
            tip: Hedef tipi (None ise otomatik tespit)

        Returns:
            OSINTSonuc: Arastirma sonucu
        """
        if tip is None:
            tip = self.otomatik_tip_tespit(hedef)

        # Cache kontrol
        cache_key = f"{tip.value}:{hedef}"
        if cache_key in self._sonuc_cache:
            cached = self._sonuc_cache[cache_key]
            # 1 saatten eski degilse cache'den don
            if (datetime.now() - cached.zaman).total_seconds() < 3600:
                return cached

        # Uygun modulu cagir
        if tip == OSINTTipi.TELEFON:
            sonuc = self.telefon.analiz_et(hedef)
        elif tip == OSINTTipi.EMAIL:
            sonuc = self.email.analiz_et(hedef)
        elif tip == OSINTTipi.KULLANICI:
            sonuc = self.sosyal.ara(hedef)
        elif tip == OSINTTipi.IP:
            sonuc = self.network.ip_analiz(hedef)
        elif tip == OSINTTipi.DOMAIN:
            sonuc = self.network.domain_analiz(hedef)
        else:
            sonuc = OSINTSonuc(
                tip=tip,
                hedef=hedef,
                basarili=False,
                veri={'hata': 'Desteklenmeyen tip'},
                guven_skoru=0.0
            )

        # Cache'e ekle
        self._sonuc_cache[cache_key] = sonuc

        return sonuc

    def toplu_arastir(self, hedefler: List[str]) -> List[OSINTSonuc]:
        """Birden fazla hedefi paralel arastir"""
        futures = []
        for hedef in hedefler:
            future = self._executor.submit(self.arastir, hedef)
            futures.append(future)

        sonuclar = []
        for future in futures:
            try:
                sonuclar.append(future.result(timeout=120))
            except Exception as e:
                print(f"[OSINT] Arastirma hatasi: {e}")

        return sonuclar

    def harita_verisi_olustur(self, sonuclar: List[OSINTSonuc]) -> List[Dict]:
        """OSINT sonuclarindan harita icin marker verisi olustur"""
        markers = []

        for sonuc in sonuclar:
            if sonuc.konum and sonuc.konum.get('lat') and sonuc.konum.get('lng'):
                marker = {
                    'lat': sonuc.konum['lat'],
                    'lng': sonuc.konum['lng'],
                    'tip': sonuc.tip.value,
                    'baslik': sonuc.hedef,
                    'icerik': self._marker_popup_olustur(sonuc),
                    'ikon': self._tip_ikonu(sonuc.tip),
                    'renk': self._tip_rengi(sonuc.tip),
                    'guven': sonuc.guven_skoru,
                }
                markers.append(marker)

        return markers

    def _marker_popup_olustur(self, sonuc: OSINTSonuc) -> str:
        """Marker popup icerigi olustur"""
        html = f"<strong>{sonuc.hedef}</strong><br>"
        html += f"Tip: {sonuc.tip.value}<br>"
        html += f"Güven: {sonuc.guven_skoru:.0%}<br>"

        if sonuc.tip == OSINTTipi.TELEFON:
            veri = sonuc.veri
            if veri.get('operator'):
                html += f"Operatör: {veri['operator']}<br>"
            if veri.get('ulke'):
                html += f"Ülke: {veri['ulke']}<br>"

        elif sonuc.tip == OSINTTipi.IP:
            veri = sonuc.veri.get('konum', {})
            if veri.get('sehir'):
                html += f"Şehir: {veri['sehir']}<br>"
            if veri.get('isp'):
                html += f"ISP: {veri['isp']}<br>"

        return html

    def _tip_ikonu(self, tip: OSINTTipi) -> str:
        """Tip icin ikon"""
        ikonlar = {
            OSINTTipi.TELEFON: '📱',
            OSINTTipi.EMAIL: '📧',
            OSINTTipi.KULLANICI: '👤',
            OSINTTipi.IP: '🌐',
            OSINTTipi.DOMAIN: '🔗',
            OSINTTipi.DOSYA: '📁',
            OSINTTipi.KONUM: '📍',
        }
        return ikonlar.get(tip, '❓')

    def _tip_rengi(self, tip: OSINTTipi) -> str:
        """Tip icin renk"""
        renkler = {
            OSINTTipi.TELEFON: '#00e5ff',
            OSINTTipi.EMAIL: '#ff9966',
            OSINTTipi.KULLANICI: '#00ff88',
            OSINTTipi.IP: '#ff6666',
            OSINTTipi.DOMAIN: '#ffff66',
            OSINTTipi.DOSYA: '#cc99ff',
            OSINTTipi.KONUM: '#ff66ff',
        }
        return renkler.get(tip, '#ffffff')

    def durum(self) -> Dict:
        """OSINT modulu durumu"""
        return {
            'aktif': True,
            'moduller': {
                'telefon': {
                    'aktif': PHONENUMBERS_AKTIF,
                    'numverify': bool(self.telefon._api_keys.get('numverify')),
                },
                'email': {
                    'holehe': self.email._holehe_mevcut,
                    'hibp': bool(self.email._api_keys.get('hibp')),
                },
                'sosyal': {
                    'sherlock': self.sosyal._sherlock_mevcut,
                    'maigret': self.sosyal._maigret_mevcut,
                },
                'adli': {
                    'exiftool': self.adli._exiftool_mevcut,
                    'virustotal': bool(self.adli._api_keys.get('virustotal')),
                    'pil': PIL_AKTIF,
                },
                'network': {
                    'dns': DNS_AKTIF,
                    'whois': WHOIS_AKTIF,
                    'ipwhois': IPWHOIS_AKTIF,
                    'geoip': self.network._geoip_db is not None,
                },
            },
            'cache_boyutu': len(self._sonuc_cache),
        }


# Global instance
_osint_instance = None

def osint_al() -> OSINTYoneticisi:
    """Global OSINT yoneticisi instance'i al"""
    global _osint_instance
    if _osint_instance is None:
        _osint_instance = OSINTYoneticisi()
    return _osint_instance


# Test
if __name__ == '__main__':
    osint = osint_al()

    print("OSINT Modulu Durumu:")
    print(json.dumps(osint.durum(), indent=2, ensure_ascii=False))

    # Test: Telefon
    print("\n--- Telefon Testi ---")
    sonuc = osint.arastir("+905551234567")
    print(json.dumps(sonuc.to_dict(), indent=2, ensure_ascii=False))

    # Test: IP
    print("\n--- IP Testi ---")
    sonuc = osint.arastir("8.8.8.8")
    print(json.dumps(sonuc.to_dict(), indent=2, ensure_ascii=False))
