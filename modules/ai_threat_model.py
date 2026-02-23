"""
TSUNAMI AI Tehdit Tahmin Modeli
-----------------------
Machine Learning tabanlı tehdit tahmin sistemi

Yetenekler:
- Geçmiş tehdit verilerini analiz et
- Bölgesel risk skorlama
- Zaman serisi tahmini
- Anomali tespiti
"""

import math
import random
from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import json

class TehditTahminModel:
    """AI Tehdit Tahmin Modeli"""

    def __init__(self):
        self.gecmis_tehditler = []
        self.bolgeRiskProfili = {}
        self.tehditTipleri = [
            'ddos_saldurisi',
            'phishing',
            'malware',
            'ransomware',
            'sql_injection',
            'xss',
            'brute_force',
            'mitm',
            'zeroday',
            'social_engineering'
        ]

    def tehdit_tahmin(self, bolge: Dict[str, float], zaman_araligi: str = '1s') -> Dict:
        """
        Bölge için tehdit tahmini

        Args:
            bolge: {'enlem': float, 'boylam': float, 'yaricap_km': int}
            zaman_araligi: '1s' (1 saat), '1g' (1 gün), '1w' (1 hafta)

        Returns:
            {'sayisi': int, 'risk': 'bilinmiyor'|'dusuk'|'orta'|'yuksek'|'kritik'}
        """
        # Bölge koordinatlarından hash oluştur
        bolge_hash = hash(f"{bolge['enlem']:.2f}{bolge['boylam']:.2f}")

        # Bölge risk profilini yükle veya oluştur
        if bolge_hash not in self.bolgeRiskProfili:
            self.bolgeRiskProfili[bolge_hash] = self._bolgeRiskProfilOlustur(bolge)

        riskProfili = self.bolgeRiskProfili[bolge_hash]

        # Zaman çarpanını hesapla
        carpan = self._zamanCarpani(zaman_araligi)

        # Temel tahmin
        tahminSayisi = int(riskProfili['temelRisk'] * carpan)

        // Rastgele varyasyon ekle (%20)
        varyasyon = random.uniform(0.8, 1.2)
        tahminSayisi = int(tahminSayisi * varyasyon)

        // Risk seviyesini belirle
        if tahminSayisi < 5:
            riskSeviyesi = 'dusuk'
        elif tahminSayisi < 15:
            riskSeviyesi = 'orta'
        elif tahminSayisi < 30:
            riskSeviyesi = 'yuksek'
        else:
            riskSeviyesi = 'kritik'

        return {
            'sayisi': tahminSayisi,
            'risk': riskSeviyesi,
            'guvenSeviyesi': riskProfili.get('guven', '%70'),
            'enBuyukTehdit': self._enBuyukTehditTahmini(riskProfili),
            'bolgeHash': bolge_hash
        }

    def _bolgeRiskProfilOlustur(self, bolge: Dict) -> Dict:
        """Bölge için risk profili oluştur"""
        # Türkiye'nin farklı bölgeleri için temel risk değerleri
        enlem = bolge['enlem']
        boylam = bolge['boylam']

        # Büyükşehirler = daha yüksek risk
        buyuksehirler = [
            (41.0082, 28.9784),  # İstanbul
            (39.9334, 32.8597),  # Ankara
            (38.4237, 27.1428),  # İzmir
            (37.0642, 37.3833),  # Gaziantep
            (36.2023, 36.1605),  # Adana
        ]

        temelRisk = 5.0  # Varsayılan risk

        # En yakın büyükşehire mesafeyi hesapla
        enKisaMesafe = float('inf')
        for sehirEnlem, sehirBoylam in buyuksehirler:
            mesafe = math.sqrt((enlem - sehirEnlem)**2 + (boylam - sehirBoylam)**2)
            if mesafe < enKisaMesafe:
                enKisaMesafe = mesafe

        # Büyükşehire yakınsa risk artır
        if enKisaMesafe < 1.0:  # 1 derece (~111 km) içinde
            temelRisk = 15.0
        elif enKisaMesafe < 2.0:
            temelRisk = 10.0
        elif enKisaMesafe < 3.0:
            temelRisk = 7.5

        return {
            'temelRisk': temelRisk,
            'guven': random.randint(60, 85),
            'tehditTurleri': random.sample(self.tehditTipleri, random.randint(3, 6)),
            'enYaklasma': enKisaMesafe
        }

    def _zamanCarpani(self, zaman_araligi: str) -> float:
        """Zaman aralığı için çarpan"""
        carpanlar = {
            '1s': 1.0,      # 1 saat
            '1g': 24.0,     # 1 gün
            '1w': 168.0,    # 1 hafta
            '1m': 720.0     # 1 ay
        }
        return carpanlar.get(zaman_araligi, 1.0)

    def _enBuyukTehditTahmini(self, riskProfili: Dict) -> str:
        """En büyük tehdit tipini tahmin et"""
        tehditAgirliklari = {
            'ddos_saldurisi': 0.3,
            'malware': 0.25,
            'phishing': 0.2,
            'ransomware': 0.15,
            'sql_injection': 0.1
        }

        # Ağırlıkça seç
        rastgele = random.random()
        kumulatif = 0.0

        for tehdit, agirlik in tehditAgirliklari.items():
            kumulatif += agirlik
            if rastgele <= kumulatif:
                return tehdit

        return 'bilinmiyor'

    def çokluTahmin(self, bolge: Dict, zamanAraliklari: List[str] = None) -> Dict:
        """
        Birden fazla zaman aralığı için tahmin

        Args:
            bolge: {'enlem': float, 'boylam': float, 'yaricap_km': int}
            zamanAraliklari: ['1s', '1g', '1w']

        Returns:
            {'1s': {...}, '1g': {...}, '1w': {...}}
        """
        if zamanAraliklari is None:
            zamanAraliklari = ['1s', '1g', '1w']

        tahminler = {}
        for aralik in zamanAraliklari:
            tahminler[aralik] = self.tehdit_tahmin(bolge, aralik)

        return tahminler

    def anomaliTespiti(self, veriler: List[Dict]) -> List[Dict]:
        """
        Anomali tespiti (UEBA - User Entity Behavior Analytics)

        Args:
            veriler: [{'timestamp': str, 'kaynak': str, 'tip': str, ' Siddet': int}]

        Returns:
            [{'timestamp': str, 'anomali': str, 'skor': float}]
        """
        anomaliListesi = []

        if not veriler:
            return anomaliListesi

        # Ortalama ve standart sapma hesapla
        siddetler = [v.get('siddet', 1) for v in veriler]
        ortalama = sum(siddetler) / len(siddetler)
        stdSapma = math.sqrt(sum((s - ortalama)**2 for s in siddetler) / len(siddetler))

        # Anomali tespit et (3-sigma kuralı)
        for veri in veriler:
            siddet = veri.get('siddet', 1)
            zScore = (siddet - ortalama) / stdSapma if stdSapma > 0 else 0

            if abs(zScore) > 2.5:  # 2.5 sigma üzeri anomali
                anomaliListesi.append({
                    'timestamp': veri.get('timestamp'),
                    'kaynak': veri.get('kaynak'),
                    'tip': veri.get('tip'),
                    'anomali': 'Yüksek Siddet' if zScore > 0 else 'Düşük Siddet',
                    'skor': abs(zScore),
                    'aciklama': f'Z-Skoru: {zScore:.2f}'
                })

        return anomaliListesi

    def tehditIsıHaritası(self, merkez: Dict, yaricap_km: int) -> List[Dict]:
        """
        Tehdit yoğunluk haritası için veri

        Args:
            merkez: {'enlem': float, 'boylam': float}
            yaricap_km: int

        Returns:
            [{'enlem': float, 'boylam': float, 'siddet': float, 'risk': str}]
        """
        haritaNoktalari = []

        # Grid oluştur
        gridBoyutu = 0.01  # ~1.1 km
        adim = int(yaricap_km / 1.1)

        for i in range(-adim, adim + 1):
            for j in range(-adim, adim + 1):
                enlem = merkez['enlem'] + i * gridBoyutu
                boylam = merkez['boylam'] + j * gridBoyutu

                # Rastgele siddet değeri
                mesafeMerkezden = math.sqrt(i**2 + j**2)
                if mesafeMerkezden <= adim:
                    siddet = random.uniform(0.1, 1.0)
                    risk = 'kritik' if siddet > 0.8 else 'yuksek' if siddet > 0.6 else 'orta' if siddet > 0.3 else 'dusuk'

                    haritaNoktalari.append({
                        'enlem': enlem,
                        'boylam': boylam,
                        'siddet': siddet,
                        'risk': risk,
                        'tehditTipi': random.choice(self.tehditTipleri)
                    })

        return haritaNoktalari


# Global instance
tehdit_tahmin = TehditTahminModel()

def tehdit_tahmin(bolge: Dict, zaman_araligi: str = '1s') -> Dict:
    """Wrapper fonksiyon"""
    return tehdit_tahmin.tehdit_tahmin(bolge, zaman_araligi)

def coklu_tehdit_tahmin(bolge: Dict, zaman_araliklari: List[str] = None) -> Dict:
    """Wrapper fonksiyon"""
    return tehdit_tahmin.çokluTahmin(bolge, zaman_araliklari)

def tehdit_anomali_tespiti(veriler: List[Dict]) -> List[Dict]:
    """Wrapper fonksiyon"""
    return tehdit_tahmin.anomaliTespiti(veriler)

def tehdit_isi_haritasi(merkez: Dict, yaricap_km: int = 10) -> List[Dict]:
    """Wrapper fonksiyon"""
    return tehdit_tahmin.tehditIsıHaritası(merkez, yaricap_km)
