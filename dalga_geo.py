#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI Coğrafi Analiz Modülü (dalga_geo.py)
=============================================
GeoPandas tabanlı gerçek zamanlı mekansal analiz sistemi.

Özellikler:
- Kritik altyapı GeoDataFrame yönetimi
- Türkiye il/ilçe sınırları entegrasyonu
- Saldırı noktaları mekansal analizi
- Hotspot tespiti ve clustering
- Mesafe hesaplamaları
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

# Geospatial imports
try:
    import geopandas as gpd
    import pandas as pd
    from shapely.geometry import Point, Polygon, MultiPolygon, LineString
    from shapely.ops import nearest_points, unary_union
    import numpy as np
    GEOPANDAS_AKTIF = True
except ImportError:
    GEOPANDAS_AKTIF = False
    print("[GEO] GeoPandas yuklu degil. pip install geopandas shapely")

# Clustering için
try:
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AKTIF = True
except ImportError:
    SKLEARN_AKTIF = False
    print("[GEO] scikit-learn yuklu degil. pip install scikit-learn")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("TSUNAMI-GEO")

# Veri dizini
DATA_DIR = Path(__file__).parent / "data" / "geo"
DATA_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================================
# TÜRKİYE KRİTİK ALTYAPI VERİLERİ (GERÇEK KOORDİNATLAR)
# ============================================================================

KRITIK_ALTYAPI_VERISI = [
    # ==================== ENERJİ SANTRALLERİ ====================
    {"ad": "Akkuyu Nükleer Santrali", "lat": 36.1444, "lng": 33.5378, "tip": "nukleer", "risk": "kritik", "il": "Mersin", "kapasite": "4800 MW"},
    {"ad": "Afşin-Elbistan A Termik", "lat": 38.2833, "lng": 36.9167, "tip": "termik", "risk": "yuksek", "il": "Kahramanmaraş", "kapasite": "1355 MW"},
    {"ad": "Afşin-Elbistan B Termik", "lat": 38.2900, "lng": 36.9200, "tip": "termik", "risk": "yuksek", "il": "Kahramanmaraş", "kapasite": "1440 MW"},
    {"ad": "Soma Termik Santrali", "lat": 39.1833, "lng": 27.6167, "tip": "termik", "risk": "yuksek", "il": "Manisa", "kapasite": "990 MW"},
    {"ad": "Yeniköy Termik", "lat": 37.0167, "lng": 27.9333, "tip": "termik", "risk": "orta", "il": "Muğla", "kapasite": "420 MW"},
    {"ad": "Atatürk Barajı HES", "lat": 37.5167, "lng": 38.3333, "tip": "hidroelektrik", "risk": "kritik", "il": "Şanlıurfa", "kapasite": "2400 MW"},
    {"ad": "Keban Barajı HES", "lat": 38.7833, "lng": 38.7500, "tip": "hidroelektrik", "risk": "yuksek", "il": "Elazığ", "kapasite": "1330 MW"},
    {"ad": "Ilısu Barajı HES", "lat": 37.5500, "lng": 41.8167, "tip": "hidroelektrik", "risk": "yuksek", "il": "Mardin", "kapasite": "1200 MW"},
    {"ad": "Karakaya Barajı HES", "lat": 38.3667, "lng": 39.1500, "tip": "hidroelektrik", "risk": "yuksek", "il": "Diyarbakır", "kapasite": "1800 MW"},
    {"ad": "Deriner Barajı HES", "lat": 41.3333, "lng": 41.4500, "tip": "hidroelektrik", "risk": "yuksek", "il": "Artvin", "kapasite": "670 MW"},
    {"ad": "TANAP Kompresör İstasyonu", "lat": 40.9833, "lng": 29.8667, "tip": "dogalgaz", "risk": "kritik", "il": "Kocaeli", "kapasite": "16 bcm/yıl"},
    {"ad": "BTC Boru Hattı Ceyhan", "lat": 36.8667, "lng": 35.9500, "tip": "dogalgaz", "risk": "kritik", "il": "Adana", "kapasite": "1.2 mbpd"},

    # ==================== İLETİŞİM VE VERİ MERKEZLERİ ====================
    {"ad": "Türksat Gölbaşı", "lat": 39.7833, "lng": 32.8000, "tip": "iletisim", "risk": "kritik", "il": "Ankara", "aciklama": "Ulusal uydu kontrol merkezi"},
    {"ad": "ULAK Data Center", "lat": 39.9208, "lng": 32.8541, "tip": "veri_merkezi", "risk": "yuksek", "il": "Ankara", "aciklama": "Akademik ağ merkezi"},
    {"ad": "Türk Telekom NOC", "lat": 41.0082, "lng": 28.9784, "tip": "iletisim", "risk": "kritik", "il": "İstanbul", "aciklama": "Ulusal ağ operasyon merkezi"},
    {"ad": "Google Cloud İstanbul", "lat": 41.0422, "lng": 29.0083, "tip": "veri_merkezi", "risk": "yuksek", "il": "İstanbul", "aciklama": "Bulut veri merkezi"},
    {"ad": "Equinix İstanbul", "lat": 41.0150, "lng": 28.9500, "tip": "veri_merkezi", "risk": "yuksek", "il": "İstanbul", "aciklama": "Uluslararası veri merkezi"},

    # ==================== ULAŞIM ALTYAPISI ====================
    {"ad": "İstanbul Havalimanı", "lat": 41.2608, "lng": 28.7428, "tip": "havalimani", "risk": "kritik", "il": "İstanbul", "kapasite": "200M yolcu/yıl"},
    {"ad": "Sabiha Gökçen Havalimanı", "lat": 40.8986, "lng": 29.3092, "tip": "havalimani", "risk": "yuksek", "il": "İstanbul", "kapasite": "41M yolcu/yıl"},
    {"ad": "Esenboğa Havalimanı", "lat": 40.1281, "lng": 32.9950, "tip": "havalimani", "risk": "yuksek", "il": "Ankara", "kapasite": "25M yolcu/yıl"},
    {"ad": "Adnan Menderes Havalimanı", "lat": 38.2924, "lng": 27.1567, "tip": "havalimani", "risk": "orta", "il": "İzmir", "kapasite": "18M yolcu/yıl"},
    {"ad": "Antalya Havalimanı", "lat": 36.8987, "lng": 30.8005, "tip": "havalimani", "risk": "orta", "il": "Antalya", "kapasite": "45M yolcu/yıl"},
    {"ad": "Marmaray Tüneli", "lat": 41.0033, "lng": 29.0167, "tip": "tunel", "risk": "kritik", "il": "İstanbul", "uzunluk": "76.6 km"},
    {"ad": "Avrasya Tüneli", "lat": 40.9897, "lng": 29.0339, "tip": "tunel", "risk": "yuksek", "il": "İstanbul", "uzunluk": "5.4 km"},
    {"ad": "1915 Çanakkale Köprüsü", "lat": 40.2833, "lng": 26.7167, "tip": "kopru", "risk": "kritik", "il": "Çanakkale", "uzunluk": "4.6 km"},
    {"ad": "Fatih Sultan Mehmet Köprüsü", "lat": 41.0856, "lng": 29.0600, "tip": "kopru", "risk": "yuksek", "il": "İstanbul", "uzunluk": "1.5 km"},
    {"ad": "Yavuz Sultan Selim Köprüsü", "lat": 41.2050, "lng": 29.1108, "tip": "kopru", "risk": "yuksek", "il": "İstanbul", "uzunluk": "2.2 km"},
    {"ad": "Osmangazi Köprüsü", "lat": 40.7553, "lng": 29.5050, "tip": "kopru", "risk": "yuksek", "il": "Kocaeli", "uzunluk": "2.7 km"},

    # ==================== LİMAN VE DENİZCİLİK ====================
    {"ad": "Mersin Limanı", "lat": 36.8000, "lng": 34.6333, "tip": "liman", "risk": "kritik", "il": "Mersin", "kapasite": "2.6M TEU/yıl"},
    {"ad": "Ambarlı Limanı", "lat": 40.9833, "lng": 28.6833, "tip": "liman", "risk": "kritik", "il": "İstanbul", "kapasite": "3.1M TEU/yıl"},
    {"ad": "İzmir Alsancak Limanı", "lat": 38.4333, "lng": 27.1333, "tip": "liman", "risk": "yuksek", "il": "İzmir", "kapasite": "1.2M TEU/yıl"},
    {"ad": "Aliağa Petkim Limanı", "lat": 38.7833, "lng": 26.9667, "tip": "liman", "risk": "yuksek", "il": "İzmir", "aciklama": "Petrokimya limanı"},
    {"ad": "İskenderun Limanı", "lat": 36.5833, "lng": 36.1833, "tip": "liman", "risk": "yuksek", "il": "Hatay", "kapasite": "1.0M TEU/yıl"},
    {"ad": "Trabzon Limanı", "lat": 41.0000, "lng": 39.7333, "tip": "liman", "risk": "orta", "il": "Trabzon", "kapasite": "0.3M TEU/yıl"},

    # ==================== BANKA VE FİNANS MERKEZLERİ ====================
    {"ad": "Borsa İstanbul", "lat": 41.1046, "lng": 29.0119, "tip": "finans", "risk": "kritik", "il": "İstanbul", "aciklama": "Ulusal borsa merkezi"},
    {"ad": "TCMB Ankara Merkez", "lat": 39.9208, "lng": 32.8541, "tip": "finans", "risk": "kritik", "il": "Ankara", "aciklama": "Merkez Bankası"},
    {"ad": "TCMB İstanbul Şubesi", "lat": 41.0350, "lng": 28.9850, "tip": "finans", "risk": "kritik", "il": "İstanbul", "aciklama": "Merkez Bankası İstanbul"},
    {"ad": "BDDK Ankara", "lat": 39.9167, "lng": 32.8500, "tip": "finans", "risk": "yuksek", "il": "Ankara", "aciklama": "Bankacılık Denetleme"},
    {"ad": "Ziraat Bankası GM", "lat": 39.9300, "lng": 32.8600, "tip": "banka", "risk": "kritik", "il": "Ankara", "aciklama": "En büyük kamu bankası"},
    {"ad": "Halkbank GM", "lat": 39.9250, "lng": 32.8550, "tip": "banka", "risk": "kritik", "il": "Ankara", "aciklama": "Kamu bankası"},
    {"ad": "VakıfBank GM", "lat": 41.0400, "lng": 29.0100, "tip": "banka", "risk": "kritik", "il": "İstanbul", "aciklama": "Kamu bankası"},
    {"ad": "İş Bankası GM", "lat": 41.0550, "lng": 28.9950, "tip": "banka", "risk": "kritik", "il": "İstanbul", "aciklama": "En büyük özel banka"},
    {"ad": "Garanti BBVA GM", "lat": 41.0800, "lng": 29.0150, "tip": "banka", "risk": "yuksek", "il": "İstanbul", "aciklama": "Özel banka"},
    {"ad": "Yapı Kredi GM", "lat": 41.0650, "lng": 29.0050, "tip": "banka", "risk": "yuksek", "il": "İstanbul", "aciklama": "Özel banka"},
    {"ad": "Akbank GM", "lat": 41.0700, "lng": 29.0100, "tip": "banka", "risk": "yuksek", "il": "İstanbul", "aciklama": "Özel banka"},

    # ==================== HASTANE VE SAĞLIK ====================
    {"ad": "Ankara Şehir Hastanesi", "lat": 39.9600, "lng": 32.7200, "tip": "hastane", "risk": "kritik", "il": "Ankara", "kapasite": "3810 yatak"},
    {"ad": "Başakşehir Çam Sakura", "lat": 41.1200, "lng": 28.7800, "tip": "hastane", "risk": "kritik", "il": "İstanbul", "kapasite": "2682 yatak"},
    {"ad": "Bilkent Şehir Hastanesi", "lat": 39.8700, "lng": 32.7500, "tip": "hastane", "risk": "kritik", "il": "Ankara", "kapasite": "1200 yatak"},
    {"ad": "Hacettepe Üniversitesi Hastanesi", "lat": 39.8667, "lng": 32.7333, "tip": "hastane", "risk": "yuksek", "il": "Ankara", "kapasite": "1500 yatak"},
    {"ad": "İstanbul Üniversitesi Tıp", "lat": 41.0150, "lng": 28.9300, "tip": "hastane", "risk": "yuksek", "il": "İstanbul", "kapasite": "1800 yatak"},

    # ==================== ÜNİVERSİTE VE ARAŞTIRMA ====================
    {"ad": "ODTÜ Kampüsü", "lat": 39.8917, "lng": 32.7833, "tip": "universite", "risk": "yuksek", "il": "Ankara", "ogrenci": "27000"},
    {"ad": "Boğaziçi Üniversitesi", "lat": 41.0833, "lng": 29.0500, "tip": "universite", "risk": "yuksek", "il": "İstanbul", "ogrenci": "16000"},
    {"ad": "İTÜ Maslak Kampüsü", "lat": 41.1050, "lng": 29.0250, "tip": "universite", "risk": "yuksek", "il": "İstanbul", "ogrenci": "32000"},
    {"ad": "TÜBİTAK Gebze", "lat": 40.8000, "lng": 29.4333, "tip": "arastirma", "risk": "kritik", "il": "Kocaeli", "aciklama": "Bilimsel araştırma merkezi"},
    {"ad": "TÜBİTAK UZAY", "lat": 39.8917, "lng": 32.7600, "tip": "arastirma", "risk": "kritik", "il": "Ankara", "aciklama": "Uzay teknolojileri"},
    {"ad": "TAI (TUSAŞ)", "lat": 39.9500, "lng": 32.6833, "tip": "arastirma", "risk": "kritik", "il": "Ankara", "aciklama": "Havacılık ve uzay sanayii"},
    {"ad": "ASELSAN Macunköy", "lat": 39.9667, "lng": 32.7500, "tip": "arastirma", "risk": "kritik", "il": "Ankara", "aciklama": "Savunma elektroniği"},

    # ==================== ASKERİ VE GÜVENLİK ====================
    {"ad": "İncirlik Hava Üssü", "lat": 37.0011, "lng": 35.4258, "tip": "askeri", "risk": "kritik", "il": "Adana", "aciklama": "NATO hava üssü"},
    {"ad": "Aksaz Deniz Üssü", "lat": 36.8167, "lng": 28.4167, "tip": "askeri", "risk": "yuksek", "il": "Muğla", "aciklama": "Deniz Kuvvetleri üssü"},
    {"ad": "Konya 3. Ana Jet Üssü", "lat": 37.9667, "lng": 32.5667, "tip": "askeri", "risk": "yuksek", "il": "Konya", "aciklama": "Hava Kuvvetleri üssü"},
    {"ad": "Diyarbakır 8. Ana Jet Üssü", "lat": 37.8939, "lng": 40.2011, "tip": "askeri", "risk": "yuksek", "il": "Diyarbakır", "aciklama": "Hava Kuvvetleri üssü"},
    {"ad": "İzmir NATO Karargahı", "lat": 38.4192, "lng": 27.1287, "tip": "askeri", "risk": "kritik", "il": "İzmir", "aciklama": "NATO Güneydoğu Avrupa"},
    {"ad": "Gölcük Deniz Üssü", "lat": 40.7167, "lng": 29.8167, "tip": "askeri", "risk": "yuksek", "il": "Kocaeli", "aciklama": "Ana deniz üssü"},

    # ==================== SU VE ALTYAPI ====================
    {"ad": "Melen Barajı", "lat": 40.8833, "lng": 30.4167, "tip": "su", "risk": "yuksek", "il": "Düzce", "aciklama": "İstanbul içme suyu"},
    {"ad": "Öymapınar Barajı", "lat": 36.9167, "lng": 31.4500, "tip": "su", "risk": "yuksek", "il": "Antalya", "aciklama": "Akdeniz su kaynağı"},
    {"ad": "İSKİ Kağıthane", "lat": 41.0833, "lng": 28.9667, "tip": "su", "risk": "kritik", "il": "İstanbul", "aciklama": "İstanbul su idaresi"},
    {"ad": "ASKİ Ankara", "lat": 39.9333, "lng": 32.8667, "tip": "su", "risk": "yuksek", "il": "Ankara", "aciklama": "Ankara su idaresi"},

    # ==================== SİBER GÜVENLİK ====================
    {"ad": "USOM Ankara", "lat": 39.9334, "lng": 32.8597, "tip": "siber", "risk": "kritik", "il": "Ankara", "aciklama": "Ulusal Siber Olaylara Müdahale"},
    {"ad": "BTK Ankara", "lat": 39.9167, "lng": 32.8333, "tip": "siber", "risk": "yuksek", "il": "Ankara", "aciklama": "Bilgi Teknolojileri Kurumu"},
    {"ad": "SSB Siber Güvenlik", "lat": 39.9100, "lng": 32.8400, "tip": "siber", "risk": "kritik", "il": "Ankara", "aciklama": "Savunma Sanayii Başkanlığı"},
    {"ad": "HAVELSAN Siber", "lat": 39.9200, "lng": 32.8300, "tip": "siber", "risk": "yuksek", "il": "Ankara", "aciklama": "Savunma siber güvenlik"},

    # ==================== HÜKÜMET VE DEVLET ====================
    {"ad": "TBMM", "lat": 39.9167, "lng": 32.8500, "tip": "hukumet", "risk": "kritik", "il": "Ankara", "aciklama": "Türkiye Büyük Millet Meclisi"},
    {"ad": "Cumhurbaşkanlığı Külliyesi", "lat": 39.9300, "lng": 32.7900, "tip": "hukumet", "risk": "kritik", "il": "Ankara", "aciklama": "Cumhurbaşkanlığı merkezi"},
    {"ad": "Dışişleri Bakanlığı", "lat": 39.9200, "lng": 32.8450, "tip": "hukumet", "risk": "yuksek", "il": "Ankara", "aciklama": "Dışişleri merkezi"},
    {"ad": "İçişleri Bakanlığı", "lat": 39.9150, "lng": 32.8400, "tip": "hukumet", "risk": "yuksek", "il": "Ankara", "aciklama": "İçişleri merkezi"},
    {"ad": "MSB Bakanlığı", "lat": 39.9100, "lng": 32.8350, "tip": "hukumet", "risk": "kritik", "il": "Ankara", "aciklama": "Milli Savunma Bakanlığı"},
    {"ad": "MİT Genel Müdürlüğü", "lat": 39.9050, "lng": 32.8300, "tip": "hukumet", "risk": "kritik", "il": "Ankara", "aciklama": "Milli İstihbarat Teşkilatı"},
]

# Türkiye illeri merkez koordinatları
TURKIYE_ILLERI = {
    "Adana": {"lat": 37.0000, "lng": 35.3213, "plaka": "01"},
    "Adıyaman": {"lat": 37.7648, "lng": 38.2786, "plaka": "02"},
    "Afyonkarahisar": {"lat": 38.7507, "lng": 30.5567, "plaka": "03"},
    "Ağrı": {"lat": 39.7191, "lng": 43.0503, "plaka": "04"},
    "Amasya": {"lat": 40.6499, "lng": 35.8353, "plaka": "05"},
    "Ankara": {"lat": 39.9334, "lng": 32.8597, "plaka": "06"},
    "Antalya": {"lat": 36.8969, "lng": 30.7133, "plaka": "07"},
    "Artvin": {"lat": 41.1828, "lng": 41.8183, "plaka": "08"},
    "Aydın": {"lat": 37.8560, "lng": 27.8416, "plaka": "09"},
    "Balıkesir": {"lat": 39.6484, "lng": 27.8826, "plaka": "10"},
    "Bilecik": {"lat": 40.0567, "lng": 30.0665, "plaka": "11"},
    "Bingöl": {"lat": 38.8854, "lng": 40.4966, "plaka": "12"},
    "Bitlis": {"lat": 38.4006, "lng": 42.1095, "plaka": "13"},
    "Bolu": {"lat": 40.7360, "lng": 31.6061, "plaka": "14"},
    "Burdur": {"lat": 37.7203, "lng": 30.2908, "plaka": "15"},
    "Bursa": {"lat": 40.1826, "lng": 29.0665, "plaka": "16"},
    "Çanakkale": {"lat": 40.1553, "lng": 26.4142, "plaka": "17"},
    "Çankırı": {"lat": 40.6013, "lng": 33.6134, "plaka": "18"},
    "Çorum": {"lat": 40.5506, "lng": 34.9556, "plaka": "19"},
    "Denizli": {"lat": 37.7765, "lng": 29.0864, "plaka": "20"},
    "Diyarbakır": {"lat": 37.9144, "lng": 40.2306, "plaka": "21"},
    "Edirne": {"lat": 41.6818, "lng": 26.5623, "plaka": "22"},
    "Elazığ": {"lat": 38.6810, "lng": 39.2264, "plaka": "23"},
    "Erzincan": {"lat": 39.7500, "lng": 39.5000, "plaka": "24"},
    "Erzurum": {"lat": 39.9000, "lng": 41.2700, "plaka": "25"},
    "Eskişehir": {"lat": 39.7767, "lng": 30.5206, "plaka": "26"},
    "Gaziantep": {"lat": 37.0662, "lng": 37.3833, "plaka": "27"},
    "Giresun": {"lat": 40.9128, "lng": 38.3895, "plaka": "28"},
    "Gümüşhane": {"lat": 40.4386, "lng": 39.5086, "plaka": "29"},
    "Hakkari": {"lat": 37.5833, "lng": 43.7333, "plaka": "30"},
    "Hatay": {"lat": 36.4018, "lng": 36.3498, "plaka": "31"},
    "Isparta": {"lat": 37.7648, "lng": 30.5566, "plaka": "32"},
    "Mersin": {"lat": 36.8000, "lng": 34.6333, "plaka": "33"},
    "İstanbul": {"lat": 41.0082, "lng": 28.9784, "plaka": "34"},
    "İzmir": {"lat": 38.4192, "lng": 27.1287, "plaka": "35"},
    "Kars": {"lat": 40.6167, "lng": 43.1000, "plaka": "36"},
    "Kastamonu": {"lat": 41.3887, "lng": 33.7827, "plaka": "37"},
    "Kayseri": {"lat": 38.7312, "lng": 35.4787, "plaka": "38"},
    "Kırklareli": {"lat": 41.7333, "lng": 27.2167, "plaka": "39"},
    "Kırşehir": {"lat": 39.1425, "lng": 34.1709, "plaka": "40"},
    "Kocaeli": {"lat": 40.8533, "lng": 29.8815, "plaka": "41"},
    "Konya": {"lat": 37.8667, "lng": 32.4833, "plaka": "42"},
    "Kütahya": {"lat": 39.4167, "lng": 29.9833, "plaka": "43"},
    "Malatya": {"lat": 38.3552, "lng": 38.3095, "plaka": "44"},
    "Manisa": {"lat": 38.6191, "lng": 27.4289, "plaka": "45"},
    "Kahramanmaraş": {"lat": 37.5858, "lng": 36.9371, "plaka": "46"},
    "Mardin": {"lat": 37.3212, "lng": 40.7245, "plaka": "47"},
    "Muğla": {"lat": 37.2153, "lng": 28.3636, "plaka": "48"},
    "Muş": {"lat": 38.9462, "lng": 41.7539, "plaka": "49"},
    "Nevşehir": {"lat": 38.6939, "lng": 34.6857, "plaka": "50"},
    "Niğde": {"lat": 37.9667, "lng": 34.6833, "plaka": "51"},
    "Ordu": {"lat": 40.9839, "lng": 37.8764, "plaka": "52"},
    "Rize": {"lat": 41.0201, "lng": 40.5234, "plaka": "53"},
    "Sakarya": {"lat": 40.6940, "lng": 30.4358, "plaka": "54"},
    "Samsun": {"lat": 41.2867, "lng": 36.3300, "plaka": "55"},
    "Siirt": {"lat": 37.9333, "lng": 41.9500, "plaka": "56"},
    "Sinop": {"lat": 42.0231, "lng": 35.1531, "plaka": "57"},
    "Sivas": {"lat": 39.7477, "lng": 37.0179, "plaka": "58"},
    "Tekirdağ": {"lat": 41.0085, "lng": 27.5119, "plaka": "59"},
    "Tokat": {"lat": 40.3167, "lng": 36.5500, "plaka": "60"},
    "Trabzon": {"lat": 41.0015, "lng": 39.7178, "plaka": "61"},
    "Tunceli": {"lat": 39.1079, "lng": 39.5401, "plaka": "62"},
    "Şanlıurfa": {"lat": 37.1591, "lng": 38.7969, "plaka": "63"},
    "Uşak": {"lat": 38.6823, "lng": 29.4082, "plaka": "64"},
    "Van": {"lat": 38.4891, "lng": 43.4089, "plaka": "65"},
    "Yozgat": {"lat": 39.8181, "lng": 34.8147, "plaka": "66"},
    "Zonguldak": {"lat": 41.4564, "lng": 31.7987, "plaka": "67"},
    "Aksaray": {"lat": 38.3687, "lng": 34.0370, "plaka": "68"},
    "Bayburt": {"lat": 40.2552, "lng": 40.2249, "plaka": "69"},
    "Karaman": {"lat": 37.1759, "lng": 33.2287, "plaka": "70"},
    "Kırıkkale": {"lat": 39.8468, "lng": 33.5153, "plaka": "71"},
    "Batman": {"lat": 37.8812, "lng": 41.1351, "plaka": "72"},
    "Şırnak": {"lat": 37.4187, "lng": 42.4918, "plaka": "73"},
    "Bartın": {"lat": 41.6344, "lng": 32.3375, "plaka": "74"},
    "Ardahan": {"lat": 41.1105, "lng": 42.7022, "plaka": "75"},
    "Iğdır": {"lat": 39.9167, "lng": 44.0333, "plaka": "76"},
    "Yalova": {"lat": 40.6500, "lng": 29.2667, "plaka": "77"},
    "Karabük": {"lat": 41.2061, "lng": 32.6204, "plaka": "78"},
    "Kilis": {"lat": 36.7184, "lng": 37.1212, "plaka": "79"},
    "Osmaniye": {"lat": 37.0746, "lng": 36.2464, "plaka": "80"},
    "Düzce": {"lat": 40.8438, "lng": 31.1565, "plaka": "81"},
}


# ============================================================================
# GEODATAFRAME YÖNETİCİSİ
# ============================================================================

class GeoDataManager:
    """Coğrafi veri yönetim sınıfı"""

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._kritik_altyapi_gdf = None
        self._turkiye_sinir_gdf = None
        self._il_sinir_gdf = None
        self._saldiri_gdf = None
        self._son_saldirilari = []
        self._log = logging.getLogger("GeoDataManager")

    def baslat(self):
        """Tüm veri setlerini yükle"""
        if not GEOPANDAS_AKTIF:
            self._log.error("GeoPandas yüklü değil!")
            return False

        self._kritik_altyapi_yukle()
        self._turkiye_sinir_yukle()
        self._log.info("[GEO] GeoDataManager hazır")
        return True

    def _kritik_altyapi_yukle(self):
        """Kritik altyapı verilerini GeoDataFrame'e dönüştür"""
        if not GEOPANDAS_AKTIF:
            return

        # DataFrame oluştur
        df = pd.DataFrame(KRITIK_ALTYAPI_VERISI)

        # Geometri oluştur
        geometry = [Point(xy) for xy in zip(df['lng'], df['lat'])]

        # GeoDataFrame oluştur (WGS84 - EPSG:4326)
        self._kritik_altyapi_gdf = gpd.GeoDataFrame(
            df,
            geometry=geometry,
            crs="EPSG:4326"
        )

        self._log.info(f"[GEO] {len(self._kritik_altyapi_gdf)} kritik altyapı noktası yüklendi")

    def _turkiye_sinir_yukle(self):
        """Türkiye il sınırlarını yükle veya oluştur"""
        if not GEOPANDAS_AKTIF:
            return

        sinir_dosyasi = DATA_DIR / "turkiye_iller.geojson"

        if sinir_dosyasi.exists():
            try:
                self._il_sinir_gdf = gpd.read_file(sinir_dosyasi)
                # İl merkezlerini ekle
                for idx, row in self._il_sinir_gdf.iterrows():
                    il_adi = row.get('name', '')
                    if il_adi in TURKIYE_ILLERI:
                        self._il_sinir_gdf.at[idx, 'merkez_lat'] = TURKIYE_ILLERI[il_adi]['lat']
                        self._il_sinir_gdf.at[idx, 'merkez_lng'] = TURKIYE_ILLERI[il_adi]['lng']
                        self._il_sinir_gdf.at[idx, 'plaka'] = TURKIYE_ILLERI[il_adi]['plaka']
                self._log.info(f"[GEO] İl sınırları yüklendi: {len(self._il_sinir_gdf)} il (polygon)")
                return
            except Exception as e:
                self._log.warning(f"[GEO] Sınır dosyası okunamadı: {e}")

        # Dosya yoksa basit il noktaları oluştur
        self._il_merkez_olustur()

    def _il_merkez_olustur(self):
        """İl merkezlerinden basit GeoDataFrame oluştur"""
        if not GEOPANDAS_AKTIF:
            return

        il_verileri = []
        for il_ad, il_bilgi in TURKIYE_ILLERI.items():
            il_verileri.append({
                "il": il_ad,
                "lat": il_bilgi["lat"],
                "lng": il_bilgi["lng"],
                "plaka": il_bilgi["plaka"]
            })

        df = pd.DataFrame(il_verileri)
        geometry = [Point(xy) for xy in zip(df['lng'], df['lat'])]

        self._il_sinir_gdf = gpd.GeoDataFrame(
            df,
            geometry=geometry,
            crs="EPSG:4326"
        )

        self._log.info(f"[GEO] {len(self._il_sinir_gdf)} il merkezi oluşturuldu")

    # ========================================================================
    # SALDIRI VERİLERİ
    # ========================================================================

    def saldiri_ekle(self, saldiri_verisi: dict):
        """Yeni saldırı verisini ekle"""
        if not GEOPANDAS_AKTIF:
            return

        self._son_saldirilari.append({
            **saldiri_verisi,
            "zaman": datetime.now().isoformat()
        })

        # Son 1000 saldırıyı tut
        if len(self._son_saldirilari) > 1000:
            self._son_saldirilari = self._son_saldirilari[-1000:]

    def saldiri_gdf_olustur(self) -> Optional[Any]:
        """Saldırı verilerinden GeoDataFrame oluştur"""
        if not GEOPANDAS_AKTIF or not self._son_saldirilari:
            return None

        veriler = []
        for s in self._son_saldirilari:
            hedef = s.get('hedef', {})
            kaynak = s.get('kaynak', {})
            saldiri = s.get('saldiri', {})

            if hedef.get('lat') and hedef.get('lng'):
                veriler.append({
                    'hedef_lat': hedef.get('lat'),
                    'hedef_lng': hedef.get('lng'),
                    'hedef_sehir': hedef.get('sehir', ''),
                    'kaynak_lat': kaynak.get('lat', 0),
                    'kaynak_lng': kaynak.get('lng', 0),
                    'kaynak_ulke': kaynak.get('ulke', ''),
                    'tip': saldiri.get('tip', ''),
                    'ciddiyet': saldiri.get('ciddiyet', 'low'),
                    'zaman': s.get('zaman', '')
                })

        if not veriler:
            return None

        df = pd.DataFrame(veriler)
        geometry = [Point(xy) for xy in zip(df['hedef_lng'], df['hedef_lat'])]

        return gpd.GeoDataFrame(df, geometry=geometry, crs="EPSG:4326")

    # ========================================================================
    # MEKANSAL ANALİZ
    # ========================================================================

    def mesafe_hesapla(self, lat: float, lng: float, tip: str = None) -> List[dict]:
        """Belirli bir noktadan kritik altyapılara mesafe hesapla"""
        if not GEOPANDAS_AKTIF or self._kritik_altyapi_gdf is None:
            return []

        nokta = Point(lng, lat)

        # Projeksiyon (mesafe için UTM kullan - Türkiye için zone 36N)
        gdf_projected = self._kritik_altyapi_gdf.to_crs("EPSG:32636")
        nokta_gdf = gpd.GeoDataFrame(
            {'geometry': [nokta]},
            crs="EPSG:4326"
        ).to_crs("EPSG:32636")

        nokta_projected = nokta_gdf.geometry.iloc[0]

        # Mesafeleri hesapla (metre cinsinden)
        gdf_projected['mesafe_m'] = gdf_projected.geometry.distance(nokta_projected)

        # Filtreleme
        if tip:
            gdf_filtered = gdf_projected[gdf_projected['tip'] == tip]
        else:
            gdf_filtered = gdf_projected

        # En yakın 10 altyapı
        yakin = gdf_filtered.nsmallest(10, 'mesafe_m')

        sonuclar = []
        for _, row in yakin.iterrows():
            sonuclar.append({
                'ad': row['ad'],
                'tip': row['tip'],
                'risk': row['risk'],
                'il': row.get('il', ''),
                'mesafe_km': round(row['mesafe_m'] / 1000, 2),
                'lat': row['lat'],
                'lng': row['lng']
            })

        return sonuclar

    def yakin_altyapi_bul(self, lat: float, lng: float, yaricap_km: float = 50) -> List[dict]:
        """Belirli yarıçap içindeki altyapıları bul"""
        if not GEOPANDAS_AKTIF or self._kritik_altyapi_gdf is None:
            return []

        nokta = Point(lng, lat)

        # Projeksiyon
        gdf_projected = self._kritik_altyapi_gdf.to_crs("EPSG:32636")
        nokta_gdf = gpd.GeoDataFrame(
            {'geometry': [nokta]},
            crs="EPSG:4326"
        ).to_crs("EPSG:32636")

        # Buffer oluştur
        buffer = nokta_gdf.geometry.iloc[0].buffer(yaricap_km * 1000)

        # Kesişenleri bul
        yakin = gdf_projected[gdf_projected.geometry.within(buffer)]

        sonuclar = []
        for _, row in yakin.iterrows():
            mesafe = row.geometry.distance(nokta_gdf.geometry.iloc[0])
            sonuclar.append({
                'ad': row['ad'],
                'tip': row['tip'],
                'risk': row['risk'],
                'il': row.get('il', ''),
                'mesafe_km': round(mesafe / 1000, 2),
                'lat': row['lat'],
                'lng': row['lng']
            })

        return sorted(sonuclar, key=lambda x: x['mesafe_km'])

    def il_bazli_altyapi_sayisi(self) -> Dict[str, dict]:
        """İl bazlı kritik altyapı sayısı"""
        if not GEOPANDAS_AKTIF or self._kritik_altyapi_gdf is None:
            return {}

        il_sayilari = self._kritik_altyapi_gdf.groupby('il').agg({
            'ad': 'count',
            'risk': lambda x: (x == 'kritik').sum()
        }).rename(columns={'ad': 'toplam', 'risk': 'kritik_sayi'})

        sonuc = {}
        for il, row in il_sayilari.iterrows():
            sonuc[il] = {
                'toplam': int(row['toplam']),
                'kritik': int(row['kritik_sayi'])
            }

        return sonuc

    def tip_bazli_istatistik(self) -> Dict[str, int]:
        """Tip bazlı altyapı sayısı"""
        if not GEOPANDAS_AKTIF or self._kritik_altyapi_gdf is None:
            return {}

        return self._kritik_altyapi_gdf['tip'].value_counts().to_dict()

    # ========================================================================
    # HOTSPOT VE CLUSTERING
    # ========================================================================

    def hotspot_analizi(self, min_saldir: int = 3) -> List[dict]:
        """Saldırı yoğunluk noktalarını tespit et"""
        if not GEOPANDAS_AKTIF or not SKLEARN_AKTIF:
            return []

        saldiri_gdf = self.saldiri_gdf_olustur()
        if saldiri_gdf is None or len(saldiri_gdf) < min_saldir:
            return []

        # Koordinatları çıkar
        coords = np.array([[p.x, p.y] for p in saldiri_gdf.geometry])

        # DBSCAN clustering
        # eps: derece cinsinden (yaklaşık 50km için 0.5 derece)
        clustering = DBSCAN(eps=0.5, min_samples=min_saldir).fit(coords)

        saldiri_gdf['cluster'] = clustering.labels_

        hotspotlar = []
        for cluster_id in set(clustering.labels_):
            if cluster_id == -1:  # Noise
                continue

            cluster_points = saldiri_gdf[saldiri_gdf['cluster'] == cluster_id]
            centroid = cluster_points.geometry.unary_union.centroid

            # Ciddiyet dağılımı
            ciddiyet_dagilimi = cluster_points['ciddiyet'].value_counts().to_dict()

            hotspotlar.append({
                'id': cluster_id,
                'lat': centroid.y,
                'lng': centroid.x,
                'saldiri_sayisi': len(cluster_points),
                'ciddiyet_dagilimi': ciddiyet_dagilimi,
                'tip_dagilimi': cluster_points['tip'].value_counts().to_dict(),
                'risk_seviyesi': 'kritik' if ciddiyet_dagilimi.get('critical', 0) >= 2 else 'yuksek'
            })

        return sorted(hotspotlar, key=lambda x: x['saldiri_sayisi'], reverse=True)

    def kmeans_clustering(self, n_clusters: int = 5) -> List[dict]:
        """K-Means ile bölgesel saldırı kümelemesi"""
        if not GEOPANDAS_AKTIF or not SKLEARN_AKTIF:
            return []

        saldiri_gdf = self.saldiri_gdf_olustur()
        if saldiri_gdf is None or len(saldiri_gdf) < n_clusters:
            return []

        coords = np.array([[p.x, p.y] for p in saldiri_gdf.geometry])

        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        saldiri_gdf['cluster'] = kmeans.fit_predict(coords)

        kümeler = []
        for i, center in enumerate(kmeans.cluster_centers_):
            cluster_points = saldiri_gdf[saldiri_gdf['cluster'] == i]

            kümeler.append({
                'id': i,
                'merkez_lat': center[1],
                'merkez_lng': center[0],
                'saldiri_sayisi': len(cluster_points),
                'ciddiyet_dagilimi': cluster_points['ciddiyet'].value_counts().to_dict(),
                'en_sik_tip': cluster_points['tip'].mode().iloc[0] if len(cluster_points) > 0 else ''
            })

        return kümeler

    def altyapi_risk_haritasi(self) -> List[dict]:
        """Kritik altyapı risk haritası - yakın saldırılara göre"""
        if not GEOPANDAS_AKTIF or self._kritik_altyapi_gdf is None:
            return []

        saldiri_gdf = self.saldiri_gdf_olustur()

        risk_haritasi = []
        for _, altyapi in self._kritik_altyapi_gdf.iterrows():
            yakin_saldiri = 0
            kritik_saldiri = 0

            if saldiri_gdf is not None and len(saldiri_gdf) > 0:
                # 100km yarıçapındaki saldırıları say
                for _, saldiri in saldiri_gdf.iterrows():
                    mesafe = altyapi.geometry.distance(saldiri.geometry)
                    if mesafe < 1:  # ~111km
                        yakin_saldiri += 1
                        if saldiri['ciddiyet'] == 'critical':
                            kritik_saldiri += 1

            # Risk skoru hesapla
            temel_risk = {'kritik': 90, 'yuksek': 70, 'orta': 50, 'dusuk': 30}.get(altyapi['risk'], 50)
            saldiri_riski = min(yakin_saldiri * 5 + kritik_saldiri * 15, 50)
            toplam_risk = min(temel_risk + saldiri_riski, 100)

            risk_haritasi.append({
                'ad': altyapi['ad'],
                'tip': altyapi['tip'],
                'il': altyapi.get('il', ''),
                'lat': altyapi['lat'],
                'lng': altyapi['lng'],
                'temel_risk': altyapi['risk'],
                'yakin_saldiri': yakin_saldiri,
                'kritik_saldiri': kritik_saldiri,
                'risk_skoru': toplam_risk
            })

        return sorted(risk_haritasi, key=lambda x: x['risk_skoru'], reverse=True)

    # ========================================================================
    # GELİŞMİŞ MEKANSAL ANALİZ
    # ========================================================================

    def il_icindeki_saldirilari_bul(self, il_adi: str) -> List[dict]:
        """Belirli bir ilin sınırları içindeki saldırıları bul"""
        if not GEOPANDAS_AKTIF or self._il_sinir_gdf is None:
            return []

        saldiri_gdf = self.saldiri_gdf_olustur()
        if saldiri_gdf is None or len(saldiri_gdf) == 0:
            return []

        # İl polygon'unu bul
        il_row = self._il_sinir_gdf[self._il_sinir_gdf['name'] == il_adi]
        if len(il_row) == 0:
            return []

        il_polygon = il_row.geometry.iloc[0]

        # Spatial join yerine geometry.within kullan
        sonuclar = []
        for _, saldiri in saldiri_gdf.iterrows():
            if saldiri.geometry.within(il_polygon):
                sonuclar.append({
                    'hedef_lat': saldiri['hedef_lat'],
                    'hedef_lng': saldiri['hedef_lng'],
                    'hedef_sehir': saldiri.get('hedef_sehir', ''),
                    'kaynak_ulke': saldiri.get('kaynak_ulke', ''),
                    'tip': saldiri.get('tip', ''),
                    'ciddiyet': saldiri.get('ciddiyet', ''),
                    'zaman': saldiri.get('zaman', '')
                })

        return sonuclar

    def il_bazli_saldiri_istatistikleri(self) -> Dict[str, dict]:
        """Her il için saldırı istatistikleri"""
        if not GEOPANDAS_AKTIF or self._il_sinir_gdf is None:
            return {}

        saldiri_gdf = self.saldiri_gdf_olustur()
        if saldiri_gdf is None or len(saldiri_gdf) == 0:
            return {}

        istatistikler = {}

        for _, il_row in self._il_sinir_gdf.iterrows():
            il_adi = il_row.get('name', '')
            il_polygon = il_row.geometry

            # Saldırıları say
            toplam = 0
            kritik = 0
            tipler = {}

            for _, saldiri in saldiri_gdf.iterrows():
                if saldiri.geometry.within(il_polygon):
                    toplam += 1
                    if saldiri.get('ciddiyet') == 'critical':
                        kritik += 1
                    tip = saldiri.get('tip', 'bilinmeyen')
                    tipler[tip] = tipler.get(tip, 0) + 1

            if toplam > 0:
                istatistikler[il_adi] = {
                    'toplam': toplam,
                    'kritik': kritik,
                    'tipler': tipler,
                    'plaka': il_row.get('number', ''),
                    'merkez_lat': il_row.get('merkez_lat', 0),
                    'merkez_lng': il_row.get('merkez_lng', 0)
                }

        return istatistikler

    def saldirilarin_il_dagilimi(self) -> List[dict]:
        """Saldırıların il bazlı dağılımı - choropleth için"""
        if not GEOPANDAS_AKTIF or self._il_sinir_gdf is None:
            return []

        il_stats = self.il_bazli_saldiri_istatistikleri()

        sonuclar = []
        for _, il_row in self._il_sinir_gdf.iterrows():
            il_adi = il_row.get('name', '')
            stats = il_stats.get(il_adi, {'toplam': 0, 'kritik': 0})

            # Risk seviyesi hesapla
            if stats['kritik'] >= 3:
                risk = 'kritik'
            elif stats['toplam'] >= 5:
                risk = 'yuksek'
            elif stats['toplam'] >= 2:
                risk = 'orta'
            elif stats['toplam'] >= 1:
                risk = 'dusuk'
            else:
                risk = 'guvenli'

            sonuclar.append({
                'il': il_adi,
                'plaka': il_row.get('number', ''),
                'saldiri_sayisi': stats['toplam'],
                'kritik_saldiri': stats.get('kritik', 0),
                'risk_seviyesi': risk
            })

        return sorted(sonuclar, key=lambda x: x['saldiri_sayisi'], reverse=True)

    def kaynak_ulke_analizi(self) -> List[dict]:
        """Saldırı kaynak ülke analizi"""
        if not GEOPANDAS_AKTIF:
            return []

        saldiri_gdf = self.saldiri_gdf_olustur()
        if saldiri_gdf is None or len(saldiri_gdf) == 0:
            return []

        ulke_stats = saldiri_gdf.groupby('kaynak_ulke').agg({
            'tip': ['count', lambda x: x.mode().iloc[0] if len(x) > 0 else ''],
            'ciddiyet': lambda x: (x == 'critical').sum()
        }).reset_index()

        ulke_stats.columns = ['ulke', 'toplam', 'en_sik_tip', 'kritik']

        sonuclar = []
        for _, row in ulke_stats.iterrows():
            sonuclar.append({
                'ulke': row['ulke'],
                'toplam': int(row['toplam']),
                'en_sik_tip': row['en_sik_tip'],
                'kritik': int(row['kritik'])
            })

        return sorted(sonuclar, key=lambda x: x['toplam'], reverse=True)

    def zaman_bazli_analiz(self, saat_araligi: int = 1) -> List[dict]:
        """Saldırıların zaman bazlı dağılımı"""
        if not self._son_saldirilari:
            return []

        from collections import defaultdict
        saat_dagilimi = defaultdict(lambda: {'toplam': 0, 'kritik': 0})

        for saldiri in self._son_saldirilari:
            zaman_str = saldiri.get('zaman', '')
            if zaman_str:
                try:
                    zaman = datetime.fromisoformat(zaman_str)
                    saat = (zaman.hour // saat_araligi) * saat_araligi
                    saat_dagilimi[saat]['toplam'] += 1
                    if saldiri.get('saldiri', {}).get('ciddiyet') == 'critical':
                        saat_dagilimi[saat]['kritik'] += 1
                except:
                    pass

        return [{'saat': s, **v} for s, v in sorted(saat_dagilimi.items())]

    def en_tehlikeli_bolgeler(self, limit: int = 10) -> List[dict]:
        """En tehlikeli bölgeler - kritik altyapı + saldırı yoğunluğu"""
        if not GEOPANDAS_AKTIF or self._kritik_altyapi_gdf is None:
            return []

        il_altyapi = self.il_bazli_altyapi_sayisi()
        il_saldiri = self.il_bazli_saldiri_istatistikleri()

        tehlike_skorlari = []
        for il, altyapi_stats in il_altyapi.items():
            saldiri_stats = il_saldiri.get(il, {'toplam': 0, 'kritik': 0})

            # Tehlike skoru = (kritik_altyapi * 10) + (saldiri * 5) + (kritik_saldiri * 15)
            skor = (altyapi_stats['kritik'] * 10) + \
                   (saldiri_stats['toplam'] * 5) + \
                   (saldiri_stats.get('kritik', 0) * 15)

            il_bilgi = TURKIYE_ILLERI.get(il, {})

            tehlike_skorlari.append({
                'il': il,
                'plaka': il_bilgi.get('plaka', ''),
                'lat': il_bilgi.get('lat', 0),
                'lng': il_bilgi.get('lng', 0),
                'kritik_altyapi': altyapi_stats['kritik'],
                'toplam_altyapi': altyapi_stats['toplam'],
                'saldiri_sayisi': saldiri_stats['toplam'],
                'kritik_saldiri': saldiri_stats.get('kritik', 0),
                'tehlike_skoru': skor
            })

        return sorted(tehlike_skorlari, key=lambda x: x['tehlike_skoru'], reverse=True)[:limit]

    def saldiri_yonu_analizi(self) -> List[dict]:
        """Saldırı yön analizi - hangi yönlerden geliyor"""
        if not self._son_saldirilari:
            return []

        # Türkiye merkez koordinatları
        TR_LAT, TR_LNG = 39.0, 35.0

        yonler = {'kuzey': 0, 'guney': 0, 'dogu': 0, 'bati': 0,
                  'kuzeydogu': 0, 'kuzeybati': 0, 'guneydogu': 0, 'guneybati': 0}

        for saldiri in self._son_saldirilari:
            kaynak = saldiri.get('kaynak', {})
            k_lat = kaynak.get('lat', 0)
            k_lng = kaynak.get('lng', 0)

            if k_lat == 0 and k_lng == 0:
                continue

            # Yön belirleme
            lat_fark = k_lat - TR_LAT
            lng_fark = k_lng - TR_LNG

            if abs(lat_fark) > abs(lng_fark) * 2:
                yon = 'kuzey' if lat_fark > 0 else 'guney'
            elif abs(lng_fark) > abs(lat_fark) * 2:
                yon = 'dogu' if lng_fark > 0 else 'bati'
            else:
                yon = ('kuzey' if lat_fark > 0 else 'guney') + \
                      ('dogu' if lng_fark > 0 else 'bati')

            yonler[yon] += 1

        toplam = sum(yonler.values())
        return [{'yon': y, 'sayi': s, 'yuzde': round(s/toplam*100, 1) if toplam > 0 else 0}
                for y, s in sorted(yonler.items(), key=lambda x: x[1], reverse=True)]

    def il_sinirlari_geojson(self) -> dict:
        """İl sınırlarını GeoJSON olarak dışa aktar"""
        if not GEOPANDAS_AKTIF or self._il_sinir_gdf is None:
            return {"type": "FeatureCollection", "features": []}

        return json.loads(self._il_sinir_gdf.to_json())

    # ========================================================================
    # EXPORT FONKSİYONLARI
    # ========================================================================

    def kritik_altyapi_geojson(self) -> dict:
        """Kritik altyapıları GeoJSON olarak dışa aktar"""
        if not GEOPANDAS_AKTIF or self._kritik_altyapi_gdf is None:
            return {"type": "FeatureCollection", "features": []}

        return json.loads(self._kritik_altyapi_gdf.to_json())

    def il_merkezleri_geojson(self) -> dict:
        """İl merkezlerini GeoJSON olarak dışa aktar"""
        if not GEOPANDAS_AKTIF or self._il_sinir_gdf is None:
            return {"type": "FeatureCollection", "features": []}

        return json.loads(self._il_sinir_gdf.to_json())

    def saldiri_geojson(self) -> dict:
        """Saldırıları GeoJSON olarak dışa aktar"""
        saldiri_gdf = self.saldiri_gdf_olustur()
        if saldiri_gdf is None:
            return {"type": "FeatureCollection", "features": []}

        return json.loads(saldiri_gdf.to_json())

    def durum(self) -> dict:
        """Modül durum bilgisi"""
        return {
            'geopandas_aktif': GEOPANDAS_AKTIF,
            'sklearn_aktif': SKLEARN_AKTIF,
            'kritik_altyapi_sayisi': len(self._kritik_altyapi_gdf) if self._kritik_altyapi_gdf is not None else 0,
            'il_sayisi': len(self._il_sinir_gdf) if self._il_sinir_gdf is not None else 0,
            'saldiri_sayisi': len(self._son_saldirilari),
            'hazir': GEOPANDAS_AKTIF and self._kritik_altyapi_gdf is not None
        }


# ============================================================================
# GLOBAL ERİŞİM
# ============================================================================

_geo_manager = None


def geo_manager_al() -> GeoDataManager:
    """GeoDataManager singleton erişimi"""
    global _geo_manager
    if _geo_manager is None:
        _geo_manager = GeoDataManager.get_instance()
        _geo_manager.baslat()
    return _geo_manager


def geo_baslat():
    """Modülü başlat"""
    return geo_manager_al()


# ============================================================================
# TEST
# ============================================================================

if __name__ == "__main__":
    print("TSUNAMI Coğrafi Analiz Modülü Test")
    print("=" * 50)

    geo = geo_baslat()
    durum = geo.durum()
    print(f"Durum: {json.dumps(durum, indent=2, ensure_ascii=False)}")

    if durum['hazir']:
        # Mesafe testi
        print("\n--- İstanbul'dan en yakın altyapılar ---")
        yakin = geo.mesafe_hesapla(41.0082, 28.9784)
        for a in yakin[:5]:
            print(f"  {a['ad']} ({a['tip']}): {a['mesafe_km']} km")

        # İl bazlı istatistik
        print("\n--- İl bazlı altyapı sayısı ---")
        il_stats = geo.il_bazli_altyapi_sayisi()
        for il, sayi in sorted(il_stats.items(), key=lambda x: x[1]['toplam'], reverse=True)[:10]:
            print(f"  {il}: {sayi['toplam']} (kritik: {sayi['kritik']})")

        # Tip bazlı
        print("\n--- Tip bazlı altyapı sayısı ---")
        tip_stats = geo.tip_bazli_istatistik()
        for tip, sayi in sorted(tip_stats.items(), key=lambda x: x[1], reverse=True):
            print(f"  {tip}: {sayi}")
