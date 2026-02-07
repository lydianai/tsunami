"""
TSUNAMI AI Usage Tracker
========================

AI kullanim istatistiklerini izler ve kaydeder.
CodexBar'dan ilham alinmistir.

Tum veriler yerel SQLite veritabaninda saklanir.
Gizlilik onceliklidir - veri disari akmaz.
"""

import sqlite3
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from pathlib import Path
from collections import defaultdict
import json

logger = logging.getLogger(__name__)


@dataclass
class KullanimKaydi:
    """Tek bir AI kullanim kaydi"""
    model: str
    girdi_token: int
    cikti_token: int
    istek_tipi: str  # 'chat', 'komut', 'analiz'
    basarili: bool
    sure_ms: float  # milisaniye
    zaman: datetime = field(default_factory=datetime.now)

    # Opsiyonel detaylar
    komut: Optional[str] = None
    hata: Optional[str] = None
    oturum_id: Optional[str] = None

    def toplam_token(self) -> int:
        return self.girdi_token + self.cikti_token


class UsageTracker:
    """
    AI Kullanim Takipci

    Ozellikleri:
    - SQLite ile yerel depolama
    - Gunluk/haftalik/aylik istatistikler
    - Model bazinda analiz
    - Maliyet tahmini
    """

    # Varsayilan veritabani yolu
    DB_DIZIN = Path.home() / '.tsunami' / 'data'
    DB_DOSYA = 'ai_usage.db'

    def __init__(self, db_yolu: Optional[str] = None):
        """
        Args:
            db_yolu: Veritabani dosya yolu (None ise varsayilan kullanilir)
        """
        if db_yolu:
            self.db_yolu = Path(db_yolu)
        else:
            self.DB_DIZIN.mkdir(parents=True, exist_ok=True)
            self.db_yolu = self.DB_DIZIN / self.DB_DOSYA

        self._veritabani_olustur()

        # Bellek ici cache (son 100 kayit)
        self._cache: List[KullanimKaydi] = []
        self._cache_limit = 100

    def _veritabani_olustur(self):
        """Veritabani tablolarini olustur"""
        try:
            conn = sqlite3.connect(str(self.db_yolu))
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS kullanim (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    zaman TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    model TEXT NOT NULL,
                    girdi_token INTEGER NOT NULL,
                    cikti_token INTEGER NOT NULL,
                    istek_tipi TEXT NOT NULL,
                    basarili INTEGER NOT NULL,
                    sure_ms REAL NOT NULL,
                    komut TEXT,
                    hata TEXT,
                    oturum_id TEXT
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_zaman ON kullanim(zaman)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_model ON kullanim(model)
            ''')

            conn.commit()
            conn.close()

            logger.info(f"AI kullanim veritabani hazir: {self.db_yolu}")

        except Exception as e:
            logger.error(f"Veritabani olusturma hatasi: {e}")

    def kaydet(self, kayit: KullanimKaydi):
        """
        Kullanim kaydini veritabanina kaydet

        Args:
            kayit: KullanimKaydi nesnesi
        """
        try:
            conn = sqlite3.connect(str(self.db_yolu))
            cursor = conn.cursor()

            cursor.execute('''
                INSERT INTO kullanim
                (zaman, model, girdi_token, cikti_token, istek_tipi,
                 basarili, sure_ms, komut, hata, oturum_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                kayit.zaman.isoformat(),
                kayit.model,
                kayit.girdi_token,
                kayit.cikti_token,
                kayit.istek_tipi,
                1 if kayit.basarili else 0,
                kayit.sure_ms,
                kayit.komut,
                kayit.hata,
                kayit.oturum_id
            ))

            conn.commit()
            conn.close()

            # Cache'e ekle
            self._cache.append(kayit)
            if len(self._cache) > self._cache_limit:
                self._cache.pop(0)

            logger.debug(f"Kullanim kaydedildi: {kayit.model}, {kayit.toplam_token()} token")

        except Exception as e:
            logger.error(f"Kayit hatasi: {e}")

    def gunluk_istatistik(self, gun: datetime = None) -> Dict[str, Any]:
        """
        Belirli bir gunun istatistiklerini getir

        Args:
            gun: Tarih (None ise bugun)

        Returns:
            Istatistik sozlugu
        """
        if gun is None:
            gun = datetime.now()

        gun_baslangic = gun.replace(hour=0, minute=0, second=0, microsecond=0)
        gun_bitis = gun_baslangic + timedelta(days=1)

        return self._donem_istatistik(gun_baslangic, gun_bitis)

    def haftalik_istatistik(self) -> Dict[str, Any]:
        """Son 7 gunun istatistikleri"""
        bitis = datetime.now()
        baslangic = bitis - timedelta(days=7)
        return self._donem_istatistik(baslangic, bitis)

    def aylik_istatistik(self) -> Dict[str, Any]:
        """Son 30 gunun istatistikleri"""
        bitis = datetime.now()
        baslangic = bitis - timedelta(days=30)
        return self._donem_istatistik(baslangic, bitis)

    def _donem_istatistik(self, baslangic: datetime, bitis: datetime) -> Dict[str, Any]:
        """Belirli bir donemin istatistiklerini hesapla"""
        try:
            conn = sqlite3.connect(str(self.db_yolu))
            cursor = conn.cursor()

            # Genel istatistikler
            cursor.execute('''
                SELECT
                    COUNT(*) as toplam_istek,
                    SUM(girdi_token) as toplam_girdi,
                    SUM(cikti_token) as toplam_cikti,
                    AVG(sure_ms) as ort_sure,
                    SUM(CASE WHEN basarili = 1 THEN 1 ELSE 0 END) as basarili_istek
                FROM kullanim
                WHERE zaman BETWEEN ? AND ?
            ''', (baslangic.isoformat(), bitis.isoformat()))

            genel = cursor.fetchone()

            # Model bazinda
            cursor.execute('''
                SELECT
                    model,
                    COUNT(*) as istek,
                    SUM(girdi_token + cikti_token) as token
                FROM kullanim
                WHERE zaman BETWEEN ? AND ?
                GROUP BY model
                ORDER BY token DESC
            ''', (baslangic.isoformat(), bitis.isoformat()))

            model_dagilim = {row[0]: {'istek': row[1], 'token': row[2]}
                           for row in cursor.fetchall()}

            # Istek tipi bazinda
            cursor.execute('''
                SELECT
                    istek_tipi,
                    COUNT(*) as sayi
                FROM kullanim
                WHERE zaman BETWEEN ? AND ?
                GROUP BY istek_tipi
            ''', (baslangic.isoformat(), bitis.isoformat()))

            tip_dagilim = {row[0]: row[1] for row in cursor.fetchall()}

            conn.close()

            toplam_istek = genel[0] or 0
            toplam_girdi = genel[1] or 0
            toplam_cikti = genel[2] or 0
            ort_sure = genel[3] or 0
            basarili_istek = genel[4] or 0

            return {
                'donem': {
                    'baslangic': baslangic.isoformat(),
                    'bitis': bitis.isoformat()
                },
                'toplam': {
                    'istek': toplam_istek,
                    'girdi_token': toplam_girdi,
                    'cikti_token': toplam_cikti,
                    'toplam_token': toplam_girdi + toplam_cikti
                },
                'performans': {
                    'basari_orani': (basarili_istek / toplam_istek * 100) if toplam_istek > 0 else 0,
                    'ortalama_sure_ms': round(ort_sure, 2)
                },
                'model_dagilimi': model_dagilim,
                'tip_dagilimi': tip_dagilim
            }

        except Exception as e:
            logger.error(f"Istatistik hatasi: {e}")
            return {'hata': str(e)}

    def son_kayitlar(self, limit: int = 20) -> List[Dict]:
        """
        Son N kaydi getir

        Args:
            limit: Kayit sayisi

        Returns:
            Kayit listesi
        """
        try:
            conn = sqlite3.connect(str(self.db_yolu))
            cursor = conn.cursor()

            cursor.execute('''
                SELECT zaman, model, girdi_token, cikti_token,
                       istek_tipi, basarili, sure_ms, komut
                FROM kullanim
                ORDER BY zaman DESC
                LIMIT ?
            ''', (limit,))

            kayitlar = []
            for row in cursor.fetchall():
                kayitlar.append({
                    'zaman': row[0],
                    'model': row[1],
                    'girdi_token': row[2],
                    'cikti_token': row[3],
                    'toplam_token': row[2] + row[3],
                    'istek_tipi': row[4],
                    'basarili': bool(row[5]),
                    'sure_ms': row[6],
                    'komut': row[7]
                })

            conn.close()
            return kayitlar

        except Exception as e:
            logger.error(f"Kayit getirme hatasi: {e}")
            return []

    def saatlik_grafik_verisi(self, son_saat: int = 24) -> List[Dict]:
        """
        Saatlik kullanim verisi (grafik icin)

        Args:
            son_saat: Kac saatlik veri

        Returns:
            Saatlik veri listesi
        """
        try:
            conn = sqlite3.connect(str(self.db_yolu))
            cursor = conn.cursor()

            baslangic = datetime.now() - timedelta(hours=son_saat)

            cursor.execute('''
                SELECT
                    strftime('%Y-%m-%d %H:00', zaman) as saat,
                    COUNT(*) as istek,
                    SUM(girdi_token + cikti_token) as token
                FROM kullanim
                WHERE zaman > ?
                GROUP BY saat
                ORDER BY saat ASC
            ''', (baslangic.isoformat(),))

            veri = []
            for row in cursor.fetchall():
                veri.append({
                    'saat': row[0],
                    'istek': row[1],
                    'token': row[2]
                })

            conn.close()
            return veri

        except Exception as e:
            logger.error(f"Grafik verisi hatasi: {e}")
            return []

    def ozet(self) -> Dict[str, Any]:
        """
        Hizli ozet istatistikler

        Returns:
            Ozet sozlugu
        """
        gunluk = self.gunluk_istatistik()
        haftalik = self.haftalik_istatistik()

        return {
            'bugun': {
                'istek': gunluk.get('toplam', {}).get('istek', 0),
                'token': gunluk.get('toplam', {}).get('toplam_token', 0)
            },
            'hafta': {
                'istek': haftalik.get('toplam', {}).get('istek', 0),
                'token': haftalik.get('toplam', {}).get('toplam_token', 0)
            },
            'aktif_model': list(haftalik.get('model_dagilimi', {}).keys())[:3],
            'son_guncelleme': datetime.now().isoformat()
        }

    def temizle(self, gun_once: int = 90):
        """
        Eski kayitlari temizle

        Args:
            gun_once: Kac gunden eski kayitlar silinsin
        """
        try:
            conn = sqlite3.connect(str(self.db_yolu))
            cursor = conn.cursor()

            esik = datetime.now() - timedelta(days=gun_once)

            cursor.execute('''
                DELETE FROM kullanim WHERE zaman < ?
            ''', (esik.isoformat(),))

            silinen = cursor.rowcount
            conn.commit()
            conn.close()

            logger.info(f"{silinen} eski kayit temizlendi")

        except Exception as e:
            logger.error(f"Temizleme hatasi: {e}")


# Global instance
_tracker: Optional[UsageTracker] = None


def tracker_al() -> UsageTracker:
    """Global tracker instance"""
    global _tracker
    if _tracker is None:
        _tracker = UsageTracker()
    return _tracker
