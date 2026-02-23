"""
TSUNAMI AI Asistan
==================

GPT4All tabanli yerel AI asistan.
Turkce destekli, harita ve SIGINT kontrolu yapabilen.

Beyaz Sapkali Guvenlik Prensipleri:
- Tum islemler yerel (veri sizintisi yok)
- Komut dogrulama ve guvenlik kontrolu
- Tehlikeli komutlar engellenir
"""

import os
import json
import logging
import asyncio
from typing import Optional, Dict, Any, List, Generator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .prompts_tr import SISTEM_PROMPTU, GUVENLIK_KURALLARI, YANITLAR
from .function_tools import KomutYorumcu, KomutSonucu, GuvenlikSeviyesi

logger = logging.getLogger(__name__)

# GPT4All import - opsiyonel
try:
    from gpt4all import GPT4All
    GPT4ALL_MEVCUT = True
except ImportError:
    GPT4ALL_MEVCUT = False
    logger.warning("GPT4All yuklu degil. 'pip install gpt4all' ile yukleyin.")


@dataclass
class SohbetMesaji:
    """Sohbet mesaji yapisi"""
    rol: str  # 'kullanici', 'asistan', 'sistem'
    icerik: str
    zaman: datetime = field(default_factory=datetime.now)
    komut_sonucu: Optional[KomutSonucu] = None


@dataclass
class OturumIstatistik:
    """Oturum istatistikleri"""
    toplam_mesaj: int = 0
    toplam_token: int = 0
    baslangic: datetime = field(default_factory=datetime.now)
    komut_sayisi: int = 0
    basarili_komut: int = 0
    hatali_komut: int = 0


class TsunamiAIAssistant:
    """
    TSUNAMI AI Asistan

    Yerel GPT4All modeli ile calisir.
    Harita ve SIGINT kontrolu yapabilir.
    """

    # Onerilen modeller (Turkce destegi icin)
    ONERILEN_MODELLER = [
        'Qwen2.5-7B-Instruct-Q4_K_M.gguf',  # En iyi Turkce
        'Qwen2.5-3B-Instruct-Q4_K_M.gguf',  # Hafif versiyon
        'Mistral-7B-Instruct-v0.3-Q4_K_M.gguf',  # Alternatif
        'Phi-3-mini-4k-instruct.Q4_0.gguf',  # Cok hafif
    ]

    # Model dizini
    MODEL_DIZINI = Path.home() / '.tsunami' / 'models'

    def __init__(self, model_adi: Optional[str] = None, gpu: bool = False):
        """
        AI Asistani baslatir

        Args:
            model_adi: Kullanilacak model (None ise otomatik sec)
            gpu: GPU kullanimi (destekleniyorsa)
        """
        self.model_adi = model_adi
        self.gpu = gpu
        self.model: Optional[Any] = None
        self.aktif = False

        # Sohbet gecmisi
        self.sohbet_gecmisi: List[SohbetMesaji] = []

        # Istatistikler
        self.istatistik = OturumIstatistik()

        # Komut yorumcusu
        self.komut_yorumcu = KomutYorumcu()

        # Guvenlik
        self.guvenlik_kurallari = GUVENLIK_KURALLARI

        # Model dizinini olustur
        self.MODEL_DIZINI.mkdir(parents=True, exist_ok=True)

    def _guvenlik_kontrolu(self, metin: str) -> tuple[bool, str]:
        """
        Guvenlik kontrolu yap

        Returns:
            (guvenli_mi, mesaj)
        """
        metin_lower = metin.lower()

        # Yasakli komutlari kontrol et
        for yasakli in self.guvenlik_kurallari['yasakli_komutlar']:
            if yasakli.lower() in metin_lower:
                return False, f"Guvenlik: '{yasakli}' iceren komutlar engellenmistir."

        return True, "Guvenlik kontrolu gecti"

    def _model_sec(self) -> Optional[str]:
        """Uygun model sec"""
        if self.model_adi:
            return self.model_adi

        # Mevcut modelleri kontrol et
        for model in self.ONERILEN_MODELLER:
            model_path = self.MODEL_DIZINI / model
            if model_path.exists():
                logger.info(f"Model bulundu: {model}")
                return model

        # Varsayilan model
        return self.ONERILEN_MODELLER[0]

    def baslat(self) -> bool:
        """
        AI modelini yukle ve baslat

        Returns:
            Basarili mi
        """
        if not GPT4ALL_MEVCUT:
            logger.error("GPT4All yuklu degil!")
            return False

        try:
            model_adi = self._model_sec()
            logger.info(f"Model yukleniyor: {model_adi}")

            # GPU ayari
            device = 'gpu' if self.gpu else 'cpu'

            self.model = GPT4All(
                model_name=model_adi,
                model_path=str(self.MODEL_DIZINI),
                device=device,
                allow_download=True
            )

            self.aktif = True
            logger.info(f"AI Asistan baslatildi: {model_adi}")

            # Sistem mesajini ekle
            self.sohbet_gecmisi.append(SohbetMesaji(
                rol='sistem',
                icerik=SISTEM_PROMPTU
            ))

            return True

        except Exception as e:
            logger.error(f"AI baslatma hatasi: {e}")
            return False

    def durdur(self):
        """AI modelini durdur"""
        self.model = None
        self.aktif = False
        logger.info("AI Asistan durduruldu")

    def mesaj_gonder(self, mesaj: str) -> Dict[str, Any]:
        """
        Kullanici mesajini isle ve yanit dondur

        Args:
            mesaj: Kullanici mesaji

        Returns:
            {
                'basarili': bool,
                'yanit': str,
                'komut': Optional[KomutSonucu],
                'istatistik': dict
            }
        """
        # Guvenlik kontrolu
        guvenli, guvenlik_mesaj = self._guvenlik_kontrolu(mesaj)
        if not guvenli:
            return {
                'basarili': False,
                'yanit': guvenlik_mesaj,
                'komut': None,
                'istatistik': self._istatistik_al()
            }

        # Kullanici mesajini kaydet
        self.sohbet_gecmisi.append(SohbetMesaji(
            rol='kullanici',
            icerik=mesaj
        ))
        self.istatistik.toplam_mesaj += 1

        # Komut yorumlama dene
        komut_sonucu = self.komut_yorumcu.yorumla(mesaj)
        self.istatistik.komut_sayisi += 1

        if komut_sonucu.basarili:
            self.istatistik.basarili_komut += 1
            yanit = komut_sonucu.mesaj
        else:
            self.istatistik.hatali_komut += 1

            # GPT4All ile yanit uret (varsa)
            if self.aktif and self.model:
                try:
                    # Sohbet oturumu ile yanit
                    with self.model.chat_session(SISTEM_PROMPTU):
                        yanit = self.model.generate(
                            mesaj,
                            max_tokens=500,
                            temp=0.7,
                            top_p=0.9
                        )
                        self.istatistik.toplam_token += len(yanit.split())
                except Exception as e:
                    logger.error(f"AI yanit hatasi: {e}")
                    yanit = komut_sonucu.mesaj
            else:
                yanit = komut_sonucu.mesaj

        # Asistan yanitini kaydet
        self.sohbet_gecmisi.append(SohbetMesaji(
            rol='asistan',
            icerik=yanit,
            komut_sonucu=komut_sonucu if komut_sonucu.basarili else None
        ))

        return {
            'basarili': True,
            'yanit': yanit,
            'komut': komut_sonucu.__dict__ if komut_sonucu.basarili else None,
            'istatistik': self._istatistik_al()
        }

    def akis_mesaj_gonder(self, mesaj: str) -> Generator[str, None, None]:
        """
        Streaming yanit gonder (token token)

        Args:
            mesaj: Kullanici mesaji

        Yields:
            Her token
        """
        # Guvenlik kontrolu
        guvenli, guvenlik_mesaj = self._guvenlik_kontrolu(mesaj)
        if not guvenli:
            yield guvenlik_mesaj
            return

        # Komut kontrolu
        komut_sonucu = self.komut_yorumcu.yorumla(mesaj)
        if komut_sonucu.basarili:
            yield komut_sonucu.mesaj
            return

        # GPT4All streaming
        if self.aktif and self.model:
            try:
                with self.model.chat_session(SISTEM_PROMPTU):
                    for token in self.model.generate(
                        mesaj,
                        max_tokens=500,
                        streaming=True
                    ):
                        yield token
            except Exception as e:
                logger.error(f"Streaming hatasi: {e}")
                yield komut_sonucu.mesaj
        else:
            yield komut_sonucu.mesaj

    def _istatistik_al(self) -> Dict[str, Any]:
        """Istatistikleri dondur"""
        return {
            'toplam_mesaj': self.istatistik.toplam_mesaj,
            'toplam_token': self.istatistik.toplam_token,
            'komut_sayisi': self.istatistik.komut_sayisi,
            'basarili_komut': self.istatistik.basarili_komut,
            'hatali_komut': self.istatistik.hatali_komut,
            'oturum_suresi': (datetime.now() - self.istatistik.baslangic).total_seconds(),
            'model_aktif': self.aktif
        }

    def gecmis_temizle(self):
        """Sohbet gecmisini temizle"""
        self.sohbet_gecmisi = [self.sohbet_gecmisi[0]]  # Sistem mesajini koru
        self.istatistik = OturumIstatistik()

    def gecmis_al(self, son_n: int = 10) -> List[Dict]:
        """
        Son N mesaji dondur

        Args:
            son_n: Alinacak mesaj sayisi

        Returns:
            Mesaj listesi
        """
        mesajlar = self.sohbet_gecmisi[-son_n:] if son_n > 0 else self.sohbet_gecmisi

        return [
            {
                'rol': m.rol,
                'icerik': m.icerik,
                'zaman': m.zaman.isoformat(),
                'komut': m.komut_sonucu.__dict__ if m.komut_sonucu else None
            }
            for m in mesajlar
            if m.rol != 'sistem'  # Sistem mesajini gizle
        ]


# Fallback: GPT4All yoksa basit komut isleyici
class BasitKomutIsleyici:
    """GPT4All olmadan calisabilen basit komut isleyici"""

    def __init__(self):
        self.komut_yorumcu = KomutYorumcu()
        self.istatistik = OturumIstatistik()
        self.sohbet_gecmisi = []

    def mesaj_gonder(self, mesaj: str) -> Dict[str, Any]:
        """Basit komut isleme"""
        komut_sonucu = self.komut_yorumcu.yorumla(mesaj)

        self.istatistik.toplam_mesaj += 1
        self.istatistik.komut_sayisi += 1

        if komut_sonucu.basarili:
            self.istatistik.basarili_komut += 1
        else:
            self.istatistik.hatali_komut += 1

        self.sohbet_gecmisi.append({
            'rol': 'kullanici',
            'icerik': mesaj,
            'zaman': datetime.now().isoformat()
        })

        self.sohbet_gecmisi.append({
            'rol': 'asistan',
            'icerik': komut_sonucu.mesaj,
            'zaman': datetime.now().isoformat(),
            'komut': komut_sonucu.__dict__ if komut_sonucu.basarili else None
        })

        return {
            'basarili': True,
            'yanit': komut_sonucu.mesaj,
            'komut': komut_sonucu.__dict__ if komut_sonucu.basarili else None,
            'istatistik': {
                'toplam_mesaj': self.istatistik.toplam_mesaj,
                'komut_sayisi': self.istatistik.komut_sayisi,
                'basarili_komut': self.istatistik.basarili_komut,
                'model_aktif': False
            }
        }

    def gecmis_al(self, son_n: int = 10) -> List[Dict]:
        """Son N mesaji dondur"""
        mesajlar = self.sohbet_gecmisi[-son_n:] if son_n > 0 else self.sohbet_gecmisi
        return [m for m in mesajlar if m.get('rol') != 'sistem']

    def gecmis_temizle(self):
        """Sohbet gecmisini temizle"""
        self.sohbet_gecmisi = []
        self.istatistik = OturumIstatistik()


# Global instance
_ai_asistan: Optional[TsunamiAIAssistant] = None
_basit_isleyici: Optional[BasitKomutIsleyici] = None


def ai_asistan_al() -> TsunamiAIAssistant:
    """Global AI asistan instance'i dondur"""
    global _ai_asistan, _basit_isleyici

    if GPT4ALL_MEVCUT:
        if _ai_asistan is None:
            _ai_asistan = TsunamiAIAssistant()
        return _ai_asistan
    else:
        if _basit_isleyici is None:
            _basit_isleyici = BasitKomutIsleyici()
        return _basit_isleyici


def ai_asistan_baslat(model_adi: Optional[str] = None, gpu: bool = False) -> bool:
    """AI asistani baslat"""
    global _ai_asistan

    if not GPT4ALL_MEVCUT:
        logger.warning("GPT4All yuklu degil, basit mod kullaniliyor")
        return True

    _ai_asistan = TsunamiAIAssistant(model_adi, gpu)
    return _ai_asistan.baslat()
