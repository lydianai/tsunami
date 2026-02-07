"""
TSUNAMI AI Cost Calculator
==========================

AI model maliyet hesaplayici.
CodexBar'dan ilham alinmistir.

Desteklenen Modeller:
- GPT4All (yerel, ucretsiz)
- OpenAI (opsiyonel, API)
- Anthropic (opsiyonel, API)
- Groq (opsiyonel, API)

Not: TSUNAMI varsayilan olarak yerel GPT4All kullanir (0 maliyet).
"""

import logging
from typing import Dict, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class ModelFiyat:
    """Model fiyat bilgisi"""
    model_adi: str
    saglayici: str  # 'yerel', 'openai', 'anthropic', 'groq'
    girdi_1k_token: float  # USD per 1K tokens
    cikti_1k_token: float  # USD per 1K tokens
    ucretsiz: bool = False
    notlar: str = ""


# Model fiyat tablosu (Ocak 2025 itibariyle)
MODEL_FIYATLARI: Dict[str, ModelFiyat] = {
    # Yerel modeller (UCRETSIZ)
    'Qwen2.5-7B-Instruct': ModelFiyat(
        model_adi='Qwen2.5-7B-Instruct',
        saglayici='yerel',
        girdi_1k_token=0.0,
        cikti_1k_token=0.0,
        ucretsiz=True,
        notlar='Yerel model, en iyi Turkce'
    ),
    'Qwen2.5-3B-Instruct': ModelFiyat(
        model_adi='Qwen2.5-3B-Instruct',
        saglayici='yerel',
        girdi_1k_token=0.0,
        cikti_1k_token=0.0,
        ucretsiz=True,
        notlar='Hafif yerel model'
    ),
    'Mistral-7B-Instruct': ModelFiyat(
        model_adi='Mistral-7B-Instruct',
        saglayici='yerel',
        girdi_1k_token=0.0,
        cikti_1k_token=0.0,
        ucretsiz=True,
        notlar='Yerel Mistral'
    ),
    'Phi-3-mini': ModelFiyat(
        model_adi='Phi-3-mini',
        saglayici='yerel',
        girdi_1k_token=0.0,
        cikti_1k_token=0.0,
        ucretsiz=True,
        notlar='Cok hafif yerel model'
    ),

    # OpenAI (referans icin)
    'gpt-4-turbo': ModelFiyat(
        model_adi='gpt-4-turbo',
        saglayici='openai',
        girdi_1k_token=0.01,
        cikti_1k_token=0.03,
        ucretsiz=False,
        notlar='En gelismis OpenAI'
    ),
    'gpt-4o-mini': ModelFiyat(
        model_adi='gpt-4o-mini',
        saglayici='openai',
        girdi_1k_token=0.00015,
        cikti_1k_token=0.0006,
        ucretsiz=False,
        notlar='Hafif ve ucuz'
    ),
    'gpt-3.5-turbo': ModelFiyat(
        model_adi='gpt-3.5-turbo',
        saglayici='openai',
        girdi_1k_token=0.0005,
        cikti_1k_token=0.0015,
        ucretsiz=False,
        notlar='Klasik GPT-3.5'
    ),

    # Anthropic (referans icin)
    'claude-3-opus': ModelFiyat(
        model_adi='claude-3-opus',
        saglayici='anthropic',
        girdi_1k_token=0.015,
        cikti_1k_token=0.075,
        ucretsiz=False,
        notlar='En gelismis Claude'
    ),
    'claude-3-sonnet': ModelFiyat(
        model_adi='claude-3-sonnet',
        saglayici='anthropic',
        girdi_1k_token=0.003,
        cikti_1k_token=0.015,
        ucretsiz=False,
        notlar='Dengeli Claude'
    ),
    'claude-3-haiku': ModelFiyat(
        model_adi='claude-3-haiku',
        saglayici='anthropic',
        girdi_1k_token=0.00025,
        cikti_1k_token=0.00125,
        ucretsiz=False,
        notlar='Hizli ve ucuz Claude'
    ),

    # Groq (referans icin)
    'llama-3.3-70b': ModelFiyat(
        model_adi='llama-3.3-70b',
        saglayici='groq',
        girdi_1k_token=0.00059,
        cikti_1k_token=0.00079,
        ucretsiz=False,
        notlar='Cok hizli Llama'
    ),
    'mixtral-8x7b': ModelFiyat(
        model_adi='mixtral-8x7b',
        saglayici='groq',
        girdi_1k_token=0.00024,
        cikti_1k_token=0.00024,
        ucretsiz=False,
        notlar='Hizli Mixtral'
    ),
}


class CostCalculator:
    """
    AI Maliyet Hesaplayici

    Ozellikleri:
    - Model bazinda maliyet hesabi
    - Karsilastirmali analiz
    - Tasarruf hesaplama
    """

    def __init__(self):
        self.fiyatlar = MODEL_FIYATLARI

    def hesapla(self, model: str, girdi_token: int, cikti_token: int) -> Dict:
        """
        Tek bir istek icin maliyet hesapla

        Args:
            model: Model adi
            girdi_token: Girdi token sayisi
            cikti_token: Cikti token sayisi

        Returns:
            Maliyet detaylari
        """
        # Model bilgisini bul
        model_bilgi = self._model_bul(model)

        if not model_bilgi:
            # Bilinmeyen model - yerel varsay
            return {
                'model': model,
                'saglayici': 'bilinmeyen',
                'girdi_maliyet': 0.0,
                'cikti_maliyet': 0.0,
                'toplam_maliyet': 0.0,
                'ucretsiz': True,
                'para_birimi': 'USD'
            }

        # Maliyet hesapla
        girdi_maliyet = (girdi_token / 1000) * model_bilgi.girdi_1k_token
        cikti_maliyet = (cikti_token / 1000) * model_bilgi.cikti_1k_token
        toplam = girdi_maliyet + cikti_maliyet

        return {
            'model': model_bilgi.model_adi,
            'saglayici': model_bilgi.saglayici,
            'girdi_token': girdi_token,
            'cikti_token': cikti_token,
            'girdi_maliyet': round(girdi_maliyet, 6),
            'cikti_maliyet': round(cikti_maliyet, 6),
            'toplam_maliyet': round(toplam, 6),
            'ucretsiz': model_bilgi.ucretsiz,
            'para_birimi': 'USD'
        }

    def karsilastir(self, girdi_token: int, cikti_token: int) -> List[Dict]:
        """
        Ayni istek icin tum modellerin maliyetini karsilastir

        Args:
            girdi_token: Girdi token sayisi
            cikti_token: Cikti token sayisi

        Returns:
            Sirali maliyet listesi
        """
        sonuclar = []

        for model_adi, fiyat in self.fiyatlar.items():
            maliyet = self.hesapla(model_adi, girdi_token, cikti_token)
            sonuclar.append({
                'model': model_adi,
                'saglayici': fiyat.saglayici,
                'maliyet_usd': maliyet['toplam_maliyet'],
                'ucretsiz': fiyat.ucretsiz,
                'notlar': fiyat.notlar
            })

        # Maliyete gore sirala
        sonuclar.sort(key=lambda x: x['maliyet_usd'])

        return sonuclar

    def tasarruf_hesapla(self, kullanim_listesi: List[Dict]) -> Dict:
        """
        Yerel model kullanarak ne kadar tasarruf edildigini hesapla

        Args:
            kullanim_listesi: Kullanim kayitlari

        Returns:
            Tasarruf raporu
        """
        toplam_girdi = sum(k.get('girdi_token', 0) for k in kullanim_listesi)
        toplam_cikti = sum(k.get('cikti_token', 0) for k in kullanim_listesi)

        # Alternatif model maliyetleri
        alternatifler = {
            'gpt-4-turbo': self.hesapla('gpt-4-turbo', toplam_girdi, toplam_cikti),
            'gpt-3.5-turbo': self.hesapla('gpt-3.5-turbo', toplam_girdi, toplam_cikti),
            'claude-3-sonnet': self.hesapla('claude-3-sonnet', toplam_girdi, toplam_cikti),
            'claude-3-haiku': self.hesapla('claude-3-haiku', toplam_girdi, toplam_cikti),
        }

        # En pahali ile karsilastir
        max_maliyet = max(a['toplam_maliyet'] for a in alternatifler.values())

        return {
            'toplam_token': toplam_girdi + toplam_cikti,
            'yerel_maliyet': 0.0,
            'alternatif_maliyetler': {
                k: round(v['toplam_maliyet'], 4)
                for k, v in alternatifler.items()
            },
            'maksimum_tasarruf': round(max_maliyet, 4),
            'aciklama': f"Yerel model kullanarak ${max_maliyet:.4f} tasarruf ettiniz!"
        }

    def aylik_tahmin(self, gunluk_token: int) -> Dict:
        """
        Aylik maliyet tahmini

        Args:
            gunluk_token: Gunluk ortalama token kullanimi

        Returns:
            Aylik tahmin
        """
        aylik_token = gunluk_token * 30

        # Oran: %40 girdi, %60 cikti varsayalim
        girdi = int(aylik_token * 0.4)
        cikti = int(aylik_token * 0.6)

        karsilastirma = self.karsilastir(girdi, cikti)

        return {
            'aylik_token_tahmini': aylik_token,
            'gunluk_ortalama': gunluk_token,
            'yerel_maliyet': 0.0,
            'en_ucuz_api': karsilastirma[1] if len(karsilastirma) > 1 else None,  # 0 yerel
            'en_pahali_api': karsilastirma[-1] if karsilastirma else None,
            'karsilastirma': karsilastirma[:5]  # Ilk 5
        }

    def _model_bul(self, model_adi: str) -> Optional[ModelFiyat]:
        """Model bilgisini bul (esnek arama)"""
        # Tam eslesme
        if model_adi in self.fiyatlar:
            return self.fiyatlar[model_adi]

        # Kismi eslesme
        model_lower = model_adi.lower()
        for adi, fiyat in self.fiyatlar.items():
            if model_lower in adi.lower() or adi.lower() in model_lower:
                return fiyat

        # GPT4All/yerel model varsayimi
        if 'gguf' in model_lower or 'local' in model_lower:
            return ModelFiyat(
                model_adi=model_adi,
                saglayici='yerel',
                girdi_1k_token=0.0,
                cikti_1k_token=0.0,
                ucretsiz=True,
                notlar='Yerel model'
            )

        return None

    def fiyat_listesi(self) -> List[Dict]:
        """Tum model fiyatlarini listele"""
        liste = []
        for adi, fiyat in self.fiyatlar.items():
            liste.append({
                'model': adi,
                'saglayici': fiyat.saglayici,
                'girdi_1k': fiyat.girdi_1k_token,
                'cikti_1k': fiyat.cikti_1k_token,
                'ucretsiz': fiyat.ucretsiz,
                'notlar': fiyat.notlar
            })

        # Saglayiciya gore grupla
        liste.sort(key=lambda x: (not x['ucretsiz'], x['saglayici'], x['girdi_1k']))

        return liste


# Global instance
_calculator: Optional[CostCalculator] = None


def calculator_al() -> CostCalculator:
    """Global calculator instance"""
    global _calculator
    if _calculator is None:
        _calculator = CostCalculator()
    return _calculator
