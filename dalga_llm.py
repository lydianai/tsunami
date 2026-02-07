#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI LLM v1.0 - Lokal Yapay Zeka Entegrasyonu
================================================================================

    AirLLM ve Transformers ile:
    - Bellek-verimli büyük dil modelleri (4GB GPU'da 70B model)
    - Tehdit analizi ve raporlama
    - BEYIN modülü entegrasyonu
    - Otonom güvenlik değerlendirmesi

================================================================================
"""

import json
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

# Transformers ve AirLLM
TRANSFORMERS_AKTIF = False
AIRLLM_AKTIF = False

try:
    from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline
    import torch
    TRANSFORMERS_AKTIF = True
except ImportError:
    print("[LLM] Transformers bulunamadı")

try:
    from airllm import AutoModel as AirLLMModel
    AIRLLM_AKTIF = True
except ImportError:
    # AirLLM opsiyonel
    pass


class LLMProvider(Enum):
    """LLM sağlayıcı türleri"""
    TRANSFORMERS = "transformers"
    AIRLLM = "airllm"
    OLLAMA = "ollama"


@dataclass
class LLMYanit:
    """LLM yanıt objesi"""
    metin: str
    model: str
    token_sayisi: int
    sure_ms: float
    basarili: bool
    hata: Optional[str] = None


class LokalLLM:
    """
    Lokal LLM Yöneticisi

    Bellek-verimli büyük dil modellerini yönetir.
    AirLLM ile 70B parametreli modeller 4GB GPU'da çalışabilir.
    """

    _instance = None
    _lock = threading.Lock()

    # Önerilen modeller
    MODELLER = {
        'kucuk': {
            'ad': 'microsoft/phi-2',
            'boyut': '2.7B',
            'bellek': '6GB',
            'aciklama': 'Hızlı, hafif model'
        },
        'orta': {
            'ad': 'meta-llama/Llama-3.2-3B-Instruct',
            'boyut': '3B',
            'bellek': '8GB',
            'aciklama': 'Dengeli performans'
        },
        'buyuk': {
            'ad': 'meta-llama/Llama-3.1-8B-Instruct',
            'boyut': '8B',
            'bellek': '16GB',
            'aciklama': 'Yüksek kalite'
        },
        'dev': {
            'ad': 'meta-llama/Llama-3.1-70B-Instruct',
            'boyut': '70B',
            'bellek': '4GB (AirLLM)',
            'aciklama': 'En güçlü, AirLLM gerektirir'
        }
    }

    # Güvenlik analizi promptları
    GUVENLIK_PROMPTLARI = {
        'tehdit_analizi': """Aşağıdaki siber tehdit verisini analiz et ve Türkçe yanıt ver:

{veri}

Analiz formatı:
1. TEHDİT TİPİ: [tehdit türü]
2. CİDDİYET: [kritik/yüksek/orta/düşük]
3. ETKİ: [potansiyel etkiler]
4. ÖNERİLER: [alınması gereken aksiyonlar]
5. IOC: [göstergeler varsa]

Kısa ve öz ol, maksimum 200 kelime.""",

        'zafiyet_analizi': """Bu güvenlik açığını değerlendir:

{veri}

CVSS skoru tahmin et ve açıkla:
- Saldırı vektörü
- Karmaşıklık
- Gerekli yetkiler
- Etki (gizlilik, bütünlük, erişilebilirlik)

Maksimum 150 kelime.""",

        'log_analizi': """Aşağıdaki log kayıtlarını güvenlik açısından analiz et:

{veri}

Tespit et:
1. Anormal aktiviteler
2. Potansiyel saldırı göstergeleri
3. Şüpheli IP/kullanıcı/işlemler
4. Önerilen aksiyon

Maksimum 200 kelime.""",

        'rapor_olustur': """Güvenlik durumu raporu oluştur:

{veri}

Rapor bölümleri:
1. ÖZET (2-3 cümle)
2. TEHDİT DURUMU
3. RİSK SEVİYESİ
4. ÖNCELİKLİ AKSİYONLAR
5. ÖNERİLER

Profesyonel ve teknik dil kullan."""
    }

    @classmethod
    def get_instance(cls) -> 'LokalLLM':
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._model = None
        self._tokenizer = None
        self._pipeline = None
        self._model_adi: Optional[str] = None
        self._provider: Optional[LLMProvider] = None
        self._yuklendi = False
        self._device = None
        self._yuklenme_zamani: Optional[datetime] = None

        # İstatistikler
        self._toplam_istek = 0
        self._toplam_token = 0
        self._ortalama_sure = 0.0

    def mevcut_modeller(self) -> Dict[str, Any]:
        """Mevcut model listesi"""
        return self.MODELLER

    def durum(self) -> Dict[str, Any]:
        """LLM durumu"""
        return {
            'yuklendi': self._yuklendi,
            'model': self._model_adi,
            'provider': self._provider.value if self._provider else None,
            'device': str(self._device) if self._device else None,
            'yuklenme_zamani': self._yuklenme_zamani.isoformat() if self._yuklenme_zamani else None,
            'istatistikler': {
                'toplam_istek': self._toplam_istek,
                'toplam_token': self._toplam_token,
                'ortalama_sure_ms': round(self._ortalama_sure, 2)
            },
            'transformers_aktif': TRANSFORMERS_AKTIF,
            'airllm_aktif': AIRLLM_AKTIF
        }

    def yukle(self, model_adi: str = None, provider: str = 'transformers') -> Dict[str, Any]:
        """
        LLM modelini yükle

        Args:
            model_adi: Model adı (HuggingFace formatı) veya preset ('kucuk', 'orta', 'buyuk', 'dev')
            provider: 'transformers' veya 'airllm'
        """
        if not TRANSFORMERS_AKTIF and provider == 'transformers':
            return {'basarili': False, 'hata': 'Transformers kütüphanesi yüklü değil. pip install transformers torch'}

        if provider == 'airllm' and not AIRLLM_AKTIF:
            return {'basarili': False, 'hata': 'AirLLM kütüphanesi yüklü değil. pip install airllm'}

        # Preset kontrolü
        if model_adi in self.MODELLER:
            model_adi = self.MODELLER[model_adi]['ad']
        elif model_adi is None:
            model_adi = self.MODELLER['orta']['ad']

        try:
            print(f"[LLM] {model_adi} yükleniyor ({provider})...")

            if provider == 'airllm':
                # AirLLM - bellek verimli yükleme
                self._model = AirLLMModel.from_pretrained(model_adi)
                self._provider = LLMProvider.AIRLLM
                self._device = 'airllm'  # AirLLM kendi yönetir

            else:
                # Transformers - standart yükleme
                self._device = torch.device(
                    'cuda' if torch.cuda.is_available() else
                    'mps' if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available() else
                    'cpu'
                )

                self._tokenizer = AutoTokenizer.from_pretrained(model_adi)
                self._model = AutoModelForCausalLM.from_pretrained(
                    model_adi,
                    torch_dtype=torch.float16 if self._device.type != 'cpu' else torch.float32,
                    device_map='auto',
                    trust_remote_code=True
                )

                # Pipeline oluştur
                self._pipeline = pipeline(
                    "text-generation",
                    model=self._model,
                    tokenizer=self._tokenizer,
                    device_map='auto'
                )

                self._provider = LLMProvider.TRANSFORMERS

            self._model_adi = model_adi
            self._yuklendi = True
            self._yuklenme_zamani = datetime.now()

            print(f"[LLM] Model yüklendi: {model_adi}")

            return {
                'basarili': True,
                'model': model_adi,
                'provider': provider,
                'device': str(self._device)
            }

        except Exception as e:
            self._yuklendi = False
            return {'basarili': False, 'hata': str(e)}

    def olustur(self, prompt: str, max_tokens: int = 256, temperature: float = 0.7) -> LLMYanit:
        """
        Metin oluştur

        Args:
            prompt: Giriş metni
            max_tokens: Maksimum çıktı token sayısı
            temperature: Yaratıcılık (0-1)
        """
        if not self._yuklendi:
            return LLMYanit(
                metin="",
                model="",
                token_sayisi=0,
                sure_ms=0,
                basarili=False,
                hata="Model yüklenmemiş"
            )

        baslangic = datetime.now()

        try:
            if self._provider == LLMProvider.AIRLLM:
                # AirLLM ile oluştur
                input_ids = self._tokenizer(prompt, return_tensors="pt").input_ids
                output = self._model.generate(
                    input_ids,
                    max_new_tokens=max_tokens,
                    do_sample=True,
                    temperature=temperature
                )
                metin = self._tokenizer.decode(output[0], skip_special_tokens=True)
                # Prompt'u çıkar
                metin = metin[len(prompt):].strip()

            else:
                # Transformers pipeline ile oluştur
                outputs = self._pipeline(
                    prompt,
                    max_new_tokens=max_tokens,
                    do_sample=True,
                    temperature=temperature,
                    pad_token_id=self._tokenizer.eos_token_id,
                    return_full_text=False
                )
                metin = outputs[0]['generated_text'].strip()

            bitis = datetime.now()
            sure_ms = (bitis - baslangic).total_seconds() * 1000

            # İstatistikleri güncelle
            self._toplam_istek += 1
            token_sayisi = len(metin.split())
            self._toplam_token += token_sayisi
            self._ortalama_sure = (self._ortalama_sure * (self._toplam_istek - 1) + sure_ms) / self._toplam_istek

            return LLMYanit(
                metin=metin,
                model=self._model_adi,
                token_sayisi=token_sayisi,
                sure_ms=sure_ms,
                basarili=True
            )

        except Exception as e:
            return LLMYanit(
                metin="",
                model=self._model_adi or "",
                token_sayisi=0,
                sure_ms=0,
                basarili=False,
                hata=str(e)
            )

    def analiz_et(self, veri: Dict[str, Any], analiz_tipi: str = 'tehdit_analizi') -> Dict[str, Any]:
        """
        Güvenlik analizi yap

        Args:
            veri: Analiz edilecek veri
            analiz_tipi: 'tehdit_analizi', 'zafiyet_analizi', 'log_analizi', 'rapor_olustur'
        """
        if analiz_tipi not in self.GUVENLIK_PROMPTLARI:
            return {'basarili': False, 'hata': f'Bilinmeyen analiz tipi: {analiz_tipi}'}

        # Prompt hazırla
        veri_str = json.dumps(veri, ensure_ascii=False, indent=2) if isinstance(veri, dict) else str(veri)
        prompt = self.GUVENLIK_PROMPTLARI[analiz_tipi].format(veri=veri_str)

        # Oluştur
        yanit = self.olustur(prompt, max_tokens=512, temperature=0.3)

        return {
            'basarili': yanit.basarili,
            'analiz_tipi': analiz_tipi,
            'sonuc': yanit.metin,
            'model': yanit.model,
            'sure_ms': yanit.sure_ms,
            'hata': yanit.hata
        }

    def tehdit_analizi(self, tehdit: Dict[str, Any]) -> Dict[str, Any]:
        """Tehdit analizi kısayolu"""
        return self.analiz_et(tehdit, 'tehdit_analizi')

    def zafiyet_analizi(self, zafiyet: Dict[str, Any]) -> Dict[str, Any]:
        """Zafiyet analizi kısayolu"""
        return self.analiz_et(zafiyet, 'zafiyet_analizi')

    def log_analizi(self, loglar: List[str]) -> Dict[str, Any]:
        """Log analizi kısayolu"""
        return self.analiz_et({'loglar': loglar}, 'log_analizi')

    def rapor_olustur(self, durum: Dict[str, Any]) -> Dict[str, Any]:
        """Güvenlik raporu oluştur"""
        return self.analiz_et(durum, 'rapor_olustur')

    def bosalt(self):
        """Modeli bellekten kaldır"""
        if self._model is not None:
            del self._model
            self._model = None

        if self._tokenizer is not None:
            del self._tokenizer
            self._tokenizer = None

        if self._pipeline is not None:
            del self._pipeline
            self._pipeline = None

        self._yuklendi = False
        self._model_adi = None

        # GPU belleğini temizle
        if TRANSFORMERS_AKTIF:
            import torch
            if torch.cuda.is_available():
                torch.cuda.empty_cache()

        return {'basarili': True, 'mesaj': 'Model bellekten kaldırıldı'}


# ==================== OLLAMA ENTEGRASYONU ====================

class OllamaLLM:
    """
    Ollama ile lokal LLM

    Ollama sunucusu çalışıyorsa kullanılabilir.
    """

    def __init__(self, host: str = "http://localhost:11434"):
        self.host = host
        self._mevcut_model: Optional[str] = None

    def durum(self) -> Dict[str, Any]:
        """Ollama sunucu durumu"""
        try:
            import urllib.request
            req = urllib.request.Request(f"{self.host}/api/tags")
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                return {
                    'aktif': True,
                    'modeller': [m['name'] for m in data.get('models', [])]
                }
        except:
            return {'aktif': False, 'modeller': []}

    def olustur(self, prompt: str, model: str = "llama3.2", max_tokens: int = 256) -> Dict[str, Any]:
        """Ollama ile metin oluştur"""
        try:
            import urllib.request

            veri = json.dumps({
                'model': model,
                'prompt': prompt,
                'stream': False,
                'options': {
                    'num_predict': max_tokens
                }
            }).encode('utf-8')

            req = urllib.request.Request(
                f"{self.host}/api/generate",
                data=veri,
                headers={'Content-Type': 'application/json'}
            )

            with urllib.request.urlopen(req, timeout=120) as response:
                data = json.loads(response.read().decode())
                return {
                    'basarili': True,
                    'metin': data.get('response', ''),
                    'model': model
                }

        except Exception as e:
            return {'basarili': False, 'hata': str(e)}


# ==================== KOLAYLIK FONKSİYONLARI ====================

def llm_al() -> LokalLLM:
    """Global LLM instance'ı al"""
    return LokalLLM.get_instance()


def ollama_al() -> OllamaLLM:
    """Ollama instance'ı al"""
    return OllamaLLM()


# Test
if __name__ == "__main__":
    print("=" * 60)
    print("TSUNAMI LLM Modülü Test")
    print("=" * 60)

    llm = llm_al()
    print(f"\nDurum: {llm.durum()}")
    print(f"\nMevcut modeller: {list(llm.mevcut_modeller().keys())}")

    # Ollama testi
    ollama = ollama_al()
    ollama_durum = ollama.durum()
    print(f"\nOllama durumu: {ollama_durum}")

    if ollama_durum.get('aktif'):
        print("\nOllama test:")
        yanit = ollama.olustur("Merhaba, sen kimsin?", max_tokens=50)
        print(f"  Yanıt: {yanit}")
