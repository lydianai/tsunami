"""
TSUNAMI GPT4All Entegrasyonu
============================

Yerel AI asistan modulu - Turkce destekli, harita kontrolu yapabilen.
GPT4All + Qwen 2.5 modeli ile calisir.

Beyaz Sapkali Guvenlik:
- Tum islemler yerel, veri sizintisi yok
- Komut dogrulama ve whitelist
- Kullanici onay gerektiren islemler
"""

from .ai_assistant import TsunamiAIAssistant, ai_asistan_al, ai_asistan_baslat
from .function_tools import HaritaKomutlari, SIGINTKomutlari, KomutYorumcu
from .prompts_tr import SISTEM_PROMPTU, GUVENLIK_KURALLARI

__all__ = [
    'TsunamiAIAssistant',
    'ai_asistan_al',
    'ai_asistan_baslat',
    'HaritaKomutlari',
    'SIGINTKomutlari',
    'KomutYorumcu',
    'SISTEM_PROMPTU',
    'GUVENLIK_KURALLARI'
]

__version__ = '1.0.0'
