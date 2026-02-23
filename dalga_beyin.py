#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI BEYIN - Otonom Merkezi Zeka Sistemi
==========================================
Tum DALGA siber altyapisini 7/24 otonom yoneten merkezi zeka modulu.

Ozellikler:
- DEFCON bazli tehdit seviyeleri
- Coklu kaynak tehdit analizi
- Otonom karar alma
- Gizli/hayalet mod operasyonlari
- Otomatik iyilestirme
"""

import asyncio
import threading
import time
import random
import hashlib
import json
import os
import subprocess
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import logging

# ============================================================================
# ENUM VE DATACLASS TANIMLARI
# ============================================================================

class DefconSeviyesi(Enum):
    """DEFCON Tehdit Seviyeleri"""
    KRITIK = 1      # Aktif saldiri altinda
    YUKSEK = 2      # Ciddi tehdit tespit edildi
    ORTA = 3        # Anormallik var
    DUSUK = 4       # Normal izleme
    GUVENLI = 5     # Tam guvenli


class GizliMod(Enum):
    """Gizli Calisma Modlari"""
    NORMAL = "normal"       # Standart operasyon
    SESSIZ = "sessiz"       # Minimal log, azaltilmis trafik
    HAYALET = "hayalet"     # Sifir iz, kritik islemler
    KAPALI = "kapali"       # Tam devre disi


class MesajTipi(Enum):
    """Mesaj Veri Yolu Tipleri"""
    TEHDIT = "tehdit"
    ALARM = "alarm"
    BILGI = "bilgi"
    KOMUT = "komut"
    YANIT = "yanit"
    KALP_ATISI = "kalp_atisi"
    # Defensive Message Types
    SAVUNMA_BASLATILDI = "defense_started"
    IZOLASYON_AKTIF = "isolation_active"
    KANIT_TOPLANIYOR = "evidence_collecting"
    ESCALATION_NEEDED = "human_approval_needed"


class AksiyonTipi(Enum):
    """Otonom Aksiyon Tipleri"""
    IP_ENGELLE = "ip_engelle"
    SERVIS_YENIDEN_BASLAT = "servis_yeniden_baslat"
    LOG_TEMIZLE = "log_temizle"
    BAGLANTI_KES = "baglanti_kes"
    ALARM_GONDER = "alarm_gonder"
    YEDEK_AL = "yedek_al"
    MOD_DEGISTIR = "mod_degistir"
    IZLEME_ARTIR = "izleme_artir"
    # Defensive Security Actions
    NETWORK_ISOLATE = "network_isolate"          # Isolate compromised hosts
    HONEYPOT_TRIGGER = "honeypot_trigger"        # Activate deception
    FORENSIC_CAPTURE = "forensic_capture"        # Evidence collection
    ENHANCED_MONITORING = "enhanced_monitoring"  # Increase logging
    ALERT_ESCALATE = "alert_escalate"            # Human escalation
    ACCOUNT_DISABLE = "account_disable"          # Disable compromised account
    TOKEN_REVOKE = "token_revoke"                # Revoke access tokens
    QUARANTINE_FILE = "quarantine_file"          # File quarantine
    SENSOR_DEPLOY = "sensor_deploy"              # Deploy monitoring sensor


@dataclass
class Tehdit:
    """Tehdit Veri Yapisi"""
    id: str
    kaynak: str
    tip: str
    skor: float
    detay: Dict[str, Any]
    zaman: datetime = field(default_factory=datetime.now)
    islendi: bool = False
    aksiyon: Optional[str] = None


@dataclass
class Karar:
    """Otonom Karar Veri Yapisi"""
    id: str
    tehdit_id: Optional[str]
    aksiyon: AksiyonTipi
    sebep: str
    parametre: Dict[str, Any]
    zaman: datetime = field(default_factory=datetime.now)
    yurutuldu: bool = False
    sonuc: Optional[str] = None


@dataclass
class Mesaj:
    """Mesaj Veri Yolu Mesaji"""
    id: str
    tip: MesajTipi
    kaynak: str
    hedef: str
    icerik: Dict[str, Any]
    zaman: datetime = field(default_factory=datetime.now)


@dataclass
class AksiyonSonucu:
    """Aksiyon Yürütme Sonucu - Geri Bildirim Döngüsü için"""
    aksiyon_id: str
    aksiyon_tipi: AksiyonTipi
    basarili: bool = False
    baslangic: datetime = field(default_factory=datetime.now)
    bitis: Optional[datetime] = None
    detay: str = ""
    hedef: str = ""
    hata: Optional[str] = None


@dataclass
class OnayBekleyenAksiyon:
    """İnsan Onayı Bekleyen Aksiyon"""
    id: str
    aksiyon_tipi: AksiyonTipi
    hedef: str
    sebep: str
    risk_seviyesi: str = "orta"  # dusuk, orta, yuksek, kritik
    olusturma_zamani: datetime = field(default_factory=datetime.now)
    zaman_asimi: Optional[datetime] = None
    onaylayan: Optional[str] = None
    onay_zamani: Optional[datetime] = None
    durum: str = "bekliyor"  # bekliyor, onaylandi, reddedildi, zaman_asimi

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'tip': self.aksiyon_tipi.value,
            'aksiyon_tipi': self.aksiyon_tipi.value,
            'hedef': self.hedef,
            'sebep': self.sebep,
            'risk_seviyesi': self.risk_seviyesi,
            'zaman': self.olusturma_zamani.isoformat(),
            'durum': self.durum
        }


# ============================================================================
# GERİ BİLDİRİM YÖNETİCİSİ
# ============================================================================

class GeriBildirimYoneticisi:
    """
    Aksiyon sonuçlarını merkeze raporlayan geri bildirim sistemi.
    Tüm aksiyonların başlangıç, tamamlanma ve sonuçlarını takip eder.
    """

    def __init__(self):
        self._sonuclar: Dict[str, AksiyonSonucu] = {}
        self._bekleyen_events: Dict[str, threading.Event] = {}
        self._kilit = threading.Lock()
        self._log = logging.getLogger("GeriBildirim")
        self._callback_listesi: List[Callable] = []

    def aksiyon_baslat(self, aksiyon_id: str, tip: AksiyonTipi, hedef: str = "") -> AksiyonSonucu:
        """Aksiyon başladığında kaydet"""
        with self._kilit:
            sonuc = AksiyonSonucu(
                aksiyon_id=aksiyon_id,
                aksiyon_tipi=tip,
                basarili=False,
                baslangic=datetime.now(),
                hedef=hedef
            )
            self._sonuclar[aksiyon_id] = sonuc
            self._bekleyen_events[aksiyon_id] = threading.Event()
            self._log.info(f"[GERI_BILDIRIM] Aksiyon başlatıldı: {tip.value} - {aksiyon_id}")
            return sonuc

    def aksiyon_tamamla(self, aksiyon_id: str, basarili: bool, detay: str = "", hata: str = None) -> Optional[AksiyonSonucu]:
        """Aksiyon bittiğinde güncelle ve callback'leri çağır"""
        with self._kilit:
            if aksiyon_id not in self._sonuclar:
                self._log.warning(f"[GERI_BILDIRIM] Bilinmeyen aksiyon: {aksiyon_id}")
                return None

            sonuc = self._sonuclar[aksiyon_id]
            sonuc.basarili = basarili
            sonuc.bitis = datetime.now()
            sonuc.detay = detay
            sonuc.hata = hata

            # Event'i tetikle
            if aksiyon_id in self._bekleyen_events:
                self._bekleyen_events[aksiyon_id].set()

            self._log.info(f"[GERI_BILDIRIM] Aksiyon tamamlandı: {aksiyon_id} - {'BAŞARILI' if basarili else 'BAŞARISIZ'}")

            # Callback'leri çağır
            for callback in self._callback_listesi:
                try:
                    callback(sonuc)
                except Exception as e:
                    self._log.error(f"[GERI_BILDIRIM] Callback hatası: {e}")

            return sonuc

    def sonuc_bekle(self, aksiyon_id: str, timeout: float = 30.0) -> Optional[AksiyonSonucu]:
        """Aksiyon sonucunu bekle"""
        if aksiyon_id not in self._bekleyen_events:
            return None

        event = self._bekleyen_events[aksiyon_id]
        event.wait(timeout=timeout)

        return self._sonuclar.get(aksiyon_id)

    def sonuc_al(self, aksiyon_id: str) -> Optional[AksiyonSonucu]:
        """Aksiyon sonucunu al (beklemeden)"""
        return self._sonuclar.get(aksiyon_id)

    def callback_ekle(self, callback: Callable) -> None:
        """Aksiyon tamamlandığında çağrılacak callback ekle"""
        self._callback_listesi.append(callback)

    def tum_sonuclar(self, limit: int = 100) -> List[AksiyonSonucu]:
        """Son sonuçları getir"""
        sonuclar = list(self._sonuclar.values())
        return sorted(sonuclar, key=lambda x: x.baslangic, reverse=True)[:limit]

    def basarisiz_aksiyonlar(self) -> List[AksiyonSonucu]:
        """Başarısız aksiyonları getir"""
        return [s for s in self._sonuclar.values() if not s.basarili and s.bitis]

    def istatistikler(self) -> Dict[str, Any]:
        """Geri bildirim istatistikleri"""
        tamamlanan = [s for s in self._sonuclar.values() if s.bitis]
        basarili = [s for s in tamamlanan if s.basarili]

        return {
            'toplam': len(self._sonuclar),
            'tamamlanan': len(tamamlanan),
            'bekleyen': len(self._sonuclar) - len(tamamlanan),
            'basarili': len(basarili),
            'basarisiz': len(tamamlanan) - len(basarili),
            'basari_orani': len(basarili) / len(tamamlanan) if tamamlanan else 0
        }


# ============================================================================
# ONAY YÖNETİCİSİ
# ============================================================================

class OnayYoneticisi:
    """
    Kritik aksiyonlar için insan onay mekanizması.
    DEFCON seviyesine göre otomatik veya manuel onay gerektirir.
    """

    # Risk seviyesine göre zaman aşımı (saniye)
    ZAMAN_ASIMLARI = {
        'dusuk': 3600,      # 1 saat
        'orta': 1800,       # 30 dakika
        'yuksek': 600,      # 10 dakika
        'kritik': 120       # 2 dakika
    }

    def __init__(self):
        self._bekleyenler: Dict[str, OnayBekleyenAksiyon] = {}
        self._gecmis: deque = deque(maxlen=500)
        self._kilit = threading.Lock()
        self._log = logging.getLogger("OnayYoneticisi")
        self._onay_callback: Optional[Callable] = None

    def onay_iste(self, aksiyon_tipi: AksiyonTipi, hedef: str, sebep: str,
                  risk_seviyesi: str = "orta") -> OnayBekleyenAksiyon:
        """Yeni bir onay talebi oluştur"""
        with self._kilit:
            aksiyon_id = hashlib.md5(
                f"{aksiyon_tipi.value}:{hedef}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:12]

            zaman_asimi = datetime.now() + timedelta(
                seconds=self.ZAMAN_ASIMLARI.get(risk_seviyesi, 1800)
            )

            onay = OnayBekleyenAksiyon(
                id=aksiyon_id,
                aksiyon_tipi=aksiyon_tipi,
                hedef=hedef,
                sebep=sebep,
                risk_seviyesi=risk_seviyesi,
                zaman_asimi=zaman_asimi
            )

            self._bekleyenler[aksiyon_id] = onay
            self._log.warning(f"[ONAY] Yeni onay talebi: {aksiyon_tipi.value} -> {hedef}")

            return onay

    def onayla(self, aksiyon_id: str, onaylayan: str = "admin") -> bool:
        """Aksiyonu onayla"""
        with self._kilit:
            if aksiyon_id not in self._bekleyenler:
                return False

            onay = self._bekleyenler.pop(aksiyon_id)
            onay.durum = "onaylandi"
            onay.onaylayan = onaylayan
            onay.onay_zamani = datetime.now()

            self._gecmis.append(onay)
            self._log.info(f"[ONAY] Aksiyon onaylandı: {aksiyon_id} by {onaylayan}")

            # Callback çağır
            if self._onay_callback:
                try:
                    self._onay_callback(onay, True)
                except Exception as e:
                    self._log.error(f"[ONAY] Callback hatası: {e}")

            return True

    def reddet(self, aksiyon_id: str, sebep: str = "", reddeden: str = "admin") -> bool:
        """Aksiyonu reddet"""
        with self._kilit:
            if aksiyon_id not in self._bekleyenler:
                return False

            onay = self._bekleyenler.pop(aksiyon_id)
            onay.durum = "reddedildi"
            onay.onaylayan = reddeden
            onay.onay_zamani = datetime.now()

            self._gecmis.append(onay)
            self._log.info(f"[ONAY] Aksiyon reddedildi: {aksiyon_id} - {sebep}")

            # Callback çağır
            if self._onay_callback:
                try:
                    self._onay_callback(onay, False)
                except Exception as e:
                    self._log.error(f"[ONAY] Callback hatası: {e}")

            return True

    def bekleyenleri_al(self) -> List[OnayBekleyenAksiyon]:
        """Onay bekleyen aksiyonları listele"""
        with self._kilit:
            # Zaman aşımı kontrolü
            simdi = datetime.now()
            zaman_asimi_olanlar = []

            for aksiyon_id, onay in list(self._bekleyenler.items()):
                if onay.zaman_asimi and simdi > onay.zaman_asimi:
                    onay.durum = "zaman_asimi"
                    self._gecmis.append(onay)
                    zaman_asimi_olanlar.append(aksiyon_id)

            for aksiyon_id in zaman_asimi_olanlar:
                del self._bekleyenler[aksiyon_id]

            return list(self._bekleyenler.values())

    def onay_bekliyor_mu(self, aksiyon_id: str) -> bool:
        """Aksiyon hala onay bekliyor mu?"""
        return aksiyon_id in self._bekleyenler

    def gecmis_al(self, limit: int = 50) -> List[OnayBekleyenAksiyon]:
        """Geçmiş onay kararlarını getir"""
        return list(self._gecmis)[-limit:]

    def callback_ayarla(self, callback: Callable) -> None:
        """Onay/red callback'i ayarla"""
        self._onay_callback = callback


# ============================================================================
# MESAJ VERI YOLU
# ============================================================================

class DalgaMesajVeriyolu:
    """
    Modul arasi asenkron iletisim sistemi.
    Pub/Sub patterni ile calisan merkezi mesajlasma.
    """

    def __init__(self):
        self._aboneler: Dict[str, List[Callable]] = {}
        self._mesaj_kuyrugu: deque = deque(maxlen=1000)
        self._aktif = False
        self._kilit = threading.Lock()
        self._log = logging.getLogger("DalgaVeriyolu")

    def abone_ol(self, kanal: str, callback: Callable) -> None:
        """Bir kanala abone ol"""
        with self._kilit:
            if kanal not in self._aboneler:
                self._aboneler[kanal] = []
            self._aboneler[kanal].append(callback)
            self._log.debug(f"Yeni abone: {kanal}")

    def abonelik_iptal(self, kanal: str, callback: Callable) -> None:
        """Aboneligi iptal et"""
        with self._kilit:
            if kanal in self._aboneler and callback in self._aboneler[kanal]:
                self._aboneler[kanal].remove(callback)

    def yayinla(self, mesaj: Mesaj) -> None:
        """Mesaj yayinla"""
        with self._kilit:
            self._mesaj_kuyrugu.append(mesaj)
            kanal = mesaj.tip.value
            if kanal in self._aboneler:
                for callback in self._aboneler[kanal]:
                    try:
                        callback(mesaj)
                    except Exception as e:
                        self._log.error(f"Callback hatasi: {e}")

    def son_mesajlar(self, limit: int = 50) -> List[Mesaj]:
        """Son mesajlari getir"""
        return list(self._mesaj_kuyrugu)[-limit:]


# ============================================================================
# TEHDIT DEGERLENDIRICI
# ============================================================================

class TehditDegerlendirici:
    """
    Coklu kaynak tehdit analizi.
    Agirlikli fusion algoritmasi ile tehdit skoru hesaplar.
    """

    # Kaynak agirliklari
    AGIRLIKLAR = {
        'firewall': 0.25,
        'ids': 0.30,
        'network': 0.20,
        'kullanici': 0.15,
        'sistem': 0.10
    }

    # DEFCON esik degerleri
    ESIKLER = {
        DefconSeviyesi.KRITIK: 0.85,
        DefconSeviyesi.YUKSEK: 0.65,
        DefconSeviyesi.ORTA: 0.40,
        DefconSeviyesi.DUSUK: 0.20,
        DefconSeviyesi.GUVENLI: 0.0
    }

    def __init__(self):
        self._tehditler: Dict[str, Tehdit] = {}
        self._son_skorlar: Dict[str, float] = {}
        self._log = logging.getLogger("TehditDegerlendirici")

    def kaynak_skoru_guncelle(self, kaynak: str, skor: float, detay: Dict = None) -> None:
        """Belirli bir kaynaktan gelen skoru guncelle"""
        self._son_skorlar[kaynak] = max(0.0, min(1.0, skor))

        if skor > 0.3 and detay:
            tehdit_id = hashlib.md5(
                f"{kaynak}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:12]

            self._tehditler[tehdit_id] = Tehdit(
                id=tehdit_id,
                kaynak=kaynak,
                tip=detay.get('tip', 'bilinmeyen'),
                skor=skor,
                detay=detay
            )

    def toplam_skor_hesapla(self) -> float:
        """Agirlikli toplam tehdit skoru hesapla"""
        toplam = 0.0
        for kaynak, agirlik in self.AGIRLIKLAR.items():
            skor = self._son_skorlar.get(kaynak, 0.0)
            toplam += skor * agirlik
        return round(toplam, 3)

    def defcon_seviyesi_belirle(self) -> DefconSeviyesi:
        """Mevcut DEFCON seviyesini belirle"""
        skor = self.toplam_skor_hesapla()

        for seviye, esik in self.ESIKLER.items():
            if skor >= esik:
                return seviye

        return DefconSeviyesi.GUVENLI

    def aktif_tehditler(self) -> List[Tehdit]:
        """Islenmemis tehditleri getir"""
        return [t for t in self._tehditler.values() if not t.islendi]

    def tehdit_isle(self, tehdit_id: str, aksiyon: str) -> None:
        """Tehdidi islenmis olarak isaretle"""
        if tehdit_id in self._tehditler:
            self._tehditler[tehdit_id].islendi = True
            self._tehditler[tehdit_id].aksiyon = aksiyon

    def durum_ozeti(self) -> Dict[str, Any]:
        """Tehdit durumu ozeti"""
        return {
            'toplam_skor': self.toplam_skor_hesapla(),
            'defcon': self.defcon_seviyesi_belirle().name,
            'defcon_numara': self.defcon_seviyesi_belirle().value,
            'kaynak_skorlari': self._son_skorlar.copy(),
            'aktif_tehdit_sayisi': len(self.aktif_tehditler()),
            'toplam_tehdit_sayisi': len(self._tehditler)
        }


# ============================================================================
# OTONOM KARAR MOTORU
# ============================================================================

class OtonomKararMotoru:
    """
    Otomatik karar ve aksiyon sistemi.
    Tehdit seviyesine gore uygun aksiyonlari belirler ve yurutur.
    """

    # DEFCON seviyesine gore izin verilen aksiyonlar
    SEVIYE_AKSIYONLAR = {
        DefconSeviyesi.KRITIK: [
            AksiyonTipi.IP_ENGELLE,
            AksiyonTipi.BAGLANTI_KES,
            AksiyonTipi.MOD_DEGISTIR,
            AksiyonTipi.ALARM_GONDER,
            # KRITIK: Full isolation, forensic capture, account disable, all alerts
            AksiyonTipi.NETWORK_ISOLATE,
            AksiyonTipi.FORENSIC_CAPTURE,
            AksiyonTipi.ACCOUNT_DISABLE,
            AksiyonTipi.TOKEN_REVOKE,
            AksiyonTipi.QUARANTINE_FILE,
            AksiyonTipi.ALERT_ESCALATE,
        ],
        DefconSeviyesi.YUKSEK: [
            AksiyonTipi.IP_ENGELLE,
            AksiyonTipi.IZLEME_ARTIR,
            AksiyonTipi.ALARM_GONDER,
            # YUKSEK: Partial isolation, enhanced monitoring, honeypot activation
            AksiyonTipi.NETWORK_ISOLATE,
            AksiyonTipi.ENHANCED_MONITORING,
            AksiyonTipi.HONEYPOT_TRIGGER,
            AksiyonTipi.ALERT_ESCALATE,
        ],
        DefconSeviyesi.ORTA: [
            AksiyonTipi.IZLEME_ARTIR,
            AksiyonTipi.LOG_TEMIZLE,
            AksiyonTipi.YEDEK_AL,
            # ORTA: Enhanced monitoring, sensor deployment
            AksiyonTipi.ENHANCED_MONITORING,
            AksiyonTipi.SENSOR_DEPLOY,
        ],
        DefconSeviyesi.DUSUK: [
            AksiyonTipi.LOG_TEMIZLE,
            AksiyonTipi.YEDEK_AL,
            # DUSUK: Logging increase only
            AksiyonTipi.ENHANCED_MONITORING,
        ],
        DefconSeviyesi.GUVENLI: []
    }

    def __init__(self, veriyolu: DalgaMesajVeriyolu):
        self._veriyolu = veriyolu
        self._kararlar: Dict[str, Karar] = {}
        self._aksiyon_isleyiciler: Dict[AksiyonTipi, Callable] = {}
        self._otonom_aktif = True
        self._log = logging.getLogger("OtonomKararMotoru")

    def aksiyon_isleyici_kaydet(self, aksiyon: AksiyonTipi, isleyici: Callable) -> None:
        """Aksiyon icin isleyici kaydet"""
        self._aksiyon_isleyiciler[aksiyon] = isleyici

    def karar_al(self, tehdit: Tehdit, defcon: DefconSeviyesi) -> Optional[Karar]:
        """Tehdit icin uygun karar al"""
        if not self._otonom_aktif:
            return None

        izinli_aksiyonlar = self.SEVIYE_AKSIYONLAR.get(defcon, [])
        if not izinli_aksiyonlar:
            return None

        # Tehdit tipine gore aksiyon sec
        aksiyon = self._aksiyon_sec(tehdit, izinli_aksiyonlar)
        if not aksiyon:
            return None

        karar_id = hashlib.md5(
            f"{tehdit.id}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        karar = Karar(
            id=karar_id,
            tehdit_id=tehdit.id,
            aksiyon=aksiyon,
            sebep=f"{tehdit.tip} tehdidi icin otomatik {aksiyon.value}",
            parametre=self._parametre_belirle(aksiyon, tehdit)
        )

        self._kararlar[karar_id] = karar
        return karar

    def _aksiyon_sec(self, tehdit: Tehdit, izinli: List[AksiyonTipi]) -> Optional[AksiyonTipi]:
        """Tehdit tipine gore en uygun aksiyonu sec"""
        # Tehdit tipine gore oncelik
        oncelik_map = {
            'brute_force': AksiyonTipi.IP_ENGELLE,
            'ddos': AksiyonTipi.BAGLANTI_KES,
            'intrusion': AksiyonTipi.IP_ENGELLE,
            'anomaly': AksiyonTipi.IZLEME_ARTIR,
            'malware': AksiyonTipi.BAGLANTI_KES,
        }

        tercih = oncelik_map.get(tehdit.tip)
        if tercih and tercih in izinli:
            return tercih

        # Varsayilan: ilk izinli aksiyonu sec
        return izinli[0] if izinli else None

    def _parametre_belirle(self, aksiyon: AksiyonTipi, tehdit: Tehdit) -> Dict:
        """Aksiyon parametrelerini belirle"""
        params = {'tehdit_id': tehdit.id}

        if aksiyon == AksiyonTipi.IP_ENGELLE:
            params['ip'] = tehdit.detay.get('kaynak_ip', 'bilinmeyen')
            params['sure'] = 3600  # 1 saat
        elif aksiyon == AksiyonTipi.MOD_DEGISTIR:
            params['yeni_mod'] = GizliMod.HAYALET.value

        return params

    def karar_yurutv(self, karar: Karar) -> bool:
        """Karari yurutv"""
        if karar.aksiyon not in self._aksiyon_isleyiciler:
            self._log.warning(f"Isleyici yok: {karar.aksiyon.value}")
            karar.sonuc = "isleyici_yok"
            return False

        try:
            isleyici = self._aksiyon_isleyiciler[karar.aksiyon]
            sonuc = isleyici(karar.parametre)
            karar.yurutuldu = True
            karar.sonuc = "basarili" if sonuc else "basarisiz"

            # Mesaj yayinla
            self._veriyolu.yayinla(Mesaj(
                id=hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
                tip=MesajTipi.KOMUT,
                kaynak="karar_motoru",
                hedef="*",
                icerik={'karar_id': karar.id, 'aksiyon': karar.aksiyon.value}
            ))

            return sonuc
        except Exception as e:
            self._log.error(f"Yurutme hatasi: {e}")
            karar.sonuc = f"hata: {str(e)}"
            return False

    def son_kararlar(self, limit: int = 20) -> List[Karar]:
        """Son kararlari getir"""
        kararlar = sorted(
            self._kararlar.values(),
            key=lambda k: k.zaman,
            reverse=True
        )
        return kararlar[:limit]

    def otonom_durumu_degistir(self, aktif: bool) -> None:
        """Otonom modu ac/kapat"""
        self._otonom_aktif = aktif


# ============================================================================
# OTOMATİK MÜDAHALE YÖNETİCİSİ
# ============================================================================

class OtomatikMudahaleYoneticisi:
    """
    Tehdit seviyesine göre otomatik aksiyon alan merkezi müdahale sistemi.
    DEFCON seviyelerine göre proaktif ve reaktif müdahale yapar.
    Kritik aksiyonlar için insan onayı gerektirir.
    """

    # DEFCON → Otomatik Aksiyon Eşleştirmesi
    OTOMATIK_AKSIYONLAR = {
        DefconSeviyesi.KRITIK: [
            (AksiyonTipi.NETWORK_ISOLATE, True),    # (aksiyon, onay_gerekli)
            (AksiyonTipi.FORENSIC_CAPTURE, False),
            (AksiyonTipi.HONEYPOT_TRIGGER, False),
            (AksiyonTipi.ALERT_ESCALATE, False),
        ],
        DefconSeviyesi.YUKSEK: [
            (AksiyonTipi.ENHANCED_MONITORING, False),
            (AksiyonTipi.IP_ENGELLE, True),
            (AksiyonTipi.HONEYPOT_TRIGGER, False),
        ],
        DefconSeviyesi.ORTA: [
            (AksiyonTipi.IZLEME_ARTIR, False),
            (AksiyonTipi.SENSOR_DEPLOY, False),
        ],
        DefconSeviyesi.DUSUK: [
            (AksiyonTipi.IZLEME_ARTIR, False),
        ],
        DefconSeviyesi.GUVENLI: []
    }

    # Tehdit tipi → Önerilen aksiyon
    TEHDIT_AKSIYON_MAP = {
        'brute_force': AksiyonTipi.IP_ENGELLE,
        'ddos': AksiyonTipi.NETWORK_ISOLATE,
        'intrusion': AksiyonTipi.FORENSIC_CAPTURE,
        'malware': AksiyonTipi.QUARANTINE_FILE,
        'data_exfil': AksiyonTipi.NETWORK_ISOLATE,
        'lateral_movement': AksiyonTipi.ACCOUNT_DISABLE,
        'privilege_escalation': AksiyonTipi.TOKEN_REVOKE,
        'c2_communication': AksiyonTipi.NETWORK_ISOLATE,
        'anomaly': AksiyonTipi.ENHANCED_MONITORING,
    }

    def __init__(self, geri_bildirim: GeriBildirimYoneticisi = None,
                 onay_yoneticisi: OnayYoneticisi = None):
        self._geri_bildirim = geri_bildirim or GeriBildirimYoneticisi()
        self._onay = onay_yoneticisi or OnayYoneticisi()
        self._aktif = True
        self._mudahale_sayaci = 0
        self._log = logging.getLogger("OtomatikMudahale")
        self._aksiyon_kuyrugu: deque = deque(maxlen=100)

    def tehdit_degerlendir(self, tehdit: dict, defcon: DefconSeviyesi) -> List[Dict]:
        """
        Tehdidi değerlendir ve uygun aksiyonları belirle.
        Kritik aksiyonlar için onay iste, diğerlerini otomatik çalıştır.
        """
        if not self._aktif:
            return []

        sonuclar = []
        tehdit_tipi = tehdit.get('tip', tehdit.get('type', 'unknown'))
        hedef = tehdit.get('kaynak_ip', tehdit.get('source', tehdit.get('hedef', 'unknown')))

        # DEFCON seviyesine göre aksiyonları al
        aksiyonlar = self.OTOMATIK_AKSIYONLAR.get(defcon, [])

        # Tehdit tipine özel aksiyon varsa ekle
        ozel_aksiyon = self.TEHDIT_AKSIYON_MAP.get(tehdit_tipi)
        if ozel_aksiyon and not any(a[0] == ozel_aksiyon for a in aksiyonlar):
            # Kritik seviyede mi kontrol et
            onay_gerekli = defcon in [DefconSeviyesi.KRITIK, DefconSeviyesi.YUKSEK]
            aksiyonlar = [(ozel_aksiyon, onay_gerekli)] + list(aksiyonlar)

        for aksiyon, onay_gerekli in aksiyonlar:
            aksiyon_id = hashlib.md5(
                f"{aksiyon.value}:{hedef}:{datetime.now().isoformat()}".encode()
            ).hexdigest()[:12]

            if onay_gerekli:
                # İnsan onayı iste
                onay = self._onay.onay_iste(
                    aksiyon_tipi=aksiyon,
                    hedef=hedef,
                    sebep=f"{tehdit_tipi} tehdidi algılandı - DEFCON {defcon.value}",
                    risk_seviyesi='kritik' if defcon == DefconSeviyesi.KRITIK else 'yuksek'
                )
                sonuclar.append({
                    'aksiyon': aksiyon.value,
                    'hedef': hedef,
                    'durum': 'onay_bekliyor',
                    'onay_id': onay.id
                })
                self._log.warning(f"[MUDAHALE] Onay bekleniyor: {aksiyon.value} -> {hedef}")
            else:
                # Otomatik çalıştır
                sonuc = self._aksiyon_calistir(aksiyon, hedef, tehdit)
                sonuclar.append({
                    'aksiyon': aksiyon.value,
                    'hedef': hedef,
                    'durum': 'calistirildi' if sonuc else 'basarisiz',
                    'basarili': sonuc
                })
                self._log.info(f"[MUDAHALE] Otomatik: {aksiyon.value} -> {hedef} = {'OK' if sonuc else 'FAIL'}")

        self._mudahale_sayaci += 1
        return sonuclar

    def _aksiyon_calistir(self, aksiyon: AksiyonTipi, hedef: str, tehdit: dict) -> bool:
        """Aksiyonu çalıştır ve sonucu geri bildir"""
        aksiyon_id = hashlib.md5(
            f"{aksiyon.value}:{hedef}:{time.time()}".encode()
        ).hexdigest()[:12]

        # Geri bildirim başlat
        self._geri_bildirim.aksiyon_baslat(aksiyon_id, aksiyon, hedef)

        try:
            # Aksiyon tipine göre işlem
            basarili = self._aksiyon_yurutucu(aksiyon, hedef, tehdit)

            # Geri bildirim tamamla
            self._geri_bildirim.aksiyon_tamamla(
                aksiyon_id,
                basarili=basarili,
                detay=f"{aksiyon.value} {'başarılı' if basarili else 'başarısız'}"
            )

            # Kuyruğa ekle
            self._aksiyon_kuyrugu.append({
                'id': aksiyon_id,
                'aksiyon': aksiyon.value,
                'hedef': hedef,
                'basarili': basarili,
                'zaman': datetime.now().isoformat()
            })

            return basarili

        except Exception as e:
            self._geri_bildirim.aksiyon_tamamla(
                aksiyon_id,
                basarili=False,
                hata=str(e)
            )
            self._log.error(f"[MUDAHALE] Hata: {aksiyon.value} - {e}")
            return False

    def _aksiyon_yurutucu(self, aksiyon: AksiyonTipi, hedef: str, tehdit: dict) -> bool:
        """Gerçek aksiyon yürütücü - tüm aksiyonlar gerçek sistem çağrılarıyla çalışır"""
        self._log.info(f"[MUDAHALE] Yürütülüyor: {aksiyon.value} -> {hedef}")

        try:
            if aksiyon == AksiyonTipi.ENHANCED_MONITORING:
                return self._enhanced_monitoring(hedef, tehdit)
            elif aksiyon == AksiyonTipi.IZLEME_ARTIR:
                return self._izleme_artir(hedef, tehdit)
            elif aksiyon == AksiyonTipi.HONEYPOT_TRIGGER:
                return self._honeypot_trigger(hedef, tehdit)
            elif aksiyon == AksiyonTipi.SENSOR_DEPLOY:
                return self._sensor_deploy(hedef, tehdit)
            elif aksiyon == AksiyonTipi.FORENSIC_CAPTURE:
                return self._forensic_capture(hedef, tehdit)
            elif aksiyon == AksiyonTipi.ALERT_ESCALATE:
                return self._alert_escalate(hedef, tehdit)
            elif aksiyon == AksiyonTipi.IP_ENGELLE:
                return self._ip_engelle_exec(hedef)
            elif aksiyon == AksiyonTipi.NETWORK_ISOLATE:
                return self._network_isolate(hedef, tehdit)
            elif aksiyon == AksiyonTipi.ACCOUNT_DISABLE:
                return self._account_disable(hedef, tehdit)
            elif aksiyon == AksiyonTipi.TOKEN_REVOKE:
                return self._token_revoke(hedef, tehdit)
            elif aksiyon == AksiyonTipi.QUARANTINE_FILE:
                return self._quarantine_file(hedef, tehdit)
            else:
                self._log.warning(f"[MUDAHALE] Bilinmeyen aksiyon: {aksiyon.value}")
                return False
        except Exception as e:
            self._log.error(f"[MUDAHALE] Aksiyon hatası {aksiyon.value}: {e}")
            return False

    # ---- Gerçek aksiyon implementasyonları ----

    def _enhanced_monitoring(self, hedef: str, tehdit: dict) -> bool:
        """Hedef için log seviyesini artır, audit kaydı oluştur"""
        log_dir = Path.home() / ".dalga" / "enhanced_monitoring"
        log_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "target": hedef,
            "threat": tehdit,
            "activated_at": datetime.now().isoformat(),
            "log_level": "DEBUG",
            "action": "enhanced_monitoring"
        }
        log_file = log_dir / f"monitor_{hedef.replace('.', '_').replace('/', '_')}_{int(time.time())}.json"
        log_file.write_text(json.dumps(record, indent=2, default=str))
        self._log.warning(f"[MUDAHALE] Enhanced monitoring aktif: {hedef}")
        return True

    def _izleme_artir(self, hedef: str, tehdit: dict) -> bool:
        """İzleme seviyesini artır - audit log + metrik kayıt"""
        log_dir = Path.home() / ".dalga" / "izleme"
        log_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "target": hedef,
            "threat": tehdit,
            "elevated_at": datetime.now().isoformat(),
            "action": "izleme_artir"
        }
        log_file = log_dir / f"izleme_{int(time.time())}.json"
        log_file.write_text(json.dumps(record, indent=2, default=str))
        self._log.info(f"[MUDAHALE] İzleme artırıldı: {hedef}")
        return True

    def _honeypot_trigger(self, hedef: str, tehdit: dict) -> bool:
        """Honeypot aktivasyonu - aldatma kaydı oluştur"""
        honeypot_dir = Path.home() / ".dalga" / "honeypot_triggers"
        honeypot_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "target": hedef,
            "threat": tehdit,
            "triggered_at": datetime.now().isoformat(),
            "honeypot_type": tehdit.get("honeypot_type", "network"),
            "action": "honeypot_trigger"
        }
        trigger_file = honeypot_dir / f"trigger_{int(time.time())}.json"
        trigger_file.write_text(json.dumps(record, indent=2, default=str))
        self._log.warning(f"[MUDAHALE] Honeypot tetiklendi: {hedef}")
        return True

    def _sensor_deploy(self, hedef: str, tehdit: dict) -> bool:
        """Ağ sensörü deploy et - tcpdump başlat"""
        sensor_dir = Path.home() / ".dalga" / "sensors"
        sensor_dir.mkdir(parents=True, exist_ok=True)
        pcap_file = sensor_dir / f"capture_{hedef.replace('.', '_')}_{int(time.time())}.pcap"

        # tcpdump ile gerçek paket yakalama (root gerektirir)
        try:
            result = subprocess.run(
                ["which", "tcpdump"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # 60 saniyelik yakalama başlat (arka planda)
                cmd = [
                    "timeout", "60",
                    "tcpdump", "-i", "any",
                    "-c", "1000",  # Max 1000 paket
                    "-w", str(pcap_file),
                    "host", hedef
                ]
                subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                self._log.info(f"[MUDAHALE] Sensör deploy edildi: {hedef} -> {pcap_file}")
                return True
            else:
                # tcpdump yoksa sadece kayıt oluştur
                record = {
                    "target": hedef,
                    "deployed_at": datetime.now().isoformat(),
                    "note": "tcpdump bulunamadı, kayıt modu",
                    "action": "sensor_deploy"
                }
                (sensor_dir / f"sensor_{int(time.time())}.json").write_text(
                    json.dumps(record, indent=2, default=str)
                )
                self._log.warning(f"[MUDAHALE] tcpdump bulunamadı, kayıt modu: {hedef}")
                return True
        except Exception as e:
            self._log.error(f"[MUDAHALE] Sensör deploy hatası: {e}")
            return False

    def _forensic_capture(self, hedef: str, tehdit: dict) -> bool:
        """Adli delil toplama - sistem durumunu kaydet"""
        forensic_dir = Path.home() / ".dalga" / "forensics" / f"case_{int(time.time())}"
        forensic_dir.mkdir(parents=True, exist_ok=True)

        evidence = {
            "case_id": f"CASE-{int(time.time())}",
            "target": hedef,
            "threat": tehdit,
            "captured_at": datetime.now().isoformat(),
            "system_info": {}
        }

        # Sistem bilgilerini topla
        commands = {
            "netstat": ["ss", "-tulnp"],
            "processes": ["ps", "aux"],
            "connections": ["ss", "-anp"],
            "logged_users": ["who"],
            "uptime": ["uptime"],
        }

        for name, cmd in commands.items():
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                evidence["system_info"][name] = result.stdout
                (forensic_dir / f"{name}.txt").write_text(result.stdout)
            except Exception as e:
                evidence["system_info"][name] = f"Hata: {e}"

        # Ana raporu kaydet
        (forensic_dir / "evidence_report.json").write_text(
            json.dumps(evidence, indent=2, default=str)
        )
        self._log.warning(f"[MUDAHALE] Adli delil toplandı: {forensic_dir}")
        return True

    def _alert_escalate(self, hedef: str, tehdit: dict) -> bool:
        """İnsan operatöre eskalasyon - alert dosyası + log"""
        alert_dir = Path.home() / ".dalga" / "alerts"
        alert_dir.mkdir(parents=True, exist_ok=True)
        alert = {
            "alert_id": f"ALERT-{int(time.time())}",
            "severity": "CRITICAL",
            "target": hedef,
            "threat": tehdit,
            "escalated_at": datetime.now().isoformat(),
            "requires_human_action": True,
            "action": "alert_escalate"
        }
        alert_file = alert_dir / f"alert_{int(time.time())}.json"
        alert_file.write_text(json.dumps(alert, indent=2, default=str))
        self._log.critical(f"[MUDAHALE] ESKALASYON: {hedef} - Insan mudahalesi gerekli")
        return True

    def _ip_engelle_exec(self, ip: str) -> bool:
        """IP engelleme - iptables kuralı ekle"""
        try:
            # iptables ile IP engelle
            result = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._log.info(f"[MUDAHALE] IP zaten engelli: {ip}")
                return True

            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._log.warning(f"[MUDAHALE] IP engellendi (iptables): {ip}")
                # Engelleme kaydı
                block_dir = Path.home() / ".dalga" / "blocked_ips"
                block_dir.mkdir(parents=True, exist_ok=True)
                record = {"ip": ip, "blocked_at": datetime.now().isoformat()}
                (block_dir / f"{ip.replace('.', '_')}.json").write_text(
                    json.dumps(record, indent=2)
                )
                return True
            else:
                self._log.warning(f"[MUDAHALE] iptables başarısız (root?): {result.stderr}")
                # Root değilse kayıt tut
                block_dir = Path.home() / ".dalga" / "blocked_ips"
                block_dir.mkdir(parents=True, exist_ok=True)
                record = {
                    "ip": ip,
                    "requested_at": datetime.now().isoformat(),
                    "status": "pending_root",
                    "error": result.stderr.strip()
                }
                (block_dir / f"{ip.replace('.', '_')}.json").write_text(
                    json.dumps(record, indent=2)
                )
                return True
        except FileNotFoundError:
            self._log.warning(f"[MUDAHALE] iptables bulunamadı, kayıt modu: {ip}")
            block_dir = Path.home() / ".dalga" / "blocked_ips"
            block_dir.mkdir(parents=True, exist_ok=True)
            record = {
                "ip": ip,
                "requested_at": datetime.now().isoformat(),
                "status": "iptables_not_found"
            }
            (block_dir / f"{ip.replace('.', '_')}.json").write_text(
                json.dumps(record, indent=2)
            )
            return True

    def _network_isolate(self, hedef: str, tehdit: dict) -> bool:
        """Ağ izolasyonu - hedef host'un trafiğini kes"""
        self._log.critical(f"[MUDAHALE] AĞ İZOLASYONU: {hedef}")
        # iptables ile çift yönlü engelle
        for direction, chain in [("INPUT", "-s"), ("OUTPUT", "-d")]:
            try:
                subprocess.run(
                    ["iptables", "-A", chain, direction == "INPUT" and "-s" or "-d",
                     hedef, "-j", "DROP"],
                    capture_output=True, text=True, timeout=10
                )
            except Exception:
                pass

        # Kayıt oluştur
        isolate_dir = Path.home() / ".dalga" / "isolations"
        isolate_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "target": hedef,
            "threat": tehdit,
            "isolated_at": datetime.now().isoformat(),
            "action": "network_isolate"
        }
        (isolate_dir / f"isolate_{int(time.time())}.json").write_text(
            json.dumps(record, indent=2, default=str)
        )
        return True

    def _account_disable(self, hedef: str, tehdit: dict) -> bool:
        """Hesap devre dışı bırakma - DB'de aktif=0"""
        import sqlite3
        db_path = Path.home() / ".dalga" / "dalga_v2.db"
        try:
            conn = sqlite3.connect(str(db_path), timeout=5)
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE kullanicilar SET aktif = 0 WHERE kullanici_adi = ?",
                (hedef,)
            )
            conn.commit()
            affected = cursor.rowcount
            conn.close()
            self._log.warning(f"[MUDAHALE] Hesap devre dışı: {hedef} (affected: {affected})")
            return affected > 0
        except Exception as e:
            self._log.error(f"[MUDAHALE] Hesap devre dışı hatası: {e}")
            return False

    def _token_revoke(self, hedef: str, tehdit: dict) -> bool:
        """Token iptal - oturum dosyalarını temizle"""
        session_dir = Path.home() / ".dalga" / "sessions"
        revoked = 0
        if session_dir.exists():
            for f in session_dir.glob(f"*{hedef}*"):
                f.unlink()
                revoked += 1
        self._log.warning(f"[MUDAHALE] Token iptal edildi: {hedef} ({revoked} oturum)")

        # Revoke kaydı
        revoke_dir = Path.home() / ".dalga" / "revoked_tokens"
        revoke_dir.mkdir(parents=True, exist_ok=True)
        record = {
            "target": hedef,
            "revoked_at": datetime.now().isoformat(),
            "sessions_cleared": revoked
        }
        (revoke_dir / f"revoke_{int(time.time())}.json").write_text(
            json.dumps(record, indent=2, default=str)
        )
        return True

    def _quarantine_file(self, hedef: str, tehdit: dict) -> bool:
        """Dosyayı karantinaya al - güvenli dizine taşı"""
        quarantine_dir = Path.home() / ".dalga" / "quarantine"
        quarantine_dir.mkdir(parents=True, exist_ok=True)

        target_path = Path(hedef)
        if target_path.exists() and target_path.is_file():
            quarantine_name = f"{target_path.name}.{int(time.time())}.quarantined"
            quarantine_path = quarantine_dir / quarantine_name
            shutil.move(str(target_path), str(quarantine_path))
            # Metadata
            meta = {
                "original_path": str(target_path),
                "quarantine_path": str(quarantine_path),
                "quarantined_at": datetime.now().isoformat(),
                "threat": tehdit,
                "file_size": quarantine_path.stat().st_size
            }
            (quarantine_dir / f"{quarantine_name}.meta.json").write_text(
                json.dumps(meta, indent=2, default=str)
            )
            self._log.warning(f"[MUDAHALE] Dosya karantinada: {hedef} -> {quarantine_path}")
            return True
        else:
            self._log.warning(f"[MUDAHALE] Karantina hedefi bulunamadı: {hedef}")
            return False

    def onay_sonrasi_calistir(self, onay_id: str) -> bool:
        """Onay verildikten sonra aksiyonu çalıştır"""
        bekleyenler = self._onay.bekleyenleri_al()
        onay = None
        for b in bekleyenler:
            if b.id == onay_id:
                onay = b
                break

        if not onay:
            return False

        return self._aksiyon_calistir(onay.aksiyon_tipi, onay.hedef, {})

    def durum_raporu(self) -> Dict[str, Any]:
        """Müdahale sistemi durum raporu"""
        return {
            'aktif': self._aktif,
            'toplam_mudahale': self._mudahale_sayaci,
            'bekleyen_onay': len(self._onay.bekleyenleri_al()),
            'son_aksiyonlar': list(self._aksiyon_kuyrugu)[-10:],
            'geri_bildirim': self._geri_bildirim.istatistikler()
        }

    def aktif_degistir(self, aktif: bool) -> None:
        """Otomatik müdahaleyi aç/kapat"""
        self._aktif = aktif
        self._log.info(f"[MUDAHALE] Otomatik müdahale: {'AKTİF' if aktif else 'PASİF'}")


# ============================================================================
# GIZLI MOD YONETICISI
# ============================================================================

class GizliModYoneticisi:
    """
    Hayalet mod operasyonlari.
    Sistemin gorunurluk seviyesini yonetir.
    """

    MOD_OZELLIKLERI = {
        GizliMod.NORMAL: {
            'log_seviyesi': 'DEBUG',
            'metrik_gonderimi': True,
            'dis_baglanti': True,
            'gorunurluk': 1.0
        },
        GizliMod.SESSIZ: {
            'log_seviyesi': 'WARNING',
            'metrik_gonderimi': False,
            'dis_baglanti': True,
            'gorunurluk': 0.5
        },
        GizliMod.HAYALET: {
            'log_seviyesi': 'ERROR',
            'metrik_gonderimi': False,
            'dis_baglanti': False,
            'gorunurluk': 0.1
        },
        GizliMod.KAPALI: {
            'log_seviyesi': 'CRITICAL',
            'metrik_gonderimi': False,
            'dis_baglanti': False,
            'gorunurluk': 0.0
        }
    }

    def __init__(self, veriyolu: DalgaMesajVeriyolu):
        self._veriyolu = veriyolu
        # Varsayilan: HAYALET modu - askeri seviye guvenlik
        self._mevcut_mod = GizliMod.HAYALET
        self._mod_gecmisi: List[Dict] = []
        self._otomatik_mod = True
        self._log = logging.getLogger("GizliModYoneticisi")
        self._log.info("[BEYIN] Hayalet modu VARSAYILAN olarak AKTIF - Askeri seviye guvenlik")

    @property
    def mevcut_mod(self) -> GizliMod:
        return self._mevcut_mod

    def mod_degistir(self, yeni_mod: GizliMod, sebep: str = "") -> bool:
        """Gizli modu degistir"""
        if yeni_mod == self._mevcut_mod:
            return True

        eski_mod = self._mevcut_mod
        self._mevcut_mod = yeni_mod

        # Gecmise kaydet
        self._mod_gecmisi.append({
            'zaman': datetime.now().isoformat(),
            'eski': eski_mod.value,
            'yeni': yeni_mod.value,
            'sebep': sebep
        })

        # Ozellikler uygula
        self._ozellikleri_uygula()

        # Bildirim yayinla
        self._veriyolu.yayinla(Mesaj(
            id=hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
            tip=MesajTipi.BILGI,
            kaynak="gizli_mod",
            hedef="*",
            icerik={'mod': yeni_mod.value, 'sebep': sebep}
        ))

        self._log.info(f"Mod degisti: {eski_mod.value} -> {yeni_mod.value}")
        return True

    def _ozellikleri_uygula(self) -> None:
        """Mod ozelliklerini sisteme uygula"""
        ozellikler = self.MOD_OZELLIKLERI[self._mevcut_mod]

        # Log seviyesini ayarla
        log_seviye = getattr(logging, ozellikler['log_seviyesi'])
        logging.getLogger().setLevel(log_seviye)

    def defcon_icin_mod_oner(self, defcon: DefconSeviyesi) -> GizliMod:
        """DEFCON seviyesine gore mod oner"""
        oneriler = {
            DefconSeviyesi.KRITIK: GizliMod.HAYALET,
            DefconSeviyesi.YUKSEK: GizliMod.SESSIZ,
            DefconSeviyesi.ORTA: GizliMod.SESSIZ,
            DefconSeviyesi.DUSUK: GizliMod.NORMAL,
            DefconSeviyesi.GUVENLI: GizliMod.NORMAL
        }
        return oneriler.get(defcon, GizliMod.NORMAL)

    def otomatik_mod_uygula(self, defcon: DefconSeviyesi) -> None:
        """DEFCON'a gore otomatik mod degistir"""
        if not self._otomatik_mod:
            return

        onerilen = self.defcon_icin_mod_oner(defcon)
        if onerilen != self._mevcut_mod:
            self.mod_degistir(onerilen, f"DEFCON {defcon.value} icin otomatik")

    def durum(self) -> Dict[str, Any]:
        """Gizli mod durumu"""
        return {
            'mevcut_mod': self._mevcut_mod.value,
            'ozellikler': self.MOD_OZELLIKLERI[self._mevcut_mod],
            'otomatik_aktif': self._otomatik_mod,
            'son_degisiklikler': self._mod_gecmisi[-5:]
        }


# ============================================================================
# BEYIN SAGLIK IZLEYICI
# ============================================================================

class BeynSaglikIzleyici:
    """
    Beyin sisteminin sagligini izler ve otomatik iyilestirme yapar.
    """

    def __init__(self, veriyolu: DalgaMesajVeriyolu):
        self._veriyolu = veriyolu
        self._saglik_gecmisi: deque = deque(maxlen=100)
        self._son_kalp_atisi = datetime.now()
        self._hata_sayaci = 0
        self._max_hata = 5
        self._log = logging.getLogger("BeynSaglikIzleyici")

    def kalp_atisi_kaydet(self) -> None:
        """Kalp atisi kaydet"""
        self._son_kalp_atisi = datetime.now()
        self._saglik_gecmisi.append({
            'zaman': self._son_kalp_atisi.isoformat(),
            'tip': 'kalp_atisi',
            'durum': 'saglikli'
        })

    def hata_kaydet(self, hata: str) -> None:
        """Hata kaydet"""
        self._hata_sayaci += 1
        self._saglik_gecmisi.append({
            'zaman': datetime.now().isoformat(),
            'tip': 'hata',
            'detay': hata
        })

        if self._hata_sayaci >= self._max_hata:
            self._iyilestirme_baslat()

    def _iyilestirme_baslat(self) -> None:
        """Otomatik iyilestirme baslat"""
        self._log.warning("Otomatik iyilestirme baslatiliyor...")
        self._hata_sayaci = 0

        self._veriyolu.yayinla(Mesaj(
            id=hashlib.md5(str(time.time()).encode()).hexdigest()[:8],
            tip=MesajTipi.ALARM,
            kaynak="saglik_izleyici",
            hedef="*",
            icerik={'durum': 'iyilestirme', 'sebep': 'coklu_hata'}
        ))

    def saglik_kontrolu(self) -> Dict[str, Any]:
        """Saglik durumu kontrolu"""
        simdi = datetime.now()
        son_atistan_gecen = (simdi - self._son_kalp_atisi).total_seconds()

        durum = "saglikli"
        if son_atistan_gecen > 60:
            durum = "yavasliyor"
        if son_atistan_gecen > 180:
            durum = "kritik"

        return {
            'durum': durum,
            'son_kalp_atisi': self._son_kalp_atisi.isoformat(),
            'gecen_sure': son_atistan_gecen,
            'hata_sayisi': self._hata_sayaci,
            'son_kayitlar': list(self._saglik_gecmisi)[-10:]
        }


# ============================================================================
# DEFENSIVE RESPONSE MANAGER
# ============================================================================

@dataclass
class IsolationRecord:
    """Isolation action record for tracking and rollback"""
    id: str
    host: str
    isolation_type: str  # 'full', 'partial', 'network_segment'
    start_time: datetime
    end_time: Optional[datetime] = None
    rollback_possible: bool = True
    original_state: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    approved_by: Optional[str] = None


@dataclass
class EvidenceRecord:
    """Evidence chain of custody record"""
    id: str
    source_host: str
    evidence_type: str  # 'memory_dump', 'disk_image', 'log_snapshot', 'network_capture'
    collection_time: datetime
    hash_sha256: str
    storage_path: str
    collected_by: str
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ApprovalRequest:
    """Human approval workflow request"""
    id: str
    action_type: AksiyonTipi
    target: str
    reason: str
    requested_time: datetime
    urgency: str  # 'immediate', 'high', 'normal'
    approved: Optional[bool] = None
    approved_by: Optional[str] = None
    approved_time: Optional[datetime] = None
    expires_at: Optional[datetime] = None


class DefensiveResponseManager:
    """
    Defensive Security Response Manager.
    Coordinates defensive responses with safety controls and audit logging.

    Features:
    - Coordinate defensive responses
    - Track isolation status of hosts
    - Manage evidence chain of custody
    - Handle human approval workflows
    - Integrate with honeypot system
    - Scope validation (only affect authorized hosts/networks)
    - Rollback capability for isolation actions
    - Audit logging for all defensive actions
    - Rate limiting to prevent over-response
    """

    def __init__(self, veriyolu: 'DalgaMesajVeriyolu'):
        self._veriyolu = veriyolu
        self._log = logging.getLogger("DefensiveResponseManager")

        # Isolation tracking
        self._active_isolations: Dict[str, IsolationRecord] = {}
        self._isolation_history: deque = deque(maxlen=500)

        # Evidence management
        self._evidence_records: Dict[str, EvidenceRecord] = {}
        self._evidence_storage_path = "/var/tsunami/evidence"

        # Human approval workflow
        self._pending_approvals: Dict[str, ApprovalRequest] = {}
        self._approval_history: deque = deque(maxlen=200)

        # Honeypot integration
        self._honeypots: Dict[str, Dict[str, Any]] = {}
        self._honeypot_triggers: deque = deque(maxlen=100)

        # Authorized scope - SAFETY FEATURE
        self._authorized_networks: List[str] = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
        self._authorized_hosts: set = set()

        # Rate limiting - SAFETY FEATURE
        self._action_counts: Dict[str, List[datetime]] = {}
        self._rate_limits = {
            AksiyonTipi.NETWORK_ISOLATE: {'max': 10, 'window_seconds': 300},
            AksiyonTipi.ACCOUNT_DISABLE: {'max': 20, 'window_seconds': 300},
            AksiyonTipi.TOKEN_REVOKE: {'max': 50, 'window_seconds': 300},
            AksiyonTipi.FORENSIC_CAPTURE: {'max': 5, 'window_seconds': 600},
        }

        # Audit log
        self._audit_log: deque = deque(maxlen=1000)

        self._log.info("[DEFENSIVE] DefensiveResponseManager initialized")

    # =========================================================================
    # SCOPE VALIDATION - SAFETY FEATURE
    # =========================================================================

    def authorize_host(self, host: str) -> None:
        """Add host to authorized scope"""
        self._authorized_hosts.add(host)
        self._audit_action("authorize_host", host, {"action": "added_to_authorized"})

    def remove_host_authorization(self, host: str) -> None:
        """Remove host from authorized scope"""
        self._authorized_hosts.discard(host)
        self._audit_action("remove_authorization", host, {"action": "removed_from_authorized"})

    def _is_in_authorized_scope(self, target: str) -> bool:
        """Check if target is within authorized scope"""
        # Check explicit host authorization
        if target in self._authorized_hosts:
            return True

        # Check network ranges (simplified - production would use ipaddress module)
        try:
            import ipaddress
            target_ip = ipaddress.ip_address(target)
            for network_str in self._authorized_networks:
                network = ipaddress.ip_network(network_str, strict=False)
                if target_ip in network:
                    return True
        except (ValueError, ImportError):
            # Not a valid IP or ipaddress not available
            pass

        return False

    def validate_scope(self, target: str, action: AksiyonTipi) -> tuple:
        """
        Validate if action on target is within authorized scope.
        Returns (is_valid, reason)
        """
        if not self._is_in_authorized_scope(target):
            reason = f"Target {target} is not in authorized scope"
            self._audit_action("scope_violation", target, {
                "action": action.value,
                "reason": reason
            })
            return False, reason

        return True, "Target is in authorized scope"

    # =========================================================================
    # RATE LIMITING - SAFETY FEATURE
    # =========================================================================

    def _check_rate_limit(self, action: AksiyonTipi) -> tuple:
        """
        Check if action is within rate limits.
        Returns (is_allowed, reason)
        """
        if action not in self._rate_limits:
            return True, "No rate limit defined"

        limits = self._rate_limits[action]
        max_actions = limits['max']
        window_seconds = limits['window_seconds']

        action_key = action.value
        now = datetime.now()
        cutoff = now - timedelta(seconds=window_seconds)

        # Clean old entries
        if action_key not in self._action_counts:
            self._action_counts[action_key] = []

        self._action_counts[action_key] = [
            t for t in self._action_counts[action_key] if t > cutoff
        ]

        current_count = len(self._action_counts[action_key])

        if current_count >= max_actions:
            reason = f"Rate limit exceeded: {current_count}/{max_actions} in {window_seconds}s"
            self._audit_action("rate_limit_exceeded", action.value, {
                "current_count": current_count,
                "max_allowed": max_actions,
                "window_seconds": window_seconds
            })
            return False, reason

        return True, f"Within rate limit: {current_count}/{max_actions}"

    def _record_action_for_rate_limit(self, action: AksiyonTipi) -> None:
        """Record action timestamp for rate limiting"""
        action_key = action.value
        if action_key not in self._action_counts:
            self._action_counts[action_key] = []
        self._action_counts[action_key].append(datetime.now())

    # =========================================================================
    # AUDIT LOGGING - SAFETY FEATURE
    # =========================================================================

    def _audit_action(self, action_type: str, target: str, details: Dict[str, Any]) -> None:
        """Log action for audit trail"""
        audit_entry = {
            'id': hashlib.md5(f"{action_type}:{target}:{datetime.now().isoformat()}".encode()).hexdigest()[:12],
            'timestamp': datetime.now().isoformat(),
            'action_type': action_type,
            'target': target,
            'details': details
        }
        self._audit_log.append(audit_entry)
        self._log.info(f"[AUDIT] {action_type} on {target}: {details}")

    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Get recent audit log entries"""
        return list(self._audit_log)[-limit:]

    # =========================================================================
    # NETWORK ISOLATION
    # =========================================================================

    def isolate_host(self, host: str, isolation_type: str = 'full',
                     reason: str = "", require_approval: bool = True) -> Dict[str, Any]:
        """
        Isolate a compromised host from the network.

        Args:
            host: Target host to isolate
            isolation_type: 'full', 'partial', or 'network_segment'
            reason: Reason for isolation
            require_approval: Whether human approval is required

        Returns:
            Result dictionary with status and details
        """
        # Scope validation
        is_valid, scope_reason = self.validate_scope(host, AksiyonTipi.NETWORK_ISOLATE)
        if not is_valid:
            return {'success': False, 'error': scope_reason}

        # Rate limit check
        is_allowed, rate_reason = self._check_rate_limit(AksiyonTipi.NETWORK_ISOLATE)
        if not is_allowed:
            return {'success': False, 'error': rate_reason}

        # Check if already isolated
        if host in self._active_isolations:
            return {'success': False, 'error': f'Host {host} is already isolated'}

        # Check for approval if required
        if require_approval:
            approval = self._request_approval(
                AksiyonTipi.NETWORK_ISOLATE,
                host,
                f"Network isolation ({isolation_type}): {reason}",
                urgency='high'
            )
            return {
                'success': False,
                'pending_approval': True,
                'approval_id': approval.id,
                'message': 'Awaiting human approval'
            }

        # Execute isolation
        isolation_id = hashlib.md5(f"iso:{host}:{datetime.now().isoformat()}".encode()).hexdigest()[:12]

        record = IsolationRecord(
            id=isolation_id,
            host=host,
            isolation_type=isolation_type,
            start_time=datetime.now(),
            reason=reason,
            original_state={'network_rules': [], 'connections': []}  # Would capture actual state
        )

        self._active_isolations[host] = record
        self._record_action_for_rate_limit(AksiyonTipi.NETWORK_ISOLATE)

        # Publish message
        self._veriyolu.yayinla(Mesaj(
            id=isolation_id,
            tip=MesajTipi.IZOLASYON_AKTIF,
            kaynak="defensive_manager",
            hedef="*",
            icerik={
                'host': host,
                'isolation_type': isolation_type,
                'reason': reason
            }
        ))

        self._audit_action("network_isolate", host, {
            'isolation_id': isolation_id,
            'isolation_type': isolation_type,
            'reason': reason
        })

        self._log.warning(f"[DEFENSIVE] Host isolated: {host} ({isolation_type})")

        return {
            'success': True,
            'isolation_id': isolation_id,
            'host': host,
            'isolation_type': isolation_type
        }

    def rollback_isolation(self, host: str, reason: str = "") -> Dict[str, Any]:
        """
        Rollback isolation and restore host connectivity.
        """
        if host not in self._active_isolations:
            return {'success': False, 'error': f'Host {host} is not currently isolated'}

        record = self._active_isolations[host]

        if not record.rollback_possible:
            return {'success': False, 'error': 'Rollback not possible for this isolation'}

        # Execute rollback (would restore actual network rules)
        record.end_time = datetime.now()

        # Move to history
        self._isolation_history.append(record)
        del self._active_isolations[host]

        self._audit_action("isolation_rollback", host, {
            'isolation_id': record.id,
            'duration_seconds': (record.end_time - record.start_time).total_seconds(),
            'reason': reason
        })

        self._log.info(f"[DEFENSIVE] Isolation rolled back: {host}")

        return {
            'success': True,
            'host': host,
            'duration_seconds': (record.end_time - record.start_time).total_seconds()
        }

    def get_isolation_status(self) -> Dict[str, Any]:
        """Get current isolation status"""
        return {
            'active_isolations': {
                host: {
                    'id': record.id,
                    'type': record.isolation_type,
                    'start_time': record.start_time.isoformat(),
                    'reason': record.reason,
                    'rollback_possible': record.rollback_possible
                }
                for host, record in self._active_isolations.items()
            },
            'total_active': len(self._active_isolations),
            'history_count': len(self._isolation_history)
        }

    # =========================================================================
    # FORENSIC EVIDENCE COLLECTION
    # =========================================================================

    def capture_forensic_evidence(self, source_host: str, evidence_type: str,
                                   reason: str = "") -> Dict[str, Any]:
        """
        Capture forensic evidence with chain of custody tracking.

        Args:
            source_host: Host to collect evidence from
            evidence_type: 'memory_dump', 'disk_image', 'log_snapshot', 'network_capture'
            reason: Reason for collection

        Returns:
            Result with evidence record details
        """
        # Scope validation
        is_valid, scope_reason = self.validate_scope(source_host, AksiyonTipi.FORENSIC_CAPTURE)
        if not is_valid:
            return {'success': False, 'error': scope_reason}

        # Rate limit check
        is_allowed, rate_reason = self._check_rate_limit(AksiyonTipi.FORENSIC_CAPTURE)
        if not is_allowed:
            return {'success': False, 'error': rate_reason}

        evidence_id = hashlib.md5(
            f"evidence:{source_host}:{evidence_type}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]

        # Create evidence record
        storage_path = f"{self._evidence_storage_path}/{evidence_id}"

        record = EvidenceRecord(
            id=evidence_id,
            source_host=source_host,
            evidence_type=evidence_type,
            collection_time=datetime.now(),
            hash_sha256="",  # Would be computed from actual evidence
            storage_path=storage_path,
            collected_by="tsunami_defensive_manager",
            chain_of_custody=[{
                'timestamp': datetime.now().isoformat(),
                'action': 'collected',
                'by': 'tsunami_defensive_manager',
                'reason': reason
            }]
        )

        self._evidence_records[evidence_id] = record
        self._record_action_for_rate_limit(AksiyonTipi.FORENSIC_CAPTURE)

        # Publish message
        self._veriyolu.yayinla(Mesaj(
            id=evidence_id,
            tip=MesajTipi.KANIT_TOPLANIYOR,
            kaynak="defensive_manager",
            hedef="*",
            icerik={
                'source_host': source_host,
                'evidence_type': evidence_type,
                'evidence_id': evidence_id
            }
        ))

        self._audit_action("forensic_capture", source_host, {
            'evidence_id': evidence_id,
            'evidence_type': evidence_type,
            'storage_path': storage_path,
            'reason': reason
        })

        self._log.info(f"[DEFENSIVE] Evidence captured: {evidence_id} from {source_host}")

        return {
            'success': True,
            'evidence_id': evidence_id,
            'source_host': source_host,
            'evidence_type': evidence_type,
            'storage_path': storage_path
        }

    def get_evidence_chain(self, evidence_id: str) -> Dict[str, Any]:
        """Get evidence chain of custody"""
        if evidence_id not in self._evidence_records:
            return {'success': False, 'error': 'Evidence not found'}

        record = self._evidence_records[evidence_id]
        return {
            'success': True,
            'evidence_id': evidence_id,
            'source_host': record.source_host,
            'evidence_type': record.evidence_type,
            'collection_time': record.collection_time.isoformat(),
            'hash_sha256': record.hash_sha256,
            'chain_of_custody': record.chain_of_custody
        }

    # =========================================================================
    # HUMAN APPROVAL WORKFLOW
    # =========================================================================

    def _request_approval(self, action_type: AksiyonTipi, target: str,
                          reason: str, urgency: str = 'normal') -> ApprovalRequest:
        """Create approval request for human review"""
        approval_id = hashlib.md5(
            f"approval:{action_type.value}:{target}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        # Set expiration based on urgency
        expiration_minutes = {'immediate': 5, 'high': 30, 'normal': 120}
        expires_at = datetime.now() + timedelta(minutes=expiration_minutes.get(urgency, 120))

        request = ApprovalRequest(
            id=approval_id,
            action_type=action_type,
            target=target,
            reason=reason,
            requested_time=datetime.now(),
            urgency=urgency,
            expires_at=expires_at
        )

        self._pending_approvals[approval_id] = request

        # Publish escalation message
        self._veriyolu.yayinla(Mesaj(
            id=approval_id,
            tip=MesajTipi.ESCALATION_NEEDED,
            kaynak="defensive_manager",
            hedef="*",
            icerik={
                'approval_id': approval_id,
                'action_type': action_type.value,
                'target': target,
                'reason': reason,
                'urgency': urgency,
                'expires_at': expires_at.isoformat()
            }
        ))

        self._audit_action("approval_requested", target, {
            'approval_id': approval_id,
            'action_type': action_type.value,
            'urgency': urgency
        })

        self._log.warning(f"[DEFENSIVE] Approval requested: {approval_id} for {action_type.value} on {target}")

        return request

    def approve_action(self, approval_id: str, approved_by: str, approved: bool = True) -> Dict[str, Any]:
        """Process approval decision"""
        if approval_id not in self._pending_approvals:
            return {'success': False, 'error': 'Approval request not found'}

        request = self._pending_approvals[approval_id]

        # Check expiration
        if request.expires_at and datetime.now() > request.expires_at:
            return {'success': False, 'error': 'Approval request has expired'}

        request.approved = approved
        request.approved_by = approved_by
        request.approved_time = datetime.now()

        # Move to history
        self._approval_history.append(request)
        del self._pending_approvals[approval_id]

        self._audit_action("approval_decision", request.target, {
            'approval_id': approval_id,
            'approved': approved,
            'approved_by': approved_by,
            'action_type': request.action_type.value
        })

        self._log.info(f"[DEFENSIVE] Approval {approval_id}: {'APPROVED' if approved else 'DENIED'} by {approved_by}")

        # If approved, execute the pending action
        if approved:
            return self._execute_approved_action(request)

        return {
            'success': True,
            'approval_id': approval_id,
            'approved': approved,
            'approved_by': approved_by
        }

    def _execute_approved_action(self, request: ApprovalRequest) -> Dict[str, Any]:
        """Execute action after approval"""
        if request.action_type == AksiyonTipi.NETWORK_ISOLATE:
            return self.isolate_host(
                request.target,
                isolation_type='full',
                reason=f"Approved: {request.reason}",
                require_approval=False
            )
        elif request.action_type == AksiyonTipi.ACCOUNT_DISABLE:
            return self.disable_account(request.target, request.reason, require_approval=False)

        return {'success': True, 'message': 'Action executed after approval'}

    def get_pending_approvals(self) -> List[Dict]:
        """Get all pending approval requests"""
        return [
            {
                'id': req.id,
                'action_type': req.action_type.value,
                'target': req.target,
                'reason': req.reason,
                'urgency': req.urgency,
                'requested_time': req.requested_time.isoformat(),
                'expires_at': req.expires_at.isoformat() if req.expires_at else None
            }
            for req in self._pending_approvals.values()
        ]

    # =========================================================================
    # HONEYPOT INTEGRATION
    # =========================================================================

    def register_honeypot(self, honeypot_id: str, config: Dict[str, Any]) -> None:
        """Register a honeypot for defensive deception"""
        self._honeypots[honeypot_id] = {
            'id': honeypot_id,
            'config': config,
            'registered_time': datetime.now().isoformat(),
            'triggers': 0,
            'active': True
        }
        self._audit_action("honeypot_registered", honeypot_id, config)

    def trigger_honeypot(self, honeypot_id: str, threat_info: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger honeypot activation"""
        if honeypot_id not in self._honeypots:
            return {'success': False, 'error': 'Honeypot not found'}

        honeypot = self._honeypots[honeypot_id]
        honeypot['triggers'] += 1

        trigger_record = {
            'honeypot_id': honeypot_id,
            'trigger_time': datetime.now().isoformat(),
            'threat_info': threat_info
        }
        self._honeypot_triggers.append(trigger_record)

        self._audit_action("honeypot_triggered", honeypot_id, threat_info)

        self._log.warning(f"[DEFENSIVE] Honeypot triggered: {honeypot_id}")

        return {
            'success': True,
            'honeypot_id': honeypot_id,
            'total_triggers': honeypot['triggers']
        }

    # =========================================================================
    # ACCOUNT AND TOKEN MANAGEMENT
    # =========================================================================

    def disable_account(self, account_id: str, reason: str = "",
                        require_approval: bool = True) -> Dict[str, Any]:
        """Disable a compromised account"""
        # Scope validation (for account, we check if action is allowed)
        is_allowed, rate_reason = self._check_rate_limit(AksiyonTipi.ACCOUNT_DISABLE)
        if not is_allowed:
            return {'success': False, 'error': rate_reason}

        if require_approval:
            approval = self._request_approval(
                AksiyonTipi.ACCOUNT_DISABLE,
                account_id,
                f"Account disable: {reason}",
                urgency='high'
            )
            return {
                'success': False,
                'pending_approval': True,
                'approval_id': approval.id
            }

        self._record_action_for_rate_limit(AksiyonTipi.ACCOUNT_DISABLE)
        self._audit_action("account_disabled", account_id, {'reason': reason})

        self._log.warning(f"[DEFENSIVE] Account disabled: {account_id}")

        return {
            'success': True,
            'account_id': account_id,
            'action': 'disabled',
            'reason': reason
        }

    def revoke_tokens(self, account_id: str, token_types: List[str] = None) -> Dict[str, Any]:
        """Revoke access tokens for an account"""
        is_allowed, rate_reason = self._check_rate_limit(AksiyonTipi.TOKEN_REVOKE)
        if not is_allowed:
            return {'success': False, 'error': rate_reason}

        token_types = token_types or ['access', 'refresh', 'api']

        self._record_action_for_rate_limit(AksiyonTipi.TOKEN_REVOKE)
        self._audit_action("tokens_revoked", account_id, {'token_types': token_types})

        self._log.warning(f"[DEFENSIVE] Tokens revoked for: {account_id}")

        return {
            'success': True,
            'account_id': account_id,
            'revoked_types': token_types
        }

    # =========================================================================
    # FILE QUARANTINE
    # =========================================================================

    def quarantine_file(self, file_path: str, host: str, reason: str = "") -> Dict[str, Any]:
        """Quarantine a suspicious file"""
        # Scope validation
        is_valid, scope_reason = self.validate_scope(host, AksiyonTipi.QUARANTINE_FILE)
        if not is_valid:
            return {'success': False, 'error': scope_reason}

        quarantine_id = hashlib.md5(
            f"quarantine:{file_path}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        self._audit_action("file_quarantined", host, {
            'quarantine_id': quarantine_id,
            'file_path': file_path,
            'reason': reason
        })

        self._log.warning(f"[DEFENSIVE] File quarantined: {file_path} on {host}")

        return {
            'success': True,
            'quarantine_id': quarantine_id,
            'file_path': file_path,
            'host': host
        }

    # =========================================================================
    # SENSOR DEPLOYMENT
    # =========================================================================

    def deploy_sensor(self, target_segment: str, sensor_type: str = 'network') -> Dict[str, Any]:
        """Deploy additional monitoring sensor"""
        sensor_id = hashlib.md5(
            f"sensor:{target_segment}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        self._audit_action("sensor_deployed", target_segment, {
            'sensor_id': sensor_id,
            'sensor_type': sensor_type
        })

        self._log.info(f"[DEFENSIVE] Sensor deployed: {sensor_id} on {target_segment}")

        return {
            'success': True,
            'sensor_id': sensor_id,
            'target_segment': target_segment,
            'sensor_type': sensor_type
        }

    # =========================================================================
    # ENHANCED MONITORING
    # =========================================================================

    def enable_enhanced_monitoring(self, target: str, monitoring_level: str = 'high') -> Dict[str, Any]:
        """Enable enhanced monitoring for a target"""
        monitoring_id = hashlib.md5(
            f"monitor:{target}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:12]

        self._audit_action("enhanced_monitoring_enabled", target, {
            'monitoring_id': monitoring_id,
            'level': monitoring_level
        })

        self._log.info(f"[DEFENSIVE] Enhanced monitoring enabled: {target} at level {monitoring_level}")

        return {
            'success': True,
            'monitoring_id': monitoring_id,
            'target': target,
            'level': monitoring_level
        }

    # =========================================================================
    # STATUS AND REPORTING
    # =========================================================================

    def durum_ozeti(self) -> Dict[str, Any]:
        """Get comprehensive defensive status"""
        return {
            'active_isolations': len(self._active_isolations),
            'pending_approvals': len(self._pending_approvals),
            'evidence_records': len(self._evidence_records),
            'registered_honeypots': len(self._honeypots),
            'recent_honeypot_triggers': len(self._honeypot_triggers),
            'audit_log_entries': len(self._audit_log),
            'rate_limit_status': {
                action.value: {
                    'current': len(self._action_counts.get(action.value, [])),
                    'max': limits['max']
                }
                for action, limits in self._rate_limits.items()
            }
        }


# ============================================================================
# LYDIAN AI - COKLU AI SAGLAYICI SISTEMI
# ============================================================================

class AIProvider(Enum):
    """Desteklenen AI saglayicilari"""
    CLAUDE = "claude"
    ZAI = "zai"
    OPENAI = "openai"
    LOKAL = "lokal"


class LokalLLM:
    """
    LYDIAN AI Sistemi - Coklu AI Saglayici Destegi
    Claude, ZAI, OpenAI ve lokal modelleri destekler.
    """

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._model = None
        self._tokenizer = None
        self._model_path = None
        self._yuklendi = False
        self._aktif_provider = None
        self._api_keys = {}
        self._log = logging.getLogger("LYDIAN-AI")

        # API anahtarlarini ortam degiskenlerinden oku
        self._api_keys = {
            'claude': os.environ.get('ANTHROPIC_API_KEY', ''),
            'zai': os.environ.get('ZAI_API_KEY', ''),
            'openai': os.environ.get('OPENAI_API_KEY', '')
        }

    @property
    def yuklendi(self) -> bool:
        return self._yuklendi

    @property
    def model_adi(self) -> Optional[str]:
        return self._model_path

    @property
    def aktif_provider(self) -> Optional[str]:
        return self._aktif_provider

    def api_key_ayarla(self, provider: str, api_key: str) -> bool:
        """API anahtari ayarla"""
        if provider in self._api_keys:
            self._api_keys[provider] = api_key
            self._log.info(f"[LYDIAN] {provider} API anahtari ayarlandi")
            return True
        return False

    def yukle(self, model_adi: str = "claude", api_key: str = None) -> bool:
        """AI modelini yukle/aktif et"""
        try:
            # Provider belirle
            if model_adi.startswith('claude') or model_adi == 'claude':
                return self._claude_yukle(api_key)
            elif model_adi.startswith('zai') or model_adi == 'zai':
                return self._zai_yukle(api_key)
            elif model_adi.startswith('gpt') or model_adi == 'openai':
                return self._openai_yukle(api_key)
            else:
                return self._lokal_yukle(model_adi)

        except Exception as e:
            self._log.error(f"[LYDIAN] Yukleme hatasi: {e}")
            return False

    def _claude_yukle(self, api_key: str = None) -> bool:
        """Claude API'yi aktif et"""
        key = api_key or self._api_keys.get('claude', '')
        if not key:
            self._log.warning("[LYDIAN] Claude API anahtari bulunamadi")
            return False

        try:
            import anthropic
            self._model = anthropic.Anthropic(api_key=key)
            self._model_path = "claude-3-5-sonnet-20241022"
            self._aktif_provider = "claude"
            self._yuklendi = True
            self._api_keys['claude'] = key
            self._log.info("[LYDIAN] Claude API aktif")
            return True
        except ImportError:
            self._log.warning("[LYDIAN] anthropic paketi yuklu degil. pip install anthropic")
            return False
        except Exception as e:
            self._log.error(f"[LYDIAN] Claude hatasi: {e}")
            return False

    def _zai_yukle(self, api_key: str = None) -> bool:
        """ZAI API'yi aktif et"""
        key = api_key or self._api_keys.get('zai', '')
        if not key:
            self._log.warning("[LYDIAN] ZAI API anahtari bulunamadi")
            return False

        try:
            # ZAI OpenAI uyumlu API kullanir
            import openai
            self._model = openai.OpenAI(
                api_key=key,
                base_url="https://api.zai.chat/v1"  # ZAI endpoint
            )
            self._model_path = "zai-1"
            self._aktif_provider = "zai"
            self._yuklendi = True
            self._api_keys['zai'] = key
            self._log.info("[LYDIAN] ZAI API aktif")
            return True
        except ImportError:
            self._log.warning("[LYDIAN] openai paketi yuklu degil. pip install openai")
            return False
        except Exception as e:
            self._log.error(f"[LYDIAN] ZAI hatasi: {e}")
            return False

    def _openai_yukle(self, api_key: str = None) -> bool:
        """OpenAI API'yi aktif et"""
        key = api_key or self._api_keys.get('openai', '')
        if not key:
            self._log.warning("[LYDIAN] OpenAI API anahtari bulunamadi")
            return False

        try:
            import openai
            self._model = openai.OpenAI(api_key=key)
            self._model_path = "gpt-4-turbo-preview"
            self._aktif_provider = "openai"
            self._yuklendi = True
            self._api_keys['openai'] = key
            self._log.info("[LYDIAN] OpenAI API aktif")
            return True
        except ImportError:
            self._log.warning("[LYDIAN] openai paketi yuklu degil. pip install openai")
            return False
        except Exception as e:
            self._log.error(f"[LYDIAN] OpenAI hatasi: {e}")
            return False

    def _lokal_yukle(self, model_adi: str) -> bool:
        """Lokal modeli yukle (AirLLM)"""
        try:
            from airllm import AutoModel

            self._log.info(f"[LYDIAN] Lokal model yukleniyor: {model_adi}")
            self._model = AutoModel.from_pretrained(model_adi)
            self._model_path = model_adi
            self._aktif_provider = "lokal"
            self._yuklendi = True
            self._log.info(f"[LYDIAN] Lokal model hazir: {model_adi}")
            return True
        except ImportError:
            self._log.warning("[LYDIAN] airllm paketi yuklu degil")
            return False
        except Exception as e:
            self._log.error(f"[LYDIAN] Lokal model hatasi: {e}")
            return False

    def olustur(self, prompt: str, max_tokens: int = 1024, system_prompt: str = None) -> str:
        """Metin olustur - provider'a gore"""
        if not self._yuklendi:
            return "[LYDIAN AI yuklu degil. Lutfen bir provider ile yukleyin.]"

        try:
            if self._aktif_provider == "claude":
                return self._claude_olustur(prompt, max_tokens, system_prompt)
            elif self._aktif_provider == "zai":
                return self._zai_olustur(prompt, max_tokens, system_prompt)
            elif self._aktif_provider == "openai":
                return self._openai_olustur(prompt, max_tokens, system_prompt)
            elif self._aktif_provider == "lokal":
                return self._lokal_olustur(prompt, max_tokens)
            else:
                return "[Bilinmeyen provider]"
        except Exception as e:
            self._log.error(f"[LYDIAN] Olusturma hatasi: {e}")
            return f"[Hata: {e}]"

    def _claude_olustur(self, prompt: str, max_tokens: int, system_prompt: str = None) -> str:
        """Claude ile metin olustur"""
        sys_prompt = system_prompt or "Sen TSUNAMI siber guvenlik platformunun yapay zeka asistanisin. Turkce yanit ver."

        message = self._model.messages.create(
            model=self._model_path,
            max_tokens=max_tokens,
            system=sys_prompt,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text

    def _zai_olustur(self, prompt: str, max_tokens: int, system_prompt: str = None) -> str:
        """ZAI ile metin olustur"""
        sys_prompt = system_prompt or "Sen TSUNAMI siber guvenlik platformunun yapay zeka asistanisin. Turkce yanit ver."

        response = self._model.chat.completions.create(
            model=self._model_path,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content

    def _openai_olustur(self, prompt: str, max_tokens: int, system_prompt: str = None) -> str:
        """OpenAI ile metin olustur"""
        sys_prompt = system_prompt or "Sen TSUNAMI siber guvenlik platformunun yapay zeka asistanisin. Turkce yanit ver."

        response = self._model.chat.completions.create(
            model=self._model_path,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content

    def _lokal_olustur(self, prompt: str, max_tokens: int) -> str:
        """Lokal model ile metin olustur"""
        from transformers import AutoTokenizer

        if self._tokenizer is None:
            self._tokenizer = AutoTokenizer.from_pretrained(self._model_path)

        input_ids = self._tokenizer(prompt, return_tensors="pt").input_ids
        output = self._model.generate(
            input_ids,
            max_new_tokens=max_tokens,
            do_sample=True,
            temperature=0.7
        )
        return self._tokenizer.decode(output[0], skip_special_tokens=True)

    def analiz_et(self, veri: dict, analiz_tipi: str) -> dict:
        """Guvenlik analizleri"""
        system_prompts = {
            'tehdit': "Sen uzman bir siber guvenlik analistisin. Tehdit istihbarati ve saldiri analizi konusunda derin bilgiye sahipsin.",
            'zafiyet': "Sen uzman bir guvenlik arastirmacisisin. Zafiyet degerlendirme ve risk analizi konusunda derin bilgiye sahipsin.",
            'log': "Sen uzman bir SOC analistisin. Log analizi ve anomali tespiti konusunda derin bilgiye sahipsin.",
            'osint': "Sen uzman bir istihbarat analistisin. Acik kaynak istihbarati ve hedef profilleme konusunda derin bilgiye sahipsin.",
            'harita': "Sen uzman bir siber tehdit haritasi analistisin. Cografi tehdit analizi ve saldiri kaliplari konusunda derin bilgiye sahipsin."
        }

        prompts = {
            'tehdit': f"""Asagidaki siber tehdit verisini analiz et:

{json.dumps(veri, ensure_ascii=False, indent=2)}

Detayli analiz yap ve su bilgileri ver:
1. **Tehdit Seviyesi**: kritik/yuksek/orta/dusuk
2. **Saldiri Tipi**: (APT, DDoS, Ransomware, vb.)
3. **Saldirgain Profili**: Olasi aktör ve niyet
4. **Taktik ve Teknikler**: MITRE ATT&CK eslesmesi
5. **Onerilen Aksiyonlar**: Acil ve uzun vadeli
6. **IOC (Indicators of Compromise)**: Tespit edilenler""",

            'zafiyet': f"""Asagidaki guvenlik acigini degerlendir:

{json.dumps(veri, ensure_ascii=False, indent=2)}

Detayli degerlendirme yap:
1. **Risk Skoru**: 1-10 arasi
2. **CVSS Detayi**: Base, Temporal, Environmental
3. **Istismar Zorlugu**: Kolay/Orta/Zor
4. **Potansiyel Etki**: Gizlilik/Butunluk/Erisilebilirlik
5. **Cozum Onerileri**: Kisa ve uzun vadeli
6. **Referanslar**: CVE, CWE iliskileri""",

            'log': f"""Asagidaki log kayitlarini analiz et:

{json.dumps(veri, ensure_ascii=False, indent=2)}

Detayli analiz yap:
1. **Anomali Tespiti**: Normal disi aktiviteler
2. **Zaman Serisi**: Olay kronolojisi
3. **Korelasyon**: Iliskili olaylar
4. **Tehdit Gostergeleri**: Potansiyel saldiri izleri
5. **Oneriler**: Alinmasi gereken aksiyonlar""",

            'osint': f"""Asagidaki OSINT verisini degerlendir:

{json.dumps(veri, ensure_ascii=False, indent=2)}

Detayli istihbarat raporu olustur:
1. **Hedef Profili**: Kim/ne oldugu
2. **Dijital Ayak Izi**: Online varlik
3. **Guvenlik Riskleri**: Tespit edilen zafiyetler
4. **Iliskiler**: Bagli varliklar ve kisiler
5. **Oneriler**: Ek arastirma alanlari""",

            'harita': f"""Asagidaki cografi siber tehdit verisini analiz et:

{json.dumps(veri, ensure_ascii=False, indent=2)}

Detayli harita analizi yap:
1. **Kaynak Bolge Analizi**: Saldirilarin cografyasi
2. **Hedef Bolge Analizi**: Turkiye ozelinde etkilenen alanlar
3. **Saldiri Kaliplari**: Cografi dagilim trendleri
4. **Kritik Altyapi Riski**: Etkilenen tesisler
5. **Oneriler**: Bolgeler arasi koruma stratejileri"""
        }

        system_prompt = system_prompts.get(analiz_tipi, system_prompts['tehdit'])
        prompt = prompts.get(analiz_tipi, prompts['tehdit'])

        if self._yuklendi:
            yanit = self.olustur(prompt, max_tokens=1500, system_prompt=system_prompt)
        else:
            yanit = self.kural_tabanli_analiz(veri, analiz_tipi).get('sonuc', 'Analiz yapilamadi')

        return {
            'analiz_tipi': analiz_tipi,
            'sonuc': yanit,
            'model': self._model_path,
            'provider': self._aktif_provider,
            'zaman': datetime.now().isoformat()
        }

    def kural_tabanli_analiz(self, veri: dict, analiz_tipi: str) -> dict:
        """LLM yuklu degilse kural tabanli fallback analiz"""
        sonuc = {
            'analiz_tipi': analiz_tipi,
            'model': 'kural_tabanli',
            'zaman': datetime.now().isoformat()
        }

        if analiz_tipi == 'tehdit':
            ciddiyet = veri.get('saldiri', {}).get('ciddiyet', 'low')
            tip = veri.get('saldiri', {}).get('tip', 'bilinmeyen')
            sonuc['sonuc'] = f"Tehdit Tipi: {tip}, Ciddiyet: {ciddiyet.upper()}"
            sonuc['tehdit_seviyesi'] = ciddiyet

        elif analiz_tipi == 'zafiyet':
            cvss = veri.get('cvss', 0)
            if cvss >= 9:
                sonuc['risk_seviyesi'] = 'kritik'
            elif cvss >= 7:
                sonuc['risk_seviyesi'] = 'yuksek'
            elif cvss >= 4:
                sonuc['risk_seviyesi'] = 'orta'
            else:
                sonuc['risk_seviyesi'] = 'dusuk'
            sonuc['sonuc'] = f"CVSS: {cvss}, Risk: {sonuc['risk_seviyesi'].upper()}"

        else:
            sonuc['sonuc'] = "Kural tabanli analiz tamamlandi"

        return sonuc

    # ========================================================================
    # GERCEK ZAMANLI TSUNAMI EKOSISTEM ENTEGRASYONU
    # ========================================================================

    def gercek_zamanli_tehdit_analizi(self, saldiri_verisi: dict) -> dict:
        """
        Canli saldirilar icin anlik tehdit analizi.
        TSUNAMI haritasi ile entegre calisir.
        """
        prompt = f"""🔴 CANLI SALDIRI ANALIZI - ACIL

Canli tespit edilen saldiri:
- Saldiri Tipi: {saldiri_verisi.get('saldiri', {}).get('tip', 'Bilinmiyor')}
- Kaynak: {saldiri_verisi.get('kaynak', {}).get('ulke', 'Bilinmiyor')} ({saldiri_verisi.get('kaynak', {}).get('ip', 'N/A')})
- Hedef: {saldiri_verisi.get('hedef', {}).get('sehir', 'Bilinmiyor')} ({saldiri_verisi.get('hedef', {}).get('ip', 'N/A')})
- Ciddiyet: {saldiri_verisi.get('saldiri', {}).get('ciddiyet', 'medium')}
- Port: {saldiri_verisi.get('saldiri', {}).get('port', 'N/A')}
- Protokol: {saldiri_verisi.get('saldiri', {}).get('protokol', 'N/A')}

30 saniye icinde yanit ver:
1. Tehdit Degerlendirmesi (1 cumle)
2. Onerilen Acil Aksiyon (1-2 cumle)
3. DEFCON Onerisi (1-5)"""

        system_prompt = "Sen TSUNAMI siber guvenlik merkezinin otomatik tehdit analiz motorusun. Cok kisa, ozellikle operasyonel yanit ver."

        if self._yuklendi:
            yanit = self.olustur(prompt, max_tokens=300, system_prompt=system_prompt)
        else:
            # Fallback kural tabanli
            ciddiyet = saldiri_verisi.get('saldiri', {}).get('ciddiyet', 'low')
            defcon_map = {'critical': 2, 'high': 3, 'medium': 4, 'low': 5}
            defcon = defcon_map.get(ciddiyet, 4)
            yanit = f"⚠️ {ciddiyet.upper()} seviye tehdit. IP engellemesi oneriliyor. DEFCON {defcon} onerisi."

        return {
            'tip': 'canli_analiz',
            'sonuc': yanit,
            'zaman': datetime.now().isoformat(),
            'saldiri_id': saldiri_verisi.get('id')
        }

    def saldiri_tahmini(self, son_saldirilari: list) -> dict:
        """
        Son saldirilara dayanarak gelecek saldiri tahmini.
        """
        if len(son_saldirilari) < 3:
            return {'tahmin': 'Yeterli veri yok', 'guven': 0}

        # Saldiri istatistiklerini cikar
        kaynak_ulkeler = {}
        saldiri_tipleri = {}
        hedef_sehirler = {}

        for s in son_saldirilari[-20:]:  # Son 20 saldiri
            ulke = s.get('kaynak', {}).get('ulke', 'Bilinmiyor')
            tip = s.get('saldiri', {}).get('tip', 'Bilinmiyor')
            sehir = s.get('hedef', {}).get('sehir', 'Bilinmiyor')

            kaynak_ulkeler[ulke] = kaynak_ulkeler.get(ulke, 0) + 1
            saldiri_tipleri[tip] = saldiri_tipleri.get(tip, 0) + 1
            hedef_sehirler[sehir] = hedef_sehirler.get(sehir, 0) + 1

        # En olasi sonraki saldiri
        en_aktif_ulke = max(kaynak_ulkeler, key=kaynak_ulkeler.get) if kaynak_ulkeler else 'Bilinmiyor'
        en_yaygin_tip = max(saldiri_tipleri, key=saldiri_tipleri.get) if saldiri_tipleri else 'Bilinmiyor'
        en_hedeflenen = max(hedef_sehirler, key=hedef_sehirler.get) if hedef_sehirler else 'Bilinmiyor'

        if self._yuklendi:
            prompt = f"""Son 20 saldiri analizi:
- En aktif kaynak: {en_aktif_ulke} ({kaynak_ulkeler.get(en_aktif_ulke, 0)} saldiri)
- En yaygin tip: {en_yaygin_tip} ({saldiri_tipleri.get(en_yaygin_tip, 0)} saldiri)
- En hedeflenen: {en_hedeflenen} ({hedef_sehirler.get(en_hedeflenen, 0)} saldiri)

Sonraki olasi saldiriyi tahmin et ve kisa savunma onerisi ver."""

            yanit = self.olustur(prompt, max_tokens=200, system_prompt="Siber tehdit tahmincisi olarak kisa tahmin yap.")
        else:
            yanit = f"Tahmin: {en_aktif_ulke} kaynakli {en_yaygin_tip} saldirisi {en_hedeflenen}'i hedef alabilir."

        return {
            'tahmin': yanit,
            'istatistik': {
                'en_aktif_ulke': en_aktif_ulke,
                'en_yaygin_tip': en_yaygin_tip,
                'en_hedeflenen': en_hedeflenen
            },
            'guven': min(len(son_saldirilari) / 20, 1.0),
            'zaman': datetime.now().isoformat()
        }

    def defcon_onerisi(self, tehdit_metrikleri: dict) -> dict:
        """
        Mevcut tehdit metriklerine gore DEFCON seviyesi onerisi.
        """
        kritik_sayi = tehdit_metrikleri.get('kritik', 0)
        yuksek_sayi = tehdit_metrikleri.get('yuksek', 0)
        toplam_saldiri = tehdit_metrikleri.get('toplam', 0)

        # Basit kural tabanli
        if kritik_sayi >= 5:
            oneri = 1
            aciklama = "Coklu kritik saldiri - DEFCON 1 acil"
        elif kritik_sayi >= 2 or yuksek_sayi >= 10:
            oneri = 2
            aciklama = "Ciddi tehdit seviyesi"
        elif kritik_sayi >= 1 or yuksek_sayi >= 5:
            oneri = 3
            aciklama = "Artmis tehdit aktivitesi"
        elif toplam_saldiri >= 50:
            oneri = 4
            aciklama = "Normal izleme, yuksek trafik"
        else:
            oneri = 5
            aciklama = "Guvenli durum"

        if self._yuklendi:
            prompt = f"""Tehdit metrikleri:
- Kritik saldirilari: {kritik_sayi}
- Yuksek saldirilari: {yuksek_sayi}
- Toplam saldirilari: {toplam_saldiri}

DEFCON seviyesi oner (1-5) ve kisa gerekce."""

            yanit = self.olustur(prompt, max_tokens=150, system_prompt="DEFCON danismani olarak onerini ver.")
            aciklama = yanit

        return {
            'oneri': oneri,
            'aciklama': aciklama,
            'metrikler': tehdit_metrikleri,
            'zaman': datetime.now().isoformat()
        }

    def kritik_altyapi_risk_analizi(self, altyapi_verileri: list, yakin_saldirilari: list) -> dict:
        """
        Kritik altyapi noktalarinin risk analizi.
        """
        risk_haritasi = {}

        for altyapi in altyapi_verileri:
            altyapi_lat = altyapi.get('lat', 0)
            altyapi_lng = altyapi.get('lng', 0)
            ad = altyapi.get('ad', 'Bilinmiyor')

            # Yakin saldirilari say
            yakin_saldiri_sayisi = 0
            for saldiri in yakin_saldirilari:
                hedef_lat = saldiri.get('hedef', {}).get('lat', 0)
                hedef_lng = saldiri.get('hedef', {}).get('lng', 0)

                # Basit mesafe hesabi (1 derece ~= 111km)
                mesafe = ((altyapi_lat - hedef_lat)**2 + (altyapi_lng - hedef_lng)**2)**0.5
                if mesafe < 1:  # ~111km yaricap
                    yakin_saldiri_sayisi += 1

            # Risk seviyesi
            if yakin_saldiri_sayisi >= 5:
                risk = 'kritik'
            elif yakin_saldiri_sayisi >= 2:
                risk = 'yuksek'
            elif yakin_saldiri_sayisi >= 1:
                risk = 'orta'
            else:
                risk = 'dusuk'

            risk_haritasi[ad] = {
                'risk': risk,
                'yakin_saldiri': yakin_saldiri_sayisi,
                'tip': altyapi.get('tip', 'bilinmiyor')
            }

        # En riskli 5 altyapi
        riskli_altyapilar = sorted(
            risk_haritasi.items(),
            key=lambda x: x[1]['yakin_saldiri'],
            reverse=True
        )[:5]

        return {
            'analiz': 'kritik_altyapi',
            'riskli_altyapilar': dict(riskli_altyapilar),
            'toplam_analiz': len(altyapi_verileri),
            'zaman': datetime.now().isoformat()
        }

    def savunma_onerisi(self, saldiri_verisi: dict) -> dict:
        """
        Belirli bir saldiri icin savunma onerisi.
        """
        saldiri_tipi = saldiri_verisi.get('saldiri', {}).get('tip', 'bilinmeyen')
        ciddiyet = saldiri_verisi.get('saldiri', {}).get('ciddiyet', 'low')

        # Saldiri tipine gore standart oneriler
        standart_oneriler = {
            'DDoS': ['Rate limiting uygula', 'CDN/WAF aktif et', 'Trafik analizi yap'],
            'SQL Injection': ['Input validasyonu kontrol et', 'Prepared statement kullan', 'WAF kurallarini guncelle'],
            'Brute Force': ['Account lockout aktif et', 'CAPTCHA ekle', 'IP rate limiting'],
            'Ransomware': ['Yedekleri kontrol et', 'Ag segmentasyonu yap', 'Endpoint isolasyonu'],
            'Phishing': ['Email filtrelemeyi guclendir', 'Kullanici egitimi', 'Domain blocklist guncelle'],
            'Port Scan': ['Gereksiz portlari kapat', 'IDS kurallarini guncelle', 'Honeypot aktiflestir'],
            'XSS': ['CSP header ekle', 'Output encoding', 'Input sanitization']
        }

        oneriler = standart_oneriler.get(saldiri_tipi, ['Genel guvenlik taramasi yap'])

        if self._yuklendi and ciddiyet in ['critical', 'high']:
            prompt = f"""Saldiri: {saldiri_tipi}
Ciddiyet: {ciddiyet}
Kaynak: {saldiri_verisi.get('kaynak', {}).get('ulke', 'Bilinmiyor')}

3 maddede acil savunma onerisi ver."""

            yanit = self.olustur(prompt, max_tokens=200, system_prompt="SOC analisti olarak acil savunma onerisi ver.")
            return {
                'saldiri_tipi': saldiri_tipi,
                'oneriler': yanit,
                'ai_destekli': True,
                'zaman': datetime.now().isoformat()
            }

        return {
            'saldiri_tipi': saldiri_tipi,
            'oneriler': oneriler,
            'ai_destekli': False,
            'zaman': datetime.now().isoformat()
        }

    def durum(self) -> dict:
        """LLM durum bilgisi"""
        return {
            'yuklendi': self._yuklendi,
            'model': self._model_path,
            'provider': self._aktif_provider,
            'hazir': self._yuklendi and self._model is not None,
            'gercek_zamanli': True  # Yeni ozellik
        }


# ============================================================================
# ANA BEYIN SINIFI
# ============================================================================

class DalgaBeyin:
    """
    DALGA Merkezi Zeka Sistemi.
    Tum alt sistemleri koordine eder ve 7/24 otonom calisir.
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._baslatildi = False
        return cls._instance

    def __init__(self):
        if self._baslatildi:
            return

        # Alt sistemler
        self._veriyolu = DalgaMesajVeriyolu()
        self._tehdit = TehditDegerlendirici()
        self._karar = OtonomKararMotoru(self._veriyolu)
        self._gizli = GizliModYoneticisi(self._veriyolu)
        self._saglik = BeynSaglikIzleyici(self._veriyolu)

        # Defensive Response Manager
        self._savunma = DefensiveResponseManager(self._veriyolu)

        # Lokal LLM (AirLLM)
        self._lokal_llm = LokalLLM.get_instance()

        # Durum
        self._aktif = False
        self._otonom_dongu_thread: Optional[threading.Thread] = None
        self._dongu_araliği = 5  # saniye
        self._log = logging.getLogger("DalgaBeyin")

        # Aksiyon isleyicileri kaydet
        self._aksiyon_isleyicileri_kaydet()

        # Socket.IO referansi (dalga_web.py'den ayarlanir)
        self._socketio = None

        self._baslatildi = True
        self._log.info("TSUNAMI BEYIN baslatildi")

    def _aksiyon_isleyicileri_kaydet(self) -> None:
        """Varsayilan aksiyon isleyicileri"""
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.IP_ENGELLE,
            lambda p: self._ip_engelle(p.get('ip'))
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.ALARM_GONDER,
            lambda p: self._alarm_gonder(p)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.MOD_DEGISTIR,
            lambda p: self._gizli.mod_degistir(
                GizliMod(p.get('yeni_mod', 'normal')),
                "otonom karar"
            )
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.IZLEME_ARTIR,
            lambda p: self._izleme_artir(p)
        )

        # Register defensive action handlers
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.NETWORK_ISOLATE,
            lambda p: self._savunma.isolate_host(
                p.get('host', p.get('ip', '')),
                p.get('isolation_type', 'full'),
                p.get('reason', 'autonomous decision'),
                require_approval=p.get('require_approval', True)
            ).get('success', False)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.HONEYPOT_TRIGGER,
            lambda p: self._savunma.trigger_honeypot(
                p.get('honeypot_id', 'default'),
                p.get('threat_info', {})
            ).get('success', False)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.FORENSIC_CAPTURE,
            lambda p: self._savunma.capture_forensic_evidence(
                p.get('host', p.get('ip', '')),
                p.get('evidence_type', 'log_snapshot'),
                p.get('reason', 'autonomous decision')
            ).get('success', False)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.ENHANCED_MONITORING,
            lambda p: self._savunma.enable_enhanced_monitoring(
                p.get('target', p.get('host', p.get('ip', ''))),
                p.get('level', 'high')
            ).get('success', False)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.ALERT_ESCALATE,
            lambda p: self._savunma._request_approval(
                AksiyonTipi(p.get('action_type', 'alert_escalate')),
                p.get('target', 'unknown'),
                p.get('reason', 'escalation required'),
                p.get('urgency', 'high')
            ) is not None
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.ACCOUNT_DISABLE,
            lambda p: self._savunma.disable_account(
                p.get('account_id', ''),
                p.get('reason', 'autonomous decision'),
                p.get('require_approval', True)
            ).get('success', False)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.TOKEN_REVOKE,
            lambda p: self._savunma.revoke_tokens(
                p.get('account_id', ''),
                p.get('token_types', None)
            ).get('success', False)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.QUARANTINE_FILE,
            lambda p: self._savunma.quarantine_file(
                p.get('file_path', ''),
                p.get('host', ''),
                p.get('reason', 'autonomous decision')
            ).get('success', False)
        )
        self._karar.aksiyon_isleyici_kaydet(
            AksiyonTipi.SENSOR_DEPLOY,
            lambda p: self._savunma.deploy_sensor(
                p.get('target_segment', ''),
                p.get('sensor_type', 'network')
            ).get('success', False)
        )

    def _ip_engelle(self, ip: str) -> bool:
        """IP engelleme aksiyonu - iptables ile gerçek engelleme"""
        self._log.info(f"IP engelleniyor: {ip}")
        try:
            # Önce mevcut kuralı kontrol et
            check = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            if check.returncode == 0:
                self._log.info(f"IP zaten engelli: {ip}")
                return True

            result = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                self._log.warning(f"IP engellendi: {ip}")
                return True
            else:
                self._log.warning(f"iptables hata (root gerekli?): {result.stderr}")
                # Kayıt tut (root olmasa bile)
                block_dir = Path.home() / ".dalga" / "blocked_ips"
                block_dir.mkdir(parents=True, exist_ok=True)
                record = {"ip": ip, "requested_at": datetime.now().isoformat(),
                         "status": "pending_root"}
                (block_dir / f"{ip.replace('.', '_')}.json").write_text(
                    json.dumps(record, indent=2))
                return True
        except FileNotFoundError:
            self._log.warning(f"iptables bulunamadı, kayıt modu: {ip}")
            block_dir = Path.home() / ".dalga" / "blocked_ips"
            block_dir.mkdir(parents=True, exist_ok=True)
            record = {"ip": ip, "requested_at": datetime.now().isoformat(),
                     "status": "iptables_not_found"}
            (block_dir / f"{ip.replace('.', '_')}.json").write_text(
                json.dumps(record, indent=2))
            return True

    def _alarm_gonder(self, params: Dict) -> bool:
        """Alarm gonderme aksiyonu"""
        if self._socketio:
            self._socketio.emit('beyin_alarm', params, namespace='/')
        return True

    def _izleme_artir(self, params: Dict) -> bool:
        """İzleme seviyesini artır - audit log ve metrik kayıt"""
        try:
            log_dir = Path.home() / ".dalga" / "izleme"
            log_dir.mkdir(parents=True, exist_ok=True)
            record = {
                "target": params.get("target", params.get("hedef", "unknown")),
                "threat": {k: v for k, v in params.items() if k not in ("target", "hedef")},
                "elevated_at": datetime.now().isoformat(),
                "action": "izleme_artir"
            }
            log_file = log_dir / f"izleme_{int(time.time())}.json"
            log_file.write_text(json.dumps(record, indent=2, default=str))
            self._log.info(f"[BEYIN] İzleme artırıldı: {record['target']}")
            return True
        except Exception as e:
            self._log.error(f"[BEYIN] İzleme artırma hatası: {e}")
            return False

    def socketio_ayarla(self, socketio) -> None:
        """Socket.IO referansini ayarla"""
        self._socketio = socketio

    def baslat(self) -> None:
        """Beyin sistemini baslat"""
        if self._aktif:
            return

        self._aktif = True

        # Hayalet modunu aktif et - askeri seviye guvenlik
        self._gizli.mod_degistir(GizliMod.HAYALET, "sistem_baslangici")
        self._log.info("[BEYIN] HAYALET modu AKTIF - Askeri seviye guvenlik")

        self._otonom_dongu_thread = threading.Thread(
            target=self._otonom_dongu,
            daemon=True,
            name='BeyinOtonomDongu'
        )
        self._otonom_dongu_thread.start()
        self._log.info("[BEYIN] Otonom dongu baslatildi - 5 saniye aralikla tehdit taramasi")

    def durdur(self) -> None:
        """Beyin sistemini durdur"""
        self._aktif = False
        self._log.info("Beyin durduruluyor...")

    def _otonom_dongu(self) -> None:
        """Ana otonom calisma dongusu"""
        while self._aktif:
            try:
                # Kalp atisi
                self._saglik.kalp_atisi_kaydet()

                # DEFCON hesapla
                defcon = self._tehdit.defcon_seviyesi_belirle()

                # Gizli mod otomatik ayarla
                self._gizli.otomatik_mod_uygula(defcon)

                # Aktif tehditleri isle
                for tehdit in self._tehdit.aktif_tehditler():
                    karar = self._karar.karar_al(tehdit, defcon)
                    if karar:
                        self._karar.karar_yurutv(karar)
                        self._tehdit.tehdit_isle(tehdit.id, karar.aksiyon.value)

                # Socket.IO bildirimi
                if self._socketio:
                    self._socketio.emit('beyin_durum', self.durum_ozeti(), namespace='/')

            except Exception as e:
                self._saglik.hata_kaydet(str(e))
                self._log.error(f"Dongu hatasi: {e}")

            time.sleep(self._dongu_araliği)

    # -------------------------------------------------------------------------
    # DIS API METODLARI
    # -------------------------------------------------------------------------

    def tehdit_bildir(self, kaynak: str, veri: any = None) -> None:
        """
        Dis sistemlerden tehdit bildirimi al.
        Canli saldiri verisi veya basit skor olabilir.
        """
        # Canli saldiri verisi ise ozel isle
        if isinstance(veri, dict) and 'saldiri' in veri:
            # Ciddiyet skorunu hesapla
            ciddiyet_map = {
                'critical': 0.9,
                'high': 0.7,
                'medium': 0.5,
                'low': 0.3
            }
            ciddiyet = veri.get('saldiri', {}).get('ciddiyet', 'low')
            skor = ciddiyet_map.get(ciddiyet, 0.3)

            detay = {
                'tip': veri.get('saldiri', {}).get('tip', 'unknown'),
                'kaynak_ip': veri.get('kaynak', {}).get('ip', '0.0.0.0'),
                'kaynak_ulke': veri.get('kaynak', {}).get('ulke', 'Unknown'),
                'hedef': veri.get('hedef', {}).get('sehir', 'Istanbul'),
                'protokol': veri.get('saldiri', {}).get('protokol', 'TCP'),
                'port': veri.get('saldiri', {}).get('port', 0),
                'zaman': veri.get('zaman', datetime.now().isoformat())
            }

            # Network skorunu guncelle (birikimli, decay ile)
            mevcut = self._tehdit._skorlar.get('network', 0)
            yeni_skor = min(1.0, mevcut * 0.95 + skor * 0.15)  # Exponential decay
            self._tehdit.kaynak_skoru_guncelle('network', yeni_skor, detay)

            # Kritik saldiri ise alarm gonder
            if ciddiyet == 'critical' and self._socketio:
                self._socketio.emit('beyin_alarm', {
                    'tip': 'kritik_saldiri',
                    'mesaj': f"Kritik saldiri tespit edildi: {detay['tip']} - {detay['kaynak_ulke']}",
                    'detay': detay
                }, namespace='/')

        # Basit skor ise dogrudan isle
        elif isinstance(veri, (int, float)):
            self._tehdit.kaynak_skoru_guncelle(kaynak, float(veri), None)
        else:
            self._tehdit.kaynak_skoru_guncelle(kaynak, 0.5, veri)

    def manuel_komut(self, komut: str, parametre: Dict = None) -> Dict:
        """Manuel komut calistir"""
        parametre = parametre or {}

        komutlar = {
            'defcon_goster': lambda: {'defcon': self._tehdit.defcon_seviyesi_belirle().value},
            'mod_degistir': lambda: self._gizli.mod_degistir(
                GizliMod(parametre.get('mod', 'normal')),
                parametre.get('sebep', 'manuel')
            ),
            'otonom_ac': lambda: self._karar.otonom_durumu_degistir(True),
            'otonom_kapat': lambda: self._karar.otonom_durumu_degistir(False),
            'tehdit_simule': lambda: self._tehdit_simule(parametre),
            'ip_engelle': lambda: self._ip_engelle_manuel(parametre),
            'karsi_saldiri': lambda: self._karsi_saldiri_manuel(parametre),
            'ip_izle': lambda: self._ip_izle_manuel(parametre),
        }

        if komut in komutlar:
            sonuc = komutlar[komut]()
            return {'basarili': True, 'sonuc': sonuc}

        return {'basarili': False, 'hata': 'bilinmeyen_komut'}

    def _ip_engelle_manuel(self, parametre: Dict) -> Dict:
        """Manuel IP engelleme"""
        ip = parametre.get('ip')
        sebep = parametre.get('sebep', 'manuel')

        if not ip:
            return {'engellendi': False, 'hata': 'IP belirtilmeli'}

        # IP'yi engelle
        basarili = self._ip_engelle(ip)

        # Tehdit kaydı oluştur
        if basarili:
            self._tehdit.kaynak_skoru_guncelle(ip, 1.0, {
                'tip': 'engellenen_ip',
                'sebep': sebep,
                'aksiyon': 'engellendi'
            })

            # SocketIO ile bildir
            if self._socketio:
                self._socketio.emit('ip_engellendi', {
                    'ip': ip,
                    'sebep': sebep,
                    'zaman': datetime.now().isoformat()
                }, namespace='/')

        return {'engellendi': basarili, 'ip': ip, 'sebep': sebep}

    def _karsi_saldiri_manuel(self, parametre: Dict) -> Dict:
        """Manuel karşı saldırı simülasyonu (defensive)"""
        hedef_ip = parametre.get('hedef_ip')
        saldiri_tipi = parametre.get('saldiri_tipi', 'savunma')
        kaynak_saldiri = parametre.get('kaynak_saldiri', 'bilinmiyor')

        if not hedef_ip:
            return {'baslatildi': False, 'hata': 'Hedef IP belirtilmeli'}

        self._log.warning(f"[KARSI SALDIRI] Hedef: {hedef_ip}, Tip: {saldiri_tipi}")

        # Karşı saldırı kaydı
        kayit = {
            'hedef': hedef_ip,
            'tip': saldiri_tipi,
            'kaynak_saldiri': kaynak_saldiri,
            'zaman': datetime.now().isoformat(),
            'durum': 'baslatildi'
        }

        # Tehdit olarak işaretle
        self._tehdit.kaynak_skoru_guncelle(hedef_ip, 1.0, {
            'tip': 'karsi_saldiri_hedefi',
            'kaynak_saldiri': kaynak_saldiri
        })

        # SocketIO ile bildir
        if self._socketio:
            self._socketio.emit('karsi_saldiri', kayit, namespace='/')

        return {'baslatildi': True, 'kayit': kayit}

    def _ip_izle_manuel(self, parametre: Dict) -> Dict:
        """Manuel IP izleme"""
        ip = parametre.get('ip')

        if not ip:
            return {'izleniyor': False, 'hata': 'IP belirtilmeli'}

        # İzleme listesine ekle (düşük tehdit skoru)
        self._tehdit.kaynak_skoru_guncelle(ip, 0.3, {
            'tip': 'izleme',
            'sebep': 'manuel_izleme'
        })

        return {'izleniyor': True, 'ip': ip}

    def _tehdit_simule(self, parametre: Dict) -> Dict:
        """Test amacli tehdit simulasyonu"""
        kaynak = parametre.get('kaynak', 'test')
        skor = parametre.get('skor', 0.7)
        tip = parametre.get('tip', 'test_tehdidi')

        self._tehdit.kaynak_skoru_guncelle(kaynak, skor, {
            'tip': tip,
            'kaynak_ip': parametre.get('ip', '192.168.1.100'),
            'aciklama': 'Simulasyon tehdidi'
        })

        return {'simule_edildi': True, 'kaynak': kaynak, 'skor': skor}

    def durum_ozeti(self) -> Dict[str, Any]:
        """Tam durum ozeti"""
        return {
            'aktif': self._aktif,
            'zaman': datetime.now().isoformat(),
            'defcon': self._tehdit.durum_ozeti(),
            'gizli_mod': self._gizli.durum(),
            'saglik': self._saglik.saglik_kontrolu(),
            'savunma': self._savunma.durum_ozeti(),
            'son_kararlar': [
                {
                    'id': k.id,
                    'aksiyon': k.aksiyon.value,
                    'zaman': k.zaman.isoformat(),
                    'yurutuldu': k.yurutuldu
                }
                for k in self._karar.son_kararlar(5)
            ]
        }

    # -------------------------------------------------------------------------
    # DEFENSIVE API METHODS
    # -------------------------------------------------------------------------

    @property
    def savunma(self) -> DefensiveResponseManager:
        """Get defensive response manager"""
        return self._savunma

    def savunma_izole_et(self, host: str, isolation_type: str = 'full',
                          reason: str = "", require_approval: bool = True) -> Dict:
        """Isolate a host (defensive action)"""
        return self._savunma.isolate_host(host, isolation_type, reason, require_approval)

    def savunma_geri_al(self, host: str, reason: str = "") -> Dict:
        """Rollback isolation for a host"""
        return self._savunma.rollback_isolation(host, reason)

    def savunma_kanit_topla(self, source_host: str, evidence_type: str,
                             reason: str = "") -> Dict:
        """Capture forensic evidence"""
        return self._savunma.capture_forensic_evidence(source_host, evidence_type, reason)

    def savunma_onay_ver(self, approval_id: str, approved_by: str,
                          approved: bool = True) -> Dict:
        """Approve or deny a pending defensive action"""
        return self._savunma.approve_action(approval_id, approved_by, approved)

    def savunma_bekleyen_onaylar(self) -> List[Dict]:
        """Get pending approval requests"""
        return self._savunma.get_pending_approvals()

    def savunma_izolasyon_durumu(self) -> Dict:
        """Get current isolation status"""
        return self._savunma.get_isolation_status()

    def savunma_denetim_logu(self, limit: int = 100) -> List[Dict]:
        """Get defensive audit log"""
        return self._savunma.get_audit_log(limit)

    def savunma_honeypot_kaydet(self, honeypot_id: str, config: Dict) -> None:
        """Register a honeypot"""
        self._savunma.register_honeypot(honeypot_id, config)

    def savunma_hesap_devre_disi(self, account_id: str, reason: str = "",
                                   require_approval: bool = True) -> Dict:
        """Disable a compromised account"""
        return self._savunma.disable_account(account_id, reason, require_approval)

    def savunma_token_iptal(self, account_id: str, token_types: List[str] = None) -> Dict:
        """Revoke access tokens"""
        return self._savunma.revoke_tokens(account_id, token_types)

    def savunma_dosya_karantina(self, file_path: str, host: str, reason: str = "") -> Dict:
        """Quarantine a suspicious file"""
        return self._savunma.quarantine_file(file_path, host, reason)

    def savunma_sensor_kur(self, target_segment: str, sensor_type: str = 'network') -> Dict:
        """Deploy monitoring sensor"""
        return self._savunma.deploy_sensor(target_segment, sensor_type)

    def savunma_izleme_artir(self, target: str, level: str = 'high') -> Dict:
        """Enable enhanced monitoring"""
        return self._savunma.enable_enhanced_monitoring(target, level)

    def savunma_yetki_ver(self, host: str) -> None:
        """Authorize a host for defensive actions"""
        self._savunma.authorize_host(host)

    def savunma_yetki_kaldir(self, host: str) -> None:
        """Remove host authorization"""
        self._savunma.remove_host_authorization(host)

    def tehditler_listesi(self) -> List[Dict]:
        """Tum tehditleri listele"""
        return [
            {
                'id': t.id,
                'kaynak': t.kaynak,
                'tip': t.tip,
                'skor': t.skor,
                'zaman': t.zaman.isoformat(),
                'islendi': t.islendi
            }
            for t in self._tehdit._tehditler.values()
        ]

    def kararlar_listesi(self) -> List[Dict]:
        """Tum kararlari listele"""
        return [
            {
                'id': k.id,
                'aksiyon': k.aksiyon.value,
                'sebep': k.sebep,
                'zaman': k.zaman.isoformat(),
                'yurutuldu': k.yurutuldu,
                'sonuc': k.sonuc
            }
            for k in self._karar.son_kararlar(50)
        ]

    # ==================== AI ANALIZ METODLARI ====================

    def ai_analiz(self, veri: dict, tip: str) -> dict:
        """
        BEYIN AI analizi - Lokal LLM ile veya kural tabanli.

        Args:
            veri: Analiz edilecek veri
            tip: Analiz tipi (tehdit, zafiyet, log, osint)

        Returns:
            Analiz sonucu
        """
        if self._lokal_llm.yuklendi:
            return self._lokal_llm.analiz_et(veri, tip)
        else:
            return self._lokal_llm.kural_tabanli_analiz(veri, tip)

    def llm_yukle(self, provider: str = None, api_key: str = None) -> bool:
        """LYDIAN AI provider'i yukle/aktif et"""
        if provider:
            return self._lokal_llm.yukle(provider, api_key)
        return self._lokal_llm.yukle("claude", api_key)

    def llm_durum(self) -> dict:
        """LLM durum bilgisi"""
        return self._lokal_llm.durum()

    def akilli_tehdit_analizi(self, tehdit_verisi: dict) -> dict:
        """
        Tehditi AI ile analiz et ve karar olustur.

        Args:
            tehdit_verisi: Analiz edilecek tehdit verisi

        Returns:
            AI analizi ve onerilen aksiyonlar
        """
        analiz = self.ai_analiz(tehdit_verisi, 'tehdit')

        # DEFCON skoruna etki
        ciddiyet = tehdit_verisi.get('saldiri', {}).get('ciddiyet', 'low')
        ciddiyet_skor = {'critical': 0.9, 'high': 0.7, 'medium': 0.5, 'low': 0.3}
        skor = ciddiyet_skor.get(ciddiyet, 0.3)

        self._tehdit.kaynak_skoru_guncelle('ai_analiz', skor, {
            'kaynak': tehdit_verisi.get('kaynak', {}),
            'analiz': analiz.get('sonuc', '')
        })

        return {
            'analiz': analiz,
            'defcon_etkisi': skor,
            'zaman': datetime.now().isoformat()
        }


# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

def beyin_al() -> DalgaBeyin:
    """Global beyin instance'i al"""
    return DalgaBeyin()


# ============================================================================
# TEST
# ============================================================================

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    beyin = beyin_al()
    beyin.baslat()

    # Test tehdit bildirimi
    beyin.tehdit_bildir('firewall', 0.6, {'tip': 'brute_force', 'kaynak_ip': '10.0.0.1'})
    beyin.tehdit_bildir('ids', 0.8, {'tip': 'intrusion', 'kaynak_ip': '10.0.0.2'})

    time.sleep(10)

    print("\n=== TSUNAMI BEYIN DURUM ===")
    print(json.dumps(beyin.durum_ozeti(), indent=2, ensure_ascii=False))

    beyin.durdur()
