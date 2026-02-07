#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI GNN v1.0 - Graph Neural Network Tehdit Tespiti
================================================================================

    PyTorch Geometric ile:
    - Ağ Trafik Anomali Tespiti
    - Saldırı Grafiği Analizi
    - APT (Advanced Persistent Threat) Zincir Tespiti
    - IP İlişki Ağı Analizi
    - Botnet Tespiti
    - Lateral Movement Algılama

================================================================================
"""

import json
import math
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import threading

# PyTorch ve PyG
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch_geometric.data import Data, Batch
    from torch_geometric.nn import GCNConv, GATConv, SAGEConv, global_mean_pool, global_max_pool
    from torch_geometric.utils import to_networkx, from_networkx
    TORCH_AKTIF = True
except ImportError:
    TORCH_AKTIF = False
    print("[GNN] PyTorch Geometric bulunamadı - Mock mod aktif")

# NetworkX (graf görselleştirme için)
try:
    import networkx as nx
    NX_AKTIF = True
except ImportError:
    NX_AKTIF = False


# ==================== ENUM VE DATACLASS ====================

class DugumTipi(Enum):
    """Graf düğüm tipleri"""
    IP_ADRES = "ip"
    DOMAIN = "domain"
    PORT = "port"
    SERVIS = "servis"
    KULLANICI = "kullanici"
    DOSYA = "dosya"
    PROSES = "proses"
    ULKE = "ulke"
    ASN = "asn"


class KenarTipi(Enum):
    """Graf kenar tipleri"""
    BAGLANTI = "baglanti"
    DNS_SORGU = "dns_sorgu"
    HTTP_ISTEK = "http_istek"
    SSH_ERISIM = "ssh_erisim"
    DOSYA_TRANSFER = "dosya_transfer"
    LATERAL_HAREKET = "lateral_hareket"
    C2_ILETISIM = "c2_iletisim"
    EXPLOIT = "exploit"


class TehditSinifi(Enum):
    """Tehdit sınıflandırması"""
    NORMAL = 0
    RECON = 1          # Keşif
    BRUTE_FORCE = 2    # Kaba kuvvet
    EXPLOIT = 3        # Zafiyet istismarı
    C2 = 4             # Komuta kontrol
    LATERAL = 5        # Yanal hareket
    EXFIL = 6          # Veri sızdırma
    APT = 7            # Gelişmiş kalıcı tehdit


@dataclass
class GrafDugum:
    """Graf düğümü"""
    id: str
    tip: DugumTipi
    etiket: str
    ozellikler: Dict[str, Any] = field(default_factory=dict)
    risk_skoru: float = 0.0
    ilk_gorulme: datetime = field(default_factory=datetime.now)
    son_gorulme: datetime = field(default_factory=datetime.now)


@dataclass
class GrafKenar:
    """Graf kenarı"""
    kaynak_id: str
    hedef_id: str
    tip: KenarTipi
    agirlik: float = 1.0
    ozellikler: Dict[str, Any] = field(default_factory=dict)
    zaman: datetime = field(default_factory=datetime.now)


# ==================== GNN MODELLERİ ====================

if TORCH_AKTIF:

    class TehditGCN(nn.Module):
        """
        Graph Convolutional Network - Tehdit Tespiti

        3 katmanlı GCN ile düğüm sınıflandırması
        """

        def __init__(self, girdi_boyut: int = 16, gizli_boyut: int = 64, cikti_boyut: int = 8):
            super(TehditGCN, self).__init__()

            self.conv1 = GCNConv(girdi_boyut, gizli_boyut)
            self.conv2 = GCNConv(gizli_boyut, gizli_boyut)
            self.conv3 = GCNConv(gizli_boyut, gizli_boyut // 2)

            self.fc1 = nn.Linear(gizli_boyut // 2, 32)
            self.fc2 = nn.Linear(32, cikti_boyut)

            self.dropout = nn.Dropout(0.3)
            self.bn1 = nn.BatchNorm1d(gizli_boyut)
            self.bn2 = nn.BatchNorm1d(gizli_boyut)

        def forward(self, x, edge_index, batch=None):
            # GCN katmanları
            x = self.conv1(x, edge_index)
            x = self.bn1(x)
            x = F.relu(x)
            x = self.dropout(x)

            x = self.conv2(x, edge_index)
            x = self.bn2(x)
            x = F.relu(x)
            x = self.dropout(x)

            x = self.conv3(x, edge_index)
            x = F.relu(x)

            # Graf seviyesi pooling
            if batch is not None:
                x = global_mean_pool(x, batch)

            # Tam bağlantılı katmanlar
            x = self.fc1(x)
            x = F.relu(x)
            x = self.dropout(x)
            x = self.fc2(x)

            return F.log_softmax(x, dim=1)


    class AnomaliGAT(nn.Module):
        """
        Graph Attention Network - Anomali Tespiti

        Dikkat mekanizmalı GNN
        """

        def __init__(self, girdi_boyut: int = 16, gizli_boyut: int = 64, head_sayisi: int = 4):
            super(AnomaliGAT, self).__init__()

            self.gat1 = GATConv(girdi_boyut, gizli_boyut // head_sayisi, heads=head_sayisi, dropout=0.3)
            self.gat2 = GATConv(gizli_boyut, gizli_boyut // head_sayisi, heads=head_sayisi, dropout=0.3)
            self.gat3 = GATConv(gizli_boyut, 32, heads=1, concat=False, dropout=0.3)

            self.fc = nn.Linear(32, 1)  # Anomali skoru (0-1)

        def forward(self, x, edge_index, batch=None):
            x = F.elu(self.gat1(x, edge_index))
            x = F.elu(self.gat2(x, edge_index))
            x = self.gat3(x, edge_index)

            if batch is not None:
                x = global_max_pool(x, batch)

            x = torch.sigmoid(self.fc(x))
            return x


    class APTDetector(nn.Module):
        """
        GraphSAGE tabanlı APT Zincir Tespiti

        Saldırı zincirlerini tespit eder
        """

        def __init__(self, girdi_boyut: int = 16, gizli_boyut: int = 128):
            super(APTDetector, self).__init__()

            self.sage1 = SAGEConv(girdi_boyut, gizli_boyut)
            self.sage2 = SAGEConv(gizli_boyut, gizli_boyut)
            self.sage3 = SAGEConv(gizli_boyut, 64)

            # Zincir tespiti için LSTM
            self.lstm = nn.LSTM(64, 32, batch_first=True, bidirectional=True)

            # Çıktı
            self.fc = nn.Linear(64, 2)  # APT / Normal

        def forward(self, x, edge_index, batch=None):
            # GraphSAGE
            x = F.relu(self.sage1(x, edge_index))
            x = F.relu(self.sage2(x, edge_index))
            x = self.sage3(x, edge_index)

            if batch is not None:
                x = global_mean_pool(x, batch)

            # LSTM için reshape
            if x.dim() == 2:
                x = x.unsqueeze(1)

            lstm_out, _ = self.lstm(x)
            x = lstm_out[:, -1, :]

            x = self.fc(x)
            return F.log_softmax(x, dim=1)


# ==================== AĞ GRAFİ YÖNETİCİSİ ====================

class AgGrafiYoneticisi:
    """
    Ağ trafiği graf yöneticisi

    Canlı saldırı verilerinden graf oluşturur ve GNN ile analiz eder
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def al(cls) -> 'AgGrafiYoneticisi':
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self.dugumler: Dict[str, GrafDugum] = {}
        self.kenarlar: List[GrafKenar] = []
        self.nx_graf: Optional[nx.DiGraph] = None

        # Modeller
        self._tehdit_model: Optional['TehditGCN'] = None
        self._anomali_model: Optional['AnomaliGAT'] = None
        self._apt_model: Optional['APTDetector'] = None

        # Eğitim verileri
        self._egitim_grafi: List[Any] = []
        self._egitim_etiketleri: List[int] = []

        # İstatistikler
        self._toplam_analiz = 0
        self._tespit_edilen = 0
        self._son_analiz: Optional[datetime] = None

        # Modelleri başlat
        self._modelleri_yukle()

    def _modelleri_yukle(self):
        """GNN modellerini başlat"""
        if not TORCH_AKTIF:
            return

        try:
            self._tehdit_model = TehditGCN(girdi_boyut=16, gizli_boyut=64, cikti_boyut=8)
            self._anomali_model = AnomaliGAT(girdi_boyut=16, gizli_boyut=64)
            self._apt_model = APTDetector(girdi_boyut=16, gizli_boyut=128)

            # Eval moduna al
            self._tehdit_model.eval()
            self._anomali_model.eval()
            self._apt_model.eval()

            print("[GNN] Modeller yüklendi")
        except Exception as e:
            print(f"[GNN] Model yükleme hatası: {e}")

    # ==================== DÜĞÜM/KENAR YÖNETİMİ ====================

    def dugum_ekle(self, dugum: GrafDugum) -> bool:
        """Grafa düğüm ekle"""
        if dugum.id in self.dugumler:
            # Mevcut düğümü güncelle
            self.dugumler[dugum.id].son_gorulme = datetime.now()
            return False

        self.dugumler[dugum.id] = dugum

        # NetworkX grafına ekle
        if NX_AKTIF:
            if self.nx_graf is None:
                self.nx_graf = nx.DiGraph()
            self.nx_graf.add_node(dugum.id, **{
                'tip': dugum.tip.value,
                'etiket': dugum.etiket,
                'risk': dugum.risk_skoru
            })

        return True

    def kenar_ekle(self, kenar: GrafKenar) -> bool:
        """Grafa kenar ekle"""
        # Kaynak ve hedef düğümlerin varlığını kontrol et
        if kenar.kaynak_id not in self.dugumler:
            return False
        if kenar.hedef_id not in self.dugumler:
            return False

        self.kenarlar.append(kenar)

        # NetworkX grafına ekle
        if NX_AKTIF and self.nx_graf:
            self.nx_graf.add_edge(
                kenar.kaynak_id,
                kenar.hedef_id,
                tip=kenar.tip.value,
                agirlik=kenar.agirlik
            )

        return True

    def saldiri_ekle(self, saldiri: Dict[str, Any]) -> Dict[str, Any]:
        """
        Canlı saldırı verisinden graf düğümleri oluştur

        Args:
            saldiri: Canlı saldırı verisi (kaynak, hedef, saldiri bilgileri)

        Returns:
            Oluşturulan düğüm ve kenar bilgileri
        """
        sonuc = {'dugumler': [], 'kenarlar': [], 'analiz': None}

        kaynak = saldiri.get('kaynak', {})
        hedef = saldiri.get('hedef', {})
        saldiri_bilgi = saldiri.get('saldiri', {})

        # Kaynak IP düğümü
        kaynak_ip = kaynak.get('ip', 'unknown')
        kaynak_dugum = GrafDugum(
            id=f"ip_{kaynak_ip}",
            tip=DugumTipi.IP_ADRES,
            etiket=kaynak_ip,
            ozellikler={
                'ulke': kaynak.get('ulke', 'XX'),
                'lat': kaynak.get('lat', 0),
                'lng': kaynak.get('lng', 0)
            },
            risk_skoru=self._ciddiyet_skoru(saldiri_bilgi.get('ciddiyet', 'low'))
        )
        if self.dugum_ekle(kaynak_dugum):
            sonuc['dugumler'].append(kaynak_dugum.id)

        # Hedef IP düğümü
        hedef_ip = hedef.get('ip', 'unknown')
        hedef_dugum = GrafDugum(
            id=f"ip_{hedef_ip}",
            tip=DugumTipi.IP_ADRES,
            etiket=hedef_ip,
            ozellikler={
                'sehir': hedef.get('sehir', 'Unknown'),
                'lat': hedef.get('lat', 0),
                'lng': hedef.get('lng', 0)
            },
            risk_skoru=0.0  # Hedef değil, kurban
        )
        if self.dugum_ekle(hedef_dugum):
            sonuc['dugumler'].append(hedef_dugum.id)

        # Ülke düğümü
        ulke = kaynak.get('ulke', 'XX')
        ulke_dugum = GrafDugum(
            id=f"ulke_{ulke}",
            tip=DugumTipi.ULKE,
            etiket=ulke,
            ozellikler={'kod': ulke}
        )
        if self.dugum_ekle(ulke_dugum):
            sonuc['dugumler'].append(ulke_dugum.id)

        # Kenarlar
        kenar_tipi = self._saldiri_tipi_kenar(saldiri_bilgi.get('tip', 'Unknown'))

        # Kaynak -> Hedef
        kenar1 = GrafKenar(
            kaynak_id=f"ip_{kaynak_ip}",
            hedef_id=f"ip_{hedef_ip}",
            tip=kenar_tipi,
            agirlik=self._ciddiyet_skoru(saldiri_bilgi.get('ciddiyet', 'low')),
            ozellikler={'saldiri_tip': saldiri_bilgi.get('tip', 'Unknown')}
        )
        if self.kenar_ekle(kenar1):
            sonuc['kenarlar'].append(f"{kenar1.kaynak_id} -> {kenar1.hedef_id}")

        # Ülke -> Kaynak IP
        kenar2 = GrafKenar(
            kaynak_id=f"ulke_{ulke}",
            hedef_id=f"ip_{kaynak_ip}",
            tip=KenarTipi.BAGLANTI,
            agirlik=0.5
        )
        if self.kenar_ekle(kenar2):
            sonuc['kenarlar'].append(f"{kenar2.kaynak_id} -> {kenar2.hedef_id}")

        # GNN Analizi
        if TORCH_AKTIF and len(self.dugumler) >= 3:
            sonuc['analiz'] = self.analiz_et()

        return sonuc

    def _ciddiyet_skoru(self, ciddiyet: str) -> float:
        """Ciddiyet stringini skora çevir"""
        skorlar = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }
        return skorlar.get(ciddiyet.lower(), 0.3)

    def _saldiri_tipi_kenar(self, saldiri_tipi: str) -> KenarTipi:
        """Saldırı tipini kenar tipine çevir"""
        mapping = {
            'DDoS': KenarTipi.BAGLANTI,
            'Brute Force': KenarTipi.SSH_ERISIM,
            'SQL Injection': KenarTipi.HTTP_ISTEK,
            'XSS': KenarTipi.HTTP_ISTEK,
            'Ransomware': KenarTipi.DOSYA_TRANSFER,
            'APT': KenarTipi.C2_ILETISIM,
            'Phishing': KenarTipi.HTTP_ISTEK,
            'Port Scan': KenarTipi.BAGLANTI,
            'Exploit': KenarTipi.EXPLOIT
        }
        return mapping.get(saldiri_tipi, KenarTipi.BAGLANTI)

    # ==================== GRAF -> PYTORCH GEOMETRIC ====================

    def pyg_data_olustur(self) -> Optional[Any]:
        """
        Mevcut grafı PyTorch Geometric Data objesine dönüştür
        """
        if not TORCH_AKTIF:
            return None

        if len(self.dugumler) < 2 or len(self.kenarlar) < 1:
            return None

        # Düğüm indeksleme
        dugum_idx = {dugum_id: i for i, dugum_id in enumerate(self.dugumler.keys())}

        # Düğüm özellikleri (16 boyutlu)
        x_list = []
        for dugum in self.dugumler.values():
            ozellik = self._dugum_ozellik_vektoru(dugum)
            x_list.append(ozellik)

        x = torch.tensor(x_list, dtype=torch.float)

        # Kenar indeksleri
        edge_list = []
        for kenar in self.kenarlar:
            if kenar.kaynak_id in dugum_idx and kenar.hedef_id in dugum_idx:
                edge_list.append([dugum_idx[kenar.kaynak_id], dugum_idx[kenar.hedef_id]])

        if not edge_list:
            return None

        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()

        return Data(x=x, edge_index=edge_index)

    def _dugum_ozellik_vektoru(self, dugum: GrafDugum) -> List[float]:
        """Düğümü 16 boyutlu vektöre dönüştür"""
        vektor = [0.0] * 16

        # Tip (one-hot, 0-7)
        tip_idx = list(DugumTipi).index(dugum.tip)
        if tip_idx < 8:
            vektor[tip_idx] = 1.0

        # Risk skoru (8)
        vektor[8] = dugum.risk_skoru

        # Koordinatlar (normalize) (9-10)
        lat = dugum.ozellikler.get('lat', 0)
        lng = dugum.ozellikler.get('lng', 0)
        vektor[9] = (lat + 90) / 180  # 0-1 arası
        vektor[10] = (lng + 180) / 360  # 0-1 arası

        # Bağlantı sayısı (11)
        baglanti = sum(1 for k in self.kenarlar if k.kaynak_id == dugum.id or k.hedef_id == dugum.id)
        vektor[11] = min(baglanti / 100, 1.0)

        # Zaman özelliği (12)
        zaman_farki = (datetime.now() - dugum.ilk_gorulme).total_seconds()
        vektor[12] = min(zaman_farki / 86400, 1.0)  # 1 gün normalize

        # Aktivite süresi (13)
        aktivite = (dugum.son_gorulme - dugum.ilk_gorulme).total_seconds()
        vektor[13] = min(aktivite / 3600, 1.0)  # 1 saat normalize

        # Padding (14-15)
        vektor[14] = random.random() * 0.1  # Gürültü
        vektor[15] = random.random() * 0.1

        return vektor

    # ==================== ANALİZ FONKSİYONLARI ====================

    def analiz_et(self) -> Dict[str, Any]:
        """
        Mevcut grafı GNN modelleri ile analiz et

        Returns:
            Analiz sonuçları (tehdit, anomali, APT skorları)
        """
        sonuc = {
            'zaman': datetime.now().isoformat(),
            'dugum_sayisi': len(self.dugumler),
            'kenar_sayisi': len(self.kenarlar),
            'tehdit': None,
            'anomali': None,
            'apt': None,
            'toplam_risk': 0.0
        }

        if not TORCH_AKTIF:
            sonuc['hata'] = "PyTorch Geometric yüklü değil"
            return sonuc

        # PyG Data oluştur
        data = self.pyg_data_olustur()
        if data is None:
            sonuc['hata'] = "Yeterli graf verisi yok"
            return sonuc

        try:
            with torch.no_grad():
                # Batch tensoru (tum dugumler tek graf)
                batch = torch.zeros(data.x.size(0), dtype=torch.long)

                # Tehdit Sınıflandırması
                if self._tehdit_model:
                    tehdit_out = self._tehdit_model(data.x, data.edge_index, batch)
                    # Çıktı boyutuna göre işle
                    if tehdit_out.dim() == 2 and tehdit_out.size(0) == 1:
                        tehdit_sinif = tehdit_out[0].argmax().item()
                        tehdit_prob = torch.exp(tehdit_out[0]).max().item()
                    else:
                        tehdit_sinif = tehdit_out.argmax().item()
                        tehdit_prob = torch.exp(tehdit_out).max().item()

                    # Sınıf indeksini sınırla
                    tehdit_sinif = min(tehdit_sinif, len(TehditSinifi) - 1)

                    sonuc['tehdit'] = {
                        'sinif': TehditSinifi(tehdit_sinif).name,
                        'sinif_id': tehdit_sinif,
                        'guven': round(tehdit_prob * 100, 2)
                    }

                # Anomali Tespiti
                if self._anomali_model:
                    anomali_out = self._anomali_model(data.x, data.edge_index, batch)
                    anomali_skor = anomali_out.mean().item()

                    sonuc['anomali'] = {
                        'skor': round(anomali_skor * 100, 2),
                        'durum': 'ANOMALI' if anomali_skor > 0.7 else 'NORMAL',
                        'seviye': self._anomali_seviye(anomali_skor)
                    }

                # APT Tespiti
                if self._apt_model:
                    apt_out = self._apt_model(data.x, data.edge_index, batch)
                    # Çıktı boyutuna göre işle
                    if apt_out.dim() == 2 and apt_out.size(0) == 1:
                        apt_sinif = apt_out[0].argmax().item()
                        apt_prob = torch.exp(apt_out[0]).max().item()
                    else:
                        apt_sinif = apt_out.argmax().item()
                        apt_prob = torch.exp(apt_out).max().item()

                    sonuc['apt'] = {
                        'tespit': apt_sinif == 1,
                        'guven': round(apt_prob * 100, 2),
                        'risk': 'YUKSEK' if apt_sinif == 1 and apt_prob > 0.7 else 'DUSUK'
                    }

                # Toplam risk hesapla
                risks = []
                if sonuc['tehdit']:
                    risks.append(sonuc['tehdit']['guven'] / 100)
                if sonuc['anomali']:
                    risks.append(sonuc['anomali']['skor'] / 100)
                if sonuc['apt'] and sonuc['apt']['tespit']:
                    risks.append(sonuc['apt']['guven'] / 100)

                sonuc['toplam_risk'] = round(sum(risks) / len(risks) * 100, 2) if risks else 0.0

        except Exception as e:
            sonuc['hata'] = str(e)

        self._toplam_analiz += 1
        if sonuc.get('toplam_risk', 0) > 50:
            self._tespit_edilen += 1
        self._son_analiz = datetime.now()

        return sonuc

    def _anomali_seviye(self, skor: float) -> str:
        """Anomali skorundan seviye belirle"""
        if skor >= 0.9:
            return "KRITIK"
        elif skor >= 0.7:
            return "YUKSEK"
        elif skor >= 0.5:
            return "ORTA"
        elif skor >= 0.3:
            return "DUSUK"
        else:
            return "NORMAL"

    def merkezi_dugumler(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """
        En merkezi düğümleri bul (PageRank)
        """
        if not NX_AKTIF or not self.nx_graf:
            return []

        if len(self.nx_graf.nodes()) == 0:
            return []

        try:
            pagerank = nx.pagerank(self.nx_graf, alpha=0.85)
            sirali = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)[:top_n]

            sonuc = []
            for dugum_id, skor in sirali:
                if dugum_id in self.dugumler:
                    dugum = self.dugumler[dugum_id]
                    sonuc.append({
                        'id': dugum_id,
                        'etiket': dugum.etiket,
                        'tip': dugum.tip.value,
                        'pagerank': round(skor, 4),
                        'risk': dugum.risk_skoru
                    })

            return sonuc
        except:
            return []

    def topluluk_tespit(self) -> List[Dict[str, Any]]:
        """
        Graf topluluklarını tespit et (community detection)
        """
        if not NX_AKTIF or not self.nx_graf:
            return []

        if len(self.nx_graf.nodes()) < 3:
            return []

        try:
            # Yönsüz grafa dönüştür
            G_undirected = self.nx_graf.to_undirected()

            # Label propagation ile topluluk tespiti
            from networkx.algorithms import community
            communities = community.label_propagation_communities(G_undirected)

            sonuc = []
            for i, comm in enumerate(communities):
                topluluk_dugumler = list(comm)

                # Topluluk risk skoru
                risk_skorlari = [
                    self.dugumler[d].risk_skoru
                    for d in topluluk_dugumler
                    if d in self.dugumler
                ]
                ort_risk = sum(risk_skorlari) / len(risk_skorlari) if risk_skorlari else 0

                sonuc.append({
                    'topluluk_id': i,
                    'boyut': len(topluluk_dugumler),
                    'dugumler': topluluk_dugumler[:10],  # İlk 10
                    'ortalama_risk': round(ort_risk, 2)
                })

            return sorted(sonuc, key=lambda x: x['ortalama_risk'], reverse=True)
        except:
            return []

    def saldiri_yolu_bul(self, baslangic_id: str, hedef_id: str) -> Optional[Dict[str, Any]]:
        """
        İki düğüm arasındaki saldırı yolunu bul
        """
        if not NX_AKTIF or not self.nx_graf:
            return None

        if baslangic_id not in self.nx_graf.nodes() or hedef_id not in self.nx_graf.nodes():
            return None

        try:
            # En kısa yol
            yol = nx.shortest_path(self.nx_graf, baslangic_id, hedef_id)

            # Yol detayları
            detaylar = []
            for i in range(len(yol) - 1):
                kaynak = yol[i]
                hedef = yol[i + 1]

                # Kenar bilgisi
                kenar_bilgi = self.nx_graf.edges[kaynak, hedef]

                detaylar.append({
                    'adim': i + 1,
                    'kaynak': kaynak,
                    'hedef': hedef,
                    'tip': kenar_bilgi.get('tip', 'unknown')
                })

            return {
                'yol': yol,
                'uzunluk': len(yol) - 1,
                'detaylar': detaylar
            }
        except nx.NetworkXNoPath:
            return {'hata': 'Yol bulunamadı'}
        except:
            return None

    # ==================== İSTATİSTİKLER ====================

    def istatistikler(self) -> Dict[str, Any]:
        """Graf ve analiz istatistikleri"""
        stats = {
            'graf': {
                'dugum_sayisi': len(self.dugumler),
                'kenar_sayisi': len(self.kenarlar),
                'tip_dagilimi': defaultdict(int),
                'kenar_tip_dagilimi': defaultdict(int)
            },
            'analiz': {
                'toplam_analiz': self._toplam_analiz,
                'tespit_edilen': self._tespit_edilen,
                'tespit_orani': round(self._tespit_edilen / max(self._toplam_analiz, 1) * 100, 2),
                'son_analiz': self._son_analiz.isoformat() if self._son_analiz else None
            },
            'model': {
                'pytorch_aktif': TORCH_AKTIF,
                'networkx_aktif': NX_AKTIF,
                'tehdit_model': self._tehdit_model is not None,
                'anomali_model': self._anomali_model is not None,
                'apt_model': self._apt_model is not None
            }
        }

        # Tip dağılımı
        for dugum in self.dugumler.values():
            stats['graf']['tip_dagilimi'][dugum.tip.value] += 1

        for kenar in self.kenarlar:
            stats['graf']['kenar_tip_dagilimi'][kenar.tip.value] += 1

        # Dict'e çevir
        stats['graf']['tip_dagilimi'] = dict(stats['graf']['tip_dagilimi'])
        stats['graf']['kenar_tip_dagilimi'] = dict(stats['graf']['kenar_tip_dagilimi'])

        return stats

    def temizle(self, max_yas_saat: int = 24):
        """Eski düğümleri temizle"""
        simdi = datetime.now()
        silinecekler = []

        for dugum_id, dugum in self.dugumler.items():
            yas = (simdi - dugum.son_gorulme).total_seconds() / 3600
            if yas > max_yas_saat:
                silinecekler.append(dugum_id)

        for dugum_id in silinecekler:
            del self.dugumler[dugum_id]
            if NX_AKTIF and self.nx_graf and dugum_id in self.nx_graf.nodes():
                self.nx_graf.remove_node(dugum_id)

        # İlgili kenarları temizle
        self.kenarlar = [
            k for k in self.kenarlar
            if k.kaynak_id in self.dugumler and k.hedef_id in self.dugumler
        ]

        return len(silinecekler)

    def json_export(self) -> Dict[str, Any]:
        """Grafı JSON formatında dışa aktar"""
        return {
            'meta': {
                'zaman': datetime.now().isoformat(),
                'versiyon': '1.0'
            },
            'dugumler': [
                {
                    'id': d.id,
                    'tip': d.tip.value,
                    'etiket': d.etiket,
                    'risk': d.risk_skoru,
                    'ozellikler': d.ozellikler
                }
                for d in self.dugumler.values()
            ],
            'kenarlar': [
                {
                    'kaynak': k.kaynak_id,
                    'hedef': k.hedef_id,
                    'tip': k.tip.value,
                    'agirlik': k.agirlik
                }
                for k in self.kenarlar
            ]
        }

    # ==================== GELİŞMİŞ ANALİZ ====================

    def betweenness_centrality(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """
        Betweenness centrality - kritik köprü düğümleri bul
        Saldırı yollarında kritik noktaları tespit eder
        """
        if not NX_AKTIF or not self.nx_graf:
            return []

        if len(self.nx_graf.nodes()) < 3:
            return []

        try:
            betweenness = nx.betweenness_centrality(self.nx_graf)
            sirali = sorted(betweenness.items(), key=lambda x: x[1], reverse=True)[:top_n]

            sonuc = []
            for dugum_id, skor in sirali:
                if dugum_id in self.dugumler:
                    dugum = self.dugumler[dugum_id]
                    sonuc.append({
                        'id': dugum_id,
                        'etiket': dugum.etiket,
                        'tip': dugum.tip.value,
                        'betweenness': round(skor, 4),
                        'risk': dugum.risk_skoru,
                        'kritik': skor > 0.3  # Yüksek betweenness = kritik köprü
                    })

            return sonuc
        except:
            return []

    def link_prediction(self, top_n: int = 10) -> List[Dict[str, Any]]:
        """
        Link prediction - olası yeni saldırı bağlantılarını tahmin et
        Adamic-Adar indeksi kullanır
        """
        if not NX_AKTIF or not self.nx_graf:
            return []

        if len(self.nx_graf.nodes()) < 3:
            return []

        try:
            # Yönsüz grafa çevir
            G_undirected = self.nx_graf.to_undirected()

            # Mevcut olmayan kenarlar için tahmin
            from networkx.algorithms.link_prediction import adamic_adar_index

            # Mevcut kenarları al
            mevcut_kenarlar = set(G_undirected.edges())

            # Tüm olası kenarları kontrol et
            tahminler = []
            dugum_listesi = list(self.dugumler.keys())

            for i, u in enumerate(dugum_listesi):
                for v in dugum_listesi[i+1:]:
                    if (u, v) not in mevcut_kenarlar and (v, u) not in mevcut_kenarlar:
                        try:
                            preds = list(adamic_adar_index(G_undirected, [(u, v)]))
                            if preds:
                                _, _, skor = preds[0]
                                if skor > 0:
                                    tahminler.append({
                                        'kaynak': u,
                                        'hedef': v,
                                        'skor': round(skor, 4),
                                        'kaynak_etiket': self.dugumler[u].etiket if u in self.dugumler else u,
                                        'hedef_etiket': self.dugumler[v].etiket if v in self.dugumler else v
                                    })
                        except:
                            pass

            # En yüksek skorlu tahminleri döndür
            tahminler.sort(key=lambda x: x['skor'], reverse=True)
            return tahminler[:top_n]
        except Exception as e:
            return []

    def graf_metrikleri(self) -> Dict[str, Any]:
        """
        Kapsamlı graf metrikleri
        """
        if not NX_AKTIF or not self.nx_graf:
            return {'hata': 'NetworkX aktif değil'}

        if len(self.nx_graf.nodes()) == 0:
            return {'hata': 'Graf boş'}

        try:
            G = self.nx_graf
            G_undirected = G.to_undirected()

            metriker = {
                'temel': {
                    'dugum_sayisi': G.number_of_nodes(),
                    'kenar_sayisi': G.number_of_edges(),
                    'yogunluk': round(nx.density(G), 4)
                },
                'baglanti': {},
                'merkezi': {}
            }

            # Bağlantı metrikleri
            try:
                if nx.is_weakly_connected(G):
                    metriker['baglanti']['zayif_bagli'] = True
                else:
                    metriker['baglanti']['zayif_bagli'] = False
                    metriker['baglanti']['bilesen_sayisi'] = nx.number_weakly_connected_components(G)
            except:
                pass

            # Ortalama derece
            dereceler = [d for n, d in G.degree()]
            if dereceler:
                metriker['temel']['ortalama_derece'] = round(sum(dereceler) / len(dereceler), 2)
                metriker['temel']['max_derece'] = max(dereceler)

            # Kümeleme katsayısı (yönsüz graf için)
            try:
                metriker['baglanti']['kumeleme_katsayisi'] = round(
                    nx.average_clustering(G_undirected), 4
                )
            except:
                pass

            # En merkezi düğümler (özet)
            try:
                pagerank = nx.pagerank(G, alpha=0.85)
                en_merkezi = max(pagerank, key=pagerank.get)
                metriker['merkezi']['en_merkezi_dugum'] = en_merkezi
                metriker['merkezi']['en_merkezi_skor'] = round(pagerank[en_merkezi], 4)
            except:
                pass

            return metriker
        except Exception as e:
            return {'hata': str(e)}

    # ==================== MODEL YÖNETİMİ ====================

    def model_kaydet(self, dizin: str = None) -> Dict[str, Any]:
        """
        GNN modellerini diske kaydet
        """
        if not TORCH_AKTIF:
            return {'basarili': False, 'hata': 'PyTorch aktif değil'}

        from pathlib import Path

        if dizin is None:
            dizin = Path.home() / '.dalga' / 'gnn_modeller'
        else:
            dizin = Path(dizin)

        dizin.mkdir(parents=True, exist_ok=True)

        kaydedilen = []

        try:
            if self._tehdit_model:
                torch.save(self._tehdit_model.state_dict(), dizin / 'tehdit_gcn.pth')
                kaydedilen.append('tehdit_gcn.pth')

            if self._anomali_model:
                torch.save(self._anomali_model.state_dict(), dizin / 'anomali_gat.pth')
                kaydedilen.append('anomali_gat.pth')

            if self._apt_model:
                torch.save(self._apt_model.state_dict(), dizin / 'apt_detector.pth')
                kaydedilen.append('apt_detector.pth')

            return {
                'basarili': True,
                'dizin': str(dizin),
                'dosyalar': kaydedilen
            }
        except Exception as e:
            return {'basarili': False, 'hata': str(e)}

    def model_yukle(self, dizin: str = None) -> Dict[str, Any]:
        """
        GNN modellerini diskten yükle
        """
        if not TORCH_AKTIF:
            return {'basarili': False, 'hata': 'PyTorch aktif değil'}

        from pathlib import Path

        if dizin is None:
            dizin = Path.home() / '.dalga' / 'gnn_modeller'
        else:
            dizin = Path(dizin)

        if not dizin.exists():
            return {'basarili': False, 'hata': 'Dizin bulunamadı'}

        yuklenen = []

        try:
            tehdit_path = dizin / 'tehdit_gcn.pth'
            if tehdit_path.exists() and self._tehdit_model:
                self._tehdit_model.load_state_dict(torch.load(tehdit_path, weights_only=True))
                self._tehdit_model.eval()
                yuklenen.append('tehdit_gcn.pth')

            anomali_path = dizin / 'anomali_gat.pth'
            if anomali_path.exists() and self._anomali_model:
                self._anomali_model.load_state_dict(torch.load(anomali_path, weights_only=True))
                self._anomali_model.eval()
                yuklenen.append('anomali_gat.pth')

            apt_path = dizin / 'apt_detector.pth'
            if apt_path.exists() and self._apt_model:
                self._apt_model.load_state_dict(torch.load(apt_path, weights_only=True))
                self._apt_model.eval()
                yuklenen.append('apt_detector.pth')

            return {
                'basarili': True,
                'yuklenen': yuklenen
            }
        except Exception as e:
            return {'basarili': False, 'hata': str(e)}

    def gpu_durumu(self) -> Dict[str, Any]:
        """
        GPU durumunu kontrol et
        """
        if not TORCH_AKTIF:
            return {'aktif': False, 'hata': 'PyTorch yüklü değil'}

        durum = {
            'cuda_mevcut': torch.cuda.is_available(),
            'mps_mevcut': hasattr(torch.backends, 'mps') and torch.backends.mps.is_available(),
            'cihaz': 'cpu'
        }

        if durum['cuda_mevcut']:
            durum['cihaz'] = 'cuda'
            durum['gpu_sayisi'] = torch.cuda.device_count()
            durum['gpu_adi'] = torch.cuda.get_device_name(0)
            durum['gpu_bellek'] = {
                'toplam_gb': round(torch.cuda.get_device_properties(0).total_memory / 1e9, 2),
                'ayrilmis_gb': round(torch.cuda.memory_allocated(0) / 1e9, 4),
                'onbellek_gb': round(torch.cuda.memory_reserved(0) / 1e9, 4)
            }
        elif durum['mps_mevcut']:
            durum['cihaz'] = 'mps'  # Apple Silicon

        return durum

    def modelleri_gpuya_tasi(self) -> Dict[str, Any]:
        """
        Modelleri GPU'ya taşı (varsa)
        """
        if not TORCH_AKTIF:
            return {'basarili': False, 'hata': 'PyTorch yüklü değil'}

        device = torch.device('cuda' if torch.cuda.is_available() else
                             'mps' if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available() else
                             'cpu')

        tasinan = []
        try:
            if self._tehdit_model:
                self._tehdit_model = self._tehdit_model.to(device)
                tasinan.append('tehdit_model')

            if self._anomali_model:
                self._anomali_model = self._anomali_model.to(device)
                tasinan.append('anomali_model')

            if self._apt_model:
                self._apt_model = self._apt_model.to(device)
                tasinan.append('apt_model')

            return {
                'basarili': True,
                'cihaz': str(device),
                'tasinan': tasinan
            }
        except Exception as e:
            return {'basarili': False, 'hata': str(e)}

    def d3_export(self) -> Dict[str, Any]:
        """
        Grafı D3.js formatında dışa aktar (frontend görselleştirme için)
        """
        nodes = []
        links = []

        # Düğüm indeksleme
        dugum_idx = {dugum_id: i for i, dugum_id in enumerate(self.dugumler.keys())}

        # Düğümler
        for dugum in self.dugumler.values():
            nodes.append({
                'id': dugum.id,
                'label': dugum.etiket,
                'group': dugum.tip.value,
                'risk': dugum.risk_skoru,
                'size': 5 + dugum.risk_skoru * 10  # Risk bazlı boyut
            })

        # Kenarlar
        for kenar in self.kenarlar:
            if kenar.kaynak_id in dugum_idx and kenar.hedef_id in dugum_idx:
                links.append({
                    'source': kenar.kaynak_id,
                    'target': kenar.hedef_id,
                    'type': kenar.tip.value,
                    'weight': kenar.agirlik
                })

        return {
            'nodes': nodes,
            'links': links
        }

    # ==================== EĞİTİM SİSTEMİ ====================

    def egitim_verisi_olustur(self, ornek_sayisi: int = 1000) -> Tuple[List[Any], List[int]]:
        """
        GNN eğitimi için sentetik saldırı verisi oluştur

        Gerçek tehdit istihbaratı modellerine dayalı veri üretimi
        """
        if not TORCH_AKTIF:
            return [], []

        veri_listesi = []
        etiketler = []

        # Tehdit profilleri (gerçek APT gruplarına dayalı)
        tehdit_profilleri = [
            # NORMAL trafik
            {'tip': TehditSinifi.NORMAL, 'dugum_sayisi': (3, 5), 'kenar_yogunluk': 0.3, 'risk_aralik': (0.0, 0.2)},
            # RECON - Keşif aktivitesi
            {'tip': TehditSinifi.RECON, 'dugum_sayisi': (5, 10), 'kenar_yogunluk': 0.2, 'risk_aralik': (0.2, 0.4)},
            # BRUTE_FORCE
            {'tip': TehditSinifi.BRUTE_FORCE, 'dugum_sayisi': (3, 6), 'kenar_yogunluk': 0.8, 'risk_aralik': (0.5, 0.8)},
            # EXPLOIT
            {'tip': TehditSinifi.EXPLOIT, 'dugum_sayisi': (4, 8), 'kenar_yogunluk': 0.5, 'risk_aralik': (0.7, 1.0)},
            # C2 - Komuta kontrol
            {'tip': TehditSinifi.C2, 'dugum_sayisi': (5, 15), 'kenar_yogunluk': 0.4, 'risk_aralik': (0.6, 0.9)},
            # LATERAL - Yanal hareket
            {'tip': TehditSinifi.LATERAL, 'dugum_sayisi': (6, 12), 'kenar_yogunluk': 0.6, 'risk_aralik': (0.7, 0.95)},
            # EXFIL - Veri sızdırma
            {'tip': TehditSinifi.EXFIL, 'dugum_sayisi': (4, 8), 'kenar_yogunluk': 0.3, 'risk_aralik': (0.8, 1.0)},
            # APT - Gelişmiş kalıcı tehdit
            {'tip': TehditSinifi.APT, 'dugum_sayisi': (10, 25), 'kenar_yogunluk': 0.35, 'risk_aralik': (0.85, 1.0)},
        ]

        for _ in range(ornek_sayisi):
            profil = random.choice(tehdit_profilleri)

            # Düğüm sayısı
            dugum_sayisi = random.randint(*profil['dugum_sayisi'])

            # Düğüm özellikleri oluştur (16 boyut)
            x_list = []
            for i in range(dugum_sayisi):
                ozellik = [0.0] * 16
                # Tip one-hot (rastgele)
                tip_idx = random.randint(0, 7)
                ozellik[tip_idx] = 1.0
                # Risk skoru
                ozellik[8] = random.uniform(*profil['risk_aralik'])
                # Koordinatlar (normalize)
                ozellik[9] = random.random()
                ozellik[10] = random.random()
                # Bağlantı sayısı
                ozellik[11] = random.random() * 0.5
                # Zaman özellikleri
                ozellik[12] = random.random()
                ozellik[13] = random.random()
                # Gürültü
                ozellik[14] = random.random() * 0.1
                ozellik[15] = random.random() * 0.1
                x_list.append(ozellik)

            x = torch.tensor(x_list, dtype=torch.float)

            # Kenarlar oluştur
            edge_list = []
            for i in range(dugum_sayisi):
                for j in range(dugum_sayisi):
                    if i != j and random.random() < profil['kenar_yogunluk']:
                        edge_list.append([i, j])

            # En az 1 kenar olsun
            if not edge_list:
                edge_list = [[0, 1], [1, 0]] if dugum_sayisi > 1 else [[0, 0]]

            edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()

            # Data objesi
            data = Data(x=x, edge_index=edge_index, y=torch.tensor([profil['tip'].value]))
            veri_listesi.append(data)
            etiketler.append(profil['tip'].value)

        return veri_listesi, etiketler

    def model_egit(self, model_tipi: str = 'tehdit', epochs: int = 100,
                   lr: float = 0.01, ornek_sayisi: int = 500) -> Dict[str, Any]:
        """
        GNN modelini eğit

        Args:
            model_tipi: 'tehdit', 'anomali', veya 'apt'
            epochs: Eğitim döngüsü sayısı
            lr: Öğrenme oranı
            ornek_sayisi: Eğitim verisi sayısı
        """
        if not TORCH_AKTIF:
            return {'basarili': False, 'hata': 'PyTorch aktif değil'}

        # Model seç
        if model_tipi == 'tehdit':
            model = self._tehdit_model
            cikti_sinif = 8
        elif model_tipi == 'anomali':
            model = self._anomali_model
            cikti_sinif = 1
        elif model_tipi == 'apt':
            model = self._apt_model
            cikti_sinif = 2
        else:
            return {'basarili': False, 'hata': f'Bilinmeyen model tipi: {model_tipi}'}

        if model is None:
            return {'basarili': False, 'hata': 'Model yüklenmemiş'}

        try:
            # Eğitim verisi oluştur
            veri_listesi, etiketler = self.egitim_verisi_olustur(ornek_sayisi)

            if not veri_listesi:
                return {'basarili': False, 'hata': 'Eğitim verisi oluşturulamadı'}

            # Batch oluştur
            from torch_geometric.loader import DataLoader
            loader = DataLoader(veri_listesi, batch_size=32, shuffle=True)

            # Optimizer
            optimizer = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=5e-4)

            # Eğitim modu
            model.train()

            kayip_gecmisi = []

            for epoch in range(epochs):
                toplam_kayip = 0
                for batch in loader:
                    optimizer.zero_grad()

                    # Forward pass
                    out = model(batch.x, batch.edge_index, batch.batch)

                    # Loss hesapla
                    if model_tipi == 'anomali':
                        # Anomali için MSE loss
                        target = (batch.y > 0).float().unsqueeze(1)
                        loss = F.mse_loss(out, target)
                    else:
                        # Sınıflandırma için NLL loss
                        loss = F.nll_loss(out, batch.y)

                    # Backward pass
                    loss.backward()
                    optimizer.step()

                    toplam_kayip += loss.item()

                ort_kayip = toplam_kayip / len(loader)
                kayip_gecmisi.append(ort_kayip)

                if epoch % 10 == 0:
                    print(f'[GNN] Epoch {epoch}/{epochs}, Loss: {ort_kayip:.4f}')

            # Eval moduna al
            model.eval()

            # Modeli kaydet
            self.model_kaydet()

            return {
                'basarili': True,
                'model': model_tipi,
                'epochs': epochs,
                'son_kayip': kayip_gecmisi[-1] if kayip_gecmisi else 0,
                'kayip_gecmisi': kayip_gecmisi[-10:],  # Son 10 epoch
                'ornek_sayisi': ornek_sayisi
            }

        except Exception as e:
            return {'basarili': False, 'hata': str(e)}

    def toplu_egitim(self, epochs: int = 50) -> Dict[str, Any]:
        """Tüm modelleri sırayla eğit"""
        sonuclar = {}

        for model_tipi in ['tehdit', 'anomali', 'apt']:
            print(f'\n[GNN] {model_tipi.upper()} modeli eğitiliyor...')
            sonuc = self.model_egit(model_tipi, epochs=epochs)
            sonuclar[model_tipi] = sonuc

        return {
            'basarili': all(s.get('basarili', False) for s in sonuclar.values()),
            'sonuclar': sonuclar
        }

    def tehdit_feed_topla(self) -> Dict[str, Any]:
        """
        Gerçek tehdit istihbaratı kaynaklarından veri topla

        Desteklenen kaynaklar:
        - AbuseIPDB (API key gerekli)
        - AlienVault OTX
        - Feodo Tracker
        - URLhaus
        """
        toplanan = {
            'kaynaklar': [],
            'toplam_ip': 0,
            'toplam_domain': 0
        }

        # Feodo Tracker (ücretsiz, API key gerektirmez)
        try:
            import urllib.request
            feodo_url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt"
            req = urllib.request.Request(feodo_url, headers={'User-Agent': 'TSUNAMI-Threat-Intel/1.0'})

            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                ips = [line.strip() for line in content.split('\n')
                       if line.strip() and not line.startswith('#')]

                for ip in ips[:100]:  # İlk 100 IP
                    self.dugum_ekle(GrafDugum(
                        id=f"ip_{ip}",
                        tip=DugumTipi.IP_ADRES,
                        etiket=ip,
                        ozellikler={'kaynak': 'feodo_tracker', 'tehdit_tipi': 'botnet'},
                        risk_skoru=0.9
                    ))

                toplanan['kaynaklar'].append({'ad': 'Feodo Tracker', 'ip_sayisi': len(ips[:100])})
                toplanan['toplam_ip'] += len(ips[:100])
        except Exception as e:
            toplanan['kaynaklar'].append({'ad': 'Feodo Tracker', 'hata': str(e)})

        # URLhaus (ücretsiz)
        try:
            urlhaus_url = "https://urlhaus.abuse.ch/downloads/text_online/"
            req = urllib.request.Request(urlhaus_url, headers={'User-Agent': 'TSUNAMI-Threat-Intel/1.0'})

            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8')
                urls = [line.strip() for line in content.split('\n')
                        if line.strip() and not line.startswith('#')]

                for url in urls[:50]:  # İlk 50 URL
                    try:
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        domain = parsed.netloc
                        if domain:
                            self.dugum_ekle(GrafDugum(
                                id=f"domain_{domain}",
                                tip=DugumTipi.DOMAIN,
                                etiket=domain,
                                ozellikler={'kaynak': 'urlhaus', 'url': url, 'tehdit_tipi': 'malware'},
                                risk_skoru=0.85
                            ))
                    except:
                        pass

                toplanan['kaynaklar'].append({'ad': 'URLhaus', 'url_sayisi': len(urls[:50])})
                toplanan['toplam_domain'] += min(len(urls), 50)
        except Exception as e:
            toplanan['kaynaklar'].append({'ad': 'URLhaus', 'hata': str(e)})

        return toplanan


# ==================== KOLAYLIK FONKSİYONLARI ====================

def gnn_yoneticisi() -> AgGrafiYoneticisi:
    """Global GNN yöneticisini al"""
    return AgGrafiYoneticisi.al()


# Test
if __name__ == "__main__":
    print("=" * 60)
    print("TSUNAMI GNN Modülü Test")
    print("=" * 60)

    yonetici = gnn_yoneticisi()

    # Test saldırıları ekle
    test_saldirilari = [
        {
            'kaynak': {'ip': '185.220.101.1', 'ulke': 'RU', 'lat': 55.75, 'lng': 37.61},
            'hedef': {'ip': '192.168.1.100', 'sehir': 'Ankara', 'lat': 39.92, 'lng': 32.86},
            'saldiri': {'tip': 'Brute Force', 'ciddiyet': 'high'}
        },
        {
            'kaynak': {'ip': '103.224.182.1', 'ulke': 'CN', 'lat': 39.90, 'lng': 116.40},
            'hedef': {'ip': '192.168.1.100', 'sehir': 'Ankara', 'lat': 39.92, 'lng': 32.86},
            'saldiri': {'tip': 'SQL Injection', 'ciddiyet': 'critical'}
        },
        {
            'kaynak': {'ip': '185.220.101.2', 'ulke': 'RU', 'lat': 55.75, 'lng': 37.61},
            'hedef': {'ip': '192.168.1.101', 'sehir': 'Istanbul', 'lat': 41.01, 'lng': 28.97},
            'saldiri': {'tip': 'DDoS', 'ciddiyet': 'high'}
        }
    ]

    print("\n[TEST] Saldırılar ekleniyor...")
    for saldiri in test_saldirilari:
        sonuc = yonetici.saldiri_ekle(saldiri)
        print(f"  Düğümler: {sonuc['dugumler']}")

    print(f"\n[TEST] Graf boyutu: {len(yonetici.dugumler)} düğüm, {len(yonetici.kenarlar)} kenar")

    # Analiz
    print("\n[TEST] GNN Analizi...")
    analiz = yonetici.analiz_et()
    print(f"  Tehdit: {analiz.get('tehdit', 'N/A')}")
    print(f"  Anomali: {analiz.get('anomali', 'N/A')}")
    print(f"  APT: {analiz.get('apt', 'N/A')}")
    print(f"  Toplam Risk: {analiz.get('toplam_risk', 0)}%")

    # Merkezi düğümler
    print("\n[TEST] Merkezi düğümler...")
    merkezi = yonetici.merkezi_dugumler(5)
    for m in merkezi:
        print(f"  {m['etiket']}: PageRank={m['pagerank']}")

    # İstatistikler
    print("\n[TEST] İstatistikler...")
    stats = yonetici.istatistikler()
    print(f"  Model durumu: {stats['model']}")

    print("\n" + "=" * 60)
    print("Test tamamlandı!")
