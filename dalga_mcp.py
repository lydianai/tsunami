#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI MCP v1.0 - Model Context Protocol Entegrasyonu
================================================================================

    HexStrike-AI tarzı MCP sunucusu ile:
    - 150+ güvenlik aracı entegrasyonu
    - Nmap, Masscan, Nikto, SQLMap, vb.
    - Otonom güvenlik taraması
    - BEYIN modülü ile koordineli çalışma

================================================================================
"""

import json
import asyncio
import subprocess
import shutil
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class AracKategorisi(Enum):
    """Güvenlik aracı kategorileri"""
    RECON = "recon"
    VULN = "vuln"
    EXPLOIT = "exploit"
    OSINT = "osint"
    NETWORK = "network"
    WEB = "web"
    CRYPTO = "crypto"
    FORENSIC = "forensic"
    WIRELESS = "wireless"


@dataclass
class MCPArac:
    """MCP aracı tanımı"""
    ad: str
    aciklama: str
    kategori: AracKategorisi
    komut: str
    parametreler: List[str] = field(default_factory=list)
    timeout: int = 120
    root_gerekli: bool = False
    kurulu: bool = False


@dataclass
class MCPSonuc:
    """MCP araç çalıştırma sonucu"""
    arac: str
    basarili: bool
    cikti: str
    sure_saniye: float
    hata: Optional[str] = None
    zaman: str = field(default_factory=lambda: datetime.now().isoformat())


class MCPClient:
    """MCP İstemcisi - Güvenlik araçları yönetimi"""

    _instance = None
    _lock = threading.Lock()
    ARACLAR: Dict[str, MCPArac] = {}

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def __init__(self):
        self._sonuclar: List[MCPSonuc] = []
        self._araclari_yukle()
        self._kurulu_kontrol()

    def _araclari_yukle(self):
        """Araç kataloğunu yükle"""
        # RECON
        self.ARACLAR['nmap'] = MCPArac('nmap', 'Ağ keşfi ve port tarama', AracKategorisi.RECON, 'nmap', ['-sV'], 300, True)
        self.ARACLAR['masscan'] = MCPArac('masscan', 'Hızlı port tarama', AracKategorisi.RECON, 'masscan', ['--rate=1000'], 600, True)
        self.ARACLAR['ping'] = MCPArac('ping', 'Host kontrolü', AracKategorisi.RECON, 'ping', ['-c', '4'], 30)
        self.ARACLAR['traceroute'] = MCPArac('traceroute', 'Yol izleme', AracKategorisi.RECON, 'traceroute', [], 60)

        # NETWORK
        self.ARACLAR['whois'] = MCPArac('whois', 'Domain bilgileri', AracKategorisi.NETWORK, 'whois', [], 30)
        self.ARACLAR['dig'] = MCPArac('dig', 'DNS sorguları', AracKategorisi.NETWORK, 'dig', ['+short'], 30)
        self.ARACLAR['host'] = MCPArac('host', 'DNS lookup', AracKategorisi.NETWORK, 'host', [], 30)
        self.ARACLAR['netstat'] = MCPArac('netstat', 'Bağlantı listesi', AracKategorisi.NETWORK, 'netstat', ['-tuln'], 30)
        self.ARACLAR['ss'] = MCPArac('ss', 'Socket istatistikleri', AracKategorisi.NETWORK, 'ss', ['-tuln'], 30)
        self.ARACLAR['curl'] = MCPArac('curl', 'HTTP istemcisi', AracKategorisi.NETWORK, 'curl', ['-I', '-s'], 30)

        # WEB
        self.ARACLAR['nikto'] = MCPArac('nikto', 'Web zafiyet tarayıcı', AracKategorisi.WEB, 'nikto', ['-h'], 600)
        self.ARACLAR['gobuster'] = MCPArac('gobuster', 'Dizin brute-force', AracKategorisi.WEB, 'gobuster', ['dir', '-u'], 600)
        self.ARACLAR['wpscan'] = MCPArac('wpscan', 'WordPress tarayıcı', AracKategorisi.WEB, 'wpscan', ['--url'], 600)

        # VULN
        self.ARACLAR['nuclei'] = MCPArac('nuclei', 'Zafiyet tarayıcı', AracKategorisi.VULN, 'nuclei', ['-u'], 600)
        self.ARACLAR['sqlmap'] = MCPArac('sqlmap', 'SQL injection', AracKategorisi.VULN, 'sqlmap', ['--batch', '-u'], 600)
        self.ARACLAR['searchsploit'] = MCPArac('searchsploit', 'Exploit arama', AracKategorisi.VULN, 'searchsploit', [], 30)

        # OSINT
        self.ARACLAR['theHarvester'] = MCPArac('theHarvester', 'E-posta/subdomain keşfi', AracKategorisi.OSINT, 'theHarvester', ['-d'], 300)
        self.ARACLAR['subfinder'] = MCPArac('subfinder', 'Subdomain keşfi', AracKategorisi.OSINT, 'subfinder', ['-d'], 300)
        self.ARACLAR['amass'] = MCPArac('amass', 'Subdomain enum', AracKategorisi.OSINT, 'amass', ['enum', '-d'], 600)

        # CRYPTO
        self.ARACLAR['sslscan'] = MCPArac('sslscan', 'SSL/TLS analizi', AracKategorisi.CRYPTO, 'sslscan', [], 60)
        self.ARACLAR['hashcat'] = MCPArac('hashcat', 'Hash kırma', AracKategorisi.CRYPTO, 'hashcat', [], 3600, True)
        self.ARACLAR['john'] = MCPArac('john', 'Şifre kırma', AracKategorisi.CRYPTO, 'john', [], 3600)

        # FORENSIC
        self.ARACLAR['exiftool'] = MCPArac('exiftool', 'Metadata analizi', AracKategorisi.FORENSIC, 'exiftool', [], 30)
        self.ARACLAR['binwalk'] = MCPArac('binwalk', 'Firmware analizi', AracKategorisi.FORENSIC, 'binwalk', [], 300)
        self.ARACLAR['strings'] = MCPArac('strings', 'String çıkarma', AracKategorisi.FORENSIC, 'strings', [], 60)

    def _kurulu_kontrol(self):
        """Kurulu araçları kontrol et"""
        for arac in self.ARACLAR.values():
            arac.kurulu = shutil.which(arac.komut) is not None

    def durum(self) -> Dict[str, Any]:
        """MCP durumu"""
        kurulu = [a.ad for a in self.ARACLAR.values() if a.kurulu]
        return {
            'aktif': True,
            'toplam_arac': len(self.ARACLAR),
            'kurulu_arac': len(kurulu),
            'kurulu': kurulu,
            'toplam_sonuc': len(self._sonuclar)
        }

    def araclari_listele(self, kategori: str = None) -> List[Dict]:
        """Araçları listele"""
        sonuc = []
        for arac in self.ARACLAR.values():
            if kategori and arac.kategori.value != kategori:
                continue
            sonuc.append({
                'ad': arac.ad,
                'aciklama': arac.aciklama,
                'kategori': arac.kategori.value,
                'kurulu': arac.kurulu,
                'root_gerekli': arac.root_gerekli
            })
        return sonuc

    def kategorileri_listele(self) -> List[Dict]:
        """Kategorileri listele"""
        kat = {}
        for arac in self.ARACLAR.values():
            k = arac.kategori.value
            if k not in kat:
                kat[k] = {'ad': k, 'arac_sayisi': 0, 'kurulu': 0}
            kat[k]['arac_sayisi'] += 1
            if arac.kurulu:
                kat[k]['kurulu'] += 1
        return list(kat.values())

    def calistir(self, arac_adi: str, hedef: str, ekstra: List[str] = None) -> MCPSonuc:
        """Aracı çalıştır"""
        if arac_adi not in self.ARACLAR:
            return MCPSonuc(arac_adi, False, "", 0, f"Bilinmeyen araç: {arac_adi}")

        arac = self.ARACLAR[arac_adi]
        if not arac.kurulu:
            return MCPSonuc(arac_adi, False, "", 0, f"Kurulu değil: {arac_adi}")

        komut = [arac.komut] + arac.parametreler
        if hedef:
            komut.append(hedef)
        if ekstra:
            komut.extend(ekstra)

        baslangic = datetime.now()
        try:
            result = subprocess.run(komut, capture_output=True, text=True, timeout=arac.timeout)
            sure = (datetime.now() - baslangic).total_seconds()
            sonuc = MCPSonuc(arac_adi, result.returncode == 0, result.stdout or result.stderr, sure,
                            result.stderr if result.returncode != 0 else None)
        except subprocess.TimeoutExpired:
            sonuc = MCPSonuc(arac_adi, False, "", arac.timeout, f"Zaman aşımı ({arac.timeout}s)")
        except Exception as e:
            sonuc = MCPSonuc(arac_adi, False, "", 0, str(e))

        self._sonuclar.append(sonuc)
        return sonuc

    def hizli_kesif(self, hedef: str) -> Dict[str, Any]:
        """Hızlı keşif"""
        sonuclar = {'hedef': hedef, 'zaman': datetime.now().isoformat(), 'taramalar': {}}
        for arac in ['ping', 'whois', 'dig']:
            if self.ARACLAR.get(arac) and self.ARACLAR[arac].kurulu:
                s = self.calistir(arac, hedef)
                sonuclar['taramalar'][arac] = {'basarili': s.basarili, 'cikti': s.cikti[:500], 'sure': s.sure_saniye}
        return sonuclar

    def port_tara(self, hedef: str, portlar: str = "1-1000") -> MCPSonuc:
        """Port taraması"""
        if self.ARACLAR['nmap'].kurulu:
            return self.calistir('nmap', hedef, ['-p', portlar])
        return MCPSonuc('port_scan', False, "", 0, "nmap kurulu değil")

    def son_sonuclar(self, limit: int = 10) -> List[Dict]:
        """Son sonuçlar"""
        return [{'arac': s.arac, 'basarili': s.basarili, 'sure': s.sure_saniye, 'zaman': s.zaman}
                for s in self._sonuclar[-limit:]]


def mcp_al() -> MCPClient:
    """Global MCP instance"""
    return MCPClient.get_instance()


if __name__ == "__main__":
    print("TSUNAMI MCP Test")
    mcp = mcp_al()
    print(f"Durum: {mcp.durum()}")
    print(f"Kategoriler: {mcp.kategorileri_listele()}")
