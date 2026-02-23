"""
TSUNAMI WiFi SIGINT Scanner - MIT License
Copyright (c) 2026 TSUNAMI Project

Gelişmiş WiFi ağ tarama ve analizi modülü.
TSUNAMI v6.0 NEPTUNE_GHOST entegrasyonu için tasarlandı.

Lisans:
- pywifi kütüphanesi (Cross-platform WiFi scanning)
- TSUNAMI: MIT License (telifsiz kullanım)
- Bu modül: MIT License

Özellikler:
- Çekirdek (802.11) WiFi tarama
- SSID, BSSID, sinyal gücü, kanal analizi
- TSUNAMI threat intel ile otomatik korelasyon
- Gizli SSID tespiti
- WPS vulnerability taraması
- Real-time izleme

Kullanım:
    from modules.sigint_wifi_scanner.tsunami_wifi import TsunamiWiFiScanner

    scanner = TsunamiWiFiScanner()
    networks = await scanner.scan_networks(interface='wlan0')
"""

import sys
import os
import json
import logging
import asyncio
import subprocess
import re
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import hashlib

# TSUNAMI path ekle
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

# Logging yapılandırması
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('TSUNAMI_WiFi_SIGINT')

try:
    import pywifi
    from pywifi import const
    PYWIFI_AVAILABLE = True
except ImportError:
    PYWIFI_AVAILABLE = False
    logger.warning("[TSUNAMI-WiFi] pywifi yüklü değil, iwconfig kullanılacak")


@dataclass
class WiFiNetwork:
    """WiFi ağı veri modeli"""
    ssid: str
    bssid: str
    signal_strength: int  # dBm
    channel: int
    frequency: float  # GHz
    encryption: str
    auth_mode: str
    hidden: bool
    threat_score: float = 0.0
    risk_level: str = "unknown"
    first_seen: str = ""
    last_seen: str = ""
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Dictionary formatına çevir"""
        return asdict(self)


class TsunamiWiFiScanner:
    """
    TSUNAMI WiFi SIGINT Scanner

    WiFi ağlarını tarama, analiz et ve TSUNAMI threat intel ile korele et.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        WiFi Scanner başlatıcı

        Args:
            config: Yapılandırma sözlüğü
        """
        self.config = config or {}
        self.interface = self.config.get('interface', 'wlan0')
        self.scan_timeout = self.config.get('scan_timeout', 10)
        self.threat_intel_enabled = self.config.get('threat_intel_enabled', True)
        self.auto_scan = self.config.get('auto_scan', False)
        self.scan_interval = self.config.get('scan_interval', 60)  # saniye

        # Threat intelligence cache
        self.threat_cache = self._load_threat_cache()

        logger.info(f"[TSUNAMI-WiFi] Scanner başlatıldı: interface={self.interface}")
        logger.info(f"[TSUNAMI-WiFi] Threat intel: {'Aktif' if self.threat_intel_enabled else 'Pasif'}")

    async def scan_networks(self, interface: Optional[str] = None) -> List[WiFiNetwork]:
        """
        WiFi ağlarını tara

        Args:
            interface: Ağ arayüzü (opsiyonel, varsayılan self.interface)

        Returns:
            Taranmış ağ listesi
        """
        interface = interface or self.interface

        logger.info(f"[TSUNAMI-WiFi] Tarama başlatılıyor: interface={interface}")

        if PYWIFI_AVAILABLE:
            networks = await self._scan_with_pywifi(interface)
        else:
            networks = await self._scan_with_iwconfig(interface)

        # Threat intelligence ile zenginleştir
        enriched_networks = await self._enrich_with_threat_intel(networks)

        logger.info(f"[TSUNAMI-WiFi] Tarama tamamlandı: {len(enriched_networks)} ağ")

        return enriched_networks

    async def _scan_with_pywifi(self, interface: str) -> List[WiFiNetwork]:
        """
        pywifi ile tarama

        Args:
            interface: Ağ arayüzü

        Returns:
            Taranmış ağ listesi
        """
        networks = []

        try:
            wifi = pywifi.PyWiFi()

            # Arayüzü bul
            iface = None
            for i in wifi.interfaces():
                if i.name() == interface:
                    iface = i
                    break

            if iface is None:
                # İlk arayüzü kullan
                interfaces = wifi.interfaces()
                if interfaces:
                    iface = interfaces[0]
                    logger.warning(f"[TSUNAMI-WiFi] Interface bulunamadı, ilk kullanılıyor: {iface.name()}")
                else:
                    logger.error("[TSUNAMI-WiFi] Hiçbir interface bulunamadı")
                    return networks

            # Taramayı başlat
            iface.scan()

            # Tarama tamamlanmasını bekle
            await asyncio.sleep(self.scan_timeout)

            # Sonuçları al
            scan_results = iface.scan_results()

            # Sonuçları parse et
            for result in scan_results:
                try:
                    network = WiFiNetwork(
                        ssid=result.ssid or "",
                        bssid=result.bssid,
                        signal_strength=result.signal,
                        channel=result.channel,
                        frequency=self._channel_to_frequency(result.channel),
                        encryption=self._get_encryption_type(result),
                        auth_mode=self._get_auth_mode(result),
                        hidden=not bool(result.ssid),
                        first_seen=datetime.now().isoformat(),
                        last_seen=datetime.now().isoformat()
                    )

                    # Metadata ekle
                    network.metadata = {
                        'quality': self._calculate_signal_quality(result.signal),
                        'noise': self._estimate_noise(result.signal)
                    }

                    networks.append(network)

                except Exception as e:
                    logger.warning(f"[TSUNAMI-WiFi] Ağ parse hatası: {str(e)}")
                    continue

        except Exception as e:
            logger.error(f"[TSUNAMI-WiFi] pywifi tarama hatası: {str(e)}")

        return networks

    async def _scan_with_iwconfig(self, interface: str) -> List[WiFiNetwork]:
        """
        iwconfig/iw ile tarama (fallback)

        Args:
            interface: Ağ arayüzü

        Returns:
            Taranmış ağ listesi
        """
        networks = []

        try:
            # iw list ile WiFi'yi tara
            cmd = ['sudo', 'iwlist', interface, 'scan']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                logger.error(f"[TSUNAMI-WiFi] iwlist hatası: {result.stderr}")
                return networks

            # Çıktıyı parse et
            networks = self._parse_iwlist_output(result.stdout)

        except subprocess.TimeoutExpired:
            logger.error(f"[TSUNAMI-WiFi] Tarama zaman aşımı: {interface}")
        except Exception as e:
            logger.error(f"[TSUNAMI-WiFi] iw tarama hatası: {str(e)}")

        return networks

    def _parse_iwlist_output(self, output: str) -> List[WiFiNetwork]:
        """
        iwlist çıktısını parse et

        Args:
            output: iwlist scan çıktısı

        Returns:
            Parse edilmiş ağ listesi
        """
        networks = []
        current_cell = None

        for line in output.split('\n'):
            line = line.strip()

            # Yeni hücre başlangıcı
            if line.startswith('Cell'):
                if current_cell:
                    networks.append(current_cell)

                # BSSID'yi çıkar
                bssid_match = re.search(r'Address: ([0-9A-F:]{17})', line)
                bssid = bssid_match.group(1) if bssid_match else ""

                current_cell = {
                    'bssid': bssid,
                    'ssid': '',
                    'signal': 0,
                    'channel': 0,
                    'encryption': '',
                    'raw_lines': []
                }

            elif current_cell is not None:
                current_cell['raw_lines'].append(line)

                # SSID
                if 'ESSID:' in line:
                    ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                    if ssid_match:
                        current_cell['ssid'] = ssid_match.group(1)

                # Signal (Quality)
                elif 'Quality=' in line:
                    quality_match = re.search(r'Quality=(\d+)', line)
                    if quality_match:
                        quality = int(quality_match.group(1))
                        # Quality'yi dBm'e çevirme (yaklaşık)
                        current_cell['signal'] = int((quality / 100) * -50 - 20)

                # Encryption
                elif 'Encryption key:' in line:
                    if 'on' in line.lower():
                        enc_match = re.search(r'Encryption key:(.+?)\s', line)
                        if enc_match:
                            current_cell['encryption'] = enc_match.group(1).strip()

        # Son hücreyi ekle
        if current_cell:
            networks.append(current_cell)

        # WiFiNetwork objelerine çevir
        wifi_networks = []
        for net in networks:
            try:
                network = WiFiNetwork(
                    ssid=net.get('ssid', ''),
                    bssid=net.get('bssid', ''),
                    signal_strength=net.get('signal', 0),
                    channel=0,  # Çıkartılacak
                    frequency=2.4,
                    encryption=net.get('encryption', 'Unknown'),
                    auth_mode='Unknown',
                    hidden=not bool(net.get('ssid', '')),
                    first_seen=datetime.now().isoformat(),
                    last_seen=datetime.now().isoformat()
                )

                # Kanal bilgisini çıkar (varsa)
                channel = self._extract_channel_from_raw(net.get('raw_lines', []))
                if channel:
                    network.channel = channel
                    network.frequency = self._channel_to_frequency(channel)

                wifi_networks.append(network)

            except Exception as e:
                logger.warning(f"[TSUNAMI-WiFi] Hücre dönüştürme hatası: {str(e)}")
                continue

        return wifi_networks

    def _extract_channel_from_raw(self, raw_lines: List[str]) -> int:
        """Raw verilerden kanal bilgisini çıkar"""
        for line in raw_lines:
            channel_match = re.search(r'Channel:(\d+)', line)
            if channel_match:
                return int(channel_match.group(1))
        return 0

    async def _enrich_with_threat_intel(self, networks: List[WiFiNetwork]) -> List[WiFiNetwork]:
        """
        Threat intelligence ile zenginleştir

        Args:
            networks: Taranmış ağ listesi

        Returns:
            Zenginleştirilmiş ağ listesi
        """
        if not self.threat_intel_enabled:
            return networks

        for network in networks:
            try:
                # BSSID threat kontrolü
                bssid_threat = self._check_bssid_threat(network.bssid)

                # SSID threat kontrolü
                ssid_threat = self._check_ssid_threat(network.ssid)

                # Encryption threat kontrolü
                crypto_threat = self._check_encryption_threat(network.encryption)

                # Skorları hesapla
                threat_score = (
                    bssid_threat['score'] * 0.4 +
                    ssid_threat['score'] * 0.3 +
                    crypto_threat['score'] * 0.3
                )

                network.threat_score = min(threat_score, 1.0)
                network.risk_level = self._determine_risk_level(network.threat_score)

                # Metadata ekle
                network.metadata.update({
                    'bssid_threat': bssid_threat,
                    'ssid_threat': ssid_threat,
                    'crypto_threat': crypto_threat
                })

            except Exception as e:
                logger.warning(f"[TSUNAMI-WiFi] Threat intel hatası: {str(e)}")
                network.threat_score = 0.0
                network.risk_level = "unknown"

        return networks

    def _check_bssid_threat(self, bssid: str) -> Dict[str, Any]:
        """BSSID threat kontrolü"""
        # Threat cache'te ara
        bssid_hash = hashlib.md5(bssid.encode()).hexdigest()

        if bssid_hash in self.threat_cache:
            return self.threat_cache[bssid_hash]

        # Yerel threat veritabanında ara (TSUNAMI)
        threat_data = self._query_tsunami_threat_db('bssid', bssid)

        if threat_data:
            result = {
                'found': True,
                'score': threat_data.get('threat_score', 0.5),
                'category': threat_data.get('category', 'unknown'),
                'description': threat_data.get('description', '')
            }
        else:
            result = {
                'found': False,
                'score': 0.0,
                'category': 'none',
                'description': ''
            }

        # Cache'e ekle
        self.threat_cache[bssid_hash] = result

        return result

    def _check_ssid_threat(self, ssid: str) -> Dict[str, Any]:
        """SSID threat kontrolü"""
        # Şüpheli SSID pattern'leri
        suspicious_patterns = [
            r'^free.*wifi',
            r'^public.*wifi',
            r'.*hack.*',
            r'.*malware.*',
            r'^null$',
            r'^$$$'
        ]

        for pattern in suspicious_patterns:
            if re.match(pattern, ssid, re.IGNORECASE):
                return {
                    'found': True,
                    'score': 0.3,
                    'category': 'suspicious_pattern',
                    'description': f'Shüpheli SSID pattern: {pattern}'
                }

        # WPS kontrolü
        if 'WPS' in ssid.upper():
            return {
                'found': True,
                'score': 0.4,
                'category': 'wps_detected',
                'description': 'WPS açık SSID'
            }

        return {
            'found': False,
            'score': 0.0,
            'category': 'none',
            'description': ''
        }

    def _check_encryption_threat(self, encryption: str) -> Dict[str, Any]:
        """Encryption threat kontrolü"""
        if not encryption or encryption.lower() in ['open', 'none', '']:
            return {
                'found': True,
                'score': 0.7,
                'category': 'open_network',
                'description': 'Şifrelenmemiş ağ'
            }

        if 'wep' in encryption.lower():
            return {
                'found': True,
                'score': 0.8,
                'category': 'weak_encryption',
                'description': 'WEP zayıf şifreleme'
            }

        return {
            'found': False,
            'score': 0.0,
            'category': 'none',
            'description': ''
        }

    def _determine_risk_level(self, threat_score: float) -> str:
        """Risk seviyesini belirle"""
        if threat_score >= 0.7:
            return 'critical'
        elif threat_score >= 0.5:
            return 'high'
        elif threat_score >= 0.3:
            return 'medium'
        elif threat_score > 0:
            return 'low'
        else:
            return 'safe'

    def _channel_to_frequency(self, channel: int) -> float:
        """Kanal frekansına çevir"""
        if 1 <= channel <= 14:
            return 2.412 + (channel - 1) * 0.005
        elif channel == 14:
            return 2.484
        elif 36 <= channel <= 165:
            return 5.180 + (channel - 36) * 0.020
        else:
            return 0.0

    def _get_encryption_type(self, result) -> str:
        """Şifreleme tipini al"""
        if hasattr(result, 'encryption'):
            enc = result.encryption
            if enc and enc != '':
                return str(enc)
        return "Unknown"

    def _get_auth_mode(self, result) -> str:
        """Kimlik doğrulama modunu al"""
        # Şifreleme tipinden auth modunu çıkar
        enc = self._get_encryption_type(result)
        if 'WPA2' in enc:
            return 'WPA2-Personal'
        elif 'WPA' in enc:
            return 'WPA-Personal'
        elif 'WEP' in enc:
            return 'WEP'
        else:
            return 'Open'

    def _calculate_signal_quality(self, signal_dbm: int) -> int:
        """Sinyal kalitesini hesapla (0-100)"""
        # dBm'i yüzdeye çevir (yaklaşık)
        # -30 dBm = %100, -90 dBm = %0
        quality = max(0, min(100, int((signal_dbm + 30) * 1.67)))
        return quality

    def _estimate_noise(self, signal_dbm: int) -> int:
        """Gürültü seviyesini tahmin et"""
        # Basit tahmin: sinyal zayıfça gürültü fazla
        return max(0, min(100, 100 - self._calculate_signal_quality(signal_dbm)))

    def _query_tsunami_threat_db(self, field: str, value: str) -> Optional[Dict[str, Any]]:
        """TSUNAMI threat veritabanında sorgu"""
        try:
            # TSUNAMI veritabanına bağlan
            import sqlite3

            conn = sqlite3.connect('tsunami.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Threat IOC tablosunda ara
            cursor.execute('''
                SELECT ioc_value, threat_score, category, description
                FROM threat_ioc
                WHERE ioc_type = ? AND ioc_value = ?
            ''', (field, value))

            result = cursor.fetchone()
            conn.close()

            if result:
                return dict(result)
            return None

        except Exception as e:
            logger.error(f"[TSUNAMI-WiFi] Threat DB sorgu hatası: {str(e)}")
            return None

    def _load_threat_cache(self) -> Dict[str, Any]:
        """Threat cache'i yükle"""
        return {}

    def start_continuous_scan(self):
        """Sürekli tarama başlat (background)"""
        if self.auto_scan:
            logger.info(f"[TSUNAMI-WiFi] Sürekli tarama başlatılıyor: {self.scan_interval}s aralıklarla")

            async def continuous_scan_loop():
                while True:
                    try:
                        networks = await self.scan_networks()
                        await self._store_scan_results(networks)
                        await asyncio.sleep(self.scan_interval)
                    except asyncio.CancelledError:
                        logger.info("[TSUNAMI-WiFi] Sürekli tarama durduruldu")
                        break
                    except Exception as e:
                        logger.error(f"[TSUNAMI-WiFi] Tarama döngüs hatası: {str(e)}")
                        await asyncio.sleep(self.scan_interval)

            # Background task olarak çalıştır
            asyncio.create_task(continuous_scan_loop())

    async def _store_scan_results(self, networks: List[WiFiNetwork]):
        """Tarama sonuçlarını TSUNAMI veritabanına kaydet"""
        try:
            import sqlite3
            from datetime import datetime

            conn = sqlite3.connect('tsunami.db')
            cursor = conn.cursor()

            for network in networks:
                # SIGINT WiFi tablosuna kaydet
                cursor.execute('''
                    INSERT OR REPLACE INTO sigint_wifi
                    (bssid, ssid, signal_strength, channel, frequency, encryption,
                     threat_score, risk_level, last_seen, metadata)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    network.bssid,
                    network.ssid,
                    network.signal_strength,
                    network.channel,
                    network.frequency,
                    network.encryption,
                    network.threat_score,
                    network.risk_level,
                    network.last_seen,
                    json.dumps(network.metadata)
                ))

            conn.commit()
            conn.close()

            logger.debug(f"[TSUNAMI-WiFi] {len(networks)} ağ veritabanına kaydedildi")

        except Exception as e:
            logger.error(f"[TSUNAMI-WiFi] Veritabanı kayıt hatası: {str(e)}")

    def get_scan_summary(self) -> Dict[str, Any]:
        """Tarama özeti getir"""
        try:
            import sqlite3

            conn = sqlite3.connect('tsunami.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Son tarama sonuçları
            cursor.execute('''
                SELECT
                    COUNT(*) as total_networks,
                    COUNT(CASE WHEN risk_level = 'critical' THEN 1 END) as critical,
                    COUNT(CASE WHEN risk_level = 'high' THEN 1 END) as high,
                    COUNT(CASE WHEN risk_level = 'medium' THEN 1 END) as medium,
                    AVG(signal_strength) as avg_signal
                FROM sigint_wifi
                WHERE last_seen > datetime('now', '-1 hour')
            ''')

            result = cursor.fetchone()
            conn.close()

            return dict(result) if result else {}

        except Exception as e:
            logger.error(f"[TSUNAMI-WiFi] Özet hesaplama hatası: {str(e)}")
            return {}


# CLI wrapper fonksiyonları
def scan_wifi_command(interface: str = 'wlan0') -> str:
    """
    CLI üzerinden WiFi taraması

    Args:
        interface: Ağ arayüzü

    Returns:
        JSON formatında sonuçlar
    """
    async def scan():
        scanner = TsunamiWiFiScanner({'interface': interface})
        networks = await scanner.scan_networks()

        return json.dumps({
            'interface': interface,
            'scan_time': datetime.now().isoformat(),
            'networks': [net.to_dict() for net in networks],
            'summary': {
                'total': len(networks),
                'critical': len([n for n in networks if n.risk_level == 'critical']),
                'high': len([n for n in networks if n.risk_level == 'high']),
                'medium': len([n for n in networks if n.risk_level == 'medium'])
            }
        }, indent=2, ensure_ascii=False)

    # Async çalıştır
    return asyncio.run(scan())


# Modül testi
if __name__ == '__main__':
    print("=" * 60)
    print("TSUNAMI WiFi SIGINT Scanner Test")
    print("=" * 60)

    # Mevcut interface'leri listele
    print("\n[TEST] Mevcut WiFi interface'leri:")

    try:
        import pywifi
        wifi = pywifi.PyWiFi()
        interfaces = wifi.interfaces()

        for iface in interfaces:
            print(f"  - {iface.name()} ({iface.description()})")

        if not interfaces:
            print("  (Interface bulunamadı)")

    except ImportError:
        print("  [!] pywifi yüklü değil")

    # Demo tarama
    print("\n[TEST] Demo tarama (gerçek tarama için root yetkisi gerekli):")

    demo_networks = [
        {
            'ssid': 'TestWiFi',
            'bssid': '00:11:22:33:44:55',
            'signal_strength': -45,
            'channel': 6,
            'frequency': 2.437,
            'encryption': 'WPA2-Personal',
            'auth_mode': 'WPA2-Personal',
            'hidden': False,
            'threat_score': 0.2,
            'risk_level': 'low',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'metadata': {'quality': 60, 'noise': 40}
        }
    ]

    print(json.dumps(demo_networks, indent=2, ensure_ascii=False))

    print("\n[TEST] Modül hazır!")
    print(f"[TEST] Modül yolu: {__file__}")
    print("[TEST] Kullanım: from modules.sigint_wifi_scanner.tsunami_wifi import TsunamiWiFiScanner")
    print("\n[TEST] API endpoint: /api/sigint/wifi/scan")
