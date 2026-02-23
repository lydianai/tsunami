# OPEN SOURCE PROJE ENTEGRASYON KILAVUZU

**Tarih**: 20 Şubat 2026
**Amaç**: TSUNAMI v6.0 projesine telifsiz open source projeler entegrasyonu

---

## ✅ UYGUN PROJELER (MIT/Apache/BSD Lisans)

### 1. OSINT PLATFORMLARI

#### SpiderFoot HX
```bash
GitHub: https://github.com/smicallef/spiderfoot
Lisans: MIT License ✅
Kategori: OSINT Otomasyonu
Açıklama: 200+ veri kaynağı entegrasyonu
TSUNAMI Kullanımı: modules/osint_spiderfoot/
```

**Kurulum:**
```bash
cd ~/Desktop/TSUNAMI/modules
git clone https://github.com/smicallef/spiderfoot.git osint_spiderfoot
cd osint_spiderfoot
pip install -r requirements.txt
```

**Entegrasyon Kod Örneği:**
```python
# modules/osint_spiderfoot/tsunami_integration.py
from spiderfoot import SpiderFoot

class TsunamiSpiderFootPlugin:
    """TSUNAMI-SpiderFoot Entegrasyon Plugin"""
    
    def __init__(self, config):
        self.sf = SpiderFoot(token=config['api_token'])
    
    def scan_domain(self, domain: str) -> dict:
        """Domain taraması ve sonuçları TSUNAMI formatına çevirme"""
        results = self.sf.scan(domain)
        return {
            'domain': domain,
            'emails': results.get('emails', []),
            'subdomains': results.get('subdomains', []),
            'ips': results.get('ips', []),
            'metadata': {
                'scan_time': results.get('scan_time'),
                'source': 'spiderfoot'
            }
        }
```

#### theHarvester
```bash
GitHub: https://github.com/laramies/theHarvester
Lisans: MIT License ✅
Kategori: E-posta/Subdomain Toplama
Açıklama: Google, Bing, Shodan gibi kaynaklardan veri toplama
TSUNAMI Kullanımı: modules/osint_harvester/
```

**Kurulum:**
```bash
cd ~/Desktop/TSUNAMI/modules
git clone https://github.com/laramies/theHarvester.git osint_harvester
cd osint_harvester
pip3 install -r requirements.txt
```

**CLI Wrapper:**
```python
# modules/osint_harvester/wrapper.py
import subprocess

class HarvesterWrapper:
    def __init__(self):
        self.harvester_path = '/home/lydian/Desktop/TSUNAMI/modules/osint_harvester/theHarvester.py'
    
    def harvest_email(self, domain: str) -> list:
        """E-posta adreslerini toplama"""
        cmd = ['python3', self.harvester_path, '-d', domain, '-b', 'google']
        result = subprocess.run(cmd, capture_output=True, text=True)
        return self._parse_emails(result.stdout)
```

#### Mitaka
```bash
GitHub: https://github.com/ninoseki/mitaka
Lisans: MIT License ✅
Kategori: Browser Extension (IOC Analizi)
Açıklama: Chrome/Firefox uzantısı
TSUNAMI Kullanımı: API olarak kullanım
```

### 2. SIGINT/WIRELESS PLATFORMLARI

#### Airometa (WiFi Tarama)
```bash
GitHub: https://github.com/DAWACS/Airometa
Lisans: MIT License ✅
Kategori: Kablosuz Ağ Tarama
Açıklama: Python tabanlı WiFi tarama ve analiz
TSUNAMI Kullanımı: modules/sigint_wifi_airometa/
```

**Kurulum:**
```bash
cd ~/Desktop/TSUNAMI/modules
git clone https://github.com/DAWACS/Airometa.git sigint_wifi_airometa
cd sigint_wifi_airometa
pip3 install -r requirements.txt
```

**Entegrasyon:**
```python
# modules/sigint_wifi_airometa/scanner.py
from airometa import Airometa

class EnhancedWiFiScanner:
    def __init__(self):
        self.scanner = Airometa()
    
    async def scan_networks(self, interface='wlan0'):
        """WiFi ağlarını gelişmiş tarama"""
        networks = await self.scanner.scan(interface)
        
        # TSUNAMI threat intel ile koreleasyon
        enriched_networks = []
        for network in networks:
            threat_score = self._check_threat_intel(network['bssid'])
            network['risk_score'] = threat_score
            enriched_networks.append(network)
        
        return enriched_networks
```

#### PyRTL-SDR (RF Spektrum Analizi)
```bash
GitHub: https://github.com/roger/pyrtlsdr
Lisans: MIT License ✅
Kategori: SDR (Software Defined Radio)
Açıklama: RTL-SDR dongle için Python wrapper
TSUNAMI Kullanımı: modules/sigint_sdr/
```

**Kurulum:**
```bash
cd ~/Desktop/TSUNAMI/modules
pip install pyrtlsdr
```

**RF Analiz Kodu:**
```python
# modules/sigint_sdr/rf_analyzer.py
import rtlsdr

class RFAnalyzer:
    def __init__(self):
        self.sdr = rtlsdr.RtlSdr()
    
    def scan_spectrum(self, freq_start=88000000, freq_end=108000000):
        """RF spektrum tarama"""
        self.sdr.set_center_freq(freq_start)
        samples = self.sdr.read_samples(256*1024)
        return self._analyze_spectrum(samples)
```

### 3. TEHDİT İSTİHBARATI

#### OpenCTI
```bash
GitHub: https://github.com/opencyberalliance/opencti
Lisans: Apache 2.0 ✅
Kategori: Tehdit İstihbaratı Platformu
Açıklama: STIX2 formatı desteği
TSUNAMI Kullanımı: modules/threat_opencti/
```

**STIX2 Entegrasyonu:**
```python
# modules/threat_opencti/stix_processor.py
from stix2 import Indicator, Malware

class OpenCTIProcessor:
    def __init__(self, api_url, api_key):
        self.api_url = api_url
        self.api_key = api_key
    
    def import_iocs(self, iocs: list):
        """IOC'ları TSUNAMI formatına çevirme"""
        stix_indicators = []
        for ioc in iocs:
            indicator = Indicator(
                pattern=ioc['value'],
                pattern_type=ioc['type'],
                valid_from=datetime.datetime.now()
            )
            stix_indicators.append(indicator)
        
        # TSUNAMI veritabanına kaydet
        self._store_in_tsunami(stix_indicators)
```

#### YARA (Malware Tarama)
```bash
GitHub: https://github.com/VirusTotal/yara
Lisans: BSD 3-Clause ✅
Kategori: Malware Tarama Kuralları
Açıklama: Malware imza tespiti
TSUNAMI Kullanımı: modules/threat_yara/
```

### 4. VİSUALİZASYON

#### Leaflet Plugins
```bash
Leaflet Heat Map: https://github.com/Leaflet/Leaflet.heat
Lisans: BSD 2-Clause ✅
Kategori: Isı Haritası
Açıklama: Cihaz yoğunluk haritası
TSUNAMI Kullanımı: templates/harita.html
```

**Entegrasyon:**
```html
<link rel="stylesheet" href="https://unpkg.com/leaflet-heat@0.4.0/dist/leaflet-heat.css" />
<script src="https://unpkg.com/leaflet-heat@0.4.0/dist/leaflet-heat.js"></script>

<script>
// IoT cihaz yoğunluk haritası
var heatData = iotDevices.map(d => [d.lat, d.lon, d.intensity]);
var heatLayer = L.heatLayer(heatData, {
    radius: 25,
    blur: 15,
    maxZoom: 17,
}).addTo(map);
</script>
```

#### D3.js (Network Topology)
```bash
D3.js: https://d3js.org/
Lisans: BSD 3-Clause ✅
Kategori: Veri Görselleştirme
Açıklama: Ağ topolojisi görselleştirme
TSUNAMI Kullanımı: static/js/network_topology.js
```

---

## ⚠️ DİKKAT: LİSANS KONTROLÜ GEREKLİ

### GPL Lisanslı Projeler (Modül Olarak Kullanılabilir)
- Kismet (Wireless Tarama) - Modül olarak ayrı süreç
- MISP (Tehdit Platformu) - Sadece Python client kullanımı

### AGPL Lisanslı Projeler (Dikkatli Kullanım)
- OSRFramework - Bağımsız kullanım önerilmez
- TheHive - Modül değil, bağımsız kullanım

---

## 📋 ENTEGRASYON CHECK-LIST

### Bir Proje Entegrasyonu İçin

- [ ] Lisans uyumluluğu kontrolü
- [ ] GitHub reposunu inceleme
- [ ] Dokümantasyon okuma
- [ ] Test ortamında kurulum
- [ ] TSUNAMI modülü yazma
- [ ] API entegrasyonu test
- [ ] Hata yönetimi ekleme
- [ ] Dokümantasyon yazma
- [ ] TSUNAMI veritabanı entegrasyonu

---

## 🔗 KAYNAKLAR

### MIT Lisanslı Projeler
- [SpiderFoot](https://github.com/smicallef/spiderfoot) - OSINT
- [theHarvester](https://github.com/laramies/theHarvester) - Email/Subdomain
- [Mitaka](https://github.com/ninoseki/mitaka) - IOC Analizi
- [Airometa](https://github.com/DAWACS/Airometa) - WiFi Tarama
- [PyRTL-SDR](https://github.com/roger/pyrtlsdr) - SDR

### Apache 2.0 Lisanslı Projeler
- [OpenCTI](https://github.com/opencyberalliance/opencti) - Threat Intel

### BSD Lisanslı Projeler
- [YARA](https://github.com/VirusTotal/yara) - Malware Tarama
- [Leaflet](https://leafletjs.com/) - Map Framework
- [D3.js](https://d3js.org/) - Visualization

---

**Son Güncelleme**: 20 Şubat 2026
**Hazırlayan**: AILYDIAN AI ORCHESTRATOR v8.0
