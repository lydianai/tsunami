# RadVPN Entegrasyon Plani - TSUNAMI Siber Komuta Merkezi

## Proje Analizi

### RadVPN Ozellikleri
| Ozellik | Deger |
|---------|-------|
| **Lisans** | MIT (Ticari kullanim serbest, atif gerekli) |
| **Dil** | Go 1.11+ |
| **Mimari** | Full-mesh / Decentralized P2P |
| **Sifreleme** | AES-GCM / AES-CBC |
| **Konfigurasyon** | YAML / etcd |
| **Platform** | Linux |

### Telif Uyumlulugu
MIT Lisansi gereksinimleri:
1. Lisans metnini kodda tutmak
2. Kaynak belirtmek (attribution)
3. Degisiklik yapilabilir
4. Ticari kullanim serbest

```
Copyright (c) mehrdadrad/radvpn
MIT License - https://github.com/mehrdadrad/radvpn
```

---

## Mimari Tasarim

### Mevcut TSUNAMI VPN Altyapisi
```
dalga_stealth.py
├── VPNCascade (multi-hop VPN)
├── ProxyChain (SOCKS proxy chain)
├── CryptoComm (Signal Protocol)
└── StealthOrchestrator

dalga_web.py
├── /api/vpn/durum
├── /api/vpn/baglan
├── /api/vpn/kes
├── /api/vpn/sunucular
└── /api/vpn/killswitch
```

### Yeni RadVPN Entegrasyonu
```
modules/
└── tsunami_radvpn/
    ├── __init__.py
    ├── radvpn_manager.py      # Ana yonetici sinif
    ├── mesh_network.py        # Mesh ag yonetimi
    ├── node_discovery.py      # Node kesfi
    ├── config_generator.py    # YAML konfigurasyon
    ├── crypto_handler.py      # Sifreleme
    └── bin/
        └── radvpn             # Derlenmiş Go binary
```

---

## Entegrasyon Adimlari

### Adim 1: RadVPN Binary Derleme

```bash
# Go kurulumu (1.11+)
# RadVPN klonla ve derle
git clone https://github.com/mehrdadrad/radvpn.git /tmp/radvpn
cd /tmp/radvpn
go build -o radvpn cmd/radvpn/main.go

# TSUNAMI'ye kopyala
cp radvpn /home/lydian/Desktop/TSUNAMI/modules/tsunami_radvpn/bin/
chmod +x /home/lydian/Desktop/TSUNAMI/modules/tsunami_radvpn/bin/radvpn
```

### Adim 2: Python Wrapper Modulu

```python
# modules/tsunami_radvpn/radvpn_manager.py

import subprocess
import yaml
import os
import hashlib
import secrets
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging
import asyncio
import socket

logger = logging.getLogger(__name__)

@dataclass
class RadVPNNode:
    """RadVPN node tanimi"""
    name: str
    address: str
    private_addresses: List[str]
    private_subnets: List[str]
    lat: float = 0.0
    lng: float = 0.0
    country: str = ""
    is_active: bool = False

@dataclass
class RadVPNConfig:
    """RadVPN konfigurasyon"""
    revision: int = 1
    crypto_type: str = "gcm"  # gcm veya cbc
    crypto_key: str = ""
    nodes: List[RadVPNNode] = field(default_factory=list)

class RadVPNManager:
    """RadVPN Mesh Network Yoneticisi"""

    def __init__(self, config_dir: str = None):
        self.config_dir = config_dir or "/etc/tsunami/radvpn"
        self.binary_path = os.path.join(
            os.path.dirname(__file__),
            "bin",
            "radvpn"
        )
        self.config: Optional[RadVPNConfig] = None
        self.process: Optional[subprocess.Popen] = None
        self.local_node: Optional[RadVPNNode] = None
        self._ensure_dirs()

    def _ensure_dirs(self):
        """Gerekli dizinleri olustur"""
        os.makedirs(self.config_dir, exist_ok=True)

    def generate_crypto_key(self) -> str:
        """Kriptografik olarak guvenli anahtar uret"""
        # 32 byte = 256 bit AES anahtari
        key = secrets.token_hex(32)
        logger.info("[RADVPN] Yeni sifreleme anahtari uretildi")
        return key

    def create_config(self,
                      nodes: List[Dict],
                      crypto_type: str = "gcm",
                      crypto_key: str = None) -> RadVPNConfig:
        """RadVPN konfigurasyonu olustur"""
        if not crypto_key:
            crypto_key = self.generate_crypto_key()

        config = RadVPNConfig(
            revision=1,
            crypto_type=crypto_type,
            crypto_key=crypto_key,
            nodes=[
                RadVPNNode(
                    name=n.get('name', f'node-{i}'),
                    address=n['address'],
                    private_addresses=n.get('private_addresses', [f'10.0.{i}.1/24']),
                    private_subnets=n.get('private_subnets', [f'10.0.{i}.0/24']),
                    lat=n.get('lat', 0),
                    lng=n.get('lng', 0),
                    country=n.get('country', 'XX')
                )
                for i, n in enumerate(nodes)
            ]
        )

        self.config = config
        return config

    def config_to_yaml(self, config: RadVPNConfig = None) -> str:
        """Konfigurasyon YAML formatina cevir"""
        cfg = config or self.config
        if not cfg:
            raise ValueError("Konfigurasyon bulunamadi")

        yaml_dict = {
            'revision': cfg.revision,
            'crypto': {
                'type': cfg.crypto_type,
                'key': cfg.crypto_key
            },
            'nodes': [
                {
                    'node': {
                        'name': n.name,
                        'address': n.address,
                        'privateAddresses': n.private_addresses,
                        'privateSubnets': n.private_subnets
                    }
                }
                for n in cfg.nodes
            ]
        }

        return yaml.dump(yaml_dict, default_flow_style=False)

    def save_config(self, filename: str = "radvpn.yaml"):
        """Konfigurasyon dosyasini kaydet"""
        config_path = os.path.join(self.config_dir, filename)
        yaml_content = self.config_to_yaml()

        with open(config_path, 'w') as f:
            f.write(yaml_content)

        logger.info(f"[RADVPN] Konfigurasyon kaydedildi: {config_path}")
        return config_path

    async def start(self, config_file: str = None) -> Dict:
        """RadVPN servisini baslat"""
        if self.process and self.process.poll() is None:
            return {"basarili": False, "hata": "Zaten calisiyor"}

        config_path = config_file or os.path.join(self.config_dir, "radvpn.yaml")

        if not os.path.exists(config_path):
            return {"basarili": False, "hata": "Konfigurasyon dosyasi bulunamadi"}

        if not os.path.exists(self.binary_path):
            return {"basarili": False, "hata": "RadVPN binary bulunamadi"}

        try:
            self.process = subprocess.Popen(
                [self.binary_path, "-config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            # Baslama icin bekle
            await asyncio.sleep(2)

            if self.process.poll() is not None:
                stderr = self.process.stderr.read().decode()
                return {"basarili": False, "hata": f"Baslatma hatasi: {stderr}"}

            logger.info("[RADVPN] Mesh VPN baslatildi")
            return {
                "basarili": True,
                "pid": self.process.pid,
                "mesaj": "RadVPN mesh network aktif"
            }

        except Exception as e:
            logger.error(f"[RADVPN] Baslama hatasi: {e}")
            return {"basarili": False, "hata": str(e)}

    async def stop(self) -> Dict:
        """RadVPN servisini durdur"""
        if not self.process:
            return {"basarili": False, "hata": "Calisan servis yok"}

        try:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None

            logger.info("[RADVPN] Mesh VPN durduruldu")
            return {"basarili": True, "mesaj": "RadVPN durduruldu"}

        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process = None
            return {"basarili": True, "mesaj": "RadVPN zorla durduruldu"}
        except Exception as e:
            return {"basarili": False, "hata": str(e)}

    def durum(self) -> Dict:
        """Servis durumunu kontrol et"""
        aktif = self.process is not None and self.process.poll() is None

        return {
            "aktif": aktif,
            "pid": self.process.pid if aktif else None,
            "node_sayisi": len(self.config.nodes) if self.config else 0,
            "sifreleme": self.config.crypto_type if self.config else None,
            "mesh_topoloji": "full-mesh"
        }

    def get_nodes(self) -> List[Dict]:
        """Tum node'lari getir"""
        if not self.config:
            return []

        return [
            {
                "name": n.name,
                "address": n.address,
                "private_addresses": n.private_addresses,
                "country": n.country,
                "lat": n.lat,
                "lng": n.lng,
                "aktif": n.is_active
            }
            for n in self.config.nodes
        ]

    async def add_node(self, node_info: Dict) -> Dict:
        """Yeni node ekle"""
        if not self.config:
            return {"basarili": False, "hata": "Konfigurasyon yok"}

        new_node = RadVPNNode(
            name=node_info.get('name', f'node-{len(self.config.nodes)}'),
            address=node_info['address'],
            private_addresses=node_info.get('private_addresses', []),
            private_subnets=node_info.get('private_subnets', []),
            lat=node_info.get('lat', 0),
            lng=node_info.get('lng', 0),
            country=node_info.get('country', 'XX')
        )

        self.config.nodes.append(new_node)
        self.config.revision += 1

        # Konfigurasyon guncelle
        self.save_config()

        logger.info(f"[RADVPN] Yeni node eklendi: {new_node.name}")
        return {"basarili": True, "node": new_node.name, "revision": self.config.revision}

    async def remove_node(self, node_name: str) -> Dict:
        """Node kaldir"""
        if not self.config:
            return {"basarili": False, "hata": "Konfigurasyon yok"}

        self.config.nodes = [n for n in self.config.nodes if n.name != node_name]
        self.config.revision += 1
        self.save_config()

        logger.info(f"[RADVPN] Node kaldirildi: {node_name}")
        return {"basarili": True, "revision": self.config.revision}


class MeshNetworkManager:
    """Mesh Network Yonetimi"""

    def __init__(self, radvpn: RadVPNManager):
        self.radvpn = radvpn
        self.topology = {}

    def calculate_mesh_routes(self) -> Dict:
        """Mesh ag rotalarini hesapla"""
        nodes = self.radvpn.get_nodes()
        routes = {}

        for node in nodes:
            routes[node['name']] = {
                'direct_peers': [n['name'] for n in nodes if n['name'] != node['name']],
                'subnet': node['private_addresses'][0] if node['private_addresses'] else None
            }

        return routes

    def get_topology_map(self) -> Dict:
        """Harita icin topoloji verisi"""
        nodes = self.radvpn.get_nodes()

        return {
            "type": "mesh",
            "nodes": [
                {
                    "id": n['name'],
                    "lat": n['lat'],
                    "lng": n['lng'],
                    "country": n['country'],
                    "connections": len(nodes) - 1  # Full mesh
                }
                for n in nodes
            ],
            "connections": [
                {"from": n1['name'], "to": n2['name']}
                for i, n1 in enumerate(nodes)
                for n2 in nodes[i+1:]
            ]
        }


# Global instance
_radvpn_manager: Optional[RadVPNManager] = None

def get_radvpn_manager() -> RadVPNManager:
    """Singleton RadVPN manager"""
    global _radvpn_manager
    if _radvpn_manager is None:
        _radvpn_manager = RadVPNManager()
    return _radvpn_manager
```

### Adim 3: API Endpoint'leri (dalga_web.py)

```python
# dalga_web.py'ye eklenecek

from modules.tsunami_radvpn import get_radvpn_manager, MeshNetworkManager

# ==================== RADVPN MESH API ====================

@app.route('/api/radvpn/durum')
@login_required
def api_radvpn_durum():
    """RadVPN mesh network durumu"""
    manager = get_radvpn_manager()
    return jsonify(manager.durum())

@app.route('/api/radvpn/baslat', methods=['POST'])
@login_required
async def api_radvpn_baslat():
    """RadVPN mesh network baslat"""
    manager = get_radvpn_manager()
    data = request.get_json() or {}

    # Varsayilan node'lar
    if not manager.config:
        default_nodes = [
            {"name": "tsunami-hub", "address": "0.0.0.0", "country": "TR", "lat": 39.93, "lng": 32.86},
        ]
        manager.create_config(data.get('nodes', default_nodes))
        manager.save_config()

    sonuc = await manager.start()
    if sonuc.get('basarili'):
        socketio.emit('radvpn_durum', {'aktif': True})
    return jsonify(sonuc)

@app.route('/api/radvpn/durdur', methods=['POST'])
@login_required
async def api_radvpn_durdur():
    """RadVPN mesh network durdur"""
    manager = get_radvpn_manager()
    sonuc = await manager.stop()
    socketio.emit('radvpn_durum', {'aktif': False})
    return jsonify(sonuc)

@app.route('/api/radvpn/nodes')
@login_required
def api_radvpn_nodes():
    """Mesh node listesi"""
    manager = get_radvpn_manager()
    return jsonify({"nodes": manager.get_nodes()})

@app.route('/api/radvpn/node/ekle', methods=['POST'])
@login_required
async def api_radvpn_node_ekle():
    """Yeni mesh node ekle"""
    manager = get_radvpn_manager()
    data = request.get_json()
    sonuc = await manager.add_node(data)
    return jsonify(sonuc)

@app.route('/api/radvpn/node/kaldir', methods=['POST'])
@login_required
async def api_radvpn_node_kaldir():
    """Mesh node kaldir"""
    manager = get_radvpn_manager()
    data = request.get_json()
    sonuc = await manager.remove_node(data.get('name'))
    return jsonify(sonuc)

@app.route('/api/radvpn/topoloji')
@login_required
def api_radvpn_topoloji():
    """Mesh topoloji harita verisi"""
    manager = get_radvpn_manager()
    mesh = MeshNetworkManager(manager)
    return jsonify(mesh.get_topology_map())

@app.route('/api/radvpn/konfigurasyon', methods=['GET', 'POST'])
@login_required
def api_radvpn_konfigurasyon():
    """Konfigurasyon yonetimi"""
    manager = get_radvpn_manager()

    if request.method == 'POST':
        data = request.get_json()
        manager.create_config(
            nodes=data.get('nodes', []),
            crypto_type=data.get('crypto_type', 'gcm'),
            crypto_key=data.get('crypto_key')
        )
        manager.save_config()
        return jsonify({"basarili": True})

    return jsonify({
        "revision": manager.config.revision if manager.config else 0,
        "crypto_type": manager.config.crypto_type if manager.config else None,
        "node_count": len(manager.config.nodes) if manager.config else 0
    })
```

### Adim 4: Frontend Entegrasyonu (harita.html)

```javascript
// RadVPN Mesh Network UI

// Mesh topoloji cizimi
async function drawMeshTopology() {
    try {
        const res = await fetch('/api/radvpn/topoloji');
        const data = await res.json();

        if (!data.nodes || data.nodes.length === 0) return;

        // Node'lari haritaya ekle
        data.nodes.forEach(node => {
            if (node.lat && node.lng) {
                const marker = L.circleMarker([node.lat, node.lng], {
                    radius: 8,
                    fillColor: '#8a2be2',
                    color: '#8a2be2',
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 0.6
                }).addTo(map);

                marker.bindPopup(`
                    <strong style="color:#8a2be2">Mesh Node: ${node.id}</strong><br>
                    <span style="color:#aaa">Ulke:</span> ${node.country}<br>
                    <span style="color:#aaa">Baglantilar:</span> ${node.connections}
                `);
            }
        });

        // Baglantilari ciz
        data.connections.forEach(conn => {
            const from = data.nodes.find(n => n.id === conn.from);
            const to = data.nodes.find(n => n.id === conn.to);

            if (from && to && from.lat && to.lat) {
                L.polyline([[from.lat, from.lng], [to.lat, to.lng]], {
                    color: '#8a2be2',
                    weight: 1,
                    opacity: 0.4,
                    dashArray: '5, 10'
                }).addTo(map);
            }
        });

        termLog(`[MESH] ${data.nodes.length} node, ${data.connections.length} baglanti cizildi`, 'ok');
    } catch (e) {
        console.error('[MESH] Topoloji hatasi:', e);
    }
}

// RadVPN durum kontrolu
async function checkRadVPNStatus() {
    try {
        const res = await fetch('/api/radvpn/durum');
        const data = await res.json();

        const statusEl = document.getElementById('radvpnStatus');
        if (statusEl) {
            statusEl.textContent = data.aktif ? 'Aktif' : 'Pasif';
            statusEl.style.color = data.aktif ? '#00ff88' : '#ff3355';
        }

        return data;
    } catch (e) {
        return { aktif: false };
    }
}

// RadVPN baslat/durdur
async function toggleRadVPN() {
    const status = await checkRadVPNStatus();

    if (status.aktif) {
        await fetch('/api/radvpn/durdur', { method: 'POST' });
        termLog('[MESH] RadVPN durduruldu', 'warn');
    } else {
        await fetch('/api/radvpn/baslat', { method: 'POST' });
        termLog('[MESH] RadVPN baslatildi', 'ok');
        setTimeout(drawMeshTopology, 2000);
    }

    await checkRadVPNStatus();
}
```

### Adim 5: StealthOrchestrator Entegrasyonu

```python
# dalga_stealth.py'ye eklenecek

from modules.tsunami_radvpn import get_radvpn_manager

class StealthOrchestrator:
    """Ana gizlilik orkestratoru - RadVPN destekli"""

    def __init__(self):
        self.tor_manager = TorManager()
        self.proxy_chain = ProxyChain()
        self.vpn_cascade = VPNCascade()
        self.radvpn = get_radvpn_manager()  # Yeni
        self.crypto_comm = CryptoComm()
        self.current_level = 0

    async def set_stealth_level(self, level: int) -> Dict:
        """Gizlilik seviyesi ayarla"""
        hops = []

        if level >= 1:
            # TOR + Proxy
            await self.tor_manager.renew_circuit()
            hops.extend(self.tor_manager.get_circuit_path())

        if level >= 2:
            # + VPN Cascade
            await self.vpn_cascade.build_cascade(1)
            hops.extend([{"type": "vpn", **v} for v in self.vpn_cascade.get_cascade_path()])

        if level >= 3:
            # + RadVPN Mesh (YENi)
            radvpn_status = self.radvpn.durum()
            if radvpn_status.get('aktif'):
                mesh_nodes = self.radvpn.get_nodes()
                hops.extend([{"type": "mesh", **n} for n in mesh_nodes[:2]])
                logger.info("[STEALTH] RadVPN mesh katmani eklendi")

        if level >= 4:
            # + Multi-hop VPN + Mesh
            await self.vpn_cascade.build_cascade(2)
            hops.extend([{"type": "vpn", **v} for v in self.vpn_cascade.get_cascade_path()])

            # Tam mesh aktivasyonu
            if not self.radvpn.durum().get('aktif'):
                await self.radvpn.start()

        self.current_level = level
        return {
            "level": level,
            "hops": len(hops),
            "path": hops,
            "mesh_active": self.radvpn.durum().get('aktif', False)
        }
```

---

## Guvenlik Onlemleri

### 1. Anahtar Yonetimi
- Kriptografik olarak guvenli anahtar uretimi (`secrets.token_hex`)
- Anahtarlar dosya sisteminde guvenli saklanir
- Her konfigurasyon degisikliginde revision artar

### 2. Network Izolasyonu
- Ozel subnet'ler (10.0.x.0/24)
- Mesh trafigi sifrelenir (AES-GCM)
- Kill switch destegi

### 3. Telif Uyumlulugu
- MIT lisansi korunur
- Attribution eklenir
- Fork degil, wrapper kullanimi

---

## Test Plani

### Birim Testleri
```python
def test_radvpn_config_generation():
    manager = RadVPNManager()
    config = manager.create_config([
        {"name": "test-1", "address": "192.168.1.1"},
        {"name": "test-2", "address": "192.168.1.2"}
    ])
    assert len(config.nodes) == 2
    assert config.crypto_type == "gcm"

def test_yaml_export():
    manager = RadVPNManager()
    manager.create_config([{"name": "n1", "address": "1.1.1.1"}])
    yaml_str = manager.config_to_yaml()
    assert "revision:" in yaml_str
    assert "crypto:" in yaml_str
```

### Entegrasyon Testleri
1. RadVPN binary derleme ve calistirma
2. Multi-node mesh kurulumu
3. Trafik sifreleme dogrulama
4. StealthOrchestrator ile senkronizasyon
5. Harita UI entegrasyonu

---

## Dosya Yapisi

```
TSUNAMI/
├── modules/
│   └── tsunami_radvpn/
│       ├── __init__.py
│       ├── radvpn_manager.py
│       ├── mesh_network.py
│       ├── config_generator.py
│       ├── LICENSE_RADVPN.txt      # MIT lisans metni
│       └── bin/
│           └── radvpn              # Derlenmiş binary
├── dalga_web.py                    # API endpoint'leri
├── dalga_stealth.py                # StealthOrchestrator
└── templates/
    └── harita.html                 # UI entegrasyonu
```

---

## Uygulama Sirasi

1. **Faz 1**: Modul yapisi ve RadVPN binary
2. **Faz 2**: Python wrapper (RadVPNManager)
3. **Faz 3**: API endpoint'leri
4. **Faz 4**: StealthOrchestrator entegrasyonu
5. **Faz 5**: Frontend UI
6. **Faz 6**: Test ve dokumantasyon

---

## Sonuc

RadVPN entegrasyonu TSUNAMI'ye:
- Merkezi olmayan mesh VPN yetenegi
- Daha guclu anonimlik katmani
- Dagitik operasyon kapasitesi
- P2P node yonetimi

kazandiracaktir. MIT lisansi sayesinde telif sorunu olmadan ticari kullanim mumkundur.
