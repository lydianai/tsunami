"""
RadVPN Mesh Network Manager

Decentralized P2P VPN yonetimi
Full-mesh topoloji destegi
AES-GCM sifreleme

Kaynak: https://github.com/mehrdadrad/radvpn
Lisans: MIT
"""

import subprocess
import yaml
import os
import secrets
import json
import socket
import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class RadVPNNode:
    """RadVPN node tanimi"""
    name: str
    address: str
    private_addresses: List[str] = field(default_factory=list)
    private_subnets: List[str] = field(default_factory=list)
    lat: float = 0.0
    lng: float = 0.0
    country: str = "XX"
    is_active: bool = False
    last_seen: Optional[datetime] = None

    def to_dict(self) -> Dict:
        return {
            'name': self.name,
            'address': self.address,
            'private_addresses': self.private_addresses,
            'private_subnets': self.private_subnets,
            'lat': self.lat,
            'lng': self.lng,
            'country': self.country,
            'is_active': self.is_active
        }


@dataclass
class RadVPNConfig:
    """RadVPN konfigurasyon"""
    revision: int = 1
    crypto_type: str = "gcm"  # gcm veya cbc
    crypto_key: str = ""
    nodes: List[RadVPNNode] = field(default_factory=list)
    etcd_endpoints: List[str] = field(default_factory=list)
    etcd_timeout: int = 10

    def to_dict(self) -> Dict:
        return {
            'revision': self.revision,
            'crypto': {
                'type': self.crypto_type,
                'key': self.crypto_key
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
                for n in self.nodes
            ]
        }


class RadVPNManager:
    """RadVPN Mesh Network Yoneticisi"""

    # Varsayilan mesh node'lari (genis cografya)
    DEFAULT_MESH_NODES = [
        {"name": "mesh-tr-ist", "address": "0.0.0.0", "country": "TR", "lat": 41.01, "lng": 28.98, "private_addresses": ["10.10.1.1/24"], "private_subnets": ["10.10.1.0/24"]},
        {"name": "mesh-tr-ank", "address": "0.0.0.0", "country": "TR", "lat": 39.93, "lng": 32.86, "private_addresses": ["10.10.2.1/24"], "private_subnets": ["10.10.2.0/24"]},
        {"name": "mesh-de-fra", "address": "0.0.0.0", "country": "DE", "lat": 50.11, "lng": 8.68, "private_addresses": ["10.10.3.1/24"], "private_subnets": ["10.10.3.0/24"]},
        {"name": "mesh-nl-ams", "address": "0.0.0.0", "country": "NL", "lat": 52.37, "lng": 4.90, "private_addresses": ["10.10.4.1/24"], "private_subnets": ["10.10.4.0/24"]},
        {"name": "mesh-ch-zur", "address": "0.0.0.0", "country": "CH", "lat": 47.37, "lng": 8.54, "private_addresses": ["10.10.5.1/24"], "private_subnets": ["10.10.5.0/24"]},
        {"name": "mesh-se-sto", "address": "0.0.0.0", "country": "SE", "lat": 59.33, "lng": 18.07, "private_addresses": ["10.10.6.1/24"], "private_subnets": ["10.10.6.0/24"]},
        {"name": "mesh-is-rey", "address": "0.0.0.0", "country": "IS", "lat": 64.15, "lng": -21.95, "private_addresses": ["10.10.7.1/24"], "private_subnets": ["10.10.7.0/24"]},
        {"name": "mesh-sg-sin", "address": "0.0.0.0", "country": "SG", "lat": 1.35, "lng": 103.82, "private_addresses": ["10.10.8.1/24"], "private_subnets": ["10.10.8.0/24"]},
    ]

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
        self._load_existing_config()

    def _ensure_dirs(self):
        """Gerekli dizinleri olustur"""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
        except PermissionError:
            # Fallback to user directory
            self.config_dir = os.path.expanduser("~/.tsunami/radvpn")
            os.makedirs(self.config_dir, exist_ok=True)

    def _load_existing_config(self):
        """Mevcut konfigurasyon dosyasini yukle"""
        config_path = os.path.join(self.config_dir, "radvpn.yaml")
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    data = yaml.safe_load(f)
                    if data:
                        self._parse_yaml_config(data)
                        logger.info("[RADVPN] Mevcut konfigurasyon yuklendi")
            except Exception as e:
                logger.warning(f"[RADVPN] Konfigurasyon yuklenemedi: {e}")

    def _parse_yaml_config(self, data: Dict):
        """YAML verisini config objesine cevir"""
        nodes = []
        for node_entry in data.get('nodes', []):
            node_data = node_entry.get('node', {})
            nodes.append(RadVPNNode(
                name=node_data.get('name', ''),
                address=node_data.get('address', ''),
                private_addresses=node_data.get('privateAddresses', []),
                private_subnets=node_data.get('privateSubnets', [])
            ))

        crypto = data.get('crypto', {})
        self.config = RadVPNConfig(
            revision=data.get('revision', 1),
            crypto_type=crypto.get('type', 'gcm'),
            crypto_key=crypto.get('key', ''),
            nodes=nodes
        )

    def generate_crypto_key(self) -> str:
        """Kriptografik olarak guvenli anahtar uret (256-bit)"""
        key = secrets.token_hex(32)
        logger.info("[RADVPN] Yeni AES-256 sifreleme anahtari uretildi")
        return key

    def create_config(self,
                      nodes: List[Dict] = None,
                      crypto_type: str = "gcm",
                      crypto_key: str = None,
                      use_defaults: bool = True) -> RadVPNConfig:
        """RadVPN konfigurasyonu olustur"""
        if not crypto_key:
            crypto_key = self.generate_crypto_key()

        # Node'lari hazirla
        if nodes:
            node_list = nodes
        elif use_defaults:
            node_list = self.DEFAULT_MESH_NODES
        else:
            node_list = []

        config = RadVPNConfig(
            revision=1,
            crypto_type=crypto_type,
            crypto_key=crypto_key,
            nodes=[
                RadVPNNode(
                    name=n.get('name', f'node-{i}'),
                    address=n.get('address', '0.0.0.0'),
                    private_addresses=n.get('private_addresses', [f'10.10.{i+1}.1/24']),
                    private_subnets=n.get('private_subnets', [f'10.10.{i+1}.0/24']),
                    lat=n.get('lat', 0),
                    lng=n.get('lng', 0),
                    country=n.get('country', 'XX')
                )
                for i, n in enumerate(node_list)
            ]
        )

        self.config = config
        logger.info(f"[RADVPN] Konfigurasyon olusturuldu: {len(config.nodes)} node")
        return config

    def config_to_yaml(self, config: RadVPNConfig = None) -> str:
        """Konfigurasyon YAML formatina cevir"""
        cfg = config or self.config
        if not cfg:
            raise ValueError("Konfigurasyon bulunamadi")

        return yaml.dump(cfg.to_dict(), default_flow_style=False, allow_unicode=True)

    def save_config(self, filename: str = "radvpn.yaml") -> str:
        """Konfigurasyon dosyasini kaydet"""
        config_path = os.path.join(self.config_dir, filename)
        yaml_content = self.config_to_yaml()

        with open(config_path, 'w') as f:
            f.write(yaml_content)

        logger.info(f"[RADVPN] Konfigurasyon kaydedildi: {config_path}")
        return config_path

    def check_binary(self) -> Dict:
        """Binary durumunu kontrol et"""
        exists = os.path.exists(self.binary_path)
        executable = os.access(self.binary_path, os.X_OK) if exists else False

        return {
            "exists": exists,
            "executable": executable,
            "path": self.binary_path,
            "ready": exists and executable
        }

    async def start(self, config_file: str = None) -> Dict:
        """RadVPN servisini baslat"""
        if self.process and self.process.poll() is None:
            return {"basarili": True, "mesaj": "Zaten calisiyor", "pid": self.process.pid}

        # Konfigurasyon kontrolu
        config_path = config_file or os.path.join(self.config_dir, "radvpn.yaml")

        if not os.path.exists(config_path):
            # Varsayilan konfigurasyon olustur
            if not self.config:
                self.create_config(use_defaults=True)
            self.save_config()

        # Binary kontrolu
        binary_status = self.check_binary()
        if not binary_status['ready']:
            logger.error("[RADVPN] Binary bulunamadi - kurulum gerekli")
            return {
                "basarili": False,
                "hata": "RadVPN binary bulunamadi",
                "cozum": "curl -sSL https://github.com/mehrdadrad/radvpn/releases/latest/download/radvpn-linux-amd64 -o /usr/local/bin/radvpn && chmod +x /usr/local/bin/radvpn",
                "detay": binary_status.get('mesaj', 'Binary yolu kontrol edin')
            }

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

            logger.info(f"[RADVPN] Mesh VPN baslatildi (PID: {self.process.pid})")
            return {
                "basarili": True,
                "pid": self.process.pid,
                "mesaj": "RadVPN mesh network aktif",
                "node_sayisi": len(self.config.nodes) if self.config else 0,
                "mod": "native"
            }

        except Exception as e:
            logger.error(f"[RADVPN] Baslama hatasi: {e}")
            return {"basarili": False, "hata": str(e)}

    async def stop(self) -> Dict:
        """RadVPN servisini durdur"""
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            except Exception as e:
                logger.warning(f"[RADVPN] Durdurma hatasi: {e}")
            finally:
                self.process = None

        # Node'lari pasif yap
        if self.config:
            for node in self.config.nodes:
                node.is_active = False

        logger.info("[RADVPN] Mesh VPN durduruldu")
        return {"basarili": True, "mesaj": "RadVPN durduruldu"}

    def durum(self) -> Dict:
        """Servis durumunu kontrol et"""
        # Process kontrolu
        process_aktif = self.process is not None and self.process.poll() is None

        return {
            "aktif": process_aktif,
            "pid": self.process.pid if process_aktif else None,
            "mod": "native" if process_aktif else "stopped",
            "node_sayisi": len(self.config.nodes) if self.config else 0,
            "aktif_node_sayisi": sum(1 for n in self.config.nodes if n.is_active) if self.config else 0,
            "sifreleme": self.config.crypto_type if self.config else None,
            "mesh_topoloji": "full-mesh",
            "revision": self.config.revision if self.config else 0
        }

    def get_nodes(self) -> List[Dict]:
        """Tum node'lari getir"""
        if not self.config:
            return []

        return [n.to_dict() for n in self.config.nodes]

    async def add_node(self, node_info: Dict) -> Dict:
        """Yeni node ekle"""
        if not self.config:
            self.create_config(nodes=[], use_defaults=False)

        # Subnet hesapla
        next_subnet = len(self.config.nodes) + 1

        new_node = RadVPNNode(
            name=node_info.get('name', f'mesh-node-{next_subnet}'),
            address=node_info.get('address', '0.0.0.0'),
            private_addresses=node_info.get('private_addresses', [f'10.10.{next_subnet}.1/24']),
            private_subnets=node_info.get('private_subnets', [f'10.10.{next_subnet}.0/24']),
            lat=node_info.get('lat', 0),
            lng=node_info.get('lng', 0),
            country=node_info.get('country', 'XX'),
            is_active=False
        )

        self.config.nodes.append(new_node)
        self.config.revision += 1

        # Konfigurasyon guncelle
        self.save_config()

        logger.info(f"[RADVPN] Yeni node eklendi: {new_node.name}")
        return {
            "basarili": True,
            "node": new_node.to_dict(),
            "revision": self.config.revision,
            "toplam_node": len(self.config.nodes)
        }

    async def remove_node(self, node_name: str) -> Dict:
        """Node kaldir"""
        if not self.config:
            return {"basarili": False, "hata": "Konfigurasyon yok"}

        original_count = len(self.config.nodes)
        self.config.nodes = [n for n in self.config.nodes if n.name != node_name]

        if len(self.config.nodes) == original_count:
            return {"basarili": False, "hata": f"Node bulunamadi: {node_name}"}

        self.config.revision += 1
        self.save_config()

        logger.info(f"[RADVPN] Node kaldirildi: {node_name}")
        return {
            "basarili": True,
            "revision": self.config.revision,
            "kalan_node": len(self.config.nodes)
        }

    def ping_node(self, node_name: str) -> Dict:
        """Node'a ping at"""
        if not self.config:
            return {"basarili": False, "hata": "Konfigurasyon yok"}

        node = next((n for n in self.config.nodes if n.name == node_name), None)
        if not node:
            return {"basarili": False, "hata": f"Node bulunamadi: {node_name}"}

        # Gercek ping - subprocess ile ICMP
        try:
            ip = node.address.split(':')[0]  # host:port formatindan IP al
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3', ip],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # "time=12.3 ms" satirindan latency cek
                import re
                match = re.search(r'time[=<]([\d.]+)\s*ms', result.stdout)
                latency = float(match.group(1)) if match else -1
                return {
                    "basarili": True,
                    "node": node_name,
                    "address": ip,
                    "latency_ms": round(latency, 2),
                    "status": "reachable"
                }
            else:
                return {
                    "basarili": True,
                    "node": node_name,
                    "address": ip,
                    "latency_ms": -1,
                    "status": "unreachable"
                }
        except subprocess.TimeoutExpired:
            return {"basarili": True, "node": node_name, "latency_ms": -1, "status": "timeout"}
        except Exception as e:
            return {"basarili": False, "hata": f"Ping hatasi: {str(e)}"}


class MeshNetworkManager:
    """Mesh Network Yonetimi ve Topoloji"""

    def __init__(self, radvpn: RadVPNManager = None):
        self.radvpn = radvpn or get_radvpn_manager()

    def calculate_mesh_routes(self) -> Dict:
        """Mesh ag rotalarini hesapla"""
        nodes = self.radvpn.get_nodes()
        routes = {}

        for node in nodes:
            routes[node['name']] = {
                'direct_peers': [n['name'] for n in nodes if n['name'] != node['name']],
                'subnet': node['private_addresses'][0] if node['private_addresses'] else None,
                'peer_count': len(nodes) - 1
            }

        return {
            "routes": routes,
            "total_connections": len(nodes) * (len(nodes) - 1) // 2,
            "topology": "full-mesh"
        }

    def get_topology_map(self) -> Dict:
        """Harita icin topoloji verisi"""
        nodes = self.radvpn.get_nodes()

        return {
            "type": "mesh",
            "encryption": self.radvpn.config.crypto_type if self.radvpn.config else "gcm",
            "nodes": [
                {
                    "id": n['name'],
                    "lat": n['lat'],
                    "lng": n['lng'],
                    "country": n['country'],
                    "address": n['address'],
                    "subnet": n['private_addresses'][0] if n['private_addresses'] else None,
                    "connections": len(nodes) - 1,
                    "aktif": n.get('is_active', False)
                }
                for n in nodes
            ],
            "connections": [
                {
                    "from": n1['name'],
                    "to": n2['name'],
                    "from_coords": [n1['lat'], n1['lng']],
                    "to_coords": [n2['lat'], n2['lng']]
                }
                for i, n1 in enumerate(nodes)
                for n2 in nodes[i+1:]
                if n1['lat'] and n2['lat']
            ],
            "stats": {
                "total_nodes": len(nodes),
                "total_connections": len(nodes) * (len(nodes) - 1) // 2,
                "countries": list(set(n['country'] for n in nodes if n['country']))
            }
        }

    def get_optimal_route(self, source: str, destination: str) -> List[str]:
        """En optimal rotayi hesapla (full-mesh'te direkt)"""
        nodes = self.radvpn.get_nodes()
        node_names = [n['name'] for n in nodes]

        if source not in node_names or destination not in node_names:
            return []

        # Full-mesh'te her zaman direkt baglanti
        return [source, destination]


# Global instance
_radvpn_manager: Optional[RadVPNManager] = None

def get_radvpn_manager() -> RadVPNManager:
    """Singleton RadVPN manager"""
    global _radvpn_manager
    if _radvpn_manager is None:
        _radvpn_manager = RadVPNManager()
    return _radvpn_manager
