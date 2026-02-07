#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
    TSUNAMI - AILYDIAN AGENT ORCHESTRATOR ENTEGRASYONU v1.0
    214 Agent | 36 Core | 23 PAI Skill Pack
================================================================================

    Özellikler:
    - Tam AILYDIAN Agent Orchestrator erişimi
    - 214 Agent Registry entegrasyonu
    - Message Bus iletişimi
    - Query Engine doğal dil sorguları
    - Güvenlik ajanları (Recon, RedTeam, OSINT)

================================================================================
"""

import os
import sys
import asyncio
import threading
import json
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from datetime import datetime
import logging

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# AILYDIAN path
AILYDIAN_PATH = "/home/lydian/Desktop/AILYDIAN-AGENT-ORCHESTRATOR"


class AgentCategory(Enum):
    """Agent kategorileri"""
    SECURITY = "security"
    RESEARCH = "research"
    RECON = "recon"
    ANALYSIS = "analysis"
    AUTOMATION = "automation"
    DESIGN = "design"
    DEBATE = "debate"
    INTELLIGENCE = "intelligence"


class AgentStatus(Enum):
    """Agent durumları"""
    IDLE = "idle"
    BUSY = "busy"
    READY = "ready"
    ERROR = "error"
    OFFLINE = "offline"


@dataclass
class AgentInfo:
    """Agent bilgisi"""
    id: str
    name: str
    type: str
    category: str
    capabilities: List[str] = field(default_factory=list)
    status: str = "ready"
    description: str = ""
    success_rate: float = 0.95
    avg_response_time: float = 1.5


@dataclass
class AgentTask:
    """Agent görevi"""
    agent_id: str
    task: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: str = "normal"
    callback_url: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    status: str = "pending"
    result: Optional[Any] = None


@dataclass
class AgentResult:
    """Agent sonucu"""
    success: bool
    agent_id: str
    task_id: str
    result: Any
    execution_time: float
    timestamp: datetime = field(default_factory=datetime.now)


class AILYDIANBridge:
    """
    TSUNAMI ↔ AILYDIAN Köprüsü

    214 Agent'a tam erişim sağlar.
    Lazy initialization ile performans optimizasyonu.
    """

    _instance = None
    _lock = threading.Lock()

    # Önemli güvenlik agent'ları
    SECURITY_AGENTS = {
        'recon': 'pai-recon-skill',
        'redteam': 'pai-redteam-skill',
        'osint': 'pai-osint-skill',
        'browser': 'pai-browser-skill',
        'council': 'pai-council-skill',
        'research': 'pai-research-skill',
        'privateinvestigator': 'pai-privateinvestigator-skill'
    }

    # Open Source Entegrasyon Agent'ları
    INTEGRATION_AGENTS = {
        'claude-mem': 'claude-mem-agent',
        'agent-lightning': 'agent-lightning-trainer',
        'skill-hub': 'skill-hub-manager',
        'erpnext': 'erpnext-developer',
        'trellis': 'trellis-3d-generator',
        'gpui': 'gpui-designer'
    }

    # Agent kategorileri
    AGENT_CATEGORIES = {
        'security': ['recon-agent', 'redteam-agent', 'security-analyst'],
        'research': ['research-agent', 'deep-research-agent', 'analyst-agent'],
        'automation': ['browser-agent', 'scraping-agent', 'automation-agent'],
        'intelligence': ['osint-agent', 'threat-intel-agent', 'private-investigator'],
        'design': ['architect-agent', 'system-design-agent', 'gpui-designer'],
        'debate': ['council-agent', 'consensus-agent'],
        'memory': ['claude-mem-agent'],
        'training': ['agent-lightning-trainer', 'agent-lightning-evaluator', 'agent-lightning-optimizer'],
        'skills': ['skill-hub-manager'],
        'development': ['erpnext-developer'],
        'creative': ['trellis-3d-generator']
    }

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized') and self._initialized:
            return

        self._initialized = False
        self._ailydian_available = False
        self._orchestrator = None
        self._query_engine = None
        self._message_bus = None
        self._agent_registry = None
        self._comm_layer = None
        self._tasks: Dict[str, AgentTask] = {}
        self._results: Dict[str, AgentResult] = {}
        self._callbacks: Dict[str, Callable] = {}

        # İstatistikler
        self._stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'total_agents': 0,
            'active_agents': 0
        }

    def initialize(self) -> bool:
        """Lazy initialization - AILYDIAN bileşenlerini yükle"""
        if self._initialized:
            return self._ailydian_available

        with self._lock:
            if self._initialized:
                return self._ailydian_available

            try:
                # AILYDIAN path'i ekle
                if AILYDIAN_PATH not in sys.path:
                    sys.path.insert(0, AILYDIAN_PATH)

                # Query Engine yükle
                try:
                    from core.query_engine import get_query_engine
                    self._query_engine = get_query_engine()
                    logger.info("[AILYDIAN] Query Engine yüklendi")
                except ImportError as e:
                    logger.warning(f"[AILYDIAN] Query Engine yüklenemedi: {e}")

                # Orchestrator yükle
                try:
                    from core.autonomous_agent_orchestrator import AILYDIANOrchestrator
                    self._orchestrator = AILYDIANOrchestrator()
                    logger.info("[AILYDIAN] Orchestrator yüklendi")
                except ImportError as e:
                    logger.warning(f"[AILYDIAN] Orchestrator yüklenemedi: {e}")

                # Communication Layer yükle
                try:
                    from core.agent_communication_layer import AgentCommunicationLayer
                    self._comm_layer = AgentCommunicationLayer()
                    logger.info("[AILYDIAN] Communication Layer yüklendi")
                except ImportError as e:
                    logger.warning(f"[AILYDIAN] Communication Layer yüklenemedi: {e}")

                self._ailydian_available = bool(self._query_engine or self._orchestrator)
                self._initialized = True

                if self._ailydian_available:
                    logger.info("[AILYDIAN] Tam entegrasyon aktif")
                else:
                    logger.info("[AILYDIAN] Fallback modu aktif")

                return self._ailydian_available

            except Exception as e:
                logger.error(f"[AILYDIAN] Başlatma hatası: {e}")
                self._initialized = True
                self._ailydian_available = False
                return False

    def is_available(self) -> bool:
        """AILYDIAN kullanılabilir mi?"""
        self.initialize()
        return self._ailydian_available

    def get_status(self) -> Dict:
        """Sistem durumu"""
        self.initialize()
        return {
            'ailydian_available': self._ailydian_available,
            'query_engine': self._query_engine is not None,
            'orchestrator': self._orchestrator is not None,
            'comm_layer': self._comm_layer is not None,
            'stats': self._stats,
            'fallback_mode': not self._ailydian_available
        }

    # ==================== AGENT YÖNETİMİ ====================

    def get_agents(self) -> List[Dict]:
        """Tüm kullanılabilir agent'ları listele"""
        self.initialize()

        if self._ailydian_available and self._orchestrator:
            try:
                agents = self._orchestrator.agent_registry.list_all_agents()
                return [{
                    'id': a.get('id'),
                    'name': a.get('name'),
                    'type': a.get('type'),
                    'category': a.get('category'),
                    'capabilities': a.get('capabilities', []),
                    'status': a.get('status', 'idle'),
                    'success_rate': a.get('success_rate', 0.95),
                    'description': a.get('description', '')
                } for a in agents]
            except Exception as e:
                logger.warning(f"[AILYDIAN] Agent listesi alınamadı: {e}")

        # Fallback: Yerleşik agent listesi
        return self._get_fallback_agents()

    def _get_fallback_agents(self) -> List[Dict]:
        """Fallback agent listesi - AILYDIAN unavailable olduğunda"""
        return [
            # Güvenlik Agent'ları
            {
                'id': 'recon-agent',
                'name': 'Recon Agent',
                'type': 'security',
                'category': 'RECON',
                'capabilities': ['whois', 'dns', 'ssl', 'port_scan', 'subdomain_enum', 'certificate_transparency'],
                'status': 'ready',
                'description': 'Pasif ve aktif keşif taraması. WHOIS, DNS, SSL sertifika analizi.',
                'success_rate': 0.95
            },
            {
                'id': 'redteam-agent',
                'name': 'RedTeam Agent',
                'type': 'security',
                'category': 'ADVERSARIAL',
                'capabilities': ['vulnerability_scan', 'exploit_check', 'attack_simulation', 'steelman', 'counterargument'],
                'status': 'ready',
                'description': '32 paralel agent ile adversarial analiz. 8 engineer, 8 architect, 8 pentester, 8 intern.',
                'success_rate': 0.92
            },
            {
                'id': 'osint-agent',
                'name': 'OSINT Agent',
                'type': 'intelligence',
                'category': 'OSINT',
                'capabilities': ['social_search', 'email_lookup', 'domain_intel', 'person_search', 'company_intel'],
                'status': 'ready',
                'description': 'Açık kaynak istihbarat toplama. Sosyal medya, e-posta, domain araştırması.',
                'success_rate': 0.94
            },

            # Araştırma Agent'ları
            {
                'id': 'research-agent',
                'name': 'Deep Research Agent',
                'type': 'research',
                'category': 'RESEARCH',
                'capabilities': ['deep_research', 'multi_source', 'synthesis', 'citation', 'fact_check'],
                'status': 'ready',
                'description': 'Çoklu kaynaklı derinlemesine araştırma. Kaynak doğrulama ve sentez.',
                'success_rate': 0.93
            },
            {
                'id': 'analyst-agent',
                'name': 'Data Analyst',
                'type': 'analysis',
                'category': 'ANALYSIS',
                'capabilities': ['data_analysis', 'pattern_detection', 'reporting', 'statistics', 'visualization'],
                'status': 'ready',
                'description': 'Veri analizi ve örüntü tespiti. İstatistiksel analiz ve raporlama.',
                'success_rate': 0.96
            },

            # Otomasyon Agent'ları
            {
                'id': 'browser-agent',
                'name': 'Browser Agent',
                'type': 'automation',
                'category': 'BROWSER',
                'capabilities': ['web_scrape', 'screenshot', 'form_fill', 'navigation', 'extraction'],
                'status': 'ready',
                'description': 'Playwright tabanlı tarayıcı otomasyonu. Web scraping ve ekran görüntüsü.',
                'success_rate': 0.91
            },
            {
                'id': 'scraping-agent',
                'name': 'Web Scraping Agent',
                'type': 'automation',
                'category': 'SCRAPING',
                'capabilities': ['html_parse', 'api_extract', 'data_clean', 'json_export'],
                'status': 'ready',
                'description': 'BeautifulSoup tabanlı web scraping. HTML parsing ve veri temizleme.',
                'success_rate': 0.94
            },

            # Tasarım Agent'ları
            {
                'id': 'architect-agent',
                'name': 'System Architect',
                'type': 'design',
                'category': 'ARCHITECTURE',
                'capabilities': ['system_design', 'security_review', 'optimization', 'diagram_generation'],
                'status': 'ready',
                'description': 'Sistem mimarisi tasarımı ve güvenlik incelemesi. Mermaid diagram üretimi.',
                'success_rate': 0.95
            },

            # Tartışma Agent'ları
            {
                'id': 'council-agent',
                'name': 'Council Agent',
                'type': 'debate',
                'category': 'COUNCIL',
                'capabilities': ['multi_perspective', 'consensus', 'decision', 'debate', 'synthesis'],
                'status': 'ready',
                'description': 'Çoklu perspektif analizi ve konsensüs oluşturma. Tartışma ve sentez.',
                'success_rate': 0.90
            },

            # İstihbarat Agent'ları
            {
                'id': 'threat-intel-agent',
                'name': 'Threat Intelligence Agent',
                'type': 'intelligence',
                'category': 'THREAT_INTEL',
                'capabilities': ['ioc_analysis', 'apt_tracking', 'malware_analysis', 'threat_correlation'],
                'status': 'ready',
                'description': 'Tehdit istihbaratı analizi. IOC, APT takibi ve malware analizi.',
                'success_rate': 0.93
            },
            {
                'id': 'private-investigator',
                'name': 'Private Investigator',
                'type': 'intelligence',
                'category': 'INVESTIGATION',
                'capabilities': ['person_locate', 'background_check', 'asset_search', 'connection_mapping'],
                'status': 'ready',
                'description': 'Etik kişi araştırması. Arka plan kontrolü ve bağlantı haritalama.',
                'success_rate': 0.89
            },
        ]

    def get_agent_by_id(self, agent_id: str) -> Optional[Dict]:
        """Belirli agent'ı getir"""
        agents = self.get_agents()
        for agent in agents:
            if agent['id'] == agent_id:
                return agent
        return None

    def get_agents_by_category(self, category: str) -> List[Dict]:
        """Kategoriye göre agent'ları getir"""
        agents = self.get_agents()
        return [a for a in agents if a.get('category', '').lower() == category.lower()]

    # ==================== SORGU VE ÇALIŞTIRMA ====================

    def query(self, query: str) -> Dict:
        """Doğal dil sorgusu işle"""
        self.initialize()

        if self._query_engine:
            try:
                result = self._query_engine.process_query(query)
                return {
                    'success': True,
                    'result': result,
                    'source': 'ailydian_query_engine'
                }
            except Exception as e:
                logger.error(f"[AILYDIAN] Query hatası: {e}")
                return {
                    'success': False,
                    'error': str(e),
                    'source': 'ailydian_query_engine'
                }

        # Fallback: Basit yanıt
        return {
            'success': True,
            'result': f"Sorgu alındı: {query}. AILYDIAN tam modunda değil, fallback yanıtı döndürülüyor.",
            'source': 'fallback'
        }

    def execute_agent(self, agent_id: str, task: str, params: Dict = None) -> Dict:
        """Agent çalıştır"""
        self.initialize()

        self._stats['total_tasks'] += 1
        task_id = f"task_{datetime.now().strftime('%Y%m%d%H%M%S%f')}"

        # Task kaydı
        agent_task = AgentTask(
            agent_id=agent_id,
            task=task,
            parameters=params or {},
            status='running'
        )
        self._tasks[task_id] = agent_task

        try:
            if self._ailydian_available and self._orchestrator:
                # Gerçek AILYDIAN execution
                result = self._execute_with_orchestrator(agent_id, task, params or {})
            else:
                # Fallback execution
                result = self._execute_fallback(agent_id, task, params or {})

            agent_task.status = 'completed'
            agent_task.result = result
            self._stats['completed_tasks'] += 1

            return {
                'success': True,
                'task_id': task_id,
                'agent_id': agent_id,
                'result': result,
                'status': 'completed'
            }

        except Exception as e:
            agent_task.status = 'failed'
            self._stats['failed_tasks'] += 1
            logger.error(f"[AILYDIAN] Execution hatası: {e}")

            return {
                'success': False,
                'task_id': task_id,
                'agent_id': agent_id,
                'error': str(e),
                'status': 'failed'
            }

    def _execute_with_orchestrator(self, agent_id: str, task: str, params: Dict) -> Any:
        """Orchestrator ile çalıştır"""
        from core.autonomous_agent_orchestrator import Message, MessageType

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            message = Message(
                type=MessageType.TASK_ASSIGN,
                sender_id="tsunami_web",
                receiver_id=agent_id,
                payload={'task': task, 'parameters': params}
            )

            result = loop.run_until_complete(
                self._orchestrator.message_bus.publish(message)
            )
            return result
        finally:
            loop.close()

    def _execute_fallback(self, agent_id: str, task: str, params: Dict) -> Dict:
        """Fallback execution - basit simülasyon"""
        agent = self.get_agent_by_id(agent_id)

        if not agent:
            return {'error': f'Agent bulunamadı: {agent_id}'}

        # Agent türüne göre simüle et
        if 'recon' in agent_id.lower():
            return self._simulate_recon(params)
        elif 'redteam' in agent_id.lower():
            return self._simulate_redteam(params)
        elif 'osint' in agent_id.lower():
            return self._simulate_osint(params)
        else:
            return {
                'message': f"Task alındı: {task}",
                'agent': agent['name'],
                'params': params,
                'note': 'Fallback modu - simüle edilmiş yanıt'
            }

    def _simulate_recon(self, params: Dict) -> Dict:
        """Gerçek Recon taraması - AILYDIAN AutoFix: Simülasyon kaldırıldı"""
        import socket
        import ssl
        import requests

        target = params.get('target', 'unknown')
        findings = {'whois': {}, 'dns': {}, 'ssl': {}, 'subdomains': []}

        try:
            # Gerçek DNS çözümlemesi
            try:
                a_records = socket.gethostbyname_ex(target)[2]
                findings['dns']['a_records'] = a_records
            except socket.gaierror:
                findings['dns']['a_records'] = []

            # Gerçek MX kayıtları
            try:
                import dns.resolver
                mx_records = [str(r.exchange).rstrip('.') for r in dns.resolver.resolve(target, 'MX')]
                findings['dns']['mx_records'] = mx_records
            except Exception:
                findings['dns']['mx_records'] = []

            # Gerçek SSL sertifika bilgisi
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((target, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        findings['ssl'] = {
                            'issuer': dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown'),
                            'valid': True,
                            'expires': cert.get('notAfter', 'Unknown')
                        }
            except Exception:
                findings['ssl'] = {'issuer': 'N/A', 'valid': False}

            # Gerçek WHOIS (basit)
            try:
                resp = requests.get(f"https://api.hackertarget.com/whois/?q={target}", timeout=10)
                if resp.status_code == 200:
                    findings['whois']['raw'] = resp.text[:500]
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"Recon hatası: {e}")

        return {
            'target': target,
            'findings': findings,
            'risk_score': 5.0 if not findings['ssl'].get('valid') else 2.0,
            'recommendations': self._generate_recon_recommendations(findings),
            'mode': 'real'
        }

    def _generate_recon_recommendations(self, findings: Dict) -> List[str]:
        """Recon bulgularına göre öneriler üret"""
        recs = []
        if not findings.get('ssl', {}).get('valid'):
            recs.append('SSL sertifikası geçersiz veya eksik - HTTPS yapılandırmasını kontrol edin')
        if not findings.get('dns', {}).get('mx_records'):
            recs.append('MX kayıtları bulunamadı - E-posta yapılandırmasını kontrol edin')
        if len(findings.get('dns', {}).get('a_records', [])) > 5:
            recs.append('Çok sayıda A kaydı tespit edildi - Load balancer veya CDN kullanımını doğrulayın')
        return recs or ['Kritik sorun tespit edilmedi']

    def _simulate_redteam(self, params: Dict) -> Dict:
        """RedTeam simülasyonu"""
        target = params.get('target', 'unknown')
        return {
            'target': target,
            'analysis': {
                'engineers': ['Code review completed', 'No critical bugs found'],
                'architects': ['Architecture is sound', 'Consider microservices'],
                'pentesters': ['No immediate vulnerabilities', 'Recommend regular scanning'],
                'interns': ['Fresh perspective: UI could be improved']
            },
            'steelman': 'The target system shows good security practices',
            'counterarguments': ['Potential for social engineering attacks'],
            'overall_risk': 'LOW',
            'mode': 'simulation'
        }

    def _simulate_osint(self, params: Dict) -> Dict:
        """Gerçek OSINT araştırması - AILYDIAN AutoFix: Simülasyon kaldırıldı"""
        import requests

        query = params.get('query', 'unknown')
        findings = {'social_media': [], 'domain_intel': [], 'email_patterns': [], 'breaches': []}
        sources_checked = 0

        try:
            # HackerTarget OSINT
            try:
                resp = requests.get(f"https://api.hackertarget.com/hostsearch/?q={query}", timeout=10)
                if resp.status_code == 200 and 'error' not in resp.text.lower():
                    subdomains = [line.split(',')[0] for line in resp.text.strip().split('\n') if ',' in line]
                    findings['domain_intel'] = subdomains[:20]
                    sources_checked += 1
            except Exception:
                pass

            # Email pattern tespiti
            if '@' in query or '.' in query:
                domain = query.split('@')[-1] if '@' in query else query
                findings['email_patterns'] = [
                    f"Olası format: ad.soyad@{domain}",
                    f"Olası format: a.soyad@{domain}",
                    f"Olası format: adsoyad@{domain}"
                ]
                sources_checked += 1

            # HIBP breach check (API key gerektirir, opsiyonel)
            hibp_key = os.environ.get('HIBP_API_KEY')
            if hibp_key and '@' in query:
                try:
                    headers = {'hibp-api-key': hibp_key, 'User-Agent': 'TSUNAMI-OSINT'}
                    resp = requests.get(
                        f"https://haveibeenpwned.com/api/v3/breachedaccount/{query}",
                        headers=headers, timeout=10
                    )
                    if resp.status_code == 200:
                        findings['breaches'] = [b['Name'] for b in resp.json()]
                    sources_checked += 1
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"OSINT hatası: {e}")

        return {
            'query': query,
            'findings': findings,
            'confidence': min(0.95, 0.5 + (sources_checked * 0.15)),
            'sources_checked': sources_checked,
            'mode': 'real'
        }

    # ==================== ÖZEL GÜVENLİK FONKSİYONLARI ====================

    def recon_scan(self, target: str, scan_type: str = 'passive') -> Dict:
        """Keşif taraması başlat"""
        return self.execute_agent('recon-agent', f"{scan_type} reconnaissance on {target}", {
            'target': target,
            'type': scan_type,
            'modules': ['whois', 'dns', 'ssl', 'subdomains', 'certificate_transparency']
        })

    def redteam_analysis(self, target: str, scope: str = 'full') -> Dict:
        """RedTeam analizi"""
        return self.execute_agent('redteam-agent', f"adversarial analysis of {target}", {
            'target': target,
            'scope': scope,
            'agents': 32,  # 8 engineer + 8 architect + 8 pentester + 8 intern
            'methodology': 'parallel_adversarial'
        })

    def osint_investigation(self, query: str, depth: str = 'deep') -> Dict:
        """OSINT araştırması"""
        return self.execute_agent('osint-agent', f"investigate {query}", {
            'query': query,
            'depth': depth,
            'sources': ['social', 'domain', 'email', 'phone', 'company']
        })

    def threat_analysis(self, ioc: str, ioc_type: str = 'auto') -> Dict:
        """Tehdit analizi"""
        return self.execute_agent('threat-intel-agent', f"analyze threat indicator {ioc}", {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'correlate': True
        })

    def browser_task(self, url: str, action: str = 'scrape') -> Dict:
        """Browser görevi"""
        return self.execute_agent('browser-agent', f"{action} on {url}", {
            'url': url,
            'action': action,
            'screenshot': True
        })

    # ==================== YARDIMCI METODLAR ====================

    def get_task_status(self, task_id: str) -> Optional[Dict]:
        """Task durumunu getir"""
        task = self._tasks.get(task_id)
        if task:
            return asdict(task)
        return None

    def get_all_tasks(self, limit: int = 50) -> List[Dict]:
        """Tüm taskları getir"""
        tasks = list(self._tasks.values())[-limit:]
        return [asdict(t) for t in tasks]

    def get_statistics(self) -> Dict:
        """İstatistikleri getir"""
        return self._stats.copy()


# ==================== SINGLETON ERIŞIM ====================

_ailydian_bridge: Optional[AILYDIANBridge] = None


def ailydian_al() -> AILYDIANBridge:
    """AILYDIAN bridge singleton"""
    global _ailydian_bridge
    if _ailydian_bridge is None:
        _ailydian_bridge = AILYDIANBridge()
    return _ailydian_bridge


# ==================== TEST ====================

if __name__ == '__main__':
    # Test
    bridge = ailydian_al()
    print("AILYDIAN Status:", bridge.get_status())
    print("\nAgents:", json.dumps(bridge.get_agents()[:3], indent=2))
    print("\nRecon Test:", bridge.recon_scan('example.com'))
