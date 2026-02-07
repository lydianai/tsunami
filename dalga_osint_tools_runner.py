#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DALGA OSINT TOOLS RUNNER
Kurulu OSINT araçlarını gerçek olarak çalıştırır
Tüm araçlar entegre ve aktif
"""

import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import aiohttp

# Araç dizini
TOOLS_DIR = Path("/home/lydian/Desktop/TSUNAMI/osint_tools")

# ==================== ARAÇ DURUMU ====================

class ToolStatus(Enum):
    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    ERROR = "error"
    RUNNING = "running"
    COMPLETED = "completed"

@dataclass
class ToolResult:
    """Araç çalıştırma sonucu"""
    tool_name: str
    status: ToolStatus
    output: str = ""
    data: Dict = field(default_factory=dict)
    error: str = ""
    execution_time: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

# ==================== ARAÇ KONTROL ====================

def check_tool_installed(tool_name: str, check_command: str = None) -> bool:
    """Aracın kurulu olup olmadığını kontrol et"""
    # Dizin bazlı kontrol
    tool_paths = {
        'sherlock': TOOLS_DIR / 'username' / 'sherlock',
        'maigret': TOOLS_DIR / 'username' / 'maigret',
        'holehe': TOOLS_DIR / 'email' / 'holehe',
        'h8mail': TOOLS_DIR / 'email' / 'h8mail',
        'phoneinfoga': TOOLS_DIR / 'phone' / 'phoneinfoga',
        'ignorant': TOOLS_DIR / 'phone' / 'ignorant',
        'subfinder': TOOLS_DIR / 'domain' / 'subfinder',
        'theHarvester': TOOLS_DIR / 'domain' / 'theHarvester',
        'dnsrecon': TOOLS_DIR / 'domain' / 'dnsrecon',
        'sublist3r': TOOLS_DIR / 'domain' / 'sublist3r',
        'recon-ng': TOOLS_DIR / 'recon' / 'recon-ng',
        'spiderfoot': TOOLS_DIR / 'recon' / 'spiderfoot',
    }

    if tool_name in tool_paths:
        return tool_paths[tool_name].exists()

    # Komut bazlı kontrol
    if check_command:
        try:
            result = subprocess.run(
                check_command.split(),
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            pass

    # pip paket kontrolü
    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'show', tool_name],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except:
        pass

    return False

def get_installed_tools() -> Dict[str, bool]:
    """Tüm kurulu araçları listele"""
    tools = {
        # Username araçları - önce pip/system komutları kontrol et
        'sherlock': shutil.which('sherlock') is not None,
        'maigret': shutil.which('maigret') is not None,
        'social-analyzer': (TOOLS_DIR / 'username' / 'social-analyzer').exists(),
        'whatsmyname': (TOOLS_DIR / 'username' / 'whatsmyname').exists(),

        # Email araçları
        'holehe': shutil.which('holehe') is not None,
        'h8mail': shutil.which('h8mail') is not None,
        'infoga': (TOOLS_DIR / 'email' / 'infoga').exists(),

        # Telefon araçları
        'phoneinfoga': shutil.which('phoneinfoga') is not None,
        'ignorant': shutil.which('ignorant') is not None,

        # Domain araçları - dizin kontrolü
        'subfinder': shutil.which('subfinder') is not None or (TOOLS_DIR / 'domain' / 'subfinder').exists(),
        'theHarvester': shutil.which('theHarvester') is not None or (TOOLS_DIR / 'domain' / 'theHarvester' / 'theHarvester' / 'theHarvester.py').exists(),
        'dnsrecon': shutil.which('dnsrecon') is not None or (TOOLS_DIR / 'domain' / 'dnsrecon').exists(),
        'sublist3r': shutil.which('sublist3r') is not None or (TOOLS_DIR / 'domain' / 'sublist3r' / 'sublist3r.py').exists(),
        'amass': shutil.which('amass') is not None or (TOOLS_DIR / 'domain' / 'amass').exists(),

        # IP araçları
        'shodan': shutil.which('shodan') is not None,
        'censys': shutil.which('censys') is not None,
        'ipinfo': shutil.which('ipinfo') is not None,

        # Sosyal medya
        'instaloader': shutil.which('instaloader') is not None,
        'yt-dlp': shutil.which('yt-dlp') is not None,
        'gallery-dl': shutil.which('gallery-dl') is not None,
        'osintgram': (TOOLS_DIR / 'social' / 'osintgram').exists(),

        # Recon
        'recon-ng': (TOOLS_DIR / 'recon' / 'recon-ng').exists(),
        'spiderfoot': (TOOLS_DIR / 'recon' / 'spiderfoot').exists(),

        # Sistem araçları
        'whois': shutil.which('whois') is not None,
        'dig': shutil.which('dig') is not None,
        'nmap': shutil.which('nmap') is not None,
        'exiftool': shutil.which('exiftool') is not None,
        'traceroute': shutil.which('traceroute') is not None,
        'curl': shutil.which('curl') is not None,
    }
    return tools

# ==================== ARAÇ ÇALIŞTIRICILAR ====================

class OSINTToolRunner:
    """OSINT araç çalıştırıcı ana sınıf"""

    def __init__(self):
        self.tools_dir = TOOLS_DIR
        self.installed_tools = get_installed_tools()
        self.results_cache = {}

    async def run_sherlock(self, username: str, timeout: int = 120) -> ToolResult:
        """Sherlock ile kullanıcı adı araması"""
        tool_name = "sherlock"
        start_time = datetime.now()

        # Sherlock pip ile kurulu mu kontrol et
        sherlock_path = shutil.which('sherlock')
        if not sherlock_path:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="Sherlock kurulu değil. pip3 install sherlock-project çalıştırın."
            )

        try:
            # Sherlock'u doğrudan çalıştır (pip ile kurulu)
            proc = await asyncio.create_subprocess_exec(
                sherlock_path, username, '--print-found', '--timeout', '10',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            # Sonuçları parse et
            found_sites = []
            for line in output.split('\n'):
                if '[+]' in line or 'http' in line.lower():
                    found_sites.append(line.strip())

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output,
                data={
                    'username': username,
                    'found_count': len(found_sites),
                    'sites': found_sites[:50]  # İlk 50 site
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_maigret(self, username: str, timeout: int = 180) -> ToolResult:
        """Maigret ile gelişmiş kullanıcı adı araması (2500+ site)"""
        tool_name = "maigret"
        start_time = datetime.now()

        maigret_path = shutil.which('maigret')
        if not maigret_path:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="Maigret kurulu değil. pip3 install maigret çalıştırın."
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                maigret_path, username, '--timeout', '10', '-a',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            # Sonuçları parse et
            found_sites = []
            for line in output.split('\n'):
                if '[+]' in line or 'Found:' in line or 'http' in line.lower():
                    found_sites.append(line.strip())

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output[:10000],
                data={
                    'username': username,
                    'found_count': len(found_sites),
                    'sites': found_sites[:100]
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_holehe(self, email: str, timeout: int = 60) -> ToolResult:
        """Holehe ile email hesap kontrolü"""
        tool_name = "holehe"
        start_time = datetime.now()

        # Holehe pip ile kurulu mu kontrol et
        holehe_path = shutil.which('holehe')
        if not holehe_path:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="Holehe kurulu değil. pip3 install holehe çalıştırın."
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                holehe_path, email,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            # Sonuçları parse et
            registered_sites = []
            for line in output.split('\n'):
                if '[+]' in line:
                    registered_sites.append(line.strip())

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output,
                data={
                    'email': email,
                    'registered_count': len(registered_sites),
                    'sites': registered_sites
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_theharvester(self, domain: str, timeout: int = 120) -> ToolResult:
        """theHarvester ile domain bilgisi toplama"""
        tool_name = "theHarvester"
        start_time = datetime.now()

        # theHarvester dizin yapısı: theHarvester/theHarvester/theHarvester.py
        harvester_base = self.tools_dir / 'domain' / 'theHarvester'
        harvester_script = harvester_base / 'theHarvester' / 'theHarvester.py'

        if not harvester_script.exists():
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="theHarvester kurulu değil"
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, str(harvester_script),
                '-d', domain,
                '-b', 'hackertarget,crtsh,rapiddns',
                '-l', '50',
                cwd=str(harvester_base),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            # Sonuçları parse et
            emails = []
            hosts = []
            ips = []

            for line in output.split('\n'):
                line = line.strip()
                if '@' in line and '.' in line:
                    emails.append(line)
                elif line.startswith(domain) or domain in line:
                    if re.match(r'^[\w.-]+\.' + re.escape(domain), line):
                        hosts.append(line)
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line):
                    ips.append(line)

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output[:5000],  # İlk 5000 karakter
                data={
                    'domain': domain,
                    'emails': list(set(emails))[:50],
                    'hosts': list(set(hosts))[:50],
                    'ips': list(set(ips))[:50]
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_dnsrecon(self, domain: str, timeout: int = 60) -> ToolResult:
        """DNSRecon ile DNS analizi"""
        tool_name = "dnsrecon"
        start_time = datetime.now()

        dnsrecon_path = self.tools_dir / 'domain' / 'dnsrecon'
        if not dnsrecon_path.exists():
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="DNSRecon kurulu değil"
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, 'dnsrecon.py',
                '-d', domain,
                '-t', 'std',
                cwd=str(dnsrecon_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output[:3000],
                data={
                    'domain': domain,
                    'records': output.count('[*]')
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_whois(self, target: str, timeout: int = 30) -> ToolResult:
        """WHOIS sorgusu"""
        tool_name = "whois"
        start_time = datetime.now()

        if not shutil.which('whois'):
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="whois komutu bulunamadı"
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                'whois', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            # Önemli bilgileri çıkar
            data = {}
            patterns = {
                'registrar': r'Registrar:\s*(.+)',
                'creation_date': r'Creation Date:\s*(.+)',
                'expiration_date': r'Registry Expiry Date:\s*(.+)',
                'name_servers': r'Name Server:\s*(.+)',
                'registrant_country': r'Registrant Country:\s*(.+)',
            }

            for key, pattern in patterns.items():
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    data[key] = match.group(1).strip()

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output[:3000],
                data=data,
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_dig(self, domain: str, record_type: str = 'ANY', timeout: int = 15) -> ToolResult:
        """DNS sorgusu"""
        tool_name = "dig"
        start_time = datetime.now()

        if not shutil.which('dig'):
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="dig komutu bulunamadı"
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                'dig', domain, record_type, '+short',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            records = [r.strip() for r in output.split('\n') if r.strip()]

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output,
                data={
                    'domain': domain,
                    'record_type': record_type,
                    'records': records
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_nmap(self, target: str, ports: str = "1-1000", timeout: int = 120) -> ToolResult:
        """Nmap port tarama"""
        tool_name = "nmap"
        start_time = datetime.now()

        if not shutil.which('nmap'):
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="nmap komutu bulunamadı"
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                'nmap', '-sV', '-p', ports, '--open', target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            # Açık portları parse et
            open_ports = []
            for line in output.split('\n'):
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        open_ports.append({
                            'port': parts[0],
                            'state': parts[1],
                            'service': parts[2] if len(parts) > 2 else ''
                        })

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output[:5000],
                data={
                    'target': target,
                    'open_ports': open_ports
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_shodan(self, ip: str, api_key: str = None, timeout: int = 30) -> ToolResult:
        """Shodan IP araması"""
        tool_name = "shodan"
        start_time = datetime.now()

        if not api_key:
            # Vault'tan API key al
            try:
                from dalga_vault import Vault
                vault = Vault()
                api_key = vault.get('SHODAN_API_KEY')
            except:
                pass

        if not api_key:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error="Shodan API key gerekli"
            )

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        data = await response.json()

                        execution_time = (datetime.now() - start_time).total_seconds()

                        return ToolResult(
                            tool_name=tool_name,
                            status=ToolStatus.COMPLETED,
                            data={
                                'ip': ip,
                                'country': data.get('country_name'),
                                'city': data.get('city'),
                                'org': data.get('org'),
                                'isp': data.get('isp'),
                                'ports': data.get('ports', []),
                                'vulns': data.get('vulns', []),
                                'hostnames': data.get('hostnames', [])
                            },
                            execution_time=execution_time
                        )
                    else:
                        return ToolResult(
                            tool_name=tool_name,
                            status=ToolStatus.ERROR,
                            error=f"Shodan API hatası: {response.status}"
                        )

        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    async def run_sublist3r(self, domain: str, timeout: int = 120) -> ToolResult:
        """Sublist3r ile subdomain keşfi"""
        tool_name = "sublist3r"
        start_time = datetime.now()

        sublist3r_path = self.tools_dir / 'domain' / 'sublist3r'
        if not sublist3r_path.exists():
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.NOT_INSTALLED,
                error="Sublist3r kurulu değil"
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, 'sublist3r.py',
                '-d', domain,
                '-o', '/dev/stdout',
                cwd=str(sublist3r_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            output = stdout.decode('utf-8', errors='ignore')

            # Subdomainleri parse et
            subdomains = []
            for line in output.split('\n'):
                line = line.strip()
                if domain in line and '.' in line:
                    subdomains.append(line)

            execution_time = (datetime.now() - start_time).total_seconds()

            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.COMPLETED,
                output=output[:3000],
                data={
                    'domain': domain,
                    'subdomains': list(set(subdomains))[:100]
                },
                execution_time=execution_time
            )

        except asyncio.TimeoutError:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=f"Zaman aşımı ({timeout}s)"
            )
        except Exception as e:
            return ToolResult(
                tool_name=tool_name,
                status=ToolStatus.ERROR,
                error=str(e)
            )

    # ==================== ANA ARAŞTIRMA FONKSİYONLARI ====================

    async def investigate_username(self, username: str) -> Dict[str, ToolResult]:
        """Kullanıcı adı tam araştırması - tüm araçlar paralel çalışır"""
        results = {}

        # Paralel çalıştır
        tasks = {
            'sherlock': self.run_sherlock(username),
            'maigret': self.run_maigret(username),
        }

        # Tüm araçları paralel çalıştır
        completed = await asyncio.gather(*tasks.values(), return_exceptions=True)

        for tool_name, result in zip(tasks.keys(), completed):
            if isinstance(result, Exception):
                results[tool_name] = ToolResult(
                    tool_name=tool_name,
                    status=ToolStatus.ERROR,
                    error=str(result)
                )
            else:
                results[tool_name] = result

        return results

    async def investigate_email(self, email: str) -> Dict[str, ToolResult]:
        """Email tam araştırması"""
        results = {}

        tasks = [
            ('holehe', self.run_holehe(email)),
        ]

        for tool_name, task in tasks:
            try:
                results[tool_name] = await task
            except Exception as e:
                results[tool_name] = ToolResult(
                    tool_name=tool_name,
                    status=ToolStatus.ERROR,
                    error=str(e)
                )

        return results

    async def investigate_domain(self, domain: str) -> Dict[str, ToolResult]:
        """Domain tam araştırması"""
        results = {}

        # Sırayla çalıştır (paralel çok fazla kaynak tüketebilir)
        tools = [
            ('whois', self.run_whois(domain)),
            ('dig', self.run_dig(domain)),
            ('sublist3r', self.run_sublist3r(domain)),
            ('theHarvester', self.run_theharvester(domain)),
            ('dnsrecon', self.run_dnsrecon(domain)),
        ]

        for tool_name, task in tools:
            try:
                results[tool_name] = await task
            except Exception as e:
                results[tool_name] = ToolResult(
                    tool_name=tool_name,
                    status=ToolStatus.ERROR,
                    error=str(e)
                )

        return results

    async def investigate_ip(self, ip: str) -> Dict[str, ToolResult]:
        """IP tam araştırması"""
        results = {}

        tools = [
            ('whois', self.run_whois(ip)),
            ('shodan', self.run_shodan(ip)),
            ('nmap', self.run_nmap(ip, ports="22,80,443,8080,8443")),
        ]

        for tool_name, task in tools:
            try:
                results[tool_name] = await task
            except Exception as e:
                results[tool_name] = ToolResult(
                    tool_name=tool_name,
                    status=ToolStatus.ERROR,
                    error=str(e)
                )

        return results


# ==================== GLOBAL INSTANCE ====================

_runner_instance = None

def get_runner() -> OSINTToolRunner:
    """Global runner instance"""
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = OSINTToolRunner()
    return _runner_instance


# ==================== TEST ====================

if __name__ == '__main__':
    async def test():
        print("OSINT Tools Runner Test")
        print("=" * 50)

        runner = get_runner()

        print("\nKurulu Araçlar:")
        for tool, installed in runner.installed_tools.items():
            status = "✅" if installed else "❌"
            print(f"  {status} {tool}")

        print("\n\nTest: WHOIS google.com")
        result = await runner.run_whois("google.com")
        print(f"  Status: {result.status.value}")
        print(f"  Data: {result.data}")

    asyncio.run(test())
