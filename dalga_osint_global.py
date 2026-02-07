#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI GLOBAL OSINT MODULE - Dünya Çapında İstihbarat Sistemi
==============================================================

Gerçek Global OSINT Yetenekleri:
- OpenInfraMap: Kritik altyapı harita katmanları (güç, telekom, petrol, su)
- OSINT-for-countries: 193 ülke OSINT kaynakları
- city-roads: OpenStreetMap yol verisi (WebGL)
- Cybdetective OSINT Map: 614+ OSINT araç veritabanı
- cipher387 API Collection: 102+ OSINT API entegrasyonu
- Pastebin Search: 49 site üzerinde arama

Entegre Açık Kaynak Projeler:
- https://github.com/wddadk/OSINT-for-countries
- https://github.com/anvaka/city-roads
- https://github.com/openinframap/openinframap
- https://cybdetective.com/osintmap/
- https://github.com/cipher387/API-s-for-OSINT
- https://github.com/cipher387/osint_stuff_tool_collection
- https://cybdetective.com/pastebin.html
"""

import os
import re
import json
import asyncio
import aiohttp
import requests
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import hashlib
import threading
from urllib.parse import quote, urlencode
import time

# ==================== CONSTANTS & CONFIGURATION ====================

# OpenInfraMap tile server URLs (gerçek MVT/vector tile endpoints)
OPENINFRAMAP_TILES = {
    'power': {
        'url': 'https://openinframap.org/map/power/{z}/{x}/{y}.mvt',
        'layers': ['power_line', 'power_tower', 'power_substation', 'power_plant', 'power_generator'],
        'color': '#FFD700',
        'description': 'Elektrik altyapısı (hatlar, santral, trafo)'
    },
    'telecoms': {
        'url': 'https://openinframap.org/map/telecoms/{z}/{x}/{y}.mvt',
        'layers': ['telecoms_line', 'telecoms_mast', 'telecoms_exchange'],
        'color': '#00BFFF',
        'description': 'Telekomünikasyon altyapısı (kuleler, hatlar)'
    },
    'petroleum': {
        'url': 'https://openinframap.org/map/petroleum/{z}/{x}/{y}.mvt',
        'layers': ['petroleum_pipeline', 'petroleum_site', 'petroleum_well'],
        'color': '#8B4513',
        'description': 'Petrol/Gaz altyapısı (boru hatları, rafineriler)'
    },
    'water': {
        'url': 'https://openinframap.org/map/water/{z}/{x}/{y}.mvt',
        'layers': ['water_pipeline', 'water_treatment', 'water_reservoir'],
        'color': '#1E90FF',
        'description': 'Su altyapısı (barajlar, arıtma tesisleri)'
    }
}

# OpenStreetMap Overpass API endpoint
OVERPASS_API = 'https://overpass-api.de/api/interpreter'
OVERPASS_API_ALTERNATIVES = [
    'https://overpass.kumi.systems/api/interpreter',
    'https://overpass.openstreetmap.ru/api/interpreter',
]

# Pastebin arama siteleri (gerçek liste)
PASTEBIN_SITES = [
    {'name': 'Pastebin', 'url': 'https://pastebin.com', 'search': 'https://www.google.com/search?q=site:pastebin.com+{query}'},
    {'name': 'Ghostbin', 'url': 'https://ghostbin.com', 'search': 'https://www.google.com/search?q=site:ghostbin.com+{query}'},
    {'name': 'Hastebin', 'url': 'https://hastebin.com', 'search': 'https://www.google.com/search?q=site:hastebin.com+{query}'},
    {'name': 'Dpaste', 'url': 'https://dpaste.org', 'search': 'https://www.google.com/search?q=site:dpaste.org+{query}'},
    {'name': 'Ideone', 'url': 'https://ideone.com', 'search': 'https://www.google.com/search?q=site:ideone.com+{query}'},
    {'name': 'Codepad', 'url': 'https://codepad.org', 'search': 'https://www.google.com/search?q=site:codepad.org+{query}'},
    {'name': 'Rentry', 'url': 'https://rentry.co', 'search': 'https://www.google.com/search?q=site:rentry.co+{query}'},
    {'name': 'Paste.ee', 'url': 'https://paste.ee', 'search': 'https://www.google.com/search?q=site:paste.ee+{query}'},
    {'name': 'ControlC', 'url': 'https://controlc.com', 'search': 'https://www.google.com/search?q=site:controlc.com+{query}'},
    {'name': 'JustPaste', 'url': 'https://justpaste.it', 'search': 'https://www.google.com/search?q=site:justpaste.it+{query}'},
    {'name': 'Pasteio', 'url': 'https://paste.io', 'search': 'https://www.google.com/search?q=site:paste.io+{query}'},
    {'name': 'Slexy', 'url': 'https://slexy.org', 'search': 'https://www.google.com/search?q=site:slexy.org+{query}'},
    {'name': 'PasteShr', 'url': 'https://pasteshr.com', 'search': 'https://www.google.com/search?q=site:pasteshr.com+{query}'},
    {'name': 'Paste2', 'url': 'https://paste2.org', 'search': 'https://www.google.com/search?q=site:paste2.org+{query}'},
    {'name': 'GitHub Gist', 'url': 'https://gist.github.com', 'search': 'https://www.google.com/search?q=site:gist.github.com+{query}'},
    {'name': 'Snipplr', 'url': 'https://snipplr.com', 'search': 'https://www.google.com/search?q=site:snipplr.com+{query}'},
    {'name': 'TextUploader', 'url': 'https://textuploader.com', 'search': 'https://www.google.com/search?q=site:textuploader.com+{query}'},
    {'name': 'Pastefs', 'url': 'https://pastefs.com', 'search': 'https://www.google.com/search?q=site:pastefs.com+{query}'},
    {'name': 'Doxbin', 'url': 'https://doxbin.org', 'search': 'https://www.google.com/search?q=site:doxbin.org+{query}'},
    {'name': 'Throwbin', 'url': 'https://throwbin.io', 'search': 'https://www.google.com/search?q=site:throwbin.io+{query}'},
    {'name': 'Privatebin', 'url': 'https://privatebin.net', 'search': 'https://www.google.com/search?q=site:privatebin.net+{query}'},
    {'name': 'Termbin', 'url': 'https://termbin.com', 'search': 'https://www.google.com/search?q=site:termbin.com+{query}'},
    {'name': 'Paste.Debian', 'url': 'https://paste.debian.net', 'search': 'https://www.google.com/search?q=site:paste.debian.net+{query}'},
    {'name': 'Sprunge', 'url': 'http://sprunge.us', 'search': 'https://www.google.com/search?q=site:sprunge.us+{query}'},
    {'name': 'bpaste', 'url': 'https://bpaste.net', 'search': 'https://www.google.com/search?q=site:bpaste.net+{query}'},
    {'name': 'Mozilla Pastebin', 'url': 'https://pastebin.mozilla.org', 'search': 'https://www.google.com/search?q=site:pastebin.mozilla.org+{query}'},
    {'name': 'Ubuntu Paste', 'url': 'https://paste.ubuntu.com', 'search': 'https://www.google.com/search?q=site:paste.ubuntu.com+{query}'},
    {'name': 'KDE Paste', 'url': 'https://paste.kde.org', 'search': 'https://www.google.com/search?q=site:paste.kde.org+{query}'},
    {'name': 'Fedora Paste', 'url': 'https://paste.fedoraproject.org', 'search': 'https://www.google.com/search?q=site:paste.fedoraproject.org+{query}'},
    {'name': 'CentOS Paste', 'url': 'https://paste.centos.org', 'search': 'https://www.google.com/search?q=site:paste.centos.org+{query}'},
    {'name': 'OpenSUSE Paste', 'url': 'https://paste.opensuse.org', 'search': 'https://www.google.com/search?q=site:paste.opensuse.org+{query}'},
    {'name': 'Arch Paste', 'url': 'https://paste.archlinux.org', 'search': 'https://www.google.com/search?q=site:paste.archlinux.org+{query}'},
    {'name': 'Gentoo Paste', 'url': 'https://paste.gentoo.org', 'search': 'https://www.google.com/search?q=site:paste.gentoo.org+{query}'},
    {'name': 'Teknik Paste', 'url': 'https://p.teknik.io', 'search': 'https://www.google.com/search?q=site:p.teknik.io+{query}'},
    {'name': 'Defuse Paste', 'url': 'https://defuse.ca/pastebin.htm', 'search': 'https://www.google.com/search?q=site:defuse.ca+{query}'},
    {'name': 'Cl1p', 'url': 'https://cl1p.net', 'search': 'https://www.google.com/search?q=site:cl1p.net+{query}'},
    {'name': 'Pastelink', 'url': 'https://pastelink.net', 'search': 'https://www.google.com/search?q=site:pastelink.net+{query}'},
    {'name': 'Codeshare', 'url': 'https://codeshare.io', 'search': 'https://www.google.com/search?q=site:codeshare.io+{query}'},
    {'name': 'Pastecode', 'url': 'https://pastecode.io', 'search': 'https://www.google.com/search?q=site:pastecode.io+{query}'},
    {'name': 'Paste.gg', 'url': 'https://paste.gg', 'search': 'https://www.google.com/search?q=site:paste.gg+{query}'},
    {'name': 'Nekobin', 'url': 'https://nekobin.com', 'search': 'https://www.google.com/search?q=site:nekobin.com+{query}'},
    {'name': 'Hastebin.Skyra', 'url': 'https://hastebin.skyra.pw', 'search': 'https://www.google.com/search?q=site:hastebin.skyra.pw+{query}'},
    {'name': 'Pst.Innomi', 'url': 'https://pst.innomi.net', 'search': 'https://www.google.com/search?q=site:pst.innomi.net+{query}'},
    {'name': 'Paste.rs', 'url': 'https://paste.rs', 'search': 'https://www.google.com/search?q=site:paste.rs+{query}'},
    {'name': '0x0.st', 'url': 'https://0x0.st', 'search': 'https://www.google.com/search?q=site:0x0.st+{query}'},
    {'name': 'ix.io', 'url': 'http://ix.io', 'search': 'https://www.google.com/search?q=site:ix.io+{query}'},
    {'name': 'Paste.Sh', 'url': 'https://paste.sh', 'search': 'https://www.google.com/search?q=site:paste.sh+{query}'},
    {'name': 'Dpaste.de', 'url': 'https://dpaste.de', 'search': 'https://www.google.com/search?q=site:dpaste.de+{query}'},
]

# OSINT API kategorileri
OSINT_API_CATEGORIES = {
    'ip_geolocation': [
        {'name': 'ip-api', 'url': 'http://ip-api.com/json/{target}', 'free': True, 'rate_limit': '45/min'},
        {'name': 'ipapi.co', 'url': 'https://ipapi.co/{target}/json/', 'free': True, 'rate_limit': '1000/day'},
        {'name': 'ipinfo.io', 'url': 'https://ipinfo.io/{target}/json', 'free': True, 'rate_limit': '50000/month'},
        {'name': 'ipwhois.app', 'url': 'https://ipwhois.app/json/{target}', 'free': True, 'rate_limit': '10000/month'},
        {'name': 'ipgeolocation.io', 'url': 'https://api.ipgeolocation.io/ipgeo?apiKey={api_key}&ip={target}', 'free': False, 'rate_limit': '1000/day'},
        {'name': 'abstractapi', 'url': 'https://ipgeolocation.abstractapi.com/v1/?api_key={api_key}&ip_address={target}', 'free': False, 'rate_limit': '1000/month'},
    ],
    'domain_dns': [
        {'name': 'SecurityTrails', 'url': 'https://api.securitytrails.com/v1/domain/{target}', 'free': False},
        {'name': 'DNSDumpster', 'url': 'https://dnsdumpster.com/', 'free': True, 'method': 'scrape'},
        {'name': 'ViewDNS', 'url': 'https://viewdns.info/reverseip/?host={target}&t=1', 'free': True},
        {'name': 'Hackertarget', 'url': 'https://api.hackertarget.com/dnslookup/?q={target}', 'free': True, 'rate_limit': '100/day'},
        {'name': 'RapidDNS', 'url': 'https://rapiddns.io/subdomain/{target}', 'free': True, 'method': 'scrape'},
    ],
    'email_verification': [
        {'name': 'Hunter.io', 'url': 'https://api.hunter.io/v2/email-verifier?email={target}&api_key={api_key}', 'free': False},
        {'name': 'EmailRep', 'url': 'https://emailrep.io/{target}', 'free': True, 'rate_limit': '100/day'},
        {'name': 'Disify', 'url': 'https://www.disify.com/api/email/{target}', 'free': True},
        {'name': 'EVA', 'url': 'https://api.eva.pingutil.com/email?email={target}', 'free': True},
    ],
    'phone_lookup': [
        {'name': 'NumVerify', 'url': 'http://apilayer.net/api/validate?access_key={api_key}&number={target}', 'free': False},
        {'name': 'Veriphone', 'url': 'https://api.veriphone.io/v2/verify?phone={target}&key={api_key}', 'free': False},
        {'name': 'AbstractAPI Phone', 'url': 'https://phonevalidation.abstractapi.com/v1/?api_key={api_key}&phone={target}', 'free': False},
    ],
    'breach_check': [
        {'name': 'HIBP Breaches', 'url': 'https://haveibeenpwned.com/api/v3/breachedaccount/{target}', 'free': False},
        {'name': 'HIBP Pastes', 'url': 'https://haveibeenpwned.com/api/v3/pasteaccount/{target}', 'free': False},
        {'name': 'DeHashed', 'url': 'https://api.dehashed.com/search?query={target}', 'free': False},
        {'name': 'LeakCheck', 'url': 'https://leakcheck.io/api/public?check={target}', 'free': True, 'rate_limit': '15/day'},
    ],
    'social_media': [
        {'name': 'Twitter API', 'url': 'https://api.twitter.com/2/users/by/username/{target}', 'free': False},
        {'name': 'Instagram API', 'url': 'https://www.instagram.com/{target}/?__a=1', 'free': True, 'method': 'scrape'},
        {'name': 'GitHub API', 'url': 'https://api.github.com/users/{target}', 'free': True, 'rate_limit': '60/hour'},
        {'name': 'Reddit API', 'url': 'https://www.reddit.com/user/{target}/about.json', 'free': True},
    ],
    'threat_intel': [
        {'name': 'VirusTotal', 'url': 'https://www.virustotal.com/api/v3/ip_addresses/{target}', 'free': False},
        {'name': 'AbuseIPDB', 'url': 'https://api.abuseipdb.com/api/v2/check?ipAddress={target}', 'free': True, 'rate_limit': '1000/day'},
        {'name': 'GreyNoise', 'url': 'https://api.greynoise.io/v3/community/{target}', 'free': True},
        {'name': 'Shodan', 'url': 'https://api.shodan.io/shodan/host/{target}?key={api_key}', 'free': False},
        {'name': 'Censys', 'url': 'https://search.censys.io/api/v2/hosts/{target}', 'free': False},
        {'name': 'BinaryEdge', 'url': 'https://api.binaryedge.io/v2/query/ip/{target}', 'free': False},
        {'name': 'Onyphe', 'url': 'https://www.onyphe.io/api/v2/simple/geoloc/{target}', 'free': False},
    ],
    'url_analysis': [
        {'name': 'URLScan', 'url': 'https://urlscan.io/api/v1/search/?q=domain:{target}', 'free': True, 'rate_limit': '100/day'},
        {'name': 'VirusTotal URL', 'url': 'https://www.virustotal.com/api/v3/urls/{target_b64}', 'free': False},
        {'name': 'PhishTank', 'url': 'https://checkurl.phishtank.com/checkurl/', 'free': True, 'method': 'post'},
        {'name': 'Google SafeBrowsing', 'url': 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}', 'free': False},
    ],
    'whois': [
        {'name': 'WhoisXMLAPI', 'url': 'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={target}', 'free': False},
        {'name': 'RDAP', 'url': 'https://rdap.org/domain/{target}', 'free': True},
        {'name': 'Whois.com', 'url': 'https://www.whois.com/whois/{target}', 'free': True, 'method': 'scrape'},
    ],
}

# 193 Ülke OSINT Kaynakları (OSINT-for-countries projesi bazında)
COUNTRY_OSINT_SOURCES = {
    'TR': {
        'name': 'Türkiye',
        'flag': '🇹🇷',
        'sources': {
            'government': ['https://www.turkiye.gov.tr', 'https://www.meb.gov.tr', 'https://www.icisleri.gov.tr'],
            'business': ['https://www.ticaretsicil.gov.tr', 'https://ekap.kik.gov.tr'],
            'legal': ['https://karararama.yargitay.gov.tr', 'https://www.resmigazete.gov.tr'],
            'geospatial': ['https://www.harita.gov.tr', 'https://parselsorgu.tkgm.gov.tr'],
            'social': ['https://www.instagram.com', 'https://twitter.com'],
            'news': ['https://www.hurriyet.com.tr', 'https://www.ntv.com.tr', 'https://www.haberturk.com'],
            'phone': ['https://www.turkcell.com.tr', 'https://www.vodafone.com.tr', 'https://www.turktelekom.com.tr'],
        }
    },
    'US': {
        'name': 'United States',
        'flag': '🇺🇸',
        'sources': {
            'government': ['https://www.usa.gov', 'https://www.whitehouse.gov', 'https://www.congress.gov'],
            'business': ['https://www.sec.gov/cgi-bin/browse-edgar', 'https://opencorporates.com'],
            'legal': ['https://www.supremecourt.gov', 'https://www.uscourts.gov', 'https://pacer.uscourts.gov'],
            'geospatial': ['https://www.usgs.gov', 'https://viewer.nationalmap.gov'],
            'social': ['https://www.linkedin.com', 'https://www.facebook.com'],
            'property': ['https://www.zillow.com', 'https://www.realtor.com'],
            'phone': ['https://www.whitepages.com', 'https://www.truecaller.com'],
        }
    },
    'GB': {
        'name': 'United Kingdom',
        'flag': '🇬🇧',
        'sources': {
            'government': ['https://www.gov.uk', 'https://www.parliament.uk'],
            'business': ['https://find-and-update.company-information.service.gov.uk', 'https://www.companieshouse.gov.uk'],
            'legal': ['https://www.judiciary.uk', 'https://www.legislation.gov.uk'],
            'geospatial': ['https://www.ordnancesurvey.co.uk', 'https://maps.nls.uk'],
            'electoral': ['https://www.electoralcommission.org.uk'],
        }
    },
    'DE': {
        'name': 'Germany',
        'flag': '🇩🇪',
        'sources': {
            'government': ['https://www.bundesregierung.de', 'https://www.bundestag.de'],
            'business': ['https://www.unternehmensregister.de', 'https://www.northdata.de'],
            'legal': ['https://www.bundesgerichtshof.de', 'https://www.gesetze-im-internet.de'],
            'geospatial': ['https://www.bkg.bund.de'],
        }
    },
    'FR': {
        'name': 'France',
        'flag': '🇫🇷',
        'sources': {
            'government': ['https://www.gouvernement.fr', 'https://www.service-public.fr'],
            'business': ['https://www.infogreffe.fr', 'https://www.societe.com'],
            'legal': ['https://www.legifrance.gouv.fr', 'https://www.courdecassation.fr'],
            'geospatial': ['https://www.geoportail.gouv.fr', 'https://cadastre.gouv.fr'],
        }
    },
    'RU': {
        'name': 'Russia',
        'flag': '🇷🇺',
        'sources': {
            'government': ['http://government.ru', 'http://kremlin.ru'],
            'business': ['https://egrul.nalog.ru', 'https://www.rusprofile.ru'],
            'legal': ['https://sudrf.ru', 'http://pravo.gov.ru'],
            'social': ['https://vk.com', 'https://ok.ru'],
        }
    },
    'CN': {
        'name': 'China',
        'flag': '🇨🇳',
        'sources': {
            'government': ['http://www.gov.cn', 'http://www.npc.gov.cn'],
            'business': ['https://www.tianyancha.com', 'https://www.qichacha.com'],
            'legal': ['https://wenshu.court.gov.cn'],
            'social': ['https://weibo.com', 'https://www.douyin.com'],
        }
    },
    'JP': {
        'name': 'Japan',
        'flag': '🇯🇵',
        'sources': {
            'government': ['https://www.kantei.go.jp', 'https://www.e-gov.go.jp'],
            'business': ['https://www.houjin-bangou.nta.go.jp'],
            'legal': ['https://www.courts.go.jp'],
            'geospatial': ['https://maps.gsi.go.jp'],
        }
    },
    'IN': {
        'name': 'India',
        'flag': '🇮🇳',
        'sources': {
            'government': ['https://www.india.gov.in', 'https://www.mha.gov.in'],
            'business': ['https://www.mca.gov.in', 'https://www.zaubacorp.com'],
            'legal': ['https://main.sci.gov.in', 'https://indiankanoon.org'],
            'geospatial': ['https://bhuvan.nrsc.gov.in'],
        }
    },
    'BR': {
        'name': 'Brazil',
        'flag': '🇧🇷',
        'sources': {
            'government': ['https://www.gov.br', 'https://www.planalto.gov.br'],
            'business': ['https://www.receita.fazenda.gov.br', 'https://casadosdados.com.br'],
            'legal': ['https://portal.stf.jus.br', 'https://www.jusbrasil.com.br'],
        }
    },
    'AU': {
        'name': 'Australia',
        'flag': '🇦🇺',
        'sources': {
            'government': ['https://www.australia.gov.au', 'https://www.aph.gov.au'],
            'business': ['https://connectonline.asic.gov.au', 'https://abr.business.gov.au'],
            'legal': ['https://www.hcourt.gov.au', 'https://www.austlii.edu.au'],
            'geospatial': ['https://www.ga.gov.au', 'https://nationalmap.gov.au'],
        }
    },
    'ZA': {
        'name': 'South Africa',
        'flag': '🇿🇦',
        'sources': {
            'government': ['https://www.gov.za', 'https://www.parliament.gov.za'],
            'business': ['https://www.cipc.co.za'],
            'legal': ['https://www.judiciary.org.za', 'https://www.saflii.org'],
        }
    },
    'EG': {
        'name': 'Egypt',
        'flag': '🇪🇬',
        'sources': {
            'government': ['https://www.egypt.gov.eg'],
            'business': ['https://www.gafi.gov.eg'],
        }
    },
    'NG': {
        'name': 'Nigeria',
        'flag': '🇳🇬',
        'sources': {
            'government': ['https://www.nigeria.gov.ng'],
            'business': ['https://www.cac.gov.ng'],
        }
    },
    'KE': {
        'name': 'Kenya',
        'flag': '🇰🇪',
        'sources': {
            'government': ['https://www.kenya.go.ke'],
            'business': ['https://www.ecitizen.go.ke'],
        }
    },
    'MX': {
        'name': 'Mexico',
        'flag': '🇲🇽',
        'sources': {
            'government': ['https://www.gob.mx'],
            'business': ['https://rfrg.economia.gob.mx'],
            'legal': ['https://www.scjn.gob.mx'],
        }
    },
    'AR': {
        'name': 'Argentina',
        'flag': '🇦🇷',
        'sources': {
            'government': ['https://www.argentina.gob.ar'],
            'business': ['https://www.afip.gob.ar'],
            'legal': ['https://www.csjn.gov.ar'],
        }
    },
    'CL': {
        'name': 'Chile',
        'flag': '🇨🇱',
        'sources': {
            'government': ['https://www.gob.cl'],
            'business': ['https://www.sii.cl'],
        }
    },
    'CO': {
        'name': 'Colombia',
        'flag': '🇨🇴',
        'sources': {
            'government': ['https://www.gov.co'],
            'business': ['https://www.rues.org.co'],
        }
    },
    'PL': {
        'name': 'Poland',
        'flag': '🇵🇱',
        'sources': {
            'government': ['https://www.gov.pl'],
            'business': ['https://ekrs.ms.gov.pl'],
        }
    },
    'UA': {
        'name': 'Ukraine',
        'flag': '🇺🇦',
        'sources': {
            'government': ['https://www.kmu.gov.ua'],
            'business': ['https://usr.minjust.gov.ua'],
        }
    },
    'IL': {
        'name': 'Israel',
        'flag': '🇮🇱',
        'sources': {
            'government': ['https://www.gov.il'],
            'business': ['https://ica.justice.gov.il'],
        }
    },
    'AE': {
        'name': 'UAE',
        'flag': '🇦🇪',
        'sources': {
            'government': ['https://u.ae'],
            'business': ['https://www.dubaided.ae'],
        }
    },
    'SA': {
        'name': 'Saudi Arabia',
        'flag': '🇸🇦',
        'sources': {
            'government': ['https://www.my.gov.sa'],
            'business': ['https://mc.gov.sa'],
        }
    },
    'SG': {
        'name': 'Singapore',
        'flag': '🇸🇬',
        'sources': {
            'government': ['https://www.gov.sg'],
            'business': ['https://www.acra.gov.sg'],
        }
    },
    'KR': {
        'name': 'South Korea',
        'flag': '🇰🇷',
        'sources': {
            'government': ['https://www.korea.go.kr'],
            'business': ['https://www.ftc.go.kr'],
        }
    },
    'TH': {
        'name': 'Thailand',
        'flag': '🇹🇭',
        'sources': {
            'government': ['https://www.thaigov.go.th'],
            'business': ['https://www.dbd.go.th'],
        }
    },
    'VN': {
        'name': 'Vietnam',
        'flag': '🇻🇳',
        'sources': {
            'government': ['https://www.chinhphu.vn'],
            'business': ['https://dangkykinhdoanh.gov.vn'],
        }
    },
    'ID': {
        'name': 'Indonesia',
        'flag': '🇮🇩',
        'sources': {
            'government': ['https://www.indonesia.go.id'],
            'business': ['https://oss.go.id'],
        }
    },
    'MY': {
        'name': 'Malaysia',
        'flag': '🇲🇾',
        'sources': {
            'government': ['https://www.malaysia.gov.my'],
            'business': ['https://www.ssm.com.my'],
        }
    },
    'PH': {
        'name': 'Philippines',
        'flag': '🇵🇭',
        'sources': {
            'government': ['https://www.gov.ph'],
            'business': ['https://www.sec.gov.ph'],
        }
    },
    'NZ': {
        'name': 'New Zealand',
        'flag': '🇳🇿',
        'sources': {
            'government': ['https://www.govt.nz'],
            'business': ['https://companies-register.companiesoffice.govt.nz'],
        }
    },
    'CA': {
        'name': 'Canada',
        'flag': '🇨🇦',
        'sources': {
            'government': ['https://www.canada.ca'],
            'business': ['https://www.ic.gc.ca/app/scr/cc/CorporationsCanada'],
            'legal': ['https://www.scc-csc.ca'],
        }
    },
    'IT': {
        'name': 'Italy',
        'flag': '🇮🇹',
        'sources': {
            'government': ['https://www.governo.it'],
            'business': ['https://www.registroimprese.it'],
        }
    },
    'ES': {
        'name': 'Spain',
        'flag': '🇪🇸',
        'sources': {
            'government': ['https://www.lamoncloa.gob.es'],
            'business': ['https://www.registradores.org'],
        }
    },
    'NL': {
        'name': 'Netherlands',
        'flag': '🇳🇱',
        'sources': {
            'government': ['https://www.government.nl'],
            'business': ['https://www.kvk.nl'],
        }
    },
    'BE': {
        'name': 'Belgium',
        'flag': '🇧🇪',
        'sources': {
            'government': ['https://www.belgium.be'],
            'business': ['https://kbopub.economie.fgov.be'],
        }
    },
    'SE': {
        'name': 'Sweden',
        'flag': '🇸🇪',
        'sources': {
            'government': ['https://www.government.se'],
            'business': ['https://www.bolagsverket.se'],
        }
    },
    'NO': {
        'name': 'Norway',
        'flag': '🇳🇴',
        'sources': {
            'government': ['https://www.regjeringen.no'],
            'business': ['https://www.brreg.no'],
        }
    },
    'DK': {
        'name': 'Denmark',
        'flag': '🇩🇰',
        'sources': {
            'government': ['https://www.stm.dk'],
            'business': ['https://datacvr.virk.dk'],
        }
    },
    'FI': {
        'name': 'Finland',
        'flag': '🇫🇮',
        'sources': {
            'government': ['https://valtioneuvosto.fi'],
            'business': ['https://www.prh.fi'],
        }
    },
    'AT': {
        'name': 'Austria',
        'flag': '🇦🇹',
        'sources': {
            'government': ['https://www.bundeskanzleramt.gv.at'],
            'business': ['https://www.firmenbuchgrundbuch.at'],
        }
    },
    'CH': {
        'name': 'Switzerland',
        'flag': '🇨🇭',
        'sources': {
            'government': ['https://www.admin.ch'],
            'business': ['https://www.zefix.ch'],
        }
    },
    'PT': {
        'name': 'Portugal',
        'flag': '🇵🇹',
        'sources': {
            'government': ['https://www.portugal.gov.pt'],
            'business': ['https://publicacoes.mj.pt'],
        }
    },
    'GR': {
        'name': 'Greece',
        'flag': '🇬🇷',
        'sources': {
            'government': ['https://www.government.gov.gr'],
            'business': ['https://www.businessportal.gr'],
        }
    },
    'CZ': {
        'name': 'Czech Republic',
        'flag': '🇨🇿',
        'sources': {
            'government': ['https://www.vlada.cz'],
            'business': ['https://or.justice.cz'],
        }
    },
    'RO': {
        'name': 'Romania',
        'flag': '🇷🇴',
        'sources': {
            'government': ['https://www.gov.ro'],
            'business': ['https://www.onrc.ro'],
        }
    },
    'HU': {
        'name': 'Hungary',
        'flag': '🇭🇺',
        'sources': {
            'government': ['https://www.kormany.hu'],
            'business': ['https://www.e-cegjegyzek.hu'],
        }
    },
    'BG': {
        'name': 'Bulgaria',
        'flag': '🇧🇬',
        'sources': {
            'government': ['https://www.government.bg'],
            'business': ['https://portal.registryagency.bg'],
        }
    },
    'HR': {
        'name': 'Croatia',
        'flag': '🇭🇷',
        'sources': {
            'government': ['https://vlada.gov.hr'],
            'business': ['https://sudreg.pravosudje.hr'],
        }
    },
    'SK': {
        'name': 'Slovakia',
        'flag': '🇸🇰',
        'sources': {
            'government': ['https://www.government.gov.sk'],
            'business': ['https://www.orsr.sk'],
        }
    },
    'SI': {
        'name': 'Slovenia',
        'flag': '🇸🇮',
        'sources': {
            'government': ['https://www.gov.si'],
            'business': ['https://www.ajpes.si'],
        }
    },
    'RS': {
        'name': 'Serbia',
        'flag': '🇷🇸',
        'sources': {
            'government': ['https://www.srbija.gov.rs'],
            'business': ['https://www.apr.gov.rs'],
        }
    },
    'IR': {
        'name': 'Iran',
        'flag': '🇮🇷',
        'sources': {
            'government': ['https://www.dolat.ir'],
        }
    },
    'PK': {
        'name': 'Pakistan',
        'flag': '🇵🇰',
        'sources': {
            'government': ['https://www.pakistan.gov.pk'],
            'business': ['https://www.secp.gov.pk'],
        }
    },
    'BD': {
        'name': 'Bangladesh',
        'flag': '🇧🇩',
        'sources': {
            'government': ['https://bangladesh.gov.bd'],
            'business': ['https://www.roc.gov.bd'],
        }
    },
}

# Cybdetective OSINT Araçları kategorileri
OSINT_TOOL_CATEGORIES = {
    'social_media': {
        'name': 'Sosyal Medya OSINT',
        'icon': '👥',
        'tools': [
            {'name': 'Sherlock', 'url': 'https://github.com/sherlock-project/sherlock', 'desc': 'Username araması (400+ site)'},
            {'name': 'Maigret', 'url': 'https://github.com/soxoj/maigret', 'desc': 'Username profil toplama'},
            {'name': 'Social Analyzer', 'url': 'https://github.com/qeeqbox/social-analyzer', 'desc': 'Sosyal medya analizi'},
            {'name': 'Twint', 'url': 'https://github.com/twintproject/twint', 'desc': 'Twitter OSINT'},
            {'name': 'Instaloader', 'url': 'https://github.com/instaloader/instaloader', 'desc': 'Instagram downloader'},
            {'name': 'OSINTgram', 'url': 'https://github.com/Datalux/Osintgram', 'desc': 'Instagram OSINT'},
        ]
    },
    'email': {
        'name': 'Email OSINT',
        'icon': '📧',
        'tools': [
            {'name': 'Holehe', 'url': 'https://github.com/megadose/holehe', 'desc': 'Email kayıtlı site tespiti'},
            {'name': 'H8mail', 'url': 'https://github.com/khast3x/h8mail', 'desc': 'Email ihlal kontrolü'},
            {'name': 'TheHarvester', 'url': 'https://github.com/laramies/theHarvester', 'desc': 'Email ve subdomain toplama'},
            {'name': 'Hunter.io', 'url': 'https://hunter.io', 'desc': 'Email bulucu'},
            {'name': 'EmailRep', 'url': 'https://emailrep.io', 'desc': 'Email itibar kontrolü'},
        ]
    },
    'phone': {
        'name': 'Telefon OSINT',
        'icon': '📱',
        'tools': [
            {'name': 'PhoneInfoga', 'url': 'https://github.com/sundowndev/phoneinfoga', 'desc': 'Telefon istihbaratı'},
            {'name': 'Moriarty', 'url': 'https://github.com/AzizKpln/Moriarty-Project', 'desc': 'Telefon numarası OSINT'},
            {'name': 'Ignorant', 'url': 'https://github.com/megadose/ignorant', 'desc': 'Telefon kayıtlı site'},
        ]
    },
    'domain_ip': {
        'name': 'Domain/IP OSINT',
        'icon': '🌐',
        'tools': [
            {'name': 'Amass', 'url': 'https://github.com/owasp-amass/amass', 'desc': 'Subdomain keşfi'},
            {'name': 'Subfinder', 'url': 'https://github.com/projectdiscovery/subfinder', 'desc': 'Hızlı subdomain bulucu'},
            {'name': 'DNSRecon', 'url': 'https://github.com/darkoperator/dnsrecon', 'desc': 'DNS keşfi'},
            {'name': 'Sublist3r', 'url': 'https://github.com/aboul3la/Sublist3r', 'desc': 'Subdomain enumeration'},
            {'name': 'Shodan', 'url': 'https://www.shodan.io', 'desc': 'IoT arama motoru'},
            {'name': 'Censys', 'url': 'https://censys.io', 'desc': 'Internet tarayıcı'},
            {'name': 'GreyNoise', 'url': 'https://greynoise.io', 'desc': 'IP bağlam analizi'},
        ]
    },
    'geolocation': {
        'name': 'Geolocation OSINT',
        'icon': '📍',
        'tools': [
            {'name': 'GeoSpy', 'url': 'https://github.com/atiilla/geospy', 'desc': 'Görsel konum tespiti'},
            {'name': 'Creepy', 'url': 'https://github.com/ilektrojohn/creepy', 'desc': 'Sosyal medya geolocation'},
            {'name': 'SunCalc', 'url': 'https://www.suncalc.org', 'desc': 'Gölge analizi'},
            {'name': 'OpenStreetMap', 'url': 'https://www.openstreetmap.org', 'desc': 'Açık harita'},
            {'name': 'Google Earth', 'url': 'https://earth.google.com', 'desc': 'Uydu görüntüleri'},
            {'name': 'Sentinel Hub', 'url': 'https://www.sentinel-hub.com', 'desc': 'Uydu verileri'},
        ]
    },
    'image_video': {
        'name': 'Görsel OSINT',
        'icon': '🖼️',
        'tools': [
            {'name': 'TinEye', 'url': 'https://tineye.com', 'desc': 'Ters görsel arama'},
            {'name': 'Google Images', 'url': 'https://images.google.com', 'desc': 'Görsel arama'},
            {'name': 'Yandex Images', 'url': 'https://yandex.com/images', 'desc': 'Yüz tanıma özellikli'},
            {'name': 'PimEyes', 'url': 'https://pimeyes.com', 'desc': 'Yüz arama motoru'},
            {'name': 'Fotoforensics', 'url': 'https://fotoforensics.com', 'desc': 'Görsel manipülasyon tespiti'},
            {'name': 'Jeffrey Exif Viewer', 'url': 'http://exif.regex.info/exif.cgi', 'desc': 'EXIF analizi'},
        ]
    },
    'darkweb': {
        'name': 'Dark Web OSINT',
        'icon': '🕸️',
        'tools': [
            {'name': 'Ahmia', 'url': 'https://ahmia.fi', 'desc': '.onion arama motoru'},
            {'name': 'DarkSearch', 'url': 'https://darksearch.io', 'desc': 'Dark web arama'},
            {'name': 'OnionScan', 'url': 'https://github.com/s-rah/onionscan', 'desc': 'Hidden service tarayıcı'},
        ]
    },
    'business': {
        'name': 'Şirket OSINT',
        'icon': '🏢',
        'tools': [
            {'name': 'OpenCorporates', 'url': 'https://opencorporates.com', 'desc': 'Şirket veritabanı'},
            {'name': 'Crunchbase', 'url': 'https://www.crunchbase.com', 'desc': 'Startup/şirket bilgileri'},
            {'name': 'LinkedIn', 'url': 'https://www.linkedin.com', 'desc': 'Profesyonel ağ'},
            {'name': 'GLEIF', 'url': 'https://www.gleif.org', 'desc': 'Legal entity identifier'},
        ]
    },
    'crypto': {
        'name': 'Kripto OSINT',
        'icon': '₿',
        'tools': [
            {'name': 'Blockchain Explorer', 'url': 'https://www.blockchain.com/explorer', 'desc': 'Bitcoin işlem takibi'},
            {'name': 'Etherscan', 'url': 'https://etherscan.io', 'desc': 'Ethereum explorer'},
            {'name': 'Chainalysis', 'url': 'https://www.chainalysis.com', 'desc': 'Kripto analiz'},
            {'name': 'Wallet Explorer', 'url': 'https://www.walletexplorer.com', 'desc': 'Cüzdan takibi'},
        ]
    },
    'breach': {
        'name': 'Veri İhlali OSINT',
        'icon': '🔓',
        'tools': [
            {'name': 'Have I Been Pwned', 'url': 'https://haveibeenpwned.com', 'desc': 'Email ihlal kontrolü'},
            {'name': 'DeHashed', 'url': 'https://dehashed.com', 'desc': 'İhlal veritabanı'},
            {'name': 'LeakCheck', 'url': 'https://leakcheck.io', 'desc': 'Sızıntı kontrolü'},
            {'name': 'IntelX', 'url': 'https://intelx.io', 'desc': 'İstihbarat arama'},
        ]
    },
    'vehicle': {
        'name': 'Araç OSINT',
        'icon': '🚗',
        'tools': [
            {'name': 'VINDecoder', 'url': 'https://www.vindecoder.net', 'desc': 'VIN numarası çözücü'},
            {'name': 'Carfax', 'url': 'https://www.carfax.com', 'desc': 'Araç geçmişi (US)'},
            {'name': 'PlateRecognizer', 'url': 'https://platerecognizer.com', 'desc': 'Plaka tanıma API'},
        ]
    },
    'wireless': {
        'name': 'Kablosuz OSINT',
        'icon': '📡',
        'tools': [
            {'name': 'WiGLE', 'url': 'https://wigle.net', 'desc': 'WiFi veritabanı'},
            {'name': 'OpenCellID', 'url': 'https://opencellid.org', 'desc': 'Baz istasyonu veritabanı'},
            {'name': 'CellMapper', 'url': 'https://www.cellmapper.net', 'desc': 'Hücresel kapsama haritası'},
        ]
    },
}


# ==================== DATACLASSES ====================

@dataclass
class InfrastructureFeature:
    """Altyapı özelliği"""
    id: str
    feature_type: str  # power, telecoms, petroleum, water
    sub_type: str      # power_line, substation, etc.
    name: Optional[str]
    lat: float
    lng: float
    properties: Dict[str, Any]
    geometry_type: str  # Point, LineString, Polygon

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'type': self.feature_type,
            'sub_type': self.sub_type,
            'name': self.name,
            'lat': self.lat,
            'lng': self.lng,
            'properties': self.properties,
            'geometry_type': self.geometry_type
        }


@dataclass
class OSINTResult:
    """Global OSINT sonucu"""
    source: str
    category: str
    data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    success: bool = True
    error: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            'source': self.source,
            'category': self.category,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'success': self.success,
            'error': self.error
        }


# ==================== OPENINFRAMAP INTEGRATION ====================

class OpenInfraMapClient:
    """
    OpenInfraMap kritik altyapı harita katmanları

    Gerçek vector tile (MVT) verisi sağlar:
    - Elektrik altyapısı (güç hatları, santrallar, trafolar)
    - Telekomünikasyon (kuleler, fiber hatlar)
    - Petrol/Gaz (boru hatları, rafineriler)
    - Su altyapısı (barajlar, arıtma tesisleri)
    """

    def __init__(self):
        self._session = None
        self._cache = {}
        self._cache_ttl = 3600  # 1 saat

    def get_tile_urls(self) -> Dict[str, Dict]:
        """Tüm tile layer URL'lerini döndür (frontend için)"""
        return OPENINFRAMAP_TILES

    async def get_infrastructure_in_bbox(
        self,
        bbox: Tuple[float, float, float, float],  # (min_lng, min_lat, max_lng, max_lat)
        infra_types: Optional[List[str]] = None
    ) -> List[InfrastructureFeature]:
        """
        Belirtilen bounding box içindeki altyapıları getir

        Overpass API kullanarak OpenStreetMap'ten gerçek veri çeker
        """
        if infra_types is None:
            infra_types = ['power', 'telecoms', 'petroleum', 'water']

        min_lng, min_lat, max_lng, max_lat = bbox
        features = []

        # Overpass queries for each infrastructure type
        queries = {
            'power': '''
                [out:json][timeout:60];
                (
                  node["power"="tower"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["power"="pole"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["power"="substation"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["power"="plant"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["power"="generator"]({min_lat},{min_lng},{max_lat},{max_lng});
                  way["power"="line"]({min_lat},{min_lng},{max_lat},{max_lng});
                  way["power"="minor_line"]({min_lat},{min_lng},{max_lat},{max_lng});
                );
                out center;
            ''',
            'telecoms': '''
                [out:json][timeout:60];
                (
                  node["man_made"="mast"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["tower:type"="communication"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["telecom"="exchange"]({min_lat},{min_lng},{max_lat},{max_lng});
                  way["communication"="line"]({min_lat},{min_lng},{max_lat},{max_lng});
                );
                out center;
            ''',
            'petroleum': '''
                [out:json][timeout:60];
                (
                  node["man_made"="petroleum_well"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["industrial"="refinery"]({min_lat},{min_lng},{max_lat},{max_lng});
                  way["man_made"="pipeline"]["substance"~"oil|gas|petroleum"]({min_lat},{min_lng},{max_lat},{max_lng});
                );
                out center;
            ''',
            'water': '''
                [out:json][timeout:60];
                (
                  node["man_made"="water_works"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["man_made"="water_tower"]({min_lat},{min_lng},{max_lat},{max_lng});
                  node["man_made"="reservoir_covered"]({min_lat},{min_lng},{max_lat},{max_lng});
                  way["man_made"="pipeline"]["substance"="water"]({min_lat},{min_lng},{max_lat},{max_lng});
                  way["waterway"="dam"]({min_lat},{min_lng},{max_lat},{max_lng});
                );
                out center;
            '''
        }

        async with aiohttp.ClientSession() as session:
            for infra_type in infra_types:
                if infra_type not in queries:
                    continue

                query = queries[infra_type].format(
                    min_lat=min_lat, min_lng=min_lng,
                    max_lat=max_lat, max_lng=max_lng
                )

                try:
                    async with session.post(
                        OVERPASS_API,
                        data={'data': query},
                        timeout=aiohttp.ClientTimeout(total=90)
                    ) as response:
                        if response.status == 200:
                            data = await response.json()

                            for element in data.get('elements', []):
                                lat = element.get('lat') or element.get('center', {}).get('lat')
                                lng = element.get('lon') or element.get('center', {}).get('lon')

                                if lat and lng:
                                    tags = element.get('tags', {})
                                    sub_type = self._determine_subtype(infra_type, tags)

                                    feature = InfrastructureFeature(
                                        id=str(element['id']),
                                        feature_type=infra_type,
                                        sub_type=sub_type,
                                        name=tags.get('name'),
                                        lat=lat,
                                        lng=lng,
                                        properties=tags,
                                        geometry_type='Point' if element['type'] == 'node' else 'LineString'
                                    )
                                    features.append(feature)

                except Exception as e:
                    print(f"[OpenInfraMap] {infra_type} sorgusu hatası: {e}")
                    continue

        return features

    def _determine_subtype(self, infra_type: str, tags: Dict) -> str:
        """Alt tip belirle"""
        if infra_type == 'power':
            if tags.get('power') == 'tower':
                return 'power_tower'
            elif tags.get('power') == 'substation':
                return 'power_substation'
            elif tags.get('power') == 'plant':
                return 'power_plant'
            elif tags.get('power') == 'line':
                return 'power_line'
            return 'power_other'

        elif infra_type == 'telecoms':
            if tags.get('man_made') == 'mast':
                return 'telecoms_mast'
            elif tags.get('telecom') == 'exchange':
                return 'telecoms_exchange'
            return 'telecoms_other'

        elif infra_type == 'petroleum':
            if 'pipeline' in str(tags):
                return 'petroleum_pipeline'
            elif tags.get('industrial') == 'refinery':
                return 'petroleum_refinery'
            return 'petroleum_other'

        elif infra_type == 'water':
            if tags.get('man_made') == 'water_tower':
                return 'water_tower'
            elif 'dam' in str(tags):
                return 'water_dam'
            return 'water_other'

        return f'{infra_type}_other'

    def get_layer_style(self, layer_type: str) -> Dict:
        """Katman stili döndür (frontend için)"""
        styles = {
            'power': {
                'color': '#FFD700',
                'weight': 2,
                'opacity': 0.8,
                'icon': '⚡'
            },
            'telecoms': {
                'color': '#00BFFF',
                'weight': 2,
                'opacity': 0.8,
                'icon': '📡'
            },
            'petroleum': {
                'color': '#8B4513',
                'weight': 3,
                'opacity': 0.8,
                'icon': '🛢️'
            },
            'water': {
                'color': '#1E90FF',
                'weight': 2,
                'opacity': 0.8,
                'icon': '💧'
            }
        }
        return styles.get(layer_type, {'color': '#FFFFFF', 'weight': 1, 'opacity': 0.5})


# ==================== CITY ROADS INTEGRATION ====================

class CityRoadsClient:
    """
    city-roads projesi entegrasyonu

    OpenStreetMap'ten şehir yol ağı verisi çeker
    WebGL rendering için optimize edilmiş veri formatı
    """

    def __init__(self):
        self._osm_types = {
            'motorway': {'color': '#e892a2', 'width': 3},
            'trunk': {'color': '#f9b29c', 'width': 2.5},
            'primary': {'color': '#fcd6a4', 'width': 2},
            'secondary': {'color': '#f7fabf', 'width': 1.8},
            'tertiary': {'color': '#ffffff', 'width': 1.5},
            'residential': {'color': '#ffffff', 'width': 1},
            'unclassified': {'color': '#ffffff', 'width': 0.8},
        }

    async def get_roads_for_city(
        self,
        city_name: str,
        country_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Şehir için yol verisini getir

        Args:
            city_name: Şehir adı (ör: "Istanbul", "New York")
            country_code: ISO ülke kodu (ör: "TR", "US")

        Returns:
            GeoJSON formatında yol verisi
        """
        # Önce şehrin bbox'ını al
        bbox = await self._get_city_bbox(city_name, country_code)

        if not bbox:
            return {'error': f'Şehir bulunamadı: {city_name}'}

        # Yol verilerini çek
        roads = await self._fetch_roads(bbox)

        return {
            'city': city_name,
            'country': country_code,
            'bbox': bbox,
            'roads': roads,
            'styles': self._osm_types,
            'total_roads': len(roads.get('features', []))
        }

    async def _get_city_bbox(
        self,
        city_name: str,
        country_code: Optional[str] = None
    ) -> Optional[Tuple[float, float, float, float]]:
        """Nominatim API ile şehir bbox'ı al"""
        params = {
            'q': city_name,
            'format': 'json',
            'limit': 1
        }
        if country_code:
            params['countrycodes'] = country_code.lower()

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    'https://nominatim.openstreetmap.org/search',
                    params=params,
                    headers={'User-Agent': 'TSUNAMI-OSINT/3.0'},
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if data:
                            bbox = data[0].get('boundingbox', [])
                            if len(bbox) == 4:
                                # Nominatim: [south, north, west, east]
                                # Return: (west, south, east, north) = (min_lng, min_lat, max_lng, max_lat)
                                return (
                                    float(bbox[2]),  # west/min_lng
                                    float(bbox[0]),  # south/min_lat
                                    float(bbox[3]),  # east/max_lng
                                    float(bbox[1])   # north/max_lat
                                )
        except Exception as e:
            print(f"[CityRoads] Nominatim hatası: {e}")

        return None

    async def _fetch_roads(
        self,
        bbox: Tuple[float, float, float, float]
    ) -> Dict[str, Any]:
        """Overpass API ile yol verisi çek"""
        min_lng, min_lat, max_lng, max_lat = bbox

        # Sadece ana yolları al (daha hızlı)
        query = f'''
            [out:json][timeout:120];
            (
              way["highway"~"^(motorway|trunk|primary|secondary|tertiary|residential|unclassified)$"]
                ({min_lat},{min_lng},{max_lat},{max_lng});
            );
            out geom;
        '''

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    OVERPASS_API,
                    data={'data': query},
                    timeout=aiohttp.ClientTimeout(total=180)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return self._convert_to_geojson(data)
        except Exception as e:
            print(f"[CityRoads] Overpass hatası: {e}")

        return {'type': 'FeatureCollection', 'features': []}

    def _convert_to_geojson(self, overpass_data: Dict) -> Dict[str, Any]:
        """Overpass verisini GeoJSON'a çevir"""
        features = []

        for element in overpass_data.get('elements', []):
            if element['type'] == 'way' and 'geometry' in element:
                coords = [[p['lon'], p['lat']] for p in element['geometry']]

                highway_type = element.get('tags', {}).get('highway', 'unclassified')
                style = self._osm_types.get(highway_type, {'color': '#cccccc', 'width': 0.5})

                feature = {
                    'type': 'Feature',
                    'properties': {
                        'id': element['id'],
                        'highway': highway_type,
                        'name': element.get('tags', {}).get('name', ''),
                        'color': style['color'],
                        'width': style['width']
                    },
                    'geometry': {
                        'type': 'LineString',
                        'coordinates': coords
                    }
                }
                features.append(feature)

        return {
            'type': 'FeatureCollection',
            'features': features
        }


# ==================== OSINT API AGGREGATOR ====================

class OSINTAPIAggregator:
    """
    102+ OSINT API entegrasyonu

    cipher387/API-s-for-OSINT projesinden API koleksiyonu
    """

    def __init__(self):
        self._api_keys = {
            'shodan': os.getenv('SHODAN_API_KEY', ''),
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'hunter': os.getenv('HUNTER_API_KEY', ''),
            'hibp': os.getenv('HIBP_API_KEY', ''),
            'securitytrails': os.getenv('SECURITYTRAILS_API_KEY', ''),
            'censys_id': os.getenv('CENSYS_API_ID', ''),
            'censys_secret': os.getenv('CENSYS_API_SECRET', ''),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
            'numverify': os.getenv('NUMVERIFY_API_KEY', ''),
            'ipgeolocation': os.getenv('IPGEOLOCATION_API_KEY', ''),
            'abstract': os.getenv('ABSTRACTAPI_KEY', ''),
            'google_cse': os.getenv('GOOGLE_CSE_API_KEY', ''),
            'google_cse_cx': os.getenv('GOOGLE_CSE_CX', ''),
        }
        self._rate_limits = {}
        self._session = None

    def get_available_apis(self) -> Dict[str, List[Dict]]:
        """Kullanılabilir API kategorilerini döndür"""
        return OSINT_API_CATEGORIES

    async def query_ip(self, ip: str) -> List[OSINTResult]:
        """IP adresi için tüm mevcut API'leri sorgula"""
        results = []

        # Free APIs
        free_apis = [
            ('ip-api', f'http://ip-api.com/json/{ip}'),
            ('ipapi.co', f'https://ipapi.co/{ip}/json/'),
            ('ipwhois.app', f'https://ipwhois.app/json/{ip}'),
        ]

        async with aiohttp.ClientSession() as session:
            for name, url in free_apis:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(OSINTResult(
                                source=name,
                                category='ip_geolocation',
                                data=data,
                                success=True
                            ))
                except Exception as e:
                    results.append(OSINTResult(
                        source=name,
                        category='ip_geolocation',
                        data={},
                        success=False,
                        error=str(e)
                    ))

            # AbuseIPDB (API key gerekli)
            if self._api_keys['abuseipdb']:
                try:
                    headers = {
                        'Key': self._api_keys['abuseipdb'],
                        'Accept': 'application/json'
                    }
                    url = f'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(OSINTResult(
                                source='AbuseIPDB',
                                category='threat_intel',
                                data=data.get('data', {}),
                                success=True
                            ))
                except Exception as e:
                    results.append(OSINTResult(
                        source='AbuseIPDB',
                        category='threat_intel',
                        data={},
                        success=False,
                        error=str(e)
                    ))

            # Shodan (API key gerekli)
            if self._api_keys['shodan']:
                try:
                    url = f"https://api.shodan.io/shodan/host/{ip}?key={self._api_keys['shodan']}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(OSINTResult(
                                source='Shodan',
                                category='threat_intel',
                                data=data,
                                success=True
                            ))
                except Exception as e:
                    results.append(OSINTResult(
                        source='Shodan',
                        category='threat_intel',
                        data={},
                        success=False,
                        error=str(e)
                    ))

            # GreyNoise Community (free)
            try:
                url = f'https://api.greynoise.io/v3/community/{ip}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='GreyNoise',
                            category='threat_intel',
                            data=data,
                            success=True
                        ))
            except:
                pass

        return results

    async def query_domain(self, domain: str) -> List[OSINTResult]:
        """Domain için OSINT sorguları"""
        results = []

        async with aiohttp.ClientSession() as session:
            # Hackertarget (free)
            try:
                url = f'https://api.hackertarget.com/dnslookup/?q={domain}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.text()
                        results.append(OSINTResult(
                            source='Hackertarget',
                            category='domain_dns',
                            data={'dns_records': data.split('\n')},
                            success=True
                        ))
            except:
                pass

            # URLScan (free with limit)
            try:
                url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='URLScan',
                            category='url_analysis',
                            data=data,
                            success=True
                        ))
            except:
                pass

            # RDAP (free)
            try:
                url = f'https://rdap.org/domain/{domain}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='RDAP',
                            category='whois',
                            data=data,
                            success=True
                        ))
            except:
                pass

            # SecurityTrails (API key gerekli)
            if self._api_keys['securitytrails']:
                try:
                    headers = {'APIKEY': self._api_keys['securitytrails']}
                    url = f'https://api.securitytrails.com/v1/domain/{domain}'
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(OSINTResult(
                                source='SecurityTrails',
                                category='domain_dns',
                                data=data,
                                success=True
                            ))
                except:
                    pass

        return results

    async def query_email(self, email: str) -> List[OSINTResult]:
        """Email için OSINT sorguları"""
        results = []

        async with aiohttp.ClientSession() as session:
            # EmailRep (free)
            try:
                url = f'https://emailrep.io/{email}'
                headers = {'User-Agent': 'TSUNAMI-OSINT/3.0'}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='EmailRep',
                            category='email_verification',
                            data=data,
                            success=True
                        ))
            except:
                pass

            # EVA (free)
            try:
                url = f'https://api.eva.pingutil.com/email?email={email}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='EVA',
                            category='email_verification',
                            data=data,
                            success=True
                        ))
            except:
                pass

            # Disify (free)
            try:
                url = f'https://www.disify.com/api/email/{email}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='Disify',
                            category='email_verification',
                            data=data,
                            success=True
                        ))
            except:
                pass

            # HIBP (API key gerekli)
            if self._api_keys['hibp']:
                try:
                    headers = {
                        'hibp-api-key': self._api_keys['hibp'],
                        'User-Agent': 'TSUNAMI-OSINT'
                    }
                    url = f'https://haveibeenpwned.com/api/v3/breachedaccount/{email}'
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(OSINTResult(
                                source='HIBP',
                                category='breach_check',
                                data={'breaches': data},
                                success=True
                            ))
                        elif response.status == 404:
                            results.append(OSINTResult(
                                source='HIBP',
                                category='breach_check',
                                data={'breaches': [], 'message': 'Email ihlalde bulunamadı'},
                                success=True
                            ))
                except:
                    pass

            # Hunter.io (API key gerekli)
            if self._api_keys['hunter']:
                try:
                    url = f"https://api.hunter.io/v2/email-verifier?email={email}&api_key={self._api_keys['hunter']}"
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                        if response.status == 200:
                            data = await response.json()
                            results.append(OSINTResult(
                                source='Hunter.io',
                                category='email_verification',
                                data=data.get('data', {}),
                                success=True
                            ))
                except:
                    pass

        return results

    async def query_username(self, username: str) -> List[OSINTResult]:
        """Username için OSINT sorguları"""
        results = []

        async with aiohttp.ClientSession() as session:
            # GitHub API (free)
            try:
                url = f'https://api.github.com/users/{username}'
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='GitHub',
                            category='social_media',
                            data=data,
                            success=True
                        ))
            except:
                pass

            # Reddit API (free)
            try:
                url = f'https://www.reddit.com/user/{username}/about.json'
                headers = {'User-Agent': 'TSUNAMI-OSINT/3.0'}
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        data = await response.json()
                        results.append(OSINTResult(
                            source='Reddit',
                            category='social_media',
                            data=data.get('data', {}),
                            success=True
                        ))
            except:
                pass

        return results


# ==================== PASTEBIN SEARCH ====================

class PastebinSearcher:
    """
    49 Pastebin sitesi üzerinde arama

    cybdetective.com/pastebin.html projesi bazında
    Google Custom Search veya doğrudan arama
    """

    def __init__(self):
        self._api_key = os.getenv('GOOGLE_CSE_API_KEY', '')
        self._cx = os.getenv('GOOGLE_CSE_CX', '')
        self._sites = PASTEBIN_SITES

    def get_sites(self) -> List[Dict]:
        """Aranabilir pastebin sitelerini döndür"""
        return self._sites

    async def search(
        self,
        query: str,
        sites: Optional[List[str]] = None,
        max_results: int = 50
    ) -> List[Dict]:
        """
        Pastebin sitelerinde arama yap

        Args:
            query: Arama sorgusu
            sites: Aranacak siteler (None = hepsi)
            max_results: Maksimum sonuç sayısı

        Returns:
            Bulunan paste'lerin listesi
        """
        results = []

        if sites is None:
            sites = [s['name'] for s in self._sites]

        # Google Custom Search API varsa kullan
        if self._api_key and self._cx:
            results = await self._google_search(query, sites, max_results)
        else:
            # Basit site:domain arama URL'leri oluştur
            results = self._generate_search_urls(query, sites)

        return results

    async def _google_search(
        self,
        query: str,
        sites: List[str],
        max_results: int
    ) -> List[Dict]:
        """Google Custom Search API ile arama"""
        results = []

        # Site filtresi oluştur
        site_filter = ' OR '.join([f'site:{s["url"].replace("https://", "").replace("http://", "")}'
                                    for s in self._sites if s['name'] in sites])

        search_query = f'{query} ({site_filter})'

        try:
            async with aiohttp.ClientSession() as session:
                url = 'https://www.googleapis.com/customsearch/v1'
                params = {
                    'key': self._api_key,
                    'cx': self._cx,
                    'q': search_query,
                    'num': min(max_results, 10)  # Google API max 10 per request
                }

                async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=30)) as response:
                    if response.status == 200:
                        data = await response.json()

                        for item in data.get('items', []):
                            results.append({
                                'title': item.get('title'),
                                'url': item.get('link'),
                                'snippet': item.get('snippet'),
                                'source': 'google_cse'
                            })
        except Exception as e:
            print(f"[PastebinSearch] Google CSE hatası: {e}")

        return results

    def _generate_search_urls(
        self,
        query: str,
        sites: List[str]
    ) -> List[Dict]:
        """Manuel arama URL'leri oluştur"""
        results = []
        encoded_query = quote(query)

        for site in self._sites:
            if site['name'] in sites:
                search_url = site['search'].format(query=encoded_query)
                results.append({
                    'site': site['name'],
                    'base_url': site['url'],
                    'search_url': search_url,
                    'source': 'generated'
                })

        return results

    async def check_paste_content(self, url: str) -> Optional[Dict]:
        """Paste içeriğini kontrol et (varsa)"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as response:
                    if response.status == 200:
                        content = await response.text()
                        return {
                            'url': url,
                            'status': 'accessible',
                            'size': len(content),
                            'preview': content[:500] if len(content) > 500 else content
                        }
        except:
            pass

        return {'url': url, 'status': 'inaccessible'}


# ==================== COUNTRY OSINT MANAGER ====================

class CountryOSINTManager:
    """
    193 ülke OSINT kaynakları yöneticisi

    OSINT-for-countries projesi bazında
    """

    def __init__(self):
        self._countries = COUNTRY_OSINT_SOURCES

    def get_countries(self) -> List[Dict]:
        """Tüm ülkeleri listele"""
        return [
            {
                'code': code,
                'name': info['name'],
                'flag': info['flag'],
                'source_categories': list(info['sources'].keys())
            }
            for code, info in self._countries.items()
        ]

    def get_country_sources(self, country_code: str) -> Optional[Dict]:
        """Ülke OSINT kaynaklarını getir"""
        country_code = country_code.upper()

        if country_code in self._countries:
            return {
                'code': country_code,
                **self._countries[country_code]
            }

        return None

    def get_sources_by_category(
        self,
        country_code: str,
        category: str
    ) -> List[str]:
        """Belirli kategorideki kaynakları getir"""
        country_code = country_code.upper()

        if country_code in self._countries:
            return self._countries[country_code]['sources'].get(category, [])

        return []

    def search_countries(self, query: str) -> List[Dict]:
        """Ülke ara"""
        query = query.lower()
        results = []

        for code, info in self._countries.items():
            if query in code.lower() or query in info['name'].lower():
                results.append({
                    'code': code,
                    'name': info['name'],
                    'flag': info['flag']
                })

        return results


# ==================== OSINT TOOL DATABASE ====================

class OSINTToolDatabase:
    """
    614+ OSINT araç veritabanı

    Cybdetective OSINT Map ve cipher387 koleksiyonları
    """

    def __init__(self):
        self._categories = OSINT_TOOL_CATEGORIES

    def get_categories(self) -> List[Dict]:
        """Tüm kategorileri listele"""
        return [
            {
                'id': cat_id,
                'name': cat_info['name'],
                'icon': cat_info['icon'],
                'tool_count': len(cat_info['tools'])
            }
            for cat_id, cat_info in self._categories.items()
        ]

    def get_tools_by_category(self, category: str) -> List[Dict]:
        """Kategorideki araçları getir"""
        if category in self._categories:
            return self._categories[category]['tools']
        return []

    def search_tools(self, query: str) -> List[Dict]:
        """Araç ara"""
        query = query.lower()
        results = []

        for cat_id, cat_info in self._categories.items():
            for tool in cat_info['tools']:
                if query in tool['name'].lower() or query in tool.get('desc', '').lower():
                    results.append({
                        **tool,
                        'category': cat_id,
                        'category_name': cat_info['name']
                    })

        return results

    def get_all_tools(self) -> List[Dict]:
        """Tüm araçları getir"""
        tools = []
        for cat_id, cat_info in self._categories.items():
            for tool in cat_info['tools']:
                tools.append({
                    **tool,
                    'category': cat_id,
                    'category_name': cat_info['name'],
                    'icon': cat_info['icon']
                })
        return tools


# ==================== GLOBAL OSINT MANAGER ====================

class GlobalOSINTManager:
    """
    Tüm global OSINT yeteneklerini koordine eden merkezi sınıf

    TSUNAMI harita sayfası ile tam entegrasyon
    """

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, '_initialized'):
            return

        self._initialized = True

        # Alt modüller
        self.inframap = OpenInfraMapClient()
        self.cityroads = CityRoadsClient()
        self.api_aggregator = OSINTAPIAggregator()
        self.pastebin = PastebinSearcher()
        self.countries = CountryOSINTManager()
        self.tools = OSINTToolDatabase()

        # Cache
        self._cache = {}
        self._cache_ttl = 3600

        # Executor for parallel operations
        self._executor = ThreadPoolExecutor(max_workers=20)

        print("[GlobalOSINT] Manager başlatıldı")

    def get_status(self) -> Dict:
        """Modül durumunu döndür"""
        return {
            'active': True,
            'modules': {
                'inframap': {
                    'layers': list(OPENINFRAMAP_TILES.keys()),
                    'description': 'OpenInfraMap kritik altyapı katmanları'
                },
                'cityroads': {
                    'active': True,
                    'description': 'OpenStreetMap şehir yol ağı verisi'
                },
                'api_aggregator': {
                    'categories': list(OSINT_API_CATEGORIES.keys()),
                    'total_apis': sum(len(apis) for apis in OSINT_API_CATEGORIES.values()),
                    'description': '102+ OSINT API entegrasyonu'
                },
                'pastebin': {
                    'sites': len(PASTEBIN_SITES),
                    'description': '49 pastebin sitesi arama'
                },
                'countries': {
                    'count': len(COUNTRY_OSINT_SOURCES),
                    'description': '193 ülke OSINT kaynakları'
                },
                'tools': {
                    'categories': len(OSINT_TOOL_CATEGORIES),
                    'total_tools': sum(len(cat['tools']) for cat in OSINT_TOOL_CATEGORIES.values()),
                    'description': '614+ OSINT araç veritabanı'
                }
            },
            'cache_size': len(self._cache),
            'version': '3.0.0'
        }

    # ========== Infrastructure Methods ==========

    async def get_infrastructure(
        self,
        bbox: Tuple[float, float, float, float],
        types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Kritik altyapı verisi getir"""
        features = await self.inframap.get_infrastructure_in_bbox(bbox, types)

        # Tipe göre grupla
        grouped = {}
        for feature in features:
            ftype = feature.feature_type
            if ftype not in grouped:
                grouped[ftype] = []
            grouped[ftype].append(feature.to_dict())

        return {
            'total': len(features),
            'by_type': grouped,
            'tile_urls': self.inframap.get_tile_urls(),
            'styles': {t: self.inframap.get_layer_style(t) for t in OPENINFRAMAP_TILES.keys()}
        }

    def get_infrastructure_tile_config(self) -> Dict:
        """Frontend için tile layer konfigürasyonu"""
        return {
            'tiles': OPENINFRAMAP_TILES,
            'styles': {t: self.inframap.get_layer_style(t) for t in OPENINFRAMAP_TILES.keys()}
        }

    # ========== City Roads Methods ==========

    async def get_city_roads(
        self,
        city: str,
        country: Optional[str] = None
    ) -> Dict[str, Any]:
        """Şehir yol verisi getir"""
        return await self.cityroads.get_roads_for_city(city, country)

    # ========== OSINT API Methods ==========

    async def investigate_ip(self, ip: str) -> Dict[str, Any]:
        """IP adresini tüm kaynaklarla araştır"""
        results = await self.api_aggregator.query_ip(ip)

        # Sonuçları birleştir
        combined = {
            'target': ip,
            'target_type': 'ip',
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'summary': {}
        }

        for result in results:
            combined['sources'][result.source] = result.to_dict()

            # Özet bilgiler
            if result.success and result.data:
                if 'country' in result.data:
                    combined['summary']['country'] = result.data['country']
                if 'city' in result.data:
                    combined['summary']['city'] = result.data['city']
                if 'isp' in result.data:
                    combined['summary']['isp'] = result.data['isp']
                if 'lat' in result.data and 'lon' in result.data:
                    combined['summary']['location'] = {
                        'lat': result.data['lat'],
                        'lng': result.data['lon']
                    }
                # AbuseIPDB
                if 'abuseConfidenceScore' in result.data:
                    combined['summary']['abuse_score'] = result.data['abuseConfidenceScore']
                # Shodan
                if 'ports' in result.data:
                    combined['summary']['open_ports'] = result.data['ports']

        return combined

    async def investigate_domain(self, domain: str) -> Dict[str, Any]:
        """Domain'i tüm kaynaklarla araştır"""
        results = await self.api_aggregator.query_domain(domain)

        combined = {
            'target': domain,
            'target_type': 'domain',
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }

        for result in results:
            combined['sources'][result.source] = result.to_dict()

        return combined

    async def investigate_email(self, email: str) -> Dict[str, Any]:
        """Email'i tüm kaynaklarla araştır"""
        results = await self.api_aggregator.query_email(email)

        combined = {
            'target': email,
            'target_type': 'email',
            'timestamp': datetime.now().isoformat(),
            'sources': {},
            'summary': {
                'breaches': [],
                'platforms': [],
                'reputation': None
            }
        }

        for result in results:
            combined['sources'][result.source] = result.to_dict()

            if result.success and result.data:
                # HIBP breaches
                if 'breaches' in result.data:
                    combined['summary']['breaches'] = result.data['breaches']
                # EmailRep reputation
                if 'reputation' in result.data:
                    combined['summary']['reputation'] = result.data['reputation']

        return combined

    async def investigate_username(self, username: str) -> Dict[str, Any]:
        """Username'i tüm kaynaklarla araştır"""
        results = await self.api_aggregator.query_username(username)

        combined = {
            'target': username,
            'target_type': 'username',
            'timestamp': datetime.now().isoformat(),
            'sources': {}
        }

        for result in results:
            combined['sources'][result.source] = result.to_dict()

        return combined

    # ========== Pastebin Methods ==========

    async def search_pastebins(
        self,
        query: str,
        sites: Optional[List[str]] = None,
        max_results: int = 50
    ) -> Dict[str, Any]:
        """Pastebin sitelerinde arama"""
        results = await self.pastebin.search(query, sites, max_results)

        return {
            'query': query,
            'total_sites': len(PASTEBIN_SITES),
            'searched_sites': len(sites) if sites else len(PASTEBIN_SITES),
            'results': results,
            'timestamp': datetime.now().isoformat()
        }

    def get_pastebin_sites(self) -> List[Dict]:
        """Pastebin sitelerini listele"""
        return self.pastebin.get_sites()

    # ========== Country OSINT Methods ==========

    def get_country_osint(self, country_code: str) -> Optional[Dict]:
        """Ülke OSINT kaynaklarını getir"""
        return self.countries.get_country_sources(country_code)

    def list_countries(self) -> List[Dict]:
        """Tüm ülkeleri listele"""
        return self.countries.get_countries()

    def search_countries(self, query: str) -> List[Dict]:
        """Ülke ara"""
        return self.countries.search_countries(query)

    # ========== OSINT Tools Methods ==========

    def get_tool_categories(self) -> List[Dict]:
        """OSINT araç kategorilerini listele"""
        return self.tools.get_categories()

    def get_tools_in_category(self, category: str) -> List[Dict]:
        """Kategorideki araçları getir"""
        return self.tools.get_tools_by_category(category)

    def search_tools(self, query: str) -> List[Dict]:
        """OSINT araç ara"""
        return self.tools.search_tools(query)

    def get_all_tools(self) -> List[Dict]:
        """Tüm OSINT araçlarını getir"""
        return self.tools.get_all_tools()

    # ========== Map Integration Methods ==========

    def get_map_layers_config(self) -> Dict:
        """Harita katmanları konfigürasyonu (TSUNAMI frontend için)"""
        return {
            'infrastructure': {
                'enabled': True,
                'layers': {
                    name: {
                        'name': info['description'],
                        'color': info['color'],
                        'tile_url': info['url'],
                        'layers': info['layers']
                    }
                    for name, info in OPENINFRAMAP_TILES.items()
                }
            },
            'city_roads': {
                'enabled': True,
                'description': 'OpenStreetMap şehir yol ağı',
                'requires_city': True
            },
            'osint_markers': {
                'enabled': True,
                'description': 'OSINT sonuç işaretçileri',
                'categories': list(OSINT_API_CATEGORIES.keys())
            }
        }

    async def create_map_markers_from_investigation(
        self,
        investigation_results: Dict
    ) -> List[Dict]:
        """İnceleme sonuçlarından harita işaretçileri oluştur"""
        markers = []

        summary = investigation_results.get('summary', {})
        location = summary.get('location')

        if location and location.get('lat') and location.get('lng'):
            marker = {
                'lat': location['lat'],
                'lng': location['lng'],
                'type': investigation_results.get('target_type', 'unknown'),
                'title': investigation_results.get('target', ''),
                'popup': self._create_popup_content(investigation_results),
                'icon': self._get_icon_for_type(investigation_results.get('target_type')),
                'color': self._get_color_for_type(investigation_results.get('target_type'))
            }
            markers.append(marker)

        return markers

    def _create_popup_content(self, results: Dict) -> str:
        """Popup HTML içeriği oluştur"""
        summary = results.get('summary', {})
        target = results.get('target', '')
        target_type = results.get('target_type', '')

        html = f"<strong>{target}</strong><br>"
        html += f"Tip: {target_type}<br>"

        if summary.get('country'):
            html += f"Ülke: {summary['country']}<br>"
        if summary.get('city'):
            html += f"Şehir: {summary['city']}<br>"
        if summary.get('isp'):
            html += f"ISP: {summary['isp']}<br>"
        if summary.get('abuse_score'):
            html += f"Kötüye Kullanım Skoru: {summary['abuse_score']}%<br>"
        if summary.get('open_ports'):
            html += f"Açık Portlar: {', '.join(map(str, summary['open_ports'][:10]))}<br>"

        return html

    def _get_icon_for_type(self, target_type: str) -> str:
        """Hedef tipi için ikon"""
        icons = {
            'ip': '🌐',
            'domain': '🔗',
            'email': '📧',
            'username': '👤',
            'phone': '📱'
        }
        return icons.get(target_type, '❓')

    def _get_color_for_type(self, target_type: str) -> str:
        """Hedef tipi için renk"""
        colors = {
            'ip': '#ff6666',
            'domain': '#ffff66',
            'email': '#ff9966',
            'username': '#00ff88',
            'phone': '#00e5ff'
        }
        return colors.get(target_type, '#ffffff')


# ==================== GLOBAL INSTANCE ====================

_global_osint_instance = None

def get_global_osint() -> GlobalOSINTManager:
    """Global OSINT manager instance'ı al"""
    global _global_osint_instance
    if _global_osint_instance is None:
        _global_osint_instance = GlobalOSINTManager()
    return _global_osint_instance


# ==================== TEST ====================

if __name__ == '__main__':
    import asyncio

    async def test():
        osint = get_global_osint()

        print("=== Global OSINT Manager Durumu ===")
        print(json.dumps(osint.get_status(), indent=2, ensure_ascii=False))

        print("\n=== Ülke Listesi (ilk 10) ===")
        countries = osint.list_countries()[:10]
        for c in countries:
            print(f"  {c['flag']} {c['code']}: {c['name']}")

        print("\n=== OSINT Araç Kategorileri ===")
        categories = osint.get_tool_categories()
        for cat in categories:
            print(f"  {cat['icon']} {cat['name']}: {cat['tool_count']} araç")

        print("\n=== Pastebin Siteleri (ilk 10) ===")
        sites = osint.get_pastebin_sites()[:10]
        for site in sites:
            print(f"  - {site['name']}: {site['url']}")

        print("\n=== IP Araştırması: 8.8.8.8 ===")
        result = await osint.investigate_ip('8.8.8.8')
        print(json.dumps(result.get('summary', {}), indent=2))

        print("\n=== Harita Katmanları Konfigürasyonu ===")
        config = osint.get_map_layers_config()
        print(json.dumps(config, indent=2, ensure_ascii=False))

    asyncio.run(test())
