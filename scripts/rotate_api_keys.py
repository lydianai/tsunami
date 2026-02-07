#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
TSUNAMI API Key Rotation Script
================================

Bu script .env dosyasındaki API anahtarlarını güvenli bir şekilde yönetir.
Mevcut anahtarları yedekler ve yeni anahtarlar için rehberlik sağlar.

Kullanım:
    python scripts/rotate_api_keys.py --backup     # Mevcut anahtarları yedekle
    python scripts/rotate_api_keys.py --check      # Anahtar güvenliğini kontrol et
    python scripts/rotate_api_keys.py --rotate     # Rotasyon rehberi göster

AILYDIAN AutoFix - Security Enhancement
"""

import os
import sys
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import shutil

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
ENV_BACKUP_DIR = PROJECT_ROOT / ".env_backups"
VAULT_FILE = PROJECT_ROOT / "data" / ".vault" / "secrets.vault"


def load_env_file() -> Dict[str, str]:
    """Load environment variables from .env file"""
    env_vars = {}
    if ENV_FILE.exists():
        with open(ENV_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    env_vars[key.strip()] = value.strip()
    return env_vars


def backup_env_file() -> Optional[Path]:
    """Create timestamped backup of .env file"""
    if not ENV_FILE.exists():
        print("[!] .env dosyası bulunamadı")
        return None

    ENV_BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_path = ENV_BACKUP_DIR / f".env.backup_{timestamp}"

    shutil.copy2(ENV_FILE, backup_path)
    os.chmod(backup_path, 0o600)

    print(f"[+] Yedek oluşturuldu: {backup_path}")
    return backup_path


def check_key_security(env_vars: Dict[str, str]) -> List[Dict]:
    """Check security of API keys"""
    issues = []

    # Known sensitive keys
    sensitive_keys = [
        'SHODAN_API_KEY',
        'OPENCELLID_API_KEY',
        'N2YO_API_KEY',
        'VIRUSTOTAL_API_KEY',
        'ABUSEIPDB_API_KEY',
        'GOOGLE_MAPS_API_KEY',
        'SECRET_KEY',
        'DATABASE_URL',
        'REDIS_URL',
    ]

    for key in sensitive_keys:
        if key in env_vars:
            value = env_vars[key]

            # Check for weak/default values
            if len(value) < 16:
                issues.append({
                    'key': key,
                    'issue': 'Anahtar çok kısa (<16 karakter)',
                    'severity': 'HIGH'
                })

            # Check for common patterns
            if value.lower() in ['test', 'demo', 'example', 'changeme', 'password']:
                issues.append({
                    'key': key,
                    'issue': 'Varsayılan/test değeri kullanılıyor',
                    'severity': 'CRITICAL'
                })

            # Check if key looks like a real key (has mix of chars)
            has_upper = any(c.isupper() for c in value)
            has_lower = any(c.islower() for c in value)
            has_digit = any(c.isdigit() for c in value)

            if not (has_upper and has_lower and has_digit):
                issues.append({
                    'key': key,
                    'issue': 'Anahtar karmaşıklığı düşük',
                    'severity': 'MEDIUM'
                })

    return issues


def show_rotation_guide():
    """Show API key rotation guide"""
    guide = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    TSUNAMI API KEY ROTATION REHBERİ                          ║
╠══════════════════════════════════════════════════════════════════════════════╣

1. SHODAN API KEY
   ├─ Portal: https://account.shodan.io/
   ├─ Adım: Account → API Key → Generate New Key
   └─ Not: Eski anahtar hemen geçersiz olur

2. OPENCELLID API KEY
   ├─ Portal: https://opencellid.org/
   ├─ Adım: My Account → API Access → Request New Token
   └─ Not: Günlük istek limiti var

3. N2YO API KEY
   ├─ Portal: https://www.n2yo.com/api/
   ├─ Adım: Sign In → My Account → Generate New Key
   └─ Not: Ücretsiz hesapta günlük limit

4. VIRUSTOTAL API KEY
   ├─ Portal: https://www.virustotal.com/gui/my-apikey
   ├─ Adım: API Key → Request New Key
   └─ Not: Public API günlük 500 istek

5. ABUSEIPDB API KEY
   ├─ Portal: https://www.abuseipdb.com/account/api
   ├─ Adım: API → Manage Keys → Create New Key
   └─ Not: Ücretsiz günlük 1000 istek

╠══════════════════════════════════════════════════════════════════════════════╣
║                           ÖNERİLEN ADIMLAR                                   ║
╠══════════════════════════════════════════════════════════════════════════════╣

1. Önce mevcut .env dosyasını yedekleyin:
   python scripts/rotate_api_keys.py --backup

2. Her servis için yeni anahtar oluşturun (yukarıdaki portallarda)

3. .env dosyasını güncelleyin:
   nano .env

4. Uygulamayı yeniden başlatın:
   sudo systemctl restart tsunami

5. Eski anahtarları ilgili servislerde iptal edin

╠══════════════════════════════════════════════════════════════════════════════╣
║                        GÜVENLİK ÖNERİLERİ                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣

• API anahtarlarını asla git'e commit etmeyin
• .env dosyası .gitignore'da olmalı
• Production'da environment variables veya secret manager kullanın
• Düzenli olarak (3 ayda bir) anahtarları rotate edin
• Her anahtar için ayrı scope/permission belirleyin

╚══════════════════════════════════════════════════════════════════════════════╝
"""
    print(guide)


def migrate_to_vault():
    """Migrate .env keys to TSUNAMI Vault (recommended)"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║              .ENV → TSUNAMI VAULT MİGRASYONU                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣

TSUNAMI Vault, API anahtarlarını şifrelenmiş formatta saklar.

Migrasyon için:

1. dalga_vault.py kullanarak anahtarları import edin:

   from dalga_vault import vault_al
   vault = vault_al()

   # Her anahtar için:
   vault.secret_ekle('SHODAN_API_KEY', 'yeni_anahtar_değeri')
   vault.secret_ekle('OPENCELLID_API_KEY', 'yeni_anahtar_değeri')

2. .env dosyasından anahtarları kaldırın

3. Uygulama otomatik olarak Vault'tan okuyacak

╚══════════════════════════════════════════════════════════════════════════════╝
""")


def main():
    parser = argparse.ArgumentParser(
        description='TSUNAMI API Key Rotation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--backup', action='store_true',
                        help='Mevcut .env dosyasını yedekle')
    parser.add_argument('--check', action='store_true',
                        help='API anahtarı güvenliğini kontrol et')
    parser.add_argument('--rotate', action='store_true',
                        help='Rotasyon rehberini göster')
    parser.add_argument('--migrate', action='store_true',
                        help='Vault migrasyon rehberini göster')

    args = parser.parse_args()

    if args.backup:
        backup_env_file()

    elif args.check:
        env_vars = load_env_file()
        if not env_vars:
            print("[!] .env dosyası boş veya bulunamadı")
            sys.exit(1)

        issues = check_key_security(env_vars)

        if issues:
            print("\n" + "=" * 60)
            print("GÜVENLİK SORUNLARI TESPİT EDİLDİ")
            print("=" * 60 + "\n")

            for issue in issues:
                severity_color = {
                    'CRITICAL': '\033[91m',  # Red
                    'HIGH': '\033[93m',      # Yellow
                    'MEDIUM': '\033[94m',    # Blue
                }.get(issue['severity'], '')
                reset = '\033[0m'

                print(f"{severity_color}[{issue['severity']}]{reset} {issue['key']}")
                print(f"    └─ {issue['issue']}\n")

            print(f"Toplam: {len(issues)} sorun bulundu")
            print("\nRotasyon rehberi için: python scripts/rotate_api_keys.py --rotate")
        else:
            print("[+] Tüm anahtarlar güvenli görünüyor")

    elif args.rotate:
        show_rotation_guide()

    elif args.migrate:
        migrate_to_vault()

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
