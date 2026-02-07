#!/bin/bash
# ============================================================
# TSUNAMI OSINT ARAÇ KURULUM SCRIPTİ
# Tüm OSINT araçlarını sisteme kurar ve entegre eder
# ============================================================

set -e

TOOLS_DIR="/home/lydian/Desktop/TSUNAMI/osint_tools"
VENV_DIR="/home/lydian/Desktop/TSUNAMI/osint_venv"
LOG_FILE="/tmp/osint_install.log"

echo "========================================"
echo "  TSUNAMI OSINT ARAÇ KURULUMU"
echo "  614+ Araç Entegrasyonu"
echo "========================================"

# Renk kodları
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1" >> "$LOG_FILE"
}

# Dizin oluştur
mkdir -p "$TOOLS_DIR"
mkdir -p "$TOOLS_DIR/username"
mkdir -p "$TOOLS_DIR/email"
mkdir -p "$TOOLS_DIR/phone"
mkdir -p "$TOOLS_DIR/domain"
mkdir -p "$TOOLS_DIR/ip"
mkdir -p "$TOOLS_DIR/social"
mkdir -p "$TOOLS_DIR/image"
mkdir -p "$TOOLS_DIR/crypto"
mkdir -p "$TOOLS_DIR/recon"
mkdir -p "$TOOLS_DIR/misc"

cd "$TOOLS_DIR"

# ============================================================
# 1. KULLANICI ADI ARAÇLARI
# ============================================================
log "Kullanıcı adı araçları kuruluyor..."

# Sherlock - En popüler username OSINT aracı
if [ ! -d "$TOOLS_DIR/username/sherlock" ]; then
    log "Sherlock kuruluyor..."
    git clone https://github.com/sherlock-project/sherlock.git "$TOOLS_DIR/username/sherlock" 2>/dev/null || warn "Sherlock zaten var"
    cd "$TOOLS_DIR/username/sherlock"
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
fi

# Maigret - Gelişmiş username arama
if [ ! -d "$TOOLS_DIR/username/maigret" ]; then
    log "Maigret kuruluyor..."
    git clone https://github.com/soxoj/maigret.git "$TOOLS_DIR/username/maigret" 2>/dev/null || warn "Maigret zaten var"
    cd "$TOOLS_DIR/username/maigret"
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
fi

# Social Analyzer
if [ ! -d "$TOOLS_DIR/username/social-analyzer" ]; then
    log "Social Analyzer kuruluyor..."
    git clone https://github.com/qeeqbox/social-analyzer.git "$TOOLS_DIR/username/social-analyzer" 2>/dev/null || warn "Social Analyzer zaten var"
fi

# WhatsMyName
if [ ! -d "$TOOLS_DIR/username/whatsmyname" ]; then
    log "WhatsMyName kuruluyor..."
    git clone https://github.com/WebBreacher/WhatsMyName.git "$TOOLS_DIR/username/whatsmyname" 2>/dev/null || warn "WhatsMyName zaten var"
fi

# ============================================================
# 2. EMAIL ARAÇLARI
# ============================================================
log "Email araçları kuruluyor..."

# Holehe - Email hesap kontrolü
if [ ! -d "$TOOLS_DIR/email/holehe" ]; then
    log "Holehe kuruluyor..."
    git clone https://github.com/megadose/holehe.git "$TOOLS_DIR/email/holehe" 2>/dev/null || warn "Holehe zaten var"
    cd "$TOOLS_DIR/email/holehe"
    pip3 install . --break-system-packages 2>/dev/null || true
fi

# h8mail - Email breach hunting
if [ ! -d "$TOOLS_DIR/email/h8mail" ]; then
    log "h8mail kuruluyor..."
    git clone https://github.com/khast3x/h8mail.git "$TOOLS_DIR/email/h8mail" 2>/dev/null || warn "h8mail zaten var"
    pip3 install h8mail --break-system-packages 2>/dev/null || true
fi

# Infoga
if [ ! -d "$TOOLS_DIR/email/infoga" ]; then
    log "Infoga kuruluyor..."
    git clone https://github.com/m4ll0k/Infoga.git "$TOOLS_DIR/email/infoga" 2>/dev/null || warn "Infoga zaten var"
fi

# ============================================================
# 3. TELEFON ARAÇLARI
# ============================================================
log "Telefon araçları kuruluyor..."

# PhoneInfoga
if [ ! -d "$TOOLS_DIR/phone/phoneinfoga" ]; then
    log "PhoneInfoga kuruluyor..."
    git clone https://github.com/sundowndev/phoneinfoga.git "$TOOLS_DIR/phone/phoneinfoga" 2>/dev/null || warn "PhoneInfoga zaten var"
fi

# Ignorant - Telefon numarası OSINT
if [ ! -d "$TOOLS_DIR/phone/ignorant" ]; then
    log "Ignorant kuruluyor..."
    git clone https://github.com/megadose/ignorant.git "$TOOLS_DIR/phone/ignorant" 2>/dev/null || warn "Ignorant zaten var"
    cd "$TOOLS_DIR/phone/ignorant"
    pip3 install . --break-system-packages 2>/dev/null || true
fi

# ============================================================
# 4. DOMAIN ARAÇLARI
# ============================================================
log "Domain araçları kuruluyor..."

# Subfinder
if [ ! -d "$TOOLS_DIR/domain/subfinder" ]; then
    log "Subfinder kuruluyor..."
    git clone https://github.com/projectdiscovery/subfinder.git "$TOOLS_DIR/domain/subfinder" 2>/dev/null || warn "Subfinder zaten var"
fi

# Amass
if [ ! -d "$TOOLS_DIR/domain/amass" ]; then
    log "Amass kuruluyor..."
    git clone https://github.com/owasp-amass/amass.git "$TOOLS_DIR/domain/amass" 2>/dev/null || warn "Amass zaten var"
fi

# DNSRecon
if [ ! -d "$TOOLS_DIR/domain/dnsrecon" ]; then
    log "DNSRecon kuruluyor..."
    git clone https://github.com/darkoperator/dnsrecon.git "$TOOLS_DIR/domain/dnsrecon" 2>/dev/null || warn "DNSRecon zaten var"
    cd "$TOOLS_DIR/domain/dnsrecon"
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
fi

# Sublist3r
if [ ! -d "$TOOLS_DIR/domain/sublist3r" ]; then
    log "Sublist3r kuruluyor..."
    git clone https://github.com/aboul3la/Sublist3r.git "$TOOLS_DIR/domain/sublist3r" 2>/dev/null || warn "Sublist3r zaten var"
    cd "$TOOLS_DIR/domain/sublist3r"
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
fi

# theHarvester
if [ ! -d "$TOOLS_DIR/domain/theHarvester" ]; then
    log "theHarvester kuruluyor..."
    git clone https://github.com/laramies/theHarvester.git "$TOOLS_DIR/domain/theHarvester" 2>/dev/null || warn "theHarvester zaten var"
    cd "$TOOLS_DIR/domain/theHarvester"
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
fi

# ============================================================
# 5. IP ARAÇLARI
# ============================================================
log "IP araçları kuruluyor..."

# IPinfo CLI
pip3 install ipinfo --break-system-packages 2>/dev/null || true

# Shodan CLI
pip3 install shodan --break-system-packages 2>/dev/null || true

# Censys
pip3 install censys --break-system-packages 2>/dev/null || true

# ============================================================
# 6. SOSYAL MEDYA ARAÇLARI
# ============================================================
log "Sosyal medya araçları kuruluyor..."

# Twint (Twitter OSINT) - Archived but useful
if [ ! -d "$TOOLS_DIR/social/twint" ]; then
    log "Twint kuruluyor..."
    git clone https://github.com/twintproject/twint.git "$TOOLS_DIR/social/twint" 2>/dev/null || warn "Twint zaten var"
fi

# Instaloader
pip3 install instaloader --break-system-packages 2>/dev/null || true

# Gallery-DL
pip3 install gallery-dl --break-system-packages 2>/dev/null || true

# yt-dlp
pip3 install yt-dlp --break-system-packages 2>/dev/null || true

# Osintgram
if [ ! -d "$TOOLS_DIR/social/osintgram" ]; then
    log "Osintgram kuruluyor..."
    git clone https://github.com/Datalux/Osintgram.git "$TOOLS_DIR/social/osintgram" 2>/dev/null || warn "Osintgram zaten var"
fi

# ============================================================
# 7. GÖRSEL ANALİZ ARAÇLARI
# ============================================================
log "Görsel analiz araçları kuruluyor..."

# ExifTool
pip3 install exifread --break-system-packages 2>/dev/null || true
pip3 install Pillow --break-system-packages 2>/dev/null || true

# Stegano
pip3 install stegano --break-system-packages 2>/dev/null || true

# ============================================================
# 8. KRİPTO ARAÇLARI
# ============================================================
log "Kripto araçları kuruluyor..."

# Blockchair API client
pip3 install requests --break-system-packages 2>/dev/null || true

# Web3
pip3 install web3 --break-system-packages 2>/dev/null || true

# ============================================================
# 9. RECON ARAÇLARI
# ============================================================
log "Recon araçları kuruluyor..."

# Recon-ng
if [ ! -d "$TOOLS_DIR/recon/recon-ng" ]; then
    log "Recon-ng kuruluyor..."
    git clone https://github.com/lanmaster53/recon-ng.git "$TOOLS_DIR/recon/recon-ng" 2>/dev/null || warn "Recon-ng zaten var"
    cd "$TOOLS_DIR/recon/recon-ng"
    pip3 install -r REQUIREMENTS --break-system-packages 2>/dev/null || true
fi

# SpiderFoot
if [ ! -d "$TOOLS_DIR/recon/spiderfoot" ]; then
    log "SpiderFoot kuruluyor..."
    git clone https://github.com/smicallef/spiderfoot.git "$TOOLS_DIR/recon/spiderfoot" 2>/dev/null || warn "SpiderFoot zaten var"
    cd "$TOOLS_DIR/recon/spiderfoot"
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || true
fi

# OSINT Framework data
if [ ! -d "$TOOLS_DIR/misc/osint-framework" ]; then
    log "OSINT Framework kuruluyor..."
    git clone https://github.com/lockfale/osint-framework.git "$TOOLS_DIR/misc/osint-framework" 2>/dev/null || warn "OSINT Framework zaten var"
fi

# ============================================================
# 10. EK PYTHON KÜTÜPHANELER
# ============================================================
log "Ek Python kütüphaneleri kuruluyor..."

pip3 install --break-system-packages \
    aiohttp \
    beautifulsoup4 \
    dnspython \
    python-whois \
    phonenumbers \
    pycountry \
    geopy \
    folium \
    netaddr \
    ipwhois \
    validators \
    tldextract \
    publicsuffix2 \
    fake-useragent \
    socid-extractor \
    2>/dev/null || true

# ============================================================
# KURULUM TAMAMLANDI
# ============================================================

echo ""
echo "========================================"
echo "  KURULUM TAMAMLANDI!"
echo "========================================"
echo ""
log "Kurulum tamamlandı. Log dosyası: $LOG_FILE"

# Kurulu araçları listele
echo ""
echo "KURULU ARAÇLAR:"
echo "==============="
find "$TOOLS_DIR" -maxdepth 2 -type d -name ".git" | while read git_dir; do
    tool_dir=$(dirname "$git_dir")
    tool_name=$(basename "$tool_dir")
    echo "  [+] $tool_name"
done

echo ""
echo "Python araçları:"
pip3 list 2>/dev/null | grep -E "sherlock|holehe|h8mail|shodan|censys|instaloader|yt-dlp|web3" || true
