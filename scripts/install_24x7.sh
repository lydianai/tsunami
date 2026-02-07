#!/bin/bash
# ==============================================================================
# TSUNAMI 24/7 KORUMA KURULUM SCRIPTI
# ==============================================================================
# Bu script TSUNAMI Defender ve Network Guardian servislerini kurar
# ve sisteminizi 7/24 koruma altina alir.
#
# KULLANIM:
#   chmod +x install_24x7.sh
#   sudo ./install_24x7.sh
#
# NOTLAR:
#   - Root yetkisi gerektirir (tam koruma icin)
#   - Ubuntu/Debian sistemleri icin optimize edilmis
#   - Kurulum sonrasi servisler otomatik baslar
#
# ==============================================================================

set -e

# Renkli cikti
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "================================================================================"
    echo "  ████████╗███████╗██╗   ██╗███╗   ██╗ █████╗ ███╗   ███╗██╗"
    echo "  ╚══██╔══╝██╔════╝██║   ██║████╗  ██║██╔══██╗████╗ ████║██║"
    echo "     ██║   ███████╗██║   ██║██╔██╗ ██║███████║██╔████╔██║██║"
    echo "     ██║   ╚════██║██║   ██║██║╚██╗██║██╔══██║██║╚██╔╝██║██║"
    echo "     ██║   ███████║╚██████╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║██║"
    echo "     ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝"
    echo ""
    echo "                    24/7 KORUMA KURULUM SCRIPTI"
    echo "================================================================================"
    echo -e "${NC}"
}

# Log fonksiyonlari
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[UYARI]${NC} $1"
}

log_error() {
    echo -e "${RED}[HATA]${NC} $1"
}

log_step() {
    echo -e "\n${BLUE}>>> $1${NC}"
}

# Root kontrolu
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Bu script root yetkisi gerektirir!"
        echo "Kullanim: sudo $0"
        exit 1
    fi
}

# Sistem kontrolu
check_system() {
    log_step "Sistem kontrol ediliyor..."

    # Ubuntu/Debian kontrolu
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        log_info "Isletim sistemi: $PRETTY_NAME"
    else
        log_warn "OS bilgisi alinamadi"
    fi

    # Python kontrolu
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version 2>&1)
        log_info "Python: $PYTHON_VERSION"
    else
        log_error "Python3 bulunamadi!"
        exit 1
    fi

    # pip kontrolu
    if command -v pip3 &> /dev/null; then
        log_info "pip3 mevcut"
    else
        log_warn "pip3 bulunamadi, yukleniyor..."
        apt-get update && apt-get install -y python3-pip
    fi
}

# Dizinleri olustur
create_directories() {
    log_step "Dizinler olusturuluyor..."

    # TSUNAMI dizinleri
    TSUNAMI_DIR="/home/lydian/Desktop/TSUNAMI"
    TSUNAMI_USER_DIR="/home/lydian/.tsunami"

    # Kullanici dizinleri
    mkdir -p "$TSUNAMI_USER_DIR/logs"
    mkdir -p "$TSUNAMI_USER_DIR/network_data"
    mkdir -p "$TSUNAMI_USER_DIR/blocked_ips"
    mkdir -p "$TSUNAMI_USER_DIR/file_hashes"
    mkdir -p "$TSUNAMI_USER_DIR/alerts"

    # Yetkileri ayarla
    chown -R lydian:lydian "$TSUNAMI_USER_DIR"
    chmod 700 "$TSUNAMI_USER_DIR"

    log_info "Dizinler olusturuldu: $TSUNAMI_USER_DIR"
}

# Python bagimliliklarini yukle
install_dependencies() {
    log_step "Python bagimliliklari yukleniyor..."

    # Sistem paketleri
    apt-get update
    apt-get install -y \
        python3-pip \
        python3-dev \
        python3-venv \
        net-tools \
        iproute2 \
        iw \
        wpasupplicant \
        network-manager \
        iptables \
        ipset \
        libpcap-dev \
        tcpdump \
        nmap \
        arp-scan

    # Python paketleri
    pip3 install --upgrade pip
    pip3 install \
        psutil \
        scapy \
        netifaces \
        watchdog \
        inotify

    log_info "Bagimliliklar yuklendi"
}

# Firewall kurulumu
setup_firewall() {
    log_step "Firewall yapilandiriliyor..."

    # UFW yoksa yukle
    if ! command -v ufw &> /dev/null; then
        apt-get install -y ufw
    fi

    # Mevcut durumu kontrol et
    UFW_STATUS=$(ufw status | head -1)
    log_info "Mevcut UFW durumu: $UFW_STATUS"

    # Temel guvenlik kurallari
    # NOT: Bu kurallar varsayilan olarak yorumlu
    # Kullanicinin kendi ihtiyacina gore acmasi gerekir

    cat > /etc/ufw/applications.d/tsunami << 'EOF'
[TSUNAMI-Defender]
title=TSUNAMI Defender
description=TSUNAMI Security Suite - Defender Service
ports=

[TSUNAMI-Network-Guardian]
title=TSUNAMI Network Guardian
description=TSUNAMI Security Suite - Network Monitoring Service
ports=
EOF

    log_info "UFW uygulama profilleri olusturuldu"

    # Iptables ile ek koruma kurallari
    # Bu kurallar TSUNAMI servisleri tarafindan yonetilecek
    cat > /etc/tsunami-firewall.rules << 'EOF'
# ==============================================================================
# TSUNAMI FIREWALL KURALLARI
# ==============================================================================
# Bu kurallar TSUNAMI Defender tarafindan yonetilir
# Manuel olarak degistirmeyin
#
# Uygulamak icin:
#   iptables-restore < /etc/tsunami-firewall.rules
#
# ==============================================================================

*filter
:INPUT ACCEPT [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:TSUNAMI-BLOCK - [0:0]

# Loopback'e izin ver
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o lo -j ACCEPT

# Kurulu baglantilara izin ver
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# TSUNAMI engelleme zinciri
-A INPUT -j TSUNAMI-BLOCK

# Ping'e izin ver (isteğe bagli - yoruma alinabilir)
-A INPUT -p icmp --icmp-type echo-request -j ACCEPT

# SSH (eger kullaniliyorsa)
# -A INPUT -p tcp --dport 22 -j ACCEPT

# HTTP/HTTPS (eger web servisi varsa)
# -A INPUT -p tcp --dport 80 -j ACCEPT
# -A INPUT -p tcp --dport 443 -j ACCEPT

COMMIT
EOF

    log_info "Firewall kurallari /etc/tsunami-firewall.rules dosyasina yazildi"
}

# Ipset kurulumu (IP engelleme icin)
setup_ipset() {
    log_step "IPset yapilandiriliyor..."

    # IPset yoksa yukle
    if ! command -v ipset &> /dev/null; then
        apt-get install -y ipset
    fi

    # TSUNAMI icin ipset olustur
    ipset create tsunami_blocked_ips hash:ip timeout 3600 2>/dev/null || true
    ipset create tsunami_blocked_macs hash:mac timeout 3600 2>/dev/null || true

    # Ipset'i kalici yap
    cat > /etc/ipset.conf << 'EOF'
create tsunami_blocked_ips hash:ip family inet hashsize 1024 maxelem 65536 timeout 3600
create tsunami_blocked_macs hash:mac hashsize 1024 maxelem 65536 timeout 3600
EOF

    log_info "IPset yapilandi"
}

# Systemd servislerini kur
install_systemd_services() {
    log_step "Systemd servisleri kuruluyor..."

    TSUNAMI_DIR="/home/lydian/Desktop/TSUNAMI"
    SYSTEMD_DIR="/etc/systemd/system"

    # Defender servisi
    cp "$TSUNAMI_DIR/config/systemd/tsunami-defender.service" "$SYSTEMD_DIR/"
    log_info "tsunami-defender.service kuruldu"

    # Network Guardian servisi
    cp "$TSUNAMI_DIR/config/systemd/tsunami-network-guardian.service" "$SYSTEMD_DIR/"
    log_info "tsunami-network-guardian.service kuruldu"

    # Systemd'yi yeniden yukle
    systemctl daemon-reload
    log_info "Systemd yapilandirmasi yuklendi"
}

# Servisleri etkinlestir ve baslat
enable_services() {
    log_step "Servisler etkinlestiriliyor ve baslatiliyor..."

    # Defender
    systemctl enable tsunami-defender.service
    log_info "tsunami-defender otomatik baslatma etkin"

    # Network Guardian
    systemctl enable tsunami-network-guardian.service
    log_info "tsunami-network-guardian otomatik baslatma etkin"

    # Servisleri baslat
    systemctl start tsunami-defender.service || log_warn "Defender baslatilamadi"
    systemctl start tsunami-network-guardian.service || log_warn "Network Guardian baslatilamadi"

    # Durum kontrolu
    echo ""
    log_info "Servis durumlari:"
    systemctl status tsunami-defender.service --no-pager | head -5
    echo ""
    systemctl status tsunami-network-guardian.service --no-pager | head -5
}

# Logrotate yapilandirmasi
setup_logrotate() {
    log_step "Log rotasyonu yapilandiriliyor..."

    cat > /etc/logrotate.d/tsunami << 'EOF'
/home/lydian/.tsunami/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0640 lydian lydian
    sharedscripts
    postrotate
        systemctl reload tsunami-defender.service 2>/dev/null || true
        systemctl reload tsunami-network-guardian.service 2>/dev/null || true
    endscript
}
EOF

    log_info "Logrotate yapilandirma dosyasi olusturuldu"
}

# Cron job'lari ayarla
setup_cron_jobs() {
    log_step "Zamanlanmis gorevler ayarlaniyor..."

    # TSUNAMI cron dosyasi
    cat > /etc/cron.d/tsunami << 'EOF'
# TSUNAMI 24/7 Koruma - Zamanlanmis Gorevler
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Her gun gece yarisi log temizligi ve rapor
0 0 * * * root /usr/bin/python3 /home/lydian/Desktop/TSUNAMI/scripts/tsunami_defender.py scan > /dev/null 2>&1

# Her saat WiFi taramasi
0 * * * * root /usr/bin/python3 /home/lydian/Desktop/TSUNAMI/scripts/network_guardian.py wifi > /home/lydian/.tsunami/logs/wifi_hourly.log 2>&1

# Gunluk sistem taramasi
30 3 * * * root /usr/bin/python3 /home/lydian/Desktop/TSUNAMI/scripts/network_guardian.py scan > /home/lydian/.tsunami/logs/daily_scan.log 2>&1

# Servis saglik kontrolu (her 5 dakika)
*/5 * * * * root systemctl is-active --quiet tsunami-defender.service || systemctl restart tsunami-defender.service
*/5 * * * * root systemctl is-active --quiet tsunami-network-guardian.service || systemctl restart tsunami-network-guardian.service
EOF

    chmod 644 /etc/cron.d/tsunami
    log_info "Cron job'lari ayarlandi"
}

# Kernel guvenlik ayarlari
harden_kernel() {
    log_step "Kernel guvenlik ayarlari yapiliyor..."

    # Sysctl ayarlari
    cat > /etc/sysctl.d/99-tsunami-security.conf << 'EOF'
# ==============================================================================
# TSUNAMI Security - Kernel Hardening
# ==============================================================================

# Ag guvenlik ayarlari
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# IPv6 (kullanilmiyorsa devre disi birakilabilir)
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Bellek koruma
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3

# Dosya sistemi koruma
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0

# Core dump'lari engelle
kernel.core_uses_pid = 1
EOF

    # Ayarlari uygula
    sysctl -p /etc/sysctl.d/99-tsunami-security.conf > /dev/null 2>&1 || true
    log_info "Kernel guvenlik ayarlari uygulandi"
}

# Kurulum ozeti
print_summary() {
    echo ""
    echo -e "${GREEN}================================================================================${NC}"
    echo -e "${GREEN}                    TSUNAMI 24/7 KORUMA KURULUMU TAMAMLANDI!${NC}"
    echo -e "${GREEN}================================================================================${NC}"
    echo ""
    echo -e "${CYAN}Kurulan servisler:${NC}"
    echo "  - tsunami-defender.service    : Sistem koruma daemon'u"
    echo "  - tsunami-network-guardian.service : Ag/WiFi izleme daemon'u"
    echo ""
    echo -e "${CYAN}Servis yonetimi:${NC}"
    echo "  Durum:    sudo systemctl status tsunami-defender"
    echo "  Baslat:   sudo systemctl start tsunami-defender"
    echo "  Durdur:   sudo systemctl stop tsunami-defender"
    echo "  Loglar:   sudo journalctl -u tsunami-defender -f"
    echo ""
    echo -e "${CYAN}Manuel komutlar:${NC}"
    echo "  Defender tarama:   python3 /home/lydian/Desktop/TSUNAMI/scripts/tsunami_defender.py scan"
    echo "  Ag tarama:         python3 /home/lydian/Desktop/TSUNAMI/scripts/network_guardian.py scan"
    echo "  WiFi tarama:       python3 /home/lydian/Desktop/TSUNAMI/scripts/network_guardian.py wifi"
    echo "  Cihaz listesi:     python3 /home/lydian/Desktop/TSUNAMI/scripts/network_guardian.py devices"
    echo ""
    echo -e "${CYAN}Log dosyalari:${NC}"
    echo "  /home/lydian/.tsunami/logs/"
    echo ""
    echo -e "${CYAN}Yapilandirma:${NC}"
    echo "  /home/lydian/Desktop/TSUNAMI/tsunami_config.json"
    echo ""
    echo -e "${YELLOW}ONEMLI:${NC}"
    echo "  - Guvenli cihazlarinizi tsunami_config.json'a ekleyin"
    echo "  - Guvenli WiFi aglarinizi trusted_ssids listesine ekleyin"
    echo "  - Logları duzenli kontrol edin"
    echo ""
    echo -e "${GREEN}Sisteminiz artik 7/24 koruma altinda!${NC}"
    echo ""
}

# Kurulumu kaldir
uninstall() {
    log_step "TSUNAMI 24/7 koruma kaldiriliyor..."

    # Servisleri durdur ve devre disi birak
    systemctl stop tsunami-defender.service 2>/dev/null || true
    systemctl stop tsunami-network-guardian.service 2>/dev/null || true
    systemctl disable tsunami-defender.service 2>/dev/null || true
    systemctl disable tsunami-network-guardian.service 2>/dev/null || true

    # Servis dosyalarini sil
    rm -f /etc/systemd/system/tsunami-defender.service
    rm -f /etc/systemd/system/tsunami-network-guardian.service

    # Cron job'lari sil
    rm -f /etc/cron.d/tsunami

    # Logrotate'i sil
    rm -f /etc/logrotate.d/tsunami

    # Sysctl'i sil
    rm -f /etc/sysctl.d/99-tsunami-security.conf

    # Firewall kurallarini sil
    rm -f /etc/tsunami-firewall.rules

    # IPset'leri sil
    ipset destroy tsunami_blocked_ips 2>/dev/null || true
    ipset destroy tsunami_blocked_macs 2>/dev/null || true

    # Systemd'yi yeniden yukle
    systemctl daemon-reload

    log_info "TSUNAMI 24/7 koruma kaldirildi"
    log_warn "Kullanici verileri (/home/lydian/.tsunami) korundu"
}

# Ana fonksiyon
main() {
    print_banner

    # Arguman kontrolu
    if [[ "$1" == "uninstall" ]]; then
        check_root
        uninstall
        exit 0
    fi

    check_root
    check_system

    echo ""
    echo -e "${YELLOW}Bu script asagidaki islemleri yapacak:${NC}"
    echo "  1. Gerekli dizinleri olustur"
    echo "  2. Python bagimlilik kurulumu"
    echo "  3. Firewall yapilandirmasi"
    echo "  4. IPset kurulumu"
    echo "  5. Systemd servis kurulumu"
    echo "  6. Log rotasyonu ayarlari"
    echo "  7. Cron job'lari"
    echo "  8. Kernel guvenlik ayarlari"
    echo ""
    read -p "Devam etmek istiyor musunuz? (e/h): " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Ee]$ ]]; then
        log_info "Kurulum iptal edildi"
        exit 0
    fi

    # Kurulum adimlari
    create_directories
    install_dependencies
    setup_firewall
    setup_ipset
    install_systemd_services
    setup_logrotate
    setup_cron_jobs
    harden_kernel
    enable_services

    print_summary
}

# Script'i calistir
main "$@"
