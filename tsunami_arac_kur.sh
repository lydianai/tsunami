#!/bin/bash
#===============================================================================
#  TSUNAMI GUVENLIK ARACLARI TOPLU KURULUM SCRIPTI
#  Versiyon: 3.0
#
#  Kullanim: sudo bash tsunami_arac_kur.sh [kategori]
#  Ornek:    sudo bash tsunami_arac_kur.sh tarama
#            sudo bash tsunami_arac_kur.sh tumu
#
#  Kategoriler: tarama, kablosuz, bluetooth, paket, web, sifre, cerceve, osint, diger, tumu
#===============================================================================

set -e

# Renk Kodlari
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Log dosyasi
LOG_FILE="/tmp/tsunami_kurulum_$(date +%Y%m%d_%H%M%S).log"

echo_info() { echo -e "${CYAN}[*]${NC} $1"; }
echo_ok() { echo -e "${GREEN}[+]${NC} $1"; }
echo_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
echo_err() { echo -e "${RED}[-]${NC} $1"; }

log() { echo "[$(date +%H:%M:%S)] $1" >> "$LOG_FILE"; }

banner() {
    echo -e "${CYAN}"
    echo "==============================================================================="
    echo "                    TSUNAMI GUVENLIK ARACLARI KURULUM"
    echo "                           Versiyon 3.0"
    echo "==============================================================================="
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo_err "Bu script root yetkisi gerektirir. sudo ile calistirin."
        exit 1
    fi
}

update_system() {
    echo_info "Sistem guncelleniyor..."
    apt-get update -qq >> "$LOG_FILE" 2>&1
    echo_ok "Sistem guncellendi"
}

install_tool() {
    local name=$1
    local package=$2
    local desc=$3

    if command -v "$name" &> /dev/null || dpkg -l "$package" &> /dev/null 2>&1; then
        echo_ok "$name zaten yuklu"
        return 0
    fi

    echo_info "$name kuruluyor... ($desc)"
    log "Kuruluyor: $name ($package)"

    if apt-get install -y -qq "$package" >> "$LOG_FILE" 2>&1; then
        echo_ok "$name basariyla kuruldu"
        log "Basarili: $name"
        return 0
    else
        echo_warn "$name apt ile kurulamadi, alternatif deneniyor..."
        return 1
    fi
}

install_pip_tool() {
    local name=$1
    local package=$2

    if python3 -c "import $name" &> /dev/null 2>&1 || pip3 show "$package" &> /dev/null 2>&1; then
        echo_ok "$name (pip) zaten yuklu"
        return 0
    fi

    echo_info "$name (pip) kuruluyor..."
    if pip3 install --break-system-packages "$package" >> "$LOG_FILE" 2>&1; then
        echo_ok "$name (pip) basariyla kuruldu"
        return 0
    else
        echo_err "$name (pip) kurulamadi"
        return 1
    fi
}

install_go_tool() {
    local name=$1
    local repo=$2

    if command -v "$name" &> /dev/null; then
        echo_ok "$name zaten yuklu"
        return 0
    fi

    echo_info "$name (go) kuruluyor..."
    if command -v go &> /dev/null; then
        GO111MODULE=on go install "$repo" >> "$LOG_FILE" 2>&1 && echo_ok "$name kuruldu" || echo_warn "$name kurulamadi"
    else
        echo_warn "Go yuklu degil, $name atlanıyor"
    fi
}

# ==================== KATEGORI FONKSIYONLARI ====================

install_tarama() {
    echo -e "\n${PURPLE}=== AG TARAMA ARACLARI ===${NC}"

    install_tool "nmap" "nmap" "Ag tarama ve port kesfetme"
    install_tool "masscan" "masscan" "Yuksek hizli port tarayici"
    install_tool "rustscan" "rustscan" "Hizli Rust tarayici" || {
        # Rustscan alternatif kurulum
        if ! command -v rustscan &> /dev/null; then
            echo_info "rustscan cargo ile kuruluyor..."
            if command -v cargo &> /dev/null; then
                cargo install rustscan >> "$LOG_FILE" 2>&1 && echo_ok "rustscan kuruldu"
            fi
        fi
    }

    # ZMap kurulumu
    if ! command -v zmap &> /dev/null; then
        echo_info "zmap kuruluyor..."
        apt-get install -y -qq zmap >> "$LOG_FILE" 2>&1 && echo_ok "zmap kuruldu" || echo_warn "zmap kurulamadi"
    else
        echo_ok "zmap zaten yuklu"
    fi
}

install_kablosuz() {
    echo -e "\n${PURPLE}=== KABLOSUZ GUVENLIK ARACLARI ===${NC}"

    install_tool "aircrack-ng" "aircrack-ng" "WiFi guvenlik analizi"
    install_tool "kismet" "kismet" "Kablosuz ag dedektoru"
    install_tool "wifite" "wifite" "Otomatik WiFi denetimi"
    install_tool "reaver" "reaver" "WPS kirma araci"
    install_tool "bully" "bully" "WPS brute force"
    install_tool "mdk4" "mdk4" "WiFi stres testi"
    install_tool "hostapd" "hostapd" "Access point yazilimi"
    install_tool "dnsmasq" "dnsmasq" "DNS/DHCP sunucu"

    # Fluxion (manuel)
    if [ ! -d "/opt/fluxion" ]; then
        echo_info "Fluxion klonlaniyor..."
        git clone https://github.com/FluxionNetwork/fluxion.git /opt/fluxion >> "$LOG_FILE" 2>&1 && echo_ok "Fluxion kuruldu" || echo_warn "Fluxion kurulamadi"
    else
        echo_ok "Fluxion zaten yuklu"
    fi

    # Wifiphisher
    install_pip_tool "wifiphisher" "wifiphisher"
}

install_bluetooth() {
    echo -e "\n${PURPLE}=== BLUETOOTH ARACLARI ===${NC}"

    install_tool "bluetoothctl" "bluez" "Bluetooth yonetimi"
    install_tool "hcitool" "bluez" "Bluetooth HCI araci"
    install_tool "btscanner" "btscanner" "Bluetooth tarayici"
    install_tool "bluelog" "bluelog" "Bluetooth logger"

    # Ubertooth
    if ! command -v ubertooth-scan &> /dev/null; then
        echo_info "Ubertooth kuruluyor..."
        apt-get install -y -qq ubertooth >> "$LOG_FILE" 2>&1 && echo_ok "Ubertooth kuruldu" || echo_warn "Ubertooth kurulamadi"
    else
        echo_ok "Ubertooth zaten yuklu"
    fi
}

install_paket() {
    echo -e "\n${PURPLE}=== PAKET ANALIZ ARACLARI ===${NC}"

    install_tool "wireshark" "wireshark" "Paket analizoru"
    install_tool "tshark" "tshark" "Komut satiri paket analizoru"
    install_tool "tcpdump" "tcpdump" "Paket yakalama"
    install_tool "ettercap" "ettercap-text-only" "Ag koklama araci"
    install_tool "bettercap" "bettercap" "Ag saldiri cercevesi"
    install_tool "dsniff" "dsniff" "Ag koklama araci"
    install_tool "arpwatch" "arpwatch" "ARP izleme"
    install_tool "ngrep" "ngrep" "Ag grep"

    # Scapy (Python)
    install_pip_tool "scapy" "scapy"
}

install_web() {
    echo -e "\n${PURPLE}=== WEB GUVENLIK ARACLARI ===${NC}"

    install_tool "nikto" "nikto" "Web sunucu tarayici"
    install_tool "sqlmap" "sqlmap" "SQL enjeksiyon araci"
    install_tool "dirb" "dirb" "Dizin brute force"
    install_tool "gobuster" "gobuster" "Dizin/DNS bulucu"
    install_tool "wfuzz" "wfuzz" "Web fuzzer"
    install_tool "whatweb" "whatweb" "Web parmak izi"
    install_tool "wafw00f" "wafw00f" "WAF tespiti"

    # Nuclei
    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"

    # FFuf
    install_go_tool "ffuf" "github.com/ffuf/ffuf/v2@latest"

    # HTTPX
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
}

install_sifre() {
    echo -e "\n${PURPLE}=== SIFRE KIRMA ARACLARI ===${NC}"

    install_tool "john" "john" "John the Ripper"
    install_tool "hashcat" "hashcat" "GPU sifre kirma"
    install_tool "hydra" "hydra" "Giris kiricisi"
    install_tool "medusa" "medusa" "Paralel giris kiricisi"
    install_tool "ncrack" "ncrack" "Ag kimlik kirici"
    install_tool "ophcrack" "ophcrack" "Windows sifre kirici"
    install_tool "crunch" "crunch" "Wordlist olusturucu"
    install_tool "cewl" "cewl" "Ozel wordlist olusturucu"
}

install_cerceve() {
    echo -e "\n${PURPLE}=== GUVENLIK CERCEVELERI ===${NC}"

    # Metasploit
    if ! command -v msfconsole &> /dev/null; then
        echo_info "Metasploit kuruluyor (bu uzun surebilir)..."
        apt-get install -y -qq metasploit-framework >> "$LOG_FILE" 2>&1 && echo_ok "Metasploit kuruldu" || {
            echo_warn "Metasploit apt ile kurulamadi, manuel kurulum gerekebilir"
            echo_info "Kurulum: curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall"
        }
    else
        echo_ok "Metasploit zaten yuklu"
    fi

    # OWASP ZAP
    if ! command -v zaproxy &> /dev/null; then
        echo_info "OWASP ZAP kuruluyor..."
        apt-get install -y -qq zaproxy >> "$LOG_FILE" 2>&1 && echo_ok "ZAP kuruldu" || echo_warn "ZAP kurulamadi"
    else
        echo_ok "ZAP zaten yuklu"
    fi

    # BeEF
    if [ ! -d "/usr/share/beef-xss" ]; then
        echo_info "BeEF kuruluyor..."
        apt-get install -y -qq beef-xss >> "$LOG_FILE" 2>&1 && echo_ok "BeEF kuruldu" || echo_warn "BeEF kurulamadi"
    else
        echo_ok "BeEF zaten yuklu"
    fi
}

install_osint() {
    echo -e "\n${PURPLE}=== OSINT ARACLARI ===${NC}"

    install_tool "theharvester" "theharvester" "Email/subdomain toplama"
    install_tool "recon-ng" "recon-ng" "Kesif cercevesi"
    install_tool "spiderfoot" "spiderfoot" "Otomatik OSINT"
    install_tool "maltego" "maltego" "OSINT araci"

    # Sherlock
    if ! command -v sherlock &> /dev/null; then
        echo_info "Sherlock kuruluyor..."
        pip3 install --break-system-packages sherlock-project >> "$LOG_FILE" 2>&1 && echo_ok "Sherlock kuruldu" || echo_warn "Sherlock kurulamadi"
    else
        echo_ok "Sherlock zaten yuklu"
    fi

    # Shodan CLI
    install_pip_tool "shodan" "shodan"

    # Amass
    install_go_tool "amass" "github.com/owasp-amass/amass/v4/...@master"

    # Subfinder
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
}

install_diger() {
    echo -e "\n${PURPLE}=== DIGER ARACLAR ===${NC}"

    install_tool "ncat" "ncat" "Gelismis netcat"
    install_tool "socat" "socat" "Soket arac"
    install_tool "proxychains4" "proxychains4" "Proxy zincirleme"
    install_tool "tor" "tor" "Anonimlik agi"
    install_tool "hping3" "hping3" "Paket olusturucu"
    install_tool "netcat" "netcat-openbsd" "Ag Swiss Army Knife"
    install_tool "curl" "curl" "URL transfer"
    install_tool "wget" "wget" "Web indirici"
    install_tool "whois" "whois" "Domain sorgu"
    install_tool "dnsutils" "dnsutils" "DNS araclari"
    install_tool "net-tools" "net-tools" "Ag araclari"
    install_tool "iptables" "iptables" "Firewall"
    install_tool "macchanger" "macchanger" "MAC degistirici"

    # Responder
    if [ ! -d "/opt/Responder" ]; then
        echo_info "Responder klonlaniyor..."
        git clone https://github.com/lgandx/Responder.git /opt/Responder >> "$LOG_FILE" 2>&1 && echo_ok "Responder kuruldu" || echo_warn "Responder kurulamadi"
    else
        echo_ok "Responder zaten yuklu"
    fi

    # Impacket
    install_pip_tool "impacket" "impacket"
}

install_bagimlilklar() {
    echo -e "\n${PURPLE}=== TEMEL BAGIMLILIKLAR ===${NC}"

    apt-get install -y -qq \
        build-essential \
        git \
        python3 \
        python3-pip \
        python3-dev \
        libssl-dev \
        libffi-dev \
        libpcap-dev \
        libnl-3-dev \
        libnl-genl-3-dev \
        libnetfilter-queue-dev \
        wireless-tools \
        iw \
        >> "$LOG_FILE" 2>&1

    echo_ok "Temel bagimliliklar kuruldu"

    # Go kurulumu (opsiyonel)
    if ! command -v go &> /dev/null; then
        echo_info "Go kuruluyor..."
        apt-get install -y -qq golang >> "$LOG_FILE" 2>&1 && echo_ok "Go kuruldu" || echo_warn "Go kurulamadi"
    fi

    # Rust kurulumu (opsiyonel)
    if ! command -v cargo &> /dev/null; then
        echo_info "Rust kuruluyor..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y >> "$LOG_FILE" 2>&1 && echo_ok "Rust kuruldu" || echo_warn "Rust kurulamadi"
        source "$HOME/.cargo/env" 2>/dev/null || true
    fi
}

install_tumu() {
    install_bagimlilklar
    install_tarama
    install_kablosuz
    install_bluetooth
    install_paket
    install_web
    install_sifre
    install_cerceve
    install_osint
    install_diger
}

show_summary() {
    echo -e "\n${CYAN}===============================================================================${NC}"
    echo -e "${CYAN}                         KURULUM OZETI${NC}"
    echo -e "${CYAN}===============================================================================${NC}"

    echo -e "\n${GREEN}Kurulu Araclar:${NC}"

    local tools=(
        "nmap" "masscan" "zmap" "rustscan"
        "aircrack-ng" "kismet" "wifite" "reaver"
        "bluetoothctl" "hcitool" "btscanner"
        "wireshark" "tshark" "tcpdump" "ettercap" "bettercap"
        "nikto" "sqlmap" "dirb" "gobuster" "nuclei"
        "john" "hashcat" "hydra" "medusa"
        "msfconsole" "zaproxy"
        "theharvester" "sherlock" "shodan"
        "ncat" "socat" "proxychains4" "tor" "hping3"
    )

    local installed=0
    local missing=0

    for tool in "${tools[@]}"; do
        if command -v "$tool" &> /dev/null; then
            echo -e "  ${GREEN}[+]${NC} $tool"
            ((installed++))
        else
            echo -e "  ${RED}[-]${NC} $tool"
            ((missing++))
        fi
    done

    echo -e "\n${CYAN}Istatistikler:${NC}"
    echo -e "  Kurulu: ${GREEN}$installed${NC}"
    echo -e "  Eksik:  ${RED}$missing${NC}"
    echo -e "  Log:    $LOG_FILE"

    echo -e "\n${CYAN}===============================================================================${NC}"
}

# ==================== ANA PROGRAM ====================

main() {
    banner
    check_root

    local kategori=${1:-"tumu"}

    echo_info "Kurulum kategorisi: $kategori"
    echo_info "Log dosyasi: $LOG_FILE"
    echo ""

    update_system

    case "$kategori" in
        "tarama")
            install_bagimlilklar
            install_tarama
            ;;
        "kablosuz")
            install_bagimlilklar
            install_kablosuz
            ;;
        "bluetooth")
            install_bagimlilklar
            install_bluetooth
            ;;
        "paket")
            install_bagimlilklar
            install_paket
            ;;
        "web")
            install_bagimlilklar
            install_web
            ;;
        "sifre")
            install_bagimlilklar
            install_sifre
            ;;
        "cerceve")
            install_bagimlilklar
            install_cerceve
            ;;
        "osint")
            install_bagimlilklar
            install_osint
            ;;
        "diger")
            install_bagimlilklar
            install_diger
            ;;
        "tumu"|"all")
            install_tumu
            ;;
        *)
            echo_err "Bilinmeyen kategori: $kategori"
            echo_info "Kullanim: sudo bash $0 [tarama|kablosuz|bluetooth|paket|web|sifre|cerceve|osint|diger|tumu]"
            exit 1
            ;;
    esac

    show_summary

    echo_ok "Kurulum tamamlandi!"
    echo_info "Bazi araclar icin yeniden baslatis gerekebilir."
}

main "$@"
