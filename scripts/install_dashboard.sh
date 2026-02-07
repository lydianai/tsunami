#!/bin/bash
# ==============================================================================
# TSUNAMI GUVENLIK DASHBOARD - Kurulum Scripti
# ==============================================================================
# Elite Hacker Security Dashboard kurulum ve yapilandirmasi
#
# KULLANIM:
#   chmod +x install_dashboard.sh
#   ./install_dashboard.sh
#
# ==============================================================================

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << 'EOF'
================================================================================
   ████████╗███████╗██╗   ██╗███╗   ██╗ █████╗ ███╗   ███╗██╗
   ╚══██╔══╝██╔════╝██║   ██║████╗  ██║██╔══██╗████╗ ████║██║
      ██║   ███████╗██║   ██║██╔██╗ ██║███████║██╔████╔██║██║
      ██║   ╚════██║██║   ██║██║╚██╗██║██╔══██║██║╚██╔╝██║██║
      ██║   ███████║╚██████╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║██║
      ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝

   GUVENLIK DASHBOARD - Kurulum Scripti v1.0
   Elite Hacker SOC Analyst Workstation
================================================================================
EOF
echo -e "${NC}"

# Dizin kontrolu
TSUNAMI_HOME="/home/lydian/Desktop/TSUNAMI"
if [ ! -d "$TSUNAMI_HOME" ]; then
    echo -e "${RED}HATA: TSUNAMI dizini bulunamadi: $TSUNAMI_HOME${NC}"
    exit 1
fi

cd "$TSUNAMI_HOME"

echo -e "${BLUE}[1/6] Sistem bagimliliklari kontrol ediliyor...${NC}"

# Sistem paketleri
SYSTEM_PACKAGES="python3-gi python3-gi-cairo gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-notify-0.7 libnotify-bin"

MISSING_PACKAGES=""
for pkg in $SYSTEM_PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $pkg"; then
        MISSING_PACKAGES="$MISSING_PACKAGES $pkg"
    fi
done

if [ -n "$MISSING_PACKAGES" ]; then
    echo -e "${YELLOW}Eksik paketler yukleniyor:$MISSING_PACKAGES${NC}"
    sudo apt update
    sudo apt install -y $MISSING_PACKAGES
else
    echo -e "${GREEN}Tum sistem paketleri yuklu.${NC}"
fi

echo -e "${BLUE}[2/6] Python bagimliliklari kontrol ediliyor...${NC}"

# Python paketleri
PYTHON_PACKAGES="psutil requests"

for pkg in $PYTHON_PACKAGES; do
    if ! python3 -c "import $pkg" 2>/dev/null; then
        echo -e "${YELLOW}Python paketi yukleniyor: $pkg${NC}"
        pip3 install --user $pkg
    fi
done

# Opsiyonel websocket
if ! python3 -c "import websocket" 2>/dev/null; then
    echo -e "${YELLOW}websocket-client yukleniyor (opsiyonel)...${NC}"
    pip3 install --user websocket-client || true
fi

echo -e "${GREEN}Python paketleri tamam.${NC}"

echo -e "${BLUE}[3/6] Dosya izinleri ayarlaniyor...${NC}"

# Calistirma izinleri
chmod +x "$TSUNAMI_HOME/tsunami_dashboard.py"
chmod +x "$TSUNAMI_HOME/tsunami_notify.py"

echo -e "${GREEN}Dosya izinleri ayarlandi.${NC}"

echo -e "${BLUE}[4/6] Autostart yapilandiriliyor...${NC}"

# Autostart dizini
mkdir -p ~/.config/autostart

# Dashboard autostart
cat > ~/.config/autostart/tsunami-dashboard.desktop << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=TSUNAMI Guvenlik Dashboard
Name[tr]=TSUNAMI Guvenlik Dashboard
Comment=Elite Hacker Security Dashboard - SOC Analyst Workstation
Comment[tr]=Elite Hacker Guvenlik Merkezi - SOC Analisti Is Istasyonu
Exec=/usr/bin/python3 /home/lydian/Desktop/TSUNAMI/tsunami_dashboard.py
Icon=security-high
Terminal=false
Categories=Security;System;Monitor;
Keywords=security;dashboard;tsunami;monitoring;threat;
StartupNotify=true
StartupWMClass=tsunami-dashboard
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=5
DESKTOP

# Notification daemon autostart
cat > ~/.config/autostart/tsunami-notify.desktop << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=TSUNAMI Bildirim Servisi
Name[tr]=TSUNAMI Bildirim Servisi
Comment=Real-time Threat Notification Daemon
Comment[tr]=Gercek Zamanli Tehdit Bildirimi Daemon'u
Exec=/usr/bin/python3 /home/lydian/Desktop/TSUNAMI/tsunami_notify.py start
Icon=dialog-warning
Terminal=false
Categories=Security;System;
Keywords=security;notification;tsunami;alert;
StartupNotify=false
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Delay=3
DESKTOP

echo -e "${GREEN}Autostart yapilandirmasi tamamlandi.${NC}"

echo -e "${BLUE}[5/6] User systemd servisi yapilandiriliyor (opsiyonel)...${NC}"

# User systemd dizini
mkdir -p ~/.config/systemd/user

# Notification servis dosyasini kopyala
if [ -f "$TSUNAMI_HOME/config/systemd/tsunami-notify.service" ]; then
    cp "$TSUNAMI_HOME/config/systemd/tsunami-notify.service" ~/.config/systemd/user/
    systemctl --user daemon-reload
    echo -e "${GREEN}Systemd user servisi yapilandirildi.${NC}"
    echo -e "${YELLOW}Servisi etkinlestirmek icin: systemctl --user enable tsunami-notify${NC}"
else
    echo -e "${YELLOW}Systemd servis dosyasi bulunamadi, atlaniyor.${NC}"
fi

echo -e "${BLUE}[6/6] Yapilandirma dosyalari olusturuluyor...${NC}"

# Logs dizini
mkdir -p "$TSUNAMI_HOME/logs"
mkdir -p "$TSUNAMI_HOME/backups"

# Varsayilan yapilandirma
if [ ! -f "$TSUNAMI_HOME/notify_config.json" ]; then
    cat > "$TSUNAMI_HOME/notify_config.json" << 'JSON'
{
    "aktif": true,
    "ses_aktif": true,
    "izleme_araligi": 5,
    "min_seviye": "dusuk",
    "bildirim_suresi": 10000
}
JSON
    echo -e "${GREEN}Bildirim yapilandirmasi olusturuldu.${NC}"
fi

echo ""
echo -e "${GREEN}================================================================================${NC}"
echo -e "${GREEN}   KURULUM TAMAMLANDI!${NC}"
echo -e "${GREEN}================================================================================${NC}"
echo ""
echo -e "${CYAN}KULLANIM:${NC}"
echo ""
echo -e "  ${YELLOW}Dashboard'u baslatmak icin:${NC}"
echo "    python3 $TSUNAMI_HOME/tsunami_dashboard.py"
echo ""
echo -e "  ${YELLOW}Bildirim daemon'unu baslatmak icin:${NC}"
echo "    python3 $TSUNAMI_HOME/tsunami_notify.py start"
echo ""
echo -e "  ${YELLOW}Bildirim daemon'unu durdurmak icin:${NC}"
echo "    python3 $TSUNAMI_HOME/tsunami_notify.py stop"
echo ""
echo -e "  ${YELLOW}Test bildirimi gondermek icin:${NC}"
echo "    python3 $TSUNAMI_HOME/tsunami_notify.py test"
echo ""
echo -e "${CYAN}OTOMATIK BASLATMA:${NC}"
echo "  Dashboard ve bildirim servisi bir sonraki oturumda otomatik baslatilacak."
echo ""
echo -e "${CYAN}MANUEL BASLATMA (HEMEN):${NC}"
echo "  Dashboard'u simdi baslatmak ister misiniz? (e/h)"
read -r response
if [[ "$response" =~ ^([eE])$ ]]; then
    echo -e "${BLUE}Dashboard baslatiliyor...${NC}"
    python3 "$TSUNAMI_HOME/tsunami_notify.py" start &
    sleep 2
    python3 "$TSUNAMI_HOME/tsunami_dashboard.py" &
    echo -e "${GREEN}Dashboard baslatildi!${NC}"
fi

echo ""
echo -e "${GREEN}TSUNAMI Guvenlik Dashboard kurulumu tamamlandi.${NC}"
echo -e "${CYAN}Guvenli kalin! 🌊${NC}"
