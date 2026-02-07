#!/bin/bash
#===============================================================================
#  TSUNAMI SISTEM TEST SCRIPTI
#  Tum modullerin gercek zamanli calistigini dogrular
#===============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

BASE_URL="http://127.0.0.1:8080"
COOKIE_FILE="/tmp/tsunami_test_cookies.txt"

echo -e "${CYAN}"
echo "==============================================================================="
echo "                    TSUNAMI SISTEM DOGRULAMA TESTI"
echo "==============================================================================="
echo -e "${NC}"

# Login
echo -e "${CYAN}[*] Giris yapiliyor...${NC}"
curl -s -c "$COOKIE_FILE" -d "kullanici=admin&sifre=dalga2024" "$BASE_URL/login" > /dev/null 2>&1

# 1. Sunucu Durumu
echo -e "\n${CYAN}=== 1. SUNUCU DURUMU ===${NC}"
if curl -s "$BASE_URL/login" | grep -q "TSUNAMI"; then
    echo -e "${GREEN}[+] Sunucu AKTIF${NC}"
else
    echo -e "${RED}[-] Sunucu PASIF${NC}"
fi

# 2. Arac Durumu API
echo -e "\n${CYAN}=== 2. ARAC DURUMU API ===${NC}"
ARAC_SONUC=$(curl -s -b "$COOKIE_FILE" "$BASE_URL/api/yerel/araclar" 2>/dev/null)
if echo "$ARAC_SONUC" | grep -q "toplam"; then
    TOPLAM=$(echo "$ARAC_SONUC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('toplam',0))" 2>/dev/null)
    YUKLU=$(echo "$ARAC_SONUC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('yuklu',0))" 2>/dev/null)
    echo -e "${GREEN}[+] Arac API AKTIF - Toplam: $TOPLAM, Yuklu: $YUKLU${NC}"
else
    echo -e "${YELLOW}[!] Arac API yanit vermedi (login gerekli olabilir)${NC}"
fi

# 3. DEFCON API
echo -e "\n${CYAN}=== 3. DEFCON API ===${NC}"
DEFCON_SONUC=$(curl -s -b "$COOKIE_FILE" "$BASE_URL/api/beyin/defcon" 2>/dev/null)
if echo "$DEFCON_SONUC" | grep -q "defcon"; then
    DEFCON=$(echo "$DEFCON_SONUC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('defcon',0))" 2>/dev/null)
    DEFCON_AD=$(echo "$DEFCON_SONUC" | python3 -c "import sys,json; print(json.load(sys.stdin).get('defcon_ad',''))" 2>/dev/null)
    echo -e "${GREEN}[+] DEFCON API AKTIF - Seviye: $DEFCON ($DEFCON_AD)${NC}"
else
    echo -e "${YELLOW}[!] DEFCON API yanit vermedi${NC}"
fi

# 4. Beyin Durumu
echo -e "\n${CYAN}=== 4. BEYIN DURUMU ===${NC}"
BEYIN_SONUC=$(curl -s -b "$COOKIE_FILE" "$BASE_URL/api/beyin/durum" 2>/dev/null)
if echo "$BEYIN_SONUC" | grep -q "sistem"; then
    echo -e "${GREEN}[+] BEYIN modulu AKTIF${NC}"
else
    echo -e "${YELLOW}[!] BEYIN durumu alinamadi${NC}"
fi

# 5. Aktif Araclar
echo -e "\n${CYAN}=== 5. AKTIF ARACLAR ===${NC}"
AKTIF_SONUC=$(curl -s -b "$COOKIE_FILE" "$BASE_URL/api/yerel/aktif-araclar" 2>/dev/null)
if echo "$AKTIF_SONUC" | grep -q "aktif"; then
    AKTIF_SAYI=$(echo "$AKTIF_SONUC" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('aktif',[])))" 2>/dev/null)
    echo -e "${GREEN}[+] Aktif Arac Sayisi: $AKTIF_SAYI${NC}"
else
    echo -e "${YELLOW}[!] Aktif arac bilgisi alinamadi${NC}"
fi

# 6. Gizlilik Durumu
echo -e "\n${CYAN}=== 6. GIZLILIK DURUMU ===${NC}"
GIZLILIK_SONUC=$(curl -s -b "$COOKIE_FILE" "$BASE_URL/api/gizlilik/durum" 2>/dev/null)
if echo "$GIZLILIK_SONUC" | grep -q "vpn"; then
    VPN=$(echo "$GIZLILIK_SONUC" | python3 -c "import sys,json; print('AKTIF' if json.load(sys.stdin).get('vpn_aktif',False) else 'PASIF')" 2>/dev/null)
    echo -e "${GREEN}[+] Gizlilik API AKTIF - VPN: $VPN${NC}"
else
    echo -e "${YELLOW}[!] Gizlilik durumu alinamadi${NC}"
fi

# 7. Kurulu Araclar (Sistem Kontrolu)
echo -e "\n${CYAN}=== 7. KURULU ARACLAR (SISTEM) ===${NC}"
KURULU=0
EKSIK=0
for tool in nmap masscan wireshark tcpdump nikto sqlmap john hashcat hydra aircrack-ng bettercap ettercap msfconsole gobuster dirb tor; do
    if command -v $tool &>/dev/null; then
        ((KURULU++))
    else
        ((EKSIK++))
    fi
done
echo -e "${GREEN}[+] Kurulu: $KURULU${NC}"
echo -e "${RED}[-] Eksik: $EKSIK${NC}"

# 8. Sayfalar
echo -e "\n${CYAN}=== 8. SAYFA DURUMU ===${NC}"
for page in panel harita dashboard araclar beyin komuta osint tarama spektrum trafik raporlar; do
    if curl -s -b "$COOKIE_FILE" "$BASE_URL/$page" 2>/dev/null | grep -q "TSUNAMI\|DOCTYPE"; then
        echo -e "${GREEN}[+] /$page AKTIF${NC}"
    else
        echo -e "${RED}[-] /$page PASIF${NC}"
    fi
done

# Temizlik
rm -f "$COOKIE_FILE"

echo -e "\n${CYAN}===============================================================================${NC}"
echo -e "${GREEN}                         TEST TAMAMLANDI${NC}"
echo -e "${CYAN}===============================================================================${NC}"
echo ""
echo -e "Sunucu: ${CYAN}http://localhost:8080${NC}"
echo -e "Giris:  ${CYAN}admin / dalga2024${NC}"
echo ""
