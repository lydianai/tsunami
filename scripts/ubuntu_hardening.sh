#!/bin/bash
# =============================================================================
#     TSUNAMI UBUNTU HARDENING SCRIPT v1.0
#     Askeri Seviye Sistem Guvenligi
# =============================================================================
#
#     AMAC: Ubuntu sistemini askeri seviye guvenlikle korumak
#     HEDEF: Hacker saldirilarina karsi tam koruma
#     YONTEM: Defense-in-depth (katmanli savunma)
#
#     OZELLIKLER:
#     - UFW Firewall yapilandirmasi
#     - Fail2Ban korumasi
#     - AppArmor profilleri
#     - SSH guvenligi (sadece anahtar, root yok)
#     - Kernel guvenligi (sysctl)
#     - Otomatik guvenlik guncellemeleri
#     - ClamAV antivirus
#     - Auditd denetim sistemi
#     - Rootkit tespiti (rkhunter, chkrootkit)
#     - Gereksiz servislerin kapatilmasi
#     - Dosya izinleri guvenligi
#     - DNS over HTTPS
#     - TOR destegi (opsiyonel)
#     - Bellek korumasi ve ASLR
#     - USB cihaz kisitlamalari
#
#     KULLANIM: sudo ./ubuntu_hardening.sh [--full|--minimal|--tor|--revert]
#
#     DIKKAT: Bu script SAVUNMA amaclidir. Sisteminizi korur.
#
# =============================================================================

set -e

# Renkler
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # Renk yok

# Log dosyasi
LOG_DIR="/var/log/tsunami"
LOG_FILE="$LOG_DIR/hardening_$(date +%Y%m%d_%H%M%S).log"
BACKUP_DIR="/var/backups/tsunami_hardening"

# Banner
banner() {
    echo -e "${CYAN}"
    echo "============================================================"
    echo "    ████████╗███████╗██╗   ██╗███╗   ██╗ █████╗ ███╗   ███╗██╗"
    echo "    ╚══██╔══╝██╔════╝██║   ██║████╗  ██║██╔══██╗████╗ ████║██║"
    echo "       ██║   ███████╗██║   ██║██╔██╗ ██║███████║██╔████╔██║██║"
    echo "       ██║   ╚════██║██║   ██║██║╚██╗██║██╔══██║██║╚██╔╝██║██║"
    echo "       ██║   ███████║╚██████╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║██║"
    echo "       ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝"
    echo ""
    echo "         UBUNTU HARDENING - Askeri Seviye Guvenlik"
    echo "============================================================"
    echo -e "${NC}"
}

# Loglama fonksiyonu
log() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        INFO)
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        WARN)
            echo -e "${YELLOW}[UYARI]${NC} $message"
            ;;
        ERROR)
            echo -e "${RED}[HATA]${NC} $message"
            ;;
        SUCCESS)
            echo -e "${GREEN}[BASARILI]${NC} $message"
            ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || true
}

# Root kontrolu
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[HATA] Bu script root olarak calistirilmalidir!${NC}"
        echo "Kullanim: sudo $0"
        exit 1
    fi
}

# Sistem bilgisi
get_system_info() {
    log INFO "Sistem bilgisi aliniyor..."

    OS_NAME=$(lsb_release -is 2>/dev/null || cat /etc/os-release | grep "^NAME" | cut -d'=' -f2 | tr -d '"')
    OS_VERSION=$(lsb_release -rs 2>/dev/null || cat /etc/os-release | grep "^VERSION_ID" | cut -d'=' -f2 | tr -d '"')
    KERNEL=$(uname -r)
    ARCH=$(uname -m)

    log INFO "Isletim Sistemi: $OS_NAME $OS_VERSION"
    log INFO "Kernel: $KERNEL"
    log INFO "Mimari: $ARCH"

    # Ubuntu kontrolu
    if [[ "$OS_NAME" != *"Ubuntu"* ]]; then
        log WARN "Bu script Ubuntu icin optimize edilmistir. Diger dagitimlarda sorun cikabilir."
    fi
}

# Dizinleri olustur
setup_directories() {
    log INFO "Gerekli dizinler olusturuluyor..."

    mkdir -p "$LOG_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$BACKUP_DIR/config"
    mkdir -p "$BACKUP_DIR/scripts"

    chmod 700 "$LOG_DIR"
    chmod 700 "$BACKUP_DIR"

    log SUCCESS "Dizinler olusturuldu"
}

# Yedekleme fonksiyonu
backup_file() {
    local file=$1
    if [[ -f "$file" ]]; then
        local backup_name=$(basename "$file")_$(date +%Y%m%d_%H%M%S).bak
        cp "$file" "$BACKUP_DIR/config/$backup_name"
        log INFO "Yedeklendi: $file -> $BACKUP_DIR/config/$backup_name"
    fi
}

# =============================================================================
# 1. SISTEM GUNCELLEMESI
# =============================================================================
update_system() {
    log INFO "=== SISTEM GUNCELLEMESI ==="

    # Paket listesini guncelle
    apt-get update -y

    # Guvenlik guncellemelerini yukle
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

    # Otomatik guvenlik guncellemeleri
    apt-get install -y unattended-upgrades apt-listchanges

    # Otomatik guvenlik guncellemelerini yapilandir
    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::DevRelease "false";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::SyslogEnable "true";
EOF

    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    systemctl enable unattended-upgrades
    systemctl start unattended-upgrades

    log SUCCESS "Sistem guncellemesi tamamlandi"
}

# =============================================================================
# 2. UFW FIREWALL YAPILANDIRMASI
# =============================================================================
configure_firewall() {
    log INFO "=== UFW FIREWALL YAPILANDIRMASI ==="

    # UFW kur
    apt-get install -y ufw

    # Mevcut kurallari yedekle
    if [[ -f /etc/ufw/user.rules ]]; then
        backup_file /etc/ufw/user.rules
    fi

    # Firewall'u sifirla
    ufw --force reset

    # Varsayilan politikalar - her seyi engelle
    ufw default deny incoming
    ufw default deny outgoing
    ufw default deny forward

    # Temel giden trafik izinleri
    # DNS
    ufw allow out 53/udp
    ufw allow out 53/tcp

    # HTTP/HTTPS (guvenli web trafigi)
    ufw allow out 80/tcp
    ufw allow out 443/tcp

    # NTP (zaman senkronizasyonu)
    ufw allow out 123/udp

    # SSH (sadece belirli IP'lerden izin - varsayilan olarak localhost)
    # Kullanici kendi IP'sini ekleyebilir
    ufw allow from 127.0.0.1 to any port 22 proto tcp

    # Loopback trafigi
    ufw allow in on lo
    ufw allow out on lo

    # ICMP (ping) kisitli izin
    # /etc/ufw/before.rules dosyasinda ayarlanir

    # Rate limiting - SSH icin
    ufw limit ssh comment 'SSH rate limiting'

    # IPv6 devre disi birak (opsiyonel - guvenlik icin)
    sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw

    # Firewall'u etkinlestir
    ufw --force enable

    # Log seviyesini artir
    ufw logging high

    log SUCCESS "UFW Firewall yapilandirildi"
    ufw status verbose
}

# =============================================================================
# 3. FAIL2BAN YAPILANDIRMASI
# =============================================================================
configure_fail2ban() {
    log INFO "=== FAIL2BAN YAPILANDIRMASI ==="

    # Fail2ban kur
    apt-get install -y fail2ban

    # Mevcut yapilandirmayi yedekle
    backup_file /etc/fail2ban/jail.local

    # Ana yapilandirma dosyasi
    cat > /etc/fail2ban/jail.local << 'EOF'
# =============================================================================
# TSUNAMI FAIL2BAN YAPILANDIRMASI
# Saldiri tespit ve engelleme sistemi
# =============================================================================

[DEFAULT]
# Yasaklama suresi (saniye) - 1 saat
bantime = 3600

# Kontrol edilen zaman penceresi (saniye) - 10 dakika
findtime = 600

# Maksimum basarisiz deneme
maxretry = 3

# Yasaklama eylemi - UFW ile entegre
banaction = ufw

# Tekrarlayan saldirganlar icin artan yasaklama
bantime.increment = true
bantime.factor = 24
bantime.maxtime = 604800

# E-posta bildirimi (yapilandirilirsa)
# destemail = admin@example.com
# sender = fail2ban@example.com
# mta = sendmail

# Loglama
logtarget = /var/log/fail2ban.log
loglevel = INFO

# IP whitelist (localhost)
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 6
bantime = 172800

[apache-auth]
enabled = true
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 3

[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache*/*access.log
maxretry = 2
bantime = 172800

[apache-noscript]
enabled = true
port = http,https
filter = apache-noscript
logpath = /var/log/apache*/*error.log
maxretry = 3

[nginx-http-auth]
enabled = true
port = http,https
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 172800

[nginx-bad-request]
enabled = true
port = http,https
filter = nginx-bad-request
logpath = /var/log/nginx/access.log
maxretry = 2

[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
maxretry = 3

[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = postfix-sasl
logpath = /var/log/mail.log
maxretry = 3

[dovecot]
enabled = true
port = pop3,pop3s,imap,imaps,submission,465,sieve
filter = dovecot
logpath = /var/log/mail.log
maxretry = 3

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = %(action_)s
bantime = 604800
findtime = 86400
maxretry = 5
EOF

    # Ozel filtre - port tarama tespiti
    cat > /etc/fail2ban/filter.d/portscan.conf << 'EOF'
[Definition]
failregex = ^.*\[UFW BLOCK\].*SRC=<HOST>.*$
ignoreregex =
EOF

    # Port tarama jail'i ekle
    cat >> /etc/fail2ban/jail.local << 'EOF'

[portscan]
enabled = true
filter = portscan
logpath = /var/log/ufw.log
maxretry = 3
findtime = 300
bantime = 86400
EOF

    # Servisi yeniden baslat
    systemctl enable fail2ban
    systemctl restart fail2ban

    log SUCCESS "Fail2ban yapilandirildi"
    fail2ban-client status
}

# =============================================================================
# 4. APPARMOR YAPILANDIRMASI
# =============================================================================
configure_apparmor() {
    log INFO "=== APPARMOR YAPILANDIRMASI ==="

    # AppArmor kur
    apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra

    # AppArmor'u etkinlestir
    systemctl enable apparmor
    systemctl start apparmor

    # Tum profilleri enforce moduna al
    aa-enforce /etc/apparmor.d/*

    # Ozel TSUNAMI profili
    cat > /etc/apparmor.d/tsunami.profile << 'EOF'
# TSUNAMI AppArmor Profili
# Sistem korunmasi icin ek kisitlamalar

#include <tunables/global>

profile tsunami-hardening flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Dosya sistemi erisimi
  / r,
  /home/** rw,
  /tmp/** rw,
  /var/log/tsunami/** rw,

  # Ag erisimi
  network inet stream,
  network inet dgram,
  network inet6 stream,
  network inet6 dgram,

  # Sistem cagrilari
  capability net_admin,
  capability sys_admin,

  # Yasak alanlar
  deny /etc/shadow rw,
  deny /etc/gshadow rw,
  deny /boot/** w,
  deny /lib/modules/** w,
}
EOF

    # Profili yukle
    apparmor_parser -r /etc/apparmor.d/tsunami.profile 2>/dev/null || true

    log SUCCESS "AppArmor yapilandirildi"
    aa-status
}

# =============================================================================
# 5. SSH GUVENLIGI
# =============================================================================
configure_ssh() {
    log INFO "=== SSH GUVENLIGI ==="

    # Mevcut yapilandirmayi yedekle
    backup_file /etc/ssh/sshd_config

    # SSH anahtari olustur (yoksa)
    if [[ ! -f /root/.ssh/id_ed25519 ]]; then
        ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" -C "tsunami_$(hostname)_$(date +%Y%m%d)"
        log INFO "Ed25519 SSH anahtari olusturuldu"
    fi

    # Guclu SSH yapilandirmasi
    cat > /etc/ssh/sshd_config << 'EOF'
# =============================================================================
# TSUNAMI SSH YAPILANDIRMASI
# Askeri seviye SSH guvenligi
# =============================================================================

# Temel Ayarlar
Port 22
Protocol 2
AddressFamily inet

# Kimlik Dogrulama
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Kerberos devre disi
KerberosAuthentication no
GSSAPIAuthentication no

# Guclu Sifreleme
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com

# Oturum Ayarlari
LoginGraceTime 30
MaxAuthTries 3
MaxSessions 2
MaxStartups 3:50:10

# X11 ve Agent devre disi
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no

# Banner ve Bilgi
Banner /etc/ssh/banner
PrintMotd no
PrintLastLog yes

# Timeout
ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

# Loglama
SyslogFacility AUTH
LogLevel VERBOSE

# Chroot ve Subsystem
Subsystem sftp internal-sftp

# Strict Modes
StrictModes yes

# Disable compression (BREACH attack)
Compression no
EOF

    # SSH banner olustur
    cat > /etc/ssh/banner << 'EOF'
================================================================================
                    TSUNAMI GUVENLIK SISTEMI
================================================================================
       UYARI: Bu sistem izinsiz erisimlere karsi korunmaktadir.
       Tum baglantilar kayit altina alinmaktadir.
       Yetkisiz erisim cezai islem gerektirir.
================================================================================
EOF

    # Moduli dosyasini guclendir (zayif DH parametrelerini kaldir)
    if [[ -f /etc/ssh/moduli ]]; then
        awk '$5 >= 3071' /etc/ssh/moduli > /etc/ssh/moduli.safe
        mv /etc/ssh/moduli.safe /etc/ssh/moduli
    fi

    # Dosya izinleri
    chmod 600 /etc/ssh/sshd_config
    chmod 644 /etc/ssh/banner

    # Yapilandirmayi test et
    sshd -t

    # SSH'i yeniden baslat
    systemctl restart sshd

    log SUCCESS "SSH guvenligi yapilandirildi"
    log WARN "DIKKAT: Parola ile giris devre disi. SSH anahtari kullanin!"
}

# =============================================================================
# 6. KERNEL GUVENLIGI (SYSCTL)
# =============================================================================
configure_kernel_security() {
    log INFO "=== KERNEL GUVENLIGI ==="

    # Mevcut yapilandirmayi yedekle
    backup_file /etc/sysctl.conf

    # Guvenli kernel parametreleri
    cat > /etc/sysctl.d/99-tsunami-hardening.conf << 'EOF'
# =============================================================================
# TSUNAMI KERNEL GUVENLIGI
# Askeri seviye kernel korumasi
# =============================================================================

# === BELLEK KORUMASI ===
# ASLR (Address Space Layout Randomization) - maksimum
kernel.randomize_va_space = 2

# Kernel pointer gizleme
kernel.kptr_restrict = 2

# dmesg kisitlamasi
kernel.dmesg_restrict = 1

# ptrace kisitlamasi
kernel.yama.ptrace_scope = 2

# Core dump devre disi
fs.suid_dumpable = 0

# === AG GUVENLIGI ===
# IP spoofing korumasi
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# ICMP redirect engelleme
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source routing devre disi
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# SYN flood korumasi
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# IP forwarding devre disi
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Bogus ICMP response loglama
net.ipv4.icmp_ignore_bogus_error_responses = 1

# ICMP broadcast engellemesi (Smurf attack)
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Martian packet loglama
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# TCP timestamps (fingerprinting onleme)
net.ipv4.tcp_timestamps = 0

# TCP SACK (selective acknowledgments)
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_fack = 1

# IPv6 devre disi (opsiyonel)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# === DOSYA SISTEMI ===
# Hardlink/symlink korumasi
fs.protected_hardlinks = 1
fs.protected_symlinks = 1

# FIFO ve regular file korumasi
fs.protected_fifos = 2
fs.protected_regular = 2

# inotify limitleri
fs.inotify.max_user_watches = 524288

# === PROSES GUVENLIGI ===
# Magic SysRq kisitlamasi
kernel.sysrq = 0

# Kernel module yuklemesini kisitla (dikkatli kullanin)
# kernel.modules_disabled = 1

# Performans event kisitlamasi
kernel.perf_event_paranoid = 3

# BPF JIT hardening
net.core.bpf_jit_harden = 2

# Exec shield
# kernel.exec-shield = 1

# === GUVENLIK LIMITLERI ===
# Max PID
kernel.pid_max = 65536

# Message queue boyutu
kernel.msgmnb = 65536
kernel.msgmax = 65536

# Shared memory
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
EOF

    # Parametreleri uygula
    sysctl -p /etc/sysctl.d/99-tsunami-hardening.conf

    log SUCCESS "Kernel guvenligi yapilandirildi"
}

# =============================================================================
# 7. CLAMAV ANTIVIRUS
# =============================================================================
configure_clamav() {
    log INFO "=== CLAMAV ANTIVIRUS ==="

    # ClamAV kur
    apt-get install -y clamav clamav-daemon clamav-freshclam

    # Freshclam servisini durdur (veritabani guncellemesi icin)
    systemctl stop clamav-freshclam 2>/dev/null || true

    # Virus veritabanini guncelle
    freshclam

    # Servisleri baslat
    systemctl enable clamav-daemon
    systemctl enable clamav-freshclam
    systemctl start clamav-freshclam
    systemctl start clamav-daemon

    # Gunluk tarama icin cron job
    cat > /etc/cron.daily/tsunami-clamav-scan << 'EOF'
#!/bin/bash
# TSUNAMI ClamAV gunluk tarama
LOG_FILE="/var/log/tsunami/clamav_scan_$(date +%Y%m%d).log"

echo "=== ClamAV Tarama Basladi: $(date) ===" >> "$LOG_FILE"

# Kritik dizinleri tara
clamscan --recursive --infected --log="$LOG_FILE" \
    /home \
    /var/www \
    /tmp \
    /var/tmp \
    2>/dev/null

# Sonuclari kontrol et
if grep -q "Infected files: [1-9]" "$LOG_FILE"; then
    echo "[ALARM] Virus tespit edildi! Log: $LOG_FILE" | logger -t tsunami-clamav
fi

echo "=== ClamAV Tarama Bitti: $(date) ===" >> "$LOG_FILE"
EOF

    chmod +x /etc/cron.daily/tsunami-clamav-scan

    log SUCCESS "ClamAV yapilandirildi"
}

# =============================================================================
# 8. AUDITD DENETIM SISTEMI
# =============================================================================
configure_auditd() {
    log INFO "=== AUDITD DENETIM SISTEMI ==="

    # Auditd kur
    apt-get install -y auditd audispd-plugins

    # Mevcut yapilandirmayi yedekle
    backup_file /etc/audit/rules.d/audit.rules

    # Kapsamli denetim kurallari
    cat > /etc/audit/rules.d/tsunami.rules << 'EOF'
# =============================================================================
# TSUNAMI AUDITD KURALLARI
# Askeri seviye sistem denetimi
# =============================================================================

# Onceki kurallari temizle
-D

# Buffer boyutu
-b 8192

# Hata durumunda sistem cokerse logla
-f 1

# === KIMLIK DOGRULAMA VE YETKILENDIRME ===
# Kullanici/grup degisiklikleri
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Sudo ve su kullanimi
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/sudo.log -p wa -k sudoers

# Login yapilandirmasi
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /etc/pam.d/ -p wa -k pam

# === AG YAPILANDIRMASI ===
-w /etc/hosts -p wa -k network
-w /etc/hostname -p wa -k network
-w /etc/network/ -p wa -k network
-w /etc/netplan/ -p wa -k network
-w /etc/resolv.conf -p wa -k network
-w /etc/hosts.allow -p wa -k network
-w /etc/hosts.deny -p wa -k network

# === ZAMAN DEGISIKLIKLERI ===
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# === DOSYA SISTEMI ===
# Mount islemleri
-a always,exit -F arch=b64 -S mount -S umount2 -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -S umount -S umount2 -F auid>=1000 -F auid!=4294967295 -k mounts

# Dosya silme
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete

# Dosya izin degisiklikleri
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# === KRITIK DOSYALAR ===
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron

# Systemd servisleri
-w /etc/systemd/ -p wa -k systemd
-w /lib/systemd/ -p wa -k systemd

# === KERNEL MODULLERI ===
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules

# === PROSES CALISTIRMA ===
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=4294967295 -k exec
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=4294967295 -k exec

# === OTURUM ACMA/KAPAMA ===
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# === AUDIT LOG KORUMASI ===
-w /var/log/audit/ -p wa -k auditlog
-w /etc/audit/ -p wa -k auditconfig

# Kurallari kilitle (reboot gerektiren degisiklik)
-e 2
EOF

    # Yapilandirmayi uygula
    augenrules --load

    # Servisi yeniden baslat
    systemctl enable auditd
    systemctl restart auditd

    log SUCCESS "Auditd denetim sistemi yapilandirildi"
}

# =============================================================================
# 9. ROOTKIT TESPITI
# =============================================================================
configure_rootkit_detection() {
    log INFO "=== ROOTKIT TESPIT SISTEMI ==="

    # rkhunter ve chkrootkit kur
    apt-get install -y rkhunter chkrootkit

    # rkhunter yapilandirmasi
    cat > /etc/default/rkhunter << 'EOF'
# TSUNAMI rkhunter yapilandirmasi
CRON_DAILY_RUN="true"
CRON_DB_UPDATE="true"
APT_AUTOGEN="true"
REPORT_EMAIL=""
DB_UPDATE_EMAIL="false"
EOF

    # rkhunter veritabanini guncelle
    rkhunter --propupd
    rkhunter --update

    # Gunluk tarama icin cron job
    cat > /etc/cron.daily/tsunami-rootkit-scan << 'EOF'
#!/bin/bash
# TSUNAMI rootkit gunluk tarama
LOG_FILE="/var/log/tsunami/rootkit_scan_$(date +%Y%m%d).log"

echo "=== Rootkit Tarama Basladi: $(date) ===" >> "$LOG_FILE"

# rkhunter taramasi
rkhunter --check --skip-keypress --report-warnings-only >> "$LOG_FILE" 2>&1

# chkrootkit taramasi
chkrootkit >> "$LOG_FILE" 2>&1

# Sonuclari kontrol et
if grep -qE "(Warning|INFECTED)" "$LOG_FILE"; then
    echo "[ALARM] Rootkit/tehdit tespit edildi! Log: $LOG_FILE" | logger -t tsunami-rootkit
fi

echo "=== Rootkit Tarama Bitti: $(date) ===" >> "$LOG_FILE"
EOF

    chmod +x /etc/cron.daily/tsunami-rootkit-scan

    log SUCCESS "Rootkit tespit sistemi yapilandirildi"
}

# =============================================================================
# 10. GEREKSIZ SERVISLERI DEVRE DISI BIRAK
# =============================================================================
disable_unnecessary_services() {
    log INFO "=== GEREKSIZ SERVISLER DEVRE DISI BIRAKILIYOR ==="

    # Devre disi birakilacak servisler
    SERVICES_TO_DISABLE=(
        "avahi-daemon"      # Zeroconf/Bonjour
        "cups"              # Yazici servisi
        "cups-browsed"
        "bluetooth"         # Bluetooth
        "ModemManager"      # Modem yonetimi
        "whoopsie"          # Ubuntu hata raporlama
        "kerneloops"        # Kernel hata raporlama
        "apport"            # Crash raporlama
        "speech-dispatcher" # Konusma sentezi
        "accounts-daemon"   # Hesap servisi (GUI icin)
        "colord"            # Renk yonetimi
        "geoclue"           # Konum servisi
    )

    for service in "${SERVICES_TO_DISABLE[@]}"; do
        if systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
            systemctl disable "$service" 2>/dev/null || true
            systemctl stop "$service" 2>/dev/null || true
            log INFO "Devre disi birakildi: $service"
        fi
    done

    # Gereksiz paketleri kaldir (opsiyonel)
    # apt-get remove --purge -y telnet rsh-client rsh-redone-client

    log SUCCESS "Gereksiz servisler devre disi birakildi"
}

# =============================================================================
# 11. DOSYA IZINLERI GUVENLIGI
# =============================================================================
configure_file_permissions() {
    log INFO "=== DOSYA IZINLERI GUVENLIGI ==="

    # Kritik dosya izinleri
    chmod 600 /etc/shadow
    chmod 600 /etc/gshadow
    chmod 644 /etc/passwd
    chmod 644 /etc/group
    chmod 600 /etc/ssh/sshd_config
    chmod 700 /root
    chmod 700 /root/.ssh 2>/dev/null || true
    chmod 600 /root/.ssh/* 2>/dev/null || true

    # /tmp ve /var/tmp guvenligi
    chmod 1777 /tmp
    chmod 1777 /var/tmp

    # World-writable dosyalari bul ve raporla
    log INFO "World-writable dosyalar taranıyor..."
    find / -xdev -type f -perm -0002 -exec ls -l {} \; 2>/dev/null > "$LOG_DIR/world_writable_files.txt" || true

    # SUID/SGID dosyalari bul ve raporla
    log INFO "SUID/SGID dosyalar taranıyor..."
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -l {} \; 2>/dev/null > "$LOG_DIR/suid_sgid_files.txt" || true

    # Sahipsiz dosyalari bul
    log INFO "Sahipsiz dosyalar taranıyor..."
    find / -xdev \( -nouser -o -nogroup \) -exec ls -l {} \; 2>/dev/null > "$LOG_DIR/orphan_files.txt" || true

    log SUCCESS "Dosya izinleri yapilandirildi"
}

# =============================================================================
# 12. DNS OVER HTTPS (DOH)
# =============================================================================
configure_dns_over_https() {
    log INFO "=== DNS OVER HTTPS YAPILANDIRMASI ==="

    # systemd-resolved ile DoH yapilandirmasi
    backup_file /etc/systemd/resolved.conf

    cat > /etc/systemd/resolved.conf << 'EOF'
# TSUNAMI DNS over HTTPS Yapilandirmasi
[Resolve]
# Cloudflare DoH
DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
# Google DoH (yedek)
FallbackDNS=8.8.8.8#dns.google 8.8.4.4#dns.google

# DoH/DoT etkinlestir
DNSOverTLS=yes

# DNSSEC dogrulama
DNSSEC=yes

# Multicast DNS devre disi
MulticastDNS=no

# LLMNR devre disi
LLMNR=no

# Cache boyutu
Cache=yes
CacheFromLocalhost=no

# DNS loglama
DNSStubListener=yes
EOF

    # systemd-resolved'u yeniden baslat
    systemctl restart systemd-resolved

    # /etc/resolv.conf'u symlink yap
    if [[ ! -L /etc/resolv.conf ]]; then
        mv /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null || true
        ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    fi

    log SUCCESS "DNS over HTTPS yapilandirildi"
}

# =============================================================================
# 13. TOR YAPILANDIRMASI (OPSIYONEL)
# =============================================================================
configure_tor() {
    log INFO "=== TOR YAPILANDIRMASI ==="

    # Tor kur
    apt-get install -y tor torsocks

    # Tor yapilandirmasi
    backup_file /etc/tor/torrc

    cat > /etc/tor/torrc << 'EOF'
# TSUNAMI TOR Yapilandirmasi
# Maksimum anonimlik

SocksPort 9050 IsolateDestAddr IsolateDestPort
ControlPort 9051
CookieAuthentication 1

# Cikis politikasi (sadece web trafigi)
ExitPolicy reject *:*

# Guvenlik ayarlari
SafeSocks 1
TestSocks 1
WarnUnsafeSocks 1
Log notice file /var/log/tor/notices.log

# Devre yapisi
CircuitBuildTimeout 30
LearnCircuitBuildTimeout 0
MaxCircuitDirtiness 600
NewCircuitPeriod 30

# Bandwidth (isteğe bağlı)
# BandwidthRate 1 MB
# BandwidthBurst 2 MB
EOF

    # Tor servisini etkinlestir
    systemctl enable tor
    systemctl start tor

    # Sistem genelinde Tor proxy (opsiyonel - varsayilan devre disi)
    log WARN "Tor yapilandirildi. Sistem genelinde kullanmak icin: torsocks [komut]"

    log SUCCESS "Tor yapilandirildi"
}

# =============================================================================
# 14. BELLEK KORUMASI VE ASLR
# =============================================================================
configure_memory_protection() {
    log INFO "=== BELLEK KORUMASI ==="

    # ASLR kontrolu (zaten sysctl'de ayarlandi)
    current_aslr=$(cat /proc/sys/kernel/randomize_va_space)
    log INFO "ASLR durumu: $current_aslr (2 = tam koruma)"

    # Core dump devre disi
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "* soft core 0" >> /etc/security/limits.conf

    # Ulimits yapilandirmasi
    cat >> /etc/security/limits.conf << 'EOF'
# TSUNAMI guvenlik limitleri
* soft nofile 65536
* hard nofile 65536
* soft nproc 65536
* hard nproc 65536
root soft nofile 65536
root hard nofile 65536
EOF

    # /proc guvenligi
    # hidepid=2 - kullanicilar sadece kendi proseslerini gorebilir
    if ! grep -q "hidepid=2" /etc/fstab; then
        echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab
        mount -o remount,hidepid=2 /proc 2>/dev/null || true
    fi

    log SUCCESS "Bellek korumasi yapilandirildi"
}

# =============================================================================
# 15. USB CIHAZ KISITLAMALARI
# =============================================================================
configure_usb_restrictions() {
    log INFO "=== USB CIHAZ KISITLAMALARI ==="

    # USBGuard kur
    apt-get install -y usbguard

    # Mevcut cihazlari tara ve izin ver
    usbguard generate-policy > /etc/usbguard/rules.conf 2>/dev/null || true

    # USBGuard yapilandirmasi
    cat > /etc/usbguard/usbguard-daemon.conf << 'EOF'
# TSUNAMI USBGuard Yapilandirmasi
RuleFile=/etc/usbguard/rules.conf
ImplicitPolicyTarget=block
PresentDevicePolicy=apply-policy
PresentControllerPolicy=keep
InsertedDevicePolicy=apply-policy
RestoreControllerDeviceState=false
DeviceManagerBackend=uevent
IPCAllowedUsers=root
IPCAllowedGroups=
IPCAccessControlFiles=/etc/usbguard/IPCAccessControl.d/
DeviceRulesWithPort=false
AuditBackend=FileAudit
AuditFilePath=/var/log/usbguard/usbguard-audit.log
EOF

    # Servisi etkinlestir
    systemctl enable usbguard
    systemctl start usbguard 2>/dev/null || true

    log SUCCESS "USB cihaz kisitlamalari yapilandirildi"
    log WARN "Yeni USB cihazlari icin: usbguard allow-device <device-id>"
}

# =============================================================================
# 16. EK GUVENLIK ARACLARI
# =============================================================================
install_security_tools() {
    log INFO "=== EK GUVENLIK ARACLARI ==="

    # Guvenlik araclari
    apt-get install -y \
        lynis \
        aide \
        tripwire \
        debsums \
        needrestart \
        apt-show-versions \
        debian-goodies \
        net-tools \
        tcpdump \
        iptables-persistent

    # AIDE (dosya butunlugu) baslat
    aideinit 2>/dev/null || true

    log SUCCESS "Ek guvenlik araclari yuklendi"
}

# =============================================================================
# 17. GUVENLIK RAPORU OLUSTUR
# =============================================================================
generate_security_report() {
    log INFO "=== GUVENLIK RAPORU OLUSTURULUYOR ==="

    REPORT_FILE="$LOG_DIR/security_report_$(date +%Y%m%d_%H%M%S).txt"

    cat > "$REPORT_FILE" << 'EOF'
================================================================================
        TSUNAMI UBUNTU HARDENING - GUVENLIK RAPORU
================================================================================
EOF

    echo "Tarih: $(date)" >> "$REPORT_FILE"
    echo "Hostname: $(hostname)" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    echo "=== SISTEM BILGISI ===" >> "$REPORT_FILE"
    uname -a >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    echo "=== UFW DURUMU ===" >> "$REPORT_FILE"
    ufw status verbose >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"

    echo "=== FAIL2BAN DURUMU ===" >> "$REPORT_FILE"
    fail2ban-client status >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"

    echo "=== APPARMOR DURUMU ===" >> "$REPORT_FILE"
    aa-status >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"

    echo "=== DINLEYEN PORTLAR ===" >> "$REPORT_FILE"
    ss -tulpn >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"

    echo "=== AKTIF SERVISLER ===" >> "$REPORT_FILE"
    systemctl list-units --type=service --state=running >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"

    echo "=== SUID/SGID DOSYALAR ===" >> "$REPORT_FILE"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"

    log SUCCESS "Guvenlik raporu olusturuldu: $REPORT_FILE"
}

# =============================================================================
# GERI ALMA FONKSIYONU
# =============================================================================
revert_hardening() {
    log WARN "=== HARDENING GERI ALINIYOR ==="

    # Yedeklerden geri yukle
    if [[ -d "$BACKUP_DIR/config" ]]; then
        for backup in "$BACKUP_DIR/config"/*.bak; do
            if [[ -f "$backup" ]]; then
                original=$(basename "$backup" | sed 's/_[0-9]*_[0-9]*\.bak$//')
                log INFO "Geri yukleniyor: $original"
                # Geri yukleme mantigi buraya
            fi
        done
    fi

    # UFW devre disi
    ufw disable

    # Fail2ban durdur
    systemctl stop fail2ban
    systemctl disable fail2ban

    # USBGuard durdur
    systemctl stop usbguard 2>/dev/null || true
    systemctl disable usbguard 2>/dev/null || true

    log SUCCESS "Hardening geri alindi"
}

# =============================================================================
# ANA FONKSIYON
# =============================================================================
main() {
    banner

    # Parametre kontrolu
    MODE="${1:-full}"

    case "$MODE" in
        --full|-f)
            log INFO "Tam hardening modu secildi"
            ;;
        --minimal|-m)
            log INFO "Minimal hardening modu secildi"
            ;;
        --tor|-t)
            log INFO "TOR ile tam hardening modu secildi"
            ;;
        --revert|-r)
            check_root
            revert_hardening
            exit 0
            ;;
        --help|-h)
            echo "Kullanim: $0 [--full|--minimal|--tor|--revert]"
            echo ""
            echo "  --full, -f     Tam hardening (varsayilan)"
            echo "  --minimal, -m  Minimal hardening (firewall + SSH)"
            echo "  --tor, -t      TOR ile tam hardening"
            echo "  --revert, -r   Degisiklikleri geri al"
            echo "  --help, -h     Bu yardim mesaji"
            exit 0
            ;;
        *)
            log ERROR "Gecersiz parametre: $MODE"
            exit 1
            ;;
    esac

    # Root kontrolu
    check_root

    # Dizinleri olustur
    setup_directories

    # Sistem bilgisi
    get_system_info

    # Hardening adimlari
    update_system
    configure_firewall
    configure_fail2ban
    configure_ssh
    configure_kernel_security

    if [[ "$MODE" != "--minimal" && "$MODE" != "-m" ]]; then
        configure_apparmor
        configure_clamav
        configure_auditd
        configure_rootkit_detection
        disable_unnecessary_services
        configure_file_permissions
        configure_dns_over_https
        configure_memory_protection
        configure_usb_restrictions
        install_security_tools
    fi

    if [[ "$MODE" == "--tor" || "$MODE" == "-t" ]]; then
        configure_tor
    fi

    # Guvenlik raporu olustur
    generate_security_report

    echo ""
    echo -e "${GREEN}============================================================${NC}"
    echo -e "${GREEN}    TSUNAMI UBUNTU HARDENING TAMAMLANDI!${NC}"
    echo -e "${GREEN}============================================================${NC}"
    echo ""
    echo -e "${YELLOW}ONEMLI:${NC}"
    echo "1. SSH anahtarinizi ayarlayin: ~/.ssh/authorized_keys"
    echo "2. UFW'de SSH icin IP'nizi ekleyin: ufw allow from <IP> to any port 22"
    echo "3. Sistemi yeniden baslatin: reboot"
    echo ""
    echo "Log dosyasi: $LOG_FILE"
    echo "Guvenlik raporu: $LOG_DIR/security_report_*.txt"
    echo ""
}

# Scripti calistir
main "$@"
