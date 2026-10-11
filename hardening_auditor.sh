#!/usr/bin/env bash
#===============================================================================
#  hardening_auditor.sh  -  Linux System Hardening Auditor
#
#  Read-only security audit for a Linux machine. It checks users, SSH, firewall,
#  network exposure, kernel settings, file permissions, patching, risky services,
#  cron jobs and logging/access-control tools. Every check is scored; at the end
#  you get a security score (0-100), a grade (A-F) and a list of fixes.
#
#  SAFE: this script only READS system state. It never changes anything.
#  Use it only on systems you own or have written permission to audit.
#
#  Usage:   sudo ./hardening_auditor.sh [options]      (run ./hardening_auditor.sh -h)
#===============================================================================

VERSION="1.0.0"
SCRIPT_NAME=$(basename "$0")

# ------------------------------- globals -------------------------------------
USE_COLOR=1
FAST=0
TXT_REPORT=""
HTML_REPORT=""
SCORE_MAX=0          # scores are kept in half-points so WARN can earn half credit
SCORE_GOT=0
N_PASS=0; N_WARN=0; N_FAIL=0; N_INFO=0
CUR_SECTION=""
declare -a R_SECTION R_STATUS R_TITLE R_DETAIL R_FIX
declare -a FIXES

# Ports that should basically never be exposed (legacy / cleartext protocols)
LEGACY_PORTS="21 23 69 79 512 513 514"
# Ports that are fine locally but risky when open to the whole network
RISKY_PORTS="111 2049 3306 5432 6379 11211 27017 9200 5900 1433 445 139"
# Services that should not be running on a hardened machine
BAD_SERVICES="telnet.socket telnetd rsh.socket rlogin.socket rexec.socket vsftpd tftpd-hpa xinetd inetd"
MEH_SERVICES="avahi-daemon cups rpcbind smbd nfs-server snmpd"
# SUID binaries that are normal on most Linux systems
KNOWN_SUID='^(passwd|su|sudo|sudoedit|mount|umount|ping|ping6|chsh|chfn|newgrp|gpasswd|pkexec|fusermount|fusermount3|ssh-keysign|chage|expiry|unix_chkpwd|polkit-agent-helper-1|dbus-daemon-launch-helper|Xorg.wrap|at|crontab|newuidmap|newgidmap|mount.nfs|pppd|snap-confine|ntfs-3g|arping|traceroute6.iputils|mtr-packet|wall|write|bsd-write|ssh-agent|userhelper|pam_timestamp_check|unix2_chkpwd|dotlockfile|lockfile|procmail|exim4)$'

# ------------------------------- helpers -------------------------------------
have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ $EUID -eq 0 ]]; }
tmo()     { if have timeout; then timeout "$@"; else shift; "$@"; fi; }
svc_active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }

html_esc() {
    local s=$1
    s=${s//&/&amp;}; s=${s//</&lt;}; s=${s//>/&gt;}
    printf '%s' "$s"
}

init_colors() {
    if [[ $USE_COLOR -eq 1 && -t 1 ]]; then
        RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'
        BLU=$'\033[1;34m'; CYN=$'\033[1;36m'; DIM=$'\033[2m'
        BLD=$'\033[1m';    RST=$'\033[0m'
    else
        RED=""; GRN=""; YEL=""; BLU=""; CYN=""; DIM=""; BLD=""; RST=""
    fi
}

# Print a line to the screen (with colours) and to the text report (without).
say() {
    printf '%s\n' "$1"
    if [[ -n $TXT_REPORT ]]; then
        printf '%s\n' "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$TXT_REPORT"
    fi
}

banner() {
    say "${CYN}"
    say "  _   _                 _            _             _             _ _ _             "
    say " | | | | __ _ _ __ __| | ___ _ __ (_)_ __   __ _ / \\  _   _  __| (_) |_ ___  _ __ "
    say " | |_| |/ _\` | '__/ _\` |/ _ \\ '_ \\| | '_ \\ / _\` / _ \\| | | |/ _\` | | __/ _ \\| '__|"
    say " |  _  | (_| | | | (_| |  __/ | | | | | | | (_| / ___ \\ |_| | (_| | | || (_) | |   "
    say " |_| |_|\\__,_|_|  \\__,_|\\___|_| |_|_|_| |_|\\__, /_/   \\_\\__,_|\\__,_|_|\\__\\___/|_|   "
    say "                                           |___/                                   ${RST}"
    say "  ${BLD}Linux System Hardening Auditor v${VERSION}${RST}  ${DIM}(read-only, changes nothing)${RST}"
}

section() {
    CUR_SECTION=$1
    say ""
    say "${BLU}=== $1 ===${RST}"
}

# record STATUS WEIGHT TITLE DETAIL [FIX]
#   STATUS: PASS | WARN | FAIL | INFO     WEIGHT: 1-5 (importance), 0 for INFO
record() {
    local status=$1 weight=$2 title=$3 detail=$4 fix=${5:-} tag idx
    case $status in
        PASS) tag="${GRN}[ PASS ]${RST}"; ((N_PASS++))
              SCORE_MAX=$((SCORE_MAX + weight*2)); SCORE_GOT=$((SCORE_GOT + weight*2)) ;;
        WARN) tag="${YEL}[ WARN ]${RST}"; ((N_WARN++))
              SCORE_MAX=$((SCORE_MAX + weight*2)); SCORE_GOT=$((SCORE_GOT + weight)) ;;
        FAIL) tag="${RED}[ FAIL ]${RST}"; ((N_FAIL++))
              SCORE_MAX=$((SCORE_MAX + weight*2)) ;;
        *)    tag="${CYN}[ INFO ]${RST}"; ((N_INFO++)); status=INFO ;;
    esac
    idx=${#R_STATUS[@]}
    R_SECTION[idx]=$CUR_SECTION; R_STATUS[idx]=$status; R_TITLE[idx]=$title
    R_DETAIL[idx]=$detail;       R_FIX[idx]=$fix

    say "$tag $title"
    [[ -n $detail ]] && say "         ${DIM}${detail}${RST}"
    if [[ $status != PASS && $status != INFO && -n $fix ]]; then
        say "         ${CYN}Fix:${RST} $fix"
        FIXES+=("[$status] $title  ->  $fix")
    fi
}

# Read one sshd option (lower-case value). Uses 'sshd -T' as root, else parses files.
sshd_opt() {
    local key=$1 val=""
    if is_root && have sshd; then
        val=$(sshd -T 2>/dev/null | awk -v k="${key,,}" '$1==k {print $2; exit}')
    fi
    if [[ -z $val ]]; then
        val=$(grep -hiE "^[[:space:]]*${key}[[:space:]]+" \
              /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null \
              | head -n1 | awk '{print tolower($2)}')
    fi
    printf '%s' "$val"
}

# sysctl_check KEY EXPECTED_REGEX WEIGHT TITLE
sysctl_check() {
    local key=$1 exp=$2 w=$3 title=$4 p="/proc/sys/${1//.//}" val sev=FAIL
    (( w < 3 )) && sev=WARN
    if [[ ! -r $p ]]; then
        record INFO 0 "$title" "$key is not available on this kernel"; return
    fi
    val=$(<"$p")
    if [[ $val =~ ^($exp)$ ]]; then
        record PASS "$w" "$title" "$key = $val"
    else
        record "$sev" "$w" "$title" "$key = $val (expected: $exp)" \
            "echo '$key = ${exp%%|*}' | sudo tee -a /etc/sysctl.d/99-hardening.conf && sudo sysctl --system"
    fi
}

# perm_check FILE MAXMODE WEIGHT   (fails if the file allows anything beyond MAXMODE)
perm_check() {
    local f=$1 max=$2 w=$3 mode
    [[ -e $f ]] || return
    mode=$(stat -c '%a' "$f" 2>/dev/null) || return
    if (( (8#$mode & ~8#$max) & 8#777 )); then
        record FAIL "$w" "Permissions on $f" "mode $mode (should be $max or stricter)" "sudo chmod $max $f"
    else
        record PASS "$w" "Permissions on $f" "mode $mode"
    fi
}

# ------------------------------- audit modules -------------------------------
audit_system() {
    section "SYSTEM INFORMATION"
    local os="unknown"
    [[ -r /etc/os-release ]] && os=$(. /etc/os-release && echo "${PRETTY_NAME:-$NAME}")
    record INFO 0 "Host"        "$(hostname) | $os"
    record INFO 0 "Kernel"      "$(uname -r) ($(uname -m))"
    record INFO 0 "Uptime"      "$(uptime -p 2>/dev/null || uptime)"
    record INFO 0 "Run as"      "$(id -un) (uid $EUID)"
    if ! is_root; then
        record INFO 0 "Limited mode" "Not running as root - some checks are skipped. Re-run with sudo for a full audit."
    fi
}

audit_users() {
    section "USERS & AUTHENTICATION"
    local extra
    extra=$(awk -F: '$3==0 && $1!="root" {print $1}' /etc/passwd | tr '\n' ' ')
    if [[ -z $extra ]]; then
        record PASS 5 "Only root has UID 0" "no hidden superuser accounts"
    else
        record FAIL 5 "Extra accounts with UID 0" "found: $extra" \
            "Investigate immediately; remove with 'sudo userdel <user>' if not legitimate"
    fi

    if is_root && [[ -r /etc/shadow ]]; then
        local empty
        empty=$(awk -F: '$2=="" {print $1}' /etc/shadow | tr '\n' ' ')
        if [[ -z $empty ]]; then
            record PASS 5 "No accounts with empty passwords" "checked /etc/shadow"
        else
            record FAIL 5 "Accounts with EMPTY passwords" "found: $empty" "sudo passwd <user>   (or lock: sudo passwd -l <user>)"
        fi
    else
        record INFO 0 "Empty-password check" "needs root to read /etc/shadow - skipped"
    fi

    local maxd
    maxd=$(awk '/^[[:space:]]*PASS_MAX_DAYS/ {print $2; exit}' /etc/login.defs 2>/dev/null)
    if [[ $maxd =~ ^[0-9]+$ ]]; then
        if (( maxd > 0 && maxd <= 90 )); then
            record PASS 2 "Password expiry policy" "PASS_MAX_DAYS = $maxd"
        else
            record WARN 2 "Passwords never/rarely expire" "PASS_MAX_DAYS = $maxd" \
                "Set 'PASS_MAX_DAYS 90' in /etc/login.defs"
        fi
    fi

    if grep -rqsE 'pam_pwquality|pam_cracklib|pam_passwdqc' /etc/pam.d 2>/dev/null; then
        record PASS 3 "Password complexity enforced (PAM)" "pwquality/cracklib module found in /etc/pam.d"
    else
        record WARN 3 "No password complexity module in PAM" "weak passwords are accepted" \
            "Install libpam-pwquality (Debian/Ubuntu) or libpwquality (RHEL) and configure it"
    fi

    if is_root; then
        local nopw
        nopw=$(grep -rhsE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null | head -n3 | tr '\n' ';')
        if [[ -z $nopw ]]; then
            record PASS 3 "No passwordless sudo rules" "no NOPASSWD entries in sudoers"
        else
            record WARN 3 "Passwordless sudo configured" "$nopw" "Remove NOPASSWD entries using 'sudo visudo'"
        fi
    else
        record INFO 0 "Sudoers check" "needs root - skipped"
    fi

    local humans
    humans=$(awk -F: '$3>=1000 && $3<60000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd | tr '\n' ' ')
    record INFO 0 "Human accounts with a login shell" "${humans:-none}"
}

audit_ssh() {
    section "SSH SERVER"
    if ! have sshd && [[ ! -f /etc/ssh/sshd_config ]]; then
        record INFO 0 "SSH server" "OpenSSH server not installed - nothing to check"
        return
    fi
    local v

    v=$(sshd_opt permitrootlogin); v=${v:-prohibit-password}
    case $v in
        no)                                   record PASS 5 "SSH root login disabled" "PermitRootLogin $v" ;;
        prohibit-password|without-password|forced-commands-only)
                                              record PASS 4 "SSH root login: key-only" "PermitRootLogin $v" ;;
        *) record FAIL 5 "SSH root login allowed with password" "PermitRootLogin $v" \
               "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then 'sudo systemctl restart ssh'" ;;
    esac

    v=$(sshd_opt passwordauthentication); v=${v:-yes}
    if [[ $v == no ]]; then
        record PASS 4 "SSH password login disabled (keys only)" "PasswordAuthentication $v"
    else
        record WARN 4 "SSH allows password login" "PasswordAuthentication $v (brute-force target)" \
            "Use SSH keys, then set 'PasswordAuthentication no'"
    fi

    v=$(sshd_opt permitemptypasswords); v=${v:-no}
    if [[ $v == no ]]; then
        record PASS 5 "SSH rejects empty passwords" "PermitEmptyPasswords $v"
    else
        record FAIL 5 "SSH accepts empty passwords" "PermitEmptyPasswords $v" "Set 'PermitEmptyPasswords no'"
    fi

    v=$(sshd_opt maxauthtries); v=${v:-6}
    if [[ $v =~ ^[0-9]+$ ]] && (( v <= 4 )); then
        record PASS 2 "SSH MaxAuthTries is low" "MaxAuthTries $v"
    else
        record WARN 2 "SSH MaxAuthTries too high" "MaxAuthTries $v" "Set 'MaxAuthTries 3'"
    fi

    v=$(sshd_opt x11forwarding); v=${v:-no}
    if [[ $v == no ]]; then
        record PASS 1 "SSH X11 forwarding disabled" "X11Forwarding $v"
    else
        record WARN 1 "SSH X11 forwarding enabled" "X11Forwarding $v" "Set 'X11Forwarding no' unless you need it"
    fi

    v=$(sshd_opt port); v=${v:-22}
    if [[ $v != 22 ]]; then
        record PASS 1 "SSH on non-default port" "Port $v (reduces automated noise, not real security)"
    else
        record WARN 1 "SSH on default port 22" "constantly scanned by bots" \
            "Optional: change 'Port' (always combine with keys + fail2ban)"
    fi
}

audit_firewall() {
    section "FIREWALL"
    local fw="" s
    for s in ufw firewalld nftables; do
        if svc_active "$s"; then fw=$s; break; fi
    done
    if [[ -z $fw ]] && is_root && have iptables; then
        (( $(iptables -S 2>/dev/null | grep -c '^-A') > 0 )) && fw="iptables rules"
    fi
    if [[ -n $fw ]]; then
        record PASS 5 "Firewall is active" "detected: $fw"
        if [[ $fw == ufw ]] && is_root && have ufw; then
            if ufw status verbose 2>/dev/null | grep -qiE 'Default:.*deny \(incoming\)'; then
                record PASS 3 "Firewall default policy: deny incoming" "ufw default incoming = deny"
            else
                record WARN 3 "Firewall default incoming policy is not 'deny'" "ufw status verbose" "sudo ufw default deny incoming"
            fi
        fi
    elif is_root; then
        record FAIL 5 "No active firewall" "no ufw / firewalld / nftables / iptables rules found" \
            "sudo apt install ufw && sudo ufw default deny incoming && sudo ufw allow ssh && sudo ufw enable"
    else
        record WARN 5 "No firewall service detected" "iptables rules need root to read - re-run with sudo to be sure" \
            "Enable ufw or firewalld"
    fi
}

audit_network() {
    section "NETWORK EXPOSURE"
    if ! have ss; then
        record INFO 0 "Listening ports" "'ss' not found - skipped"
    else
        local proto addr host port entry
        local -a exposed=() r_fail=() r_warn=()
        while read -r proto addr; do
            host=${addr%:*}; port=${addr##*:}
            case $host in 0.0.0.0|'*'|'[::]'|'::') ;; *) continue ;; esac
            entry="$proto/$port"
            exposed+=("$entry")
            if   [[ " $LEGACY_PORTS " == *" $port "* ]]; then r_fail+=("$entry")
            elif [[ " $RISKY_PORTS  " == *" $port "* ]]; then r_warn+=("$entry")
            fi
        done < <(ss -tuln 2>/dev/null | awk 'NR>1 {print $1, $5}')

        local list
        list=$(printf '%s\n' "${exposed[@]}" | sort -u | tr '\n' ' ')
        record INFO 0 "Ports listening on ALL interfaces" "${list:-none}"

        if (( ${#r_fail[@]} )); then
            record FAIL 5 "Legacy/cleartext services exposed" "$(printf '%s ' "${r_fail[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')" \
                "Stop and disable them; use SSH/SFTP instead of telnet/ftp/rsh"
        else
            record PASS 5 "No legacy cleartext services exposed" "telnet/ftp/rsh/tftp not listening"
        fi
        if (( ${#r_warn[@]} )); then
            record WARN 3 "Sensitive services exposed to the network" "$(printf '%s\n' "${r_warn[@]}" | sort -u | tr '\n' ' ')" \
                "Bind databases/RPC to 127.0.0.1 or block them in the firewall"
        else
            record PASS 3 "No databases/RPC exposed on all interfaces" "checked common sensitive ports"
        fi
    fi
}

audit_kernel() {
    section "KERNEL & NETWORK HARDENING (sysctl)"
    sysctl_check kernel.randomize_va_space          "2"   4 "ASLR fully enabled"
    sysctl_check net.ipv4.tcp_syncookies            "1"   3 "SYN cookies (SYN-flood protection)"
    sysctl_check net.ipv4.conf.all.accept_redirects "0"   3 "ICMP redirects ignored"
    sysctl_check net.ipv4.conf.all.send_redirects   "0"   2 "ICMP redirects not sent"
    sysctl_check net.ipv4.conf.all.accept_source_route "0" 3 "Source-routed packets rejected"
    sysctl_check net.ipv4.conf.all.rp_filter        "1|2" 2 "Reverse-path filtering (anti-spoofing)"
    sysctl_check net.ipv4.icmp_echo_ignore_broadcasts "1" 2 "Ignore ICMP broadcast (smurf protection)"
    sysctl_check net.ipv4.ip_forward                "0"   2 "IP forwarding disabled (unless this is a router)"
    sysctl_check kernel.kptr_restrict               "1|2" 2 "Kernel pointers hidden from users"
    sysctl_check kernel.dmesg_restrict              "1"   2 "dmesg restricted to root"
    sysctl_check fs.suid_dumpable                   "0"   2 "No core dumps from SUID programs"
    sysctl_check kernel.yama.ptrace_scope           "1|2|3" 2 "ptrace restricted (Yama)"
}

audit_files() {
    section "FILE PERMISSIONS"
    perm_check /etc/passwd          644 4
    perm_check /etc/group           644 3
    perm_check /etc/shadow          640 5
    perm_check /etc/gshadow         640 4
    perm_check /etc/ssh/sshd_config 644 3
    perm_check /etc/crontab         644 2
    perm_check /root                750 3

    local ww
    ww=$(tmo 60 find /etc /usr/bin /usr/sbin /bin /sbin -xdev -type f -perm -0002 2>/dev/null | head -n 10)
    if [[ -z $ww ]]; then
        record PASS 4 "No world-writable system files" "checked /etc /usr/bin /usr/sbin /bin /sbin"
    else
        record FAIL 4 "World-writable system files found" "$(echo "$ww" | tr '\n' ' ')" "sudo chmod o-w <file>"
    fi

    if (( FAST )); then
        record INFO 0 "SUID / orphan-file scans" "skipped (--fast)"
        return
    fi

    local unusual n
    unusual=$(tmo 90 find /usr /bin /sbin /opt -xdev -type f -perm -4000 2>/dev/null | while read -r f; do
                  [[ ${f##*/} =~ $KNOWN_SUID ]] || echo "$f"
              done)
    n=$(printf '%s' "$unusual" | grep -c .)
    if (( n == 0 )); then
        record PASS 4 "No unusual SUID binaries" "all SUID files are on the known-good list"
    else
        record WARN 4 "Unusual SUID binaries ($n)" "$(echo "$unusual" | head -n 8 | tr '\n' ' ')" \
            "Review each one; remove the bit if not needed: sudo chmod u-s <file>"
    fi

    local orphans
    orphans=$(tmo 60 find /etc /home /var /usr -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -n 5)
    if [[ -z $orphans ]]; then
        record PASS 1 "No files without a valid owner" "checked /etc /home /var /usr"
    else
        record WARN 1 "Files with no valid owner/group" "$(echo "$orphans" | tr '\n' ' ')" \
            "Assign an owner with chown, or delete the files"
    fi
}

audit_updates() {
    section "PATCHING & UPDATES"
    local n=""
    if have apt-get; then
        n=$(tmo 60 apt-get -s upgrade 2>/dev/null | grep -c '^Inst')
    elif have dnf && (( ! FAST )); then
        n=$(tmo 90 dnf -q check-update 2>/dev/null | grep -cE '^[A-Za-z0-9_.+-]+\.[A-Za-z0-9_]+[[:space:]]')
    fi
    if [[ -z $n ]]; then
        record INFO 0 "Pending updates" "package manager not supported or check skipped"
    elif (( n == 0 )); then
        record PASS 4 "System is up to date" "no pending package upgrades (based on local package lists)"
    elif (( n <= 10 )); then
        record WARN 4 "$n package updates pending" "based on local package lists" "sudo apt update && sudo apt upgrade   (or: sudo dnf upgrade)"
    else
        record FAIL 4 "$n package updates pending" "unpatched software is the #1 way systems get hacked" \
            "sudo apt update && sudo apt upgrade   (or: sudo dnf upgrade)"
    fi

    if { have dpkg && dpkg -s unattended-upgrades >/dev/null 2>&1; } || { have rpm && rpm -q dnf-automatic >/dev/null 2>&1; }; then
        record PASS 2 "Automatic security updates installed" "unattended-upgrades / dnf-automatic present"
    else
        record WARN 2 "Automatic security updates not installed" "patches depend on you remembering" \
            "sudo apt install unattended-upgrades"
    fi

    if [[ -f /var/run/reboot-required ]]; then
        record WARN 1 "Reboot required" "/var/run/reboot-required exists (kernel/library updates not active yet)" "sudo reboot"
    fi
}

audit_services() {
    section "RISKY SERVICES"
    if ! have systemctl; then
        record INFO 0 "Service check" "systemctl not available - skipped"; return
    fi
    local s bad="" meh=""
    for s in $BAD_SERVICES; do svc_active "$s" && bad+="$s "; done
    for s in $MEH_SERVICES; do svc_active "$s" && meh+="$s "; done
    if [[ -z $bad ]]; then
        record PASS 4 "No insecure legacy services running" "telnet/rsh/ftp/tftp/inetd not active"
    else
        record FAIL 4 "Insecure services running" "$bad" "sudo systemctl disable --now <service>"
    fi
    if [[ -z $meh ]]; then
        record PASS 2 "No unnecessary network services running" "avahi/cups/rpcbind/smb/nfs/snmp not active"
    else
        record WARN 2 "Possibly unnecessary services running" "$meh" "If you don't need them: sudo systemctl disable --now <service>"
    fi
}

audit_cron() {
    section "SCHEDULED JOBS (cron)"
    local ww
    ww=$(find /etc/cron* /var/spool/cron* -type f -perm -0002 2>/dev/null | head -n 5)
    if [[ -z $ww ]]; then
        record PASS 3 "No world-writable cron files" "anyone-can-edit cron files would mean root takeover"
    else
        record FAIL 3 "World-writable cron files" "$(echo "$ww" | tr '\n' ' ')" "sudo chmod o-w <file>"
    fi
    local sus
    sus=$(grep -rhsEi '(curl|wget)[^#]*\|[[:space:]]*(ba)?sh|nc[[:space:]].*-e|ncat|bash -i|/dev/tcp|base64 -d' \
          /etc/cron* /var/spool/cron* 2>/dev/null | head -n 3)
    if [[ -z $sus ]]; then
        record PASS 3 "No suspicious cron commands" "no download-and-execute / reverse-shell patterns"
    else
        record WARN 3 "Suspicious cron entries" "$sus" "Review these lines - possible persistence by an attacker"
    fi
}

audit_defense() {
    section "LOGGING & ACCESS CONTROL"
    if svc_active auditd; then
        record PASS 2 "auditd running" "system call auditing active"
    else
        record WARN 2 "auditd not running" "no kernel-level audit trail" "sudo apt install auditd && sudo systemctl enable --now auditd"
    fi
    if svc_active fail2ban; then
        record PASS 3 "fail2ban running" "brute-force attempts are auto-blocked"
    else
        record WARN 3 "fail2ban not running" "nothing blocks repeated failed logins" "sudo apt install fail2ban && sudo systemctl enable --now fail2ban"
    fi
    local mac=""
    if [[ -r /sys/module/apparmor/parameters/enabled ]] && grep -q Y /sys/module/apparmor/parameters/enabled 2>/dev/null; then
        mac="AppArmor"
    elif have getenforce && [[ $(getenforce 2>/dev/null) == Enforcing ]]; then
        mac="SELinux (enforcing)"
    fi
    if [[ -n $mac ]]; then
        record PASS 3 "Mandatory access control active" "$mac"
    else
        record WARN 3 "No mandatory access control (AppArmor/SELinux)" "a compromised service has fewer limits" \
            "Enable AppArmor (Debian/Ubuntu) or set SELinux to enforcing (RHEL)"
    fi
    if svc_active rsyslog || svc_active syslog-ng || svc_active systemd-journald; then
        record PASS 2 "System logging active" "rsyslog / syslog-ng / journald running"
    else
        record WARN 2 "No logging daemon detected" "" "Enable rsyslog or systemd-journald"
    fi
    if have findmnt; then
        local opts
        opts=$(findmnt -no OPTIONS /tmp 2>/dev/null)
        if [[ -z $opts ]]; then
            record WARN 1 "/tmp is not a separate partition" "can't apply noexec/nosuid to it" "Mount /tmp as tmpfs with 'nosuid,nodev,noexec'"
        elif [[ $opts == *noexec* ]]; then
            record PASS 1 "/tmp mounted noexec" "$opts"
        else
            record WARN 1 "/tmp allows execution" "$opts" "Add 'noexec' to the /tmp mount options"
        fi
    fi
}

# ------------------------------- reporting -----------------------------------
write_html() {
    local f=$1 pct=$2 grade=$3 i st prev="" cls
    {
        cat <<'EOF'
<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hardening Audit Report</title>
<style>
body{font-family:system-ui,sans-serif;background:#0f1419;color:#d8dee9;max-width:900px;margin:2rem auto;padding:0 1rem}
h1{color:#88c0d0;margin-bottom:.2rem} h2{color:#81a1c1;border-bottom:1px solid #2e3440;padding-bottom:.3rem;margin-top:2rem}
.meta{color:#7b88a1;margin-top:0}
.score{background:#1a212b;border-radius:12px;padding:1.2rem;display:flex;gap:2rem;align-items:center;margin:1.2rem 0}
.big{font-size:3rem;font-weight:700}
.row{background:#1a212b;border-left:5px solid #444;border-radius:6px;padding:.6rem .9rem;margin:.5rem 0}
.row.PASS{border-color:#a3be8c}.row.WARN{border-color:#ebcb8b}.row.FAIL{border-color:#bf616a}.row.INFO{border-color:#5e81ac}
.tag{font-size:.75rem;font-weight:700;padding:.1rem .5rem;border-radius:99px;margin-right:.5rem;color:#0f1419}
.PASS .tag{background:#a3be8c}.WARN .tag{background:#ebcb8b}.FAIL .tag{background:#bf616a}.INFO .tag{background:#5e81ac}
.d{color:#8a96ab;font-size:.9rem;margin:.25rem 0 0}
code{background:#0f1419;padding:.1rem .4rem;border-radius:4px;color:#88c0d0}
</style></head><body>
EOF
        printf '<h1>Linux Hardening Audit</h1>\n'
        printf '<p class="meta">Host: %s &middot; %s &middot; run as %s</p>\n' \
            "$(html_esc "$(hostname)")" "$(date '+%Y-%m-%d %H:%M:%S')" "$(html_esc "$(id -un)")"
        printf '<div class="score"><div class="big">%s%%</div><div>Grade <b>%s</b><br>%s passed &middot; %s warnings &middot; %s failed</div></div>\n' \
            "$pct" "$grade" "$N_PASS" "$N_WARN" "$N_FAIL"
        for ((i=0; i<${#R_STATUS[@]}; i++)); do
            st=${R_STATUS[i]}
            if [[ ${R_SECTION[i]} != "$prev" ]]; then
                printf '<h2>%s</h2>\n' "$(html_esc "${R_SECTION[i]}")"
                prev=${R_SECTION[i]}
            fi
            printf '<div class="row %s"><span class="tag">%s</span><b>%s</b>' "$st" "$st" "$(html_esc "${R_TITLE[i]}")"
            [[ -n ${R_DETAIL[i]} ]] && printf '<p class="d">%s</p>' "$(html_esc "${R_DETAIL[i]}")"
            if [[ $st == WARN || $st == FAIL ]] && [[ -n ${R_FIX[i]} ]]; then
                printf '<p class="d">Fix: <code>%s</code></p>' "$(html_esc "${R_FIX[i]}")"
            fi
            printf '</div>\n'
        done
        printf '</body></html>\n'
    } > "$f"
}

summary() {
    local pct=0 grade color i
    (( SCORE_MAX > 0 )) && pct=$(( SCORE_GOT * 100 / SCORE_MAX ))
    if   (( pct >= 90 )); then grade=A; color=$GRN
    elif (( pct >= 80 )); then grade=B; color=$GRN
    elif (( pct >= 70 )); then grade=C; color=$YEL
    elif (( pct >= 60 )); then grade=D; color=$YEL
    else grade=F; color=$RED; fi

    say ""
    say "${BLD}============================== SUMMARY ==============================${RST}"
    say "  Security score : ${color}${pct}/100  (grade ${grade})${RST}"
    say "  ${GRN}Passed${RST}: $N_PASS   ${YEL}Warnings${RST}: $N_WARN   ${RED}Failed${RST}: $N_FAIL   ${CYN}Info${RST}: $N_INFO"

    if (( ${#FIXES[@]} )); then
        say ""
        say "${BLD}Recommended fixes (most important first as listed by section):${RST}"
        for i in "${!FIXES[@]}"; do
            say "  $((i+1)). ${FIXES[i]}"
        done
    else
        say ""
        say "  ${GRN}Nothing to fix - excellent hardening!${RST}"
    fi
    say ""
    say "  ${DIM}Audit finished: $(date '+%Y-%m-%d %H:%M:%S')${RST}"

    if [[ -n $HTML_REPORT ]]; then
        write_html "$HTML_REPORT" "$pct" "$grade"
        say "  HTML report saved to: $HTML_REPORT"
    fi
    [[ -n $TXT_REPORT ]] && echo "  Text report saved to: $TXT_REPORT"
}

usage() {
    cat <<EOF
Linux System Hardening Auditor v${VERSION}

Usage: ${SCRIPT_NAME} [options]

Options:
  -r, --report FILE   also save a plain-text report to FILE
  -H, --html FILE     also save a styled HTML report to FILE
  -n, --no-color      disable coloured output
      --fast          skip the slow full-disk scans (SUID / orphan files)
  -v, --version       show version
  -h, --help          show this help

Run with sudo for the most complete results:
  sudo ./${SCRIPT_NAME} -r audit.txt -H audit.html

This tool is read-only. Use it only on systems you own or are authorised to audit.
EOF
}

# ------------------------------- main ----------------------------------------
trap 'echo; echo "Interrupted."; exit 130' INT

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)     usage; exit 0 ;;
        -v|--version)  echo "$SCRIPT_NAME $VERSION"; exit 0 ;;
        -n|--no-color) USE_COLOR=0; shift ;;
        --fast)        FAST=1; shift ;;
        -r|--report)   [[ -z ${2:-} ]] && { echo "Option $1 needs a file name"; exit 1; }
                       TXT_REPORT=$2; shift 2 ;;
        -H|--html)     [[ -z ${2:-} ]] && { echo "Option $1 needs a file name"; exit 1; }
                       HTML_REPORT=$2; shift 2 ;;
        *) echo "Unknown option: $1"; echo; usage; exit 1 ;;
    esac
done

if [[ $(uname -s) != Linux ]]; then
    echo "This auditor only supports Linux."; exit 1
fi
[[ -n $TXT_REPORT ]] && : > "$TXT_REPORT"
init_colors

banner
audit_system
audit_users
audit_ssh
audit_firewall
audit_network
audit_kernel
audit_files
audit_updates
audit_services
audit_cron
audit_defense
summary

# exit code: 0 = no failures, 2 = at least one FAIL (handy for scripting/CI)
(( N_FAIL > 0 )) && exit 2
exit 0
