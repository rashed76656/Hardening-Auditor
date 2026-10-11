# Linux System Hardening Auditor

A read-only Bash tool that audits a Linux machine's security configuration, gives it a **score out of 100 (grade A-F)**, and tells you exactly how to fix every problem.

> It never changes anything on the system. Use it only on machines you own or have permission to audit.

## Quick start

```bash
chmod +x hardening_auditor.sh
sudo ./hardening_auditor.sh                       # full audit on screen
sudo ./hardening_auditor.sh -r audit.txt -H audit.html   # also save reports
./hardening_auditor.sh --fast -n                  # no root, no colours, skip slow scans
```

| Option | Meaning |
|---|---|
| `-r, --report FILE` | save a plain-text report |
| `-H, --html FILE`   | save a styled HTML report |
| `-n, --no-color`    | disable colours |
| `--fast`            | skip slow full-disk scans (SUID / orphan files) |
| `-h, --help`        | show help |

Exit code: `0` = no failures, `2` = at least one FAIL.

## What it checks (11 modules)

1. **System info**: host, OS, kernel, uptime, current user
2. **Users & authentication**: extra UID 0 accounts, empty passwords, password expiry, PAM complexity, passwordless sudo
3. **SSH server**: root login, password login, empty passwords, MaxAuthTries, X11 forwarding, default port
4. **Firewall**: ufw / firewalld / nftables / iptables active, default-deny policy
5. **Network exposure**: ports listening on all interfaces, legacy (telnet/ftp/rsh) and sensitive (DB/RPC/SMB) services
6. **Kernel hardening (sysctl)**: ASLR, SYN cookies, ICMP redirects, source routing, rp_filter, kptr_restrict, dmesg_restrict, ptrace scope
7. **File permissions**: /etc/passwd, shadow, gshadow, sshd_config, /root, world-writable system files, unusual SUID binaries, orphan files
8. **Patching**: pending updates, automatic security updates, reboot required
9. **Risky services**: telnet, rsh, vsftpd, tftp, inetd, avahi, cups, rpcbind, smbd...
10. **Cron**: world-writable cron files, download-and-execute / reverse-shell patterns
11. **Logging & access control**: auditd, fail2ban, AppArmor/SELinux, syslog/journald, /tmp mount options

## How scoring works

Each check has a weight from 1 (minor) to 5 (critical).

- PASS = full points
- WARN = half points
- FAIL = zero points
- INFO = not scored

`score = points earned / points possible x 100`
Grades: A >= 90, B >= 80, C >= 70, D >= 60, F below 60.

## Demo idea for your presentation

1. Run the auditor on a fresh Ubuntu VM and show the low score and the list of fixes.
2. Apply a few fixes: enable `ufw`, set `PermitRootLogin no`, install `fail2ban` and `unattended-upgrades`.
3. Run it again and show the score going up (compare the two HTML reports).

## How it works

- Everything is plain Bash plus standard tools (`awk`, `grep`, `find`, `stat`, `ss`, `systemctl`).
- `record()` is the core function: every check calls it with a status, weight, title, detail and fix. It prints the result and stores it for the summary and the HTML report.
- Kernel settings are read straight from `/proc/sys`, so no root is needed for those.
- File permissions are compared with bitmasks, so `640` passes a "max 640" rule but `644` fails.
- SSH settings come from `sshd -T` (effective config) when run as root, otherwise from the config files.
- Unusual SUID binaries are found with `find -perm -4000` and compared against a known-good list.

## Limitations

- Linux only; best tested on Debian/Ubuntu and RHEL-family systems.
- Some checks need root (shadow file, sudoers, iptables). Without root they are marked INFO and skipped.
- Pending-update count uses local package lists, so run `apt update` first for accuracy.
- It is a learning/audit tool, not a replacement for full benchmarks such as CIS or Lynis.

## Ideas to extend it

- Add a `--json` output option
- Add more checks (GRUB password, USB storage, core dumps, banner files)
- Compare two reports and show what improved
- Add an auto-fix mode (with a confirmation prompt for each change)
