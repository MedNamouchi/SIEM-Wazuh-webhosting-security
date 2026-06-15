# Web Hosting Server Discovery Playbook

> A structured methodology for security discovery on shared web hosting servers running Apache + Virtualmin/Webmin on Linux.
> Built from a real internship engagement. Use this as a reference for similar missions.

---

## Context

This playbook was built during a SOC/security internship where the mission was:
- Deploy and configure a Wazuh agent on a production web server
- Identify security gaps and active threats
- Produce an evidence-based discovery report for the team

**Target profile:** Linux server (Ubuntu 22.04), Apache2, Virtualmin/Webmin hosting panel, ~50 client virtual hosts, Wazuh agent already installed, Laravel + WordPress apps, dedicated MySQL server.

**Tools used:** Only standard Linux utilities — `ss`, `ip`, `last`, `lastb`, `grep`, `awk`, `find`, `curl`, `fail2ban-client`, `supervisorctl`, `redis-cli`, `mysql`. No automated scanners.

---

## Table of Contents

1. [Block 1 — System & Network Overview](#block-1----system--network-overview)
2. [Block 2 — Users, Auth Logs & Process Identification](#block-2----users-auth-logs--process-identification)
3. [Block 3 — Apache, Wazuh Config & Firewall](#block-3----apache-wazuh-config--firewall)
4. [Block 4 — Services, Supervisor & Security Headers](#block-4----services-supervisor--security-headers)
5. [Block 5 — Final Verifications](#block-5----final-verifications)
6. [Key Patterns Learned](#key-patterns-learned)
7. [Reusable Discovery Checklist](#reusable-discovery-checklist)

---

## Block 1 — System & Network Overview

### Goal
Understand the host: OS, uptime, network position, all listening ports, and active outbound connections.

### Commands

```bash
# OS and kernel
cat /etc/os-release
uname -a
uptime

# Full hostname
hostname -f

# Who is currently connected
who
w

# All network interfaces and IPs
ip a
ip route
cat /etc/resolv.conf

# All listening ports with process names
sudo ss -tulpn

# All currently established connections
sudo ss -tnp state established
```

### What to look for

**Kernel date:** If the kernel was compiled months ago and uptime matches, it means no kernel updates have been applied since then. Note this as a finding.

**Open ports on 0.0.0.0 or \*:** Every service bound here is potentially reachable from the internet if no upstream firewall exists. Build a table: port, process, bind address, risk level.

**Established connections:** This tells you the real architecture — which external hosts does the server talk to? Database server, monitoring, SIEM manager... all visible here.

**Unexpected PHP processes on non-standard ports:** On Laravel hosting servers, you may find PHP processes listening on ports like 6001 or 6002. Before flagging these as suspicious, identify them:
```bash
sudo cat /proc/<PID>/cmdline | tr '\0' ' '
```
They are often legitimate Laravel Reverb WebSocket servers. Verify before reporting.

### Lesson learned

> On a shared hosting server, the established connections reveal the full internal architecture: database server IP, monitoring server IP, SIEM manager IP. This is more reliable than asking for a network diagram.

---

## Block 2 — Users, Auth Logs & Process Identification

### Goal
Understand who has access, what login activity looks like, and confirm or deny suspicious authentication events.

### Commands

```bash
# All human accounts (UID >= 1000)
awk -F: '$3 >= 1000 && $3 < 65534 {print $1,$3,$6,$7}' /etc/passwd

# Recent successful logins
last | head -30

# Recent failed logins
sudo lastb | head -30

# Successful SSH authentications from auth.log
sudo grep "Accepted" /var/log/auth.log | tail -30

# Historical successful logins (rotated logs)
sudo zgrep "Accepted" /var/log/auth.log.* 2>/dev/null | tail -30

# Sudo activity
sudo grep "sudo" /var/log/auth.log | grep -v "pam_unix" | tail -20

# Count occurrences of a specific IP in auth.log
sudo grep "<SUSPICIOUS_IP>" /var/log/auth.log | wc -l
sudo grep "<SUSPICIOUS_IP>" /var/log/auth.log | tail -5

# Identify what a specific process actually is
sudo cat /proc/<PID>/cmdline | tr '\0' ' '
sudo ls -la /proc/<PID>/exe
```

### What to look for

**Recurring automated SSH logins from localhost:** On Virtualmin servers, you will see SSH logins from the server's own IP every few minutes or hours. This is normal — it is Webmin's `monitor.pl` running health checks. Do not flag these as suspicious without verification.

**Multiple accounts sharing the same UID:** Virtualmin creates one system user per hosting client, but sub-domains of the same client share the parent UID. This is expected behavior on shared hosting panels.

**`lastb` vs Wazuh alerts:** Always cross-reference Wazuh brute-force alerts with `lastb` and `auth.log` directly. A Wazuh rule can fire on patterns that do not necessarily confirm a successful login. Only `grep "Accepted" /var/log/auth.log` confirms a real successful authentication.

### Lesson learned

> Never report "successful SSH login from attacker IP" based on a Wazuh rule number alone. Always verify in `/var/log/auth.log` with `grep "Accepted"`. The rule may fire on a different condition than you think.

---

## Block 3 — Apache, Wazuh Config & Firewall

### Goal
Find where web traffic actually goes (logs, vhosts), what the SIEM actually monitors, and whether any firewall is configured.

### Commands

```bash
# Apache version and loaded security modules
apache2 -v
apache2ctl -M 2>/dev/null | grep -E 'security|ssl|rewrite|headers'

# All active virtual hosts
sudo apachectl -S 2>&1

# Where do vhosts actually log? (critical on Virtualmin servers)
sudo grep -rh 'CustomLog\|TransferLog' /etc/apache2/ 2>/dev/null | sort -u

# Find log files in web directories
sudo find /var/www -name "*.log" -o -name "access_log" 2>/dev/null
sudo find /home -name "*.log" -o -name "access_log" 2>/dev/null | head -20

# Log sizes - spot the active ones
sudo ls -lhS /var/log/virtualmin/ 2>/dev/null | head -15
sudo find /var/log/apache2 -name "*.log" ! -name "*.gz" -exec ls -lh {} \;

# What does Wazuh actually monitor?
sudo cat /var/ossec/etc/ossec.conf | grep -A5 "localfile\|directories\|active-response"

# Firewall status
sudo iptables -L INPUT -n --line-numbers
sudo ufw status verbose 2>/dev/null

# Disk usage overview
df -h
sudo du -sh /var/log/virtualmin/ /var/www /home /var/ossec 2>/dev/null

# Crontab (root)
sudo crontab -l
sudo ls /etc/cron.d/
sudo cat /etc/cron.d/* 2>/dev/null | grep -v "^#\|^$"
```

### What to look for

**The Virtualmin log blind spot:** This is the most important finding on a Virtualmin server. Apache's default `access.log` is empty — all traffic goes to `/var/log/virtualmin/<domain>_access_log`. If your SIEM is pointed at the default Apache log path, it sees nothing. Always check:
```bash
sudo grep -rh 'CustomLog' /etc/apache2/sites-enabled/ | sort -u
```

**No firewall:** An empty `iptables -L INPUT` with policy ACCEPT means no host-level filtering. Combined with no UFW output, this is a critical finding. Note separately whether upstream gateway filtering exists (requires an external test).

**Wazuh FIM coverage:** Check which directories are monitored for file integrity. On a web hosting server, `/var/www` and `/home/*/public_html` are the most important — webshell drops happen there. If they are not in the `<directories>` config, flag it.

### Lesson learned

> On any shared hosting server using Virtualmin, the first thing to check is where Apache actually writes its logs. The default path in `ossec.conf` (`/var/log/apache2/access.log`) is almost certainly empty. The real logs are in `/var/log/virtualmin/` — one file per domain.

---

## Block 4 — Services, Supervisor & Security Headers

### Goal
Identify all running application services, check Fail2ban effectiveness, and verify HTTP security posture.

### Commands

```bash
# Supervisor managed processes
sudo supervisorctl status 2>/dev/null

# Fail2ban - overall status
sudo fail2ban-client status 2>/dev/null

# Fail2ban - per jail detail
sudo fail2ban-client status sshd
for jail in postfix postfix-sasl proftpd dovecot webmin-auth; do
    echo "--- $jail ---"
    sudo fail2ban-client status $jail 2>/dev/null | grep -E "failed|banned"
done

# HTTP security headers check
curl -sI http://<SERVER_IP>

# SSL certificates location
sudo find /etc/ssl /etc/apache2 /etc/letsencrypt \
  -name "*.pem" -o -name "*.crt" 2>/dev/null | grep -v chain | head -20

# Webmin version
sudo cat /etc/webmin/version 2>/dev/null

# FTP configuration - TLS enabled?
sudo grep -E "Port|TLSEngine|PassivePorts" /etc/proftpd/proftpd.conf 2>/dev/null

# Zabbix agent configuration
sudo grep -E "^Server|^ServerActive|^Hostname" \
  /etc/zabbix/zabbix_agent2.conf 2>/dev/null
```

### What to look for

**Fail2ban total banned vs total failed ratio:** A healthy ratio is many bans relative to fails. If you see 8000+ failed attempts and only 1 total ban ever, the ban threshold or ban duration is misconfigured for the volume of attacks this server receives.

**Fail2ban only active on SSH:** On a web hosting server, you expect to see activity on postfix, proftpd, and webmin-auth jails too. If all of them show zero failed — either those services are not being attacked (good) or the jails are misconfigured and not picking up logs (verify).

**HTTP security headers:** A production server should return at minimum:
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Content-Security-Policy`
- `Strict-Transport-Security`
- `Referrer-Policy`

If `Server: Apache` is returned without version masking, add that to the findings too.

**Admin panel exposure:** For any admin interface (Webmin, phpMyAdmin, etc.), always test reachability from both inside and outside the network. Internal reachability alone is not critical if the gateway blocks external access — but requires an external test to confirm.

### Testing admin panel exposure from outside

From a machine on an external network (4G mobile hotspot, not connected to the target network):

```powershell
# Windows PowerShell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
try {
    $r = Invoke-WebRequest -Uri "https://<SERVER_DOMAIN>:10000" `
         -TimeoutSec 5 -UseBasicParsing
    Write-Host "HTTP $($r.StatusCode) - PORT OPEN"
} catch {
    Write-Host "BLOCKED or TIMEOUT"
}
```

```bash
# Linux / macOS
curl -sk --max-time 5 -o /dev/null -w "%{http_code}" https://<SERVER_DOMAIN>:10000
```

`BLOCKED or TIMEOUT` = gateway filters this port, not internet-exposed.
`200` = exposed, critical finding.

### Lesson learned

> Always test admin panel exposure from a real external network (4G hotspot). Testing from inside the server or from the same office network does not prove anything about internet exposure.

---

## Block 5 — Final Verifications

### Goal
Close any open questions from previous blocks with targeted verification commands.

### Commands

```bash
# Redis - is authentication configured?
redis-cli ping
redis-cli config get requirepass

# WordPress debug log - any recent suspicious activity?
sudo find /home/<CLIENT>/public_html -name "debug.log" 2>/dev/null | \
  xargs -I{} sudo tail -20 {} 2>/dev/null

# WordPress - recently modified plugins (installed after a suspicious date)
sudo find /home/<CLIENT>/public_html/wp-content/plugins \
  -maxdepth 1 -type d -newer /home/<CLIENT>/public_html/wp-config.php 2>/dev/null

# Postfix - open relay check and mail queue
postconf -n 2>/dev/null | grep -E "relay|mynetworks|smtpd_recipient"
sudo mailq 2>/dev/null | tail -5

# WordPress admin users - verify via database
mysql -h <DB_HOST> -u <DB_USER> -p<DB_PASS> <DB_NAME> \
  -e "SELECT user_login, user_email, user_registered FROM wp_users;" 2>/dev/null

# Check for suspicious files created after a specific date
sudo find /home/<CLIENT> -newer /var/log/virtualmin/<DOMAIN>_access_log \
  -type f 2>/dev/null | head -20
```

### What to look for

**Redis without a password:** Redis bound to localhost is not directly internet-exposed, but any process or user on the server can connect and read/write all cached data without credentials. On a shared hosting server with many clients, this is a medium-severity finding.

**WordPress suspicious login sequence in logs:**
A POST to `wp-login.php` returning HTTP 200 followed immediately by a GET to `wp-admin/index.php` returning HTTP 302 is consistent with a successful WordPress login. A failed login returns 200 on the login page but does NOT redirect to `/wp-admin/`. If you see this sequence from an unknown IP, verify directly in the WordPress database:
```bash
mysql -h <DB_HOST> -u <DB_USER> -p<DB_PASS> <DB_NAME> \
  -e "SELECT user_login, user_registered FROM wp_users ORDER BY user_registered DESC;"
```
Look for any admin account created around the suspicious date.

**Username enumeration via `/?author=1`:** This is a standard WordPress reconnaissance technique. An attacker hitting `/?author=1` repeatedly at high speed is mapping admin usernames before a brute-force attempt. If you see this in logs, check what happened in the minutes that followed.

**Postfix open relay check:** A correctly configured mail server should have:
```
smtpd_recipient_restrictions = permit_mynetworks permit_sasl_authenticated reject_unauth_destination
```
If `reject_unauth_destination` is missing, the server may be an open relay.

### Lesson learned

> When you find suspicious log sequences (like a possible WordPress login), always try to verify at the data layer (database query, WordPress user list) rather than leaving it as "inconclusive" in the report. It takes 30 seconds and removes all ambiguity.

---

## Key Patterns Learned

### 1. Virtualmin servers have a systematic SIEM blind spot
Virtualmin overrides Apache's default log path. Every virtual host logs to `/var/log/virtualmin/<domain>_access_log`. The default SIEM agent config points to `/var/log/apache2/access.log` which is empty. **Always verify log paths on Virtualmin servers before assuming the SIEM has visibility.**

Fix for Wazuh:
```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/virtualmin/*_access_log</location>
</localfile>
```

### 2. Recurring SSH logins from localhost = Webmin monitoring, not an attack
On a Webmin/Virtualmin server, `monitor.pl` generates SSH connections from the server's own IP every few minutes to check service status. These appear in `auth.log` as successful logins. They are normal and should not be reported as a finding without context.

### 3. PHP on non-standard ports = Laravel Reverb (usually)
Modern Laravel applications use Reverb for WebSocket support. This creates PHP processes listening on ports like 6001 or 6002. Always identify with `/proc/PID/cmdline` before flagging. The command will show `artisan reverb:start`.

### 4. Fail2ban activity ≠ Fail2ban effectiveness
Fail2ban being installed and running does not mean it is effectively blocking attackers. Always check the ratio of total failed attempts to total bans. A high fail count with near-zero bans means the threshold, findtime, or bantime needs tuning for the attack volume this server receives.

### 5. Test admin panel exposure from real external network
Internal reachability tests prove nothing about internet exposure. Always test from a 4G mobile connection or a VPS on a different AS to confirm whether an admin panel is truly exposed.

### 6. WordPress brute-force leaves clear log signatures
Three patterns in Apache logs indicate a WordPress attack:
- `GET /?author=1` repeated rapidly = username enumeration
- `POST /wp-login.php` HTTP 200 followed by `GET /wp-admin/index.php` HTTP 302 = successful login (suspicious if from unknown IP)
- Multiple IPs rotating User-Agent strings on the same endpoint = botnet

---

## Reusable Discovery Checklist

Use this checklist for any similar mission (shared web hosting server, Apache + panel, Wazuh agent).

### System
- [ ] OS version and kernel date noted
- [ ] Uptime recorded (indicates time since last reboot/update)
- [ ] All listening ports mapped with process names
- [ ] All established outbound connections identified (reveals internal architecture)
- [ ] Network interfaces and routing table documented

### Users & Access
- [ ] All human accounts listed (UID >= 1000)
- [ ] Recent successful SSH logins reviewed (`last`, `auth.log`)
- [ ] Recent failed SSH logins reviewed (`lastb`)
- [ ] Suspicious IPs cross-referenced directly in `auth.log`
- [ ] Sudo activity reviewed

### Web Server
- [ ] Apache version noted
- [ ] All active virtual hosts listed (`apachectl -S`)
- [ ] Actual log file locations identified (`grep CustomLog /etc/apache2/`)
- [ ] Log sizes checked (spot the active ones)
- [ ] HTTP security headers checked (`curl -sI`)
- [ ] SSL certificate locations found

### SIEM
- [ ] Wazuh `ossec.conf` reviewed — which logs are actually monitored?
- [ ] Confirmed the declared log paths exist and are non-empty
- [ ] FIM directories reviewed — does it cover `/var/www` and `/home`?
- [ ] Active response configuration noted

### Security Posture
- [ ] Firewall checked (`iptables -L INPUT`, `ufw status`)
- [ ] Fail2ban status checked per jail (ratio of fails to bans)
- [ ] Admin panel reachability tested from external network
- [ ] FTP TLS configuration checked
- [ ] Redis authentication checked
- [ ] Postfix open relay check
- [ ] Mail queue checked

### Application Layer
- [ ] Supervisor processes identified and mapped to their ports
- [ ] WordPress sites identified — check for brute-force patterns in logs
- [ ] WordPress login sequences reviewed for suspicious POST/redirect patterns
- [ ] Database credentials found in wp-config.php (note, do not publish)
- [ ] Crontab reviewed (root + /etc/cron.d/)

### Threat Activity
- [ ] Top source IPs by request count extracted from web logs
- [ ] `wp-login.php` attempts counted and top IPs identified
- [ ] Scanner signatures checked (nikto, sqlmap, masscan, nuclei, gobuster)
- [ ] 404/403 patterns reviewed for scanning activity
- [ ] SSH brute-force IPs noted and cross-referenced with `auth.log`

---

## Report Structure

When writing the discovery report, follow this structure:

1. **Methodology** — how you conducted the discovery, what tools, how long
2. **System Overview** — host info table, network architecture, application stack
3. **Exposed Services** — table of all ports with process, bind address, and risk level
4. **Critical Findings** — evidence-based, raw log output for each claim
5. **High Severity Findings** — same standard
6. **Medium / Low Findings** — same standard
7. **Infrastructure Observations** — things that are not vulnerabilities but worth documenting
8. **Summary Table** — one row per finding with severity and evidence source

**Golden rule:** Every claim in the report must be supported by a raw log line or command output. If you cannot show the evidence, do not include the finding.

---

*Built during a cybersecurity internship (blue team / SOC analyst mission). Methodology validated on a production shared hosting server running Ubuntu 22.04, Apache 2.4, Virtualmin, Wazuh 4.14.*

*Author: Mohamed Amine Namouchi*
