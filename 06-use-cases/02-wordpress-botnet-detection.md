# UC-02 — WordPress Botnet Detection & Brute Force Campaign

**Category:** Threat Detection / Incident Response
**Priority:** High
**Status:** ✅ Detected in production — organic attack traffic
**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing
**Compliance:** GDPR IV.35.7.d · NIST 800-53 AC.7 · PCI-DSS 10.2.4

---

## Incident Summary

| Field | Value |
|---|---|
| Detection date | August 2026 |
| Attack type | WordPress credential brute force — botnet |
| Target | Multiple WordPress vhosts on the hosting server |
| Primary attacker IP | `<attacker-ip-1>` |
| Secondary attacker IP | `<attacker-ip-2>` |
| Total attempts detected | 250+ in under 5 minutes |
| Rules triggered | 200100, 200101, 200105 |
| Detection time | Real-time — Mattermost alert within 2 seconds |
| Response | Mattermost notification sent — manual investigation |

---

## Attack Description

Within minutes of deploying the Mattermost active response script, the
SIEM detected a coordinated WordPress brute force campaign targeting
multiple client sites simultaneously.

**Attack characteristics observed:**

- **User-Agent rotation:** each POST request used a different browser
  User-Agent string (Chrome, Firefox, Safari across different OS versions)
  — a classic botnet evasion technique to avoid User-Agent based blocking
- **Multi-target:** same attacker IP hit multiple vhosts in parallel
- **High volume:** 257+ login attempts from a single IP in under 5 minutes
- **XML-RPC abuse:** separate IP simultaneously abusing `xmlrpc.php` on
  another vhost — coordinated multi-vector attack

---

## Detection Timeline

```
T+0s    First POST to wp-login.php detected
        Rule 200100 fires (level 4) — WordPress login attempt

T+12s   10th attempt from same IP in 60s
        Rule 200101 fires (level 10) — WordPress brute force confirmed
        Mattermost alert sent immediately

T+15s   Rule 200105 fires on second vhost (level 8) — XML-RPC abuse
        Second Mattermost alert sent

T+60s   Rule 200101 continues firing every 10 attempts
        257+ total attempts logged over 5 minutes
```

---

## Evidence — Mattermost Alerts

**First brute force alert (200101):**
```
🔑🔑 WordPress Brute Force
Rule: 200101 | Level: 10/15 | Fired: 2x
IP: <attacker-ip-1> — 📍 <country>, <city> (<ISP>)
Site: <client-domain> | URL: /wp-login.php
MITRE: T1110.001 — Password Guessing
Log: POST /wp-login.php HTTP/1.1" 503 8071
```

**XML-RPC abuse alert (200105) on second vhost:**
```
🔌 XML-RPC Abuse
Rule: 200105 | Level: 8/15 | Fired: 90x
IP: <attacker-ip-2>
Site: <client-domain-2> | URL: /xmlrpc.php
User-Agent: Jetpack by WordPress.com
MITRE: T1190 — Exploit Public-Facing Application
```

---

## Investigation

### Step 1 — Confirm attack pattern in raw logs

```bash
# Count total attempts from attacker IP
sudo grep "<attacker-ip-1>" /var/log/virtualmin/<client-domain>_access_log | \
  grep "wp-login.php" | wc -l
# → 257

# Check for successful login (HTTP 200 followed by redirect to wp-admin)
sudo grep "<attacker-ip-1>" /var/log/virtualmin/<client-domain>_access_log | \
  grep "wp-login.php" | grep -v "503\|200 " | head -5
# → All requests returned 503 (site maintenance mode) or 200 login page
# → No POST returning redirect to /wp-admin/ — no successful login confirmed
```

### Step 2 — Confirm no successful WordPress login

A successful WordPress login produces a POST to `wp-login.php` (HTTP 200)
immediately followed by a GET to `wp-admin/index.php` (HTTP 302 redirect).
This sequence was absent — no compromise confirmed.

### Step 3 — Identify botnet indicators

```bash
# Extract User-Agents used by the attacker
sudo grep "<attacker-ip-1>" /var/log/virtualmin/<client-domain>_access_log | \
  grep "wp-login" | awk -F'"' '{print $6}' | sort -u | head -10
# → Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/121
# → Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/605.1.15 Safari/605.1
# → Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119
# → ...10+ different User-Agent strings
# Confirms botnet with UA rotation
```

### Step 4 — Check WordPress database for new admin accounts

```bash
mysql -h <db-host> -u <db-user> -p <db-name> \
  -e "SELECT user_login, user_registered FROM wp_users
      ORDER BY user_registered DESC LIMIT 5;"
# → No new accounts created after attack start time
# → No compromise confirmed
```

---

## Outcome

| Check | Result |
|---|---|
| Successful login | ❌ Not detected |
| New admin account created | ❌ Not detected |
| Webshell drop | ❌ Not detected |
| Attack ongoing | ✅ Continued for several hours |
| Action taken | Documented — IP blocking pending NPM fix |

**No compromise confirmed.** The WordPress sites returned HTTP 503
(maintenance mode active on affected site) which prevented successful
authentication during the attack window.

---

## Recommendations

1. **Enable WordPress login limiting** — install a rate-limiting plugin
   (e.g. Limit Login Attempts Reloaded) on all hosted WordPress sites
2. **Deploy web-block.sh** — automatic iptables blocking on rule 200101
   trigger (pending NPM IP transparency fix for Cloudflare-proxied sites)
3. **Disable XML-RPC** — if not required by client, disable via
   `.htaccess` or WordPress plugin
4. **Deploy Mattermost throttling** — limit to one alert per IP per rule
   per 10 minutes to reduce notification spam during sustained attacks

---

## Rules Demonstrated

| Rule | Level | Fired | Description |
|---|---|---|---|
| 200100 | 4 | 257x | WordPress login attempt |
| 200101 | 10 | 25x | WordPress brute force (10+ in 60s) |
| 200105 | 8 | 90x | XML-RPC abuse |

---

*Part of the SIEM Web Hosting Security project — Use Cases*
*Last updated: August 2026*
