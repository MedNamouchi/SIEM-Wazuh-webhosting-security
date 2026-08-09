# UC-04 — LFI via Vulnerable WordPress Plugin

**Category:** Threat Detection / Web Application Attack
**Priority:** High
**Status:** ✅ Detected in production — organic attack traffic
**MITRE ATT&CK:** T1083 — File and Directory Discovery
**Compliance:** GDPR IV.35.7.d · NIST 800-53 SI.4 · PCI-DSS 6.5.1

---

## Incident Summary

| Field | Value |
|---|---|
| Detection date | August 2026 |
| Attack type | Local File Inclusion (LFI) via vulnerable WordPress plugins |
| Target | WordPress vhost (`<client-domain>`) |
| Attacker IP | `<attacker-ip>` |
| Plugins exploited | `count-per-day`, `mail-masta` |
| Target file | `/etc/passwd` |
| Rule triggered | 200303 — Sensitive file access |
| Detection time | Real-time |

---

## Attack Description

The attacker targeted known vulnerable WordPress plugins that expose
Local File Inclusion vulnerabilities — allowing arbitrary file reads
from the server filesystem via crafted URL parameters.

**Two exploit patterns detected:**

### Exploit 1 — count-per-day plugin

```
GET /wp-content/plugins/count-per-day/download.php?n=1&f=/etc/passwd
```

The `count-per-day` plugin's `download.php` script accepts a file path
via the `f` parameter without sanitization — allowing direct read of
any file accessible by the web server process.

### Exploit 2 — mail-masta plugin

```
GET /wp-content/plugins/mail-masta/inc/lists/csvexport.php?pl=/etc/passwd
```

The `mail-masta` plugin's `csvexport.php` script accepts a file path
via the `pl` parameter — same vulnerability class, different plugin.

Both are **public CVEs** with well-documented exploitation procedures
available on exploit databases.

---

## Detection

Rule 200303 matched `/etc/passwd` in the URL on both requests:

```xml
<rule id="200303" level="10">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(?i)(\.env|wp-config\.php|\.git/|/etc/passwd|\.htpasswd|id_rsa)</match>
  ...
</rule>
```

**Alert fired:**
```
Rule: 200303 (level 10) → 'Web Hosting: Sensitive file access attempt
from <attacker-ip> on <client-domain>'

URL: /wp-content/plugins/count-per-day/download.php?n=1&f=/etc/passwd
MITRE: T1083 — File and Directory Discovery
```

**Mattermost alert:**
```
🔓 Sensitive File Access
Rule: 200303 | Level: 10/15 | Fired: 12x
IP: <attacker-ip> — 📍 <country>, <city> (<ISP>)
Site: <client-domain> | URL: /wp-content/plugins/count-per-day/...
MITRE: T1083 — File and Directory Discovery
```

---

## Investigation

### Step 1 — Check HTTP response code

```bash
sudo grep "<attacker-ip>" /var/log/virtualmin/<client-domain>_access_log | \
  grep "passwd\|mail-masta\|count-per-day"
# → GET /wp-content/plugins/count-per-day/download.php?n=1&f=/etc/passwd HTTP/1.1" 301
# → GET /wp-content/plugins/mail-masta/.../csvexport.php?pl=/etc/passwd HTTP/1.1" 301
```

**HTTP 301 (redirect)** — both requests were redirected, not served.
This indicates either:
- The plugin files do not exist (plugin not installed)
- Apache redirect rules intercepted the request before the PHP script
  could execute

### Step 2 — Confirm plugin installation status

```bash
sudo ls /home/<client>/public_html/wp-content/plugins/ | \
  grep -i "count-per-day\|mail-masta"
# → (empty)
```

**Neither plugin is installed** — the attacker was scanning for known
vulnerable plugins using automated exploitation tools. The 301 redirect
confirms the attack was unsuccessful.

### Step 3 — Assess attack scope

```bash
# How many different exploit paths did the attacker try?
sudo grep "<attacker-ip>" /var/log/virtualmin/<client-domain>_access_log | \
  grep "wp-content/plugins" | awk -F'"' '{print $2}' | sort -u
# → 15+ different plugin paths attempted
# Confirms automated exploitation scanner, not manual attack
```

### Step 4 — Cross-reference with other rules

```bash
# Did the same IP trigger other rules?
sudo grep "Rule:.*<attacker-ip>\|<attacker-ip>.*Rule:" \
  /var/ossec/logs/alerts/alerts.log | grep -o "Rule: [0-9]*" | sort -u
# → Rule: 200303 (Sensitive file access)
# → Rule: 200304 (RFI — false positive on redirect_to parameter)
# → Rule: 200202 (404 flood — 30+ not found responses)
```

The same IP also triggered the 404 flood rule (200202) — consistent with
an automated scanner probing all plugin paths, generating many 404s when
plugins are not installed.

---

## Outcome

| Check | Result |
|---|---|
| LFI successful | ❌ Not confirmed (HTTP 301, plugins not installed) |
| `/etc/passwd` contents exposed | ❌ Not confirmed |
| Other files accessed | ❌ Not detected |
| Attack type | Automated exploitation scan |
| Attacker objective | Map vulnerable plugins → exfiltrate credentials/config |

**No compromise confirmed.** The attack failed because the targeted plugins
were not installed on the WordPress instance. The detection was entirely
real-time — zero delay between request and Mattermost alert.

---

## Recommendations

1. **Keep plugins updated** — both `count-per-day` and `mail-masta` have
   patched versions. Ensure all hosted WordPress sites run current plugin
   versions
2. **Remove unused plugins** — deactivated but installed plugins still
   expose their files to direct URL access
3. **Deploy web-block.sh** — automatic IP blocking on rule 200303 trigger
   (pending NPM IP transparency fix)
4. **Consider ModSecurity** — re-evaluate WAF deployment for LFI/RFI
   pattern blocking at the HTTP layer, upstream of Apache

---

## Why This Matters

This use case demonstrates a key value of the SIEM deployment: **the
attack was detected in real time, even though the plugins were not
installed and no compromise occurred.** Without SIEM visibility on web
logs, this scanning activity would have been completely invisible — leaving
no record that the server was probed for these vulnerabilities.

If the plugins had been installed and unpatched, the SIEM would have
detected the successful LFI at the same speed — enabling immediate response
before the attacker could pivot to further exploitation.

---

## Rules Demonstrated

| Rule | Level | Trigger | Status |
|---|---|---|---|
| 200303 | 10 | `/etc/passwd` in URL | ✅ Fired — real attack |
| 200202 | 10 | 30+ 404s in 60s | ✅ Fired — same attacker |
| 200304 | 12 | `redirect_to=https://` | ⚠️ False positive |

---

*Part of the SIEM Web Hosting Security project — Use Cases*
*Last updated: August 2026*
