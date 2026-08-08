# Phase 3b — IP Transparency Fix: mod_remoteip

Author: Mohamed Amine Namouchi
Date: July 2026
Status: ✅ Partial — direct vhosts resolved | ⚠️ Cloudflare vhosts pending NPM fix

---

## Problem Statement

The production hosting server sits behind two layers of reverse proxies:

```
Internet
    │
    ├── Cloudflare (11 vhosts)
    │       │
    └───────┴──► Nginx Proxy Manager (NPM) ──► Apache ──► Virtualmin vhosts
```

By default, Apache logs the IP of the last TCP connection — NPM's internal
IP (`<NPM_IP>`). Every single alert in the SIEM was attributed to the same
proxy IP, regardless of which real attacker or client made the request.
**All SIEM attribution was useless.**

---

## Investigation

### Step 1 — Identify what the proxy actually sends

Deployed a temporary PHP headers dump on a test vhost:

```php
<?php foreach(getallheaders() as $k=>$v) echo "$k: $v\n"; ?>
```

Requested from a 4G mobile phone (real external IP). Headers received by Apache:

```
X-Forwarded-For: <real-client-ip>
X-Forwarded-Proto: https
CF-Connecting-IP: <real-client-ip>    ← only present on Cloudflare-proxied sites
Host: <domain>
```

**Key finding:** NPM sends `X-Forwarded-For` with the real client IP.
For Cloudflare-proxied sites, Cloudflare also adds `CF-Connecting-IP`.
NPM does NOT send `X-Real-IP` — the header `mod_remoteip` was configured
to read by default.

### Step 2 — Audit existing mod_remoteip configuration

```bash
apache2ctl -M 2>/dev/null | grep remoteip
# → remoteip_module (shared)   ← module loaded

cat /etc/apache2/mods-enabled/remoteip.conf
# → RemoteIPHeader X-Real-IP   ← wrong header

grep "LogFormat.*combined" /etc/apache2/apache2.conf
# → LogFormat "%h ..."         ← %h = TCP connection IP, not real IP
```

**Three problems identified:**
1. `RemoteIPHeader` pointed to `X-Real-IP` — NPM sends `X-Forwarded-For`
2. No `RemoteIPInternalProxy` declared — Apache ignores the header without this
3. `LogFormat` used `%h` (TCP connection IP) instead of `%a` (post-remoteip IP)

---

## Fix — Direct vhosts (38 sites via NPM only)

### Change 1 — remoteip.conf

```apache
# /etc/apache2/mods-enabled/remoteip.conf
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy <NPM_IP>
RemoteIPInternalProxy 103.21.244.0/22
RemoteIPInternalProxy 103.22.200.0/22
RemoteIPInternalProxy 103.31.4.0/22
RemoteIPInternalProxy 104.16.0.0/13
RemoteIPInternalProxy 104.24.0.0/14
RemoteIPInternalProxy 108.162.192.0/18
RemoteIPInternalProxy 131.0.72.0/22
RemoteIPInternalProxy 141.101.64.0/18
RemoteIPInternalProxy 162.158.0.0/15
RemoteIPInternalProxy 172.64.0.0/13
RemoteIPInternalProxy 173.245.48.0/20
RemoteIPInternalProxy 188.114.96.0/20
RemoteIPInternalProxy 190.93.240.0/20
RemoteIPInternalProxy 197.234.240.0/22
RemoteIPInternalProxy 198.41.128.0/17
```

### Change 2 — LogFormat

```apache
# /etc/apache2/apache2.conf
# Before:
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined

# After:
LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
#          ^^ %a = post-remoteip IP (real client)
```

### Validation

From a 4G mobile phone, visited 5 different direct vhosts. Verified in
Apache logs:

```bash
sudo grep "<real-mobile-ip>" /var/log/virtualmin/*_access_log | wc -l
# → 47 lines — real IP correctly logged across all tested vhosts
```

```bash
sudo grep -l "<NPM_IP>" /var/log/virtualmin/*_access_log
# → empty — NPM IP no longer appears in any vhost log
```

**Result:** 38 direct vhosts now log real client IPs. ✅

---

## Remaining Issue — Cloudflare-proxied vhosts (11 sites)

### Affected sites (identified via DNS resolution)

Sites resolving to Cloudflare IPs (`104.x`, `172.67.x`, `188.114.x`) instead
of the server's public IP are proxied through Cloudflare before reaching NPM.

For these sites, the traffic chain is:
```
Real client → Cloudflare → NPM → Apache
```

Cloudflare injects `CF-Connecting-IP: <real-client-ip>` in its requests to
NPM. However, **NPM does not forward this header to Apache** — it sends only
its own `X-Forwarded-For` with its internal IP, losing the real client IP.

**Result:** Cloudflare-proxied sites still log Cloudflare IPs, not real
client IPs. ⚠️

### Pending fix — NPM side configuration

NPM needs to be configured to forward `CF-Connecting-IP` to Apache:

```nginx
# In NPM Advanced configuration for Cloudflare-proxied sites
proxy_set_header X-Forwarded-For $http_cf_connecting_ip;
```

This requires access to the NPM Docker container — pending infrastructure
team action.

### Impact on SIEM

Until the NPM fix is applied:
- WordPress brute force alerts on Cloudflare-proxied sites will attribute
  attacks to Cloudflare IPs, not real attacker IPs
- IP-based blocking active response must NOT be deployed for these sites
  (risk of blocking Cloudflare → taking down the site for all users)
- Detection rules still fire correctly — only attribution is affected

---

## Summary

| Vhost category | Count | Real IP logged | Status |
|---|---|---|---|
| Direct (NPM only) | 38 | ✅ Yes | Fixed |
| Cloudflare-proxied | 11 | ❌ Cloudflare IP | Pending NPM fix |

---

*Part of Phase 3b — IP Transparency*
*Last updated: August 2026*
