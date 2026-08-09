# Key Findings & Lessons Learned

> Takeaways from deploying and operating a SIEM on a production shared hosting server.
> Applicable to any similar engagement.
> Last updated: August 2026

---

## 1. The Virtualmin Log Blind Spot

**What happened:**
Wazuh was configured to monitor `/var/log/apache2/access.log`.
This file had been empty since 2024. All real traffic was going to
`/var/log/virtualmin/<domain>_access_log` — one file per virtual host.
The SIEM had been blind to all web traffic for years.

**The fix:**
```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/virtualmin/*_access_log</location>
</localfile>
```

**The lesson:**
On any shared hosting server using Virtualmin, the first thing to verify
is where Apache actually writes its logs. Never assume the default path is correct.
Always run:
```bash
sudo grep -rh 'CustomLog' /etc/apache2/sites-enabled/ | sort -u
```

---

## 2. Forgotten NAT Rules Are Silent Attack Vectors

**What happened:**
The server had iptables rules blocking SSH from external IPs.
But a NAT rule on the perimeter router was forwarding an external
non-standard port directly to the server's SSH port.
This rule was created years ago, forgotten, and never removed.

**How it was found:**
```bash
nmap -Pn -p- --min-rate 5000 <PUBLIC_IP>
nmap -Pn -sV -p <UNEXPECTED_PORT> <PUBLIC_IP>
```
An SSH banner appeared on a non-standard port — revealing the NAT rule.

**The lesson:**
Scan your own perimeter regularly from an external network.
Audit all router NAT/forwarding rules quarterly.
Host-level firewall alone is not sufficient — defense in depth requires
protection at both the perimeter and the host.

---

## 3. Censys Indexes Everything

**What happened:**
Censys automatically scanned the public IP, detected all open ports
and services, and published the results publicly. Any attacker searching
for the organization name or IP on censys.io gets a complete map of
the exposed infrastructure.

**The lesson:**
Assume your public IP is fully indexed by Censys, Shodan, and similar tools.
Regularly search your own IP and organization name on these platforms to see
what attackers see. Close anything that should not be public.

---

## 4. Application Layer vs Network Layer Investigation

**What happened:**
During the SSH attack investigation, significant time was spent analyzing
web logs, DNS records, HTTP headers, and Censys data. The real answer
was at the network layer — a forgotten router NAT rule.

**The right approach:**
```
Start here:   tcpdump -i any port 22 -nn
              iptables -t nat -L -n -v
              nmap -p- <PUBLIC_IP>

Not here:     web logs, DNS records, HTTP headers
```

**The lesson:**
When an attack bypasses host-level controls, investigate the network
infrastructure first. Application logs tell you WHAT happened.
Network captures tell you HOW.

---

## 5. WordPress Attacks Are Automated and Constant

**What happened:**
Analysis of unmonitored web logs revealed a coordinated WordPress
brute-force botnet with 6+ IPs making 20,000+ login attempts across
multiple hosted sites.

**Attack signatures to detect:**
- `GET /?author=1` repeated rapidly = username enumeration
- `POST /wp-login.php` (200) followed by redirect to `/wp-admin/` = successful login
- Multiple IPs rotating User-Agent strings between requests = botnet

**The lesson:**
WordPress sites on shared hosting are constantly under attack.
Without SIEM visibility on web logs, successful compromises can go
undetected for months.

---

## 6. Fail2ban Needs Tuning for Production Load

**What happened:**
Fail2ban was active with 6 jails. Despite thousands of failed SSH attempts,
only 1 IP had ever been banned. Default settings are designed for low-volume
attacks — not for servers under constant automated scanning.

**Recommended tuning:**
```ini
[sshd]
maxretry = 3
findtime = 300
bantime  = 86400
```

**The lesson:**
Always check the ratio of total failed attempts to total bans.
If thousands of attempts result in near-zero bans, Fail2ban is not
configured for the actual attack volume.

---

## 7. Always Verify Exposure from External Network

**What happened:**
An admin panel was found listening on all interfaces. Internal tests
showed HTTP 200. But an external test from a mobile 5G connection
returned timeout — the gateway was blocking the port.

**The lesson:**
Never conclude a service is internet-exposed based on an internal test.
Always verify from a real external network (mobile 4G/5G, not office WiFi).

```powershell
# Windows PowerShell from external network
Test-NetConnection -ComputerName <IP> -Port <PORT>
```

---

## 8. Reverse Proxy Makes SIEM Attribution Useless Without `mod_remoteip`

**What happened:**
The server sits behind Nginx Proxy Manager (NPM). Apache was logging
the proxy's IP (`<NPM_IP>`) on every single request — from every client,
from every attacker. The SIEM dashboard showed thousands of alerts all
attributed to the same proxy IP. All attacker attribution was worthless.

**Root cause:** Apache's `LogFormat` was using `%h` (TCP connection IP =
proxy IP) instead of `%a` (post-remoteip substitution = real client IP).
`mod_remoteip` was installed but had no trusted proxy declared —
without `RemoteIPInternalProxy`, Apache ignores the forwarded header entirely.

**The fix:**
```apache
# /etc/apache2/mods-enabled/remoteip.conf
RemoteIPHeader X-Forwarded-For
RemoteIPInternalProxy <NPM_IP>
# Add Cloudflare ranges for Cloudflare-proxied sites
RemoteIPInternalProxy 103.21.244.0/22
RemoteIPInternalProxy 104.16.0.0/13
# ... all Cloudflare ranges

# /etc/apache2/apache2.conf
LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
#          ^^ was %h
```

**How to verify:** deploy a PHP headers dump (`<?php print_r(getallheaders()); ?>`)
and request it from a 4G mobile. Check which header the proxy sends
(`X-Forwarded-For`, `X-Real-IP`, or `CF-Connecting-IP`) — then configure
`RemoteIPHeader` accordingly. Confirm by checking the Apache log for your
real mobile IP.

**The lesson:**
On any server behind a reverse proxy, `%h` in `LogFormat` = proxy IP in
every log line = useless SIEM attribution. Always verify with a real external
connection, not just config file inspection. `mod_remoteip` needs both
`RemoteIPHeader` AND `RemoteIPInternalProxy` to work.

---

## 9. iptables LOG Events Bypass the Wazuh Alert Pipeline

**What happened:**
iptables LOG rules were added to detect direct communication between the
web server and MySQL cluster nodes. The events appeared in `/var/log/kern.log`
correctly — but custom Wazuh rules with `if_sid` never fired, despite
the events being clearly visible in archives.

**Root cause:** the native Wazuh `iptables-1` decoder classifies all iptables
log messages as `type: firewall`, routing them to a separate firewall queue.
Events in the firewall queue **bypass the standard rule engine entirely** —
`if_sid` rules never see them, regardless of level or configuration.

**The fix:** use rsyslog to intercept the specific log prefix before Wazuh
collection, reformat the line with a custom template that changes the
`program_name`, and write to a dedicated file:

```
# /etc/rsyslog.d/mysql-nodes.conf
template(name="custom_tpl" type="string"
         string="%TIMESTAMP% %HOSTNAME% MYSQL_ALERT: %msg%\n")
:msg, contains, "MYSQL_NODE_DIRECT" action(type="omfile"
    file="/var/log/mysql-nodes-direct.log"
    template="custom_tpl")
& stop
```

**The lesson:**
Never use raw iptables LOG output as input for custom Wazuh detection rules.
The `type: firewall` classification silently bypasses the rule engine.
Always reformat iptables events via rsyslog before feeding them to Wazuh.

---

## 10. FIM Rule Field Name — Silent Failure

**What happened:**
Custom FIM detection rules using `<field name="syscheck.path">` were written,
validated with `wazuh-analysisd -t` (no errors), deployed, and never fired.
Files were created in monitored directories, FIM alerts appeared in `alerts.json`
with the correct path — but the custom rules did nothing.

**Root cause:** FIM events use a separate internal pipeline that cannot be
tested with `wazuh-logtest`. The correct field name for path-based matching
in FIM rules is `<field name="file">` — not `syscheck.path`. Using the wrong
name produces no error and no warning — the rule simply never matches.

**The fix:**
```xml
<!-- Wrong — silently never fires -->
<field name="syscheck.path" type="pcre2">/home/namira/.*\.php$</field>

<!-- Correct -->
<field name="file" type="pcre2">/home/namira/.*\.php$</field>
```

**The lesson:**
FIM rules cannot be tested with `wazuh-logtest`. The only valid test is
creating/modifying a real file and checking `alerts.log` on the manager.
Always use `<field name="file">` for path-based FIM rule matching.

---

## 11. inotify Exhaustion — Recursive FIM on Shared Hosting

**What happened:**
An initial attempt to deploy real-time FIM recursively across all client home
directories exceeded the system's inotify watch limit. `vendor/` and
`node_modules/` trees alone contained 300,000+ subdirectories. The failure
broke real-time monitoring on all previously working paths — including paths
that had nothing to do with the failed configuration.

**Root cause:** inotify watches are a shared system-wide resource. Real-time
FIM requires one watch per subdirectory regardless of any `restrict` filter —
the filter only controls which changes trigger alerts, not how many directories
are watched.

**The fix:** replace global recursive FIM with a deliberately scoped per-client
configuration targeting only the paths that matter:

```xml
<directories realtime="yes" recursion_level="320">/home/<client>/public_html/public</directories>
<directories realtime="yes" recursion_level="0">/home/<client></directories>
<!-- NOT: <directories realtime="yes">/home</directories> -->
```

**The lesson:**
Never deploy recursive real-time FIM on a shared hosting server without first
auditing directory counts. Check the current limit:
```bash
cat /proc/sys/fs/inotify/max_user_watches
```
Scope FIM to specific paths. Exclude `vendor/`, `node_modules/`, `.git/`,
and any large dependency trees.

---

## 12. Wazuh Reserved Field Names — Silent Rule Engine Errors

**What happened:**
Custom decoder fields named `id`, `protocol`, and `url` were used in detection
rules with `<field name="...">`. Some caused explicit errors
(`Field 'id' is static`), others failed silently — the rule compiled but
never matched. Diagnosing these required reading the Wazuh source-level
documentation, not just the user guide.

**Reserved fields discovered:**

| Field name | Behavior when used in rules |
|---|---|
| `id` | Explicit error: `Field 'id' is static` |
| `protocol` | Explicit error: `Field 'protocol' is static` |
| `url` | Silent failure — rule never matches |

**The fix:**
- Rename `id` → `http_status` in the decoder
- Use `<match>` instead of `<field>` for `protocol` and `url` patterns:

```xml
<!-- Wrong -->
<field name="protocol">^POST$</field>

<!-- Correct -->
<match>POST</match>
```

**The lesson:**
Before naming a custom decoder field, test it in a rule with `wazuh-analysisd -t`.
If the rule compiles without error but never fires, the field name may be
reserved. Prefer descriptive, non-generic names (`http_status`, `http_method`,
`request_url`) over short generic ones (`id`, `protocol`, `url`).

---

## Reusable Checklist

### Before deploying on a new server
- [ ] Verify actual Apache log paths before assuming SIEM has visibility
- [ ] Check if server is behind a reverse proxy — verify `mod_remoteip` config
- [ ] Confirm `LogFormat` uses `%a` not `%h` (test with real external connection)
- [ ] Scan public IP with nmap from external network
- [ ] Audit all NAT/forwarding rules on perimeter router
- [ ] Check Fail2ban fail/ban ratio per jail
- [ ] Confirm iptables rules exist (not just assumed)
- [ ] Test admin panel accessibility from real external network
- [ ] Search organization name on Censys and Shodan
- [ ] Check inotify watch limit before deploying recursive FIM
- [ ] Check Redis, phpMyAdmin, and similar services for authentication

### Before writing Wazuh rules
- [ ] FIM rules → use `<field name="file">` not `syscheck.path`
- [ ] FIM rules → test by creating a real file, not with wazuh-logtest
- [ ] Custom decoder fields → avoid `id`, `protocol`, `url` (reserved)
- [ ] iptables LOG events → reformat via rsyslog before feeding to Wazuh
- [ ] Always run `wazuh-analysisd -t` before restarting the manager
- [ ] Verify FIM covers web directories, not just system directories
