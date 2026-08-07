# 🛡️ SIEM Web Hosting Security — punica.ofir.hr

> Detection engineering on a production shared web hosting server: from a SIEM blind spot to full-coverage threat detection across 50+ client WordPress sites.

[![Phase 1](https://img.shields.io/badge/Phase%201-Agent%20Config-green)](02-wazuh-config/)
[![Phase 2](https://img.shields.io/badge/Phase%202-Custom%20Decoders-green)](02-wazuh-config/)
[![Phase 3](https://img.shields.io/badge/Phase%203-Detection%20Rules-green)](03-detection-rules/)
[![Phase 4](https://img.shields.io/badge/Phase%204-Active%20Response-green)](04-active-response/)
[![Phase 5](https://img.shields.io/badge/Phase%205-Dashboard-green)](05-dashboard/)
[![Wazuh](https://img.shields.io/badge/Wazuh-4.14-blue)](https://wazuh.com)
[![Apache](https://img.shields.io/badge/Apache-2.4-red)](https://httpd.apache.org)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

---

## 📌 Overview

This repository documents a full detection engineering engagement on a **production shared web hosting server** running Apache2 + Virtualmin, hosting 50+ client websites (WordPress + Laravel), during a 5-month cybersecurity internship at OFIR LTD — Osijek, Croatia (April–August 2026).

The server had a Wazuh agent installed but was effectively **blind** — the SIEM was monitoring an empty log file, missing all web traffic across every client site. This project goes from that zero-visibility state to a production-grade detection pipeline with custom decoders, 25 detection rules, real-time Mattermost alerting, a SOC dashboard, and an active response framework.

**Every rule, decoder, and alert was validated against real attack traffic captured on the production server.**

---

## 🏗️ Architecture

```
                    Internet
                       │
          ┌────────────┴────────────┐
          │                         │
 ┌────────▼────────┐     ┌──────────▼──────────┐
 │   Cloudflare    │     │    MikroTik CCR      │
 │  (11 vhosts)   │     │  (perimeter router)  │
 └────────┬────────┘     └──────────┬───────────┘
          │  CF-Connecting-IP       │
          │  (real client IP)       │
          └──────────────┬──────────┘
                         │
                ┌────────▼────────┐
                │  Nginx Proxy    │
                │  Manager (NPM)  │
                │  X-Forwarded-For│
                └────────┬────────┘
                         │
               ┌─────────▼───────────────────────┐
               │         punica.ofir.hr           │
               │  Ubuntu 22.04 — Apache2          │
               │  Virtualmin — 50+ client vhosts  │
               │  WordPress + Laravel apps        │
               │                                  │
               │  ┌──────────────────────────┐    │
               │  │     Wazuh Agent          │    │
               │  │  + mod_remoteip (IP fix) │    │
               │  │  + FIM (namira scope)    │    │
               │  │  + iptables LOG rules    │    │
               │  └────────────┬─────────────┘    │
               └───────────────┼──────────────────┘
                               │  AES-256 encrypted
                    ┌──────────▼──────────┐
                    │    Wazuh Manager    │
                    │  Custom decoders    │
                    │  25 detection rules │
                    │  Active response    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │     OpenSearch      │
                    │  SOC Dashboard      │
                    │  16 visualizations  │
                    └─────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │     Mattermost      │
                    │  Real-time alerts   │
                    │  Contextual per     │
                    │  attack type        │
                    └─────────────────────┘
```

---

## 📊 Project Summary

| Phase | Description | Status |
|---|---|---|
| **0 — Discovery** | Security discovery of an unknown production server | ✅ Complete |
| **1 — Agent Config** | Log collection fix, FIM deployment, Webmin monitoring | ✅ Complete |
| **2 — Custom Decoders** | Apache vhost decoder, WP pattern extractor, vhost name extractor | ✅ Complete |
| **3 — Detection Rules** | 25 custom rules across 5 attack families | ✅ Complete |
| **3b — IP Transparency** | mod_remoteip fix — real client IPs logged for all direct vhosts | ✅ Complete |
| **3c — MySQL Monitoring** | iptables-based direct cluster node access detection | ✅ Complete |
| **4 — Active Response** | Mattermost contextual alerting — 25 rule-specific messages | ✅ Complete |
| **5 — Dashboard** | OpenSearch SOC dashboard — 16 visualizations | ✅ Complete |

---

## 🔍 Key Findings (Sanitized)

| # | Finding | Severity |
|---|---|---|
| 1 | Wazuh monitoring empty Apache log — SIEM blind to all 50+ client sites | Critical |
| 2 | No host-based firewall configured on production server | Critical |
| 3 | Forgotten NAT rule on perimeter router exposing SSH on non-standard port | High |
| 4 | Active SSH brute-force campaign (automated Go-based script) | High |
| 5 | WordPress botnet targeting multiple hosted sites simultaneously | High |
| 6 | Apache logging NPM proxy IP instead of real client IP — SIEM useless for attribution | High |
| 7 | inotify watch exhaustion when attempting recursive FIM on full /home tree | High |
| 8 | FTP service without TLS configured | High |
| 9 | Redis without password (localhost scope) | Medium |
| 10 | No HTTP security headers on any client site | Medium |
| 11 | Webmin admin panel log not monitored | Medium |
| 12 | iptables kernel events classified as firewall type — bypassed alert pipeline | Medium |

---

## 🔎 Detection Rules

### Family 1 — WordPress Attacks (`200100–200106`)

| Rule ID | Description | Level | MITRE |
|---|---|---|---|
| 200100 | WP login attempt (POST to wp-login.php) | 4 | T1110.001 |
| 200101 | WP brute force — 10+ attempts in 60s from same IP | 10 | T1110.001 |
| 200102 | Username enumeration via ?author= | 6 | T1589.003 |
| 200103 | Rapid enumeration — 5+ requests in 30s | 10 | T1589.003 |
| 200104 | wp-admin access from non-whitelisted IP | 8 | T1078 |
| 200105 | XML-RPC abuse (POST to xmlrpc.php) | 8 | T1190 |
| 200106 | Plugin upload / webshell drop attempt | 10 | T1505.003 |

### Family 2 — Scanners & Bots (`200200–200203`)

| Rule ID | Description | Level | MITRE |
|---|---|---|---|
| 200200 | Scanner User-Agent (nikto/sqlmap/nuclei/gobuster) | 8 | T1595.002 |
| 200201 | Internet indexer (CensysInspect/ShodanBot) | 3 | T1595 |
| 200202 | 404 flood — 30+ not found responses in 60s from same IP | 10 | T1595.002 |
| 200203 | High request rate — 100+ requests in 60s from same IP | 8 | T1595 |

### Family 3 — Web Application Attacks (`200300–200306`)

| Rule ID | Description | Level | MITRE |
|---|---|---|---|
| 200300 | SQL injection attempt (UNION SELECT, %27, 1=1) | 10 | T1190 |
| 200301 | XSS attempt (%3Cscript, onerror=, javascript:) | 8 | T1190 |
| 200302 | Path traversal (../, %2e%2e) | 10 | T1190 |
| 200303 | Sensitive file access (.env, wp-config, .git, passwd) | 10 | T1083 |
| 200304 | Remote File Inclusion (http:// in URL parameter) | 12 | T1190 |
| 200305 | Command injection (cmd=, exec=, system() in URL) | 12 | T1059 |
| 200306 | Webshell access (eval(, base64_decode(, shell_exec() in URL) | 14 | T1505.003 |

### Family 4 — File Integrity Monitoring (`200400–200402`)

| Rule ID | Description | Level | MITRE |
|---|---|---|---|
| 200400 | New PHP file created in namira web directory | 12 | T1505.003 |
| 200401 | PHP file modified in namira web directory | 10 | T1505.003 |
| 200402 | Config file modified (.env, .conf, .yml) | 10 | T1565.001 |

### Family 5 — Auth Brute Force (`200501–200502`)

| Rule ID | Description | Level | MITRE |
|---|---|---|---|
| 200501 | Webmin authentication failure | 5 | T1110 |
| 200502 | Webmin brute force — 5+ failures in 60s | 12 | T1110.001 |

### Infrastructure (`200600`)

| Rule ID | Description | Level | MITRE |
|---|---|---|---|
| 200600 | Direct communication between web server and MySQL cluster node (bypassing load balancer) | 12 | T1190 |

---

## 🔧 Key Technical Challenges & Solutions

### 1. SIEM blind to all web traffic
**Problem:** Virtualmin overrides Apache's default log path. All 50+ client sites log to `/var/log/virtualmin/<domain>_access_log` — Wazuh was pointed at `/var/log/apache2/access.log` which is empty.

**Fix:** Updated `ossec.conf` with a wildcard pattern covering all Virtualmin per-client log files.

### 2. No vhost name in logs
**Problem:** Apache log lines contain no domain name — every alert from every site looks identical in the SIEM.

**Fix:** Used Wazuh agent's `out_format` directive to inject the source filename as a prefix, then extracted the domain name via a custom decoder sibling — producing a `vhost` field on every alert.

### 3. NPM proxy IP logged instead of real client IP
**Problem:** Apache was logging the NPM reverse proxy IP (`<NPM_IP>`) instead of real client IPs, making all SIEM attribution useless.

**Investigation:** Discovered NPM sends `X-Forwarded-For` (not `X-Real-IP`). Apache's `LogFormat` was using `%h` (TCP connection IP) instead of `%a` (post-remoteip substitution). `mod_remoteip` was installed but had no trusted proxy declared.

**Fix:** Configured `mods-enabled/remoteip.conf` with `RemoteIPHeader X-Forwarded-For`, `RemoteIPInternalProxy <NPM_IP>`, and all Cloudflare IP ranges as `RemoteIPInternalProxy`. Changed `LogFormat combined` from `%h` to `%a`.

**Result:** 38 direct vhosts now log real client IPs. 11 Cloudflare-proxied vhosts pending NPM-side `CF-Connecting-IP` forwarding config.

### 4. FIM events bypass rule engine
**Problem:** Custom rules using `<field name="syscheck.path">` and `<if_sid>554</if_sid>` never fired, despite FIM events being correctly generated and visible in `alerts.json`.

**Root cause:** FIM events use a separate internal pipeline and are not testable via `wazuh-logtest`. The correct field name for path-based matching in FIM rules is `<field name="file">` (not `syscheck.path`), as documented in the Wazuh FIM rule reference.

**Fix:** Replaced all FIM rule field references from `syscheck.path` to `file`.

### 5. iptables LOG events bypass alert pipeline
**Problem:** iptables LOG rules for MySQL cluster monitoring generated events that were classified as `type: firewall` by the native `iptables-1` Wazuh decoder — routing them to a separate firewall queue that bypasses the standard alert pipeline entirely.

**Fix:** Used rsyslog to intercept events containing `MYSQL_NODE_DIRECT`, reformat them with a custom template that changes the `program_name`, and write to a dedicated file owned by the Wazuh user — bypassing the firewall decoder entirely.

### 6. inotify watch exhaustion
**Problem:** Attempting recursive FIM on the full `/home` tree (50+ client sites including `vendor/` and `node_modules/`) exhausted the system's inotify watch limit, breaking real-time monitoring on all paths.

**Fix:** Replaced global recursive FIM with a deliberately scoped, per-client configuration targeting only the paths that matter: webroot, storage, routes, `.env`, and account root (non-recursive).

---

## 🗂️ Repository Structure

```
SIEM-Wazuh-webhosting-security/
│
├── README.md
│
├── 01-discovery/
│   └── Web-Hosting-Server-Discovery-Playbook.md    # Full discovery methodology
│
├── 02-wazuh-config/
│   ├── 01-log-collection-config.md                 # Phase 1 — log paths, FIM, Webmin
│   └── 02-custom-decoders.md                       # Phase 2 — apache-vhost-full family
│
├── 03-detection-rules/
│   ├── 01-wordpress-attacks.md                     # Rules 200100–200106
│   ├── 02-scanners-bots.md                         # Rules 200200–200203
│   ├── 03-web-app-attacks.md                       # Rules 200300–200306
│   ├── 04-fim-rules.md                             # Rules 200400–200402
│   ├── 05-auth-brute-force.md                      # Rules 200501–200502
│   └── rules/
│       └── webhosting-rules.xml                    # Full rule file (sanitized)
│
├── 04-active-response/
│   ├── 01-ip-transparency-fix.md                   # mod_remoteip investigation & fix
│   └── scripts/
│       ├── web-alert-mattermost.sh                 # Contextual Mattermost alerts
│       └── web-block.sh                            # IP blocking (pending NPM fix)
│
├── 05-dashboard/
│   └── 01-soc-dashboard.md                         # OpenSearch dashboard documentation
│
├── 05-use-cases/
│   └── UC-01-mysql-cluster-node-monitoring.md      # MySQL direct access detection
│
├── 06-threat-hunting/
│   └── ssh-attack-investigation.md                 # Real SSH brute-force investigation
│
└── 07-lessons-learned/
    └── key-findings-01.md                          # Key takeaways
```

---

## 🚨 Active Response

### web-alert-mattermost.sh

Contextual Mattermost alerts — one dedicated message format per attack type, based on rule ID. Each alert includes:

- 🎯 Attack type with emoji (contextual per rule)
- Source IP + geolocation (country, city, organization via ipapi.co)
- Target vhost + URL
- MITRE ATT&CK technique + tactic
- Raw log line
- Direct dashboard link

**25 rule-specific message templates** covering all detection families.

### web-block.sh *(pending)*

Automatic IP blocking via iptables — pending resolution of Cloudflare-proxied vhost IP transparency (NPM-side configuration by infrastructure team).

Whitelist protects internal IPs  from accidental blocking.

---

## 📊 SOC Dashboard

Built in OpenSearch — 16 visualizations covering:

| Visualization | Type |
|---|---|
| Dashboard Header (project context) | Markdown |
| Total Alerts — punica | Metric |
| Alerts Timeline | Vertical Bar |
| Alerts by Severity Level | Pie |
| Top Triggering IPs | Horizontal Bar |
| Top Targeted Vhosts | Pie |
| Top Attack Types | Vertical Bar |
| Top Triggered Rules | Data Table |
| MITRE ATT&CK Techniques | Horizontal Bar |
| WordPress Attacks Breakdown | Vertical Bar |
| WordPress Attack Patterns | Pie |
| Web App Attacks | Vertical Bar |
| Scanner & Bot Detection | Vertical Bar |
| FIM Alerts | Data Table |
| MySQL Cluster Direct Access | Metric |
| Attackers Geolocation | Map |

---

## 🛠️ Tools Used

- **Wazuh 4.14** — SIEM agent + manager + active response
- **OpenSearch** — log storage + SOC dashboards
- **Apache2 + mod_remoteip** — web server + IP transparency fix
- **Virtualmin/Webmin** — hosting panel (50+ client accounts)
- **rsyslog** — log routing and reformatting
- **iptables** — network-level event capture (MySQL cluster monitoring)
- **Mattermost** — real-time alerting
- **ipapi.co** — IP geolocation enrichment
- **VirusTotal** — automated FIM hash lookup (native Wazuh integration)
- **Nikto, sqlmap** — rule validation (authorized testing)
- **Kali Linux + Burp Suite** — security testing

---

## ⚙️ Prerequisites

| Component | Version | Notes |
|---|---|---|
| Ubuntu Server | 22.04 LTS | Hosting server (agent side) |
| Wazuh Manager | 4.14 | Separate server |
| Apache2 | 2.4 | With mod_remoteip enabled |
| Virtualmin | Latest | Hosting panel |
| OpenSearch | 2.x | Bundled with Wazuh |
| Mattermost | Self-hosted | For active response alerts |

---

## 🔑 Key Lessons Learned

1. **On Virtualmin servers, always verify the actual Apache log path first** — the default `/var/log/apache2/access.log` is empty. Real logs are in `/var/log/virtualmin/`.

2. **`wazuh-analysisd -t` before every restart** — catches syntax errors before they cause production downtime. Two outages during this project would have been avoided.

3. **FIM events use a separate pipeline** — `wazuh-logtest` cannot test FIM rules. The correct field for path-based FIM rules is `<field name="file">`, not `<field name="syscheck.path">`.

4. **iptables LOG events are classified as `type: firewall`** — they bypass the standard alert pipeline and never reach custom rules. Use rsyslog to reformat them before Wazuh collection.

5. **`mod_remoteip` needs both `RemoteIPHeader` and `RemoteIPInternalProxy`** — declaring the header alone is not enough. Without a trusted proxy declaration, Apache ignores the header entirely.

6. **Real-time FIM verification must happen on the manager side** — the agent-side SQLite database only reflects the last scheduled scan, not real-time events.

7. **Recursive FIM on shared hosting = inotify exhaustion** — `vendor/` and `node_modules/` trees alone can contain 300,000+ subdirectories. Always scope FIM deliberately.

---

## 👤 Author

**Mohamed Amine Namouchi**
Cybersecurity Engineering Student — Polytech Dijon (Network Security & Quality, 4th year)
Internship: SOC Analyst / Blue Team / Detection Engineer — OFIR LTD, Osijek, Croatia (April–August 2026)

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/med-namouchi)
[![GitHub](https://img.shields.io/badge/GitHub-MedNamouchi-black)](https://github.com/MedNamouchi)

---

## 📄 License

MIT — free to use, adapt, and build on.

---

*All findings are sanitized. No real IPs, domains, credentials, or client data are included in this repository.*
