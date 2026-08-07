# Log Collection Configuration — Apache, Webmin & Infrastructure

Author: Mohamed Amine Namouchi
Date: June 17, 2026
Last updated: August 2026
Status: ✅ Complete

---

## Context

Before this work, the Wazuh agent on the production hosting server was
monitoring an empty `/var/log/apache2/access.log` file, leaving the SIEM blind to
all web traffic across 50+ client virtual hosts. Each client site under Virtualmin
writes its own dedicated access log under `/var/log/virtualmin/`, which was not
being collected at all.

Additionally, the Webmin/Virtualmin admin panel itself — which manages the entire
hosting infrastructure (all client accounts, domains, and permissions) — had no
log collection configured, leaving authentication attempts to this high-value
target completely unmonitored.

---

## Part A — Apache & Webmin Log Collection

### 1.1 — Fix Virtualmin Log Path

**Problem:** Wazuh was configured to monitor `/var/log/apache2/access.log`, which
remains empty under a Virtualmin setup since each vhost logs separately.

**Fix:** Updated `ossec.conf` to monitor the actual per-client log files using a
wildcard pattern.

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/virtualmin/*_access_log</location>
  <out_format>$(location): $(log)</out_format>
</localfile>
```

**Note on `out_format`:** the `out_format` directive injects the source file path
as a prefix on each forwarded log line. This is what allows the custom decoder
(Phase 2) to extract the vhost name from the filename — producing a `vhost` field
on every alert. Without this directive, all 50+ client sites are indistinguishable
in the SIEM.

### 1.2 — Remove Empty Log Entry

Removed the now-obsolete `/var/log/apache2/access.log` entry from `ossec.conf`
to avoid wasted resources monitoring a file that never receives data under this
Virtualmin configuration.

### 1.6 — Add Webmin Log Monitoring

**Goal:** Monitor authentication and access activity on the Webmin/Virtualmin
admin panel, since it has full administrative control over all 50+ hosted
client accounts.

**Discovery:** The actual log path differs from the commonly assumed
`/var/log/webmin/miniserv.log`. On this server it is located at:

```
/var/webmin/miniserv.log
```

**Format:** Standard Apache Common Log Format (CLF):

```
<src_ip> - <username> [<timestamp>] "<method> <path> HTTP/<version>" <status> <size>
```

Failed authentication attempts are logged with an empty request field and a
`401` status:

```
<src_ip> - - [<timestamp>] "" 401 <size>
```

**Configuration applied:**

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/webmin/miniserv.log</location>
</localfile>
```

**Volume check before enabling:** counted log lines per day before committing
to full collection, to avoid unexpectedly flooding the SIEM pipeline.

| Day | Lines logged |
|---|---|
| Low-activity day | 42 |
| High-activity day | 255 |

Volume confirmed negligible compared to the existing 50+ vhost Apache log
ingestion — safe to collect in full.

**Resolution of known limitation (Phase 3):** the default Wazuh `web-accesslog`
decoder does not match failed authentication lines with empty request fields
(`"" 401`). A custom decoder (`webmin`) was built in Phase 3 using PCRE2 regex
to handle both the empty-request format and standard requests:

```xml
<decoder name="webmin">
  <prematch type="pcre2">^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - \S+ \[</prematch>
  <regex type="pcre2">^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \S+ \[\S+ \S+\] "\S*" (\d+)</regex>
  <order>srcip, http_status</order>
</decoder>
```

This decoder feeds detection rules 200501 (Webmin auth failure) and 200502
(Webmin brute force — 5+ failures in 60s). See Phase 3 documentation.

### 1.7 — Verify Log Ingestion

Validated using `wazuh-logtest` on the Wazuh server with real log lines pulled
directly from the monitored files.

**Successful match example (Virtualmin vhost access log — anonymized):**

```
Input:  /var/log/virtualmin/example.hr_access_log: <src_ip> - - [<timestamp>]
        "GET /wp-login.php HTTP/1.1" 200 4455 "-" "Mozilla/5.0..."

Phase 2 (decoding):
  name: apache-vhost-full
  srcip: <src_ip>
  protocol: GET
  url: /wp-login.php
  http_status: 200
  user_agent: Mozilla/5.0...
  vhost: example.hr
  wp_pattern: wp-login.php

Phase 3 (rules):
  id: 200100
  level: 4
  description: Web Hosting: WordPress login attempt from <src_ip> on example.hr
```

**Webmin auth failure example:**

```
Input:  <src_ip> - - [<timestamp>] "" 401 21892

Phase 2 (decoding):
  name: webmin
  srcip: <src_ip>
  http_status: 401

Phase 3 (rules):
  id: 200501
  level: 5
  description: Web Hosting: Webmin authentication failure from <src_ip>
```

---

## Part B — File Integrity Monitoring: Targeted Client Deployment

### Context

With log collection in place, the next priority was File Integrity Monitoring
(FIM) on client web roots — the most direct way to catch a webshell drop, a
tampered configuration file, or unauthorized changes to sensitive paths. A
targeted, per-client FIM configuration was designed and deployed as a pilot on
one client site (`namira` — a Laravel application), intended as a template for
replication.

Configuration scope: the public web root (primary webshell-drop target), public
media storage, the application routes directory (backdoor route injection
detection), a critical secrets file (`.env`), the account root directory
(non-recursive), and an equivalent set of monitors for a staging subdomain
(`demo.namira.hr`).

### Issue 1 — inotify watch exhaustion

**Problem:** an initial attempt to apply FIM recursively across the entire
home directory tree (50+ client sites) exhausted the system's inotify
watch limit. Combined directory count exceeded 300,000, driven largely by
`vendor/` and `node_modules/` dependency trees. Since inotify watches are a
shared, system-wide resource, the failure broke real-time monitoring even
on previously working, unrelated paths.

**Root cause:** the `restrict` attribute filters which file changes trigger
alerts on an already-watched directory — it does not reduce the number of
directories requiring inotify watches. Recursive real-time FIM needs one
watch per subdirectory regardless of any `restrict` filter.

**Resolution:** replaced the single global FIM block with a deliberately
scoped, per-client configuration.

### Issue 2 — `restrict` regex syntax

**Problem:** a `restrict` filter intended to alert only on PHP file changes
was written using PCRE-style escaping (`\.php$`). This silently broke the
baseline scan for the affected directory — zero files were indexed,
including files that predated the scan.

**Root cause:** the `restrict` attribute only accepts sregex (OS_Match)
syntax unless explicitly typed otherwise. In sregex, a backslash before a
dot does not mean "literal dot" — it is interpreted as "any character," the
opposite of the intended behavior.

**Resolution:** removed `restrict` entirely rather than rewriting it in
correct sregex syntax, since extension-based filtering was not a strict
requirement for this path and removing it carries no inotify cost.

**Result:** baseline scan went from 0 to 486 indexed files after the fix.

### Issue 3 — incorrect verification method for real-time detection

**Problem:** files created inside real-time monitored directories never
appeared in the agent's local FIM SQLite database, even after extended
waits and multiple agent restarts.

**Root cause (confirmed by Wazuh support, reproduced on their own lab):**
the agent's local FIM database only refreshes at the next scheduled scan —
it does not reflect real-time events immediately, by design. Real-time
alerting runs on a separate, independent path that fires immediately and is
visible on the manager side (alert log and dashboard), regardless of when
the local database next syncs.

**Resolution:** switched verification from the local agent database to the
manager-side alert pipeline.

**Result:** a test file created in a real-time monitored directory produced
a complete alert — including an automatic VirusTotal lookup — visible on
the dashboard within 2 seconds of creation:

```
File created:  11:30:19
Alert visible: 11:30:21
Rule 87104 — VirusTotal: Alert - <file> - No positives found
```

**Lesson recorded:** the local agent SQLite database is not a valid signal
for verifying real-time FIM detection. The manager-side alert pipeline is
now the standard verification method for all future FIM deployments.

### Issue 4 — FIM rule field name (discovered in Phase 3)

**Problem:** custom FIM detection rules using `<field name="syscheck.path">`
never fired, despite FIM events being correctly generated and visible in
`alerts.json` with `"path": "/home/namira/..."`.

**Root cause:** FIM events use a separate internal pipeline that does not
pass through `wazuh-logtest`. The correct field name for path-based matching
in FIM rules is `<field name="file">` — not `syscheck.path` — as documented
in the Wazuh FIM rule reference. Using `syscheck.path` silently fails with
no error message.

**Resolution:** replaced all FIM rule field references:

```xml
<!-- Wrong — silently fails -->
<field name="syscheck.path" type="pcre2">/home/namira/.*\.php$</field>

<!-- Correct -->
<field name="file" type="pcre2">/home/namira/.*\.php$</field>
```

**Note:** FIM rules cannot be tested with `wazuh-logtest` — the only valid
test method is creating/modifying a real file in a monitored directory and
checking `alerts.log` on the manager side.

### Final FIM Configuration (namira client)

```xml
<!-- Secrets file — no diff to prevent values leaking into Wazuh logs -->
<directories realtime="yes" report_changes="no">
  /home/namira/public_html/.env
</directories>

<!-- Public media storage -->
<directories realtime="yes" report_changes="yes" recursion_level="320">
  /home/namira/public_html/storage/app/public
</directories>

<!-- Public web root — primary webshell-drop target -->
<directories realtime="yes" report_changes="yes" recursion_level="320">
  /home/namira/public_html/public
</directories>

<!-- Routes directory — backdoor route injection detection -->
<directories realtime="yes" report_changes="yes" recursion_level="320">
  /home/namira/public_html/routes
</directories>

<!-- Account root — non-recursive, detects new files/dirs at top level only -->
<directories realtime="yes" report_changes="yes" recursion_level="0">
  /home/namira
</directories>

<!-- demo.namira.hr — mirrors production monitors -->
<directories realtime="yes" report_changes="no">
  /home/namira/domains/demo.namira.hr/public_html/.env
</directories>
<directories realtime="yes" report_changes="yes" recursion_level="320">
  /home/namira/domains/demo.namira.hr/public_html/storage/app/public
</directories>
<directories realtime="yes" report_changes="yes" recursion_level="320">
  /home/namira/domains/demo.namira.hr/public_html/public
</directories>
```

| Path | Mode | Notes |
|---|---|---|
| `.env` | realtime, no diff | Prevents secret values from being written into Wazuh logs |
| `storage/app/public` | realtime, recursive | Public-facing uploaded assets |
| `public/` | realtime, recursive | Primary webshell-drop target |
| `routes/` | realtime, recursive | Backdoor route injection detection |
| `/home/namira` | realtime, non-recursive | Detects new files/dirs at top level only |
| `demo.namira.hr` (equivalent set) | realtime | Mirrors production monitors |

---

## Part C — Infrastructure Log Collection (MySQL Cluster Monitoring)

### Context

The hosting server communicates with a backend MySQL cluster via a load
balancer. Any direct communication between the hosting server and a MySQL
cluster node (bypassing the load balancer) is abnormal and may indicate a
misconfiguration or lateral movement. The infrastructure team requested
real-time alerting on any such communication.

### Approach

iptables LOG rules capture all traffic in both directions between the hosting
server and the three MySQL cluster nodes:

```bash
# Outbound (server → nodes)
iptables -A OUTPUT -d <node1-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A OUTPUT -d <node2-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A OUTPUT -d <node3-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4

# Inbound (nodes → server)
iptables -A INPUT -s <node1-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A INPUT -s <node2-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A INPUT -s <node3-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
```

### Critical issue — iptables LOG events bypass the Wazuh alert pipeline

iptables LOG messages go to `/var/log/kern.log` by default. The native Wazuh
`iptables-1` decoder classifies all iptables events as `type: firewall`, routing
them to a separate firewall queue that **bypasses the standard alert pipeline
entirely**. Custom rules using `if_sid` never fire on these events.

**Fix:** rsyslog intercepts messages containing `MYSQL_NODE_DIRECT`, reformats
them with a custom template changing the `program_name`, and writes to a
dedicated file owned by the Wazuh user:

```
# /etc/rsyslog.d/mysql-nodes.conf
template(name="mysql_node_tpl" type="string"
         string="%TIMESTAMP% %HOSTNAME% MYSQL_ALERT: %msg%\n")
:msg, contains, "MYSQL_NODE_DIRECT" action(type="omfile"
    file="/var/log/mysql-nodes-direct.log"
    template="mysql_node_tpl")
& stop
```

The `& stop` directive prevents double-processing in `kern.log`.

File permissions (Wazuh user must be able to read):
```bash
chown syslog:wazuh /var/log/mysql-nodes-direct.log
chmod 640 /var/log/mysql-nodes-direct.log
```

Wazuh agent collection:
```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/mysql-nodes-direct.log</location>
</localfile>
```

Detection rule 200600 (level 12, `mail: True`) fires on any event in this file.
See Use Case UC-01 for full documentation.

---

## Validation Summary

| Task | Description | Status |
|---|---|---|
| 1.1 | Virtualmin per-vhost log path configured with `out_format` | ✅ Done |
| 1.2 | Obsolete empty log entry removed | ✅ Done |
| 1.3 | Real-time FIM on web server root | ✅ Done — confirmed via manager-side alerting |
| 1.4 | Real-time FIM on client site directories (namira) | ✅ Done — confirmed via manager-side alerting |
| 1.6 | Webmin admin panel log collection configured | ✅ Done |
| 1.7 | End-to-end ingestion verified | ✅ Done — full decoder + rule chain validated |
| 1.8 | FIM detection validated with real file creation | ✅ Done — alert in 2 seconds including VirusTotal scan |
| — | Webmin decoder + brute force rules (Phase 3) | ✅ Done — rules 200501, 200502 |
| — | FIM detection rules (Phase 3) | ✅ Done — rules 200400, 200401, 200402 |
| — | MySQL cluster direct access monitoring | ✅ Done — rule 200600, UC-01 |

---

*Document maintained as part of Phase 1 — Wazuh Agent Configuration*
*Last updated: August 2026*
