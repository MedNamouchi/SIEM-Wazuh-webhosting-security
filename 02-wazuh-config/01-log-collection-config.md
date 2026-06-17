# Log Collection Configuration — Apache & Webmin

Tasks: 1.1, 1.2, 1.6, 1.7
Author: Mohamed Amine Namouchi
Date: June 17, 2026
Status: ✅ Complete

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

## 1.1 — Fix Virtualmin Log Path

**Problem:** Wazuh was configured to monitor `/var/log/apache2/access.log`, which
remains empty under a Virtualmin setup since each vhost logs separately.

**Fix:** Updated `ossec.conf` to monitor the actual per-client log files using a
wildcard pattern.

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/virtualmin/*_access_log</location>
</localfile>
```

## 1.2 — Remove Empty Log Entry

Removed the now-obsolete `/var/log/apache2/access.log` entry from `ossec.conf`
to avoid wasted resources monitoring a file that never receives data under this
Virtualmin configuration.

## 1.6 — Add Webmin Log Monitoring

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

**Known limitation (tracked separately):** the default Wazuh `web-accesslog`
decoder does not match failed authentication lines, since its regex expects a
populated HTTP request between quotes (`"METHOD path HTTP/x.x"`), while Webmin
logs an empty string (`""`) on auth failure. A custom child decoder plus a
correlation rule (`same_source_ip`) is required to detect brute-force attempts
against the admin panel. This is planned as a dedicated detection-engineering
task and is not yet implemented.

## 1.7 — Verify Log Ingestion

Validated using `wazuh-logtest` on the Wazuh server with real log lines pulled
directly from the monitored files.

**Successful match example (Webmin, valid request — anonymized):**

```
Input:  <src_ip> - <username> [<timestamp>] "GET /stats.cgi HTTP/1.1" 200 198

Phase 2 (decoding):
  name: web-accesslog
  id: 200
  protocol: GET
  srcip: <src_ip>
  url: /stats.cgi

Phase 3 (rules):
  id: 31108
  level: 0
  description: Ignored URLs (simple queries)
```

Confirms the Apache decoder correctly parses both Virtualmin and Webmin log
sources end to end, from agent collection through manager decoding.



---
Document maintained as part of Phase 1 — Wazuh Agent Configuration
Last updated: June 2026
