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

# Part B — File Integrity Monitoring: Targeted Client Deployment (Pilot)
 
### Context
 
With log collection in place, the next priority was File Integrity
Monitoring (FIM) on client web roots — the most direct way to catch a
webshell drop, a tampered configuration file, or unauthorized changes to
sensitive paths. A targeted, per-client FIM configuration was designed and
deployed as a pilot on one client site, intended as a template for
replication across the other hosted clients.
 
Configuration scope: the public web root (primary webshell-drop target),
public media storage, the application routes directory (backdoor route
injection detection), a critical secrets file, the account root directory
(non-recursive), and an equivalent set of monitors for a staging subdomain.
 
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
now the standard verification method for all future FIM deployments on
this project.
 
### Final Configuration Summary
 
| Path | Mode | Notes |
|---|---|---|
| Secrets file | realtime, no diff capture | Prevents secret values from being written into Wazuh's own logs |
| Public media storage | realtime, recursive | Public-facing uploaded assets only |
| Public web root | realtime, recursive | Primary webshell-drop target |
| Application routes | realtime, recursive | Backdoor route injection detection |
| Account root | realtime, non-recursive | Detects new files/dirs at the top level only |
| Staging subdomain (equivalent set) | realtime | Mirrors production monitors |
 
---
 
## Validation Summary
 
| Task | Description | Status |
|---|---|---|
| 1.1 | Virtualmin per-vhost log path configured | ✅ Done |
| 1.2 | Obsolete empty log entry removed | ✅ Done |
| 1.3 | Real-time FIM on web server root | ✅ Done — confirmed via manager-side alerting |
| 1.4 | Real-time FIM on client site directories | ✅ Done — confirmed via manager-side alerting |
| 1.6 | Webmin admin panel log collection configured | ✅ Done (collection only — detection rules planned for Phase 2) |
| 1.7 | End-to-end ingestion verified via wazuh-logtest | ✅ Done |
| 1.8 | Test FIM detection with a created file | ✅ Done — alert fired within 2 seconds, including an automated VirusTotal scan |
 
---
Document maintained as part of Phase 1 — Wazuh Agent Configuration
Last updated: June 2026


