# Phase 5 — SOC Dashboard

Dashboard: 🛡️ Web Hosting Security — SOC Dashboard
Author: Mohamed Amine Namouchi
Date: August 2026
Status: ✅ Live in production — OpenSearch

---

## Overview

The SOC dashboard provides a single-pane-of-glass view of all security
events across the 50+ client websites hosted on the production server.
It is designed to be readable by anyone — not just SOC analysts — with
clear labels, contextual visualizations, and a logical information hierarchy
from the most general (total alert count) to the most specific (individual
file changes, MySQL cluster events).

**Index pattern:** `wazuh-alerts-*`
**Agent filter:** `agent.id: <your-agent-id>` (production hosting server)
**Default time range:** Last 24 hours

---

## Dashboard Structure

The dashboard contains **16 visualizations** organized in 5 sections:

---

### Section 1 — Header & Overview

#### Dashboard Header (Markdown)
A Markdown panel at the top of the dashboard that explains the context
to any reader — what the dashboard monitors, which server, which rule
families, and the date of last update. Makes the dashboard self-documenting
for non-SOC readers (management, clients, auditors).

```markdown
# 🛡️ Web Hosting Security — SOC Dashboard
**Agent:** <hosting-server> | **Rules:** 200100–200600
**Stack:** Wazuh 4.14 + OpenSearch | **Sites monitored:** 50+
```

#### Total Alerts — Metric
A single number showing the total alert count for the selected time range.
The fastest health check — if this number is significantly higher than
the previous period, investigate.

**Type:** Metric
**Field:** Count
**Filter:** `agent.id: <your-agent-id>`

---

### Section 2 — Attack Overview

#### Alerts Timeline — Vertical Bar
Shows alert volume over time, grouped by 30-minute intervals. Reveals
attack patterns — sustained campaigns appear as long plateaus, burst
attacks appear as sharp spikes.

**Type:** Vertical Bar
**X-axis:** Date Histogram → `@timestamp` → Auto interval
**Y-axis:** Count

#### Alerts by Severity Level — Pie
Distribution of alerts across Wazuh severity levels (4, 5, 6, 8, 10, 12, 14).
A healthy distribution has mostly level 4-6 (informational) with occasional
level 10+ (confirmed attacks). A surge in level 12+ requires immediate attention.

**Type:** Pie
**Buckets:** Terms → `rule.level` → Top 15

#### Top Attack Types — Vertical Bar
The 10 most frequent attack descriptions. Immediately answers "what is
attacking us most?" — brute force, scanners, LFI, etc.

**Type:** Vertical Bar
**X-axis:** Terms → `rule.description` → Top 10

---

### Section 3 — Attribution

#### Top Triggering IPs — Horizontal Bar
The 10 IP addresses generating the most alerts. The primary investigation
starting point — a new IP at the top of this list warrants immediate
investigation.

**Type:** Horizontal Bar
**Y-axis:** Terms → `data.srcip` → Top 10

**Note:** IPs from Cloudflare-proxied sites may appear as Cloudflare
IP ranges (`104.x`, `172.67.x`) until the NPM-side IP transparency fix
is deployed. These should not be blocked.

#### Top Targeted Vhosts — Pie
Which client sites are most frequently targeted. Helps prioritize
hardening efforts — a site appearing consistently at the top may need
additional protection (WAF, login limiting, plugin audit).

**Type:** Pie
**Buckets:** Terms → `data.vhost` → Top 10

#### Attackers Geolocation — Map
Geographic distribution of alert source IPs. Provides visual context
on attack origin — not actionable alone, but useful for threat intelligence
and reporting.

**Type:** Maps
**Field:** `GeoLocation.location`

---

### Section 4 — Technical Detail

#### Top Triggered Rules — Data Table
Tabular view of the most frequently triggered rules with their IDs,
descriptions, and counts. More precise than "Top Attack Types" — allows
direct rule-level investigation.

**Type:** Data Table
**Buckets:**
- Split rows → Terms → `rule.id` → Top 10
- Split rows → Terms → `rule.description` → Top 10

#### MITRE ATT&CK Techniques — Horizontal Bar
Distribution of alerts mapped to MITRE ATT&CK techniques. Provides
a framework-level view of the attack landscape — useful for compliance
reporting and executive summaries.

**Type:** Horizontal Bar
**Y-axis:** Terms → `rule.mitre.technique` → Top 10

---

### Section 5 — Attack Family Breakdown

#### WordPress Attacks Breakdown — Vertical Bar
Detailed view of WordPress-specific alerts (rules 200100–200106).
Breaks down by description to show which WP attack type is most prevalent:
brute force, XML-RPC, enumeration, plugin upload.

**Type:** Vertical Bar
**Filter:** `rule.groups: wordpress`
**X-axis:** Terms → `rule.description` → Top 10

#### WordPress Attack Patterns — Pie
Distribution of the `wp_pattern` field values — shows which WordPress
endpoint is most attacked (`wp-login.php`, `xmlrpc.php`, `wp-admin`, `?author=`).

**Type:** Pie
**Buckets:** Terms → `data.wp_pattern` → Top 10

#### Web App Attacks — Vertical Bar
Detailed view of web application attack alerts (rules 200300–200306).
Shows distribution across SQLi, XSS, path traversal, LFI, RFI, command
injection, and webshell access attempts.

**Type:** Vertical Bar
**Filter:** `rule.groups: web_attack`
**X-axis:** Terms → `rule.description` → Top 10

#### Scanner & Bot Detection — Vertical Bar
Alerts from scanner detection rules (200200–200203). Shows which scanner
types are most active and which IPs are generating the most scan traffic.

**Type:** Vertical Bar
**Filter:** `rule.id: (200200 OR 200201 OR 200202 OR 200203)`
**X-axis:** Terms → `data.srcip` → Top 10

#### FIM Alerts — Data Table
File integrity monitoring events — new PHP files created, PHP files
modified, config files changed. Each row shows the file path and event
type. Any new entry here requires immediate investigation.

**Type:** Data Table
**Filter:** `rule.groups: syscheck`
**Buckets:**
- Split rows → Terms → `syscheck.path` → Top 10
- Split rows → Terms → `syscheck.event` → Top 5

#### MySQL Cluster Direct Access — Metric
Count of direct communications between the web server and MySQL cluster
nodes (rule 200600). This number should always be **zero** in normal
operation. Any non-zero value requires immediate investigation and email
notification is sent automatically.

**Type:** Metric
**Filter:** `rule.id: 200600`

---

## How to Use the Dashboard

### Daily SOC check (5 minutes)
1. Check **Total Alerts** — compare to yesterday's count
2. Check **MySQL Cluster Direct Access** — must be zero
3. Scan **FIM Alerts** — any new PHP file needs investigation
4. Check **Alerts by Severity Level** — any level 12+ spike?
5. Check **Top Triggering IPs** — any new IP at the top?

### Investigating a specific IP
1. Add a filter: `data.srcip: <ip-address>`
2. Check **Top Triggered Rules** — which rules fired for this IP?
3. Check **Top Targeted Vhosts** — which sites did it target?
4. Check **Alerts Timeline** — when did it start/stop?

### Investigating a specific site
1. Add a filter: `data.vhost: <domain>`
2. Check **WordPress Attack Patterns** — which endpoints were targeted?
3. Check **Top Triggering IPs** — how many distinct attackers?
4. Check **FIM Alerts** — any file changes on this site?

---

## Export & Import

The dashboard, all visualizations, and index patterns are exported as
a single `.ndjson` file in this directory:

```
05-dashboard/dashboard-export.ndjson
```

### Import procedure
1. Go to OpenSearch → Stack Management → Saved Objects
2. Click **Import**
3. Select `dashboard-export.ndjson`
4. Choose **Request action on conflict: Overwrite**
5. Navigate to Dashboards → search "Web Hosting Security"

**Note:** after import, verify the index pattern `wazuh-alerts-*` exists
and add the agent filter `agent.id: <your-agent-id>` if monitoring a single server.

---

*Part of Phase 5 — Dashboard*
*Last updated: August 2026*
