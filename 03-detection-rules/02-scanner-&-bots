# Phase 3 — Detection Rules: Scanners & Bots

Rules: 200200–200203 + parent rules 200210–200211
Author: Mohamed Amine Namouchi
Date: June–July 2026
Status: ✅ Complete — validated in production

---

## Overview

Scanners and automated bots represent the highest volume of malicious traffic
on any public-facing web server. On the production hosting server, scanners
were detected within minutes of deploying these rules — including real Nikto
scans, CensysInspect crawlers, and 404 flood attacks from multiple IPs.

This rule family covers two attack vectors:
- **User-Agent based detection** — scanners that identify themselves (nikto,
  sqlmap, nuclei, gobuster, CensysInspect, ShodanBot)
- **Behavior based detection** — scanners that disguise their UA but reveal
  themselves through volume patterns (404 floods, high request rates)

---

## Parent Rules (no_log)

Two parent rules act as counters for the frequency-based rules. They must be
`level 1` (not level 0) for Wazuh to count their occurrences in the
`frequency`/`timeframe` engine. The `no_log` option prevents them from
generating alerts on their own.

**Critical lesson learned:** rules with `level="0"` are silently ignored by
the frequency counter. The 404 flood rule (200202) was not firing despite
real floods because the parent rule 200210 was `level 0`. Changing to
`level 1` + `no_log` fixed the issue immediately.

```xml
<!-- Parent: 404 response — counter for 200202 -->
<rule id="200210" level="1">
  <decoded_as>apache-vhost-full</decoded_as>
  <field name="http_status">404</field>
  <options>no_log</options>
  <description>Web Hosting: 404 Not Found response</description>
</rule>

<!-- Parent: any Apache request — counter for 200203 -->
<rule id="200211" level="1">
  <decoded_as>apache-vhost-full</decoded_as>
  <options>no_log</options>
  <description>Web Hosting: Apache request received</description>
</rule>
```

**Engineering note on `http_status` field:** the status code field was
initially named `id` in the decoder (matching native decoder convention).
This caused `Field 'id' is static` errors in rules. The field was renamed
to `http_status` — requiring updates across all rules that reference it.

---

## Rule 200200 — Scanner User-Agent Detection

**Trigger:** request with a known scanner/attack tool User-Agent string

**Level:** 8 — active reconnaissance, actionable.

```xml
<rule id="200200" level="8">
  <decoded_as>apache-vhost-full</decoded_as>
  <field name="user_agent" type="pcre2">(?i)nikto|sqlmap|nuclei|gobuster|dirbuster|wfuzz|masscan|zgrab</field>
  <description>Web Hosting: Scanner detected — UA: $(user_agent) from $(srcip) on $(vhost)</description>
  <group>recon,scanner,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_11.4,</group>
  <mitre>
    <id>T1595.002</id>
  </mitre>
</rule>
```

**Validated in production:** rule 200200 fired in real time during a Nikto
scan launched from Kali Linux against `<client-domain>` with
`-useragent "Nikto/2.5.0"`. Alerts appeared in `alerts.log` within seconds:

```
Rule: 200200 (level 8) -> 'Web Hosting: Scanner detected — UA: Nikto/2.5.0
from <attacker-ip> on <client-domain>'
```

Also detected organically: `TLM-Audit-Scanner/1.0` scanning `<client-domain>`
during the same testing session — a real external scanner, not our test.

**Note on evasion:** Nikto in default mode uses a generic Chrome User-Agent
to avoid detection. Rule 200200 only catches scanners that identify themselves.
Behavior-based rules (200202, 200203) cover the evasion case.

---

## Rule 200201 — Internet Indexer Detection

**Trigger:** known internet indexer/crawler User-Agent (Censys, Shodan)

**Level:** 3 — informational. These are legitimate services but their
presence confirms the server's public IP is indexed and fully mapped.

```xml
<rule id="200201" level="3">
  <decoded_as>apache-vhost-full</decoded_as>
  <field name="user_agent" type="pcre2">(?i)CensysInspect|ShodanBot|shodan\.io|censys\.io</field>
  <description>Web Hosting: Internet indexer detected — UA: $(user_agent) from $(srcip) on $(vhost)</description>
  <group>recon,indexer,nist_800_53_SI.4,</group>
  <mitre>
    <id>T1595</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest with `CensysInspect/1.1 (+https://about.censys.io/)`.

---

## Rule 200202 — 404 Flood Detection

**Trigger:** 30+ 404 responses from the same IP within 60 seconds

**Level:** 10 — active directory/file bruteforce.

```xml
<rule id="200202" level="10" frequency="30" timeframe="60">
  <if_matched_sid>200210</if_matched_sid>
  <same_source_ip/>
  <description>Web Hosting: 404 flood — 30+ not found responses from $(srcip) on $(vhost)</description>
  <group>recon,scanner,bruteforce,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_11.4,</group>
  <mitre>
    <id>T1595.002</id>
  </mitre>
</rule>
```

**Validated in production:** rule 200202 fired organically on
`<attacker-ip>` targeting `<client-domain>` — 65+ 404 responses in under
60 seconds, detected without any manual testing required.

---

## Rule 200203 — High Request Rate Detection

**Trigger:** 100+ requests from the same IP within 60 seconds

**Level:** 8 — high-volume automated traffic.

```xml
<rule id="200203" level="8" frequency="100" timeframe="60">
  <if_matched_sid>200211</if_matched_sid>
  <same_source_ip/>
  <description>Web Hosting: High request rate — 100+ requests from $(srcip) on $(vhost)</description>
  <group>recon,scanner,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_11.4,</group>
  <mitre>
    <id>T1595</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest frequency simulation — fired after 100 iterations.

---

## Key Engineering Challenges

### Challenge 1 — level 0 parent rules break frequency counting

The initial implementation used `level="0"` on parent rules 200210 and
200211, following the convention that "informational" events should be
level 0. This silently broke the frequency counter — `if_matched_sid`
with a level 0 parent never increments the counter.

**Fix:** change parent rules to `level="1"` and add `<options>no_log</options>`
to suppress individual alerts while keeping the counter active.

### Challenge 2 — `http_status` field vs `id` reserved name

The initial decoder used `id` as the field name for HTTP status code
(matching the native `web-accesslog-ip` convention). Using `<field name="id">`
in rules caused `Field 'id' is static` errors. The field was renamed to
`http_status` in the decoder.

### Challenge 3 — logall disabled hides counter events

During debugging, counter events (level 1, `no_log`) were invisible in
`archives.log` because `logall` was disabled. Enabling `logall` temporarily
was required to confirm the frequency counter was receiving events.

```bash
# Temporary debug — disable after investigation
sudo sed -i 's/<logall>no<\/logall>/<logall>yes<\/logall>/' /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

---

## Validation Summary

| Rule | Trigger | Level | MITRE | Validated |
|---|---|---|---|---|
| 200210 | 404 response (parent, no_log) | 1 | — | ✅ |
| 200211 | Any request (parent, no_log) | 1 | — | ✅ |
| 200200 | Scanner User-Agent | 8 | T1595.002 | ✅ Production (Nikto + TLM-Audit-Scanner) |
| 200201 | Internet indexer UA | 3 | T1595 | ✅ wazuh-logtest |
| 200202 | 30+ 404s in 60s | 10 | T1595.002 | ✅ Production (organic attack) |
| 200203 | 100+ requests in 60s | 8 | T1595 | ✅ wazuh-logtest |

---

*Part of Phase 3 — Detection Rules*
*Last updated: August 2026*
