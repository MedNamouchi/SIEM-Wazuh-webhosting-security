# Phase 3 — Detection Rules: Auth Brute Force

Rules: 200501–200502 (Webmin) | 200500 (FTP — deferred)
Author: Mohamed Amine Namouchi
Date: July–August 2026
Status: ✅ Webmin complete | 🟡 FTP deferred

---

## Overview

This rule family covers brute force detection on administrative interfaces —
Webmin (the hosting panel managing all 50+ client accounts) and ProFTPD
(the FTP server). Both are high-value targets: a successful Webmin compromise
gives full control over the entire hosting infrastructure.

---

## Part A — Webmin Brute Force (200501–200502)

### Context

Webmin authentication failures produce a distinctive log pattern with an
empty HTTP request field:

```
<src_ip> - - [<timestamp>] "" 401 21892
```

This format is not handled by any native Wazuh decoder — the `web-accesslog`
family expects a populated request method between the quotes. A custom
decoder (`webmin`) was built in conjunction with these rules.

### Custom Decoder — webmin

```xml
<decoder name="webmin">
  <prematch type="pcre2">^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - \S+ \[</prematch>
  <regex type="pcre2">^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \S+ \[\S+ \S+\] "\S*" (\d+)</regex>
  <order>srcip, http_status</order>
</decoder>
```

**Why PCRE2:** the empty request field (`""`) contains zero characters.
Standard sregex `\S+` requires at least one non-whitespace character and
would not match. PCRE2's `\S*` (zero or more) handles both empty and
populated request fields in a single pattern.

**Decoder location:** `local_decoder.xml` on the Wazuh manager.

**Validation:**
```
Input:  <src_ip> - - [<timestamp>] "" 401 21892

Phase 2:
  name: webmin
  srcip: <src_ip>
  http_status: 401
```

---

### Rule 200501 — Webmin Authentication Failure

**Trigger:** any 401 response decoded by the `webmin` decoder

**Level:** 5 — single failure, informational. Primary purpose is to feed
the frequency counter for 200502.

```xml
<rule id="200501" level="5">
  <decoded_as>webmin</decoded_as>
  <field name="http_status">^401$</field>
  <description>Web Hosting: Webmin authentication failure from $(srcip)</description>
  <group>authentication_failed,gdpr_IV_35.7.d,nist_800_53_AC.7,pci_dss_10.2.4,</group>
  <mitre>
    <id>T1110</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest with real Webmin auth failure log line.
```
Rule: 200501 (level 5) -> 'Web Hosting: Webmin authentication failure
from <src_ip>'
```

**Production observation:** `<internal-monitoring-ip>` generates 401s every ~7 minutes
from a legitimate admin browser session (Virtualmin login page loads
before credentials). This is normal behavior and should not be confused
with an attack. The brute force rule (200502) threshold of 5 failures in
60 seconds is calibrated to ignore this pattern.

---

### Rule 200502 — Webmin Brute Force

**Trigger:** 5+ authentication failures from the same IP within 60 seconds

**Level:** 12 — critical, email notification enabled (`mail: True`).

```xml
<rule id="200502" level="12" frequency="5" timeframe="60">
  <if_matched_sid>200501</if_matched_sid>
  <same_source_ip/>
  <description>Web Hosting: Webmin brute force — 5+ failures from $(srcip)</description>
  <group>bruteforce,authentication_failures,gdpr_IV_35.7.d,nist_800_53_AC.7,pci_dss_10.2.4,</group>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest session — 200502 fired after 5 iterations of
the same 401 line from the same IP, with `frequency: 5` and `mail: True`
confirmed.

---

## Part B — FTP Brute Force (200500 — Deferred)

### Status: 🟡 Deferred

**Why deferred:**

1. **Log format incompatibility:** ProFTPD on this server uses a timestamp
   format (`2026-06-28 00:05:01,054`) that differs from the syslog format
   expected by the native Wazuh `proftpd` decoder (`Jun 28 00:05:01`).
   The native rules (11204 — login failed, 11251 — brute force) never fire
   because the decoder does not match.

2. **No active FTP attack traffic:** `/var/log/proftpd/proftpd.log` contains
   only startup/shutdown messages — zero authentication attempts recorded.
   The FTP port is likely filtered at the perimeter gateway, making FTP
   attacks a theoretical rather than practical risk at this time.

3. **Native rules cover the need:** if the log format issue is resolved,
   the native Wazuh rule 11251 (8+ failed logins in 120s, level 10) already
   covers the FTP brute force detection need without requiring a custom rule.

**Planned resolution (if FTP becomes active):**
- Option A: fix the ProFTPD log format to syslog-compatible timestamps
  via `proftpd.conf` (`SystemLog` with syslog facility)
- Option B: write a custom `proftpd` decoder accepting the timestamp format
  in use and a corresponding frequency rule

**Native rules reference (for when this is implemented):**

| Rule ID | Description | Level |
|---|---|---|
| 11204 | ProFTPD login failed | 5 |
| 11251 | ProFTPD brute force (8+ in 120s) | 10 |

---

## Validation Summary

| Rule | Trigger | Level | MITRE | Status |
|---|---|---|---|---|
| 200501 | Webmin auth failure (401) | 5 | T1110 | ✅ Validated |
| 200502 | 5+ Webmin failures in 60s | 12 | T1110.001 | ✅ Validated |
| 200500 | FTP brute force | 10 | T1110.001 | 🟡 Deferred |

---

*Part of Phase 3 — Detection Rules*
*Last updated: August 2026*
