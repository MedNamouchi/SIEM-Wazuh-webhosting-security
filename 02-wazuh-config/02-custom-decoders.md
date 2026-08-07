# Phase 2 — Custom Decoders

Tasks: 2.0, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6
Author: Mohamed Amine Namouchi
Date: June 18, 2026
Last updated: August 2026
Status: ✅ Complete

---

## Overview

Phase 1 established log collection across 50+ client virtual hosts. Phase 2
transforms those raw log lines into structured, queryable fields that Wazuh
can act on. Without a decoder, Wazuh sees plain text — it cannot match fields,
correlate events, or fire detection rules against them. This phase produces
the decoder layer that makes Phase 3 (detection rules) possible.

---

## 2.0 — Native Decoder Audit

Before writing anything custom, a full audit of the existing native decoders
in the Wazuh manager ruleset was conducted, to avoid duplicating logic that
already exists and to understand what gaps actually need to be filled.

**Findings:**

| Need | Native decoder | Verdict |
|---|---|---|
| Apache combined log (IP, method, URL, status) | `web-accesslog-ip` | Partial — stops at status code, misses User-Agent |
| User-Agent extraction | None | Must build |
| Vhost name from log filename | None | Must build |
| WordPress attack patterns | None | Must build |
| Apache error log (PHP errors, client errors) | `apache-errorlog` family | Complete — nothing to build |
| Malformed/empty requests (`"" 401`) | None | Must build (deferred to Phase 3) |

**Side finding:** ModSecurity WAF was found installed but explicitly disabled
on this server. The hosting team confirmed this was intentional — ModSecurity
caused too many false positives on the PHP/Laravel applications, and a
reverse proxy (Nginx Proxy Manager) now handles WAF-level filtering
centrally for all client sites. The ModSecurity coverage in the native
`apache-errorlog` decoder is therefore irrelevant in this environment.

---

## 2.1 — Apache Combined Format Decoder

**Problem:** the native `web-accesslog-ip` decoder extracts IP, method, URL,
and status code — but stops there. The User-Agent field, present in all
Virtualmin access logs (Apache combined format), is never captured. This
field is often the fastest signal for distinguishing legitimate browsers,
known bots, and automated attack tools.

**Architectural challenge:** extending the native decoder via a child or
sibling in the custom decoders folder is not possible. Wazuh loads the
native ruleset first, and the native decoder always wins the matching race
regardless of what is added alongside it. The correct approach, confirmed
by Wazuh official support, is:

1. Copy the native file to the custom decoders folder
2. Exclude the original via `<decoder_exclude>` in `ossec.conf`
3. The custom copy now loads without competition and can be freely modified

**Architecture note — sibling decoders:** the custom Apache decoder uses
Wazuh's sibling decoder pattern: multiple blocks sharing the same `name`
and `parent`, each extracting a different subset of fields from the same
log line independently. This is distinct from the classic parent→child
hierarchy where each level has a unique name. The sibling pattern allows
building a rich, modular field extraction pipeline without chaining
dependencies.

**Fields extracted:** `srcip`, `protocol`, `url`, `http_status`, `user_agent`, `vhost`, `wp_pattern`

**Important note on reserved field names:** several intuitive field names
are reserved by Wazuh and cannot be used as custom decoder output fields —
attempting to do so causes silent failures or rule engine errors. Discovered
during this phase:

| Reserved name | Reason | Replacement used |
|---|---|---|
| `id` | Internal Wazuh event ID field | `http_status` |
| `protocol` | Reserved static field | Cannot be used in `<field>` rules — use `<match>` instead |
| `url` | Reserved static field | Cannot be used in `<field>` rules — use `<match>` instead |

The HTTP status code field was initially named `id` (matching the native
decoder convention). This caused rule engine errors (`Field 'id' is static`)
when used in detection rules. The field was renamed to `http_status` in the
sibling decoder, which required a global search-and-replace across all rules.

**Validation (wazuh-logtest):**
```
Input:  /var/log/virtualmin/example.hr_access_log: <src_ip> - - [<timestamp>]
        "GET /wp-login.php HTTP/1.1" 200 4455 "-" "Mozilla/5.0..."

Phase 2:
  name: apache-vhost-full
  srcip: <src_ip>
  protocol: GET
  url: /wp-login.php
  http_status: 200
  user_agent: Mozilla/5.0...
  vhost: example.hr
  wp_pattern: wp-login.php
```

---

## 2.2 — Virtualmin Vhost Name Extractor

**Problem:** Apache log lines contain no domain name in their content —
only the visitor IP, the relative URL, and the status code. On a shared
hosting server with 50+ client sites, knowing which site is being targeted
is as operationally important as knowing who is attacking it. Without this,
all alerts from all sites appear identical in the dashboard.

**Solution:** the Wazuh agent's `out_format` directive injects the source
file path as a prefix on each log line before forwarding to the manager:

```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/virtualmin/*_access_log</location>
  <out_format>$(location): $(log)</out_format>
</localfile>
```

The custom decoder then extracts the domain name from this prefix via a
targeted regex, populating a `vhost` field on every alert.

**Validated on live traffic:** confirmed via the manager's archive log that
production log lines arrive with the expected prefix format, with `vhost`
correctly extracted per client site.

---

## 2.3 — WordPress URL Pattern Decoder

**Problem:** WordPress installations are the most attacked targets on shared
hosting servers. Brute force attempts, user enumeration, and XML-RPC abuse
all target a small set of well-known endpoints. Without categorizing these
patterns, each attack request looks like ordinary web traffic in the SIEM.

**Patterns monitored:**

| Pattern | Attack type |
|---|---|
| `wp-login.php` | Brute force on the login form |
| `wp-admin` | Admin panel access attempts |
| `xmlrpc.php` | XML-RPC exploitation (brute force amplification, DDoS) |
| `?author=` | User enumeration |

**Implementation:** an additional sibling in the `apache-vhost-full` family,
extracting a `wp_pattern` field when any of the above patterns appears in
the URL.

**False positive check:** `wp-content` (legitimate asset loading) correctly
does NOT trigger `wp_pattern` — confirmed via wazuh-logtest.

**Validation:**

| URL | wp_pattern value |
|---|---|
| `/wp-login.php` | `wp-login.php` |
| `/wp-admin/` | `wp-admin` |
| `/xmlrpc.php` | `xmlrpc.php` |
| `/?author=1` | `?author=` |
| `/wp-content/plugins/...` | *(not triggered)* |

---

## 2.4 — Apache Error Log Decoder

**Context:** the native `apache-errorlog` decoder already handles the Apache
error log format comprehensively — extracting `srcip`, `srcport`, and the
Apache error code (e.g. `AH01276`), with native rules that map to MITRE
ATT&CK, GDPR, HIPAA, and PCI-DSS frameworks out of the box. Nothing needed
to be built from scratch.

**Problem:** the `out_format` prefix injected by the agent
(`/var/log/virtualmin/<domain>_error_log: `) is not recognized by the
native decoder's `prematch` — all Virtualmin vhost error lines fell through
to "No decoder matched."

**Solution:** same copy-and-exclude approach as 2.1. The native file was
copied locally, excluded from the original ruleset, and its root `prematch`
was extended to accept the optional path prefix:

```xml
<decoder name="apache-errorlog">
  <prematch type="pcre2">^(?:/\S+_error_log: )?\[\w+ \w+ \d+ [\d:.]+ \d+\] \[\S+:(?:warn|notice|error|info)\] </prematch>
</decoder>
```

**Note on vhost field:** structured `vhost` extraction was not achieved on
error logs (stacked regex approaches were not supported in this context).
The domain name remains visible in the `full_log` field of every alert via
the `out_format` prefix — sufficient for operational identification.

**Key lesson:** always validate decoder/rule syntax with
`sudo /var/ossec/bin/wazuh-analysisd -t` before restarting the Wazuh
manager. This command validates the full configuration without touching the
running service, catching syntax errors before they cause downtime. Two
production manager outages during this phase would have been avoided had
this tool been used from the start.

**Validated on live traffic:** a real request to a monitored vhost generated
a real `AH01276` error, confirmed in `alerts.log` with the full MITRE T1190
mapping and the domain name visible in the `full_log` prefix.

---

## 2.5 — Webmin Auth Failure Decoder

**Status:** ✅ Implemented in Phase 3

The `"" 401` pattern (empty HTTP request with authentication failure) is
generated by the Webmin admin panel on failed logins. A decoder alone would
produce false positives without a correlation rule — it was intentionally
deferred to Phase 3 to implement both together.

**Implementation (Phase 3):** a custom `webmin` decoder using PCRE2 handles
both the empty-request format (`"" 401`) and standard requests, extracting
`srcip` and `http_status`:

```xml
<decoder name="webmin">
  <prematch type="pcre2">^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} - \S+ \[</prematch>
  <regex type="pcre2">^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) - \S+ \[\S+ \S+\] "\S*" (\d+)</regex>
  <order>srcip, http_status</order>
</decoder>
```

**Why PCRE2 was required:** the empty request field (`""`) contains zero
characters between the quotes. Standard sregex `\S+` does not match an
empty string. PCRE2's `\S*` (zero or more non-whitespace) handles both
cases — populated requests and empty ones — in a single regex.

**Validation:**
```
Input:  <src_ip> - - [<timestamp>] "" 401 21892

Phase 2:
  name: webmin
  srcip: <src_ip>
  http_status: 401

Phase 3:
  id: 200501
  level: 5
  description: Web Hosting: Webmin authentication failure from <src_ip>
```

---

## 2.6 — Global Decoder Test

Full validation pass across all Phase 2 decoders using real log lines.

| # | Log type | Decoder | Key fields | Result |
|---|---|---|---|---|
| 1 | Virtualmin access log | `apache-vhost-full` | srcip, protocol, url, http_status, user_agent, vhost | ✅ |
| 2 | Access log with WordPress pattern | `apache-vhost-full` | + wp_pattern: 'wp-login.php' | ✅ |
| 3 | Webmin log (standard request) | `apache-vhost-full` | srcip, protocol, url, http_status, user_agent | ✅ |
| 4 | Apache error log without prefix | `apache-errorlog` | srcip, srcport, id + MITRE level 5 alert | ✅ |
| 5 | Apache error log with vhost prefix | `apache-errorlog` | same + domain visible in full_log | ✅ |
| 6 | Webmin auth failure (`"" 401`) | `webmin` | srcip: `<src_ip>`, http_status: 401 | ✅ |
| 7 | Scanner UA (nikto) | `apache-vhost-full` | user_agent: 'Nikto/2.5.0' → rule 200200 | ✅ |
| 8 | SQLi in URL (URL-encoded) | `apache-vhost-full` | url: '/product?id=1%27%20UNION...' → rule 200300 | ✅ |

---

## Task Summary

| Task | Description | Status |
|---|---|---|
| 2.0 | Native decoder audit | ✅ Done |
| 2.1 | Apache combined format + User-Agent + http_status field | ✅ Done |
| 2.2 | Virtualmin vhost name extractor | ✅ Done |
| 2.3 | WordPress URL pattern decoder | ✅ Done |
| 2.4 | Apache error log decoder | ✅ Done |
| 2.5 | Webmin auth failure decoder (`"" 401`) | ✅ Done (Phase 3) |
| 2.6 | Global decoder test — 8 cases validated | ✅ Done |

---

*Document maintained as part of Phase 2 — Custom Decoders*
*Last updated: August 2026*
