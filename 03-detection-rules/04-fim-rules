# Phase 3 — Detection Rules: File Integrity Monitoring

Rules: 200400–200402
Author: Mohamed Amine Namouchi
Date: July–August 2026
Status: ✅ Complete — validated in production

---

## Overview

FIM detection rules monitor file system changes on the `<client>` Laravel
application — the only client site with FIM configured during this
engagement (pilot scope). The three rules cover the highest-risk change
events: a new PHP file appearing in the web directory (potential webshell
drop), modification of an existing PHP file (potential backdoor injection),
and modification of a config file (potential credential theft or
configuration tampering).

These rules depend entirely on the FIM configuration deployed in Phase 1
(realtime watches on specific paths) and on a critical field name discovery
documented below.

---

## Critical Discovery — FIM Rule Field Name

The most important technical finding of this rule family:
**the correct field name for path-based FIM rules is `<field name="file">`,
not `<field name="syscheck.path">`.**

This cost significant debugging time. Both `syscheck.path` and `file`
appear in Wazuh documentation in different contexts. The JSON alert from
a FIM event contains `"syscheck": {"path": "..."}` — which suggests
`syscheck.path` as the field name. This is wrong for rule matching.

**Behavior comparison:**

| Field used | `wazuh-analysisd -t` | Rule fires? |
|---|---|---|
| `syscheck.path` | ✅ No error | ❌ Never |
| `file` | ✅ No error | ✅ Correctly |

Both compile without error. Only `file` actually works. There is no
warning when using the wrong field name — the rule silently never matches.

**Additional constraint:** FIM rules cannot be tested with `wazuh-logtest`.
FIM events use a separate internal pipeline that bypasses the logtest tool
entirely. The only valid test method is:
1. Create/modify a real file in a monitored directory on the agent
2. Check `alerts.log` on the manager for the custom rule ID

---

## Rule 200400 — New PHP File Created

**Trigger:** a new PHP file appears anywhere under `/home/<client>/`
(webroot, storage, routes, or account root)

**Why this matters:** a new PHP file appearing in a Laravel webroot or
storage directory is the primary indicator of a webshell drop. Legitimate
deployments use version control (git pull) — they do not create isolated
new PHP files at runtime.

**Level:** 12 — critical, possible webshell.

```xml
<rule id="200400" level="12">
  <if_sid>554</if_sid>
  <field name="file" type="pcre2">/home/<client>/.*\.php$</field>
  <description>Web Hosting: New PHP file created — possible webshell: $(file)</description>
  <group>webshell,gdpr_IV_35.7.d,nist_800_53_SI.7,pci_dss_11.5,</group>
  <mitre>
    <id>T1505.003</id>
  </mitre>
</rule>
```

**Parent rule:** `if_sid: 554` — native Wazuh rule "File added to the system"
(level 5, decoded by `syscheck_new_entry`).

**Validated in production:**
```bash
sudo touch /home/<client>/public_html/public/test.php
```
Result in `alerts.log` on manager:
```
Rule: 200400 (level 12) -> 'Web Hosting: New PHP file created —
possible webshell: /home/<client>/public_html/public/test.php'
```
Alert fired within 2 seconds. VirusTotal scan (rule 87104) also triggered
automatically via the native integration.

---

## Rule 200401 — PHP File Modified

**Trigger:** an existing PHP file is modified under `/home/<client>/`

**Why this matters:** modification of an existing PHP file — especially in
the webroot or routes directory — may indicate backdoor injection into a
legitimate file. More subtle than dropping a new file, and harder to detect
without FIM.

**Level:** 10 — high severity.

```xml
<rule id="200401" level="10">
  <if_sid>550</if_sid>
  <field name="file" type="pcre2">/home/<client>/.*\.php$</field>
  <description>Web Hosting: PHP file modified — $(file)</description>
  <group>fim,gdpr_IV_35.7.d,nist_800_53_SI.7,pci_dss_11.5,</group>
  <mitre>
    <id>T1505.003</id>
  </mitre>
</rule>
```

**Parent rule:** `if_sid: 550` — native Wazuh rule "Integrity checksum changed"
(level 7, decoded by `syscheck_integrity_changed`).

**Validated in production:**
```bash
echo "<?php echo 'test'; ?>" | sudo tee /home/<client>/public_html/public/test.php
sleep 10
echo "<?php echo 'modified'; ?>" | sudo tee /home/<client>/public_html/public/test.php
```
Result:
```
Rule: 200401 (level 10) -> 'Web Hosting: PHP file modified —
/home/<client>/public_html/public/test.php'
```

---

## Rule 200402 — Config File Modified

**Trigger:** modification of a config file (`.env`, `.conf`, `.config`,
`.ini`, `.yml`, `.yaml`) under `/home/<client>/`

**Why this matters:** the `.env` file in Laravel contains database
credentials, API keys, and application secrets. Any modification is a
critical security event — either an attacker has gained write access, or
a legitimate change was made without proper change management.

**Level:** 10 — high severity.

```xml
<rule id="200402" level="10">
  <if_sid>550</if_sid>
  <field name="file" type="pcre2">/home/<client>/.*\.(env|conf|config|ini|yml|yaml)$</field>
  <description>Web Hosting: Config file modified — $(file)</description>
  <group>fim,config_changed,gdpr_IV_35.7.d,nist_800_53_SI.7,pci_dss_11.5,</group>
  <mitre>
    <id>T1565.001</id>
  </mitre>
</rule>
```

**Validated in production:**
```bash
sudo touch /home/<client>/public_html/.env
```
Result:
```
Rule: 200402 (level 10) -> 'Web Hosting: Config file modified —
/home/<client>/public_html/.env'
```

**FIM scope note:** rule 200402 only fires for paths that are actively
monitored by FIM. The `.env` file at `/home/<client>/public_html/.env`
is explicitly watched (realtime, no diff). A config file outside the
monitored paths will not trigger this rule.

---

## Debugging Journey

The path from writing these rules to getting them to fire took multiple
iterations. Complete debugging log for future reference:

### Attempt 1 — `syscheck.path` field (failed silently)
```xml
<field name="syscheck.path" type="pcre2">/home/<client>/.*\.php$</field>
```
Result: compiled, never fired. No error, no warning.

### Attempt 2 — `<match>` on full log (failed)
```xml
<match>/home/<client>/</match>
<match type="pcre2">\.php'</match>
```
Result: `<match>` searches the `full_log` field of the FIM event.
The `full_log` for a FIM event is:
```
File '/home/<client>/public_html/public/test.php' added
Mode: realtime
```
The pattern `\.php'` should match `test.php' added` — but it did not fire.
Root cause: FIM events have a different `full_log` structure than log
collector events, and the internal pipeline processes them differently.

### Attempt 3 — `file` field (correct)
```xml
<field name="file" type="pcre2">/home/<client>/.*\.php$</field>
```
Result: fired correctly within 2 seconds of file creation.

**How the correct field name was found:** reading the official Wazuh FIM
rule reference documentation, which explicitly states:

> *"For FIM rules, use `<field name="file">` to match on the file path."*

The Wazuh alerts JSON confirms the field mapping:
```json
"syscheck": {
    "path": "/home/<client>/public_html/public/test.php"
}
```
In the rule engine, `syscheck.path` maps to the JSON path — but the
rule matching field exposed by the FIM pipeline is simply `file`.

---

## Validation Summary

| Rule | Trigger | Level | MITRE | Validated |
|---|---|---|---|---|
| 200400 | New PHP file created | 12 | T1505.003 | ✅ Production (2s alert) |
| 200401 | PHP file modified | 10 | T1505.003 | ✅ Production |
| 200402 | Config file modified | 10 | T1565.001 | ✅ Production (.env touch) |

---

*Part of Phase 3 — Detection Rules*
*Last updated: August 2026*
