# Phase 3 — Detection Rules: WordPress Attacks

Rules: 200100–200106
Author: Mohamed Amine Namouchi
Date: June–July 2026
Status: ✅ Complete (200104 deferred — awaiting whitelist)

---

## Overview

WordPress is the most targeted CMS on shared hosting servers. Every site
running WordPress on punica.ofir.hr is under constant automated attack —
brute force on login forms, username enumeration, XML-RPC exploitation,
and plugin upload abuse. This rule family covers the full WordPress attack
surface, from a single login attempt to a confirmed webshell drop via
plugin upload.

All rules depend on the `wp_pattern` field extracted by the Phase 2
`apache-vhost-full` sibling decoder. Without that field, none of these
rules can fire.

---

## Rule 200100 — WordPress Login Attempt

**Trigger:** any POST request to `wp-login.php`

**Why POST and not GET:** a GET to `wp-login.php` is a normal page visit
(user opening the login form). A POST is an actual credential submission —
the minimum signal for a login attempt worth tracking.

**Level:** 4 — informational, not actionable alone but feeds 200101.

```xml
<rule id="200100" level="4">
  <decoded_as>apache-vhost-full</decoded_as>
  <field name="wp_pattern">wp-login.php</field>
  <match>POST</match>
  <description>Web Hosting: WordPress login attempt from $(srcip) on $(vhost)</description>
  <group>authentication_attempt,gdpr_IV_35.7.d,nist_800_53_AC.7,pci_dss_10.2.4,</group>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

**Engineering note:** `<field name="protocol">^POST$</field>` fails with
`Field 'protocol' is static`. The workaround is `<match>POST</match>` which
searches the full log line — effective since POST only appears as the HTTP
method in this context.

**Validated:** wazuh-logtest + negative test (GET does not trigger).

---

## Rule 200101 — WordPress Brute Force

**Trigger:** 10+ login attempts from the same IP within 60 seconds

**Level:** 10 — confirmed attack pattern, actionable.

```xml
<rule id="200101" level="10" frequency="10" timeframe="60">
  <if_matched_sid>200100</if_matched_sid>
  <same_source_ip/>
  <description>Web Hosting: WordPress brute force — 10+ login attempts from $(srcip) on $(vhost)</description>
  <group>bruteforce,authentication_failures,gdpr_IV_35.7.d,gdpr_IV_32.2,nist_800_53_AC.7,pci_dss_10.2.4,pci_dss_11.4,</group>
  <mitre>
    <id>T1110.001</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest session — 200101 fired after 10 iterations of
the same POST line, with `firedtimes: 1` and `frequency: 10` confirmed.

---

## Rule 200102 — Username Enumeration

**Trigger:** any request containing `?author=` in the URL

**Why this matters:** WordPress exposes usernames via `/?author=1`,
`/?author=2` etc. — redirecting to `/author/<username>/`. Attackers use
this to map all admin accounts before a targeted brute force. The `wp_pattern`
field extracts `?author=` when present.

**Level:** 6 — reconnaissance activity.

```xml
<rule id="200102" level="6">
  <decoded_as>apache-vhost-full</decoded_as>
  <field name="wp_pattern" type="pcre2">\?author=</field>
  <description>Web Hosting: WordPress username enumeration attempt from $(srcip) on $(vhost)</description>
  <group>recon,gdpr_IV_35.7.d,nist_800_53_SI.4,</group>
  <mitre>
    <id>T1589.003</id>
  </mitre>
</rule>
```

**Engineering note:** `type="pcre2"` is required on `<field>` when the
pattern contains special characters like `?`. Standard sregex interprets
`\?` differently.

**Validated:** wazuh-logtest with `/?author=1` — `wp_pattern: ?author=`
correctly extracted, rule 200102 fires at level 6.

---

## Rule 200103 — Rapid Username Enumeration

**Trigger:** 5+ `?author=` requests from the same IP within 30 seconds

**Level:** 10 — automated enumeration confirmed.

```xml
<rule id="200103" level="10" frequency="5" timeframe="30">
  <if_matched_sid>200102</if_matched_sid>
  <same_source_ip/>
  <description>Web Hosting: Rapid username enumeration — 5+ ?author= requests from $(srcip) on $(vhost)</description>
  <group>recon,bruteforce,gdpr_IV_35.7.d,nist_800_53_SI.4,pci_dss_11.4,</group>
  <mitre>
    <id>T1589.003</id>
  </mitre>
</rule>
```

**Validated:** wazuh-logtest session — fired after 5 iterations.

---

## Rule 200104 — wp-admin Access from Unknown IP

**Status:** 🟡 Deferred — awaiting authorized IP whitelist from infrastructure team

**Planned trigger:** access to `/wp-admin/` from an IP not in a CDB list
of authorized administrator IPs.

**Planned implementation:**
```xml
<rule id="200104" level="8">
  <decoded_as>apache-vhost-full</decoded_as>
  <field name="wp_pattern">wp-admin</field>
  <list field="srcip" lookup="not_match_key">etc/lists/authorized-admin-ips</list>
  <description>Web Hosting: wp-admin access from non-whitelisted IP $(srcip) on $(vhost)</description>
  <group>authentication_attempt,gdpr_IV_35.7.d,nist_800_53_AC.7,</group>
  <mitre>
    <id>T1078</id>
  </mitre>
</rule>
```

The CDB list infrastructure (`/var/ossec/etc/lists/authorized-admin-ips`)
has been prepared and is empty pending population. The rule will be
activated once the whitelist is provided.

---

## Rule 200105 — XML-RPC Abuse

**Trigger:** POST request to `xmlrpc.php`

**Why this matters:** `xmlrpc.php` is a legacy WordPress API that allows
brute-forcing hundreds of credentials in a single HTTP request (via the
`system.multicall` method), and can be weaponized for DDoS by abusing
the pingback feature. Modern WordPress disables it by default, but many
older or poorly maintained sites still have it active.

**Level:** 8 — active exploitation attempt.

```xml
<rule id="200105" level="8">
  <decoded_as>apache-vhost-full</decoded_as>
  <field name="wp_pattern">xmlrpc.php</field>
  <match>POST</match>
  <description>Web Hosting: XML-RPC abuse attempt from $(srcip) on $(vhost)</description>
  <group>recon,exploit_attempt,gdpr_IV_35.7.d,nist_800_53_SI.4,</group>
  <mitre>
    <id>T1190</id>
  </mitre>
</rule>
```

**Validated in production:** rule 200105 fired on `111.235.X.X` targeting
`<vhost>` with `Jetpack by WordPress.com` User-Agent — 90+ hits in the
first hours after deployment. Confirmed real attack traffic.

---

## Rule 200106 — Plugin Upload / Webshell Drop

**Trigger:** POST to any PHP file under `wp-content/plugins/`

**Why this matters:** if an attacker gains WordPress admin access (or exploits
a file upload vulnerability), uploading a PHP file disguised as a plugin is
the standard webshell delivery method. This rule catches both the upload
attempt and any subsequent direct access to a PHP file in the plugins directory.

**Level:** 10 — critical, potential webshell.

```xml
<rule id="200106" level="10">
  <decoded_as>apache-vhost-full</decoded_as>
  <match type="pcre2">POST .*wp-content/plugins/.*\.(php|php5|phtml)</match>
  <description>Web Hosting: Possible plugin upload/webshell drop attempt from $(srcip) on $(vhost)</description>
  <group>webshell,exploit_attempt,gdpr_IV_35.7.d,nist_800_53_SI.4,</group>
  <mitre>
    <id>T1505.003</id>
  </mitre>
</rule>
```

**Engineering note:** `<field name="url">` fails silently (`url` is a
reserved Wazuh field). The workaround is `<match type="pcre2">` on the
full log line — combines method and path check in a single pattern.

**Validated:** wazuh-logtest with `POST /wp-content/plugins/fake/shell.php`
— rule 200106 fires at level 10 with MITRE T1505.003 (Web Shell).

---

## Validation Summary

| Rule | Trigger | Level | MITRE | Status |
|---|---|---|---|---|
| 200100 | POST to wp-login.php | 4 | T1110.001 | ✅ Validated |
| 200101 | 10+ logins in 60s, same IP | 10 | T1110.001 | ✅ Validated |
| 200102 | ?author= in URL | 6 | T1589.003 | ✅ Validated |
| 200103 | 5+ ?author= in 30s, same IP | 10 | T1589.003 | ✅ Validated |
| 200104 | wp-admin from unknown IP | 8 | T1078 | 🟡 Deferred |
| 200105 | POST to xmlrpc.php | 8 | T1190 | ✅ Validated in prod |
| 200106 | PHP upload to wp-content/plugins/ | 10 | T1505.003 | ✅ Validated |

---

*Part of Phase 3 — Detection Rules*
*Last updated: August 2026*
