# UC-03 — Real-time Scanner Detection

**Category:** Threat Detection / Reconnaissance
**Priority:** Medium
**Status:** ✅ Validated — both controlled test and organic detection
**MITRE ATT&CK:** T1595.002 — Active Scanning: Vulnerability Scanning
**Compliance:** NIST 800-53 SI.4 · PCI-DSS 11.4

---

## Incident Summary

| Field | Value |
|---|---|
| Detection date | July–August 2026 |
| Attack type | Web application vulnerability scanning |
| Scanners detected | Nikto (controlled test) + TLM-Audit-Scanner (organic) |
| Rules triggered | 200200, 200202 |
| Detection time | Real-time — under 5 seconds |

---

## Detection 1 — Controlled Nikto Scan (Rule Validation)

### Context

During Phase 3 rule validation, a Nikto scan was launched from Kali Linux
against a test vhost to confirm rule 200200 fires correctly on scanner
User-Agent strings.

### Attack

```bash
# Launched from Kali Linux (authorized test)
nikto -h <client-domain> -useragent "Nikto/2.5.0"
```

### Detection

Rule 200200 fired within 3 seconds of the first Nikto request:

```
Rule: 200200 (level 8) → 'Web Hosting: Scanner detected —
UA: Nikto/2.5.0 from <test-ip> on <client-domain>'

MITRE: T1595.002 — Vulnerability Scanning
```

**Mattermost alert:**
```
🤖 Scanner Detected
Rule: 200200 | Level: 8/15 | Fired: 1x
IP: <test-ip> — 📍 <country>, <city>
Site: <client-domain>
User-Agent: Nikto/2.5.0
MITRE: T1595.002 — Vulnerability Scanning
```

### Result

Rule 200200 validated. ✅

---

## Detection 2 — Organic TLM-Audit-Scanner (Real Attack)

### Context

During the same test session, a completely separate scanner was detected
targeting `<client-domain>` — not our test, but a real external scanner
that happened to be active at the same time.

### Evidence in logs

```bash
sudo grep "TLM-Audit" /var/log/virtualmin/<client-domain>_access_log | head -5
# → <organic-attacker-ip> - - [<timestamp>] "GET / HTTP/1.1" 200 -
#   "-" "TLM-Audit-Scanner/1.0 (Security Scanner)"
# → <organic-attacker-ip> - - [<timestamp>] "GET /wp-login.php HTTP/1.1" 200 -
#   "-" "TLM-Audit-Scanner/1.0 (Security Scanner)"
# → <organic-attacker-ip> - - [<timestamp>] "GET /admin HTTP/1.1" 404 -
```

### Detection

Rule 200200 fired for `TLM-Audit-Scanner/1.0` simultaneously with our
controlled Nikto test — demonstrating that organic real-world scanners
are being detected in the same timeframe as intentional tests.

**Key observation:** this organic scanner was not in our initial pattern
list. The `(?i)nikto|sqlmap|nuclei|gobuster|...` regex did NOT catch it.
It was caught by the **404 flood rule (200202)** instead — the scanner
generated 30+ 404 responses within 60 seconds while probing common paths.

---

## Detection 3 — 404 Flood (Rule 200202)

### Context

During production monitoring, rule 200202 fired organically on
`<attacker-ip>` targeting `<client-domain>` — a scanner that used a
generic User-Agent (evading rule 200200) but revealed itself through
its high 404 rate.

### Evidence

```
Rule: 200202 (level 10) → 'Web Hosting: 404 flood —
30+ not found responses from <attacker-ip> on <client-domain>'

Fired: 48x over 60 seconds
MITRE: T1595.002 — Active Scanning
```

### Scan pattern reconstructed from logs

```
GET /admin          → 404
GET /.env           → 404  ← also triggers 200303 (sensitive file)
GET /phpinfo.php    → 404
GET /wp-login.php   → 200  ← WordPress endpoint found
GET /.git/          → 404  ← also triggers 200303
GET /backup.sql     → 404
GET /config.php     → 404
...30+ 404s in 60s
```

This scan was caught by behavior (404 flood) rather than signature
(User-Agent) — demonstrating the complementary value of both detection
approaches.

---

## Key Lessons

### 1. User-Agent detection alone is not sufficient

Sophisticated scanners (and Nikto in stealth mode) use generic browser
User-Agents. Rule 200200 only catches scanners that identify themselves.
Rule 200202 (404 flood) catches evasive scanners through behavior.
Both rules are necessary for full coverage.

### 2. Behavior-based detection catches what signatures miss

The TLM-Audit-Scanner was caught by 200202, not 200200. A real-world
scanner using a Chrome User-Agent would still generate 30+ 404s while
probing common paths — making behavior-based detection the more robust
of the two approaches.

### 3. Evasion detection gap

**Known gap:** a scanner that uses a generic User-Agent AND limits its
404 rate (e.g. 1 request per 5 seconds) would evade both rules 200200
and 200202. A time-based correlation rule or minimum request threshold
adjustment would be needed to catch low-and-slow scanners.

---

## Rules Demonstrated

| Rule | Level | Trigger | Type |
|---|---|---|---|
| 200200 | 8 | Scanner User-Agent | Signature-based |
| 200202 | 10 | 30+ 404s in 60s | Behavior-based |

---

*Part of the SIEM Web Hosting Security project — Use Cases*
*Last updated: August 2026*
