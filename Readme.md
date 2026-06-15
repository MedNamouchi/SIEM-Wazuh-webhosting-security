# SIEM & Wazuh — Web Hosting Server Security

> Documentation of a real-world cybersecurity internship project: deploying and operating
> a SIEM on a production shared web hosting server, from zero to full detection coverage.

---

## Context

This repository documents work done during a 5-month cybersecurity internship (2026),
focused on blue team / SOC analyst work on a production environment:

- Full security discovery of an unknown production server
- Fixing critical SIEM blind spots
- Threat hunting on real incidents
- Lessons learned for future reference

**Environment:** Ubuntu 22.04, Apache2, Virtualmin/Webmin (~50 client vhosts),
Laravel + WordPress apps, dedicated MySQL server.

**SIEM Stack:** Wazuh 4.14 + Graylog 7.0 + rsyslog + OpenSearch

---

## Repository Structure

```
SIEM-Wazuh-webhosting-security/
|
+-- 01-discovery/
|   +-- web_hosting_discovery_playbook.md   # Full discovery methodology + commands
|
+-- 02-wazuh-config/                        # Coming soon
|
+-- 03-threat-hunting/
|   +-- ssh-attack-investigation.md         # Real SSH brute-force investigation
|
+-- 04-lessons-learned/
    +-- key-findings.md                     # Key takeaways from the engagement
```

---

## Key Findings (Sanitized)

| # | Finding | Severity |
|---|---------|----------|
| 1 | Wazuh monitoring empty Apache log — SIEM blind to all web traffic | Critical |
| 2 | No host-based firewall configured | Critical |
| 3 | Forgotten NAT rule on perimeter router exposing SSH on non-standard port | High |
| 4 | Active SSH brute-force campaign (automated Go script) | High |
| 5 | WordPress botnet targeting multiple hosted sites | High |
| 6 | FTP service without TLS | High |
| 7 | Redis without password (localhost scope) | Medium |
| 8 | No HTTP security headers | Medium |

---

## Tools Used

- Wazuh 4.14 (SIEM agent + manager)
- OpenSearch (log storage + dashboards)
- Graylog 7.0 (log aggregation)
- tcpdump (network packet capture)
- nmap (perimeter scanning)
- Censys / Shodan (attacker perspective recon)
- Standard Linux utilities (ss, ip, lastb, grep, awk, find, curl)

---

## Author

Mohamed Amine Namouchi
Cybersecurity Engineering Student — Polytech Dijon (Network Security & Quality)
Internship: SOC Analyst / Blue Team, 2026

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)](https://linkedin.com/in/med-namouchi)
[![Root-Me](https://img.shields.io/badge/Root--Me-Profile-orange)](https://www.root-me.org)

---

*All findings are sanitized. No real IPs, domains, credentials, or client data included.*
