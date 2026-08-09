# PB-03 — Alert Triage Checklist

**Purpose:** Fast prioritization of webhosting SIEM alerts
**Author:** Mohamed Amine Namouchi

---

## Priority Matrix

| Level | Rules | Action | Time target |
|---|---|---|---|
| 14 | 200306 (Webshell URL) | Immediate — PB-02 | 5 min |
| 12 | 200400 (New PHP file) | Immediate — PB-02 | 5 min |
| 12 | 200304, 200305 (RFI/CMDi) | Investigate | 10 min |
| 12 | 200502 (Webmin BF) | Investigate | 10 min |
| 12 | 200600 (MySQL direct) | Immediate — notify infra | 5 min |
| 10 | 200101, 200103 (WP BF) | Investigate — PB-01 | 15 min |
| 10 | 200202, 200203 (Flood) | Monitor | 30 min |
| 10 | 200300–200303 (Web attacks) | Investigate | 15 min |
| 8 | 200105, 200200 (xmlrpc/scanner) | Monitor | 60 min |
| 4–6 | 200100, 200102, 200201 | Log only | — |

---

## Known False Positives

| Rule | False positive condition | How to identify |
|---|---|---|
| 200304 (RFI) | `wp-login.php?redirect_to=https://` | URL contains `redirect_to` + legitimate vhost domain |
| 200303 (Sensitive file) | Uptime monitoring probing `.env` path | srcip = monitoring server internal IP |
| 200400 (New PHP) | Legitimate deployment via git/FTP | Check file content — no eval/base64 |
| 200501 (Webmin auth) | Admin browser pre-load | srcip = internal admin IP, low frequency |

---

## Quick Investigation Commands

```bash
# Get all alerts for a specific IP (last 24h)
sudo grep "<ip>" /var/ossec/logs/alerts/alerts.log | \
  grep "Rule:" | awk '{print $2,$3,$4,$5}' | tail -20

# Get all alerts for a specific vhost
sudo grep "<vhost>" /var/ossec/logs/alerts/alerts.log | \
  grep "Rule:" | tail -20

# Count alerts by rule ID today
sudo grep "$(date '+%b %d')" /var/ossec/logs/alerts/alerts.log | \
  grep "Rule:" | awk '{print $2}' | sort | uniq -c | sort -rn | head -10

# Check if an IP has been seen before
sudo grep -c "<ip>" /var/ossec/logs/alerts/alerts.log

# Active iptables blocks
sudo iptables -L INPUT -n | grep "DROP" | head -20
```

---

## Escalation Criteria

Escalate to infrastructure team  when:
- [ ] Rule 200600 fires (MySQL cluster direct access)
- [ ] Rule 200400 fires with confirmed webshell content
- [ ] Rule 200306 fires with HTTP 200 response (execution successful)
- [ ] Same attacker IP hits 5+ different vhosts in under 10 minutes
- [ ] Any alert firing at level 12+ on a Cloudflare-proxied site
  (attribution may be wrong — manual verification required)

---

## Dashboard Quick Links

| View | Filter to apply |
|---|---|
| All critical alerts | `rule.level: [12 TO 15]` |
| Specific attacker | `data.srcip: <ip>` |
| Specific site | `data.vhost: <domain>` |
| FIM events only | `rule.groups: syscheck` |
| WordPress attacks | `rule.groups: wordpress` |
| Today's webshell alerts | `rule.id: (200306 OR 200400) AND @timestamp: [now-24h TO now]` |

---

*Part of SIEM Web Hosting Security — SOC Playbooks*
*Last updated: August 2026*
