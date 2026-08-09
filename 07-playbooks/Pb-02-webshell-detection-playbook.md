# PB-02 — Webshell Detection Response Playbook

**Trigger rules:** 200400 (level 12), 200306 (level 14)
**Severity:** Critical
**Response time target:** 5 minutes
**Author:** Mohamed Amine Namouchi

---

## ⚠️ This is a Critical Alert — Treat as Confirmed Compromise Until Proven Otherwise

---

## Triage (1 min)

Check the Mattermost alert:

- **Rule 200400** → FIM detected a new PHP file on the filesystem
- **Rule 200306** → Webshell execution pattern in a web request URL

Both require immediate investigation. Do not dismiss without verifying.

---

## Investigation — Rule 200400 (New PHP File)

```bash
# 1. Examine the file immediately
sudo cat <filepath-from-alert>

# 2. Check file ownership and permissions
sudo ls -la <filepath-from-alert>

# 3. Check who created it (audit log)
sudo grep "<filename>" /var/log/audit/audit.log 2>/dev/null | tail -10

# 4. Check VirusTotal result (auto-scan already triggered)
sudo grep "<filename>" /var/ossec/logs/alerts/alerts.log | \
  grep "virustotal" | tail -3

# 5. Cross-reference with web logs — was it accessed?
sudo grep "<filename>" /var/log/virtualmin/*_access_log | tail -10
```

**Decision tree:**

| Observation | Conclusion |
|---|---|
| File contains `eval(`, `base64_decode(`, `system(` | **WEBSHELL — escalate** |
| File is empty or 0 bytes | Likely test file — verify creator, monitor |
| File is legitimate deployment artifact | Document and close |
| VirusTotal: malicious | **WEBSHELL — escalate** |

---

## Investigation — Rule 200306 (Webshell Execution in URL)

```bash
# 1. Get the full request from alerts
sudo grep "200306" /var/ossec/logs/alerts/alerts.log | tail -5

# 2. Check if the file exists
sudo find /home/<client>/public_html -name "<filename-from-url>" 2>/dev/null

# 3. Check response code — did it succeed?
sudo grep "<url-from-alert>" /var/log/virtualmin/<vhost>_access_log | \
  awk '{print $9}' | sort | uniq -c
# 200 = executed successfully — CRITICAL
# 404 = file not found — attempt failed
```

---

## Containment (if webshell confirmed)

```bash
# 1. Isolate the file immediately
sudo chmod 000 <webshell-path>
sudo mv <webshell-path> /tmp/webshell-evidence-$(date +%Y%m%d%H%M%S).php

# 2. Block attacker IP
sudo iptables -I INPUT -s <attacker-ip> -j DROP

# 3. Check for additional webshells
sudo find /home/<client>/public_html -name "*.php" \
  -newer /home/<client>/public_html/wp-config.php \
  -exec grep -l "eval\|base64_decode\|system\|shell_exec" {} \;

# 4. Check for cron jobs added by attacker
sudo crontab -l -u <client-user>
sudo cat /etc/cron.d/* | grep -v "^#"

# 5. Notify client and infrastructure team immediately
```

---

## Evidence Preservation

```bash
# Hash the webshell for documentation
md5sum /tmp/webshell-evidence-*.php
sha256sum /tmp/webshell-evidence-*.php

# Export relevant log lines
sudo grep "<attacker-ip>" /var/log/virtualmin/<vhost>_access_log \
  > /tmp/incident-$(date +%Y%m%d)-access-log-extract.txt
```

---

## Close

- If webshell confirmed: full incident report, client notification, post-mortem
- If false positive: document reason, consider rule tuning
- Always preserve evidence before cleanup

---

*Part of SIEM Web Hosting Security — SOC Playbooks*
