# PB-01 — WordPress Brute Force Response Playbook

**Trigger rules:** 200101 (level 10), 200103 (level 10)
**Severity:** High
**Response time target:** 15 minutes
**Author:** Mohamed Amine Namouchi

---

## Triage (2 min)

When rule 200101 or 200103 fires, check the Mattermost alert:

- **IP** — is it internal (`172.x`, `10.x`)? If yes → false positive, close
- **Site** — which vhost is targeted?
- **Fired count** — how many times? 2x = starting, 50x+ = sustained campaign

---

## Investigation (5 min)

```bash
# 1. Count total attempts from attacker IP
sudo grep "<attacker-ip>" /var/log/virtualmin/<vhost>_access_log | \
  grep "wp-login.php" | wc -l

# 2. Check for successful login (POST 200 → GET /wp-admin/ 302)
sudo grep "<attacker-ip>" /var/log/virtualmin/<vhost>_access_log | \
  grep "wp-login\|wp-admin" | tail -20

# 3. Check User-Agent rotation (botnet indicator)
sudo grep "<attacker-ip>" /var/log/virtualmin/<vhost>_access_log | \
  awk -F'"' '{print $6}' | sort -u | wc -l
# > 3 distinct UAs = botnet confirmed

# 4. Check other targeted vhosts
sudo grep -l "<attacker-ip>" /var/log/virtualmin/*_access_log
```

---

## Severity Assessment

| Condition | Action |
|---|---|
| No successful login + attack ongoing | Monitor, block IP if blocking enabled |
| Successful login detected (POST 200 → wp-admin 302) | **ESCALATE immediately** → Step 4 |
| 500+ attempts, multiple vhosts | High priority — notify infrastructure team |

---

## Containment

**If web-block.sh is deployed:**
```bash
# Manual block if active response didn't trigger
sudo iptables -I INPUT -s <attacker-ip> -j DROP
echo "$(date) - Manual block: <attacker-ip> - WP brute force" \
  >> /var/ossec/logs/active-responses.log
```

**If successful login confirmed (escalation):**
```bash
# 1. Check WordPress users for new admin account
mysql -h <db-host> -u <db-user> -p <db-name> \
  -e "SELECT user_login, user_registered, user_email
      FROM wp_users ORDER BY user_registered DESC LIMIT 5;"

# 2. Check for recently created/modified files
sudo find /home/<client>/public_html -newer /tmp/reference -type f \
  -name "*.php" 2>/dev/null | head -20

# 3. Notify client immediately
```

---

## Close

- Document in incident log: date, IP, targeted site, attempts count, outcome
- If no compromise: close as "Attack detected, contained, no impact"
- If compromise confirmed: escalate to full IR procedure

---

*Part of SIEM Web Hosting Security — SOC Playbooks*
