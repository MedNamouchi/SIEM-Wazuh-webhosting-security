# Key Findings & Lessons Learned

> Takeaways from deploying and operating a SIEM on a production shared hosting server.
> Applicable to any similar engagement.

---

## 1. The Virtualmin Log Blind Spot

**What happened:**
Wazuh was configured to monitor `/var/log/apache2/access.log`.
This file had been empty since 2024. All real traffic was going to
`/var/log/virtualmin/<domain>_access_log` — one file per virtual host.
The SIEM had been blind to all web traffic for years.

**The fix:**
```xml
<localfile>
  <log_format>apache</log_format>
  <location>/var/log/virtualmin/*_access_log</location>
</localfile>
```

**The lesson:**
On any shared hosting server using Virtualmin, the first thing to verify
is where Apache actually writes its logs. Never assume the default path is correct.
Always run:
```bash
sudo grep -rh 'CustomLog' /etc/apache2/sites-enabled/ | sort -u
```

---

## 2. Forgotten NAT Rules Are Silent Attack Vectors

**What happened:**
The server had iptables rules blocking SSH from external IPs.
But a NAT rule on the perimeter router was forwarding an external
non-standard port directly to the server's SSH port.
This rule was created years ago, forgotten, and never removed.

**How it was found:**
```bash
nmap -Pn -p- --min-rate 5000 <PUBLIC_IP>
nmap -Pn -sV -p <UNEXPECTED_PORT> <PUBLIC_IP>
```
An SSH banner appeared on a non-standard port — revealing the NAT rule.

**The lesson:**
Scan your own perimeter regularly from an external network.
Audit all router NAT/forwarding rules quarterly.
Host-level firewall alone is not sufficient — defense in depth requires
protection at both the perimeter and the host.

---

## 3. Censys Indexes Everything

**What happened:**
Censys automatically scanned the public IP, detected all open ports
and services, and published the results publicly. Any attacker searching
for the organization name or IP on censys.io gets a complete map of
the exposed infrastructure.

**The lesson:**
Assume your public IP is fully indexed by Censys, Shodan, and similar tools.
Regularly search your own IP and organization name on these platforms to see
what attackers see. Close anything that should not be public.

---

## 4. Application Layer vs Network Layer Investigation

**What happened:**
During the SSH attack investigation, significant time was spent analyzing
web logs, DNS records, HTTP headers, and Censys data. The real answer
was at the network layer — a forgotten router NAT rule.

**The right approach:**
```
Start here:   tcpdump -i any port 22 -nn
              iptables -t nat -L -n -v
              nmap -p- <PUBLIC_IP>

Not here:     web logs, DNS records, HTTP headers
```

**The lesson:**
When an attack bypasses host-level controls, investigate the network
infrastructure first. Application logs tell you WHAT happened.
Network captures tell you HOW.

---

## 5. WordPress Attacks Are Automated and Constant

**What happened:**
Analysis of unmonitored web logs revealed a coordinated WordPress
brute-force botnet with 6+ IPs making 20,000+ login attempts across
multiple hosted sites.

**Attack signatures to detect:**
- `GET /?author=1` repeated rapidly = username enumeration
- `POST /wp-login.php` (200) followed by redirect to `/wp-admin/` = successful login
- Multiple IPs rotating User-Agent strings between requests = botnet

**The lesson:**
WordPress sites on shared hosting are constantly under attack.
Without SIEM visibility on web logs, successful compromises can go
undetected for months.

---

## 6. Fail2ban Needs Tuning for Production Load

**What happened:**
Fail2ban was active with 6 jails. Despite thousands of failed SSH attempts,
only 1 IP had ever been banned. Default settings are designed for low-volume
attacks — not for servers under constant automated scanning.

**Recommended tuning:**
```ini
[sshd]
maxretry = 3
findtime = 300
bantime  = 86400
```

**The lesson:**
Always check the ratio of total failed attempts to total bans.
If thousands of attempts result in near-zero bans, Fail2ban is not
configured for the actual attack volume.

---

## 7. Always Verify Exposure from External Network

**What happened:**
An admin panel was found listening on all interfaces. Internal tests
showed HTTP 200. But an external test from a mobile 5G connection
returned timeout — the gateway was blocking the port.

**The lesson:**
Never conclude a service is internet-exposed based on an internal test.
Always verify from a real external network (mobile 4G/5G, not office WiFi).

```powershell
# Windows PowerShell from external network
Test-NetConnection -ComputerName <IP> -Port <PORT>
```

---

## Reusable Checklist

- [ ] Verify actual Apache log paths before assuming SIEM has visibility
- [ ] Scan public IP with nmap from external network
- [ ] Audit all NAT/forwarding rules on perimeter router
- [ ] Check Fail2ban fail/ban ratio per jail
- [ ] Confirm iptables rules exist (not just assumed)
- [ ] Test admin panel accessibility from real external network
- [ ] Search organization name on Censys and Shodan
- [ ] Verify FIM covers web directories, not just system directories
- [ ] Check Redis, phpMyAdmin, and similar services for authentication
