# SSH Brute-Force Attack Investigation

> Real threat hunting investigation conducted during a SOC internship.
> Methodology: from Wazuh alert to network-layer root cause.

---

## Incident Summary

| Field | Value |
|-------|-------|
| Alert source | Wazuh SIEM  |
| Attack type | SSH credential stuffing / brute force |
| Attacker profile | Automated Go-based script |
| Root cause | Forgotten NAT rule on perimeter router |

---

## Investigation Methodology

### Step 1 — Verify the alert in auth.log

Never trust a Wazuh alert number alone. Always verify in the raw log.

```bash
# Failed logins — confirm attacker IP
sudo lastb | head -20

# How many attempts today?
sudo grep "<ATTACKER_IP>" /var/log/auth.log | wc -l

# Any successful login? (critical check)
sudo grep "Accepted" /var/log/auth.log | grep "<ATTACKER_IP>"
```

> If grep "Accepted" returns nothing — no successful login, despite the alert.

---

### Step 2 — Check Fail2ban effectiveness

```bash
sudo fail2ban-client status sshd
```

Look at **total failed** vs **total banned** ratio.
High fail count + near-zero bans = threshold needs tuning.

Fix for high-volume attacks:
```ini
[sshd]
maxretry = 3
findtime = 300
bantime  = 86400
```

---

### Step 3 — Go to the network layer

This is the step most people skip — and where the real answer is.

```bash
# Live SSH traffic — see real source IPs at packet level
sudo tcpdump -i any port 22 -nn -c 100

# Full iptables audit including NAT table
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# All external traffic hitting the server
sudo tcpdump -i eth0 -nn \
  'src net not 172.16.0.0/12 and src net not 10.0.0.0/8' \
  -c 500
```

> Key insight: iptables on the host only filters AFTER traffic arrives.
> A NAT rule on the perimeter router can bypass host-level firewall entirely.

---

### Step 4 — Scan your perimeter from outside

```bash
# What does the internet actually see on your public IP?
nmap -Pn -p- --min-rate 5000 <PUBLIC_IP>

# Identify services on unexpected ports
nmap -Pn -sV -p <UNEXPECTED_PORT> <PUBLIC_IP>
```

> Any SSH banner on a non-standard port = likely a forgotten NAT rule.

---

### Step 5 — Root cause confirmed

```
Internet
    |
    v
Perimeter Router (public IP)
    |
    +-- Port XX  --> Internal Server:22  <-- FORGOTTEN NAT RULE (attack vector)
    +-- Port 80  --> Web server          (expected)
    +-- Port 443 --> Web server          (expected)
```

Attacker workflow — no special knowledge needed:
1. Port scan public IP
2. Find non-standard port with SSH banner
3. Launch automated brute-force

---

## Timeline

| Date | Event |
|------|-------|
| Unknown (old) | NAT rule created on router: non-standard port → server:22 |
| Regular scans | Censys indexes public IP and open ports |
| Attack day | Attacker finds SSH port via scan, launches brute-force |
| Discovery | SOC analyst finds alerts in Wazuh, investigates |
| Remediation | iptables rules added on host + NAT rule removed on router |
| Verification | Zero external SSH attempts in auth.log after fix |

---

## Key Lessons

### 1. Always go to the network layer first
tcpdump during the attack reveals the real traffic path instantly.
Application logs tell you WHAT happened. Packet captures tell you HOW.

### 2. Scan your own perimeter regularly
```bash
nmap -p- <YOUR_PUBLIC_IP>
```
Takes 5 minutes. Reveals exactly what attackers see.
Any unexpected SSH port = immediate investigation.

### 3. Audit router NAT rules periodically
NAT rules created for temporary access become permanent attack surfaces.
Schedule quarterly reviews of all port forwarding rules.

### 4. Host firewall alone is not enough
Defense in depth = firewall rules at the perimeter router AND at the host level.
One layer is never sufficient.

### 5. Do not chase application-layer rabbit holes
When an attack bypasses host-level controls, the answer is at the network
infrastructure level — not in web logs, DNS records, or Censys data.
Start at the bottom of the stack, not the top.

---

## Commands Reference

```bash
# Live SSH traffic capture
sudo tcpdump -i any port 22 -nn -c 100

# Full iptables audit
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# All external traffic
sudo tcpdump -i eth0 -nn \
  'src net not 172.16.0.0/12 and src net not 10.0.0.0/8' \
  -c 500

# Fail2ban status
sudo fail2ban-client status sshd

# Auth log analysis
sudo grep "Accepted\|Failed\|Invalid" /var/log/auth.log | \
  grep -v "172\.\|10\.\|127\." | tail -30

# Historical failed logins by IP
sudo zgrep "Failed password" /var/log/auth.log.* | \
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
  sort | uniq -c | sort -rn | head -20

# Perimeter scan
nmap -Pn -p- --min-rate 5000 <PUBLIC_IP>
nmap -Pn -sV -p <PORT> <PUBLIC_IP>
```
