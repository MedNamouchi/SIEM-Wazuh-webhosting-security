# UC-01 — MySQL Cluster Node Direct Access Monitoring

**Category:** Network Security / Policy Enforcement
**Priority:** High
**Status:** ✅ Deployed & Validated
**MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
**Compliance:** GDPR IV.35.7.d · NIST 800-53 AC.4 · PCI-DSS 1.3

---

## Context

The production web hosting server communicates with a backend MySQL cluster
composed of three dedicated nodes and one load balancer. The expected and
authorized architecture is:

```
Web Server (<web-server-ip>) → Load Balancer (<lb-ip>) → MySQL Nodes (<node1-ip> / <node2-ip> / <node3-ip>)
```

Any direct communication between the web server and the MySQL nodes —
bypassing the load balancer — is abnormal and may indicate:
- A misconfigured application connecting directly to a node
- A compromised process attempting lateral movement
- An attacker with local access attempting to reach the database tier directly

The infrastructure team requested real-time alerting on **any communication**
between the web server and the three MySQL nodes, regardless of protocol,
port, or direction.

---

## Objective

Detect and alert on any network communication (inbound or outbound, any
protocol, any port) between the web hosting server and the three MySQL
cluster nodes, and notify the infrastructure team immediately via email.

| Component | Role | Identifier |
|---|---|---|
| Web hosting server | Source / Destination to monitor | `<web-server-ip>` |
| Load balancer | Authorized intermediary — not monitored | `<lb-ip>` |
| MySQL node 1 | Unauthorized direct target | `<node1-ip>` |
| MySQL node 2 | Unauthorized direct target | `<node2-ip>` |
| MySQL node 3 | Unauthorized direct target | `<node3-ip>` |

---

## Solution Architecture

```
iptables LOG rules (on web server)
      ↓
rsyslog intercept + reformat
      ↓
/var/log/mysql-nodes-direct.log
      ↓
Wazuh agent (logcollector)
      ↓
Wazuh manager → rule 200600 → alert level 12 + email
```

---

## Layer 1 — iptables LOG Rules

Six iptables rules capture all traffic in both directions between the web
server and the three MySQL nodes:

```bash
# Outbound (web server → nodes)
iptables -A OUTPUT -d <node1-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A OUTPUT -d <node2-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A OUTPUT -d <node3-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4

# Inbound (nodes → web server)
iptables -A INPUT -s <node1-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A INPUT -s <node2-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A INPUT -s <node3-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
```

Rules are **LOG only** (no DROP) — traffic passes normally, only recorded.
Rules are persisted across reboots via `iptables-persistent`.

**Coverage:** TCP, UDP, ICMP — any port — both directions.

**Load balancer excluded intentionally:** `<lb-ip>` is not in the monitored
addresses. Communication between the web server and the load balancer is
expected and authorized.

---

## Layer 2 — rsyslog Interception

### Why rsyslog is required

iptables LOG messages go to `/var/log/kern.log` by default. The native
Wazuh `iptables-1` decoder classifies all iptables events as `type: firewall`,
routing them to a separate firewall queue that **bypasses the standard rule
engine entirely**. Custom rules using `if_sid` never fire on these events.

### Solution

rsyslog intercepts messages containing `MYSQL_NODE_DIRECT`, reformats them
with a custom template that changes the `program_name`, and writes to a
dedicated file owned by the Wazuh user:

```
# /etc/rsyslog.d/mysql-nodes.conf
template(name="mysql_node_tpl" type="string"
         string="%TIMESTAMP% %HOSTNAME% MYSQL_ALERT: %msg%\n")
:msg, contains, "MYSQL_NODE_DIRECT" action(type="omfile"
    file="/var/log/mysql-nodes-direct.log"
    template="mysql_node_tpl")
& stop
```

The `& stop` directive prevents double-processing in `kern.log`.

File permissions:
```bash
chown syslog:wazuh /var/log/mysql-nodes-direct.log
chmod 640 /var/log/mysql-nodes-direct.log
```

Log rotation (`/etc/logrotate.d/mysql-nodes-direct`):
```
/var/log/mysql-nodes-direct.log {
    su root adm
    rotate 4
    weekly
    missingok
    notifempty
    compress
    delaycompress
    create 0640 syslog wazuh
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
```

---

## Layer 3 — Wazuh Agent Collection

```xml
<!-- /var/ossec/etc/ossec.conf on web hosting server -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/mysql-nodes-direct.log</location>
</localfile>
```

---

## Layer 4 — Detection Rule

```xml
<group name="webhosting,network,mysql,">

  <rule id="200600" level="12">
    <if_sid>88100</if_sid>
    <match>MYSQL_NODE_DIRECT</match>
    <description>ALERT: Direct communication detected between web server
    and MySQL cluster node — should go through load balancer only</description>
    <group>policy_violation,gdpr_IV_35.7.d,nist_800_53_AC.4,pci_dss_1.3,</group>
    <options>alert_by_email</options>
    <mitre>
      <id>T1190</id>
    </mitre>
  </rule>

</group>
```

**Rule ID:** 200600
**Level:** 12 (Critical)
**Email:** Yes — infrastructure team notified immediately
**Parent:** `if_sid: 88100` (MariaDB group messages decoder — used because
the rsyslog template sets `program_name` to `MYSQL_ALERT` which is parsed
by the `mariadb-syslog` decoder)

---

## Key Engineering Notes

### Why `if_sid: 88100` instead of `if_sid: 554` or a custom decoder

The rsyslog template sets the log line's `program_name` to `MYSQL_ALERT`.
Wazuh's `mariadb-syslog` decoder matches on this program name, classifying
the event under rule 88100 (MariaDB group messages, level 0). Rule 200600
uses `if_sid: 88100` as parent and `<match>MYSQL_NODE_DIRECT</match>` to
ensure it only fires on our specific iptables events — not on actual
MariaDB log entries.

### Why the iptables firewall queue bypass was not obvious

The `iptables-1` decoder's `type: firewall` classification is not documented
prominently. The symptom — events visible in `archives.json` but custom
rules never firing — appears identical to a rule syntax error. The root cause
was identified only by examining the `firewall_written` counter in
`wazuh-analysisd.state` (value remained 0 despite events) and reading the
Wazuh decoder source files directly.

---

## Validation

Tested by generating ICMP traffic from the web server to each MySQL node:

```bash
ping -c 1 <node1-ip>
```

Alerts fired within 2 seconds in both directions:

```
Rule: 200600 (level 12) → 'ALERT: Direct communication detected between
web server and MySQL cluster node — should go through load balancer only'

Outbound: SRC=<web-server-ip> DST=<node1-ip> PROTO=ICMP
Inbound:  SRC=<node1-ip>      DST=<web-server-ip> PROTO=ICMP
```

Email notification confirmed (`mail: True`). Both directions captured. ✅

---

## Files Modified

| File | Location | Change |
|---|---|---|
| iptables rules | Web server | 6 LOG rules added (INPUT + OUTPUT × 3 nodes) |
| `/etc/rsyslog.d/mysql-nodes.conf` | Web server | New — intercept + reformat |
| `/var/log/mysql-nodes-direct.log` | Web server | New — dedicated log file |
| `/etc/logrotate.d/mysql-nodes-direct` | Web server | New — log rotation |
| `/var/ossec/etc/ossec.conf` | Web server (agent) | Added localfile entry |
| `webhosting-rules.xml` | Wazuh manager | Rule 200600 added |

---

*Part of the SIEM Web Hosting Security project — Detection Engineering*
*Last updated: August 2026*
