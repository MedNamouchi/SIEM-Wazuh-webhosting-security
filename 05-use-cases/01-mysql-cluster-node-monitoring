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
Web Server (punica) → Load Balancer (.28) → MySQL Nodes (.14 / .15 / .16)
```

Any direct communication between the web server and the MySQL nodes — bypassing
the load balancer — is abnormal and may indicate a misconfiguration, a
compromised application, or an unauthorized lateral movement attempt. The
hosting team requested real-time alerting on any such direct communication,
regardless of protocol or port.

---

## Objective

Detect and alert on **any network communication** (inbound or outbound, any
protocol, any port) between the web hosting server and the three MySQL cluster
nodes, and notify the infrastructure team immediately.

| Component | Role | IP |
|---|---|---|
| Web hosting server | Source / Destination to monitor | `<web-server-ip>` |
| Load balancer | Authorized intermediary — not monitored | `<lb-ip>` |
| MySQL node 1 | Unauthorized direct target | `<node1-ip>` |
| MySQL node 2 | Unauthorized direct target | `<node2-ip>` |
| MySQL node 3 | Unauthorized direct target | `<node3-ip>` |

---

## Solution Architecture

The detection pipeline is built in four layers:

```
iptables LOG rules
      ↓
rsyslog (intercept + reformat)
      ↓
Wazuh agent (logcollector)
      ↓
Wazuh manager (rule 200600 → alert level 12 + email)
```

### Layer 1 — iptables LOG rules

Six iptables rules were added on the web hosting server to log all traffic
in both directions between the server and the three MySQL nodes:

```bash
# Outbound traffic (server → nodes)
iptables -A OUTPUT -d <node1-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A OUTPUT -d <node2-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A OUTPUT -d <node3-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4

# Inbound traffic (nodes → server)
iptables -A INPUT -s <node1-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A INPUT -s <node2-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
iptables -A INPUT -s <node3-ip> -j LOG --log-prefix "MYSQL_NODE_DIRECT: " --log-level 4
```

Rules are **LOG only** (no DROP) — traffic is not blocked, only recorded.
Rules are persisted across reboots via `iptables-persistent`.

**Coverage:** TCP, UDP, ICMP — any port — both directions.

### Layer 2 — rsyslog interception

iptables writes to `/var/log/kern.log` by default. The native Wazuh kernel
decoder (`iptables-1`) classifies these events as `type: firewall` and routes
them to a separate firewall queue, bypassing the standard alert pipeline.

To work around this, rsyslog is configured to intercept messages containing
`MYSQL_NODE_DIRECT`, reformat them with a custom template, and write them to
a dedicated file owned by the Wazuh user:

```
# /etc/rsyslog.d/mysql-nodes.conf
template(name="mysql_node_tpl" type="string"
         string="%TIMESTAMP% %HOSTNAME% MYSQL_ALERT: %msg%\n")
:msg, contains, "MYSQL_NODE_DIRECT" action(type="omfile"
    file="/var/log/mysql-nodes-direct.log"
    template="mysql_node_tpl")
& stop
```

The `& stop` directive prevents the message from also being written to
`kern.log`, avoiding duplicate processing.

File permissions:
```bash
chown syslog:wazuh /var/log/mysql-nodes-direct.log
chmod 640 /var/log/mysql-nodes-direct.log
```

Log rotation is handled by a dedicated logrotate config
(`/etc/logrotate.d/kern-wazuh`) with `create 0640 syslog wazuh` to preserve
permissions after rotation.

### Layer 3 — Wazuh agent collection

The dedicated log file is added to the Wazuh agent configuration:

```xml
<!-- /var/ossec/etc/ossec.conf on the web hosting server -->
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/mysql-nodes-direct.log</location>
</localfile>
```

### Layer 4 — Wazuh detection rule

```xml
<group name="webhosting,network,mysql,">

  <rule id="200600" level="12">
    <if_sid>88100</if_sid>
    <match>MYSQL_NODE_DIRECT</match>
    <description>ALERT: Direct communication detected between the web server
    and a MySQL cluster node — should go through load balancer only</description>
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
**Email notification:** Yes (`mail: True`) — infrastructure team notified immediately  

---

## Key Engineering Notes

**Why rsyslog reformatting was necessary:**
The native Wazuh kernel decoder (`iptables-1` in `0140-kernel_decoders.xml`)
uses `<type>firewall</type>`, which routes matched events to a separate firewall
queue (`firewall_written`) that bypasses the standard alert pipeline and archive
log. Events classified as `type: firewall` never reach the rule engine and
therefore never trigger alerts — even with `logall` enabled. The rsyslog
template reformats the line so that it is parsed by the `mariadb-syslog`
decoder instead (`program_name: MYSQL_ALERT`), which feeds the standard
pipeline correctly.

**Why `if_sid: 88100` instead of a direct decoder match:**
Rule 200600 uses `if_sid: 88100` (MariaDB group messages) as its parent,
combined with `<match>MYSQL_NODE_DIRECT</match>` to ensure it only fires on
our specific iptables events — not on actual MariaDB log entries.

**Load balancer exclusion:**
The load balancer IP is intentionally excluded from the monitored addresses.
Communication between the web server and the load balancer is authorized
and expected; only direct node communication is suspicious.

---

## Validation

Tested by generating ICMP traffic from the web hosting server to each of the
three MySQL nodes. Alerts fired within 2 seconds of the first packet in both
directions:

```
Rule: 200600 (level 12) → 'ALERT: Direct communication detected between
the web server and a MySQL cluster node — should go through load balancer only'

Outbound: SRC=<web-server-ip> DST=<node1-ip> PROTO=ICMP
Inbound:  SRC=<node1-ip>      DST=<web-server-ip> PROTO=ICMP
```

Both directions confirmed. Email notification confirmed (`mail: True`).

---

## Files Modified

| File | Location | Change |
|---|---|---|
| iptables rules | Web hosting server | 6 LOG rules added (INPUT + OUTPUT × 3 nodes) |
| `/etc/rsyslog.d/mysql-nodes.conf` | Web hosting server | New — intercept + reformat iptables events |
| `/var/log/mysql-nodes-direct.log` | Web hosting server | New — dedicated log file owned by wazuh |
| `/etc/logrotate.d/kern-wazuh` | Web hosting server | New — log rotation with wazuh permissions |
| `/var/ossec/etc/ossec.conf` | Web hosting server (agent) | Added localfile for mysql-nodes-direct.log |
| `webhosting-rules.xml` | Wazuh manager | Rule 200600 added |

---
*Part of the SIEM Web Hosting Security project — Detection Engineering*  
*Last updated: June 2026*
