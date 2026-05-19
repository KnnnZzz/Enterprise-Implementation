# Phase 5 — Operational Validation, Monitoring & Pitfalls Compendium

---

## 5.1 Post-Deployment Validation Checklist

### Infrastructure Health Verification

```bash
# ── 1. Wazuh Manager Cluster Status ──
/var/ossec/bin/cluster_control -l
# Expected: All nodes listed, type=master/worker, synced

/var/ossec/bin/cluster_control -i
# Expected: n_connected_nodes matches expected count

# ── 2. Wazuh Indexer Cluster Health ──
curl -sk -u admin:PASSWORD "https://192.168.10.40:9200/_cluster/health?pretty"
# Expected: "status": "green", "number_of_nodes": 3

curl -sk -u admin:PASSWORD "https://192.168.10.40:9200/_cat/nodes?v"
# Expected: All 3 nodes listed with roles

# ── 3. Agent Connectivity ──
/var/ossec/bin/agent_control -l
# Verify agent count matches expected fleet size

# Check for disconnected agents
/var/ossec/bin/agent_control -l | grep -c "Disconnected"

# ── 4. Filebeat → Indexer Pipeline ──
curl -sk -u admin:PASSWORD "https://192.168.10.40:9200/_cat/indices/wazuh-alerts-*?v&s=index:desc" | head -5
# Expected: Recent indices with growing doc.count

# ── 5. Analysis Engine Health ──
cat /var/ossec/var/run/wazuh-analysisd.state
# Key metrics:
#   events_received > 0
#   events_dropped = 0 (CRITICAL if non-zero)
#   events_processed > 0
#   event_queue_usage < 0.7

# ── 6. Service Status ──
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard
systemctl status filebeat
```

### Functional Validation Tests

```bash
# ── Test 1: FIM Detection ──
# Create a test file in a monitored directory
touch /etc/fim-test-$(date +%s).tmp
# Wait for syscheck scan, then verify alert in Dashboard
# Search: rule.id:554 AND syscheck.path:"/etc/fim-test*"
# Cleanup after validation
rm /etc/fim-test-*.tmp

# ── Test 2: Custom Rule Trigger ──
# Trigger a known rule (e.g., SSH brute force simulation)
for i in $(seq 1 10); do
    ssh -o StrictHostKeyChecking=no invalid_user@localhost 2>/dev/null
done
# Expected: Rule 5710/5712 should fire + custom threshold rule

# ── Test 3: MISP Integration ──
# Check integration logs
tail -20 /var/ossec/logs/integrations.log
# Should show MISP queries without errors

# ── Test 4: Active Response ──
# Verify firewall-drop is functional (test environment only)
/var/ossec/active-response/bin/firewall-drop add - 10.99.99.99 1
iptables -L -n | grep 10.99.99.99
/var/ossec/active-response/bin/firewall-drop delete - 10.99.99.99 1

# ── Test 5: CDB List Validation ──
# Verify CDB lists are compiled
ls -la /var/ossec/etc/lists/malicious-ioc/
# Should see .cdb files alongside the text files

# ── Test 6: Vulnerability Detection ──
curl -sk -u admin:PASSWORD "https://192.168.10.40:9200/wazuh-states-vulnerabilities-*/_count" | python3 -m json.tool
# Expected: count > 0
```

---

## 5.2 Continuous Monitoring — SIEM Health Dashboard

### Self-Monitoring Commands (already configured in your ossec.conf)

Your existing configuration includes health monitoring. Here's the complete set:

```xml
<!-- System Resources (CPU/RAM) — every 2 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>top -bn1 | head -5; free -m | head -3</command>
    <alias>system_resources</alias>
    <frequency>120</frequency>
</localfile>

<!-- Analysis Engine State — every 1 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>cat /var/ossec/var/run/wazuh-analysisd.state 2>/dev/null | grep -E 'events_|queue_'</command>
    <alias>analysisd_health</alias>
    <frequency>60</frequency>
</localfile>

<!-- Cluster Health — every 5 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>/var/ossec/bin/cluster_control -l 2>/dev/null || echo "cluster_disabled"</command>
    <alias>cluster_health</alias>
    <frequency>300</frequency>
</localfile>

<!-- OpenSearch Index Sizes — every 10 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>curl -sk -u admin:admin https://192.168.10.20:9200/_cat/indices/wazuh-alerts-*?h=index,docs.count,store.size | tail -5</command>
    <alias>opensearch_index_size</alias>
    <frequency>600</frequency>
</localfile>

<!-- Disk Usage — every 6 min -->
<localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
</localfile>

<!-- Agent Connection Summary — every 10 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>/var/ossec/bin/agent_control -l | tail -1</command>
    <alias>agent_summary</alias>
    <frequency>600</frequency>
</localfile>
```

### Custom Rules for SIEM Self-Alerting

```xml
<!-- /var/ossec/etc/rules/siem_health_rules.xml -->
<group name="siem_health,">

    <!-- Disk usage > 85% on any SIEM node -->
    <rule id="100050" level="12">
        <if_sid>531</if_sid>
        <regex>8[5-9]%|9[0-9]%|100%</regex>
        <description>SIEM HEALTH: Disk usage critical (>85%) — risk of data loss.</description>
        <group>siem_health,disk,</group>
    </rule>

    <!-- Analysis engine dropping events -->
    <rule id="100051" level="14">
        <match>analysisd_health</match>
        <regex>events_dropped='[1-9]</regex>
        <description>CRITICAL: Wazuh analysisd is DROPPING events — queue overflow.</description>
        <group>siem_health,performance,</group>
    </rule>

    <!-- Agent disconnection spike -->
    <rule id="100052" level="10" frequency="5" timeframe="300">
        <if_sid>503</if_sid>
        <description>SIEM HEALTH: Multiple agents disconnected in 5 minutes — possible network issue.</description>
        <group>siem_health,agents,</group>
    </rule>

</group>
```

---

## 5.3 Enterprise Pitfalls & Gotchas Compendium

### Architecture & Deployment

| # | Pitfall | Impact | Mitigation |
|---|---|---|---|
| 1 | **Single-node indexer** | No fault tolerance; single disk failure = data loss | Deploy 3-node minimum cluster with 1 replica |
| 2 | **Enrollment to worker nodes** | Silent agent registration failure | Route `:1515` exclusively to master node via LB |
| 3 | **`cluster.initial_master_nodes` left in config** | Split-brain on network partition → data corruption | Remove after initial cluster bootstrap |
| 4 | **JVM heap > 32 GB** | Performance degradation (compressed OOPs lost) | Cap at 31 GB; never exceed 50% of RAM |
| 5 | **Spinning disks on indexer** | Indexing bottleneck at >1000 EPS | NVMe SSDs mandatory for production |

### Security & Certificates

| # | Pitfall | Impact | Mitigation |
|---|---|---|---|
| 6 | **Certificate CN ≠ `node.name`** | TLS handshake failures, nodes can't join cluster | Ensure exact match with `plugins.security.nodes_dn` |
| 7 | **Expired certificates** | Complete cluster communication failure | Implement cert expiry monitoring; renew 30 days early |
| 8 | **Default `admin:admin` credentials** | Trivial unauthorized access | Change immediately post-install; use strong passwords |
| 9 | **SAML without basic auth fallback** | Locked out when IdP is down | Keep `basic_internal_auth_domain` at order 0, challenge false |
| 10 | **API keys in ossec.conf plaintext** | Credential exposure in backups/version control | Use secret files (`/var/ossec/etc/*.secret`) loaded at runtime |

### Performance & Tuning

| # | Pitfall | Impact | Mitigation |
|---|---|---|---|
| 11 | **Default `queue_size` (16384)** | Event drops at >2000 agents | Set to `131072` for enterprise deployments |
| 12 | **`analysisd` single-threaded** | CPU bottleneck on analysis | Increase `event_threads` in `local_internal_options.conf` |
| 13 | **FIM `realtime` on entire filesystem** | Inotify watcher exhaustion; kernel panic possible | Use `realtime` only on critical dirs; `frequency` scan for others |
| 14 | **Mass agent enrollment storm** | `wazuh-authd` overwhelmed; failed registrations | Batch deployments: 100–200 agents, 60s delay between batches |
| 15 | **No ISM/ILM policy** | Unbounded index growth → disk exhaustion | Apply ISM policy immediately; auto-delete after retention period |

### Integrations

| # | Pitfall | Impact | Mitigation |
|---|---|---|---|
| 16 | **MISP integration loop** | Alert triggers MISP lookup → generates alert → infinite loop | Filter MISP rule IDs from integration trigger (rule_id prefix check) |
| 17 | **VirusTotal free API rate limit** | 4 req/min exceeded rapidly from FIM | Enterprise API key; filter by `<group>syscheck</group>` only |
| 18 | **Active Response with `location=all`** | False positive blocks legitimate IP across entire fleet | Start with `location=local`; thorough whitelist; always use `timeout` |
| 19 | **CDB list > 500K entries** | Slow `analysisd` restart; high memory usage | Use API-based lookups (MISP integration) for large IoC feeds |
| 20 | **Syslog over UDP for firewalls** | Log loss under load; no delivery guarantee | Use TCP syslog (`<protocol>tcp</protocol>`) always |

### Operational

| # | Pitfall | Impact | Mitigation |
|---|---|---|---|
| 21 | **No `client.keys` backup** | All agents must re-enroll after manager recovery | Include in daily encrypted backups |
| 22 | **Time desynchronization** | Alert correlation failures; impossible forensics | NTP/chrony on ALL nodes; UTC timezone |
| 23 | **Modifying default ruleset files** | Overwritten on Wazuh upgrade; customizations lost | Always use `/var/ossec/etc/rules/` and `/var/ossec/etc/decoders/` |
| 24 | **No log_alert_level tuning** | Level 1–3 noise floods indexer with low-value data | Set `<log_alert_level>6</log_alert_level>` minimum |
| 25 | **Dashboard as single point of failure** | SOC analysts locked out during maintenance | Deploy 2 Dashboard nodes behind LB |

---

## 5.4 Deployment Execution Order — Linear Checklist

```
Phase 0: Infrastructure Preparation
  □ Provision VMs/bare-metal per sizing matrix
  □ Configure network segmentation (VLANs)
  □ Apply firewall rules (port matrix)
  □ Configure NTP on all nodes
  □ Disable swap on Indexer nodes
  □ Apply kernel parameters (sysctl)

Phase 1: Certificate & Security Foundation
  □ Generate certificates with wazuh-certs-tool
  □ Distribute certificates to all nodes
  □ Harden SSH on all nodes
  □ Install and configure auditd
  □ Set file descriptor limits

Phase 2: Wazuh Indexer Cluster
  □ Install wazuh-indexer on 3 nodes
  □ Configure opensearch.yml (cluster, certs, performance)
  □ Tune JVM heap (50% RAM, ≤32GB)
  □ Start cluster, verify green health
  □ Run securityadmin to initialize security
  □ Change default admin password
  □ REMOVE cluster.initial_master_nodes from config
  □ Apply ISM policies

Phase 3: Wazuh Manager Cluster
  □ Install wazuh-manager (master node first)
  □ Configure ossec.conf (remote, cluster, auth, modules)
  □ Set enrollment password
  □ Install and configure Filebeat
  □ Start master, verify connectivity to Indexer
  □ Install worker node(s), join cluster
  □ Verify cluster_control -l shows all nodes

Phase 4: Wazuh Dashboard
  □ Install wazuh-dashboard (2 nodes)
  □ Configure opensearch_dashboards.yml
  □ Configure SSO/SAML (if applicable)
  □ Verify Dashboard connects to Indexer
  □ Configure RBAC roles and mappings

Phase 5: Load Balancer
  □ Install HAProxy/NGINX
  □ Configure frontends/backends for 1514, 1515, 55000, 443
  □ Test agent connectivity through LB
  □ Test enrollment through LB
  □ Test API through LB

Phase 6: Agent Deployment
  □ Create agent groups and shared configurations
  □ Test single agent enrollment manually
  □ Deploy Ansible playbook / SCCM package (batched)
  □ Verify agents appear in Dashboard
  □ Validate FIM, SCA, Vuln Detection data flowing

Phase 7: Customization & Integrations
  □ Deploy custom decoders and rules
  □ Configure CDB lists
  □ Deploy MISP integration + CDB sync cron
  □ Configure VirusTotal integration
  □ Configure TheHive/Jira integration
  □ Configure SOAR webhook (Shuffle/n8n)
  □ Configure cloud log sources (AWS/Azure/O365)
  □ Configure firewall syslog forwarding

Phase 8: Operational Readiness
  □ Run full validation test suite
  □ Configure self-monitoring rules
  □ Set up backup cron (snapshots + config)
  □ Configure Telegram/Slack alerting for critical events
  □ Document runbooks for SOC analysts
  □ Conduct tabletop exercise with SOC team
  □ Sign off for production
```

---

## 5.5 References & Resources

| Resource | URL |
|---|---|
| Wazuh Official Documentation | https://documentation.wazuh.com |
| Wazuh Ruleset Repository | https://github.com/wazuh/wazuh-ruleset |
| OpenSearch Security Plugin | https://opensearch.org/docs/latest/security/ |
| MITRE ATT&CK Framework | https://attack.mitre.org |
| Wazuh API Reference | https://documentation.wazuh.com/current/user-manual/api/reference.html |
| CIS Benchmarks | https://www.cisecurity.org/cis-benchmarks |
| MISP Project | https://www.misp-project.org |
| TheHive Project | https://thehive-project.org |

---

> **Document End — Wazuh Enterprise SOC Deployment Playbook v1.0**  
> This playbook is a living document. Update as your environment evolves, new integrations are added, and lessons are learned from operational incidents.
