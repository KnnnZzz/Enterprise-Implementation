# Day 3 — Integrations, Backups & Go-Live

> **Goal:** Threat intel connected, notifications active, backups automated, full validation, production sign-off.  
> **Estimated time:** 6–8 hours

---

## 3.1 VirusTotal Integration (30 min)

The simplest threat intel integration — requires only a free API key.

### Get API Key
1. Register at https://www.virustotal.com
2. Go to Profile → API Key → Copy

### Configure in `ossec.conf`

```xml
<!-- Add to /var/ossec/etc/ossec.conf -->
<integration>
    <name>virustotal</name>
    <api_key>YOUR_VT_API_KEY_HERE</api_key>
    <group>syscheck</group>
    <alert_format>json</alert_format>
</integration>
```

### VirusTotal Alert Rules

Add to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<!-- VirusTotal Integration -->
<rule id="100510" level="0">
    <decoded_as>json</decoded_as>
    <field name="integration">virustotal</field>
    <description>VirusTotal integration event.</description>
</rule>

<rule id="100511" level="3">
    <if_sid>100510</if_sid>
    <field name="virustotal.found">0</field>
    <description>VirusTotal: No results for file hash.</description>
</rule>

<rule id="100512" level="5">
    <if_sid>100510</if_sid>
    <field name="virustotal.found">1</field>
    <field name="virustotal.malicious">0</field>
    <description>VirusTotal: File known — no vendors flagged malicious.</description>
</rule>

<rule id="100513" level="12">
    <if_sid>100510</if_sid>
    <field name="virustotal.found">1</field>
    <field name="virustotal.positives" type="pcre2">^([1-9]|[1-9][0-9])</field>
    <description>VirusTotal ALERT: Malware detected — $(virustotal.positives) vendors flagged.</description>
    <group>malware,threat_intel,</group>
    <mitre>
        <id>T1204.002</id>
    </mitre>
</rule>
```

> **⚠️ Free VT API:** Limited to 4 requests/min and 500/day. Sufficient for small companies with `<group>syscheck</group>` filter (only FIM file changes trigger lookups). For higher volume, purchase an enterprise key.

```bash
systemctl restart wazuh-manager
```

---

## 3.2 MISP Integration — Optional but Recommended (1.5 hours)

If you have a MISP instance (or access to a community MISP), deploy the full integration.

### Quick Setup

```bash
# 1. Store API key securely
echo "YOUR_MISP_API_KEY" > /var/ossec/etc/misp.secret
chmod 400 /var/ossec/etc/misp.secret
chown root:wazuh /var/ossec/etc/misp.secret

# 2. Copy MISP CA certificate (if self-signed)
cp /path/to/misp-ca.pem /var/ossec/etc/misp-cert.pem
chmod 444 /var/ossec/etc/misp-cert.pem

# 3. Install requests library for Wazuh Python
/var/ossec/framework/python/bin/pip3 install requests

# 4. Deploy integration script
cp custom-misp_file_hashes.py /var/ossec/integrations/
chmod 750 /var/ossec/integrations/custom-misp_file_hashes.py
chown root:wazuh /var/ossec/integrations/custom-misp_file_hashes.py
```

### Add to `ossec.conf`

```xml
<integration>
    <name>custom-misp_file_hashes.py</name>
    <hook_url>https://YOUR_MISP_URL</hook_url>
    <api_key>LOADED_FROM_SECURE_FILE</api_key>
    <level>5</level>
    <alert_format>json</alert_format>
    <options>{"timeout": 10, "retries": 3, "debug": false,
              "tags": ["tlp:white", "tlp:clear", "malware"],
              "push_sightings": true,
              "ca_cert": "/var/ossec/etc/misp-cert.pem"}</options>
</integration>
```

### CDB Sync Cron (batch IoC updates)

```bash
cp misp-cdb-sync.py /var/ossec/integrations/
chmod 750 /var/ossec/integrations/misp-cdb-sync.py

# Run every 4 hours
echo '0 */4 * * * root /var/ossec/framework/python/bin/python3 /var/ossec/integrations/misp-cdb-sync.py >> /var/ossec/logs/misp-cdb-sync.log 2>&1' \
  > /etc/cron.d/wazuh-misp-sync
```

---

## 3.3 Notification Setup — Telegram or Email (45 min)

### Option A: Telegram Bot (Recommended — instant mobile alerts)

```bash
# 1. Create a Telegram bot via @BotFather → Get BOT_TOKEN
# 2. Get your chat ID: message the bot, then:
#    curl https://api.telegram.org/botYOUR_BOT_TOKEN/getUpdates
#    → Find "chat":{"id": YOUR_CHAT_ID}

# 3. Deploy the integration script
cat > /var/ossec/integrations/custom-telegram.sh << 'SCRIPT'
#!/bin/bash
ALERT_FILE="$1"
API_KEY="$2"
CHAT_ID="YOUR_CHAT_ID"

RULE_ID=$(jq -r '.rule.id' "$ALERT_FILE")
LEVEL=$(jq -r '.rule.level' "$ALERT_FILE")
DESC=$(jq -r '.rule.description' "$ALERT_FILE")
AGENT=$(jq -r '.agent.name // "Manager"' "$ALERT_FILE")
SRCIP=$(jq -r '.data.srcip // .srcip // "N/A"' "$ALERT_FILE")
TIMESTAMP=$(jq -r '.timestamp' "$ALERT_FILE")

if [ "$LEVEL" -ge 14 ]; then EMOJI="🔴"
elif [ "$LEVEL" -ge 12 ]; then EMOJI="🟠"
elif [ "$LEVEL" -ge 10 ]; then EMOJI="🟡"
else EMOJI="🔵"; fi

MSG="$EMOJI *WAZUH* (Level $LEVEL)
*Rule:* $RULE_ID
*Desc:* $DESC
*Agent:* $AGENT
*SrcIP:* $SRCIP
*Time:* $TIMESTAMP"

curl -s -X POST "https://api.telegram.org/bot${API_KEY}/sendMessage" \
    -d "chat_id=$CHAT_ID" -d "text=$MSG" -d "parse_mode=Markdown" \
    >> /var/ossec/logs/telegram.log 2>&1
SCRIPT

chmod 750 /var/ossec/integrations/custom-telegram.sh
chown root:wazuh /var/ossec/integrations/custom-telegram.sh
```

> **⚠️ Replace `YOUR_CHAT_ID`** inside the script.

```xml
<!-- Add to ossec.conf -->
<integration>
    <name>custom-telegram.sh</name>
    <hook_url>https://api.telegram.org</hook_url>
    <api_key>YOUR_TELEGRAM_BOT_TOKEN</api_key>
    <level>12</level>
    <alert_format>json</alert_format>
</integration>
```

### Option B: Email Notifications

```xml
<!-- Enable email in ossec.conf -->
<global>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.company.com</smtp_server>
    <email_from>wazuh@company.com</email_from>
    <email_to>soc-team@company.com</email_to>
    <email_maxperhour>24</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
</global>

<alerts>
    <email_alert_level>12</email_alert_level>
</alerts>

<!-- Granular email rules (optional) -->
<email_alerts>
    <email_to>ciso@company.com</email_to>
    <level>14</level>
    <group>malware|credential_access|threat_intel</group>
</email_alerts>
```

```bash
systemctl restart wazuh-manager
```

---

## 3.4 Index Lifecycle Management (30 min)

Prevent disk exhaustion with automatic data aging.

```bash
# Apply ISM policy via OpenSearch API
curl -sk -u admin:YOUR_PASSWORD -X PUT \
  "https://localhost:9200/_plugins/_ism/policies/wazuh-retention" \
  -H 'Content-Type: application/json' \
  -d '{
    "policy": {
        "description": "Small Company: 7d Hot, force-merge Warm, 90d Delete.",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [
                    {
                        "state_name": "warm",
                        "conditions": { "min_index_age": "7d" }
                    }
                ]
            },
            {
                "name": "warm",
                "actions": [
                    { "read_only": {} },
                    { "force_merge": { "max_num_segments": 1 } }
                ],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": { "min_index_age": "90d" }
                    }
                ]
            },
            {
                "name": "delete",
                "actions": [ { "delete": {} } ],
                "transitions": []
            }
        ],
        "ism_template": [
            {
                "index_patterns": [
                    "wazuh-alerts-4.x-*",
                    "wazuh-archives-4.x-*"
                ],
                "priority": 100
            }
        ]
    }
}'

# Verify policy was created
curl -sk -u admin:YOUR_PASSWORD \
  "https://localhost:9200/_plugins/_ism/policies/wazuh-retention" | python3 -m json.tool

# Apply to existing indices
curl -sk -u admin:YOUR_PASSWORD -X POST \
  "https://localhost:9200/_plugins/_ism/add/wazuh-alerts-4.x-*" \
  -H 'Content-Type: application/json' \
  -d '{"policy_id": "wazuh-retention"}'
```

---

## 3.5 Automated Backups (30 min)

### Manager Config Backup

```bash
cat > /usr/local/bin/wazuh-backup.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail
BACKUP_DIR="/opt/wazuh-backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Configuration + agent keys + rules + integrations
tar -czf "$BACKUP_DIR/wazuh-config.tar.gz" \
    /var/ossec/etc/ossec.conf \
    /var/ossec/etc/rules/ \
    /var/ossec/etc/decoders/ \
    /var/ossec/etc/lists/ \
    /var/ossec/etc/shared/ \
    /var/ossec/etc/client.keys \
    /var/ossec/etc/authd.pass \
    /var/ossec/integrations/ \
    2>/dev/null

# Keep 30 days of backups
find /opt/wazuh-backups/ -maxdepth 1 -type d -mtime +30 -exec rm -rf {} +

echo "[OK] Backup: $BACKUP_DIR — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCRIPT

chmod 700 /usr/local/bin/wazuh-backup.sh

# Daily at 03:00
echo '0 3 * * * root /usr/local/bin/wazuh-backup.sh >> /var/log/wazuh-backup.log 2>&1' \
  > /etc/cron.d/wazuh-backup
```

### OpenSearch Snapshot (optional — if you have NFS/external storage)

```bash
# Add to opensearch.yml
echo 'path.repo: ["/opt/wazuh-snapshots"]' >> /etc/wazuh-indexer/opensearch.yml
mkdir -p /opt/wazuh-snapshots
chown wazuh-indexer:wazuh-indexer /opt/wazuh-snapshots
systemctl restart wazuh-indexer

# Register repository
curl -sk -u admin:YOUR_PASSWORD -X PUT \
  "https://localhost:9200/_snapshot/backups" \
  -H 'Content-Type: application/json' \
  -d '{"type": "fs", "settings": {"location": "/opt/wazuh-snapshots", "compress": true}}'

# Create a weekly snapshot cron
echo '0 4 * * 0 root curl -sk -u admin:YOUR_PASSWORD -X PUT "https://localhost:9200/_snapshot/backups/weekly-$(date +\%Y\%m\%d)?wait_for_completion=false" -H "Content-Type: application/json" -d "{\"indices\": \"wazuh-alerts-*,.kibana*\", \"ignore_unavailable\": true, \"include_global_state\": false}" >> /var/log/wazuh-snapshot.log 2>&1' \
  > /etc/cron.d/wazuh-snapshot
```

---

## 3.6 Self-Monitoring Commands (15 min)

Add to `/var/ossec/etc/ossec.conf` to monitor the SIEM's own health:

```xml
<!-- System resources — every 2 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>top -bn1 | head -5; free -m | head -3</command>
    <alias>system_resources</alias>
    <frequency>120</frequency>
</localfile>

<!-- Analysis engine health — every 1 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>cat /var/ossec/var/run/wazuh-analysisd.state 2>/dev/null | grep -E 'events_|queue_'</command>
    <alias>analysisd_health</alias>
    <frequency>60</frequency>
</localfile>

<!-- Disk usage — every 6 min -->
<localfile>
    <log_format>command</log_format>
    <command>df -P</command>
    <frequency>360</frequency>
</localfile>

<!-- Index sizes — every 10 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>curl -sk -u admin:YOUR_PASSWORD https://localhost:9200/_cat/indices/wazuh-alerts-*?h=index,docs.count,store.size | tail -5</command>
    <alias>opensearch_index_size</alias>
    <frequency>600</frequency>
</localfile>
```

```bash
systemctl restart wazuh-manager
```

---

## 3.7 Full Validation (1 hour)

### Infrastructure Checks

```bash
echo "=== Service Status ==="
systemctl is-active wazuh-manager wazuh-indexer wazuh-dashboard filebeat

echo "=== Indexer Health ==="
curl -sk -u admin:YOUR_PASSWORD "https://localhost:9200/_cluster/health?pretty"

echo "=== Agent Summary ==="
/var/ossec/bin/agent_control -l | tail -1

echo "=== Events Processed (last hour) ==="
cat /var/ossec/var/run/wazuh-analysisd.state | grep events_

echo "=== Disk Usage ==="
df -h /var/ossec /var/lib/wazuh-indexer

echo "=== Recent Alerts ==="
curl -sk -u admin:YOUR_PASSWORD \
  "https://localhost:9200/wazuh-alerts-*/_count" | python3 -m json.tool

echo "=== ISM Policy Status ==="
curl -sk -u admin:YOUR_PASSWORD \
  "https://localhost:9200/_plugins/_ism/explain/wazuh-alerts-4.x-*" 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
for idx, info in list(data.items())[:3]:
    if isinstance(info, dict):
        print(f\"  {idx}: state={info.get('policy_id','N/A')}, step={info.get('step',{}).get('name','N/A')}\")
" 2>/dev/null || echo "  No ISM data yet"
```

### Functional Tests

```bash
# Test 1: FIM trigger
echo "test-$(date +%s)" > /etc/fim-validation-test.tmp
echo "[*] FIM test file created. Wait for next syscheck scan or use realtime dir."

# Test 2: Force a failed SSH login (generates alert)
ssh -o StrictHostKeyChecking=no invalid_user@localhost 2>/dev/null || true
echo "[*] SSH failed login generated. Check Dashboard for rule 5710."

# Test 3: Check integration logs
echo "=== Integration Logs (last 10 lines) ==="
tail -10 /var/ossec/logs/integrations.log 2>/dev/null || echo "No integration logs yet"

# Test 4: Telegram notification test (if configured)
echo "[*] Check Telegram for alert notification from the SSH test above."

# Cleanup
rm -f /etc/fim-validation-test.tmp
```

### Dashboard Validation

1. **Agents tab:** All agents show `Active` ✅
2. **Security Events:** Alerts flowing in with decoded fields ✅
3. **Integrity Monitoring:** FIM events visible ✅
4. **Vulnerability Detection:** CVEs appearing for enrolled agents ✅
5. **SCA:** Security posture scores visible per agent ✅

---

## 3.8 Quick Reference — Common Operations

### Daily SOC Tasks

```bash
# Check agent status
/var/ossec/bin/agent_control -l

# View real-time alerts
tail -f /var/ossec/logs/alerts/alerts.json | jq '.rule.description, .rule.level'

# Check for dropped events (CRITICAL if > 0)
grep events_dropped /var/ossec/var/run/wazuh-analysisd.state

# Restart after config change
/var/ossec/bin/wazuh-control restart
# OR (safer — validates config first)
systemctl restart wazuh-manager
```

### Troubleshooting

```bash
# Config syntax check
/var/ossec/bin/wazuh-control info  # Shows version
xmllint --noout /var/ossec/etc/ossec.conf  # XML validation

# Agent not connecting?
# On agent:
cat /var/ossec/etc/ossec.conf | grep address  # Check manager IP
tail -20 /var/ossec/logs/ossec.log            # Check errors

# On manager:
tail -50 /var/ossec/logs/ossec.log | grep -i "error\|agent"
```

---

## 3.9 Top 10 Pitfalls for Small Deployments

| # | Mistake | Fix |
|---|---|---|
| 1 | Using `127.0.0.1` as manager IP in `config.yml` | Use the actual LAN IP agents can reach |
| 2 | Forgetting to open port `1514/TCP` | Agents can't send events without it |
| 3 | Not setting enrollment password | Anyone on the network can enroll rogue agents |
| 4 | No ISM/retention policy | Disk fills up in weeks; SIEM crashes |
| 5 | Not backing up `client.keys` | Losing it = re-enroll every agent |
| 6 | Default admin password unchanged | Trivial unauthorized Dashboard access |
| 7 | Swap enabled on Indexer | Causes OpenSearch performance collapse |
| 8 | Editing files in `ruleset/rules/` | Overwritten on Wazuh upgrades — use `etc/rules/` |
| 9 | `log_alert_level` at default (1) | Floods indexer with noise; alert fatigue |
| 10 | No time sync (NTP) | Alert timestamps are wrong; correlation breaks |

---

## Day 3 Checklist — Go-Live Sign-Off

```
✅ VirusTotal integration active (hash lookups working)
✅ MISP integration deployed (if applicable)
✅ Telegram/Email notifications tested — alerts received
✅ ISM retention policy applied (7d hot → 90d delete)
✅ Config backup cron scheduled (daily)
✅ Self-monitoring commands added
✅ All agents Active in Dashboard
✅ FIM, SCA, Vulnerability Detection data visible
✅ Custom rules firing correctly
✅ Full validation script passed
✅ SOC team briefed on Dashboard usage
✅ SIEM IS LIVE ✅
```

---

## Post Go-Live — Week 1 Priorities

| Priority | Task |
|---|---|
| **P1** | Monitor `events_dropped` daily — if > 0, increase threads |
| **P1** | Review and tune false positives (suppress or lower level) |
| **P2** | Install Sysmon on all Windows endpoints |
| **P2** | Add firewall/network device syslog forwarding |
| **P3** | Explore MISP integration for richer threat intel |
| **P3** | Set up SOAR webhook (Shuffle/n8n) for automated response |
| **P3** | Add cloud log sources (AWS/Azure/O365) if applicable |

---

> **🎯 Your Wazuh SIEM is now operational.** Iterate on rules weekly, review alerts daily, and expand integrations as capacity allows. The full enterprise playbook in `../playbook/` provides guidance for scaling to HA clusters, SAML SSO, and advanced integrations when you're ready.
