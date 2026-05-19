# Day 5 — Tuning & Alerting (The "Zero-Tolerance" Phase)

> **Goal:** Suppress noise, elevate critical detections, configure external notifications. Make the SIEM actually useful.  
> **Estimated time:** Full day — this is the most important day.

---

## Why This Day Matters Most

Out of the box, Wazuh generates **thousands** of alerts per day. Most are level 3–5 informational noise. Without tuning:
- Your SOC team will experience **alert fatigue** within 48 hours
- **Real threats get buried** under a flood of false positives
- The SIEM becomes an expensive log collector nobody looks at

Day 5 is about implementing the **"Zero-Tolerance" policy**: critical alerts trigger instantly and reach humans, while noise is surgically suppressed.

---

## 5.1 Alert Level Strategy

| Level | Meaning | Action |
|---|---|---|
| 0 | Suppressed | Never stored, never alerted |
| 1–5 | Low / Informational | Not stored (we set `log_alert_level` to 6 on Day 1) |
| 6–7 | Moderate | Stored in indexer, visible in Dashboard |
| 8–9 | Important | Stored, visible, reviewed daily |
| 10–11 | High | Immediate SOC review required |
| 12–13 | Critical | **External notification (Slack/Teams/Email)** |
| 14–15 | Emergency | **External notification + Active Response** |

### Confirm `log_alert_level` Is Set

In `/var/ossec/etc/ossec.conf`:

```xml
<alerts>
    <log_alert_level>6</log_alert_level>
    <email_alert_level>12</email_alert_level>
</alerts>
```

---

## 5.2 Noise Suppression — Custom Rules (2 hours)

### Step 1: Identify Your Noisy Rules

```bash
# Top 20 noisiest rules in the last 24 hours
curl -sk -u admin:YOUR_PASSWORD \
  "https://localhost:9200/wazuh-alerts-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{
    "size": 0,
    "query": {"range": {"timestamp": {"gte": "now-24h"}}},
    "aggs": {
      "top_rules": {
        "terms": {"field": "rule.id", "size": 20, "order": {"_count": "desc"}}
      }
    }
  }' | python3 -m json.tool
```

### Step 2: Suppress Known-Good Activity

Add to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,noise_reduction,">

    <!-- ═══════════════════════════════════ -->
    <!--  SUPPRESS: Known infrastructure     -->
    <!-- ═══════════════════════════════════ -->

    <!-- SSH from monitoring/jump server — expected -->
    <rule id="100090" level="0">
        <if_sid>5710,5711</if_sid>
        <srcip>YOUR_MONITORING_SERVER_IP</srcip>
        <description>Suppressed: Expected SSH from monitoring server.</description>
    </rule>

    <!-- Backup service account logins — expected -->
    <rule id="100091" level="0">
        <if_sid>5501</if_sid>
        <match>svc_backup|backup_user</match>
        <description>Suppressed: Known backup service account login.</description>
    </rule>

    <!-- Scheduled task execution on Windows — expected -->
    <rule id="100092" level="0">
        <if_sid>60103</if_sid>
        <field name="win.system.eventID">4688</field>
        <field name="win.eventdata.newProcessName" type="pcre2">(?i)\\TaskScheduler\\|\\schtasks\.exe</field>
        <description>Suppressed: Expected scheduled task execution.</description>
    </rule>

    <!-- Scanner/vulnerability assessment tool — expected -->
    <rule id="100093" level="0">
        <if_sid>5710,5711</if_sid>
        <srcip>YOUR_VULN_SCANNER_IP</srcip>
        <description>Suppressed: Expected vulnerability scanner connection.</description>
    </rule>

    <!-- Windows Update service — expected file changes -->
    <rule id="100094" level="0">
        <if_sid>550,554</if_sid>
        <match>Windows\\SoftwareDistribution|Windows\\WinSxS</match>
        <description>Suppressed: Windows Update file modifications.</description>
    </rule>

    <!-- Package manager updates on Linux — expected -->
    <rule id="100095" level="0">
        <if_sid>550,554</if_sid>
        <match>/var/cache/apt|/var/lib/dpkg</match>
        <description>Suppressed: Package manager file modifications.</description>
    </rule>

</group>
```

> [!IMPORTANT]
> **Replace `YOUR_MONITORING_SERVER_IP` and `YOUR_VULN_SCANNER_IP`** with actual IPs. Leaving placeholders means these rules won't match anything and noise continues.

---

## 5.3 Elevate Critical Detections (1 hour)

These rules ensure zero-tolerance events are elevated to Level 12+ for notification:

Add to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="local,critical_detections,">

    <!-- ═══════════════════════════════════ -->
    <!--  LINUX CRITICAL                     -->
    <!-- ═══════════════════════════════════ -->

    <!-- Sudoers file modified — privilege escalation -->
    <rule id="100001" level="12">
        <if_sid>550</if_sid>
        <match>visudo|/etc/sudoers</match>
        <description>Sudoers file modified — potential privilege escalation.</description>
        <mitre><id>T1548.003</id></mitre>
        <group>privilege_escalation,</group>
    </rule>

    <!-- SSH authorized_keys modified — backdoor -->
    <rule id="100003" level="12">
        <if_sid>550,554</if_sid>
        <match>authorized_keys</match>
        <description>SSH authorized_keys modified — potential backdoor.</description>
        <mitre><id>T1098.004</id></mitre>
        <group>persistence,</group>
    </rule>

    <!-- Crontab modified — persistence mechanism -->
    <rule id="100002" level="10">
        <if_sid>550</if_sid>
        <regex>/var/spool/cron|/etc/cron</regex>
        <description>Crontab modified — persistence mechanism.</description>
        <mitre><id>T1053.003</id></mitre>
        <group>persistence,</group>
    </rule>

    <!-- ═══════════════════════════════════ -->
    <!--  WINDOWS CRITICAL                   -->
    <!-- ═══════════════════════════════════ -->

    <!-- PowerShell encoded command — obfuscation -->
    <rule id="100200" level="12">
        <if_sid>91801</if_sid>
        <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)-[Ee]nc[oded]*[Cc]ommand|FromBase64String|IEX\s*\(</field>
        <description>PowerShell: Encoded/obfuscated command execution.</description>
        <mitre><id>T1059.001</id><id>T1027</id></mitre>
        <group>execution,attack,</group>
    </rule>

    <!-- Mimikatz / LSASS credential dumping -->
    <rule id="100201" level="14">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.targetFilename" type="pcre2">(?i)mimikatz|lsass\.dmp|procdump.*lsass</field>
        <description>CRITICAL: Credential dumping tool detected.</description>
        <mitre><id>T1003.001</id></mitre>
        <group>credential_access,attack,</group>
    </rule>

    <!-- Windows audit log cleared — anti-forensics -->
    <rule id="100202" level="14">
        <if_sid>60103</if_sid>
        <field name="win.system.eventID">1102</field>
        <description>CRITICAL: Windows Security audit log was cleared.</description>
        <mitre><id>T1070.001</id></mitre>
        <group>defense_evasion,attack,</group>
    </rule>

    <!-- ═══════════════════════════════════ -->
    <!--  SIEM SELF-HEALTH                   -->
    <!-- ═══════════════════════════════════ -->

    <!-- Disk usage > 85% -->
    <rule id="100050" level="12">
        <if_sid>531</if_sid>
        <regex>8[5-9]%|9[0-9]%|100%</regex>
        <description>SIEM HEALTH: Disk usage critical (>85%).</description>
        <group>siem_health,</group>
    </rule>

    <!-- Agent disconnected -->
    <rule id="100051" level="10">
        <if_sid>505</if_sid>
        <description>Agent disconnected — investigate immediately.</description>
        <group>siem_health,agent_status,</group>
    </rule>

</group>
```

---

## 5.4 External Notifications — Slack/Teams/Telegram (2 hours)

### Option A: Microsoft Teams Webhook

```bash
cat > /var/ossec/integrations/custom-teams.sh << 'SCRIPT'
#!/bin/bash
ALERT_FILE="$1"
WEBHOOK_URL="$3"   # Passed via hook_url in ossec.conf

RULE_ID=$(jq -r '.rule.id' "$ALERT_FILE")
LEVEL=$(jq -r '.rule.level' "$ALERT_FILE")
DESC=$(jq -r '.rule.description' "$ALERT_FILE")
AGENT=$(jq -r '.agent.name // "Manager"' "$ALERT_FILE")
SRCIP=$(jq -r '.data.srcip // .srcip // "N/A"' "$ALERT_FILE")
TIMESTAMP=$(jq -r '.timestamp' "$ALERT_FILE")

if [ "$LEVEL" -ge 14 ]; then COLOR="FF0000"
elif [ "$LEVEL" -ge 12 ]; then COLOR="FF8C00"
elif [ "$LEVEL" -ge 10 ]; then COLOR="FFD700"
else COLOR="4169E1"; fi

PAYLOAD=$(cat << EOF
{
    "@type": "MessageCard",
    "@context": "http://schema.org/extensions",
    "themeColor": "$COLOR",
    "summary": "Wazuh Alert — Level $LEVEL",
    "sections": [{
        "activityTitle": "🛡️ Wazuh SIEM Alert — Level $LEVEL",
        "facts": [
            {"name": "Rule", "value": "$RULE_ID"},
            {"name": "Description", "value": "$DESC"},
            {"name": "Agent", "value": "$AGENT"},
            {"name": "Source IP", "value": "$SRCIP"},
            {"name": "Timestamp", "value": "$TIMESTAMP"}
        ],
        "markdown": true
    }]
}
EOF
)

curl -s -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD" >> /var/ossec/logs/teams.log 2>&1
SCRIPT

chmod 750 /var/ossec/integrations/custom-teams.sh
chown root:wazuh /var/ossec/integrations/custom-teams.sh
```

```xml
<!-- Add to ossec.conf -->
<integration>
    <name>custom-teams.sh</name>
    <hook_url>https://outlook.office.com/webhook/YOUR_WEBHOOK_URL</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
</integration>
```

### Option B: Slack Webhook

```bash
cat > /var/ossec/integrations/custom-slack.sh << 'SCRIPT'
#!/bin/bash
ALERT_FILE="$1"
WEBHOOK_URL="$3"

RULE_ID=$(jq -r '.rule.id' "$ALERT_FILE")
LEVEL=$(jq -r '.rule.level' "$ALERT_FILE")
DESC=$(jq -r '.rule.description' "$ALERT_FILE")
AGENT=$(jq -r '.agent.name // "Manager"' "$ALERT_FILE")
SRCIP=$(jq -r '.data.srcip // .srcip // "N/A"' "$ALERT_FILE")
TIMESTAMP=$(jq -r '.timestamp' "$ALERT_FILE")

if [ "$LEVEL" -ge 14 ]; then EMOJI=":red_circle:"
elif [ "$LEVEL" -ge 12 ]; then EMOJI=":large_orange_circle:"
elif [ "$LEVEL" -ge 10 ]; then EMOJI=":large_yellow_circle:"
else EMOJI=":large_blue_circle:"; fi

PAYLOAD=$(cat << EOF
{
    "text": "$EMOJI *WAZUH ALERT* (Level $LEVEL)\n*Rule:* $RULE_ID\n*Description:* $DESC\n*Agent:* $AGENT\n*Source IP:* $SRCIP\n*Time:* $TIMESTAMP"
}
EOF
)

curl -s -X POST "$WEBHOOK_URL" \
    -H 'Content-Type: application/json' \
    -d "$PAYLOAD" >> /var/ossec/logs/slack.log 2>&1
SCRIPT

chmod 750 /var/ossec/integrations/custom-slack.sh
chown root:wazuh /var/ossec/integrations/custom-slack.sh
```

```xml
<!-- Add to ossec.conf -->
<integration>
    <name>custom-slack.sh</name>
    <hook_url>https://hooks.slack.com/services/YOUR/WEBHOOK/URL</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
</integration>
```

### Option C: Telegram Bot

```bash
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

### Option D: Email (Built-in)

```xml
<!-- In ossec.conf -->
<global>
    <email_notification>yes</email_notification>
    <smtp_server>smtp.company.com</smtp_server>
    <email_from>wazuh@company.com</email_from>
    <email_to>soc-team@company.com</email_to>
    <email_maxperhour>24</email_maxperhour>
</global>

<!-- Granular: CISO gets Level 14+ only -->
<email_alerts>
    <email_to>ciso@company.com</email_to>
    <level>14</level>
    <group>malware|credential_access|threat_intel</group>
</email_alerts>
```

> **⚠️ PITFALL — Webhook flood:**  
> If you set `<level>10</level>` on notifications, you may get flooded during the first few days. Start with `<level>12</level>` and lower it after you've suppressed the noise.

---

## 5.5 Self-Monitoring Commands (15 min)

Add to `ossec.conf` to monitor the SIEM's own health:

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

<!-- Index sizes — every 10 min -->
<localfile>
    <log_format>full_command</log_format>
    <command>curl -sk -u admin:YOUR_PASSWORD https://localhost:9200/_cat/indices/wazuh-alerts-*?h=index,docs.count,store.size | tail -5</command>
    <alias>opensearch_index_size</alias>
    <frequency>600</frequency>
</localfile>
```

---

## 5.6 Automated Backups (15 min)

```bash
cat > /usr/local/bin/wazuh-backup.sh << 'SCRIPT'
#!/bin/bash
set -euo pipefail
BACKUP_DIR="/opt/wazuh-backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

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

find /opt/wazuh-backups/ -maxdepth 1 -type d -mtime +30 -exec rm -rf {} +
echo "[OK] Backup: $BACKUP_DIR — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
SCRIPT

chmod 700 /usr/local/bin/wazuh-backup.sh
echo '0 3 * * * root /usr/local/bin/wazuh-backup.sh >> /var/log/wazuh-backup.log 2>&1' \
  > /etc/cron.d/wazuh-backup
```

---

## 5.7 Final Validation (1 hour)

### Infrastructure Health Check

```bash
echo "=== Service Status ==="
for svc in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
    echo "  $svc: $(systemctl is-active $svc)"
done

echo "=== Indexer Health ==="
curl -sk -u admin:YOUR_PASSWORD "https://localhost:9200/_cluster/health?pretty"

echo "=== Agent Summary ==="
echo "  Active:       $(/var/ossec/bin/agent_control -l | grep -c 'Active')"
echo "  Disconnected: $(/var/ossec/bin/agent_control -l | grep -c 'Disconnected')"

echo "=== Events Processed ==="
cat /var/ossec/var/run/wazuh-analysisd.state | grep events_

echo "=== Disk Usage ==="
df -h /var/ossec /var/lib/wazuh-indexer

echo "=== Total Alerts ==="
curl -sk -u admin:YOUR_PASSWORD "https://localhost:9200/wazuh-alerts-*/_count" | python3 -m json.tool
```

### Functional Tests

```bash
# Test 1: Generate a failed SSH login (should trigger rule 5710)
ssh -o StrictHostKeyChecking=no invalid_user@localhost 2>/dev/null || true

# Test 2: FIM trigger
echo "test-$(date +%s)" > /etc/fim-validation-test.tmp

# Test 3: Check integration logs
echo "=== Integration Logs ==="
tail -10 /var/ossec/logs/integrations.log 2>/dev/null || echo "No logs yet"

# Test 4: Verify notification received
echo "[*] Check your Slack/Teams/Telegram for the alert from Test 1"

# Cleanup
rm -f /etc/fim-validation-test.tmp
```

### Dashboard Validation

1. **Agents** → All agents `Active` ✅
2. **Security Events** → Alerts with decoded fields ✅
3. **Integrity Monitoring** → FIM events visible ✅
4. **Vulnerability Detection** → CVEs appearing ✅
5. **SCA** → Security posture scores ✅
6. **MITRE ATT&CK** → Mapped techniques visible ✅

---

## 5.8 Daily SOC Operations — Quick Reference

```bash
# View real-time alerts
tail -f /var/ossec/logs/alerts/alerts.json | jq '.rule.description, .rule.level'

# Check for dropped events (CRITICAL if > 0)
grep events_dropped /var/ossec/var/run/wazuh-analysisd.state

# Check agent status
/var/ossec/bin/agent_control -l

# Test rules against sample logs
/var/ossec/bin/wazuh-logtest

# Restart after config change (validates first)
systemctl restart wazuh-manager

# XML validation before restart
xmllint --noout /var/ossec/etc/ossec.conf
```

---

## Day 5 Checklist — Go-Live Sign-Off

```
✅ Top noisy rules identified and suppressed (level 0)
✅ Critical detection rules deployed (Level 12+)
✅ External notifications configured (Slack/Teams/Telegram/Email)
✅ Test notification received successfully
✅ Self-monitoring commands active
✅ Daily backup cron scheduled
✅ events_dropped = 0
✅ All agents Active
✅ FIM, SCA, VulnDet, MISP all generating data
✅ No errors in /var/ossec/logs/ossec.log
✅ SOC team briefed on Dashboard + notification channels

🎯 YOUR WAZUH SIEM IS NOW OPERATIONAL.
```

---

## Post-Deployment — Week 2+ Priorities

| Priority | Task |
|---|---|
| **P1** | Monitor `events_dropped` daily — increase threads if > 0 |
| **P1** | Review + tune false positives every 2 days for the first 2 weeks |
| **P2** | Install Sysmon on all Windows endpoints for deep process visibility |
| **P2** | Add cloud log sources (O365, Azure AD) if applicable |
| **P3** | Explore SOAR integration (Shuffle/n8n) for automated response |
| **P3** | Schedule monthly CDB list review and MISP feed audit |
| **P3** | Plan upgrade path to distributed architecture if agent count grows |
