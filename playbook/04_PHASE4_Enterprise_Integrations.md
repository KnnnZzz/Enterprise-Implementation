# Phase 4 — Enterprise Integrations (SIEM Enhancement)

---

## 4.1 Threat Intelligence Integration

### 4.1.1 MISP Integration (Real-Time API Lookup)

Your existing `custom-misp_file_hashes.py` integration provides real-time IoC enrichment. Below is the production-hardened `ossec.conf` configuration:

```xml
<!-- Manager ossec.conf — MISP Integration -->
<integration>
    <name>custom-misp_file_hashes.py</name>
    <hook_url>https://misp.corp.local</hook_url>
    <!-- API key loaded securely from /var/ossec/etc/misp.secret at runtime -->
    <api_key>LOADED_FROM_SECURE_FILE</api_key>
    <level>5</level>
    <alert_format>json</alert_format>
    <options>
    {
        "timeout": 10,
        "retries": 3,
        "debug": false,
        "tags": ["tlp:white", "tlp:clear", "malware"],
        "push_sightings": true,
        "sightings_source": "wazuh-soc",
        "ca_cert": "/var/ossec/etc/misp-cert.pem",
        "skip_private_ips": true,
        "whitelist": [
            "127.0.0.1", "0.0.0.0",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\explorer.exe"
        ]
    }
    </options>
</integration>
```

#### MISP Rules for Alert Correlation

```xml
<!-- /var/ossec/etc/rules/misp_rules.xml -->
<group name="misp,threat_intel,">

    <!-- Base: MISP integration returned data -->
    <rule id="100800" level="0">
        <decoded_as>json</decoded_as>
        <field name="integration">misp_file_hashes</field>
        <description>MISP integration event received.</description>
    </rule>

    <!-- No match found in MISP (informational) -->
    <rule id="100801" level="3">
        <if_sid>100800</if_sid>
        <field name="misp_file_hashes.found">0</field>
        <description>MISP: IoC lookup completed — No threat intelligence match.</description>
    </rule>

    <!-- MATCH FOUND — High-priority alert -->
    <rule id="100802" level="13">
        <if_sid>100800</if_sid>
        <field name="misp_file_hashes.found">1</field>
        <description>MISP THREAT INTEL HIT: IoC $(misp_file_hashes.type)=$(misp_file_hashes.value) matched in event $(misp_file_hashes.event_id). Category: $(misp_file_hashes.category).</description>
        <group>threat_intel,attack,</group>
        <mitre>
            <id>T1566</id>
        </mitre>
    </rule>

    <!-- IP-specific match for Active Response -->
    <rule id="100803" level="14">
        <if_sid>100802</if_sid>
        <field name="misp_file_hashes.source.ioc_type">ip</field>
        <description>MISP: Malicious IP detected — $(misp_file_hashes.value). Triggering Active Response.</description>
        <group>threat_intel,active_response,</group>
    </rule>

    <!-- Hash match from FIM -->
    <rule id="100804" level="14">
        <if_sid>100802</if_sid>
        <field name="misp_file_hashes.source.ioc_type">hash</field>
        <description>MISP: Known malware hash detected via FIM — $(misp_file_hashes.value).</description>
        <group>threat_intel,malware,</group>
        <mitre>
            <id>T1204</id>
        </mitre>
    </rule>

</group>
```

### 4.1.2 MISP CDB List Synchronization (Batch Enrichment)

The `misp-cdb-sync.py` script provides batch IoC synchronization for CDB list-based rule matching:

```bash
# Cron schedule — every 4 hours
0 */4 * * * root /var/ossec/framework/python/bin/python3 \
    /var/ossec/integrations/misp-cdb-sync.py \
    >> /var/ossec/logs/misp-cdb-sync.log 2>&1
```

### 4.1.3 VirusTotal Integration

```xml
<!-- Manager ossec.conf — VirusTotal -->
<integration>
    <name>virustotal</name>
    <api_key>YOUR_VT_API_KEY</api_key>
    <group>syscheck</group>
    <alert_format>json</alert_format>
</integration>
```

```xml
<!-- /var/ossec/etc/rules/virustotal_rules.xml -->
<group name="virustotal,threat_intel,">
    <rule id="100510" level="0">
        <decoded_as>json</decoded_as>
        <field name="integration">virustotal</field>
        <description>VirusTotal integration event.</description>
    </rule>

    <rule id="100511" level="3">
        <if_sid>100510</if_sid>
        <field name="virustotal.found">0</field>
        <description>VirusTotal: No match for file hash.</description>
    </rule>

    <rule id="100512" level="5">
        <if_sid>100510</if_sid>
        <field name="virustotal.found">1</field>
        <field name="virustotal.malicious">0</field>
        <description>VirusTotal: File hash found — No vendors flagged as malicious.</description>
    </rule>

    <!-- 1+ vendor flagged malicious -->
    <rule id="100513" level="10">
        <if_sid>100510</if_sid>
        <field name="virustotal.found">1</field>
        <field name="virustotal.malicious" type="pcre2">^[1-9]</field>
        <description>VirusTotal: Potentially malicious file detected — $(virustotal.malicious) vendors flagged.</description>
        <group>malware,</group>
    </rule>

    <!-- 5+ vendors = High confidence malware -->
    <rule id="100514" level="13">
        <if_sid>100510</if_sid>
        <field name="virustotal.found">1</field>
        <field name="virustotal.positives" type="pcre2">^([5-9]|[1-9][0-9])</field>
        <description>VirusTotal ALERT: HIGH-CONFIDENCE malware — $(virustotal.positives) detections.</description>
        <group>malware,threat_intel,</group>
        <mitre>
            <id>T1204.002</id>
        </mitre>
    </rule>
</group>
```

> **⚠️ PITFALL — VirusTotal API Rate Limits:**  
> Free VT API keys are limited to 4 requests/minute and 500/day. Enterprise keys are required for high-volume environments. Without rate limiting, Wazuh will exhaust the quota rapidly from FIM events alone. Use the `<group>syscheck</group>` filter and keep `log_alert_level` ≥ 6 to reduce unnecessary lookups.

---

## 4.2 Incident Response & Ticketing

### 4.2.1 TheHive Integration

```bash
#!/bin/bash
# /var/ossec/integrations/custom-thehive.sh
# Wazuh → TheHive case creation via webhook

ALERT_FILE="$1"
API_KEY="$2"
HOOK_URL="$3"

ALERT_LEVEL=$(jq -r '.rule.level' "$ALERT_FILE")
ALERT_DESC=$(jq -r '.rule.description' "$ALERT_FILE")
AGENT_NAME=$(jq -r '.agent.name // "N/A"' "$ALERT_FILE")
AGENT_IP=$(jq -r '.agent.ip // "N/A"' "$ALERT_FILE")
RULE_ID=$(jq -r '.rule.id' "$ALERT_FILE")
TIMESTAMP=$(jq -r '.timestamp' "$ALERT_FILE")
MITRE_ID=$(jq -r '.rule.mitre.id[0] // "N/A"' "$ALERT_FILE")
SRCIP=$(jq -r '.data.srcip // .srcip // "N/A"' "$ALERT_FILE")

# Map Wazuh level → TheHive severity (1=Low, 2=Medium, 3=High, 4=Critical)
if [ "$ALERT_LEVEL" -ge 14 ]; then SEVERITY=4
elif [ "$ALERT_LEVEL" -ge 12 ]; then SEVERITY=3
elif [ "$ALERT_LEVEL" -ge 8 ]; then SEVERITY=2
else SEVERITY=1; fi

# Create TheHive Alert
PAYLOAD=$(cat << EOF
{
    "title": "[Wazuh] Rule $RULE_ID: $ALERT_DESC",
    "description": "**Agent:** $AGENT_NAME ($AGENT_IP)\n**Source IP:** $SRCIP\n**MITRE:** $MITRE_ID\n**Timestamp:** $TIMESTAMP\n\n**Full Alert:**\n\`\`\`json\n$(jq '.' "$ALERT_FILE")\n\`\`\`",
    "severity": $SEVERITY,
    "type": "wazuh-alert",
    "source": "Wazuh SIEM",
    "sourceRef": "wazuh-$RULE_ID-$(date +%s)",
    "tags": ["wazuh", "rule:$RULE_ID", "mitre:$MITRE_ID"],
    "tlp": 2,
    "pap": 2
}
EOF
)

curl -s -X POST "$HOOK_URL/api/alert" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    >> /var/ossec/logs/thehive-integration.log 2>&1
```

```xml
<!-- Manager ossec.conf — TheHive Integration -->
<integration>
    <name>custom-thehive.sh</name>
    <hook_url>https://thehive.corp.local:9000</hook_url>
    <api_key>THE_HIVE_API_KEY</api_key>
    <level>12</level>
    <alert_format>json</alert_format>
</integration>
```

### 4.2.2 Jira Service Management

```python
#!/var/ossec/framework/python/bin/python3
# /var/ossec/integrations/custom-jira.py
import json, sys, requests

ALERT_FILE = sys.argv[1]
API_KEY = sys.argv[2]
HOOK_URL = sys.argv[3]

with open(ALERT_FILE) as f:
    alert = json.load(f)

level = alert.get("rule", {}).get("level", 0)
priority_map = {range(12, 14): "High", range(14, 16): "Highest"}
priority = "Medium"
for r, p in priority_map.items():
    if level in r:
        priority = p
        break

payload = {
    "fields": {
        "project": {"key": "SOC"},
        "summary": f"[Wazuh-{alert['rule']['id']}] {alert['rule']['description']}",
        "description": json.dumps(alert, indent=2),
        "issuetype": {"name": "Incident"},
        "priority": {"name": priority},
        "labels": ["wazuh", "automated", f"level-{level}"]
    }
}

response = requests.post(
    f"{HOOK_URL}/rest/api/2/issue",
    auth=("svc_wazuh@corp.local", API_KEY),
    json=payload,
    verify="/var/ossec/etc/jira-cert.pem",
    timeout=15
)

with open("/var/ossec/logs/jira-integration.log", "a") as log:
    log.write(f"Jira response: {response.status_code} - {response.text[:200]}\n")
```

---

## 4.3 SOAR Automation

### 4.3.1 Shuffle SOAR — Webhook Integration

```xml
<!-- Manager ossec.conf — Shuffle Webhook -->
<integration>
    <name>custom-shuffle.sh</name>
    <hook_url>https://shuffle.corp.local:3001/api/v1/hooks/WEBHOOK_ID</hook_url>
    <level>10</level>
    <alert_format>json</alert_format>
    <group>threat_intel,malware,attack</group>
</integration>
```

```bash
#!/bin/bash
# /var/ossec/integrations/custom-shuffle.sh
ALERT_FILE="$1"
HOOK_URL="$3"

curl -s -X POST "$HOOK_URL" \
    -H "Content-Type: application/json" \
    -d @"$ALERT_FILE" \
    >> /var/ossec/logs/shuffle-integration.log 2>&1
```

### 4.3.2 n8n Webhook Integration

```xml
<integration>
    <name>custom-n8n.sh</name>
    <hook_url>https://n8n.corp.local/webhook/wazuh-alerts</hook_url>
    <level>12</level>
    <alert_format>json</alert_format>
</integration>
```

### 4.3.3 Active Response — Automated IP Blocking

```xml
<!-- Manager ossec.conf — Active Response for Threat Intel Hits -->
<active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <!-- Trigger on: MISP IP match, brute-force, etc. -->
    <rules_id>100803,100402</rules_id>
    <timeout>3600</timeout>  <!-- 1 hour block -->
</active-response>
```

> **⚠️ PITFALL — Active Response on Production:**  
> Never enable `firewall-drop` active response with `<location>all</location>` unless you have a thoroughly tested whitelist. A false positive from a MISP IoC could block a legitimate business partner IP across your entire fleet. Always start with `<location>local</location>` (manager only) and `<timeout>` set.

---

## 4.4 Cloud & Infrastructure Integration

### 4.4.1 AWS CloudTrail

```xml
<!-- Manager ossec.conf — AWS CloudTrail -->
<wodle name="aws-s3">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>

    <bucket type="cloudtrail">
        <name>my-cloudtrail-bucket</name>
        <access_key>AWS_ACCESS_KEY_ID</access_key>
        <secret_key>AWS_SECRET_ACCESS_KEY</secret_key>
        <regions>eu-west-1,us-east-1</regions>
        <path>AWSLogs/</path>
        <only_logs_after>2026-01-01</only_logs_after>
    </bucket>

    <!-- AWS GuardDuty -->
    <bucket type="guardduty">
        <name>my-guardduty-bucket</name>
        <access_key>AWS_ACCESS_KEY_ID</access_key>
        <secret_key>AWS_SECRET_ACCESS_KEY</secret_key>
        <regions>eu-west-1</regions>
    </bucket>

    <!-- VPC Flow Logs -->
    <bucket type="vpcflow">
        <name>my-vpcflow-bucket</name>
        <access_key>AWS_ACCESS_KEY_ID</access_key>
        <secret_key>AWS_SECRET_ACCESS_KEY</secret_key>
        <regions>eu-west-1</regions>
    </bucket>
</wodle>
```

> **Best Practice:** Use IAM Roles (instance profiles) instead of access keys when Wazuh runs on EC2. Set `<access_key>` and `<secret_key>` to empty and attach a role with S3 read permissions.

### 4.4.2 Azure AD / Microsoft Graph API

```xml
<!-- Manager ossec.conf — Azure Logs -->
<wodle name="azure-logs">
    <disabled>no</disabled>
    <interval>5m</interval>
    <run_on_start>yes</run_on_start>

    <!-- Azure Log Analytics -->
    <log_analytics>
        <application_id>APP_CLIENT_ID</application_id>
        <application_key>APP_CLIENT_SECRET</application_key>
        <tenantdomain>contoso.onmicrosoft.com</tenantdomain>
        <request>
            <tag>azure-activity</tag>
            <query>AuditLogs | where TimeGenerated > ago(5m)</query>
            <workspace>WORKSPACE_ID</workspace>
            <time_offset>5m</time_offset>
        </request>
        <request>
            <tag>azure-signin</tag>
            <query>SigninLogs | where TimeGenerated > ago(5m)</query>
            <workspace>WORKSPACE_ID</workspace>
            <time_offset>5m</time_offset>
        </request>
    </log_analytics>

    <!-- Azure Active Directory Graph -->
    <graph>
        <application_id>APP_CLIENT_ID</application_id>
        <application_key>APP_CLIENT_SECRET</application_key>
        <tenantdomain>contoso.onmicrosoft.com</tenantdomain>
        <request>
            <tag>azure-ad-audit</tag>
            <query>auditLogs/directoryAudits</query>
            <time_offset>5m</time_offset>
        </request>
    </graph>
</wodle>
```

### 4.4.3 Office 365 Audit Logs

```xml
<!-- Manager ossec.conf — O365 -->
<localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/o365/audit.json</location>
    <label key="source">office365</label>
</localfile>
```

Use the Wazuh O365 module or a custom script with the Office 365 Management Activity API:

```bash
# /etc/cron.d/wazuh-o365
*/5 * * * * root /var/ossec/framework/python/bin/python3 \
    /var/ossec/integrations/o365-collector.py \
    >> /var/ossec/logs/o365-collector.log 2>&1
```

### 4.4.4 Firewall Log Integration (Fortinet / Palo Alto)

#### Fortinet FortiGate — Syslog to Wazuh

```xml
<!-- Manager ossec.conf — FortiGate syslog receiver -->
<remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>tcp</protocol>
    <allowed-ips>10.0.1.1</allowed-ips>  <!-- FortiGate management IP -->
</remote>
```

On FortiGate:
```
config log syslogd setting
    set status enable
    set server "WAZUH_MANAGER_IP"
    set port 514
    set reliable enable
    set facility local7
    set format default
end
```

#### Palo Alto Networks — Syslog

```xml
<!-- Manager ossec.conf — Palo Alto syslog -->
<remote>
    <connection>syslog</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <allowed-ips>10.0.1.2</allowed-ips>  <!-- PAN management IP -->
</remote>
```

Custom decoder for Palo Alto:

```xml
<!-- /var/ossec/etc/decoders/paloalto_decoder.xml -->
<decoder name="paloalto-traffic">
    <prematch>^TRAFFIC,</prematch>
</decoder>

<decoder name="paloalto-traffic-fields">
    <parent>paloalto-traffic</parent>
    <regex offset="after_prematch">(\S+),(\S+),\S+,\S+,\S+,\S+,(\S+),(\S+),(\S+),(\S+)</regex>
    <order>extra_data,action,srcip,dstip,srcport,dstport</order>
</decoder>

<decoder name="paloalto-threat">
    <prematch>^THREAT,</prematch>
</decoder>

<decoder name="paloalto-threat-fields">
    <parent>paloalto-threat</parent>
    <regex offset="after_prematch">(\S+),(\S+),\S+,\S+,\S+,\S+,(\S+),(\S+),\S+,\S+,\S+,\S+,\S+,\S+,(\S+)</regex>
    <order>extra_data,action,srcip,dstip,status</order>
</decoder>
```

---

## 4.5 Telegram / Slack Notification Integration

### Telegram Bot Notifications (Critical Alerts)

```bash
#!/bin/bash
# /var/ossec/integrations/custom-telegram.sh

ALERT_FILE="$1"
API_KEY="$2"      # Telegram Bot Token
HOOK_URL="$3"     # Not used for Telegram, but required by Wazuh

CHAT_ID="YOUR_CHAT_ID"

RULE_ID=$(jq -r '.rule.id' "$ALERT_FILE")
LEVEL=$(jq -r '.rule.level' "$ALERT_FILE")
DESC=$(jq -r '.rule.description' "$ALERT_FILE")
AGENT=$(jq -r '.agent.name // "Manager"' "$ALERT_FILE")
SRCIP=$(jq -r '.data.srcip // .srcip // "N/A"' "$ALERT_FILE")
TIMESTAMP=$(jq -r '.timestamp' "$ALERT_FILE")

# Emoji based on severity
if [ "$LEVEL" -ge 14 ]; then EMOJI="🔴"
elif [ "$LEVEL" -ge 12 ]; then EMOJI="🟠"
elif [ "$LEVEL" -ge 10 ]; then EMOJI="🟡"
else EMOJI="🔵"; fi

MESSAGE="$EMOJI *WAZUH ALERT* (Level $LEVEL)
━━━━━━━━━━━━━━━━━━
*Rule:* $RULE_ID
*Description:* $DESC
*Agent:* $AGENT
*Source IP:* $SRCIP
*Time:* $TIMESTAMP
━━━━━━━━━━━━━━━━━━"

curl -s -X POST "https://api.telegram.org/bot${API_KEY}/sendMessage" \
    -d "chat_id=$CHAT_ID" \
    -d "text=$MESSAGE" \
    -d "parse_mode=Markdown" \
    >> /var/ossec/logs/telegram-integration.log 2>&1
```

```xml
<!-- Manager ossec.conf — Telegram -->
<integration>
    <name>custom-telegram.sh</name>
    <hook_url>https://api.telegram.org</hook_url>
    <api_key>BOT_TOKEN_HERE</api_key>
    <level>12</level>
    <alert_format>json</alert_format>
</integration>
```
