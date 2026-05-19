# Phase 3 — Customization, Tuning & SOC Operations

---

## 3.1 Custom Decoders

Decoders extract structured fields from raw log lines. Place custom decoders in `/var/ossec/etc/decoders/`.

### Decoder Architecture Principles

1. **Parent decoder** matches the log source (program name or format).
2. **Child decoders** (with `<parent>`) extract specific fields using `<prematch>`, `<regex>`, and `<order>`.
3. **Never modify** files in `/var/ossec/ruleset/decoders/` — always use `/var/ossec/etc/decoders/`.

### Example: Custom Application Log Decoder

```xml
<!-- /var/ossec/etc/decoders/custom_app_decoder.xml -->
<decoder name="custom-webapp">
    <program_name>^webapp</program_name>
</decoder>

<decoder name="custom-webapp-auth">
    <parent>custom-webapp</parent>
    <prematch>AUTH_FAILURE</prematch>
    <regex>AUTH_FAILURE user=(\S+) srcip=(\S+) reason="(\.+)"</regex>
    <order>user, srcip, extra_data</order>
</decoder>

<decoder name="custom-webapp-sqli">
    <parent>custom-webapp</parent>
    <prematch>SQL_INJECTION_DETECTED</prematch>
    <regex>SQL_INJECTION_DETECTED uri="(\.+)" srcip=(\S+) payload="(\.+)"</regex>
    <order>url, srcip, extra_data</order>
</decoder>
```

### Testing Decoders

```bash
# Use wazuh-logtest to validate decoder matches
/var/ossec/bin/wazuh-logtest

# Paste a sample log line:
# Type one log per line
# Feb 15 10:30:45 webserver webapp: AUTH_FAILURE user=admin srcip=10.0.1.55 reason="bad password"
```

---

## 3.2 Custom Rules

Rules generate alerts from decoded events. Place in `/var/ossec/etc/rules/`.

### Rule ID Allocation Strategy

| Range | Owner |
|---|---|
| 100000–100099 | Infrastructure & Generic Custom |
| 100100–100199 | Network Devices (MikroTik, OPNsense) |
| 100200–100299 | Windows Advanced Detection |
| 100300–100399 | Cloud (AWS, Azure, O365) |
| 100400–100499 | Application-Specific |
| 100500–100599 | Threat Intelligence (MISP, VT) |
| 100600–100699 | Active Response & Automation |
| 100700–100799 | Compliance (PCI, ISO, HIPAA) |
| 100800–100899 | MISP Integration Alerts |

### Example: Custom Detection Rules

```xml
<!-- /var/ossec/etc/rules/custom_detection_rules.xml -->
<group name="custom,attack,">

    <!-- Brute-force on custom webapp -->
    <rule id="100401" level="5">
        <decoded_as>custom-webapp-auth</decoded_as>
        <description>Custom WebApp: Authentication failure.</description>
        <group>authentication_failed,</group>
        <mitre>
            <id>T1110</id>
        </mitre>
    </rule>

    <rule id="100402" level="10" frequency="5" timeframe="120">
        <if_matched_sid>100401</if_matched_sid>
        <same_source_ip />
        <description>Custom WebApp: Brute-force attack detected (5+ failures in 2 min).</description>
        <group>authentication_failures,attack,</group>
        <mitre>
            <id>T1110.001</id>
        </mitre>
    </rule>

    <!-- SQL Injection detected -->
    <rule id="100403" level="12">
        <decoded_as>custom-webapp-sqli</decoded_as>
        <description>Custom WebApp: SQL Injection attempt detected.</description>
        <group>attack,sql_injection,web,</group>
        <mitre>
            <id>T1190</id>
        </mitre>
    </rule>

    <!-- Privilege escalation: User added to sudoers -->
    <rule id="100001" level="12">
        <if_sid>550</if_sid>
        <match>visudo|/etc/sudoers</match>
        <description>Sudoers file modification detected — potential privilege escalation.</description>
        <group>syscheck,privilege_escalation,</group>
        <mitre>
            <id>T1548.003</id>
        </mitre>
    </rule>

    <!-- Suspicious crontab modification -->
    <rule id="100002" level="10">
        <if_sid>550</if_sid>
        <regex>/var/spool/cron|/etc/cron</regex>
        <description>Crontab or cron directory modified — persistence mechanism.</description>
        <group>syscheck,persistence,</group>
        <mitre>
            <id>T1053.003</id>
        </mitre>
    </rule>

    <!-- Windows: Mimikatz / credential dumping indicators -->
    <rule id="100201" level="14">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.targetFilename" type="pcre2">(?i)mimikatz|lsass\.dmp|procdump.*lsass</field>
        <description>CRITICAL: Potential credential dumping tool detected (Sysmon File Create).</description>
        <group>credential_access,attack,</group>
        <mitre>
            <id>T1003.001</id>
        </mitre>
    </rule>

    <!-- Windows: PowerShell encoded command execution -->
    <rule id="100202" level="12">
        <if_sid>91801</if_sid>
        <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)-[Ee]nc[oded]*[Cc]ommand|FromBase64String|IEX\s*\(</field>
        <description>PowerShell: Encoded/obfuscated command execution detected.</description>
        <group>execution,attack,</group>
        <mitre>
            <id>T1059.001</id>
            <id>T1027</id>
        </mitre>
    </rule>

</group>
```

---

## 3.3 CDB Lists — Whitelisting & Blacklisting

CDB (Constant Database) lists enable O(1) lookups for IP addresses, usernames, hashes, and domains within rules.

### List File Format

```
# /var/ossec/etc/lists/malicious-ioc/malicious-ip
# Format: key:value (value is optional metadata)
185.220.101.1:tor_exit_node
45.33.32.156:known_scanner
198.51.100.23:apt_c2_server

# /var/ossec/etc/lists/malicious-ioc/malicious-domains
evil-domain.com:phishing
malware-c2.net:command_and_control
suspicious.xyz:unknown

# /var/ossec/etc/lists/malicious-ioc/malware-hashes
d41d8cd98f00b204e9800998ecf8427e:known_malware_sample
a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4:ransomware_payload

# /var/ossec/etc/lists/trusted/whitelist-ips
10.0.0.0/8:internal
172.16.0.0/12:internal
192.168.0.0/16:internal
8.8.8.8:google_dns
1.1.1.1:cloudflare_dns

# /var/ossec/etc/lists/trusted/service-accounts
svc_backup:backup_service
svc_monitoring:monitoring_agent
SYSTEM:windows_system
```

### Register Lists in `ossec.conf`

```xml
<ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>

    <!-- CDB Lists -->
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/malicious-ioc/malware-hashes</list>
    <list>etc/lists/malicious-ioc/malicious-ip</list>
    <list>etc/lists/malicious-ioc/malicious-domains</list>
    <list>etc/lists/trusted/whitelist-ips</list>
    <list>etc/lists/trusted/service-accounts</list>

    <!-- User-defined -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
</ruleset>
```

### Using CDB Lists in Rules

```xml
<!-- Alert if source IP is in malicious list -->
<rule id="100501" level="13">
    <if_sid>5710,5711</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/malicious-ioc/malicious-ip</list>
    <description>SSH connection from known malicious IP: $(srcip)</description>
    <group>threat_intel,</group>
</rule>

<!-- Suppress alerts for known service accounts -->
<rule id="100502" level="0">
    <if_sid>5501</if_sid>
    <list field="dstuser" lookup="match_key">etc/lists/trusted/service-accounts</list>
    <description>Suppressed: Known service account login — $(dstuser)</description>
</rule>

<!-- Alert on known malware hash from FIM -->
<rule id="100503" level="14">
    <if_sid>554</if_sid>
    <list field="syscheck.sha256_after" lookup="match_key">etc/lists/malicious-ioc/malware-hashes</list>
    <description>FIM: File with known malware hash detected — $(syscheck.path)</description>
    <group>malware,threat_intel,</group>
    <mitre>
        <id>T1204</id>
    </mitre>
</rule>
```

### Automated CDB List Population from MISP

Use the `misp-cdb-sync.py` script (from your existing MISP integration) via cron:

```bash
# /etc/cron.d/wazuh-misp-sync
# Sync MISP IoCs to CDB lists every 4 hours
0 */4 * * * root /var/ossec/framework/python/bin/python3 /var/ossec/integrations/misp-cdb-sync.py >> /var/ossec/logs/misp-cdb-sync.log 2>&1
```

> **⚠️ PITFALL — CDB List Size:**  
> CDB lists are loaded entirely into memory. Lists exceeding ~500K entries will significantly impact `analysisd` startup time and memory. For very large IoC feeds, use the MISP integration script for real-time API lookups instead of CDB lists.

---

## 3.4 Alert Fatigue Mitigation

### Strategy 1: Rule Level Tuning

```xml
<!-- /var/ossec/etc/rules/local_rules.xml -->

<!-- Reduce noise: Lower severity of known benign alerts -->
<rule id="100600" level="0">
    <if_sid>5402</if_sid>
    <srcip>10.0.10.50</srcip>
    <description>Suppressed: Monitoring server SSH successful login (expected).</description>
</rule>

<!-- Override: Elevate specific rule for critical assets using labels -->
<rule id="100601" level="14">
    <if_sid>5710</if_sid>
    <field name="agent.labels.criticality">critical</field>
    <description>SSH brute-force on CRITICAL asset — Immediate investigation required.</description>
</rule>
```

### Strategy 2: Frequency Thresholding

```xml
<!-- Only alert after 10 occurrences in 300 seconds -->
<rule id="100602" level="10" frequency="10" timeframe="300" ignore="60">
    <if_matched_sid>5501</if_matched_sid>
    <same_source_ip />
    <description>High-frequency login failures from $(srcip) — possible brute-force.</description>
</rule>
```

### Strategy 3: Alert Aggregation via `log_alert_level`

```xml
<!-- Manager ossec.conf — Only store alerts level 6+ -->
<alerts>
    <log_alert_level>6</log_alert_level>
    <email_alert_level>12</email_alert_level>
</alerts>
```

### Strategy 4: Wazuh Rule Overrides

```xml
<!-- Override a noisy default rule to lower level without modifying the original -->
<rule id="100603" level="3" overwrite="no">
    <if_sid>5104</if_sid>
    <match>from 10.0.10.</match>
    <description>Internal network interface entered promiscuous mode (expected for monitoring).</description>
</rule>
```

### Strategy 5: Implementing a Tiered Alert Framework

| Level | Classification | Action | Example |
|---|---|---|---|
| 0–3 | Informational / Suppressed | No alert stored | Routine logins, expected changes |
| 4–7 | Low / Monitoring | Logged, no notification | Failed auth, minor config changes |
| 8–11 | Medium / Investigation | Dashboard alert + ticket | Brute force, suspicious process |
| 12–14 | High / Incident | Immediate notification + SOAR | Malware detected, privilege escalation |
| 15 | Critical / Emergency | PagerDuty/SMS + Active Response | Rootkit, mass credential dump |

---

## 3.5 Data Retention & Index Lifecycle Management (ILM/ISM)

### ISM Policy — Enterprise Tiered Storage

```json
PUT _plugins/_ism/policies/wazuh-enterprise-ilm
{
    "policy": {
        "description": "Enterprise: 7d Hot → Warm (force-merge, read-only) → 90d Delete. Archives: 365d.",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [
                    {
                        "rollover": {
                            "min_index_age": "1d",
                            "min_primary_shard_size": "30gb"
                        }
                    }
                ],
                "transitions": [
                    {
                        "state_name": "warm",
                        "conditions": {
                            "min_index_age": "7d"
                        }
                    }
                ]
            },
            {
                "name": "warm",
                "actions": [
                    { "read_only": {} },
                    { "force_merge": { "max_num_segments": 1 } },
                    {
                        "replica_count": {
                            "number_of_replicas": 0
                        }
                    }
                ],
                "transitions": [
                    {
                        "state_name": "cold",
                        "conditions": {
                            "min_index_age": "30d"
                        }
                    }
                ]
            },
            {
                "name": "cold",
                "actions": [
                    { "read_only": {} }
                ],
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "90d"
                        }
                    }
                ]
            },
            {
                "name": "delete",
                "actions": [
                    { "delete": {} }
                ],
                "transitions": []
            }
        ],
        "ism_template": [
            {
                "index_patterns": [
                    "wazuh-alerts-4.x-*"
                ],
                "priority": 100
            }
        ]
    }
}
```

### Archive Policy (Long-Term Compliance — 1 Year)

```json
PUT _plugins/_ism/policies/wazuh-archive-ilm
{
    "policy": {
        "description": "Archive: 30d Hot → Read-only Warm → 365d Delete",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [
                    {
                        "state_name": "warm",
                        "conditions": { "min_index_age": "30d" }
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
                        "conditions": { "min_index_age": "365d" }
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
                "index_patterns": [ "wazuh-archives-4.x-*" ],
                "priority": 100
            }
        ]
    }
}
```

### Apply ISM Policy to Existing Indices

```bash
# Apply to all existing alert indices
curl -sk -u admin:PASSWORD -X POST \
  "https://192.168.10.40:9200/_plugins/_ism/add/wazuh-alerts-4.x-*" \
  -H 'Content-Type: application/json' \
  -d '{"policy_id": "wazuh-enterprise-ilm"}'

# Verify
curl -sk -u admin:PASSWORD \
  "https://192.168.10.40:9200/_plugins/_ism/explain/wazuh-alerts-4.x-*" | python3 -m json.tool
```

---

## 3.6 Backup & Disaster Recovery

### Snapshot Repository Configuration

```bash
# 1. Create snapshot repository directory
mkdir -p /mnt/wazuh-snapshots
chown wazuh-indexer:wazuh-indexer /mnt/wazuh-snapshots

# 2. Add to opensearch.yml (all indexer nodes)
echo 'path.repo: ["/mnt/wazuh-snapshots"]' >> /etc/wazuh-indexer/opensearch.yml
systemctl restart wazuh-indexer

# 3. Register repository
curl -sk -u admin:PASSWORD -X PUT \
  "https://192.168.10.40:9200/_snapshot/wazuh-backup" \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "fs",
    "settings": {
      "location": "/mnt/wazuh-snapshots",
      "compress": true,
      "max_snapshot_bytes_per_sec": "200mb",
      "max_restore_bytes_per_sec": "200mb"
    }
  }'
```

### Automated Snapshot Cron

```bash
# /etc/cron.d/wazuh-snapshot
# Daily snapshot at 02:00 UTC
0 2 * * * root /usr/local/bin/wazuh-snapshot.sh >> /var/log/wazuh-snapshot.log 2>&1
```

```bash
#!/bin/bash
# /usr/local/bin/wazuh-snapshot.sh
set -euo pipefail

SNAP_NAME="wazuh-snapshot-$(date +%Y%m%d-%H%M)"
INDEXER_URL="https://192.168.10.40:9200"
AUTH="admin:PASSWORD"

# Create snapshot
curl -sk -u "$AUTH" -X PUT \
  "$INDEXER_URL/_snapshot/wazuh-backup/$SNAP_NAME?wait_for_completion=false" \
  -H 'Content-Type: application/json' \
  -d '{
    "indices": "wazuh-alerts-*,wazuh-archives-*,wazuh-monitoring-*,.kibana*",
    "ignore_unavailable": true,
    "include_global_state": false
  }'

# Delete snapshots older than 30 days
CUTOFF=$(date -d '-30 days' +%Y%m%d)
for snap in $(curl -sk -u "$AUTH" "$INDEXER_URL/_snapshot/wazuh-backup/_all" | \
  python3 -c "import sys,json; [print(s['snapshot']) for s in json.load(sys.stdin)['snapshots'] if s['snapshot'].split('-')[2] < '$CUTOFF']" 2>/dev/null); do
    curl -sk -u "$AUTH" -X DELETE "$INDEXER_URL/_snapshot/wazuh-backup/$snap"
    echo "Deleted old snapshot: $snap"
done
```

### Manager Configuration Backup

```bash
#!/bin/bash
# /usr/local/bin/wazuh-config-backup.sh
BACKUP_DIR="/opt/wazuh-backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Critical configuration files
tar -czf "$BACKUP_DIR/wazuh-manager-config.tar.gz" \
    /var/ossec/etc/ossec.conf \
    /var/ossec/etc/rules/ \
    /var/ossec/etc/decoders/ \
    /var/ossec/etc/lists/ \
    /var/ossec/etc/shared/ \
    /var/ossec/etc/client.keys \
    /var/ossec/etc/sslmanager.* \
    /var/ossec/etc/authd.pass \
    /var/ossec/integrations/

# Certificate backup (encrypted)
tar -czf - /etc/wazuh-indexer/certs/ /etc/filebeat/certs/ | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -out "$BACKUP_DIR/certs-encrypted.tar.gz.enc"

# Retain 90 days of config backups
find /opt/wazuh-backups/ -maxdepth 1 -type d -mtime +90 -exec rm -rf {} +

echo "[OK] Backup complete: $BACKUP_DIR"
```

> **⚠️ PITFALL — `client.keys` Backup:**  
> `/var/ossec/etc/client.keys` contains all agent registration keys. Losing this file means **all agents must re-enroll**. Always include it in backups and store backups off-site/encrypted.
