# Day 2 — Configuration, Rules & Fleet Enrollment

> **Goal:** Full agent fleet enrolled, agent groups configured, FIM/SCA/Vuln active, custom rules deployed, alert noise reduced.  
> **Estimated time:** 6–8 hours

---

## 2.1 Agent Grouping (30 min)

Create groups to push different configurations to different asset types.

```bash
# Create groups via CLI (faster than API for small fleet)
/var/ossec/bin/agent_groups -a -g linux
/var/ossec/bin/agent_groups -a -g windows
/var/ossec/bin/agent_groups -a -g production
/var/ossec/bin/agent_groups -a -g development
/var/ossec/bin/agent_groups -a -g critical
/var/ossec/bin/agent_groups -a -g servers
/var/ossec/bin/agent_groups -a -g workstations

# Assign an agent to multiple groups (comma-separated during enrollment)
# Or manually after enrollment:
/var/ossec/bin/agent_groups -a -i 001 -g linux
/var/ossec/bin/agent_groups -a -i 001 -g production
/var/ossec/bin/agent_groups -a -i 001 -g servers

# List current groups
/var/ossec/bin/agent_groups -l
```

---

## 2.2 Group-Specific Agent Configurations (1 hour)

### Linux Servers — `/var/ossec/etc/shared/linux/agent.conf`

```xml
<agent_config os="Linux">
    <!-- FIM: Monitor critical Linux paths -->
    <syscheck>
        <frequency>43200</frequency>
        <scan_on_start>yes</scan_on_start>
        <alert_new_files>yes</alert_new_files>

        <directories check_sha256="yes" check_owner="yes"
                     check_perm="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>

        <!-- Web roots (if applicable) -->
        <directories realtime="yes" check_sha256="yes"
                     report_changes="yes"
                     restrict=".php$|.js$|.py$|.conf$|.html$">/var/www</directories>

        <!-- SSH authorized_keys — critical for persistence detection -->
        <directories realtime="yes" check_sha256="yes"
                     report_changes="yes">/root/.ssh,/home</directories>

        <ignore>/etc/mtab</ignore>
        <ignore>/etc/adjtime</ignore>
        <ignore type="sregex">.log$|.swp$|.tmp$</ignore>

        <skip_nfs>yes</skip_nfs>
        <skip_dev>yes</skip_dev>
        <skip_proc>yes</skip_proc>
        <skip_sys>yes</skip_sys>
        <max_eps>50</max_eps>
    </syscheck>

    <!-- SCA: Security posture checks -->
    <sca>
        <enabled>yes</enabled>
        <scan_on_start>yes</scan_on_start>
        <interval>12h</interval>
    </sca>

    <!-- Syscollector: Asset inventory -->
    <wodle name="syscollector">
        <disabled>no</disabled>
        <interval>24h</interval>
        <scan_on_start>yes</scan_on_start>
        <packages>yes</packages>
        <os>yes</os>
        <network>yes</network>
        <ports all="yes">yes</ports>
        <processes>yes</processes>
    </wodle>

    <labels>
        <label key="os.platform">linux</label>
    </labels>
</agent_config>
```

### Windows Endpoints — `/var/ossec/etc/shared/windows/agent.conf`

```xml
<agent_config os="Windows">
    <!-- FIM: Windows critical paths -->
    <syscheck>
        <frequency>43200</frequency>
        <scan_on_start>yes</scan_on_start>
        <alert_new_files>yes</alert_new_files>

        <!-- System files -->
        <directories check_sha256="yes">C:\Windows\System32\drivers\etc</directories>
        <directories check_sha256="yes">C:\Windows\System32\config</directories>

        <!-- Startup/persistence locations -->
        <directories realtime="yes" check_sha256="yes">C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup</directories>
        <directories check_sha256="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>

        <!-- Exclude noisy paths -->
        <ignore>C:\Windows\Temp</ignore>
        <ignore>C:\Windows\Prefetch</ignore>
        <ignore type="sregex">.tmp$|.log$|.etl$</ignore>

        <max_eps>50</max_eps>
    </syscheck>

    <!-- Windows Event Channels — Security-focused collection -->
    <localfile>
        <location>Security</location>
        <log_format>eventchannel</log_format>
        <!-- Key events: Logon, Failed Logon, Privilege Use, Process Creation,
             Account Management, Audit Log Cleared -->
        <query>Event/System[EventID=4624 or EventID=4625 or EventID=4648 or
               EventID=4672 or EventID=4688 or EventID=4720 or EventID=4726 or
               EventID=4728 or EventID=4732 or EventID=4756 or EventID=1102]</query>
    </localfile>

    <!-- Sysmon (if installed — highly recommended) -->
    <localfile>
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <!-- PowerShell logging -->
    <localfile>
        <location>Microsoft-Windows-PowerShell/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <sca>
        <enabled>yes</enabled>
        <scan_on_start>yes</scan_on_start>
        <interval>12h</interval>
    </sca>

    <wodle name="syscollector">
        <disabled>no</disabled>
        <interval>24h</interval>
        <scan_on_start>yes</scan_on_start>
        <packages>yes</packages>
        <os>yes</os>
        <network>yes</network>
        <ports all="yes">yes</ports>
        <processes>yes</processes>
        <hotfixes>yes</hotfixes>
    </wodle>

    <labels>
        <label key="os.platform">windows</label>
    </labels>
</agent_config>
```

### Critical Assets — `/var/ossec/etc/shared/critical/agent.conf`

```xml
<agent_config>
    <!-- Override: More aggressive FIM for critical assets -->
    <syscheck>
        <frequency>21600</frequency>  <!-- 6h instead of 12h -->
    </syscheck>

    <labels>
        <label key="criticality">critical</label>
        <label key="compliance">iso27001</label>
    </labels>
</agent_config>
```

---

## 2.3 Enable Vulnerability Detection (15 min)

Verify it's enabled in the manager's `ossec.conf`:

```xml
<vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>24h</feed-update-interval>
</vulnerability-detection>
```

```bash
# Restart manager to apply
systemctl restart wazuh-manager

# Verify feeds are downloading (check logs)
grep "vulnerability" /var/ossec/logs/ossec.log | tail -5
```

---

## 2.4 Deploy Remaining Agents (2 hours)

### Batch Linux Deployment Script

```bash
#!/bin/bash
# deploy_agents.sh — Run from the manager or a jump box
# Usage: ./deploy_agents.sh hosts.txt

MANAGER_IP="YOUR_SERVER_IP"
ENROLLMENT_PW="YourStrongEnrollmentPassword2026!"
HOST_FILE="$1"

while read -r HOST; do
    echo "[*] Deploying to $HOST..."
    ssh -o StrictHostKeyChecking=no root@"$HOST" bash -s << REMOTE
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
          --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null
        chmod 644 /usr/share/keyrings/wazuh.gpg
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
          | tee /etc/apt/sources.list.d/wazuh.list > /dev/null
        apt update -qq
        WAZUH_MANAGER="${MANAGER_IP}" \
        WAZUH_REGISTRATION_PASSWORD="${ENROLLMENT_PW}" \
        apt install wazuh-agent -y -qq
        systemctl daemon-reload
        systemctl enable --now wazuh-agent
        echo "[OK] Agent installed on \$(hostname)"
REMOTE
    echo "[✓] Done: $HOST"
    sleep 2  # Slight delay to avoid enrollment storms
done < "$HOST_FILE"
```

```bash
# hosts.txt — one IP per line
# 192.168.10.50
# 192.168.10.51
# 192.168.10.52

chmod +x deploy_agents.sh
./deploy_agents.sh hosts.txt
```

### Windows Batch Deployment (PowerShell)

```powershell
# deploy_agents.ps1 — Run from a management workstation
$ManagerIP = "YOUR_SERVER_IP"
$Password = "YourStrongEnrollmentPassword2026!"
$Targets = @("PC-001", "PC-002", "SRV-DC01", "SRV-FILE01")

foreach ($target in $Targets) {
    Write-Host "[*] Deploying to $target..." -ForegroundColor Cyan
    Invoke-Command -ComputerName $target -ScriptBlock {
        param($mgr, $pw)
        $installer = "$env:TEMP\wazuh-agent.msi"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" `
            -OutFile $installer -UseBasicParsing
        Start-Process msiexec.exe -ArgumentList @(
            "/i", $installer, "/qn",
            "WAZUH_MANAGER=`"$mgr`"",
            "WAZUH_REGISTRATION_PASSWORD=`"$pw`""
        ) -Wait
        Start-Service WazuhSvc
        Remove-Item $installer -Force
    } -ArgumentList $ManagerIP, $Password
    Write-Host "[OK] $target deployed" -ForegroundColor Green
    Start-Sleep -Seconds 3
}
```

### Verify Fleet Status

```bash
# On the manager
/var/ossec/bin/agent_control -l | grep -c "Active"
# Should match your expected agent count

# Check for any disconnected
/var/ossec/bin/agent_control -l | grep "Disconnected"
```

---

## 2.5 Custom Rules — Essential Detections (1.5 hours)

### Rule ID Allocation (keep it simple)

| Range | Purpose |
|---|---|
| 100000–100049 | Infrastructure / Generic |
| 100050–100099 | SIEM Self-Health |
| 100100–100199 | Network Devices |
| 100200–100299 | Windows Advanced |
| 100300–100399 | Linux Advanced |
| 100800–100899 | Threat Intelligence |

### `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="local,custom,">

    <!-- ═══════════════════════════════════════════ -->
    <!--  LINUX DETECTIONS                           -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- Sudoers file modified — privilege escalation -->
    <rule id="100001" level="12">
        <if_sid>550</if_sid>
        <match>visudo|/etc/sudoers</match>
        <description>Sudoers file modified — potential privilege escalation.</description>
        <mitre>
            <id>T1548.003</id>
        </mitre>
        <group>privilege_escalation,</group>
    </rule>

    <!-- Crontab modified — persistence -->
    <rule id="100002" level="10">
        <if_sid>550</if_sid>
        <regex>/var/spool/cron|/etc/cron</regex>
        <description>Crontab or cron directory modified — persistence mechanism.</description>
        <mitre>
            <id>T1053.003</id>
        </mitre>
        <group>persistence,</group>
    </rule>

    <!-- SSH authorized_keys modified — backdoor access -->
    <rule id="100003" level="12">
        <if_sid>550,554</if_sid>
        <match>authorized_keys</match>
        <description>SSH authorized_keys file modified — potential backdoor.</description>
        <mitre>
            <id>T1098.004</id>
        </mitre>
        <group>persistence,</group>
    </rule>

    <!-- New user created on Linux -->
    <rule id="100004" level="8">
        <if_sid>5902</if_sid>
        <description>New user account created on Linux system.</description>
        <mitre>
            <id>T1136.001</id>
        </mitre>
        <group>account_management,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!--  WINDOWS DETECTIONS                         -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- PowerShell encoded command — obfuscation -->
    <rule id="100200" level="12">
        <if_sid>91801</if_sid>
        <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)-[Ee]nc[oded]*[Cc]ommand|FromBase64String|IEX\s*\(</field>
        <description>PowerShell: Encoded/obfuscated command execution detected.</description>
        <mitre>
            <id>T1059.001</id>
            <id>T1027</id>
        </mitre>
        <group>execution,attack,</group>
    </rule>

    <!-- Mimikatz / LSASS credential dumping -->
    <rule id="100201" level="14">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.targetFilename" type="pcre2">(?i)mimikatz|lsass\.dmp|procdump.*lsass</field>
        <description>CRITICAL: Credential dumping tool detected (Sysmon File Create).</description>
        <mitre>
            <id>T1003.001</id>
        </mitre>
        <group>credential_access,attack,</group>
    </rule>

    <!-- Windows audit log cleared — anti-forensics -->
    <rule id="100202" level="14">
        <if_sid>60103</if_sid>
        <field name="win.system.eventID">1102</field>
        <description>CRITICAL: Windows Security audit log was cleared — anti-forensics.</description>
        <mitre>
            <id>T1070.001</id>
        </mitre>
        <group>defense_evasion,attack,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!--  SIEM SELF-HEALTH                           -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- Disk usage > 85% -->
    <rule id="100050" level="12">
        <if_sid>531</if_sid>
        <regex>8[5-9]%|9[0-9]%|100%</regex>
        <description>SIEM HEALTH: Disk usage critical (>85%).</description>
        <group>siem_health,</group>
    </rule>

    <!-- ═══════════════════════════════════════════ -->
    <!--  NOISE REDUCTION                            -->
    <!-- ═══════════════════════════════════════════ -->

    <!-- Suppress: Known monitoring tools -->
    <rule id="100090" level="0">
        <if_sid>5710</if_sid>
        <srcip>YOUR_MONITORING_SERVER_IP</srcip>
        <description>Suppressed: Expected SSH from monitoring server.</description>
    </rule>

    <!-- Suppress: Scheduled backup user -->
    <rule id="100091" level="0">
        <if_sid>5501</if_sid>
        <match>svc_backup</match>
        <description>Suppressed: Known backup service account login.</description>
    </rule>

</group>
```

> **⚠️ Remember to replace** `YOUR_MONITORING_SERVER_IP` with your actual monitoring system IP.

---

## 2.6 CDB Lists — Quick Threat Intelligence (30 min)

### Create Malicious IP List

```bash
mkdir -p /var/ossec/etc/lists/malicious-ioc

# Seed with known bad IPs (update regularly or automate with MISP later)
cat > /var/ossec/etc/lists/malicious-ioc/malicious-ip << 'EOF'
185.220.101.1:tor_exit_node
45.33.32.156:known_scanner
EOF

# Trusted IPs (never trigger alerts)
cat > /var/ossec/etc/lists/trusted-ips << 'EOF'
8.8.8.8:google_dns
1.1.1.1:cloudflare_dns
YOUR_PUBLIC_IP:company_egress
EOF
```

### Register Lists in `ossec.conf`

```xml
<ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>

    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
    <list>etc/lists/malicious-ioc/malicious-ip</list>
    <list>etc/lists/trusted-ips</list>

    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
</ruleset>
```

### CDB-Based Detection Rule

Add to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<!-- Alert if source IP is in malicious list -->
<rule id="100500" level="13">
    <if_sid>5710,5711</if_sid>
    <list field="srcip" lookup="address_match_key">etc/lists/malicious-ioc/malicious-ip</list>
    <description>Connection from known malicious IP: $(srcip).</description>
    <group>threat_intel,</group>
</rule>
```

### Apply Everything

```bash
# Restart manager to load new rules, decoders, and CDB lists
systemctl restart wazuh-manager

# Check for config errors
grep -i "error\|critical" /var/ossec/logs/ossec.log | tail -10

# Test a rule with wazuh-logtest
/var/ossec/bin/wazuh-logtest
```

---

## 2.7 Manager Performance Tuning (15 min)

```bash
cat > /var/ossec/etc/local_internal_options.conf << 'EOF'
# Analysis engine threads (increase for >100 agents)
analysisd.event_threads=2
analysisd.syscheck_threads=1
analysisd.syscollector_threads=1

# Increase decode queue
analysisd.decode_event_queue_size=16384
EOF

chown root:wazuh /var/ossec/etc/local_internal_options.conf
chmod 640 /var/ossec/etc/local_internal_options.conf

systemctl restart wazuh-manager
```

---

## Day 2 Checklist

```
✅ Agent groups created (linux, windows, production, critical, etc.)
✅ Group-specific agent.conf deployed (FIM paths, event channels, labels)
✅ Vulnerability detection enabled and feeds downloading
✅ All agents enrolled and showing Active
✅ Custom detection rules deployed (privilege escalation, credential dumping, etc.)
✅ Noise reduction rules in place (known IPs, service accounts)
✅ CDB lists created and registered
✅ Manager performance tuning applied
✅ wazuh-logtest validates rules correctly
✅ Dashboard showing alerts from the fleet
```

**→ Proceed to [Day 3: Integrations, Backups & Go-Live](./DAY3_Integrations_Backups_and_GoLive.md)**
