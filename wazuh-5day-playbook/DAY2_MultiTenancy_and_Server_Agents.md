# Day 2 — Multi-Tenancy & Server Agents

> **Goal:** Logical groups created, RBAC foundation set, all Linux/Windows servers enrolled and reporting, FIM/SCA/Vulnerability Detection active.  
> **Estimated time:** 6–8 hours

---

## 2.1 Create Agent Groups — Logical Separation (30 min)

Wazuh groups are the foundation of multi-tenancy for a small company. Each group gets its own `agent.conf`, which pushes differentiated configurations to agents.

```bash
# Create groups for logical separation
/var/ossec/bin/agent_groups -a -g Servers-Prod
/var/ossec/bin/agent_groups -a -g Servers-Dev
/var/ossec/bin/agent_groups -a -g Workstations
/var/ossec/bin/agent_groups -a -g Network-Devices
/var/ossec/bin/agent_groups -a -g Critical-Assets
/var/ossec/bin/agent_groups -a -g Linux
/var/ossec/bin/agent_groups -a -g Windows

# Verify
/var/ossec/bin/agent_groups -l
```

### Multi-Group Strategy

Agents can belong to **multiple groups simultaneously**. Use this for layered policies:

```
Server-DC01 → groups: Windows, Servers-Prod, Critical-Assets
Server-Web01 → groups: Linux, Servers-Prod
Dev-Box01 → groups: Linux, Servers-Dev
```

When an agent belongs to multiple groups, Wazuh merges their `agent.conf` files. **The last group's config wins for conflicting settings.** Order matters — assign the most specific group last.

```bash
# Assign agent 001 to multiple groups
/var/ossec/bin/agent_groups -a -i 001 -g Linux
/var/ossec/bin/agent_groups -a -i 001 -g Servers-Prod
/var/ossec/bin/agent_groups -a -i 001 -g Critical-Assets
```

---

## 2.2 RBAC on the Dashboard (30 min)

Create read-only roles for different teams. This is done via the Wazuh Dashboard → **Security** section (backed by OpenSearch Security plugin).

### Step 1: Create an Internal User

Dashboard → **☰** → **Security** → **Internal Users** → **Create internal user**

| Field | Value |
|---|---|
| Username | `soc-analyst` |
| Password | (strong password) |
| Backend role | `soc_readonly` |

### Step 2: Create a Role

Dashboard → **Security** → **Roles** → **Create role**

```
Role name: soc_readonly

Cluster permissions:
  - cluster:monitor/*

Index permissions:
  Index patterns: wazuh-alerts-*, wazuh-monitoring-*, wazuh-statistics-*
  Allowed actions:
    - read
    - search
    - get
```

### Step 3: Map Role to User

Dashboard → **Security** → **Roles** → `soc_readonly` → **Mapped users** → Add `soc-analyst`

> **⚠️ PITFALL — RBAC vs. Agent Groups:**  
> Wazuh's native RBAC (via the API) and OpenSearch's Security Plugin RBAC are **separate systems**. The Dashboard uses OpenSearch RBAC for UI access. For API-level agent isolation (e.g., "this user can only see agents in group X"), you need to use the Wazuh API RBAC via `/security/roles` and `/security/policies`. For a small company, Dashboard RBAC is usually sufficient.

---

## 2.3 Group-Specific Agent Configurations (1 hour)

### Linux Servers — `/var/ossec/etc/shared/Linux/agent.conf`

```xml
<agent_config os="Linux">
    <!-- FIM: Monitor critical Linux paths -->
    <syscheck>
        <frequency>43200</frequency>
        <scan_on_start>yes</scan_on_start>
        <alert_new_files>yes</alert_new_files>

        <!-- System binaries and configs -->
        <directories check_sha256="yes" check_owner="yes"
                     check_perm="yes">/etc,/usr/bin,/usr/sbin,/bin,/sbin</directories>

        <!-- Web roots — realtime for immediate detection -->
        <directories realtime="yes" check_sha256="yes"
                     report_changes="yes"
                     restrict=".php$|.js$|.py$|.conf$|.html$">/var/www</directories>

        <!-- SSH authorized_keys — critical for persistence detection -->
        <directories realtime="yes" check_sha256="yes"
                     report_changes="yes">/root/.ssh,/home</directories>

        <!-- Exclude noisy paths -->
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

### Windows Endpoints — `/var/ossec/etc/shared/Windows/agent.conf`

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

    <!-- Sysmon (if installed — HIGHLY recommended) -->
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

### Critical Assets Override — `/var/ossec/etc/shared/Critical-Assets/agent.conf`

```xml
<agent_config>
    <!-- Override: Aggressive FIM for critical assets -->
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

## 2.4 Enroll Linux Agents (1.5 hours)

### Individual Enrollment (with group assignment at install time)

```bash
# On the target Linux machine:
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list

apt update && WAZUH_MANAGER="YOUR_SERVER_IP" \
  WAZUH_REGISTRATION_PASSWORD="YourStrongEnrollmentPassword2026!" \
  WAZUH_AGENT_GROUP="Linux,Servers-Prod" \
  apt install wazuh-agent -y

systemctl daemon-reload
systemctl enable --now wazuh-agent
```

> **⚠️ PITFALL — `WAZUH_AGENT_GROUP` during install:**  
> You can assign agents to groups at enrollment time using the `WAZUH_AGENT_GROUP` environment variable. The groups must **already exist** on the manager (created in Step 2.1). Comma-separate multiple groups. If a group doesn't exist, enrollment will fail silently — the agent connects but lands in the `default` group.

### Batch Deployment Script

```bash
#!/bin/bash
# deploy_linux_agents.sh — Run from the manager or a jump box
# Usage: ./deploy_linux_agents.sh hosts.txt

MANAGER_IP="YOUR_SERVER_IP"
ENROLLMENT_PW="YourStrongEnrollmentPassword2026!"
AGENT_GROUPS="Linux,Servers-Prod"
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
        WAZUH_AGENT_GROUP="${AGENT_GROUPS}" \
        apt install wazuh-agent -y -qq
        systemctl daemon-reload
        systemctl enable --now wazuh-agent
        echo "[OK] Agent installed on \$(hostname)"
REMOTE
    echo "[✓] Done: $HOST"
    sleep 2  # Delay to prevent enrollment storms
done < "$HOST_FILE"
```

```bash
# hosts.txt format — one IP per line
# 192.168.10.50
# 192.168.10.51
# 192.168.10.52

chmod +x deploy_linux_agents.sh
./deploy_linux_agents.sh hosts.txt
```

---

## 2.5 Enroll Windows Agents (1 hour)

### Individual Enrollment (PowerShell as Administrator)

```powershell
$ManagerIP = "YOUR_SERVER_IP"
$Password = "YourStrongEnrollmentPassword2026!"
$Groups = "Windows,Servers-Prod"

Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"

Start-Process msiexec.exe -ArgumentList @(
    "/i", "$env:TEMP\wazuh-agent.msi", "/qn",
    "WAZUH_MANAGER=`"$ManagerIP`"",
    "WAZUH_REGISTRATION_PASSWORD=`"$Password`"",
    "WAZUH_AGENT_GROUP=`"$Groups`""
) -Wait

Start-Service WazuhSvc
Get-Service WazuhSvc
```

> [!IMPORTANT]
> Verify the exact MSI filename on https://packages.wazuh.com/4.x/windows/ — the version number in the filename must match (e.g., `wazuh-agent-4.14.0-1.msi`).

### Batch Windows Deployment (PowerShell Remoting)

```powershell
# deploy_windows_agents.ps1
$ManagerIP = "YOUR_SERVER_IP"
$Password = "YourStrongEnrollmentPassword2026!"
$Groups = "Windows,Servers-Prod"
$Targets = @("SRV-DC01", "SRV-FILE01", "SRV-APP01")

foreach ($target in $Targets) {
    Write-Host "[*] Deploying to $target..." -ForegroundColor Cyan
    Invoke-Command -ComputerName $target -ScriptBlock {
        param($mgr, $pw, $grp)
        $installer = "$env:TEMP\wazuh-agent.msi"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi" `
            -OutFile $installer -UseBasicParsing
        Start-Process msiexec.exe -ArgumentList @(
            "/i", $installer, "/qn",
            "WAZUH_MANAGER=`"$mgr`"",
            "WAZUH_REGISTRATION_PASSWORD=`"$pw`"",
            "WAZUH_AGENT_GROUP=`"$grp`""
        ) -Wait
        Start-Service WazuhSvc
        Remove-Item $installer -Force
    } -ArgumentList $ManagerIP, $Password, $Groups
    Write-Host "[OK] $target deployed" -ForegroundColor Green
    Start-Sleep -Seconds 3
}
```

---

## 2.6 Verify Fleet Status (15 min)

```bash
# On the manager — check all agents
/var/ossec/bin/agent_control -l

# Count active vs disconnected
echo "Active agents: $(/var/ossec/bin/agent_control -l | grep -c 'Active')"
echo "Disconnected:  $(/var/ossec/bin/agent_control -l | grep -c 'Disconnected')"

# Check group assignments
/var/ossec/bin/agent_groups -l -g Servers-Prod
/var/ossec/bin/agent_groups -l -g Linux
/var/ossec/bin/agent_groups -l -g Windows
```

### Troubleshooting Agents Not Connecting

```bash
# On the agent (Linux):
cat /var/ossec/etc/ossec.conf | grep address   # Is the manager IP correct?
tail -30 /var/ossec/logs/ossec.log              # Any errors?

# On the manager:
tail -50 /var/ossec/logs/ossec.log | grep -i "error\|agent"

# Common fixes:
# 1. Port 1514 not open → ufw allow 1514/tcp
# 2. Port 1515 not reachable → enrollment fails silently
# 3. Wrong enrollment password → agent shows "connected" briefly then disconnects
# 4. Agent already exists with same IP → delete old entry:
#    /var/ossec/bin/manage_agents -r <AGENT_ID>
```

---

## 2.7 Validate Data Flow in Dashboard (30 min)

In the Wazuh Dashboard (`https://YOUR_SERVER_IP`):

1. **Agents tab** → All agents show `Active` ✅
2. Click on a **Linux agent** → **Security Events** → Confirm alerts flowing
3. Click on a **Windows agent** → **Security Events** → Confirm Windows event logs appearing
4. **Integrity Monitoring** tab → Should show initial FIM baseline scan
5. **Vulnerability Detection** tab → CVEs should start appearing (may take 15-30 min for first feed download)
6. **SCA** tab → Security posture scores visible per agent

> **⚠️ PITFALL — "No data" in Vulnerability Detection:**  
> After enabling, Wazuh must download vulnerability feeds first. This can take 15-60 minutes depending on your internet speed. Check:
> ```bash
> grep "vulnerability" /var/ossec/logs/ossec.log | tail -10
> ```
> If you see "Feed downloaded" messages, it's working. Be patient.

---

## 2.8 Manager Performance Tuning (15 min)

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
✅ Agent groups created (Servers-Prod, Servers-Dev, Linux, Windows, Critical-Assets, Network-Devices)
✅ RBAC users created on Dashboard for SOC team
✅ Group-specific agent.conf deployed (FIM paths, event channels, labels)
✅ All Linux servers enrolled and in correct groups
✅ All Windows servers enrolled and in correct groups
✅ FIM baseline scan completed on all agents
✅ SCA results visible in Dashboard
✅ Vulnerability Detection feeds downloading
✅ Manager performance tuning applied
✅ All agents show "Active" in Dashboard
```

---

**→ Proceed to [Day 3: Firewalls & Router Integration](./DAY3_Firewalls_and_Router_Integration.md)**
