# Phase 2 — Core Wazuh Configuration & Agent Deployment

---

## 2.1 Automated Agent Deployment

### Strategy Overview

| Method | Best For | Scale |
|---|---|---|
| **Ansible** | Linux fleet, heterogeneous environments | 100–10,000+ |
| **SCCM/Intune** | Windows domain-joined endpoints | 1,000–50,000+ |
| **GPO** | Windows AD environments | 500–10,000 |
| **Puppet/Chef** | DevOps-managed infrastructure | Variable |
| **Cloud-Init/User Data** | AWS/Azure/GCP auto-scaling groups | Dynamic |

### Ansible Playbook — Linux Agent Deployment

```yaml
# deploy_wazuh_agent.yml
---
- name: Deploy Wazuh Agent to Linux Fleet
  hosts: all_linux_servers
  become: yes
  vars:
    wazuh_manager_ip: "10.0.40.10"           # LB VIP
    wazuh_agent_version: "4.9.2-1"
    wazuh_enrollment_password: "{{ vault_wazuh_enrollment_pw }}"
    wazuh_agent_group: "{{ group_names | join(',') }}"

  tasks:
    - name: Add Wazuh GPG key
      apt_key:
        url: https://packages.wazuh.com/key/GPG-KEY-WAZUH
        state: present
      when: ansible_os_family == "Debian"

    - name: Add Wazuh repository (Debian/Ubuntu)
      apt_repository:
        repo: "deb https://packages.wazuh.com/4.x/apt/ stable main"
        state: present
        filename: wazuh
      when: ansible_os_family == "Debian"

    - name: Add Wazuh repository (RHEL/CentOS)
      yum_repository:
        name: wazuh
        description: Wazuh repository
        baseurl: https://packages.wazuh.com/4.x/yum/
        gpgkey: https://packages.wazuh.com/key/GPG-KEY-WAZUH
        gpgcheck: yes
      when: ansible_os_family == "RedHat"

    - name: Install Wazuh agent
      package:
        name: "wazuh-agent={{ wazuh_agent_version }}"
        state: present
      environment:
        WAZUH_MANAGER: "{{ wazuh_manager_ip }}"
        WAZUH_REGISTRATION_PASSWORD: "{{ wazuh_enrollment_password }}"
        WAZUH_AGENT_GROUP: "{{ wazuh_agent_group }}"

    - name: Configure agent manager address
      lineinfile:
        path: /var/ossec/etc/ossec.conf
        regexp: '<address>.*</address>'
        line: "    <address>{{ wazuh_manager_ip }}</address>"
        backrefs: yes

    - name: Enable and start Wazuh agent
      systemd:
        name: wazuh-agent
        state: started
        enabled: yes
        daemon_reload: yes

    - name: Verify agent connection
      command: /var/ossec/bin/agent-auth -m {{ wazuh_manager_ip }}
      register: auth_result
      changed_when: false
      failed_when: auth_result.rc != 0

    - name: Lock Wazuh agent package version
      dpkg_selections:
        name: wazuh-agent
        selection: hold
      when: ansible_os_family == "Debian"
```

### Windows Agent Deployment via SCCM/GPO

```powershell
# deploy_wazuh_agent.ps1 — Execute via SCCM Task Sequence or GPO Startup Script
param(
    [string]$ManagerIP = "10.0.40.10",
    [string]$AgentGroup = "windows,production",
    [string]$EnrollmentPassword = "SECURE_PASSWORD_HERE"
)

$InstallerURL = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi"
$InstallerPath = "$env:TEMP\wazuh-agent.msi"

# Check if already installed
$service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Wazuh agent already installed. Exiting."
    exit 0
}

# Download installer
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $InstallerURL -OutFile $InstallerPath -UseBasicParsing

# Silent install with enrollment parameters
$msiArgs = @(
    "/i", $InstallerPath,
    "/qn",
    "WAZUH_MANAGER=`"$ManagerIP`"",
    "WAZUH_REGISTRATION_SERVER=`"$ManagerIP`"",
    "WAZUH_REGISTRATION_PASSWORD=`"$EnrollmentPassword`"",
    "WAZUH_AGENT_GROUP=`"$AgentGroup`""
)

Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -NoNewWindow

# Start the service
Start-Service -Name "WazuhSvc"

# Verify
$svc = Get-Service -Name "WazuhSvc"
if ($svc.Status -eq "Running") {
    Write-Host "Wazuh Agent deployed successfully."
} else {
    Write-Host "ERROR: Wazuh Agent service not running." -ForegroundColor Red
    exit 1
}

# Cleanup
Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
```

### Auto-Enrollment Best Practices

```xml
<!-- Manager ossec.conf — authd configuration -->
<auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>yes</use_source_ip>
    <purge>yes</purge>
    <use_password>yes</use_password>
    <!-- Force strong TLS ciphers -->
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_manager_cert>etc/sslmanager.cert</ssl_manager_cert>
    <ssl_manager_key>etc/sslmanager.key</ssl_manager_key>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
    <!-- Limit enrollment rate to prevent abuse -->
    <limit_maxagents>yes</limit_maxagents>
</auth>
```

```bash
# Set the enrollment password on the Manager
echo "YOUR_STRONG_ENROLLMENT_PASSWORD" > /var/ossec/etc/authd.pass
chmod 400 /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
```

> **⚠️ PITFALL — Agent Enrollment Storms:**  
> Mass-deploying agents simultaneously (e.g., 1000+ via SCCM at once) can overwhelm `wazuh-authd`. Stagger deployments in batches of 100–200 with 60-second delays between batches. Monitor `/var/ossec/logs/ossec.log` for "Too many connections" errors.

---

## 2.2 Agent Grouping Strategy

### Hierarchical Group Model

Wazuh agents support **multi-group assignment** (comma-separated). Use a layered taxonomy:

```
Layer 1: OS Platform     → linux, windows, macos, network_devices
Layer 2: Environment     → production, staging, development, dmz
Layer 3: Criticality     → critical, high, medium, low
Layer 4: Function        → webserver, database, dc, workstation, firewall
```

### Example Group Assignments

| Asset Type | Group Assignment | Resulting Config |
|---|---|---|
| Production Linux Web Server | `linux,production,critical,webserver` | Full FIM + SCA + Vuln + aggressive syscollector |
| Dev Windows Workstation | `windows,development,low,workstation` | Light FIM, relaxed SCA, no active response |
| Domain Controller | `windows,production,critical,dc` | Real-time FIM on AD dirs, enhanced audit, strict SCA |
| OPNsense Firewall (agentless) | `network_devices,production,critical,firewall` | Syslog-based, custom decoders |
| MikroTik Router (agentless) | `network_devices,production,high,router` | Syslog-based, custom decoders |

### Creating Groups and Assigning Shared Configurations

```bash
# Create groups via API
curl -k -X POST "https://localhost:55000/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id": "linux"}'

curl -k -X POST "https://localhost:55000/groups" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"group_id": "production"}'

# Assign agent to multiple groups
curl -k -X PUT "https://localhost:55000/agents/001/group/linux,production,critical,webserver" \
  -H "Authorization: Bearer $TOKEN"
```

### Group-Specific Configuration Files

Each group gets a `agent.conf` in `/var/ossec/etc/shared/<group_name>/agent.conf`:

#### `/var/ossec/etc/shared/production/agent.conf`

```xml
<agent_config>
    <!-- Production: More aggressive monitoring -->
    <syscheck>
        <frequency>21600</frequency>  <!-- 6 hours instead of 12 -->
        <scan_on_start>yes</scan_on_start>
        <alert_new_files>yes</alert_new_files>
    </syscheck>

    <wodle name="syscollector">
        <interval>12h</interval>
    </wodle>

    <labels>
        <label key="environment">production</label>
    </labels>
</agent_config>
```

#### `/var/ossec/etc/shared/critical/agent.conf`

```xml
<agent_config>
    <!-- Critical assets: Real-time FIM on sensitive directories -->
    <syscheck>
        <directories realtime="yes" check_sha256="yes" check_owner="yes"
                     check_perm="yes" report_changes="yes">/etc</directories>
        <directories realtime="yes" check_sha256="yes">/usr/bin,/usr/sbin</directories>
        <directories realtime="yes" check_sha256="yes">/bin,/sbin</directories>
    </syscheck>

    <labels>
        <label key="criticality">critical</label>
        <label key="compliance">pci-dss,iso27001</label>
    </labels>
</agent_config>
```

#### `/var/ossec/etc/shared/windows/agent.conf`

```xml
<agent_config os="Windows">
    <syscheck>
        <directories realtime="yes" check_sha256="yes">C:\Windows\System32\drivers\etc</directories>
        <directories realtime="yes" check_sha256="yes" report_changes="yes">C:\Windows\System32\config</directories>
        <directories check_sha256="yes">C:\Program Files</directories>

        <!-- Windows-specific exclusions -->
        <ignore>C:\Windows\Temp</ignore>
        <ignore type="sregex">.tmp$|.log$|.etl$</ignore>
    </syscheck>

    <!-- Windows Event Channel Collection -->
    <localfile>
        <location>Security</location>
        <log_format>eventchannel</log_format>
        <query>Event/System[EventID=4624 or EventID=4625 or EventID=4648 or
               EventID=4672 or EventID=4688 or EventID=4720 or EventID=4726 or
               EventID=4728 or EventID=4732 or EventID=4756 or EventID=1102]</query>
    </localfile>

    <localfile>
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
        <location>Microsoft-Windows-PowerShell/Operational</location>
        <log_format>eventchannel</log_format>
    </localfile>
</agent_config>
```

#### `/var/ossec/etc/shared/dc/agent.conf`

```xml
<agent_config os="Windows">
    <!-- Domain Controller: Enhanced Active Directory monitoring -->
    <syscheck>
        <directories realtime="yes" check_sha256="yes">C:\Windows\NTDS</directories>
        <directories realtime="yes" check_sha256="yes">C:\Windows\SYSVOL</directories>
        <directories realtime="yes" check_sha256="yes">C:\Windows\System32\GroupPolicy</directories>
    </syscheck>

    <localfile>
        <location>Directory Service</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <localfile>
        <location>DNS Server</location>
        <log_format>eventchannel</log_format>
    </localfile>

    <labels>
        <label key="asset_type">domain_controller</label>
        <label key="criticality">critical</label>
    </labels>
</agent_config>
```

---

## 2.3 Module Configuration — Production-Optimized

### File Integrity Monitoring (FIM / Syscheck) — Manager-side

```xml
<!-- Manager ossec.conf — Syscheck for the manager itself -->
<syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Linux critical paths -->
    <directories check_sha256="yes" check_owner="yes" check_perm="yes"
                 report_changes="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_sha256="yes">/bin,/sbin,/boot</directories>

    <!-- Web application directories (if applicable) -->
    <directories realtime="yes" check_sha256="yes" report_changes="yes"
                 restrict=".php$|.js$|.py$|.conf$">/var/www</directories>

    <!-- Ignores -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore type="sregex">.log$|.swp$|.tmp$</ignore>

    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>

    <process_priority>10</process_priority>
    <max_eps>50</max_eps>

    <synchronization>
        <enabled>yes</enabled>
        <interval>5m</interval>
        <max_eps>10</max_eps>
    </synchronization>
</syscheck>
```

### Security Configuration Assessment (SCA)

```xml
<!-- Manager ossec.conf -->
<sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
    <!-- Custom policies can be added to /var/ossec/etc/shared/<group>/
         and will be pushed to agents automatically -->
</sca>
```

Custom SCA policies are placed in the group's shared directory:
```
/var/ossec/etc/shared/linux/cis_ubuntu2404.yml
/var/ossec/etc/shared/windows/cis_win2022.yml
/var/ossec/etc/shared/dc/cis_ad_hardening.yml
```

### Vulnerability Detection

```xml
<vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>24h</feed-update-interval>
</vulnerability-detection>
```

### Syscollector — Inventory

```xml
<wodle name="syscollector">
    <disabled>no</disabled>
    <interval>24h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <users>yes</users>
    <groups>yes</groups>
    <services>yes</services>
    <browser_extensions>yes</browser_extensions>
    <synchronization>
        <max_eps>50</max_eps>
    </synchronization>
</wodle>
```

### Remote Queue Tuning (High-Volume)

```xml
<!-- Manager ossec.conf — Remote connection tuning -->
<remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <!-- Accept agents from known subnets -->
    <allowed-ips>10.0.0.0/8</allowed-ips>
    <allowed-ips>172.16.0.0/12</allowed-ips>
    <allowed-ips>192.168.0.0/16</allowed-ips>
    <!-- Queue size: 131072 for high-volume (default: 16384) -->
    <queue_size>131072</queue_size>
</remote>
```

### Analysis Engine Tuning — `internal_options.conf`

```bash
# /var/ossec/etc/internal_options.conf overrides
# (create /var/ossec/etc/local_internal_options.conf to override safely)

cat > /var/ossec/etc/local_internal_options.conf << 'EOF'
# Analysis engine — increase EPS capacity
analysisd.event_threads=4
analysisd.syscheck_threads=2
analysisd.syscollector_threads=2
analysisd.rootcheck_threads=2
analysisd.hostinfo_threads=2

# Increase decode event queue
analysisd.decode_event_queue_size=32768

# Remoted — connection handling
remoted.recv_counter_flush=128
remoted.comp_average_printout=0

# FIM database sync
syscheck.db_entry_limit=1000000
EOF

chown root:wazuh /var/ossec/etc/local_internal_options.conf
chmod 640 /var/ossec/etc/local_internal_options.conf
```

> **⚠️ PITFALL — `analysisd` Queue Saturation:**  
> If `events_dropped` in `/var/ossec/var/run/wazuh-analysisd.state` starts incrementing, your analysis engine is overloaded. First increase `decode_event_queue_size`, then add `event_threads`. Monitor this file with a custom command (as in your existing ossec.conf health checks).
