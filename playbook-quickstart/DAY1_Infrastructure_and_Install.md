# Day 1 — Infrastructure & Core Installation

> **Goal:** Wazuh fully installed, certificates configured, OS hardened, first agent connected.  
> **Estimated time:** 6–8 hours

---

## 1.1 OS Preparation (30 min)

```bash
# Update system
apt update && apt upgrade -y

# Set timezone to UTC (critical for log correlation)
timedatectl set-timezone UTC

# Install essentials
apt install -y curl apt-transport-https gnupg2 lsb-release chrony jq

# Ensure NTP is synced
systemctl enable --now chrony
chronyc tracking

# Disable swap (required for OpenSearch/Indexer)
swapoff -a
sed -i '/swap/d' /etc/fstab

# Kernel tuning — create in one shot
cat > /etc/sysctl.d/99-wazuh.conf << 'EOF'
# OpenSearch requirement
vm.max_map_count = 262144
vm.swappiness = 1

# Network performance
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_tw_reuse = 1

# Security basics
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1

# File descriptors
fs.file-max = 500000
EOF

sysctl -p /etc/sysctl.d/99-wazuh.conf

# File descriptor limits
cat > /etc/security/limits.d/99-wazuh.conf << 'EOF'
* soft nofile 65536
* hard nofile 65536
* soft nproc  4096
* hard nproc  4096
EOF
```

### Quick SSH Hardening

```bash
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
EOF
systemctl restart sshd
```

---

## 1.2 Wazuh Installation — All-in-One (1 hour)

Wazuh provides an automated installer that handles all components.

```bash
# Download and run the Wazuh installation assistant
curl -sO https://packages.wazuh.com/4.9/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.9/config.yml

# Edit config.yml for your environment
cat > config.yml << 'EOF'
nodes:
  indexer:
    - name: wazuh-indexer
      ip: "YOUR_SERVER_IP"

  server:
    - name: wazuh-server
      ip: "YOUR_SERVER_IP"

  dashboard:
    - name: wazuh-dashboard
      ip: "YOUR_SERVER_IP"
EOF
```

> **⚠️ Replace `YOUR_SERVER_IP`** with your actual server IP (e.g., `192.168.10.20`). Do NOT use `127.0.0.1` — agents need to reach this IP.

```bash
# Generate certificates
bash wazuh-install.sh --generate-config-files

# Install Wazuh Indexer
bash wazuh-install.sh --wazuh-indexer wazuh-indexer

# Start the Indexer cluster (single-node init)
bash wazuh-install.sh --start-cluster

# Install Wazuh Server (Manager + Filebeat)
bash wazuh-install.sh --wazuh-server wazuh-server

# Install Wazuh Dashboard
bash wazuh-install.sh --wazuh-dashboard wazuh-dashboard
```

### Retrieve Default Credentials

```bash
# The installer outputs the admin password. If you missed it:
tar -xvf wazuh-install-files.tar -C /tmp ./wazuh-install-files/wazuh-passwords.txt
cat /tmp/wazuh-install-files/wazuh-passwords.txt
```

> **🔴 CRITICAL:** Change the default `admin` password immediately:
```bash
# Change via the Wazuh Passwords Tool
bash wazuh-install.sh --change-passwords
```

### Verify Installation

```bash
# All services should be active
systemctl status wazuh-manager
systemctl status wazuh-indexer
systemctl status wazuh-dashboard
systemctl status filebeat

# Indexer cluster health
curl -sk -u admin:YOUR_NEW_PASSWORD "https://localhost:9200/_cluster/health?pretty"
# Expected: "status": "green" (or "yellow" for single-node — this is OK)

# Check indices are being created
curl -sk -u admin:YOUR_NEW_PASSWORD "https://localhost:9200/_cat/indices?v" | head -10
```

### Access Dashboard

Open browser: `https://YOUR_SERVER_IP`  
Login: `admin` / `YOUR_NEW_PASSWORD`

---

## 1.3 Essential Manager Configuration (1 hour)

Edit `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <agents_disconnection_time>15m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>no</update_check>
  </global>

  <!-- Only store alerts level 6+ (reduces noise significantly) -->
  <alerts>
    <log_alert_level>6</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain,json</log_format>
  </logging>

  <!-- Agent connections -->
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <allowed-ips>10.0.0.0/8</allowed-ips>
    <allowed-ips>172.16.0.0/12</allowed-ips>
    <allowed-ips>192.168.0.0/16</allowed-ips>
    <!-- Increase queue for stability -->
    <queue_size>65536</queue_size>
  </remote>

  <!-- Agent enrollment — password-protected -->
  <auth>
    <disabled>no</disabled>
    <port>1515</port>
    <use_source_ip>yes</use_source_ip>
    <purge>yes</purge>
    <use_password>yes</use_password>
    <ciphers>HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH</ciphers>
    <ssl_verify_host>no</ssl_verify_host>
    <ssl_auto_negotiate>no</ssl_auto_negotiate>
  </auth>
</ossec_config>
```

### Set Enrollment Password

```bash
echo "YourStrongEnrollmentPassword2026!" > /var/ossec/etc/authd.pass
chmod 400 /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
```

### Whitelist Trusted IPs (Active Response safety)

Add to `ossec.conf`:

```xml
<global>
    <white_list>127.0.0.1</white_list>
    <white_list>YOUR_SERVER_IP</white_list>
    <white_list>YOUR_GATEWAY_IP</white_list>
</global>
```

### Restart Manager

```bash
systemctl restart wazuh-manager
# Verify clean start
tail -20 /var/ossec/logs/ossec.log
```

---

## 1.4 Firewall Rules (15 min)

```bash
# If using ufw (simpler for small deployments)
ufw allow 22/tcp        # SSH
ufw allow 443/tcp       # Dashboard
ufw allow 1514/tcp      # Agent communication
ufw allow 1515/tcp      # Agent enrollment
ufw allow 55000/tcp     # Wazuh API
ufw enable

# Verify
ufw status verbose
```

---

## 1.5 First Agent Enrollment — Validation (30 min)

### Linux Agent

```bash
# On the target Linux machine:
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list

apt update && WAZUH_MANAGER="YOUR_SERVER_IP" \
  WAZUH_REGISTRATION_PASSWORD="YourStrongEnrollmentPassword2026!" \
  apt install wazuh-agent -y

systemctl daemon-reload
systemctl enable --now wazuh-agent

# Verify on the manager
/var/ossec/bin/agent_control -l
```

### Windows Agent

```powershell
# On the target Windows machine (PowerShell as Admin):
$ManagerIP = "YOUR_SERVER_IP"
$Password = "YourStrongEnrollmentPassword2026!"

Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"

Start-Process msiexec.exe -ArgumentList @(
    "/i", "$env:TEMP\wazuh-agent.msi", "/qn",
    "WAZUH_MANAGER=`"$ManagerIP`"",
    "WAZUH_REGISTRATION_PASSWORD=`"$Password`""
) -Wait

Start-Service WazuhSvc
Get-Service WazuhSvc
```

### Verify in Dashboard

1. Open `https://YOUR_SERVER_IP` → Log in
2. Navigate to **Agents** → Confirm new agent shows `Active`
3. Click on the agent → Check **Security Events** tab for incoming data

> **⚠️ PITFALL — Agent not connecting?**  
> - Check firewall: Is port `1514/TCP` open from agent to manager?
> - Check enrollment: Is port `1515/TCP` reachable?
> - Check `/var/ossec/logs/ossec.log` on both sides for errors.
> - Most common issue: wrong IP in agent's `ossec.conf` or enrollment password mismatch.

---

## Day 1 Checklist

```
✅ OS updated, hardened, swap disabled, sysctl applied
✅ Wazuh Indexer installed and healthy (green/yellow)
✅ Wazuh Manager installed, ossec.conf configured
✅ Wazuh Dashboard accessible via HTTPS
✅ Default admin password changed
✅ Enrollment password set
✅ Firewall rules applied
✅ First Linux agent enrolled and sending data
✅ First Windows agent enrolled and sending data
✅ Dashboard showing active agents and events
```

**→ Proceed to [Day 2: Configuration, Rules & Agents](./DAY2_Configuration_Rules_and_Agents.md)**
