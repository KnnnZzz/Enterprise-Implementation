# Day 1 — Infrastructure & Base Install

> **Goal:** Ubuntu hardened, Wazuh 4.14 fully installed, Dashboard accessible, passwords changed, first validation.  
> **Estimated time:** 6–8 hours

---

## 1.1 OS Preparation (30 min)

### System Update & Essentials

```bash
# Full system update
apt update && apt upgrade -y

# Set timezone to UTC — critical for cross-device log correlation
timedatectl set-timezone UTC

# Install dependencies
apt install -y curl apt-transport-https gnupg2 lsb-release chrony jq net-tools

# Enable NTP sync
systemctl enable --now chrony
chronyc tracking  # Verify sync
```

### Disable Swap (Mandatory for OpenSearch)

```bash
swapoff -a
sed -i '/swap/d' /etc/fstab

# Verify: should return nothing
swapon --show
```

> [!CAUTION]
> **If swap is enabled, OpenSearch will suffer severe performance degradation.** The JVM uses memory-mapped files extensively. Swap causes page faults that destroy indexing throughput. This is non-negotiable.

### Kernel Tuning

```bash
cat > /etc/sysctl.d/99-wazuh.conf << 'EOF'
# OpenSearch — mandatory
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
```

### File Descriptor Limits

```bash
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

## 1.2 Wazuh 4.14 Installation — All-in-One (1 hour)

### Download the Installation Assistant

```bash
# Download the Wazuh 4.14 installation script and config template
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
```

> [!IMPORTANT]
> **Wazuh 4.14 specifics:** The version in the URL must match exactly. Using `4.x` or `4.9` will install an older version. Always verify the URL at https://documentation.wazuh.com/current/installation-guide/

### Configure `config.yml`

Replace `YOUR_SERVER_IP` with your actual LAN IP (e.g., `192.168.10.20`):

```yaml
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
```

> [!WARNING]
> **Do NOT use `127.0.0.1` or `localhost`.** The certificates are generated with the IP you provide here. Agents use this IP to connect. If you use loopback, agents on other machines cannot reach the manager, and you'll have to regenerate all certificates.

### Run the Installation

```bash
# Step 1: Generate certificates
bash wazuh-install.sh --generate-config-files

# Step 2: Install the Wazuh Indexer
bash wazuh-install.sh --wazuh-indexer wazuh-indexer

# Step 3: Initialize the Indexer cluster
bash wazuh-install.sh --start-cluster

# Step 4: Install the Wazuh Server (Manager + Filebeat)
bash wazuh-install.sh --wazuh-server wazuh-server

# Step 5: Install the Wazuh Dashboard
bash wazuh-install.sh --wazuh-dashboard wazuh-dashboard
```

### Retrieve & Change Default Passwords

```bash
# Retrieve auto-generated passwords
tar -xvf wazuh-install-files.tar -C /tmp ./wazuh-install-files/wazuh-passwords.txt
cat /tmp/wazuh-install-files/wazuh-passwords.txt
```

> [!CAUTION]
> **Change the default `admin` password immediately.** This is the master credential for the Dashboard and API:

```bash
bash wazuh-install.sh --change-passwords
```

> **🔐 PITFALL — Password change script:**  
> The `--change-passwords` flag changes passwords for all internal users (admin, kibanaserver, etc.). Record these somewhere safe — losing the `admin` password means you're locked out of the Dashboard and API. There is no password reset mechanism without direct access to the security plugin configuration.

---

## 1.3 Verify Installation (15 min)

```bash
# Check all services
echo "=== Service Status ==="
systemctl status wazuh-manager   --no-pager -l | head -5
systemctl status wazuh-indexer   --no-pager -l | head -5
systemctl status wazuh-dashboard --no-pager -l | head -5
systemctl status filebeat        --no-pager -l | head -5

# Indexer cluster health
echo "=== Cluster Health ==="
curl -sk -u admin:YOUR_NEW_PASSWORD \
  "https://localhost:9200/_cluster/health?pretty"
# Expected: "status": "green" or "yellow" (yellow is normal for single-node — no replicas)

# Check indices are being created
echo "=== Indices ==="
curl -sk -u admin:YOUR_NEW_PASSWORD \
  "https://localhost:9200/_cat/indices?v" | head -10

# Filebeat connectivity
echo "=== Filebeat Test ==="
filebeat test output
```

### Access the Dashboard

1. Open browser: `https://YOUR_SERVER_IP`
2. Accept the self-signed certificate warning
3. Login: `admin` / `YOUR_NEW_PASSWORD`
4. You should see the Wazuh overview page with the manager itself as agent `000`

> **⚠️ PITFALL — "Yellow" cluster status:**  
> Single-node clusters will always show `yellow` because there are no replica nodes. This is **expected and harmless**. Do NOT waste time trying to make it `green` — that requires a second indexer node.

---

## 1.4 Essential Manager Configuration (45 min)

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

  <!-- CRITICAL: Only log alerts level 6+ to reduce indexer load -->
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
    <queue_size>131072</queue_size>
  </remote>

  <!-- Syslog listener — needed for Day 3 (firewalls/routers) -->
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>192.168.10.0/24</allowed-ips>
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

  <!-- Active Response — whitelist critical IPs -->
  <global>
    <white_list>127.0.0.1</white_list>
    <white_list>YOUR_SERVER_IP</white_list>
    <white_list>YOUR_GATEWAY_IP</white_list>
  </global>

  <!-- Vulnerability Detection -->
  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>24h</feed-update-interval>
  </vulnerability-detection>

  <!-- Indexer connection -->
  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>https://YOUR_SERVER_IP:9200</host>
    </hosts>
    <ssl>
      <certificate_authorities>
        <ca>/etc/filebeat/certs/root-ca.pem</ca>
      </certificate_authorities>
      <certificate>/etc/filebeat/certs/wazuh-server.pem</certificate>
      <key>/etc/filebeat/certs/wazuh-server-key.pem</key>
    </ssl>
  </indexer>

  <!-- Ruleset -->
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>

    <!-- Custom -->
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

  <rule_test>
    <enabled>yes</enabled>
    <threads>1</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>15m</session_timeout>
  </rule_test>
</ossec_config>
```

### Set Enrollment Password

```bash
# Generate a strong enrollment password
echo "YourStrongEnrollmentPassword2026!" > /var/ossec/etc/authd.pass
chmod 400 /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
```

> **⚠️ PITFALL — Enrollment without password:**  
> Without `authd.pass`, anyone who can reach port 1515 can enroll a rogue agent. In a small company, this might seem low-risk, but a compromised machine on the network could silently inject false telemetry into your SIEM.

---

## 1.5 Firewall Rules (10 min)

```bash
# Using UFW (recommended for simplicity)
ufw allow 22/tcp        # SSH
ufw allow 443/tcp       # Dashboard
ufw allow 1514/tcp      # Agent communication
ufw allow 1515/tcp      # Agent enrollment
ufw allow 55000/tcp     # Wazuh API
ufw allow 514/udp       # Syslog from network devices (Day 3)
ufw enable

# Verify
ufw status verbose
```

---

## 1.6 Index Lifecycle Management (20 min)

> **Do this NOW, not later.** Without retention, your disk will fill up within weeks and the SIEM will crash.

```bash
# Apply ISM policy via OpenSearch API
curl -sk -u admin:YOUR_NEW_PASSWORD -X PUT \
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

# Verify
curl -sk -u admin:YOUR_NEW_PASSWORD \
  "https://localhost:9200/_plugins/_ism/policies/wazuh-retention" | python3 -m json.tool
```

---

## 1.7 Restart & Final Validation

```bash
# Restart the manager to apply all config changes
systemctl restart wazuh-manager

# Check for config errors
tail -30 /var/ossec/logs/ossec.log | grep -i "error\|critical\|warn"

# Verify all services running
for svc in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
    echo "$svc: $(systemctl is-active $svc)"
done
```

---

## Day 1 Checklist

```
✅ OS updated, hardened, swap disabled, sysctl applied
✅ SSH hardened (key-only, root disabled)
✅ Wazuh Indexer installed and healthy (green/yellow)
✅ Wazuh Manager installed, ossec.conf configured
✅ Wazuh Dashboard accessible via HTTPS
✅ Default admin password CHANGED and recorded securely
✅ Enrollment password set in authd.pass
✅ Firewall rules applied (including 514/UDP for Day 3)
✅ ISM retention policy configured (7d hot → 90d delete)
✅ Syslog listener configured in ossec.conf (for Day 3)
✅ All services restarted cleanly — no errors in logs
```

---

**→ Proceed to [Day 2: Multi-Tenancy & Server Agents](./DAY2_MultiTenancy_and_Server_Agents.md)**
