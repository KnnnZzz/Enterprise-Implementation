# Phase 1 — Infrastructure Security & Hardening

---

## 1.1 Firewall Port Matrix

### Inter-Component Communication

| Source | Destination | Port | Protocol | Purpose | Encryption |
|---|---|---|---|---|---|
| Agents | Manager (LB VIP) | 1514/TCP | AES-256 | Event forwarding | Wazuh native TLS |
| Agents | Manager (LB VIP) | 1515/TCP | TLS 1.2+ | Auto-enrollment (`wazuh-authd`) | TLS |
| Manager | Indexer Cluster | 9200/TCP | HTTPS | Filebeat → OpenSearch indexing | mTLS |
| Dashboard | Indexer Cluster | 9200/TCP | HTTPS | Query & visualization | mTLS |
| Manager (Master) | Manager (Workers) | 1516/TCP | AES | Cluster synchronization | Cluster key |
| Indexer ↔ Indexer | Indexer Nodes | 9300/TCP | TLS | Transport layer (shard replication) | mTLS |
| SOC Analysts | Dashboard (LB VIP) | 443/TCP | HTTPS | Web UI | TLS 1.2+ |
| Automation/SOAR | Manager (LB VIP) | 55000/TCP | HTTPS | Wazuh REST API | TLS + JWT |

### External Integrations

| Source | Destination | Port | Purpose |
|---|---|---|---|
| Manager | MISP Instance | 443/TCP | Threat intel lookups |
| Manager | VirusTotal API | 443/TCP | Hash reputation |
| Manager | SMTP Relay | 587/TCP | Email alerting |
| Manager | Shuffle/SOAR | 443/TCP | Webhook notifications |
| Manager | TheHive | 9000/TCP | Case creation |
| Cloud Sources | Manager (Syslog) | 514/TCP,UDP | Firewall/cloud logs |

### Firewall Rules (iptables example for Manager nodes)

```bash
#!/bin/bash
# /etc/iptables/rules.v4 — Wazuh Manager Hardened Rules

# Flush existing
iptables -F
iptables -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# SSH from Management VLAN only
iptables -A INPUT -s 10.0.10.0/24 -p tcp --dport 22 -j ACCEPT

# Agent communication from Agent VLAN
iptables -A INPUT -s 10.0.40.0/16 -p tcp --dport 1514 -j ACCEPT
iptables -A INPUT -s 10.0.40.0/16 -p tcp --dport 1515 -j ACCEPT

# Cluster sync from SIEM Backend VLAN
iptables -A INPUT -s 10.0.20.0/24 -p tcp --dport 1516 -j ACCEPT

# API from SOC/Automation VLAN
iptables -A INPUT -s 10.0.30.0/24 -p tcp --dport 55000 -j ACCEPT

# Syslog from network devices
iptables -A INPUT -s 10.0.40.0/16 -p tcp --dport 514 -j ACCEPT
iptables -A INPUT -s 10.0.40.0/16 -p udp --dport 514 -j ACCEPT

# ICMP (limited)
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT

# Log dropped
iptables -A INPUT -j LOG --log-prefix "IPTABLES-DROP: " --log-level 4
iptables -A INPUT -j DROP

# Save
iptables-save > /etc/iptables/rules.v4
```

---

## 1.2 TLS/mTLS Certificate Infrastructure

### Certificate Generation with `wazuh-certs-tool`

```bash
# 1. Download the cert tool
curl -sO https://packages.wazuh.com/4.x/wazuh-certs-tool.sh
chmod 0700 wazuh-certs-tool.sh

# 2. Create configuration file
cat > config.yml << 'EOF'
nodes:
  indexer:
    - name: indexer-node-1
      ip: 192.168.10.40
    - name: indexer-node-2
      ip: 192.168.10.41
    - name: indexer-node-3
      ip: 192.168.10.42

  server:
    - name: wazuh-master
      ip: 192.168.10.20
    - name: wazuh-worker01
      ip: 192.168.10.21

  dashboard:
    - name: dashboard-node-1
      ip: 192.168.10.30
    - name: dashboard-node-2
      ip: 192.168.10.31
EOF

# 3. Generate all certificates
bash wazuh-certs-tool.sh -A

# 4. Verify output
ls -la wazuh-certificates/
# root-ca.pem, root-ca-key.pem
# indexer-node-1.pem, indexer-node-1-key.pem ...
# admin.pem, admin-key.pem
```

### Certificate Distribution

```bash
# Package and distribute to each node
tar -czf wazuh-certificates.tar.gz wazuh-certificates/

# On each Indexer node:
mkdir -p /etc/wazuh-indexer/certs
cp wazuh-certificates/root-ca.pem /etc/wazuh-indexer/certs/
cp wazuh-certificates/indexer-node-1.pem /etc/wazuh-indexer/certs/
cp wazuh-certificates/indexer-node-1-key.pem /etc/wazuh-indexer/certs/
cp wazuh-certificates/admin.pem /etc/wazuh-indexer/certs/
cp wazuh-certificates/admin-key.pem /etc/wazuh-indexer/certs/
chmod 400 /etc/wazuh-indexer/certs/*-key.pem
chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs/*

# On each Manager node (for Filebeat):
mkdir -p /etc/filebeat/certs
cp wazuh-certificates/root-ca.pem /etc/filebeat/certs/
cp wazuh-certificates/wazuh-master.pem /etc/filebeat/certs/
cp wazuh-certificates/wazuh-master-key.pem /etc/filebeat/certs/
chmod 400 /etc/filebeat/certs/*-key.pem
```

> **⚠️ PITFALL — Certificate CN Mismatch:**  
> The `CN` (Common Name) in each certificate **must** match the `node.name` in `opensearch.yml` AND be listed in `plugins.security.nodes_dn`. A CN mismatch will cause TLS handshake failures with cryptic "SSLHandshakeException" errors in the transport layer.

---

## 1.3 OS Hardening Checklist

Apply to **all** Wazuh nodes (Ubuntu 22.04/24.04 LTS recommended):

### Kernel Parameters — `/etc/sysctl.d/99-wazuh-hardening.conf`

```bash
# Network hardening
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.disable_ipv6 = 1

# Performance tuning for high-throughput SIEM
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65536
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 1024 65535

# Memory — Critical for Indexer nodes
vm.max_map_count = 262144
vm.swappiness = 1
vm.dirty_ratio = 40
vm.dirty_background_ratio = 10

# File descriptors
fs.file-max = 1000000
```

```bash
# Apply immediately
sysctl -p /etc/sysctl.d/99-wazuh-hardening.conf
```

### System Limits — `/etc/security/limits.d/99-wazuh.conf`

```
wazuh-indexer  soft  nofile  65536
wazuh-indexer  hard  nofile  65536
wazuh-indexer  soft  nproc   4096
wazuh-indexer  hard  nproc   4096
wazuh-indexer  soft  memlock unlimited
wazuh-indexer  hard  memlock unlimited
root           soft  nofile  65536
root           hard  nofile  65536
```

### Additional Hardening Steps

```bash
# 1. Disable swap (critical for Indexer)
swapoff -a
sed -i '/swap/d' /etc/fstab

# 2. Set timezone to UTC (log correlation)
timedis ectl set-timezone UTC

# 3. Install and enable chrony/NTP (time sync is CRITICAL for SIEM)
apt install chrony -y
systemctl enable --now chrony

# 4. Disable unnecessary services
systemctl disable --now avahi-daemon cups bluetooth

# 5. Install unattended-upgrades for security patches
apt install unattended-upgrades -y
dpkg-reconfigure -plow unattended-upgrades

# 6. SSH hardening — /etc/ssh/sshd_config.d/99-hardening.conf
cat > /etc/ssh/sshd_config.d/99-hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
Protocol 2
EOF
systemctl restart sshd

# 7. Install auditd for self-monitoring
apt install auditd -y
systemctl enable --now auditd
```

---

## 1.4 RBAC Configuration (Wazuh Dashboard)

### Built-in Security Roles

Wazuh uses OpenSearch Security plugin for RBAC. Configure via the Security API or Dashboard UI.

### Custom SOC Role Definitions

Create at `/etc/wazuh-indexer/opensearch-security/roles.yml`:

```yaml
# SOC Tier 1 — Read-only alert monitoring
soc_tier1:
  cluster_permissions:
    - "cluster_composite_ops_ro"
  index_permissions:
    - index_patterns:
        - "wazuh-alerts-4.x-*"
        - "wazuh-monitoring-*"
      allowed_actions:
        - "read"
        - "search"
        - "get"
  tenant_permissions:
    - tenant_patterns:
        - "global_tenant"
      allowed_actions:
        - "kibana_all_read"

# SOC Tier 2 — Read + write dashboards + agent management
soc_tier2:
  cluster_permissions:
    - "cluster_composite_ops_ro"
    - "cluster:admin/opendistro/reports/instance/list"
  index_permissions:
    - index_patterns:
        - "wazuh-alerts-4.x-*"
        - "wazuh-archives-4.x-*"
        - "wazuh-monitoring-*"
        - "wazuh-statistics-*"
      allowed_actions:
        - "read"
        - "search"
        - "get"
    - index_patterns:
        - ".kibana*"
        - ".opendistro*"
      allowed_actions:
        - "read"
        - "write"
        - "create_index"
  tenant_permissions:
    - tenant_patterns:
        - "global_tenant"
      allowed_actions:
        - "kibana_all_write"

# SOC Lead / Engineer — Full access minus security config
soc_engineer:
  cluster_permissions:
    - "cluster_composite_ops"
    - "cluster_monitor"
    - "cluster:admin/opendistro/ism/*"
  index_permissions:
    - index_patterns:
        - "*"
      allowed_actions:
        - "crud"
        - "create_index"
        - "manage"
  tenant_permissions:
    - tenant_patterns:
        - "global_tenant"
      allowed_actions:
        - "kibana_all_write"
```

### Role Mappings — `roles_mapping.yml`

```yaml
soc_tier1:
  reserved: false
  backend_roles:
    - "SOC-Tier1"        # Maps to IdP group
  users:
    - "analyst1"

soc_tier2:
  reserved: false
  backend_roles:
    - "SOC-Tier2"
  users:
    - "analyst_senior"

soc_engineer:
  reserved: false
  backend_roles:
    - "SOC-Engineers"
    - "SIEM-Admins"
```

### Apply Security Configuration

```bash
# Run securityadmin to push config changes
export JAVA_HOME=/usr/share/wazuh-indexer/jdk

/usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /etc/wazuh-indexer/opensearch-security/ \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -icl -nhnv \
  -h 192.168.10.40
```

---

## 1.5 SSO/SAML Integration (Entra ID / Okta)

### Entra ID (Azure AD) SAML Configuration

#### Step 1: Register Enterprise Application in Entra ID

1. Azure Portal → Entra ID → Enterprise Applications → New Application → Create your own
2. Name: `Wazuh SIEM Dashboard`
3. Set SSO method: **SAML**
4. Configure:
   - **Entity ID:** `https://wazuh-dashboard.corp.local`
   - **Reply URL (ACS):** `https://wazuh-dashboard.corp.local/_opendistro/_security/saml/acs`
   - **Sign-on URL:** `https://wazuh-dashboard.corp.local`
5. Download **Federation Metadata XML** or note:
   - IdP Entity ID
   - SSO URL
   - Certificate (Base64)

#### Step 2: Configure OpenSearch Security — `config.yml`

```yaml
# /etc/wazuh-indexer/opensearch-security/config.yml
_meta:
  type: "config"
  config_version: 2

config:
  dynamic:
    authc:
      basic_internal_auth_domain:
        description: "Authenticate via HTTP basic against internal users database"
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: basic
          challenge: false
        authentication_backend:
          type: intern
      saml_auth_domain:
        http_enabled: true
        transport_enabled: false
        order: 1
        http_authenticator:
          type: saml
          challenge: true
          config:
            idp:
              metadata_url: "https://login.microsoftonline.com/TENANT_ID/federationmetadata/2007-06/federationmetadata.xml?appid=APP_ID"
              entity_id: "https://sts.windows.net/TENANT_ID/"
            sp:
              entity_id: "https://wazuh-dashboard.corp.local"
              # forceAuthn: false
            kibana_url: "https://wazuh-dashboard.corp.local"
            subject_key: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"
            roles_key: "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"
            exchange_key: "GENERATE_32CHAR_RANDOM_KEY"
        authentication_backend:
          type: noop
```

#### Step 3: Configure Dashboard — `opensearch_dashboards.yml`

```yaml
# Append to /etc/wazuh-dashboard/opensearch_dashboards.yml
opensearch_security.auth.type: "saml"
server.xsrf.allowlist: ["/_opendistro/_security/saml/acs", "/_opendistro/_security/saml/logout"]
```

#### Step 4: Map Entra ID Groups → OpenSearch Roles

In `roles_mapping.yml`, map Azure group Object IDs:

```yaml
soc_tier1:
  backend_roles:
    - "aaaaaaaa-bbbb-cccc-dddd-111111111111"  # Entra Group: SOC-Tier1

soc_tier2:
  backend_roles:
    - "aaaaaaaa-bbbb-cccc-dddd-222222222222"  # Entra Group: SOC-Tier2

soc_engineer:
  backend_roles:
    - "aaaaaaaa-bbbb-cccc-dddd-333333333333"  # Entra Group: SIEM-Admins
```

> **⚠️ PITFALL — SAML + Basic Auth Coexistence:**  
> Always keep `basic_internal_auth_domain` with `order: 0` and `challenge: false`. This ensures the local `admin` account remains accessible for emergency/break-glass scenarios when SAML IdP is unreachable.

---

## 1.6 Auditing the SIEM Itself

### Wazuh Manager Self-Monitoring via FIM

```xml
<!-- In agent.conf for Wazuh nodes group -->
<syscheck>
    <!-- Monitor Wazuh's own configuration for tampering -->
    <directories realtime="yes" check_sha256="yes" check_owner="yes" 
                 check_perm="yes">/var/ossec/etc</directories>
    <directories realtime="yes" check_sha256="yes">/var/ossec/etc/rules</directories>
    <directories realtime="yes" check_sha256="yes">/var/ossec/etc/decoders</directories>
    <directories realtime="yes" check_sha256="yes">/var/ossec/etc/lists</directories>

    <!-- Monitor critical binaries -->
    <directories check_sha256="yes">/var/ossec/bin</directories>

    <!-- Alert on any file changes immediately -->
    <alert_new_files>yes</alert_new_files>
</syscheck>
```

### OpenSearch Audit Logging

```yaml
# /etc/wazuh-indexer/opensearch.yml — Append
plugins.security.audit.type: internal_opensearch
plugins.security.audit.config.enabled: true
plugins.security.audit.config.log_request_body: false
plugins.security.audit.config.disabled_rest_categories:
  - AUTHENTICATED
  - GRANTED_PRIVILEGES
plugins.security.audit.config.disabled_transport_categories:
  - AUTHENTICATED
  - GRANTED_PRIVILEGES
```

### Wazuh API Audit (ossec.conf)

```xml
<!-- Monitor API access logs -->
<localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/api.log</location>
</localfile>
```
