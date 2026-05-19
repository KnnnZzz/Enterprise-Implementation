# Phase 0 — Enterprise Architecture & Sizing

> **Document Classification:** Internal — SOC Engineering Playbook  
> **Version:** 1.0 | **Date:** 2026-05-19  
> **Scope:** Distributed, High-Availability Wazuh 4.x deployment for enterprise SOC operations.

---

## 0.1 Reference Architecture

```
                        ┌─────────────────────────────┐
                        │     SOC Analysts / RBAC      │
                        │   (Browser → Dashboard VIP)  │
                        └──────────────┬──────────────┘
                                       │ HTTPS :443
                              ┌────────▼────────┐
                              │   HAProxy / NLB  │
                              │  (Dashboard VIP) │
                              └──┬───────────┬───┘
                       ┌─────────▼───┐   ┌───▼─────────┐
                       │  Dashboard  │   │  Dashboard   │
                       │   Node A    │   │   Node B     │
                       │  (Standby)  │   │  (Active)    │
                       └──────┬──────┘   └──────┬───────┘
                              │   OpenSearch API  │
                   ┌──────────▼──────────────────▼──────────┐
                   │        Wazuh Indexer Cluster            │
                   │  ┌──────────┐┌──────────┐┌──────────┐  │
                   │  │ Indexer-1││ Indexer-2││ Indexer-3│  │
                   │  │ (Master) ││ (Data)   ││ (Data)   │  │
                   │  └──────────┘└──────────┘└──────────┘  │
                   └────────────────────────────────────────┘
                                       ▲ Filebeat :9200 (TLS)
                              ┌────────┴────────┐
                              │   HAProxy / NLB  │
                              │  (Server VIP)    │
                              │  :1514 / :1515   │
                              │  :55000 (API)    │
                              └──┬───────────┬───┘
                       ┌─────────▼───┐   ┌───▼─────────┐
                       │  Wazuh Mgr  │   │  Wazuh Mgr  │
                       │  Master     │   │  Worker-01   │
                       │  node01     │   │  node02      │
                       └─────────────┘   └──────────────┘
                                ▲  :1514 TCP (Encrypted)
                    ┌───────────┼───────────┐
               ┌────▼──┐  ┌────▼──┐  ┌─────▼──┐
               │Agent 1│  │Agent N│  │Syslog  │
               │(Linux)│  │(Win)  │  │Sources │
               └───────┘  └───────┘  └────────┘
```

### Component Roles

| Component | Role | HA Strategy |
|---|---|---|
| **Wazuh Indexer** | OpenSearch-based storage & search | 3-node cluster; 1 dedicated master-eligible + 2 data nodes (minimum). Odd quorum to prevent split-brain. |
| **Wazuh Server (Manager)** | Event analysis, rule processing, agent management | Master/Worker cluster via `wazuh-clusterd`. Master handles API, config push; workers handle agent connections. |
| **Wazuh Dashboard** | Kibana-fork UI | Active/Standby behind L7 proxy. Stateless — any node can serve. |
| **Load Balancer** | Traffic distribution | HAProxy or NGINX for agent `:1514`, enrollment `:1515`, and API `:55000`. |

---

## 0.2 Hardware Sizing Matrix

### Wazuh Manager Nodes

| Agent Count | vCPU | RAM | Disk (SSD) | Notes |
|---|---|---|---|---|
| ≤ 500 | 4 | 8 GB | 100 GB | Single-node viable |
| 500–2,000 | 8 | 16 GB | 200 GB | Master + 1 Worker |
| 2,000–10,000 | 16 | 32 GB | 500 GB | Master + 2 Workers |
| 10,000+ | 16+ | 64 GB | 1 TB NVMe | Master + 3+ Workers. Scale workers horizontally. |

### Wazuh Indexer Nodes

| Daily Ingest | vCPU | RAM (JVM Heap = 50%) | Disk | Replicas |
|---|---|---|---|---|
| ≤ 50 GB/day | 8 | 16 GB (8 GB heap) | 500 GB NVMe | 1 |
| 50–200 GB/day | 16 | 32 GB (16 GB heap) | 2 TB NVMe | 1 |
| 200+ GB/day | 32 | 64 GB (32 GB heap) | 4+ TB NVMe RAID | 1–2 |

> **⚠️ PITFALL — JVM Heap Sizing:**  
> Never exceed 50% of physical RAM for JVM heap, and never exceed 32 GB heap (compressed OOPs threshold). Going above 32 GB causes pointer decompression overhead and *degrades* performance.

### Wazuh Dashboard

| Concurrent Users | vCPU | RAM | Disk |
|---|---|---|---|
| ≤ 20 | 4 | 8 GB | 50 GB |
| 20–100 | 8 | 16 GB | 100 GB |

### Load Balancer (HAProxy)

| Scale | vCPU | RAM |
|---|---|---|
| ≤ 5,000 agents | 2 | 4 GB |
| 5,000–20,000 | 4 | 8 GB |

---

## 0.3 Disk I/O Considerations

- **Wazuh Indexer:** NVMe SSDs are **mandatory** for production. Spinning disks will create indexing bottlenecks at >1,000 EPS.
- **Filesystem:** Use `ext4` or `xfs` with `noatime` mount option.
- **Separate mount points:**
  ```
  /var/ossec          → Manager data (queues, logs)
  /var/lib/wazuh-indexer  → Indexer data (shards)
  ```
- **RAID:** RAID-10 for indexer data volumes in bare-metal deployments.

---

## 0.4 Load Balancer Configuration (HAProxy)

### `/etc/haproxy/haproxy.cfg`

```haproxy
global
    log /dev/log local0
    maxconn 50000
    tune.ssl.default-dh-param 2048
    ssl-default-bind-ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    log     global
    mode    tcp
    option  tcplog
    option  dontlognull
    timeout connect 10s
    timeout client  300s
    timeout server  300s
    retries 3

# ── Agent Communication (1514/TCP) ──
frontend ft_agent_comm
    bind *:1514
    default_backend bk_wazuh_workers

backend bk_wazuh_workers
    balance leastconn
    option tcp-check
    # Health: TCP handshake on agent port
    server wazuh-master  192.168.10.20:1514 check inter 5s fall 3 rise 2
    server wazuh-worker1 192.168.10.21:1514 check inter 5s fall 3 rise 2

# ── Agent Enrollment (1515/TCP) ──
frontend ft_agent_enroll
    bind *:1515
    default_backend bk_wazuh_enroll

backend bk_wazuh_enroll
    # Enrollment MUST go to master only
    balance roundrobin
    server wazuh-master 192.168.10.20:1515 check

# ── Wazuh API (55000/TCP) ──
frontend ft_wazuh_api
    bind *:55000 ssl crt /etc/haproxy/certs/wazuh-api.pem
    mode http
    default_backend bk_wazuh_api

backend bk_wazuh_api
    mode http
    balance roundrobin
    option httpchk GET /
    http-check expect status 200
    server wazuh-master  192.168.10.20:55000 ssl verify none check
    server wazuh-worker1 192.168.10.21:55000 ssl verify none check

# ── Dashboard (443) ──
frontend ft_dashboard
    bind *:443 ssl crt /etc/haproxy/certs/dashboard.pem
    mode http
    default_backend bk_dashboard

backend bk_dashboard
    mode http
    balance roundrobin
    option httpchk GET /api/status
    http-check expect status 200
    server dashboard1 192.168.10.30:5601 ssl verify none check
    server dashboard2 192.168.10.31:5601 ssl verify none check backup

# ── Stats Page (internal only) ──
listen stats
    bind 127.0.0.1:8404
    mode http
    stats enable
    stats uri /stats
    stats auth admin:CHANGE_ME_STRONG_PASSWORD
```

> **⚠️ PITFALL — Enrollment Routing:**  
> Agent enrollment (`wazuh-authd` on port 1515) **must** be routed exclusively to the **master** node. Worker nodes do not run `wazuh-authd`. Sending enrollment traffic to workers will cause silent registration failures.

---

## 0.5 Wazuh Server Cluster Configuration

### Master Node — `ossec.conf` cluster stanza

```xml
<cluster>
    <name>wazuh-enterprise</name>
    <node_name>wazuh-master</node_name>
    <node_type>master</node_type>
    <key>GENERATE_WITH_openssl_rand_hex_16</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <node>192.168.10.20</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
</cluster>
```

### Worker Node — `ossec.conf` cluster stanza

```xml
<cluster>
    <name>wazuh-enterprise</name>
    <node_name>wazuh-worker01</node_name>
    <node_type>worker</node_type>
    <key>SAME_KEY_AS_MASTER</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
        <!-- Points to master IP -->
        <node>192.168.10.20</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
</cluster>
```

### Validation Commands

```bash
# Check cluster status
/var/ossec/bin/cluster_control -l

# Expected output:
# NAME            TYPE    VERSION  ADDRESS
# wazuh-master    master  4.x.x   192.168.10.20
# wazuh-worker01  worker  4.x.x   192.168.10.21

# Check cluster health
/var/ossec/bin/cluster_control -i
```

---

## 0.6 Wazuh Indexer Cluster Bootstrap

### Node 1 (Initial Master) — `/etc/wazuh-indexer/opensearch.yml`

```yaml
cluster.name: wazuh-indexer-cluster
node.name: indexer-node-1
node.roles:
  - master
  - data
  - ingest

network.host: 192.168.10.40
http.port: 9200
transport.port: 9300

discovery.seed_hosts:
  - 192.168.10.40
  - 192.168.10.41
  - 192.168.10.42

cluster.initial_master_nodes:
  - indexer-node-1
  - indexer-node-2
  - indexer-node-3

# Performance tuning
indices.query.bool.max_clause_count: 4096
indices.memory.index_buffer_size: 15%
thread_pool.write.queue_size: 1000

# Path configuration
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

# Security plugin
plugins.security.ssl.transport.pemcert_filepath: /etc/wazuh-indexer/certs/indexer-node-1.pem
plugins.security.ssl.transport.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-node-1-key.pem
plugins.security.ssl.transport.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: /etc/wazuh-indexer/certs/indexer-node-1.pem
plugins.security.ssl.http.pemkey_filepath: /etc/wazuh-indexer/certs/indexer-node-1-key.pem
plugins.security.ssl.http.pemtrustedcas_filepath: /etc/wazuh-indexer/certs/root-ca.pem

plugins.security.nodes_dn:
  - "CN=indexer-node-1,OU=Wazuh,O=Enterprise,L=Lisbon,C=PT"
  - "CN=indexer-node-2,OU=Wazuh,O=Enterprise,L=Lisbon,C=PT"
  - "CN=indexer-node-3,OU=Wazuh,O=Enterprise,L=Lisbon,C=PT"

plugins.security.authcz.admin_dn:
  - "CN=admin,OU=Wazuh,O=Enterprise,L=Lisbon,C=PT"

plugins.security.allow_default_init_securityindex: true
plugins.security.restapi.roles_enabled:
  - "all_access"
  - "security_rest_api_access"

compatibility.override_main_response_version: true
```

### JVM Tuning — `/etc/wazuh-indexer/jvm.options`

```
# Heap: 50% of RAM, never > 32GB
-Xms16g
-Xmx16g

# GC: G1GC for large heaps
-XX:+UseG1GC
-XX:G1HeapRegionSize=16m
-XX:InitiatingHeapOccupancyPercent=40
-XX:MaxGCPauseMillis=200

# Avoid swapping
-XX:+AlwaysPreTouch

# OOM handling
-XX:+HeapDumpOnOutOfMemoryError
-XX:HeapDumpPath=/var/lib/wazuh-indexer/heapdump
```

> **⚠️ PITFALL — `cluster.initial_master_nodes`:**  
> This setting is **only** used during the very first cluster bootstrap. After the cluster is formed, **remove it** from all nodes' configs. Leaving it in can cause accidental cluster re-bootstrapping during network partitions, leading to catastrophic data loss (split-brain).

---

## 0.7 Network Architecture

```
 ┌──────────────────────────────────────────────────┐
 │                 MANAGEMENT VLAN (10)              │
 │  SSH, Ansible, IPMI/iDRAC — Admin access only    │
 ├──────────────────────────────────────────────────┤
 │              SIEM BACKEND VLAN (20)               │
 │  Indexer cluster, inter-node, Filebeat → Indexer  │
 ├──────────────────────────────────────────────────┤
 │            SOC ANALYST VLAN (30)                   │
 │  Dashboard access, API queries                    │
 ├──────────────────────────────────────────────────┤
 │          AGENT INGESTION VLAN (40/DMZ)            │
 │  Agent → Manager :1514, :1515                     │
 └──────────────────────────────────────────────────┘
```
