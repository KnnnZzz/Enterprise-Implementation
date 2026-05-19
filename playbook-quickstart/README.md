# Wazuh SIEM — 3-Day Enterprise Deployment (Small Company)

> **Version:** 1.0 | **Date:** 2026-05-19  
> **Target:** Small/Mid-size company (50–500 endpoints, 1–5 SOC staff)  
> **Timeline:** 3 working days — bare metal/VM to fully operational SIEM  
> **Architecture:** Single-node all-in-one OR minimal 2-node split

---

## Deployment Timeline

| Day | Focus | Outcome |
|---|---|---|
| **Day 1** | [Infrastructure + Core Install](./DAY1_Infrastructure_and_Install.md) | Wazuh stack running, certificates, hardened OS, first agents connected |
| **Day 2** | [Configuration, Rules & Agents](./DAY2_Configuration_Rules_and_Agents.md) | Fleet enrolled, FIM/SCA/Vuln active, custom rules deployed, CDB lists, alert tuning |
| **Day 3** | [Integrations, Backups & Go-Live](./DAY3_Integrations_Backups_and_GoLive.md) | MISP/VT integrated, notifications configured, backups automated, validation complete |

---

## Architecture Decision

### Option A: All-in-One (≤ 100 agents) — Recommended for fastest deployment

```
┌──────────────────────────────────────┐
│        SINGLE SERVER (AIO)           │
│                                      │
│  ┌──────────┐  ┌──────────────────┐  │
│  │ Wazuh    │  │ Wazuh Indexer    │  │
│  │ Manager  │  │ (OpenSearch)     │  │
│  └──────────┘  └──────────────────┘  │
│  ┌──────────┐  ┌──────────────────┐  │
│  │ Filebeat │  │ Wazuh Dashboard  │  │
│  └──────────┘  └──────────────────┘  │
└──────────────┬───────────────────────┘
               │ :1514 (agents)
               │ :443  (dashboard)
               │ :55000 (API)
        ┌──────┼──────┐
   ┌────▼──┐ ┌─▼───┐ ┌▼──────┐
   │Agent  │ │Agent│ │Syslog │
   │(Linux)│ │(Win)│ │Sources│
   └───────┘ └─────┘ └───────┘
```

| Resource | Minimum | Recommended |
|---|---|---|
| vCPU | 4 | 8 |
| RAM | 8 GB | 16 GB |
| Disk | 200 GB SSD | 500 GB NVMe |
| OS | Ubuntu 22.04/24.04 LTS | Ubuntu 24.04 LTS |

### Option B: 2-Node Split (100–500 agents)

```
┌─────────────────┐     ┌─────────────────────┐
│  Node 1:        │     │  Node 2:            │
│  Manager +      │────▶│  Indexer +           │
│  Filebeat       │9200 │  Dashboard           │
│  :1514, :1515   │     │  :443, :9200         │
└────────┬────────┘     └─────────────────────┘
         │
    ┌────▼────┐
    │ Agents  │
    └─────────┘
```

| Node | vCPU | RAM | Disk |
|---|---|---|---|
| Node 1 (Manager) | 4–8 | 8–16 GB | 200 GB SSD |
| Node 2 (Indexer + Dashboard) | 8 | 16 GB | 500 GB NVMe |

---

## Prerequisites (prepare before Day 1)

- [ ] VM(s) provisioned with Ubuntu 22.04/24.04 LTS
- [ ] Static IP assigned
- [ ] SSH access configured (key-based)
- [ ] DNS record for Dashboard (e.g., `wazuh.company.local`)
- [ ] Firewall ports opened: `1514/TCP`, `1515/TCP`, `443/TCP`, `55000/TCP`
- [ ] NTP/chrony configured and synced
- [ ] Internet access for package downloads
- [ ] List of endpoints to protect (IPs, OS types, criticality)
