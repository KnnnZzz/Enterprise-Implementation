# Wazuh 4.14 — 5-Day Zero-Tolerance SIEM Deployment Playbook

> **Classification:** Internal — SOC Engineering  
> **Version:** 1.0 | **Date:** 2026-05-19  
> **Target:** Small company · ≤200 endpoints · 1–3 SOC staff  
> **Architecture:** Single-node All-in-One (or optional 2-node split)  
> **Policy:** **Zero tolerance for missing critical alerts.**

---

## Architecture Overview

```
┌───────────────────────────────────────────┐
│         SINGLE SERVER (All-in-One)        │
│                                           │
│  ┌──────────┐  ┌───────────────────────┐  │
│  │  Wazuh   │  │   Wazuh Indexer       │  │
│  │  Manager │  │   (OpenSearch)        │  │
│  └──────────┘  └───────────────────────┘  │
│  ┌──────────┐  ┌───────────────────────┐  │
│  │ Filebeat │  │   Wazuh Dashboard     │  │
│  └──────────┘  └───────────────────────┘  │
└──────────────────┬────────────────────────┘
                   │
        ┌──────────┼──────────┐
   ┌────▼──┐  ┌────▼──┐  ┌───▼────┐
   │Agent  │  │Agent  │  │Syslog  │
   │(Linux)│  │(Win)  │  │Sources │
   └───────┘  └───────┘  │(FW/RT) │
                          └────────┘
```

---

## Sizing Recommendations

| Resource | Minimum (≤50 agents) | Recommended (50–200 agents) |
|---|---|---|
| vCPU | 4 | 8 |
| RAM | 8 GB | 16 GB |
| Disk | 200 GB **SSD** | 500 GB **NVMe** |
| OS | Ubuntu 24.04 LTS | Ubuntu 24.04 LTS |

> [!CAUTION]
> **NVMe/SSD is mandatory.** The Wazuh Indexer (OpenSearch) will grind to a halt on spinning disks at any meaningful event volume. This is the #1 deployment failure for first-timers.

---

## 5-Day Timeline

| Day | Document | Goal |
|---|---|---|
| **Day 1** | [Infrastructure & Base Install](./DAY1_Infrastructure_and_Base_Install.md) | Ubuntu hardened, Wazuh stack running, dashboard online, passwords changed |
| **Day 2** | [Multi-Tenancy & Server Agents](./DAY2_MultiTenancy_and_Server_Agents.md) | Agent groups created, Linux/Windows servers enrolled, FIM/SCA/Vuln active |
| **Day 3** | [Firewalls & Router Integration](./DAY3_Firewalls_and_Router_Integration.md) | Network device syslog ingested, parsed, decoded, and generating alerts |
| **Day 4** | [MISP Threat Intelligence](./DAY4_MISP_Threat_Intelligence.md) | MISP connected, IoC matching live, CDB blocklists populated |
| **Day 5** | [Tuning & Alerting (Zero-Tolerance)](./DAY5_Tuning_and_Alerting.md) | Noise suppressed, critical rules elevated, Slack/Teams/Email notifications live |

---

## Prerequisites (Prepare Before Day 1)

- [ ] VM provisioned with Ubuntu 24.04 LTS (minimal server install)
- [ ] Static IP assigned (e.g., `192.168.10.20`)
- [ ] SSH access configured (key-based, root disabled)
- [ ] DNS record for Dashboard (e.g., `wazuh.company.local`)
- [ ] Firewall ports pre-opened: `1514/TCP`, `1515/TCP`, `443/TCP`, `55000/TCP`, `514/UDP` (syslog)
- [ ] NTP/chrony running and time-synced
- [ ] Internet access for package downloads
- [ ] Inventory list of all endpoints (IP, OS, role, criticality)
- [ ] MISP instance URL and API key (for Day 4)
- [ ] Firewall admin credentials for syslog forwarding (for Day 3)
- [ ] Notification webhook URLs — Slack/Teams channel or Telegram bot token (for Day 5)

---

## Key Paths Reference

| Component | Path |
|---|---|
| Manager config | `/var/ossec/etc/ossec.conf` |
| Custom rules | `/var/ossec/etc/rules/local_rules.xml` |
| Custom decoders | `/var/ossec/etc/decoders/` |
| CDB lists | `/var/ossec/etc/lists/` |
| Agent group configs | `/var/ossec/etc/shared/<group>/agent.conf` |
| Integration scripts | `/var/ossec/integrations/` |
| Manager logs | `/var/ossec/logs/ossec.log` |
| Alert logs | `/var/ossec/logs/alerts/alerts.json` |
| Indexer config | `/etc/wazuh-indexer/opensearch.yml` |
| Dashboard config | `/etc/wazuh-dashboard/opensearch_dashboards.yml` |
| Filebeat config | `/etc/filebeat/filebeat.yml` |
| Enrollment password | `/var/ossec/etc/authd.pass` |

---

## Top 10 Pitfalls for 1-Week Rapid Deployments

| # | Mistake | Impact | Fix |
|---|---|---|---|
| 1 | Using `127.0.0.1` in `config.yml` | Agents can't connect | Use the LAN IP that agents can reach |
| 2 | Forgetting to open `1514/TCP` | Silent agent failure | Open port before enrolling agents |
| 3 | No enrollment password set | Rogue agent enrollment | Set `authd.pass` immediately |
| 4 | No ISM/retention policy | Disk fills in weeks | Configure on Day 1 |
| 5 | Not backing up `client.keys` | Lost = re-enroll everything | Automate daily backups |
| 6 | Default `admin` password unchanged | Trivial unauthorized access | Change immediately after install |
| 7 | Swap enabled on indexer node | OpenSearch performance collapse | `swapoff -a` before install |
| 8 | Editing files in `ruleset/rules/` | Overwritten on upgrades | Always use `etc/rules/` |
| 9 | `log_alert_level` set to 1 (default) | Floods indexer with noise | Set to `6` minimum |
| 10 | No NTP sync | Timestamps wrong, correlation breaks | Configure chrony first |

---

> **Strategy:** Do NOT try to do everything at once. Follow the daily structure. Each day builds on the previous. If you skip ahead, you will spend all week troubleshooting instead of deploying.
