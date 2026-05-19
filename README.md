# Enterprise-Implementation

# Wazuh Enterprise SOC Deployment Playbook

> **Version:** 1.0 | **Date:** 2026-05-19  
> **Classification:** Internal — SOC Engineering  
> **Target:** Production-grade, High-Availability Wazuh 4.x SIEM/XDR

---

## Playbook Structure

This playbook is organized into 6 sequential phases. Follow them linearly from infrastructure provisioning through to operational sign-off.

| Phase | Document | Scope |
|---|---|---|
| **Phase 0** | [Architecture & Sizing](./00_PHASE0_Architecture_and_Sizing.md) | HA architecture, hardware sizing, load balancing, indexer/manager cluster bootstrap, network topology |
| **Phase 1** | [Infrastructure Security & Hardening](./01_PHASE1_Infrastructure_Security_and_Hardening.md) | Firewall port matrix, mTLS certificates, OS hardening, RBAC, SSO/SAML (Entra ID), SIEM self-auditing |
| **Phase 2** | [Core Configuration & Agent Deployment](./02_PHASE2_Core_Configuration_and_Agents.md) | Automated deployment (Ansible/SCCM), agent grouping taxonomy, FIM/SCA/Vuln/Syscollector tuning, analysis engine optimization |
| **Phase 3** | [Customization, Tuning & SOC Operations](./03_PHASE3_Customization_Tuning_and_SOC_Ops.md) | Custom decoders/rules, CDB lists, alert fatigue strategies, ISM/ILM policies, backup & disaster recovery |
| **Phase 4** | [Enterprise Integrations](./04_PHASE4_Enterprise_Integrations.md) | MISP, VirusTotal, TheHive, Jira, SOAR (Shuffle/n8n), AWS CloudTrail, Azure AD, O365, Fortinet/PaloAlto, Telegram |
| **Phase 5** | [Validation, Monitoring & Pitfalls](./05_PHASE5_Validation_Monitoring_and_Pitfalls.md) | Post-deployment tests, self-monitoring, 25-item pitfalls compendium, linear execution checklist |

---

## Key Design Decisions

- **Indexer Cluster:** 3-node minimum (odd quorum) to prevent split-brain.
- **Manager Cluster:** Master/Worker topology; enrollment routed exclusively to master.
- **TLS Everywhere:** mTLS for inter-component communication; no plaintext channels.
- **Secrets Management:** API keys loaded from secure files at runtime, never in `ossec.conf` plaintext.
- **MISP Integration:** Dual-mode — real-time API lookups (`custom-misp_file_hashes.py`) + batch CDB list sync (`misp-cdb-sync.py`).
- **Alert Fatigue:** Tiered severity framework (L0–L15) with CDB-based suppression for known-good entities.

## Prerequisites

- Ubuntu 22.04/24.04 LTS (recommended) or RHEL 8/9
- Minimum 3 VMs for Indexer, 2 for Manager, 2 for Dashboard, 1 for HAProxy
- Internal PKI or `wazuh-certs-tool` for certificate generation
- Network segmentation (Management, Backend, SOC, Agent VLANs)
- NTP/Chrony synchronized across all nodes (UTC)
