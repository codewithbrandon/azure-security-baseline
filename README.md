# Azure Security Baseline

[![Security Audit](https://github.com/codewithbrandon/azure-security-baseline/actions/workflows/security-audit.yml/badge.svg)](https://github.com/codewithbrandon/azure-security-baseline/actions/workflows/security-audit.yml)
[![Terraform](https://img.shields.io/badge/Terraform-≥1.5-7B42BC?logo=terraform)](https://developer.hashicorp.com/terraform)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A reproducible Azure security baseline that provisions a hardened environment and immediately audits it —
demonstrating the gap between default configuration and production-ready posture.

Built for security architects who need to show clients exactly what "misconfigured" looks like before they hand over a remediation roadmap.

---

## What This Does

Most Azure environments are deployed fast and secured slowly. The gap between those two events is where breaches happen.

This project makes that gap visible. It provisions a realistic three-tier Azure environment with intentional, documented misconfigurations — the same ones found repeatedly in the wild — then runs an automated audit that classifies every finding by severity, maps it to a MITRE ATT&CK technique, and produces a client-ready remediation report.

**The output is not a compliance checkbox. It is a proof that the analyst understands what the misconfiguration means and how to fix it.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Azure Subscription                                         │
│                                                             │
│  ┌─── Resource Group ──────────────────────────────────┐   │
│  │                                                      │   │
│  │  ┌── VNet (10.0.0.0/16) ────────────────────────┐  │   │
│  │  │                                               │  │   │
│  │  │  [web-subnet 10.0.1.0/24] ←── web-nsg        │  │   │
│  │  │  [app-subnet 10.0.2.0/24] ←── app-nsg        │  │   │
│  │  │  [data-subnet 10.0.3.0/24] ←── data-nsg      │  │   │
│  │  │                                               │  │   │
│  │  └───────────────────────────────────────────────┘  │   │
│  │                                                      │   │
│  │  ┌── Logging ──────────────────────────────────┐    │   │
│  │  │  Log Analytics Workspace                    │    │   │
│  │  │  ├── Entra ID Audit Logs (sign-ins, changes)│    │   │
│  │  │  ├── Azure Activity Log (control plane)     │    │   │
│  │  │  └── Storage Account (long-term archival)   │    │   │
│  │  └─────────────────────────────────────────────┘    │   │
│  │                                                      │   │
│  │  ┌── Defender for Cloud ───────────────────────┐    │   │
│  │  │  Standard tier: VMs, SQL, Storage,          │    │   │
│  │  │  Containers, KeyVaults, AppServices, ARM     │    │   │
│  │  └─────────────────────────────────────────────┘    │   │
│  │                                                      │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Intentional Misconfigurations

The default Terraform configuration provisions the following findings for the audit script to catch.
These match patterns from real breach investigations — not synthetic examples.

| Finding | Severity | MITRE | Why It Matters |
|---------|----------|-------|----------------|
| RDP (3389) open to 0.0.0.0/0 | CRITICAL | T1021.001 | Most brute-forced port on Azure; interactive desktop if compromised |
| Database ports open to 0.0.0.0/0 | CRITICAL | T1190 | Direct data exfiltration; MongoDB/Redis have no auth by default |
| SSH (22) open to 0.0.0.0/0 | HIGH | T1021.004 | Automated credential stuffing; OpenSSH vulnerability surface |
| Management port open to VirtualNetwork | MEDIUM | T1021 | Broader scope than intended; includes all peered VNets |
| Missing explicit deny-all rule | MEDIUM | T1190 | Azure's implicit deny is not auditable by compliance frameworks |

To provision the **hardened** configuration (findings resolved), set these variables:

```hcl
# terraform/terraform.tfvars
allowed_ssh_cidrs = ["10.0.10.5/32"]   # Bastion or admin workstation IP
allowed_rdp_cidrs = []                 # Use Azure Bastion — no direct RDP
```

---

## Quick Start

### Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) + active subscription
- Python 3.12+

### 1 — Authenticate

```bash
az login
az account set --subscription <your-subscription-id>
```

### 2 — Provision the Environment

```bash
make init
make plan     # Review what will be created
make apply    # Creates the resource group, VNet, NSGs, logging, and Defender
```

### 3 — Run the Audit

```bash
make audit RG=azsec-lab-rg
```

Output:

```
======================================================================
  AZURE NSG SECURITY AUDIT
  Resource Group : azsec-lab-rg
  Timestamp      : 2026-03-10 14:22 UTC
======================================================================
  Risk Score  : 47/100
  Total       :  7

  CRITICAL  :   3
  HIGH      :   1
  MEDIUM    :   3
  LOW       :   0
  INFO      :   0
======================================================================

  FINDINGS:

  [ !! ] CRITICAL pri= 200  azsec-lab-data-nsg
             Rule: AllowDB-ANY
             Type: OPEN_HIGH_RISK_PORT

  [ !! ] CRITICAL pri= 300  azsec-lab-web-nsg
             Rule: AllowRDP-ANY
             Type: OPEN_HIGH_RISK_PORT
  ...

  STATUS: FAIL — Critical findings require immediate remediation before deployment.
======================================================================
```

### 4 — Generate the Report

```bash
make report
# Writes: reports/AUDIT-20260310.md
```

The report includes:
- Executive summary with risk score
- Per-finding detail with description, MITRE technique, and remediation steps
- MITRE ATT&CK coverage table
- Remediation checklist (copy directly into a ticket)
- Re-audit instructions

---

## Project Structure

```
azure-security-baseline/
├── terraform/
│   ├── main.tf                     # Root module: resource group + module calls
│   ├── variables.tf                # Input variables with validation
│   ├── outputs.tf                  # Outputs including audit command
│   ├── providers.tf                # AzureRM, AzureAD, Random providers
│   └── modules/
│       ├── networking/             # VNet, subnets, NSGs (with intentional findings)
│       ├── logging/                # Log Analytics, Entra ID audit logs, storage
│       └── security/               # Defender for Cloud, policy assignments
│
├── scripts/
│   ├── nsg_analyzer.py             # Core audit engine — connects to Azure, runs checks
│   ├── generate_report.py          # Converts JSON findings to Markdown report
│   └── requirements.txt
│
├── reports/
│   └── findings_template.md        # Hand-editable report template with example findings
│
├── .github/workflows/
│   └── security-audit.yml          # CI: lint → validate → live NSG audit → artifact
│
└── Makefile                        # init, plan, apply, audit, report, lint, destroy
```

---

## CI Pipeline

Every push to `main` and every pull request triggers:

1. **Ruff** — Python linting and format check
2. **Terraform fmt** — configuration style enforcement
3. **Terraform validate** — syntax and configuration validation
4. **tfsec** — IaC security scan (catches NSG misconfiguration at plan time)
5. **Gitleaks** — secret detection across full git history
6. **Live NSG Audit** — connects to Azure via OIDC (no stored credentials), runs the Python audit script, uploads findings as a 90-day artifact

The pipeline fails if any `HIGH` or `CRITICAL` findings are detected. This enforces security posture as a gate, not an afterthought.

**Authentication:** The CI pipeline uses Azure OIDC (federated identity) — no `AZURE_CLIENT_SECRET` is stored anywhere.

---

## Audit Findings Reference

### Finding Types

| Type | Severity Range | Description |
|------|---------------|-------------|
| `OPEN_HIGH_RISK_PORT` | MEDIUM–CRITICAL | Known dangerous port reachable from internet |
| `ALLOW_ALL_INBOUND` | CRITICAL | Rule allows all traffic from any source — no effective firewall |
| `BROAD_SOURCE_MANAGEMENT_PORT` | MEDIUM | Management port accessible from VirtualNetwork scope |
| `UNRESTRICTED_OUTBOUND` | LOW | All ports allowed outbound — enables data exfiltration |
| `MISSING_EXPLICIT_DENY_ALL` | MEDIUM | Relies on implicit Azure deny; not auditable by compliance frameworks |

### Risk Score Formula

```
Risk Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)
```

| Score | Rating |
|-------|--------|
| 30+ | CRITICAL RISK — Immediate action |
| 15–29 | HIGH RISK — Remediate within 72 hours |
| 5–14 | MEDIUM RISK — Next sprint |
| 1–4 | LOW RISK — Planned maintenance |
| 0 | PASS |

---

## Extending the Audit

To add a new check to `nsg_analyzer.py`:

```python
def check_your_condition(nsg, rule, findings: list) -> None:
    """Description of what this checks and why it matters."""
    if <your_condition>:
        findings.append(make_finding(
            nsg_name=nsg.name,
            resource_id=nsg.id,
            rule_name=rule.name,
            severity="HIGH",
            finding_type="YOUR_FINDING_TYPE",
            description="What is misconfigured and what an attacker can do with it.",
            mitre_technique="T1XXX — Technique Name",
            remediation="Step-by-step: how to fix it.",
        ))
```

Then call it from `analyze_nsg()`.

---

## Related Projects

- [cloud-threat-detection](https://github.com/codewithbrandon/cloud-threat-detection) — Kubernetes-native threat detection platform with Falco, Prometheus, and Loki
- [secure-cloud-platform](https://github.com/codewithbrandon/secure-cloud-platform) — Policy-enforced DevSecOps pipeline with OPA/Conftest and 19-stage Jenkins CI

---

## Author

**Brandon** — Independent Security Architect
Former Top Secret Cleared Investigator | CompTIA Security+ | RHCSA | Azure Cloud Engineer (in pursuit)

Available for security architecture engagements. [Connect on LinkedIn](https://linkedin.com/in/your-handle)

---

*MIT License*
