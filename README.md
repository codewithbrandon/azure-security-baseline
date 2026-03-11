# Azure Security Baseline

[![Security Audit](https://github.com/codewithbrandon/azure-security-baseline/actions/workflows/security-audit.yml/badge.svg)](https://github.com/codewithbrandon/azure-security-baseline/actions/workflows/security-audit.yml)
[![Terraform](https://img.shields.io/badge/Terraform-≥1.5-7B42BC?logo=terraform)](https://developer.hashicorp.com/terraform)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A reproducible Azure security baseline that provisions a hardened environment and immediately audits it,
demonstrating the gap between default configuration and production-ready posture.

Built for security architects who need to show clients exactly what "misconfigured" looks like before handing over a remediation roadmap.

---

## What This Does

Most Azure environments are deployed fast and secured slowly. The gap between those two events is where breaches happen.

This project makes that gap visible. It provisions a realistic three-tier Azure environment with intentional, documented misconfigurations — the same ones found repeatedly in real breach investigations — then runs an automated audit that classifies every finding by severity, maps it to a MITRE ATT&CK technique, and produces a client-ready remediation report.

**The output is not a compliance checkbox. It is proof that the analyst understands what the misconfiguration means and how to fix it.**

---

## Architecture

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                          AZURE SUBSCRIPTION                                  ║
║                                                                              ║
║  ╔═══════════════════════════════════════════════════════════════════════╗   ║
║  ║                         RESOURCE GROUP                               ║   ║
║  ║                                                                       ║   ║
║  ║   ┌─────────────────────────────┐   ┌───────────────────────────┐   ║   ║
║  ║   │       NETWORK (VNet)        │   │    LOG ANALYTICS          │   ║   ║
║  ║   │       10.0.0.0/16           │   │    WORKSPACE              │   ║   ║
║  ║   │                             │   │                           │   ║   ║
║  ║   │  INTERNET                   │   │  ▸ Entra ID Sign-in Logs  │   ║   ║
║  ║   │      │                      │   │  ▸ Entra ID Audit Logs    │   ║   ║
║  ║   │  ┌───▼──────────────────┐   │   │  ▸ Azure Activity Log     │   ║   ║
║  ║   │  │  web-nsg             │◄──┼───┼─ NSG Flow Logs            │   ║   ║
║  ║   │  │  ✔ :443  :80         │   │   │                           │   ║   ║
║  ║   │  │  ✘ :3389 open  CRIT  │   │   │  Storage Account          │   ║   ║
║  ║   │  │  ✘ :22   open  HIGH  │   │   │  ▸ 90-day log archival    │   ║   ║
║  ║   │  └───┬──────────────────┘   │   └───────────────────────────┘   ║   ║
║  ║   │      │                      │                                    ║   ║
║  ║   │  ┌───▼──────────────────┐   │   ┌───────────────────────────┐   ║   ║
║  ║   │  │  web-subnet          │   │   │    DEFENDER FOR CLOUD     │   ║   ║
║  ║   │  │  10.0.1.0/24         │   │   │    Standard Tier           │   ║   ║
║  ║   │  └───┬──────────────────┘   │   │                           │   ║   ║
║  ║   │      │ :8080               │   │  ▸ Virtual Machines        │   ║   ║
║  ║   │  ┌───▼──────────────────┐   │   │  ▸ SQL Servers            │   ║   ║
║  ║   │  │  app-nsg             │   │   │  ▸ Storage Accounts       │   ║   ║
║  ║   │  │  ✔ :8080 from web    │   │   │  ▸ Containers             │   ║   ║
║  ║   │  │  ✘ :8443 VNet  MED   │   │   │  ▸ Key Vaults             │   ║   ║
║  ║   │  └───┬──────────────────┘   │   │  ▸ App Services           │   ║   ║
║  ║   │      │                      │   │  ▸ ARM   ▸ DNS             │   ║   ║
║  ║   │  ┌───▼──────────────────┐   │   └───────────────────────────┘   ║   ║
║  ║   │  │  app-subnet          │   │                                    ║   ║
║  ║   │  │  10.0.2.0/24         │   │   ┌───────────────────────────┐   ║   ║
║  ║   │  └───┬──────────────────┘   │   │    POLICY ASSIGNMENTS     │   ║   ║
║  ║   │      │ :1433 :5432          │   │                           │   ║   ║
║  ║   │      │ :27017 :6379         │   │  ▸ Require HTTPS storage  │   ║   ║
║  ║   │  ┌───▼──────────────────┐   │   │  ▸ Block VM public IPs    │   ║   ║
║  ║   │  │  data-nsg            │   │   │  ▸ Enforce allowed regions │   ║   ║
║  ║   │  │  ✔ DB from app only  │   │   └───────────────────────────┘   ║   ║
║  ║   │  │  ✘ DB open 0.0.0.0/0 │   │                                    ║   ║
║  ║   │  │    CRITICAL FINDING  │   │                                    ║   ║
║  ║   │  └───┬──────────────────┘   │                                    ║   ║
║  ║   │      │                      │                                    ║   ║
║  ║   │  ┌───▼──────────────────┐   │                                    ║   ║
║  ║   │  │  data-subnet         │   │                                    ║   ║
║  ║   │  │  10.0.3.0/24         │   │                                    ║   ║
║  ║   │  └──────────────────────┘   │                                    ║   ║
║  ║   └─────────────────────────────┘                                    ║   ║
║  ╚═══════════════════════════════════════════════════════════════════════╝   ║
╚══════════════════════════════════════════════════════════════════════════════╝

  AUDIT WORKFLOW
  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
  │  nsg_analyzer   │────►│  findings.json  │────►│ generate_report │
  │  .py            │     │  risk score     │     │  .py            │
  │                 │     │  MITRE mapping  │     │                 │
  │  Azure SDK      │     │  remediation    │     │  AUDIT-DATE.md  │
  │  DefaultCred    │     │  steps          │     │  client-ready   │
  └─────────────────┘     └─────────────────┘     └─────────────────┘
        │ az login / OIDC / Managed Identity
        ▼
   Azure Resource Manager API
```

---

## Intentional Misconfigurations

The default Terraform configuration provisions the following findings for the audit script to catch.
These match patterns from real breach investigations, not synthetic examples.

| Finding | Severity | MITRE | Why It Matters |
|---------|----------|-------|----------------|
| RDP (3389) open to 0.0.0.0/0 | CRITICAL | T1021.001 | Most brute-forced port on Azure; interactive desktop access if compromised |
| Database ports open to 0.0.0.0/0 | CRITICAL | T1190 | Direct data exfiltration; MongoDB and Redis have no auth by default |
| SSH (22) open to 0.0.0.0/0 | HIGH | T1021.004 | Automated credential stuffing; persistent OpenSSH vulnerability surface |
| Management port open to VirtualNetwork | MEDIUM | T1021 | Broader scope than intended; includes all peered VNets |
| Missing explicit deny-all rule | MEDIUM | T1190 | Azure's implicit deny is not auditable by compliance frameworks |

To provision the **hardened** configuration with findings resolved, set these variables:

```hcl
# terraform/terraform.tfvars
allowed_ssh_cidrs = ["10.0.10.5/32"]   # Bastion or admin workstation IP
allowed_rdp_cidrs = []                 # Use Azure Bastion instead of direct RDP
```

---

## Quick Start

### Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >= 1.5
- [Azure CLI](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli) with an active subscription
- Python 3.12+

### 1. Authenticate

```bash
az login
az account set --subscription <your-subscription-id>
```

### 2. Provision the Environment

```bash
make init
make plan     # Review what will be created
make apply    # Creates the resource group, VNet, NSGs, logging, and Defender
```

### 3. Run the Audit

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

### 4. Generate the Report

```bash
make report
# Writes: reports/AUDIT-20260310.md
```

The report includes an executive summary with a risk score, per-finding detail with MITRE technique mapping and remediation steps, a full ATT&CK coverage table, and a remediation checklist you can paste directly into a ticket.

---

## Project Structure

```
azure-security-baseline/
├── terraform/
│   ├── main.tf                     # Root module — resource group and module calls
│   ├── variables.tf                # Input variables with validation
│   ├── outputs.tf                  # Outputs including the audit command
│   ├── providers.tf                # AzureRM, AzureAD, and Random providers
│   ├── example.tfvars              # Reference variable file safe to commit
│   └── modules/
│       ├── networking/             # VNet, subnets, and NSGs with intentional findings
│       ├── logging/                # Log Analytics, Entra ID audit logs, and storage
│       └── security/               # Defender for Cloud and policy assignments
│
├── scripts/
│   ├── nsg_analyzer.py             # Audit engine — connects to Azure and runs all checks
│   ├── generate_report.py          # Converts JSON findings into a Markdown report
│   └── requirements.txt
│
├── reports/
│   └── findings_template.md        # Hand-editable report with annotated example findings
│
├── .github/workflows/
│   └── security-audit.yml          # CI pipeline — lint, validate, live audit, artifact upload
│
└── Makefile                        # Targets: init, plan, apply, audit, report, lint, destroy
```

---

## CI Pipeline

Every push to `main` and every pull request triggers the following jobs in sequence:

1. **Ruff** lints and checks formatting across all Python scripts
2. **Terraform fmt** enforces configuration style
3. **Terraform validate** confirms syntax and provider compatibility
4. **tfsec** scans the IaC for security issues at plan time, before anything is provisioned
5. **Gitleaks** scans the full git history for accidentally committed secrets
6. **Live NSG Audit** authenticates to Azure via OIDC, runs the Python audit script, and uploads findings as a 90-day artifact

The pipeline fails if any `HIGH` or `CRITICAL` findings are detected, enforcing security posture as a gate rather than an afterthought.

Authentication uses Azure OIDC federated identity. No `AZURE_CLIENT_SECRET` is stored anywhere.

---

## Audit Findings Reference

### Finding Types

| Type | Severity | Description |
|------|----------|-------------|
| `OPEN_HIGH_RISK_PORT` | MEDIUM to CRITICAL | Known dangerous port reachable from the internet |
| `ALLOW_ALL_INBOUND` | CRITICAL | Rule allows all traffic from any source, effectively disabling the NSG |
| `BROAD_SOURCE_MANAGEMENT_PORT` | MEDIUM | Management port reachable from VirtualNetwork scope rather than a specific CIDR |
| `UNRESTRICTED_OUTBOUND` | LOW | All ports allowed outbound, enabling data exfiltration |
| `MISSING_EXPLICIT_DENY_ALL` | MEDIUM | Relies on Azure's implicit deny, which is not auditable by compliance frameworks |

### Risk Score Formula

```
Risk Score = (CRITICAL × 10) + (HIGH × 5) + (MEDIUM × 2) + (LOW × 1)
```

| Score | Rating |
|-------|--------|
| 30+ | CRITICAL RISK — Immediate action required |
| 15 to 29 | HIGH RISK — Remediate within 72 hours |
| 5 to 14 | MEDIUM RISK — Address in the next sprint |
| 1 to 4 | LOW RISK — Planned maintenance window |
| 0 | PASS |

---

## Extending the Audit

To add a new check to `nsg_analyzer.py`, define a function and call it from `analyze_nsg()`:

```python
def check_your_condition(nsg, rule, findings: list) -> None:
    """Describe what this detects and why it matters operationally."""
    if <your_condition>:
        findings.append(make_finding(
            nsg_name=nsg.name,
            resource_id=nsg.id,
            rule_name=rule.name,
            severity="HIGH",
            finding_type="YOUR_FINDING_TYPE",
            description="What is misconfigured and what an attacker can do with it.",
            mitre_technique="T1XXX — Technique Name",
            remediation="Concrete steps to resolve the finding.",
        ))
```

---

## Related Projects

- [cloud-threat-detection](https://github.com/codewithbrandon/cloud-threat-detection) — Kubernetes-native threat detection platform with Falco, Prometheus, and Loki
- [secure-cloud-platform](https://github.com/codewithbrandon/secure-cloud-platform) — Policy-enforced DevSecOps pipeline with OPA/Conftest and a 19-stage Jenkins CI workflow

---

## Author

**Brandon** — Independent Security Architect
Former Top Secret Cleared Investigator | CompTIA Security+ | RHCSA | Azure Cloud Engineer (in pursuit)

Available for security architecture engagements. [Connect on LinkedIn](https://linkedin.com/in/your-handle)

---

*MIT License*
