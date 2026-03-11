# Azure Security Baseline Audit Report
<!-- This is a hand-editable template. For automated reports, use generate_report.py -->

**Client:** [CLIENT NAME]
**Resource Group:** `[RESOURCE GROUP]`
**Audit Date:** [YYYY-MM-DD]
**Subscription:** `[SUBSCRIPTION ID]`
**Auditor:** Brandon | Independent Security Architect
**NSGs Audited:** `[nsg-name-1]`, `[nsg-name-2]`

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Overall Risk | 🔴 **CRITICAL RISK** |
| Risk Score | **XX / 100** |
| Total Findings | X |
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

### Key Observations

- **X Critical findings** represent immediate breach risk and must be resolved before this environment handles customer data.
- **Database ports are exposed to the internet.** Unauthenticated access to database services enables immediate data exfiltration without credential compromise.
- Defender for Cloud is operating in **Free tier only** — behavioral threat detection is not active.

---

## Findings Summary

| # | Severity | NSG | Rule | Type |
|---|----------|-----|------|------|
| 1 | 🔴 CRITICAL | `prod-data-nsg` | `AllowDB-ANY` | OPEN_HIGH_RISK_PORT |
| 2 | 🔴 CRITICAL | `prod-web-nsg` | `AllowRDP-ANY` | OPEN_HIGH_RISK_PORT |
| 3 | 🟠 HIGH | `prod-web-nsg` | `AllowSSH-ANY` | OPEN_HIGH_RISK_PORT |
| 4 | 🟡 MEDIUM | `prod-app-nsg` | `AllowMgmt-VNet` | BROAD_SOURCE_MANAGEMENT_PORT |
| 5 | 🟡 MEDIUM | `prod-data-nsg` | N/A | MISSING_EXPLICIT_DENY_ALL |

---

## Detailed Findings

### Finding 1 — OPEN_HIGH_RISK_PORT

| Field | Value |
|-------|-------|
| **Severity** | 🔴 CRITICAL |
| **NSG** | `prod-data-nsg` |
| **Rule** | `AllowDB-ANY` |
| **Priority** | `200` |
| **MITRE ATT&CK** | `T1190 — Exploit Public-Facing Application` |

**Description:**

> Rule 'AllowDB-ANY' (priority 200) allows PostgreSQL (port 5432), MSSQL (port 1433), MongoDB (port 27017), and Redis (port 6379) inbound from any source (0.0.0.0/0). This exposes the data tier to automated credential scanning and direct exploitation. Unauthenticated MongoDB and Redis instances are trivially accessible — no credentials required in default configurations.

**Remediation:**

> Delete rule `AllowDB-ANY` immediately. The correct rule (`AllowDB-FromAppTier`) already exists at priority 100 and restricts database access to the app subnet only. This was likely a temporary debug rule that was never removed. Conduct a git history review of the NSG configuration to determine when this rule was added and whether data was accessed during the exposure window.

<details>
<summary>Resource ID</summary>

```
/subscriptions/XXXX/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/prod-data-nsg
```

</details>

---

### Finding 2 — OPEN_HIGH_RISK_PORT

| Field | Value |
|-------|-------|
| **Severity** | 🔴 CRITICAL |
| **NSG** | `prod-web-nsg` |
| **Rule** | `AllowRDP-ANY` |
| **Priority** | `300` |
| **MITRE ATT&CK** | `T1021.001 — Remote Desktop Protocol` |

**Description:**

> Rule 'AllowRDP-ANY' (priority 300) allows RDP (port 3389) from any internet source. RDP is the most commonly brute-forced port on Azure — Shodan indexes exposed RDP endpoints within minutes of provisioning. Successful brute force grants interactive desktop access with the compromised account's privileges.

**Remediation:**

> Remove this rule and route all RDP access through Azure Bastion (fully managed RDP/SSH proxy with no public port exposure). If Bastion is not available, restrict source to a specific /32 admin workstation IP and enable MFA on all accounts with RDP access. Log all RDP sessions to Log Analytics.

<details>
<summary>Resource ID</summary>

```
/subscriptions/XXXX/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/prod-web-nsg
```

</details>

---

### Finding 3 — OPEN_HIGH_RISK_PORT

| Field | Value |
|-------|-------|
| **Severity** | 🟠 HIGH |
| **NSG** | `prod-web-nsg` |
| **Rule** | `AllowSSH-ANY` |
| **Priority** | `200` |
| **MITRE ATT&CK** | `T1021.004 — SSH` |

**Description:**

> Rule 'AllowSSH-ANY' (priority 200) allows SSH (port 22) from any source. SSH brute force is fully automated — credential stuffing tools test millions of username/password combinations against exposed SSH endpoints continuously. Weak or reused credentials result in immediate shell access.

**Remediation:**

> Restrict SSH to a specific bastion host CIDR or deploy Azure Bastion. If key-based authentication is already enforced, elevate to HIGH severity regardless — port exposure still enables vulnerability exploitation (e.g., OpenSSH CVEs) and consumes log noise that obscures real threats. Disable password authentication in `/etc/ssh/sshd_config` as a compensating control.

<details>
<summary>Resource ID</summary>

```
/subscriptions/XXXX/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/prod-web-nsg
```

</details>

---

### Finding 4 — BROAD_SOURCE_MANAGEMENT_PORT

| Field | Value |
|-------|-------|
| **Severity** | 🟡 MEDIUM |
| **NSG** | `prod-app-nsg` |
| **Rule** | `AllowMgmt-VNet` |
| **Priority** | `200` |
| **MITRE ATT&CK** | `T1021 — Remote Services` |

**Description:**

> Rule 'AllowMgmt-VNet' allows management port 8443 from source 'VirtualNetwork'. The 'VirtualNetwork' service tag encompasses all peered VNets, VPN-connected on-premises networks, and ExpressRoute circuits — significantly broader than the intended management host.

**Remediation:**

> Replace the 'VirtualNetwork' source with the specific /32 IP of the management jump host or the CIDR of the dedicated management subnet. Document the authorized source in the rule description field. This is a governance finding — the controls exist but are misconfigured.

<details>
<summary>Resource ID</summary>

```
/subscriptions/XXXX/resourceGroups/prod-rg/providers/Microsoft.Network/networkSecurityGroups/prod-app-nsg
```

</details>

---

### Finding 5 — MISSING_EXPLICIT_DENY_ALL

| Field | Value |
|-------|-------|
| **Severity** | 🟡 MEDIUM |
| **NSG** | `prod-data-nsg` |
| **Rule** | N/A — missing rule |
| **MITRE ATT&CK** | `T1190 — Exploit Public-Facing Application` |

**Description:**

> NSG 'prod-data-nsg' has no explicit inbound deny-all rule. Azure applies an implicit default deny, but CIS Azure Benchmark 6.x and SOC 2 CC6.6 require explicit deny rules for audit traceability. Implicit rules cannot be referenced in compliance reports.

**Remediation:**

> Add an inbound Deny rule at priority 4096 with: source=*, destination=*, protocol=*, port=*. This is a low-effort, zero-disruption change that closes compliance findings on the next audit cycle.

---

## MITRE ATT&CK Technique Mapping

| Technique | Tactic | Finding Types Mapped |
|-----------|--------|---------------------|
| [`T1021.001`](https://attack.mitre.org/techniques/T1021/001) | Lateral Movement — Remote Desktop Protocol | OPEN_HIGH_RISK_PORT |
| [`T1021.004`](https://attack.mitre.org/techniques/T1021/004) | Lateral Movement — SSH | OPEN_HIGH_RISK_PORT |
| [`T1190`](https://attack.mitre.org/techniques/T1190) | Initial Access — Exploit Public-Facing Application | OPEN_HIGH_RISK_PORT, MISSING_EXPLICIT_DENY_ALL |
| [`T1021`](https://attack.mitre.org/techniques/T1021) | Lateral Movement — Remote Services | BROAD_SOURCE_MANAGEMENT_PORT |

---

## Remediation Checklist

Work through findings in severity order. Do not mark complete until verified in Azure Portal or via re-audit.

- [ ] **[CRITICAL]** Finding 1: `prod-data-nsg / AllowDB-ANY` — OPEN_HIGH_RISK_PORT
- [ ] **[CRITICAL]** Finding 2: `prod-web-nsg / AllowRDP-ANY` — OPEN_HIGH_RISK_PORT
- [ ] **[HIGH]** Finding 3: `prod-web-nsg / AllowSSH-ANY` — OPEN_HIGH_RISK_PORT
- [ ] **[MEDIUM]** Finding 4: `prod-app-nsg / AllowMgmt-VNet` — BROAD_SOURCE_MANAGEMENT_PORT
- [ ] **[MEDIUM]** Finding 5: `prod-data-nsg / N/A` — MISSING_EXPLICIT_DENY_ALL

---

## Re-Audit Instructions

After applying remediations, re-run the audit to confirm resolution:

```bash
python scripts/nsg_analyzer.py \
  --resource-group [RESOURCE GROUP] \
  --output-json reports/findings-remediated.json

python scripts/generate_report.py \
  --input reports/findings-remediated.json \
  --output reports/AUDIT-REMEDIATED-[DATE].md
```

---

*Report generated by [azure-security-baseline](https://github.com/codewithbrandon/azure-security-baseline)*
*Brandon | Independent Security Architect*
