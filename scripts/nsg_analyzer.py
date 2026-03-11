#!/usr/bin/env python3
"""
nsg_analyzer.py — Azure Network Security Group Audit Tool

Connects to Azure, pulls all NSGs in a resource group, and evaluates every
inbound allow rule against a risk classification library. Produces structured
JSON output for reporting and CI gate enforcement.

Usage:
    python nsg_analyzer.py --resource-group <rg-name>
    python nsg_analyzer.py --resource-group myRG --output-json reports/findings.json
    python nsg_analyzer.py --resource-group myRG --fail-on CRITICAL

Authentication (in order of precedence — DefaultAzureCredential chain):
    1. Environment variables: AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
    2. Azure CLI:             az login
    3. Managed Identity:     Works automatically on Azure-hosted runners
    4. VS Code credential:   When running from VS Code with Azure extension

MITRE ATT&CK references: https://attack.mitre.org/techniques/
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Optional

try:
    from azure.identity import DefaultAzureCredential
    from azure.mgmt.network import NetworkManagementClient
    from azure.mgmt.resource import SubscriptionClient
except ImportError:
    print("ERROR: Azure SDK not installed. Run: pip install -r requirements.txt")
    sys.exit(1)


# ── Risk Classification Library ───────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Ports that must never be exposed to 0.0.0.0/0 or wildcard (*) sources.
# Severity reflects real-world exploitability and impact, not theoretical risk.
HIGH_RISK_PORTS: dict[str, dict] = {
    # Remote management — primary lateral movement vectors
    "22":    {"name": "SSH",                  "mitre": "T1021.004", "severity": "HIGH"},
    "3389":  {"name": "RDP",                  "mitre": "T1021.001", "severity": "CRITICAL"},
    "23":    {"name": "Telnet",               "mitre": "T1021.004", "severity": "CRITICAL"},
    "5985":  {"name": "WinRM HTTP",           "mitre": "T1021.006", "severity": "HIGH"},
    "5986":  {"name": "WinRM HTTPS",          "mitre": "T1021.006", "severity": "HIGH"},
    "135":   {"name": "RPC Endpoint Mapper",  "mitre": "T1021.003", "severity": "HIGH"},
    "445":   {"name": "SMB",                  "mitre": "T1021.002", "severity": "CRITICAL"},

    # Database ports — direct data exfiltration risk
    "1433":  {"name": "MSSQL",                "mitre": "T1190",     "severity": "CRITICAL"},
    "1434":  {"name": "MSSQL Browser UDP",    "mitre": "T1190",     "severity": "CRITICAL"},
    "3306":  {"name": "MySQL / MariaDB",      "mitre": "T1190",     "severity": "CRITICAL"},
    "5432":  {"name": "PostgreSQL",           "mitre": "T1190",     "severity": "CRITICAL"},
    "27017": {"name": "MongoDB",              "mitre": "T1190",     "severity": "CRITICAL"},
    "27018": {"name": "MongoDB Shard",        "mitre": "T1190",     "severity": "CRITICAL"},
    "6379":  {"name": "Redis",                "mitre": "T1190",     "severity": "CRITICAL"},
    "9200":  {"name": "Elasticsearch HTTP",   "mitre": "T1190",     "severity": "CRITICAL"},
    "9300":  {"name": "Elasticsearch Cluster","mitre": "T1190",     "severity": "HIGH"},

    # Container/orchestration — full cluster compromise if exposed
    "2375":  {"name": "Docker API (unauth)",  "mitre": "T1610",     "severity": "CRITICAL"},
    "2376":  {"name": "Docker API TLS",       "mitre": "T1610",     "severity": "HIGH"},
    "4243":  {"name": "Docker Alt",           "mitre": "T1610",     "severity": "CRITICAL"},
    "2379":  {"name": "etcd Client",          "mitre": "T1552.007", "severity": "CRITICAL"},
    "2380":  {"name": "etcd Peer",            "mitre": "T1552.007", "severity": "CRITICAL"},
    "10250": {"name": "Kubelet API",          "mitre": "T1609",     "severity": "CRITICAL"},
    "10255": {"name": "Kubelet Read-Only",    "mitre": "T1609",     "severity": "HIGH"},

    # Common app misconfigurations
    "8080":  {"name": "HTTP Alternate",       "mitre": "T1190",     "severity": "MEDIUM"},
    "8443":  {"name": "HTTPS Alternate",      "mitre": "T1190",     "severity": "MEDIUM"},
    "9090":  {"name": "Prometheus",           "mitre": "T1530",     "severity": "MEDIUM"},
    "9091":  {"name": "Prometheus Pushgateway","mitre": "T1530",    "severity": "MEDIUM"},
    "3000":  {"name": "Grafana / Dev Server", "mitre": "T1190",     "severity": "MEDIUM"},
    "5000":  {"name": "Flask Dev Server",     "mitre": "T1190",     "severity": "MEDIUM"},
    "8888":  {"name": "Jupyter Notebook",     "mitre": "T1190",     "severity": "HIGH"},
}

# Source addresses that represent full internet exposure
WIDE_OPEN_SOURCES = {"*", "0.0.0.0/0", "Internet", "Any"}

# Sources that are broader than intended but not full internet
BROAD_SOURCES = {"VirtualNetwork", "AzureLoadBalancer"}

# Management ports that should never be reachable even from VirtualNetwork scope
STRICT_MANAGEMENT_PORTS = {"22", "3389", "5985", "5986", "23"}


# ── Helper Functions ──────────────────────────────────────────────────────────────

def get_subscription_id(credential: DefaultAzureCredential) -> str:
    """Auto-detect subscription ID. Prompts for selection if multiple exist."""
    client = SubscriptionClient(credential)
    subs = list(client.subscriptions.list())

    if not subs:
        print("ERROR: No Azure subscriptions found. Check your credentials.")
        sys.exit(1)

    if len(subs) == 1:
        return subs[0].subscription_id

    print("\nMultiple subscriptions found. Re-run with --subscription-id:")
    for s in subs:
        print(f"  {s.subscription_id}  ({s.display_name})")
    sys.exit(1)


def normalize_ports(rule) -> list[str]:
    """Return a flat list of destination port strings from a security rule object."""
    ports: list[str] = []
    if rule.destination_port_range:
        ports.append(rule.destination_port_range)
    if rule.destination_port_ranges:
        ports.extend(rule.destination_port_ranges)
    return ports


def port_matches(target: str, port_spec: str) -> bool:
    """
    Check if a specific port number falls within a port spec.
    Handles wildcards, single ports, and ranges (e.g., '8000-9000').
    """
    if port_spec == "*":
        return True
    if "-" in port_spec:
        try:
            low, high = port_spec.split("-", 1)
            return int(low) <= int(target) <= int(high)
        except ValueError:
            return False
    return port_spec.strip() == target


def is_wide_open(source: Optional[str]) -> bool:
    return bool(source and source in WIDE_OPEN_SOURCES)


def is_broad(source: Optional[str]) -> bool:
    return bool(source and source in BROAD_SOURCES)


def make_finding(
    nsg_name: str,
    resource_id: str,
    rule_name: str,
    severity: str,
    finding_type: str,
    description: str,
    mitre_technique: str,
    remediation: str,
    priority: Optional[int] = None,
) -> dict:
    finding = {
        "nsg_name": nsg_name,
        "rule_name": rule_name,
        "severity": severity,
        "finding_type": finding_type,
        "description": description,
        "mitre_technique": mitre_technique,
        "remediation": remediation,
        "resource_id": resource_id,
    }
    if priority is not None:
        finding["priority"] = priority
    return finding


# ── NSG Analysis Checks ───────────────────────────────────────────────────────────

def check_missing_deny_all(nsg, findings: list) -> None:
    """
    MEDIUM: NSGs without an explicit deny-all rely on Azure's implicit default.
    Most compliance frameworks (CIS, NIST) require explicit deny rules for auditability.
    """
    inbound_rules = [r for r in (nsg.security_rules or []) if r.direction == "Inbound"]
    has_deny_all = any(
        r.access == "Deny"
        and r.source_address_prefix in WIDE_OPEN_SOURCES
        and (r.destination_port_range == "*" or "*" in (r.destination_port_ranges or []))
        for r in inbound_rules
    )
    if not has_deny_all:
        findings.append(make_finding(
            nsg_name=nsg.name,
            resource_id=nsg.id,
            rule_name="N/A — missing rule",
            severity="MEDIUM",
            finding_type="MISSING_EXPLICIT_DENY_ALL",
            description=(
                f"NSG '{nsg.name}' has no explicit inbound deny-all rule. "
                "Azure applies an implicit deny, but CIS Azure Benchmark 6.x requires "
                "an explicit deny-all at maximum priority (4096) for compliance auditability."
            ),
            mitre_technique="T1190 — Exploit Public-Facing Application",
            remediation=(
                "Add an inbound Deny rule at priority 4096 with: "
                "source=*, destination=*, protocol=*, port=*. "
                "This makes security posture explicit and satisfies most compliance scanners."
            ),
        ))


def check_allow_all_inbound(nsg, rule, findings: list) -> None:
    """CRITICAL: A rule allowing ALL traffic from ANY source is equivalent to no firewall."""
    source = rule.source_address_prefix
    ports = normalize_ports(rule)
    protocol = rule.protocol

    if is_wide_open(source) and protocol == "*" and "*" in ports:
        findings.append(make_finding(
            nsg_name=nsg.name,
            resource_id=nsg.id,
            rule_name=rule.name,
            priority=rule.priority,
            severity="CRITICAL",
            finding_type="ALLOW_ALL_INBOUND",
            description=(
                f"Rule '{rule.name}' (priority {rule.priority}) allows ALL protocols on ALL ports "
                f"from ANY source ({source}). This rule completely disables the NSG's protective function."
            ),
            mitre_technique="T1190 — Exploit Public-Facing Application",
            remediation=(
                "Delete this rule immediately. Conduct a traffic analysis to determine "
                "which specific ports are legitimately required and create targeted allow rules. "
                "A rule this permissive is never justified in a production environment."
            ),
        ))


def check_high_risk_ports_wide_open(nsg, rule, findings: list) -> None:
    """HIGH/CRITICAL: Known high-risk ports reachable from internet (0.0.0.0/0 or *)."""
    source = rule.source_address_prefix
    if not is_wide_open(source):
        return

    ports = normalize_ports(rule)
    for port_spec in ports:
        for risky_port, meta in HIGH_RISK_PORTS.items():
            if port_matches(risky_port, port_spec):
                findings.append(make_finding(
                    nsg_name=nsg.name,
                    resource_id=nsg.id,
                    rule_name=rule.name,
                    priority=rule.priority,
                    severity=meta["severity"],
                    finding_type="OPEN_HIGH_RISK_PORT",
                    description=(
                        f"Rule '{rule.name}' (priority {rule.priority}) allows "
                        f"{meta['name']} (port {risky_port}) inbound from any source ({source}). "
                        "This exposes the resource to automated scanning, brute force, and direct exploitation."
                    ),
                    mitre_technique=meta["mitre"],
                    remediation=(
                        f"Restrict the source address to the specific CIDR of authorized hosts. "
                        f"If {meta['name']} access is required for administration, route through "
                        "Azure Bastion (for RDP/SSH) or a site-to-site VPN. "
                        "Direct internet exposure of management and database ports is never justified."
                    ),
                ))


def check_broad_source_management(nsg, rule, findings: list) -> None:
    """
    MEDIUM: Management ports reachable from VirtualNetwork scope.
    VirtualNetwork includes all peered VNets and on-premises networks — broader than intended.
    """
    source = rule.source_address_prefix
    if not is_broad(source):
        return

    ports = normalize_ports(rule)
    for port_spec in ports:
        for mgmt_port in STRICT_MANAGEMENT_PORTS:
            if port_matches(mgmt_port, port_spec):
                meta = HIGH_RISK_PORTS.get(mgmt_port, {"name": mgmt_port, "mitre": "T1021"})
                findings.append(make_finding(
                    nsg_name=nsg.name,
                    resource_id=nsg.id,
                    rule_name=rule.name,
                    priority=rule.priority,
                    severity="MEDIUM",
                    finding_type="BROAD_SOURCE_MANAGEMENT_PORT",
                    description=(
                        f"Rule '{rule.name}' allows {meta['name']} (port {mgmt_port}) "
                        f"from source '{source}'. The '{source}' tag encompasses all VNet peers "
                        "and any connected on-premises ranges — likely broader than intended."
                    ),
                    mitre_technique=meta["mitre"],
                    remediation=(
                        f"Replace the '{source}' source with the specific /32 or /24 of the "
                        "management jump host, bastion subnet, or admin workstation CIDR. "
                        "Principle of least privilege applies to network access as much as IAM."
                    ),
                ))


def check_overly_permissive_outbound(nsg, rule, findings: list) -> None:
    """
    LOW: Unrestricted outbound to the internet allows data exfiltration and C2 callbacks.
    Most environments only need outbound on 443/80, not all ports to any destination.
    """
    if rule.direction != "Outbound" or rule.access != "Allow":
        return

    source = rule.source_address_prefix
    dest = rule.destination_address_prefix
    ports = normalize_ports(rule)

    if dest in WIDE_OPEN_SOURCES and "*" in ports and source in WIDE_OPEN_SOURCES:
        findings.append(make_finding(
            nsg_name=nsg.name,
            resource_id=nsg.id,
            rule_name=rule.name,
            priority=rule.priority,
            severity="LOW",
            finding_type="UNRESTRICTED_OUTBOUND",
            description=(
                f"Rule '{rule.name}' allows unrestricted outbound traffic on all ports to any destination. "
                "Unrestricted egress facilitates data exfiltration (T1041) and C2 callbacks (T1071)."
            ),
            mitre_technique="T1041 — Exfiltration Over C2 Channel",
            remediation=(
                "Restrict outbound to required ports only (typically 443, 80, and service-specific ports). "
                "Consider an egress firewall or Azure Firewall with FQDN filtering for production workloads."
            ),
        ))


# ── Main Audit Orchestrator ───────────────────────────────────────────────────────

def analyze_nsg(nsg, findings: list) -> None:
    """Run all checks against a single NSG. Appends findings in place."""
    check_missing_deny_all(nsg, findings)

    for rule in (nsg.security_rules or []):
        if rule.direction == "Inbound" and rule.access == "Allow":
            check_allow_all_inbound(nsg, rule, findings)
            check_high_risk_ports_wide_open(nsg, rule, findings)
            check_broad_source_management(nsg, rule, findings)
        elif rule.direction == "Outbound" and rule.access == "Allow":
            check_overly_permissive_outbound(nsg, rule, findings)


def compute_risk_score(findings: list) -> int:
    weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return sum(weights.get(f["severity"], 0) for f in findings)


def print_summary(findings: list, resource_group: str) -> None:
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
    score = compute_risk_score(findings)

    print("\n" + "=" * 70)
    print(f"  AZURE NSG SECURITY AUDIT")
    print(f"  Resource Group : {resource_group}")
    print(f"  Timestamp      : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    print("=" * 70)
    print(f"  Risk Score  : {score}/100")
    print(f"  Total       : {len(findings)}")
    print()
    print(f"  CRITICAL  : {counts['CRITICAL']:>3}")
    print(f"  HIGH      : {counts['HIGH']:>3}")
    print(f"  MEDIUM    : {counts['MEDIUM']:>3}")
    print(f"  LOW       : {counts['LOW']:>3}")
    print(f"  INFO      : {counts['INFO']:>3}")
    print("=" * 70)

    if findings:
        print("\n  FINDINGS:\n")
        prefix_map = {"CRITICAL": "[ !! ]", "HIGH": "[ HI ]", "MEDIUM": "[ MD ]", "LOW": "[ LO ]"}
        sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        for f in sorted_findings:
            pfx = prefix_map.get(f["severity"], "[    ]")
            prio = f"pri={f.get('priority', 'N/A'):>4}" if "priority" in f else "         "
            print(f"  {pfx} {f['severity']:<8} {prio}  {f['nsg_name']}")
            print(f"             Rule: {f['rule_name']}")
            print(f"             Type: {f['finding_type']}\n")

    if counts["CRITICAL"] > 0:
        status = "FAIL — Critical findings require immediate remediation before deployment."
    elif counts["HIGH"] > 0:
        status = "FAIL — High findings must be resolved (target: 72 hours)."
    elif counts["MEDIUM"] > 0:
        status = "WARN — Medium findings should be resolved within the next sprint."
    else:
        status = "PASS — No Critical or High findings detected."

    print(f"  STATUS: {status}")
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Azure NSG Security Audit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--resource-group", "-g", required=True,
                        help="Name of the Azure resource group to audit")
    parser.add_argument("--subscription-id", "-s",
                        help="Azure subscription ID (auto-detected if not specified)")
    parser.add_argument("--output-json", "-o",
                        help="Write structured findings to this JSON file path")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM"], default="HIGH",
                        help="Exit code 1 if any finding at or above this severity exists (default: HIGH)")
    parser.add_argument("--include-defaults", action="store_true",
                        help="Include Azure default NSG rules in the analysis (normally excluded)")
    args = parser.parse_args()

    print(f"\nAuthenticating via DefaultAzureCredential...")
    credential = DefaultAzureCredential()

    subscription_id = args.subscription_id or get_subscription_id(credential)
    print(f"Subscription : {subscription_id}")
    print(f"Resource Group: {args.resource_group}")

    network_client = NetworkManagementClient(credential, subscription_id)

    print("\nFetching NSGs...")
    try:
        nsgs = list(network_client.network_security_groups.list(args.resource_group))
    except Exception as e:
        print(f"ERROR: Could not retrieve NSGs: {e}")
        sys.exit(1)

    if not nsgs:
        print(f"WARN: No NSGs found in '{args.resource_group}'. Nothing to audit.")
        sys.exit(0)

    print(f"NSGs found   : {len(nsgs)} ({', '.join(n.name for n in nsgs)})\n")
    print("Running checks...")

    findings: list[dict] = []
    for nsg in nsgs:
        analyze_nsg(nsg, findings)

    # Build output payload
    output = {
        "audit_metadata": {
            "tool": "azure-security-baseline/nsg_analyzer",
            "version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "subscription_id": subscription_id,
            "resource_group": args.resource_group,
            "nsgs_audited": [n.name for n in nsgs],
        },
        "summary": {
            "total_findings": len(findings),
            "risk_score": compute_risk_score(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            },
        },
        "findings": sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)),
    }

    print_summary(findings, args.resource_group)

    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2, default=str)
        print(f"Findings written to : {args.output_json}")
        print(f"Generate report with: python scripts/generate_report.py --input {args.output_json}\n")

    # CI gate: exit non-zero if findings exceed the threshold
    threshold = SEVERITY_ORDER.get(args.fail_on, 1)
    worst_severity = min(
        (SEVERITY_ORDER.get(f["severity"], 99) for f in findings),
        default=99,
    )
    if worst_severity <= threshold:
        sys.exit(1)


if __name__ == "__main__":
    main()
