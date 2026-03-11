# Security Policy

## Intentional Misconfigurations

This repository provisions Azure infrastructure with **intentional security misconfigurations**
for audit and demonstration purposes. These findings are documented and expected.

Do not report the following as vulnerabilities:
- NSG rules permitting SSH/RDP from `0.0.0.0/0` (default variable state)
- Database ports open to the internet (data-tier NSG)
- Missing explicit deny-all rules

These are the *subjects* of the audit, not oversights.

## Reporting Actual Vulnerabilities

If you discover a genuine security issue in the audit tooling itself (e.g., a credential leak,
code injection in the Python scripts, or a secrets exposure), please report it privately:

- **Email:** [your security contact email]
- **Do not** open a public GitHub issue for security vulnerabilities.

## Credential Handling

This repository contains no Azure credentials. Authentication uses:
- **Local use:** `az login` (Azure CLI)
- **CI/CD:** Azure OIDC federated identity — no `AZURE_CLIENT_SECRET` is stored anywhere

The `.gitignore` explicitly excludes `terraform.tfvars`, `*.tfstate`, and all Azure credential files.
Run `gitleaks detect` before pushing to confirm no secrets are present.
