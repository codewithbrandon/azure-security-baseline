# ── Azure Security Baseline — Makefile ───────────────────────────────────────────
# Usage: make <target>
# All targets that interact with Azure require: az login

.PHONY: help init plan apply destroy audit report lint fmt validate clean

SHELL        := /bin/bash
TF_DIR       := terraform
SCRIPTS_DIR  := scripts
REPORTS_DIR  := reports
RG           ?= azsec-lab-rg

# Default: print help
help:
	@echo ""
	@echo "  Azure Security Baseline"
	@echo "  ──────────────────────────────────────────────────────"
	@echo ""
	@echo "  Infrastructure:"
	@echo "    make init       Terraform init (no backend — local state)"
	@echo "    make plan       Terraform plan (review before apply)"
	@echo "    make apply      Terraform apply (provisions Azure resources)"
	@echo "    make destroy    Tear down all provisioned resources"
	@echo ""
	@echo "  Audit:"
	@echo "    make audit      Run NSG security audit against RG (RG=<name>)"
	@echo "    make report     Generate Markdown report from last audit"
	@echo "    make full-audit Provision → audit → report in one command"
	@echo ""
	@echo "  Code Quality:"
	@echo "    make lint       Lint Python scripts with ruff"
	@echo "    make fmt        Format Python with ruff"
	@echo "    make validate   Validate Terraform configuration"
	@echo ""
	@echo "  Variables:"
	@echo "    RG=<name>       Resource group to audit (default: azsec-lab-rg)"
	@echo ""

# ── Infrastructure ────────────────────────────────────────────────────────────────

init:
	@echo "→ Terraform init..."
	cd $(TF_DIR) && terraform init

plan:
	@echo "→ Terraform plan..."
	cd $(TF_DIR) && terraform plan

apply:
	@echo "→ Terraform apply..."
	cd $(TF_DIR) && terraform apply -auto-approve
	@echo ""
	@echo "→ Provisioning complete. Run 'make audit' to audit the environment."

destroy:
	@echo "→ Destroying all resources in resource group..."
	cd $(TF_DIR) && terraform destroy -auto-approve

# ── Audit ─────────────────────────────────────────────────────────────────────────

audit:
	@echo "→ Running NSG security audit against resource group: $(RG)"
	@mkdir -p $(REPORTS_DIR)
	python $(SCRIPTS_DIR)/nsg_analyzer.py \
		--resource-group $(RG) \
		--output-json $(REPORTS_DIR)/findings.json \
		--fail-on HIGH; \
	EXIT=$$?; \
	echo ""; \
	if [ $$EXIT -ne 0 ]; then \
		echo "  Findings require remediation. Run 'make report' to generate the report."; \
	else \
		echo "  Audit passed. Run 'make report' to generate the report."; \
	fi; \
	exit $$EXIT

report:
	@if [ ! -f $(REPORTS_DIR)/findings.json ]; then \
		echo "ERROR: No findings.json found. Run 'make audit' first."; \
		exit 1; \
	fi
	@echo "→ Generating Markdown report..."
	python $(SCRIPTS_DIR)/generate_report.py \
		--input $(REPORTS_DIR)/findings.json \
		--output $(REPORTS_DIR)/AUDIT-$(shell date +%Y%m%d).md
	@echo "→ Report generated: $(REPORTS_DIR)/AUDIT-$(shell date +%Y%m%d).md"

full-audit: apply audit report
	@echo "→ Full audit cycle complete."

# ── Code Quality ──────────────────────────────────────────────────────────────────

lint:
	@echo "→ Linting Python..."
	ruff check $(SCRIPTS_DIR)/
	@echo "→ Checking Terraform format..."
	cd $(TF_DIR) && terraform fmt -check -recursive

fmt:
	@echo "→ Formatting Python..."
	ruff format $(SCRIPTS_DIR)/
	@echo "→ Formatting Terraform..."
	cd $(TF_DIR) && terraform fmt -recursive

validate:
	@echo "→ Validating Terraform configuration..."
	cd $(TF_DIR) && terraform init -backend=false -reconfigure && terraform validate

# ── Cleanup ───────────────────────────────────────────────────────────────────────

clean:
	@echo "→ Cleaning generated files..."
	rm -f $(REPORTS_DIR)/findings.json
	rm -f $(REPORTS_DIR)/AUDIT-*.md
	rm -rf $(TF_DIR)/.terraform
	rm -f $(TF_DIR)/.terraform.lock.hcl
	rm -f $(TF_DIR)/terraform.tfstate
	rm -f $(TF_DIR)/terraform.tfstate.backup
