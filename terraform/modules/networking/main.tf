# ── Virtual Network ───────────────────────────────────────────────────────────────
resource "azurerm_virtual_network" "main" {
  name                = "${var.name_prefix}-vnet"
  location            = var.location
  resource_group_name = var.resource_group_name
  address_space       = ["10.0.0.0/16"]
  tags                = var.tags
}

# ── Subnets ───────────────────────────────────────────────────────────────────────
resource "azurerm_subnet" "web" {
  name                 = "web-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "app" {
  name                 = "app-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_subnet" "data" {
  name                 = "data-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.0.3.0/24"]
}

# ── NSG: Web Tier ─────────────────────────────────────────────────────────────────
# AUDIT INTENT: Default var values leave SSH (22) and RDP (3389) open to 0.0.0.0/0.
# The nsg_analyzer.py script will detect these as HIGH/CRITICAL findings.
# Set allowed_ssh_cidrs / allowed_rdp_cidrs to switch to the hardened rules.
resource "azurerm_network_security_group" "web" {
  name                = "${var.name_prefix}-web-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  # ALLOW: HTTPS from internet (legitimate)
  security_rule {
    name                       = "AllowHTTPS-Inbound"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
    description                = "HTTPS inbound from internet"
  }

  # ALLOW: HTTP inbound — redirect to HTTPS handled at app layer
  security_rule {
    name                       = "AllowHTTP-Inbound"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
    description                = "HTTP inbound — redirect to HTTPS at application layer"
  }

  # FINDING — HIGH: SSH open to any source when no CIDRs specified (default)
  dynamic "security_rule" {
    for_each = length(var.allowed_ssh_cidrs) == 0 ? [1] : []
    content {
      name                       = "AllowSSH-ANY"
      priority                   = 200
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
      description                = "MISCONFIGURED: SSH open to 0.0.0.0/0 — audit finding HIGH"
    }
  }

  # HARDENED: SSH restricted to specified CIDRs (when variable is set)
  dynamic "security_rule" {
    for_each = { for idx, cidr in var.allowed_ssh_cidrs : idx => cidr }
    content {
      name                       = "AllowSSH-CIDR-${security_rule.key}"
      priority                   = 200 + security_rule.key
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "22"
      source_address_prefix      = security_rule.value
      destination_address_prefix = "*"
      description                = "SSH restricted to ${security_rule.value}"
    }
  }

  # FINDING — CRITICAL: RDP open to any source when no CIDRs specified (default)
  dynamic "security_rule" {
    for_each = length(var.allowed_rdp_cidrs) == 0 ? [1] : []
    content {
      name                       = "AllowRDP-ANY"
      priority                   = 300
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "3389"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
      description                = "MISCONFIGURED: RDP open to 0.0.0.0/0 — audit finding CRITICAL"
    }
  }

  # HARDENED: RDP restricted to specified CIDRs
  dynamic "security_rule" {
    for_each = { for idx, cidr in var.allowed_rdp_cidrs : idx => cidr }
    content {
      name                       = "AllowRDP-CIDR-${security_rule.key}"
      priority                   = 300 + security_rule.key
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_range     = "3389"
      source_address_prefix      = security_rule.value
      destination_address_prefix = "*"
      description                = "RDP restricted to ${security_rule.value}"
    }
  }

  # Explicit deny-all at max priority — makes posture auditable
  security_rule {
    name                       = "DenyAll-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Explicit deny-all — satisfies CIS Azure 6.x controls"
  }
}

# ── NSG: App Tier ─────────────────────────────────────────────────────────────────
# FINDING — MEDIUM: Management port 8443 open to VirtualNetwork scope.
# VirtualNetwork includes all peered VNets — broader than a single subnet.
resource "azurerm_network_security_group" "app" {
  name                = "${var.name_prefix}-app-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  security_rule {
    name                       = "AllowFromWebTier"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8080"
    source_address_prefix      = "10.0.1.0/24"
    destination_address_prefix = "*"
    description                = "Allow app traffic from web subnet only"
  }

  security_rule {
    name                       = "AllowMgmt-VNet"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "8443"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "*"
    description                = "MISCONFIGURED: Management port open to VirtualNetwork — audit finding MEDIUM"
  }

  security_rule {
    name                       = "DenyAll-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Explicit deny-all"
  }
}

# ── NSG: Data Tier ────────────────────────────────────────────────────────────────
# FINDING — CRITICAL: Database ports open to 0.0.0.0/0.
# This simulates the most common catastrophic misconfiguration found in the wild:
# a dev opened a DB port for testing and it was never locked back down.
resource "azurerm_network_security_group" "data" {
  name                = "${var.name_prefix}-data-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name
  tags                = var.tags

  # Correct rule: DB access from app tier only
  security_rule {
    name                       = "AllowDB-FromAppTier"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["1433", "5432", "3306"]
    source_address_prefix      = "10.0.2.0/24"
    destination_address_prefix = "*"
    description                = "DB access from app subnet only"
  }

  # FINDING — CRITICAL: Database ports exposed to internet (simulated dev misconfiguration)
  security_rule {
    name                       = "AllowDB-ANY"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["1433", "5432", "27017", "6379"]
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "MISCONFIGURED: DB ports open to 0.0.0.0/0 — audit finding CRITICAL"
  }

  security_rule {
    name                       = "DenyAll-Inbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
    description                = "Explicit deny-all"
  }
}

# ── NSG → Subnet Associations ─────────────────────────────────────────────────────
resource "azurerm_subnet_network_security_group_association" "web" {
  subnet_id                 = azurerm_subnet.web.id
  network_security_group_id = azurerm_network_security_group.web.id
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

resource "azurerm_subnet_network_security_group_association" "data" {
  subnet_id                 = azurerm_subnet.data.id
  network_security_group_id = azurerm_network_security_group.data.id
}
