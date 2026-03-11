output "vnet_id" {
  description = "Virtual network resource ID"
  value       = azurerm_virtual_network.main.id
}

output "subnet_ids" {
  description = "Map of tier name to subnet resource ID"
  value = {
    web  = azurerm_subnet.web.id
    app  = azurerm_subnet.app.id
    data = azurerm_subnet.data.id
  }
}

output "nsg_ids" {
  description = "Map of tier name to NSG resource ID"
  value = {
    web  = azurerm_network_security_group.web.id
    app  = azurerm_network_security_group.app.id
    data = azurerm_network_security_group.data.id
  }
}

output "nsg_names" {
  description = "Map of tier name to NSG name (for audit script)"
  value = {
    web  = azurerm_network_security_group.web.name
    app  = azurerm_network_security_group.app.name
    data = azurerm_network_security_group.data.name
  }
}
