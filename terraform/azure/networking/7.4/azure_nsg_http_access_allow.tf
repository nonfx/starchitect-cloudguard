provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_network_security_group" "pass_nsg" {
  provider = azurerm.pass_aws
  name                = "pass-security-group"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

resource "azurerm_network_security_rule" "pass_rule_http" {
  provider = azurerm.pass_aws
  name                        = "allow-http-restricted"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "80"
  source_address_prefix       = "10.0.0.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.pass_rg.name
  network_security_group_name = azurerm_network_security_group.pass_nsg.name
}

resource "azurerm_network_security_rule" "pass_rule_https" {
  provider = azurerm.pass_aws
  name                        = "allow-https-restricted"
  priority                    = 101
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "10.0.0.0/24"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.pass_rg.name
  network_security_group_name = azurerm_network_security_group.pass_nsg.name
}
