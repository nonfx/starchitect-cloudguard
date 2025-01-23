provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_virtual_network" "pass_vnet" {
  provider            = azurerm.pass_aws
  name                = "pass-network"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

resource "azurerm_network_security_group" "pass_nsg" {
  provider            = azurerm.pass_aws
  name                = "pass-security-group"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

resource "azurerm_network_security_rule" "pass_rule" {
  provider                    = azurerm.pass_aws
  name                        = "pass-allow-internal-udp"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "53"
  source_address_prefix       = "10.0.0.0/16"
  destination_address_prefix  = "10.0.0.0/16"
  resource_group_name         = azurerm_resource_group.pass_rg.name
  network_security_group_name = azurerm_network_security_group.pass_nsg.name
}

resource "azurerm_network_security_rule" "pass_deny_internet" {
  provider                    = azurerm.pass_aws
  name                        = "pass-deny-internet-udp"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "Udp"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.pass_rg.name
  network_security_group_name = azurerm_network_security_group.pass_nsg.name
}