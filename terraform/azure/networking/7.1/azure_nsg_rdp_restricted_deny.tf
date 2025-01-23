provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_network_security_group" "fail_nsg" {
  provider            = azurerm.fail_aws
  name                = "fail-security-group"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
}

resource "azurerm_network_security_rule" "fail_rule" {
  provider                    = azurerm.fail_aws
  name                        = "allow-rdp"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.fail_rg.name
  network_security_group_name = azurerm_network_security_group.fail_nsg.name
}
