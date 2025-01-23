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
  provider            = azurerm.pass_aws
  name                = "pass-security-group"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

resource "azurerm_network_security_rule" "pass_rule" {
  provider                    = azurerm.pass_aws
  name                        = "SSH"
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "10.0.0.0/24"  # Restricted to specific subnet
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.pass_rg.name
  network_security_group_name = azurerm_network_security_group.pass_nsg.name
}

# VPN Gateway for secure access
resource "azurerm_virtual_network" "pass_vnet" {
  provider            = azurerm.pass_aws
  name                = "pass-vnet"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "gateway" {
  provider             = azurerm.pass_aws
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.pass_rg.name
  virtual_network_name = azurerm_virtual_network.pass_vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}
