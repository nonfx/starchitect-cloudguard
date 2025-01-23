provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Create virtual network
resource "azurerm_virtual_network" "pass_vnet" {
  provider = azurerm.pass_aws
  name                = "pass-network"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  address_space       = ["10.0.0.0/16"]

  subnet {
    name           = "subnet1"
    address_prefix = "10.0.1.0/24"
  }

  tags = {
    environment = "production"
  }
}

# Enable Network Watcher for the region
resource "azurerm_network_watcher" "pass_watcher" {
  provider = azurerm.pass_aws
  name                = "pass-network-watcher"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name

  tags = {
    environment = "production"
  }
}
