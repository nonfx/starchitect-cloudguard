provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West Europe"
}

# Create virtual network for allowed access
resource "azurerm_virtual_network" "pass_vnet" {
  provider            = azurerm.pass_aws
  name                = "pass-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

# Create subnet for storage account access
resource "azurerm_subnet" "pass_subnet" {
  provider             = azurerm.pass_aws
  name                 = "pass-subnet"
  resource_group_name  = azurerm_resource_group.pass_rg.name
  virtual_network_name = azurerm_virtual_network.pass_vnet.name
  address_prefixes     = ["10.0.1.0/24"]

  service_endpoints = ["Microsoft.Storage"]
}

# Create storage account with secure network rules
resource "azurerm_storage_account" "pass_storage" {
  provider                 = azurerm.pass_aws
  name                     = "passstorage"
  resource_group_name      = azurerm_resource_group.pass_rg.name
  location                 = azurerm_resource_group.pass_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  network_rules {
    default_action             = "Deny"  # Compliant setting
    ip_rules                   = ["100.0.0.1/32"]  # Example allowed IP
    virtual_network_subnet_ids = [azurerm_subnet.pass_subnet.id]
    bypass                     = ["Metrics", "AzureServices"]
  }

  tags = {
    environment = "production"
  }
}