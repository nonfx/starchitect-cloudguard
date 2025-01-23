provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Create virtual network for Cosmos DB
resource "azurerm_virtual_network" "pass_vnet" {
  provider            = azurerm.pass_aws
  name                = "pass-vnet"
  address_space       = ["10.0.0.0/16"]
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

# Create subnet for Cosmos DB
resource "azurerm_subnet" "pass_subnet" {
  provider             = azurerm.pass_aws
  name                 = "pass-subnet"
  resource_group_name  = azurerm_resource_group.pass_rg.name
  virtual_network_name = azurerm_virtual_network.pass_vnet.name
  address_prefixes     = ["10.0.1.0/24"]

  service_endpoints = ["Microsoft.AzureCosmosDB"]
}

# Compliant: Cosmos DB account with restricted network access
resource "azurerm_cosmosdb_account" "pass" {
  provider            = azurerm.pass_aws
  name                = "pass-cosmosdb"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.pass_rg.location
    failover_priority = 0
  }

  # Compliant: Public network access disabled and virtual network filter enabled
  public_network_access_enabled     = false
  is_virtual_network_filter_enabled = true

  virtual_network_rule {
    id = azurerm_subnet.pass_subnet.id
  }

  tags = {
    Environment = "Production"
    Security    = "Restricted"
  }
}