provider "azurerm" {
  alias = "pass_aws"
  features {}
}

# Configure Security Center subscription pricing with Defender for Cosmos DB
resource "azurerm_security_center_subscription_pricing" "pass_test" {
  provider      = azurerm.pass_aws
  tier          = "Standard"
  resource_type = "CosmosDbs"
}

# Resource group for Cosmos DB
resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

# Cosmos DB account with security features
resource "azurerm_cosmosdb_account" "pass_cosmos" {
  provider            = azurerm.pass_aws
  name                = "pass-cosmos-db"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Strong"
  }

  geo_location {
    location          = azurerm_resource_group.pass_rg.location
    failover_priority = 0
  }

  # Enable network security features
  public_network_access_enabled = false

  # Enable backup encryption
  backup {
    type                = "Periodic"
    interval_in_minutes = 240
    retention_in_hours  = 8
    storage_redundancy  = "Geo"
  }
}