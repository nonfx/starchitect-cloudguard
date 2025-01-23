provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Configure Security Center subscription pricing without Defender for Cosmos DB
resource "azurerm_security_center_subscription_pricing" "fail_test" {
  provider      = azurerm.fail_aws
  tier          = "Free"
  resource_type = "CosmosDbs"
}

# Resource group for Cosmos DB
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# Cosmos DB account without Defender
resource "azurerm_cosmosdb_account" "fail_cosmos" {
  provider            = azurerm.fail_aws
  name                = "fail-cosmos-db"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.fail_rg.location
    failover_priority = 0
  }
}