provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_cosmosdb_account" "fail_account" {
  name                = "fail-cosmos-db"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  public_network_access_enabled = true

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.fail_rg.location
    failover_priority = 0
  }
}