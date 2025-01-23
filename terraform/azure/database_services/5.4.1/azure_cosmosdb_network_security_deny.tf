provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

# Non-compliant: Cosmos DB account with unrestricted network access
resource "azurerm_cosmosdb_account" "fail" {
  provider            = azurerm.fail_aws
  name                = "fail-cosmosdb"
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

  # Non-compliant: Public network access enabled and no network restrictions
  public_network_access_enabled     = true
  is_virtual_network_filter_enabled = false
}