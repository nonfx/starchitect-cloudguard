provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_virtual_network" "pass_vnet" {
  name                = "pass-vnet"
  resource_group_name = azurerm_resource_group.pass_rg.name
  location            = azurerm_resource_group.pass_rg.location
  address_space       = ["10.0.0.0/16"]
}

resource "azurerm_subnet" "pass_subnet" {
  name                 = "pass-subnet"
  resource_group_name  = azurerm_resource_group.pass_rg.name
  virtual_network_name = azurerm_virtual_network.pass_vnet.name
  address_prefixes     = ["10.0.1.0/24"]

}

resource "azurerm_cosmosdb_account" "pass_account" {
  name                = "pass-cosmos-db"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  public_network_access_enabled = false

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = azurerm_resource_group.pass_rg.location
    failover_priority = 0
  }
}

resource "azurerm_private_endpoint" "pass_endpoint" {
  name                = "pass-endpoint"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  subnet_id           = azurerm_subnet.pass_subnet.id

  private_service_connection {
    name                           = "pass-privateserviceconnection"
    private_connection_resource_id = azurerm_cosmosdb_account.pass_account.id
    is_manual_connection           = false
    subresource_names              = ["SQL"]
  }
}