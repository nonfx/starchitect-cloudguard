provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  name     = "fail-resources"
  location = "West Europe"
}

resource "azurerm_storage_account" "fail_storage" {
  name                          = "failstorage"
  resource_group_name           = azurerm_resource_group.fail_rg.name
  location                      = azurerm_resource_group.fail_rg.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  public_network_access_enabled = true
}