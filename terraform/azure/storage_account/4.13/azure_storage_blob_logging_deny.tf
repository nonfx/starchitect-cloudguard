provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  name     = "pass-resources"
  location = "West Europe"
}

resource "azurerm_storage_account" "pass_storage" {
  name                     = "passstorage"
  resource_group_name      = azurerm_resource_group.pass_rg.name
  location                 = azurerm_resource_group.pass_rg.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_kind             = "StorageV2"

  blob_properties {
    change_feed_enabled = false

    delete_retention_policy {
      days = 7
    }

    container_delete_retention_policy {
      days = 7
    }
  }

  tags = {
    environment = "production"
  }
}