provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West Europe"
}

resource "azurerm_storage_account" "fail_storage" {
  provider                 = azurerm.fail_aws
  name                     = "failstorage"
  resource_group_name      = azurerm_resource_group.fail_rg.name
  location                 = azurerm_resource_group.fail_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = {
    environment = "test"
  }
}

resource "azurerm_monitor_diagnostic_setting" "fail_diag" {
  provider           = azurerm.fail_aws
  name               = "fail-diag"
  target_resource_id = azurerm_storage_account.fail_storage.id
  storage_account_id = azurerm_storage_account.fail_storage.id

  enabled_log {
    category = "StorageRead"
  }

  enabled_log {
    category = "StorageWrite"
  }
}