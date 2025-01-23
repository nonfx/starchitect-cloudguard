provider "azurerm" {
  alias = "fail_aws"
  features {}
}

resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-resources"
  location = "West US"
}

resource "azurerm_network_security_group" "fail_nsg" {
  provider = azurerm.fail_aws
  name                = "fail-security-group"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
}

resource "azurerm_storage_account" "fail_sa" {
  provider = azurerm.fail_aws
  name                     = "failstorageaccount"
  resource_group_name      = azurerm_resource_group.fail_rg.name
  location                 = azurerm_resource_group.fail_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_network_watcher" "fail_nw" {
  provider = azurerm.fail_aws
  name                = "fail-network-watcher"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
}

resource "azurerm_network_watcher_flow_log" "fail_flow_log" {
  provider = azurerm.fail_aws
  network_watcher_name = azurerm_network_watcher.fail_nw.name
  resource_group_name  = azurerm_resource_group.fail_rg.name
  
  network_security_group_id = azurerm_network_security_group.fail_nsg.id
  storage_account_id        = azurerm_storage_account.fail_sa.id
  enabled                  = true
  
  retention_policy {
    enabled = true
    days    = 30  # Non-compliant: retention period less than 90 days
  }
}
