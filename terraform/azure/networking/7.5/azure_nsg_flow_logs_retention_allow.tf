provider "azurerm" {
  alias = "pass_aws"
  features {}
}

resource "azurerm_resource_group" "pass_rg" {
  provider = azurerm.pass_aws
  name     = "pass-resources"
  location = "West US"
}

resource "azurerm_network_security_group" "pass_nsg" {
  provider = azurerm.pass_aws
  name                = "pass-security-group"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

resource "azurerm_storage_account" "pass_sa" {
  provider = azurerm.pass_aws
  name                     = "passstorageaccount"
  resource_group_name      = azurerm_resource_group.pass_rg.name
  location                 = azurerm_resource_group.pass_rg.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_network_watcher" "pass_nw" {
  provider = azurerm.pass_aws
  name                = "pass-network-watcher"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
}

resource "azurerm_network_watcher_flow_log" "pass_flow_log" {
  provider = azurerm.pass_aws
  network_watcher_name = azurerm_network_watcher.pass_nw.name
  resource_group_name  = azurerm_resource_group.pass_rg.name
  
  network_security_group_id = azurerm_network_security_group.pass_nsg.id
  storage_account_id        = azurerm_storage_account.pass_sa.id
  enabled                  = true
  
  retention_policy {
    enabled = true
    days    = 90  # Compliant: retention period >= 90 days
  }
  
  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.pass_law.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.pass_law.location
    workspace_resource_id = azurerm_log_analytics_workspace.pass_law.id
    interval_in_minutes   = 10
  }
}

resource "azurerm_log_analytics_workspace" "pass_law" {
  provider = azurerm.pass_aws
  name                = "pass-law"
  location            = azurerm_resource_group.pass_rg.location
  resource_group_name = azurerm_resource_group.pass_rg.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}
