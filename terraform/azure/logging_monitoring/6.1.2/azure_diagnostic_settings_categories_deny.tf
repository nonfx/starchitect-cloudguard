provider "azurerm" {
  alias = "fail_aws"
  features {}
}

# Create a resource group
resource "azurerm_resource_group" "fail_rg" {
  provider = azurerm.fail_aws
  name     = "fail-diagnostics-rg"
  location = "West US"
}

# Create a Log Analytics workspace
resource "azurerm_log_analytics_workspace" "fail_law" {
  provider            = azurerm.fail_aws
  name                = "fail-law"
  location            = azurerm_resource_group.fail_rg.location
  resource_group_name = azurerm_resource_group.fail_rg.name
  sku                 = "PerGB2018"
}

# Create diagnostic setting with missing categories
resource "azurerm_monitor_diagnostic_setting" "fail_setting" {
  provider               = azurerm.fail_aws
  name                   = "fail-diagnostic-setting"
  target_resource_id     = "/subscriptions/00000000-0000-0000-0000-000000000000"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.fail_law.id

  log {
    category = "Administrative"
    enabled  = true
  }

  log {
    category = "Alert"
    enabled  = false
  }
}
